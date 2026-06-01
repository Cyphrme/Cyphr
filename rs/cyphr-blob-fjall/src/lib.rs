//! fjall-backed [`BlobStore`] implementation.

use std::path::Path;

use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle};

/// Production blob store backed by fjall (LSM-tree).
pub struct FjallBlobStore {
    keyspace: Keyspace,
    blobs: PartitionHandle,
    max_blob_size: Option<usize>,
}

impl FjallBlobStore {
    /// Open or create a blob store at `path`.
    pub fn open(path: &Path) -> Result<Self, BlobStoreError> {
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| BlobStoreError::Backend(format!("fjall keyspace open: {e}")))?;
        Self::from_keyspace(keyspace)
    }

    /// Create a blob store from an existing keyspace (supporting single keyspace cooperation).
    pub fn from_keyspace(keyspace: Keyspace) -> Result<Self, BlobStoreError> {
        let blobs = keyspace
            .open_partition("blobs", PartitionCreateOptions::default())
            .map_err(|e| BlobStoreError::Backend(format!("fjall partition open: {e}")))?;
        Ok(Self {
            keyspace,
            blobs,
            max_blob_size: None,
        })
    }

    /// Configure a maximum blob size limit.
    pub fn with_max_blob_size(mut self, max: usize) -> Self {
        self.max_blob_size = Some(max);
        self
    }

    /// Get the underlying Keyspace reference.
    pub fn keyspace(&self) -> &Keyspace {
        &self.keyspace
    }
}

impl BlobStore for FjallBlobStore {
    fn put(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let max_blob_size = self.max_blob_size;
        let blobs = self.blobs.clone();
        let data = data.to_vec();
        async move {
            if let Some(max) = max_blob_size {
                if data.len() > max {
                    return Err(BlobStoreError::BlobTooLarge {
                        size: data.len(),
                        max,
                    });
                }
            }
            let hash = Blake3Hash::from_bytes(*blake3::hash(&data).as_bytes());
            tokio::task::spawn_blocking(move || {
                blobs
                    .insert(hash.as_bytes(), data)
                    .map_err(|e| BlobStoreError::Backend(format!("fjall insert: {e}")))?;
                Ok(hash)
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        }
    }

    fn get(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send {
        let hash = *hash;
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let result = blobs
                    .get(hash.as_bytes())
                    .map_err(|e| BlobStoreError::Backend(format!("fjall get: {e}")))?;
                Ok(result.map(|slice| slice.to_vec()))
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, BlobStoreError>> + Send {
        let hash = *hash;
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                blobs
                    .contains_key(hash.as_bytes())
                    .map_err(|e| BlobStoreError::Backend(format!("fjall contains_key: {e}")))
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }

    fn iter(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>,
            BlobStoreError,
        >,
    > + Send {
        let blobs = self.blobs.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let iter = blobs.iter();
                let mut hashes = Vec::new();
                for result in iter {
                    let (key, _) =
                        result.map_err(|e| BlobStoreError::Backend(format!("fjall iter: {e}")))?;
                    let key_bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                        BlobStoreError::Backend(format!(
                            "fjall key length {}, expected 32",
                            key.len()
                        ))
                    })?;
                    hashes.push(Blake3Hash::from_bytes(key_bytes));
                }
                let iter: Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send> =
                    Box::new(hashes.into_iter().map(Ok));
                Ok(iter)
            })
            .await
            .map_err(|e| BlobStoreError::Backend(format!("spawn_blocking join failed: {e}")))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fjall_blob_store() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let store = FjallBlobStore::open(dir.path()).expect("failed to open store");

        let data = b"hello fjall store content-addressed";
        let hash = store.put(data).await.expect("put");

        let exists = store.exists(&hash).await.expect("exists");
        assert!(exists);

        let retrieved = store.get(&hash).await.expect("get").expect("found");
        assert_eq!(retrieved, data);

        // test limit
        let limited = store.with_max_blob_size(10);
        let err = limited.put(b"too long payload").await.unwrap_err();
        assert!(matches!(err, BlobStoreError::BlobTooLarge { .. }));
    }
}
