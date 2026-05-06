//! fjall-backed [`BlobStore`] implementation.
//!
//! Uses a single fjall partition keyed by 32-byte BLAKE3 digests,
//! with raw blob bytes as values. LSM-tree storage provides
//! write-optimized ingestion with built-in LZ4 compression.

use std::path::Path;

use fjall::{Config, Keyspace, PartitionCreateOptions, PartitionHandle};

use super::{Blake3Hash, BlobStore, BlobStoreError};

/// Production blob store backed by fjall (LSM-tree).
///
/// Opens (or creates) a fjall keyspace at the given directory path
/// with a single `"blobs"` partition.
pub struct FjallBlobStore {
    #[allow(dead_code)]
    keyspace: Keyspace,
    blobs: PartitionHandle,
}

impl FjallBlobStore {
    /// Open or create a blob store at `path`.
    ///
    /// The directory will be created if it does not exist.
    pub fn open(path: &Path) -> Result<Self, BlobStoreError> {
        let keyspace = Config::new(path)
            .open()
            .map_err(|e| BlobStoreError::Backend(format!("fjall keyspace open: {e}")))?;

        let blobs = keyspace
            .open_partition("blobs", PartitionCreateOptions::default())
            .map_err(|e| BlobStoreError::Backend(format!("fjall partition open: {e}")))?;

        Ok(Self { keyspace, blobs })
    }
}

impl BlobStore for FjallBlobStore {
    fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        let hash = Blake3Hash::from_bytes(*blake3::hash(data).as_bytes());
        self.blobs
            .insert(hash.as_bytes(), data)
            .map_err(|e| BlobStoreError::Backend(format!("fjall insert: {e}")))?;
        Ok(hash)
    }

    fn get(&self, hash: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        let result = self
            .blobs
            .get(hash.as_bytes())
            .map_err(|e| BlobStoreError::Backend(format!("fjall get: {e}")))?;
        Ok(result.map(|slice| slice.to_vec()))
    }

    fn exists(&self, hash: &Blake3Hash) -> Result<bool, BlobStoreError> {
        self.blobs
            .contains_key(hash.as_bytes())
            .map_err(|e| BlobStoreError::Backend(format!("fjall contains_key: {e}")))
    }

    fn iter(
        &self,
    ) -> Result<
        Box<dyn Iterator<Item = Result<(Blake3Hash, Vec<u8>), BlobStoreError>> + '_>,
        BlobStoreError,
    > {
        let iter = self.blobs.iter();
        Ok(Box::new(iter.map(|result| {
            let (key, value) =
                result.map_err(|e| BlobStoreError::Backend(format!("fjall iter: {e}")))?;

            let key_bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                BlobStoreError::Backend(format!("fjall key length {}, expected 32", key.len()))
            })?;

            Ok((Blake3Hash::from_bytes(key_bytes), value.to_vec()))
        })))
    }
}
