//! In-memory [`BlobStore`] implementation for testing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::{Blake3Hash, BlobStore, BlobStoreError};

/// In-memory blob store backed by a `HashMap`.
///
/// Thread-safe via `RwLock`. Suitable for tests and short-lived processes.
/// Implements the same [`BlobStore`] trait as production backends.
#[derive(Clone)]
pub struct MemoryBlobStore {
    blobs: Arc<RwLock<HashMap<Blake3Hash, Vec<u8>>>>,
    max_blob_size: Option<usize>,
}

impl MemoryBlobStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            max_blob_size: None,
        }
    }

    /// Create an empty in-memory store with a maximum blob size limit.
    pub fn with_max_blob_size(mut self, max: usize) -> Self {
        self.max_blob_size = Some(max);
        self
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore for MemoryBlobStore {
    fn put(
        &self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let max_blob_size = self.max_blob_size;
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
            self.blobs
                .write()
                .map(|mut guard| {
                    guard.entry(hash).or_insert(data);
                })
                .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")))?;
            Ok(hash)
        }
    }

    fn get(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send {
        let hash = *hash;
        let res = self
            .blobs
            .read()
            .map(|guard| guard.get(&hash).cloned())
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")));
        async move { res }
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, BlobStoreError>> + Send {
        let hash = *hash;
        let res = self
            .blobs
            .read()
            .map(|guard| guard.contains_key(&hash))
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")));
        async move { res }
    }

    fn iter(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>,
            BlobStoreError,
        >,
    > + Send {
        let res = self
            .blobs
            .read()
            .map(|guard| {
                let snapshot: Vec<Blake3Hash> = guard.keys().copied().collect();
                let iter: Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send> =
                    Box::new(snapshot.into_iter().map(Ok));
                iter
            })
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")));
        async move { res }
    }
}
