//! In-memory [`BlobStore`] implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use super::{Blake3Hash, BlobStore, BlobStoreError};

/// In-memory blob store backed by a `HashMap`.
///
/// Thread-safe via `RwLock`. Suitable for tests and short-lived processes.
/// Implements the same [`BlobStore`] trait as production backends.
pub struct MemoryBlobStore {
    blobs: RwLock<HashMap<Blake3Hash, Vec<u8>>>,
}

impl MemoryBlobStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self {
            blobs: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlobStore for MemoryBlobStore {
    fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        let hash = Blake3Hash::from_bytes(*blake3::hash(data).as_bytes());
        let mut blobs = self
            .blobs
            .write()
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")))?;
        blobs.entry(hash).or_insert_with(|| data.to_vec());
        Ok(hash)
    }

    fn get(&self, hash: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        let blobs = self
            .blobs
            .read()
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")))?;
        Ok(blobs.get(hash).cloned())
    }

    fn exists(&self, hash: &Blake3Hash) -> Result<bool, BlobStoreError> {
        let blobs = self
            .blobs
            .read()
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")))?;
        Ok(blobs.contains_key(hash))
    }

    fn iter(
        &self,
    ) -> Result<
        Box<dyn Iterator<Item = Result<(Blake3Hash, Vec<u8>), BlobStoreError>> + '_>,
        BlobStoreError,
    > {
        let blobs = self
            .blobs
            .read()
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")))?;
        // Collect a snapshot to avoid holding the read lock across iteration.
        let snapshot: Vec<(Blake3Hash, Vec<u8>)> =
            blobs.iter().map(|(k, v)| (*k, v.clone())).collect();
        Ok(Box::new(snapshot.into_iter().map(Ok)))
    }
}
