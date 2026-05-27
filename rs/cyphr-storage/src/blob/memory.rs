//! In-memory [`BlobStore`] implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use super::{Blake3Hash, BlobStore, BlobStoreError};

use std::sync::Arc;

/// In-memory blob store backed by a `HashMap`.
///
/// Thread-safe via `RwLock`. Suitable for tests and short-lived processes.
/// Implements the same [`BlobStore`] trait as production backends.
#[derive(Clone)]
pub struct MemoryBlobStore {
    blobs: Arc<RwLock<HashMap<Blake3Hash, Vec<u8>>>>,
}

impl MemoryBlobStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

/// Writer handle for in-memory blob storage.
pub struct MemoryWriteHandle {
    buffer: Vec<u8>,
}

impl AsyncWrite for MemoryWriteHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffer.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl BlobStore for MemoryBlobStore {
    type WriteHandle = MemoryWriteHandle;

    fn open_write(
        &self,
    ) -> impl std::future::Future<Output = Result<Self::WriteHandle, BlobStoreError>> + Send {
        async move { Ok(MemoryWriteHandle { buffer: Vec::new() }) }
    }

    fn close(
        &self,
        handle: Self::WriteHandle,
    ) -> impl std::future::Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let data = handle.buffer;
        let hash = Blake3Hash::from_bytes(*blake3::hash(&data).as_bytes());
        let res = self
            .blobs
            .write()
            .map(|mut guard| {
                guard.entry(hash).or_insert(data);
            })
            .map_err(|e| BlobStoreError::Backend(format!("lock poisoned: {e}")));
        async move {
            res?;
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
