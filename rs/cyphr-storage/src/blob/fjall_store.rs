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

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

/// Writer handle for Fjall-backed blob storage.
pub struct FjallWriteHandle {
    buffer: Vec<u8>,
}

impl AsyncWrite for FjallWriteHandle {
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

impl BlobStore for FjallBlobStore {
    type WriteHandle = FjallWriteHandle;

    async fn open_write(&self) -> Result<Self::WriteHandle, BlobStoreError> {
        Ok(FjallWriteHandle { buffer: Vec::new() })
    }

    fn close(
        &self,
        handle: Self::WriteHandle,
    ) -> impl std::future::Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let data = handle.buffer;
        let hash = Blake3Hash::from_bytes(*blake3::hash(&data).as_bytes());
        let res = self
            .blobs
            .insert(hash.as_bytes(), data)
            .map_err(|e| BlobStoreError::Backend(format!("fjall insert: {e}")));
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
        let blobs = self.blobs.clone();
        async move {
            let result = blobs
                .get(hash.as_bytes())
                .map_err(|e| BlobStoreError::Backend(format!("fjall get: {e}")))?;
            Ok(result.map(|slice| slice.to_vec()))
        }
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, BlobStoreError>> + Send {
        let hash = *hash;
        let blobs = self.blobs.clone();
        async move {
            blobs
                .contains_key(hash.as_bytes())
                .map_err(|e| BlobStoreError::Backend(format!("fjall contains_key: {e}")))
        }
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
        async move {
            let iter = blobs.iter();
            let mut hashes = Vec::new();
            for result in iter {
                let (key, _) =
                    result.map_err(|e| BlobStoreError::Backend(format!("fjall iter: {e}")))?;
                let key_bytes: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                    BlobStoreError::Backend(format!("fjall key length {}, expected 32", key.len()))
                })?;
                hashes.push(Blake3Hash::from_bytes(key_bytes));
            }
            let iter: Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send> =
                Box::new(hashes.into_iter().map(Ok));
            Ok(iter)
        }
    }
}
