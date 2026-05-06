//! Error types for the storage engine.

use crate::blob::BlobStoreError;
use crate::index::IndexerError;

/// Errors from [`super::StorageEngine`] operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Propagated from the blob store backend.
    #[error("blob store: {0}")]
    BlobStore(#[from] BlobStoreError),

    /// Propagated from the indexer backend.
    #[error("indexer: {0}")]
    Indexer(#[from] IndexerError),

    /// Requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Caller-provided input was invalid.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Propagated from Principal replay (import/load).
    #[error("load: {0}")]
    Load(#[from] crate::import::LoadError),

    /// Propagated from the Cyphr protocol layer.
    #[error("protocol: {0}")]
    Protocol(#[from] cyphr::Error),

    /// Raw blob bytes failed JSON parsing.
    #[error("malformed blob: {0}")]
    MalformedBlob(String),
}
