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

    /// A lookup key names several principals (a Principal Root held by
    /// more than one, or a resync anchor held at several positions of one
    /// chain), so no single one can be chosen. Address the principal by a
    /// key that is unique to it, its PG.
    #[error("ambiguous: {0}")]
    Ambiguous(String),

    /// Propagated from Principal replay (import/load).
    #[error("load: {0}")]
    Load(#[from] crate::import::LoadError),

    /// Propagated from the Cyphr protocol layer.
    #[error("protocol: {0}")]
    Protocol(#[from] cyphr::Error),

    /// Raw blob bytes failed JSON parsing.
    #[error("malformed blob: {0}")]
    MalformedBlob(String),

    /// The wire blob store holds a blob shaped like a commit manifest.
    /// Manifests live apart from wire blobs; a manifest-shaped wire blob
    /// is either an old shared-store manifest or a forged one, and
    /// nothing here can tell which, so it is never indexed.
    #[error("legacy manifest-shaped blob {hash} in the wire blob store; re-ingest from the wire")]
    LegacyManifest {
        /// BLAKE3 hash of the offending blob.
        hash: crate::blob::Blake3Hash,
    },

    /// The principal already has [`BRANCH_LIMIT`](super::BRANCH_LIMIT)
    /// retained branches, so this fork is refused and nothing of it stored.
    #[error("branch limit reached: principal already has the maximum retained branches")]
    BranchLimit,

    /// The engine's commit-tree storage factory failed to produce a fresh
    /// storage instance for a `Principal`.
    #[error("storage: {0}")]
    Storage(String),
}
