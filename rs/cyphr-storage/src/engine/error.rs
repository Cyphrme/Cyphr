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

    /// The wire blob store holds a blob shaped like a commit manifest.
    /// Manifests live apart from wire blobs; a manifest-shaped wire blob
    /// is either an old shared-store manifest or a forged one, and
    /// nothing here can tell which, so it is never indexed.
    #[error("legacy manifest-shaped blob {hash} in the wire blob store; re-ingest from the wire")]
    LegacyManifest {
        /// BLAKE3 hash of the offending blob.
        hash: crate::blob::Blake3Hash,
    },

    /// A stored manifest is not bound to the blobs it names: its principal
    /// id is not the genesis-derived id of that principal's sequence-0
    /// blobs. Nothing was indexed.
    #[error("manifest {manifest} is not bound to principal {principal_id}: {reason}")]
    ManifestUnbound {
        /// BLAKE3 hash of the offending manifest blob.
        manifest: crate::blob::Blake3Hash,
        /// The principal id the manifest claims.
        principal_id: String,
        /// Why the binding failed.
        reason: String,
    },

    /// The engine's commit-tree storage factory failed to produce a fresh
    /// storage instance for a `Principal`.
    #[error("storage: {0}")]
    Storage(String),
}
