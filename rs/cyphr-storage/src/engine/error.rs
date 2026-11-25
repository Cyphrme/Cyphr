//! Error types for the storage engine.

use crate::blob::BlobStoreError;
use crate::index::IndexerError;

/// Errors from [`super::StorageEngine`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// Propagated from the blob store backend.
    #[error("blob store: {0}")]
    BlobStore(#[from] BlobStoreError),

    /// Propagated from the indexer backend.
    #[error("indexer: {0}")]
    Indexer(#[from] IndexerError),

    /// The record could not be made durable, now or at an earlier write.
    /// Until the process restarts the engine refuses every write: a sync
    /// that failed may have dropped the pages it covered, so a later sync
    /// that succeeds proves nothing about them, and a signature over a
    /// commit those pages held would attest state a power cut can erase.
    #[error("record not durable, writes refused until restart: {0}")]
    DurabilityLost(String),

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

    /// A coz dated at or after its key's naked revoke is signed by that
    /// key (SPEC 6.4).
    #[error("signed by a revoked key: {key}")]
    DeadKey {
        /// Thumbprint of the revoked key (base64url).
        key: String,
    },

    /// A rival signed by `key` is refused and nothing of it stored: `key`
    /// already holds [`BRANCH_PER_KEY`](super::BRANCH_PER_KEY) retained
    /// rivals of this principal, or the principal already holds
    /// [`BRANCH_LIMIT`](super::BRANCH_LIMIT) in all. The per-key quota is
    /// what stops one key from filling the slots other keys' rivals need.
    #[error("branch limit reached: no slot left for a rival signed by key {key}")]
    BranchLimit {
        /// Thumbprint of the key that signed the refused rival.
        key: String,
    },

    /// A commit was admitted through the embedded principal `member` at its
    /// PR `b`, and the commits `b` descends from are not all held: blobs were
    /// lost. The commit is not replayable; it is never read as opaque.
    #[error("embedded principal {member} at PR {b} is not replayable: its ancestry is not held")]
    EmbeddedPinLost {
        /// The digest in the embedding principal's Key Tree.
        member: String,
        /// The PR the commit was admitted against.
        b: String,
    },

    /// The principal is in Error (SPEC 15.5: an unresolved fork) and the
    /// bundle does not resolve it, so it is refused. A refused commit that
    /// verifies on a held branch is kept as evidence.
    #[error("principal {principal_id} is in Error: only a fork resolution is admitted")]
    Errored {
        /// The principal's storage key.
        principal_id: String,
    },

    /// The engine's commit-tree storage factory failed to produce a fresh
    /// storage instance for a `Principal`.
    #[error("storage: {0}")]
    Storage(String),
}

impl EngineError {
    /// Whether this is a fault of the store rather than its verdict on what
    /// it was offered. A refusal is an answer (a held commit, a fork kept as
    /// evidence); a fault, a failed sync included, means nothing a round
    /// reports as kept is durable.
    #[must_use]
    pub fn is_store_fault(&self) -> bool {
        matches!(
            self,
            Self::BlobStore(_) | Self::Indexer(_) | Self::Storage(_) | Self::DurabilityLost(_)
        )
    }
}
