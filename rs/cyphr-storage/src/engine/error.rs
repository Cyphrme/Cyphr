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

    /// A coz dated at or after its key's naked revoke is signed by, or
    /// introduces, that key (SPEC 6.4).
    #[error("{} a revoked key: {key}", if *introduced { "introduces" } else { "signed by" })]
    DeadKey {
        /// Thumbprint of the revoked key (base64url).
        key: String,
        /// Whether the coz introduces the key rather than being signed by it.
        introduced: bool,
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

    /// A coz is signed by no key of the principal, and the principal's Key
    /// Tree holds digests that may be embedded principals (SPEC 10.3). The
    /// engine resolves no embedded principal's tip, so it cannot tell an
    /// embedded member's key from an unknown one and refuses the bundle as
    /// unsupported rather than as an unknown key.
    #[error(
        "embedded unsupported: signer {signer} is no key of this principal, whose Key Tree may \
         embed principals; this engine resolves no embedded principal"
    )]
    EmbeddedUnsupported {
        /// Thumbprint of the coz's signer.
        signer: String,
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
