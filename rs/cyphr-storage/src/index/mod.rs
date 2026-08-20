//! # Index
//!
//! Backend-agnostic trait for indexing Cyphr commits.
//!
//! The index is a secondary projection of the BlobStore — always
//! rebuildable by scanning blobs and re-parsing. It accelerates
//! queries that the content-addressed blob layer cannot serve
//! efficiently: tip lookups, commit chain traversal, digest resolution.
//!
//! ## Implementations
//!
//! - [`MemoryIndexer`] — `HashMap`-backed (testing)
//! - `FjallIndexer` (in `cyphr-index-fjall`) — fjall KV-backed (production)
//!
//! ## Write invariant (S3a, c-unwritable)
//!
//! The index is a strictly DERIVED projection: every write must
//! originate from the engine's own derivation path (blob-store record →
//! index entry), never from an out-of-crate caller reaching a write
//! method directly. That path is `StorageEngine::ingest_commit`,
//! `StorageEngine::rebuild_index_from_manifests`, and `StorageEngine::reindex`
//! — all inside `cyphr-storage`'s `engine` module — and nowhere else.
//!
//! This is proved, not merely asserted: the call below is exactly what
//! an out-of-crate feature reaching for a write would write, and it MUST
//! NOT compile. Today it does — the write half is not yet sealed off
//! from the read half — so this doctest is a deliberate, tracked
//! baseline failure: `cargo test -p cyphr-storage --doc` reports it as
//! "expected this to not compile, but it compiled". Whoever seals the
//! write surface (S3a's sealing mechanism, delegated in the campaign
//! IBC) drives this doctest to genuinely fail to compile — updating the
//! call's exact syntax to match the chosen shape is expected; weakening
//! or deleting the assertion it makes is not.
//!
//! ```compile_fail
//! use cyphr_storage::index::{Indexer, MemoryIndexer};
//!
//! let indexer = MemoryIndexer::new();
//! // An out-of-crate caller must not be able to reach the index's write
//! // surface directly -- only the engine's derivation path may call
//! // `clear` (or `index_commit`). Constructing the call is enough to
//! // prove reachability; it need not be awaited or executed.
//! let _write_reachable_from_outside = indexer.clear();
//! ```

#[cfg(any(test, feature = "conformance-tests"))]
pub mod conformance;
mod memory;
pub mod types;

use cyphr::state::TaggedDigest;
pub use memory::MemoryIndexer;
pub use types::*;

use crate::blob::Blake3Hash;

/// Errors from [`Indexer`] operations.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// Requested entity was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-specific error (SQLite, etc.).
    #[error("indexer backend error: {0}")]
    Backend(String),

    /// Internal consistency violation (e.g., duplicate commit ID).
    #[error("index consistency error: {0}")]
    Consistency(String),
}

pub trait Indexer: Send + Sync {
    /// Record a validated commit in the index.
    ///
    /// The engine calls this after storing coz blobs.
    /// The `IndexableCommit` carries pre-serialized digest strings —
    /// the indexer stores them verbatim without re-deriving state.
    ///
    /// Idempotent: re-indexing the same commit (by `commit_id`) is a no-op.
    fn index_commit(
        &self,
        commit: &IndexableCommit,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send;

    /// Retrieve the current tip state for a principal.
    ///
    /// Returns `None` if the principal is unknown (never indexed).
    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send;

    /// Retrieve the commit chain between two sequence numbers.
    ///
    /// Returns commits in sequence order, inclusive of both endpoints.
    /// If `from` is `None`, starts from genesis. If `to` is `None`,
    /// extends to the current tip.
    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send;

    /// Resolve a protocol-level tagged digest to a storage-level entity.
    ///
    /// Used for content-addressed lookup: given a `TaggedDigest`
    /// (e.g., `SHA-256:U5XUZ...`), find which blob contains it and
    /// what kind of entity it represents.
    fn resolve_digest(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<EntityRef>, IndexerError>> + Send;

    /// List all known principals with summary metadata.
    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send;

    /// Clear the index, removing all indexed records.
    fn clear(&self) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send;

    /// Verify if a specific raw blob hash has already been indexed.
    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send;

    /// Retrieve public key metadata by thumbprint.
    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send;
}

#[cfg(test)]
mod tests;
