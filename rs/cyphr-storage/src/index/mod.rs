//! # Relational Index
//!
//! Backend-agnostic trait for relational indexing of Cyphr commits.
//!
//! The index is a secondary projection of the BlobStore — always
//! rebuildable by scanning blobs and re-parsing. It accelerates
//! queries that the content-addressed blob layer cannot serve
//! efficiently: tip lookups, commit chain traversal, digest resolution.
//!
//! ## Implementations
//!
//! - [`MemoryIndexer`] — `HashMap`-backed (testing)
//! - `SqliteIndexer` — SQLite-backed (production, Phase 2b)

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
