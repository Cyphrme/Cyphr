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

pub use memory::MemoryIndexer;
pub use types::*;

use cyphr::state::TaggedDigest;

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

/// Relational index over Cyphr commit history.
///
/// Implementations track the relationships between principals,
/// commits, transactions, and their digests. The index is synchronous —
/// async wrapping (actor model) is handled at the engine layer.
///
/// The index is NOT the source of truth. It is always rebuildable
/// from the BlobStore by scanning and re-parsing stored blobs.
pub trait Indexer {
    /// Record a validated commit in the index.
    ///
    /// The engine calls this after `BlobStore::put()` for each coz.
    /// The `IndexableCommit` carries pre-serialized digest strings —
    /// the indexer stores them verbatim without re-deriving state.
    ///
    /// Idempotent: re-indexing the same commit (by `commit_id`) is a no-op.
    fn index_commit(&self, commit: &IndexableCommit) -> Result<(), IndexerError>;

    /// Retrieve the current tip state for a principal.
    ///
    /// Returns `None` if the principal is unknown (never indexed).
    fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, IndexerError>;

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
    ) -> Result<Vec<CommitRef>, IndexerError>;

    /// Resolve a protocol-level tagged digest to a storage-level entity.
    ///
    /// Used for content-addressed lookup: given a `TaggedDigest`
    /// (e.g., `SHA-256:U5XUZ...`), find which blob contains it and
    /// what kind of entity it represents.
    fn resolve_digest(&self, digest: &TaggedDigest) -> Result<Option<EntityRef>, IndexerError>;

    /// List all known principals with summary metadata.
    fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError>;
}

#[cfg(test)]
mod tests;
