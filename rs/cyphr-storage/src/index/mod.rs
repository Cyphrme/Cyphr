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
//! The write surface ([`IndexerWrite::index_commit`], [`IndexerWrite::clear`])
//! is split onto its own trait, and every method on it takes a
//! [`DeriveToken`]. `DeriveToken` is a public type (an out-of-crate
//! backend like `cyphr-index-fjall`'s `FjallIndexer` must still be able
//! to *implement* `IndexerWrite`) whose single field is private, so only
//! code inside this crate can *construct* one. Sealing the trait's
//! implementation (a `Sealed`-supertrait) would stop a foreign crate from
//! writing a new `IndexerWrite` impl, but not from *calling* a method on
//! an already-legitimate impl like `FjallIndexer`'s — only an
//! unconstructable argument closes calls, which is why the token exists
//! instead.
//!
//! This is proved, not merely asserted: the call below is exactly what
//! an out-of-crate feature reaching for a write would write, and it MUST
//! NOT compile. The proof is that `DeriveToken::new` cannot even be
//! named from outside `cyphr-storage`, so the token the write methods
//! require can never be constructed there.
//!
//! ```compile_fail
//! use cyphr_storage::index::{DeriveToken, IndexerWrite, MemoryIndexer};
//!
//! let indexer = MemoryIndexer::new();
//! // An out-of-crate caller must not be able to reach the index's write
//! // surface directly -- only the engine's derivation path may call
//! // `clear` (or `index_commit`), and both require a `DeriveToken` this
//! // crate cannot mint (`DeriveToken::new` is private to cyphr-storage).
//! // Constructing the call is enough to prove reachability; it need not
//! // be awaited or executed.
//! let _forged_token = DeriveToken::new();
//! let _write_reachable_from_outside = indexer.clear(&_forged_token);
//! ```

#[cfg(any(test, feature = "conformance-tests"))]
pub mod conformance;
mod memory;
pub mod types;

use cyphr::state::TaggedDigest;
pub use memory::MemoryIndexer;
pub use types::*;

use crate::blob::Blake3Hash;

/// Capability token proving a write to the index originates from this
/// crate's own derivation path — the mechanism the write invariant
/// (S3a, c-unwritable) depends on. See the module docs' "Write
/// invariant" section for why this closes *calls* where a
/// sealed-supertrait alone would only close *implementations*.
pub struct DeriveToken(());

impl DeriveToken {
    /// Mint a token. Private to this crate (the tuple field is private,
    /// and this constructor is `pub(crate)`) — the engine's derivation
    /// path (`ingest_commit`, `rebuild_index_from_manifests`, `reindex`)
    /// is the intended, and only production, caller.
    pub(crate) fn new() -> Self {
        DeriveToken(())
    }

    /// Test-facing grant: mints a token outside the deriver so the
    /// shared conformance suite — and a backend's own crate-external
    /// tests, e.g. `cyphr-index-fjall/src/tests.rs` — can exercise every
    /// `IndexerWrite` method uniformly across backends without each
    /// reimplementing the deriver. Gated identically to [`conformance`]
    /// itself: `#[cfg(test)]` inside this crate, or an out-of-crate
    /// backend's `conformance-tests` feature dev-dependency (which is
    /// what actually makes this function reachable cross-crate — a
    /// plain `pub(crate)` grant would not be, since a dev-dependency
    /// compiles this crate as a genuinely external crate to the
    /// dependent).
    #[cfg(any(test, feature = "conformance-tests"))]
    pub fn for_conformance_tests() -> Self {
        DeriveToken(())
    }
}

/// Errors from [`Indexer`] operations.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// Requested entity was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-specific error (fjall, etc.).
    #[error("indexer backend error: {0}")]
    Backend(String),

    /// Internal consistency violation (e.g., duplicate commit ID).
    #[error("index consistency error: {0}")]
    Consistency(String),
}

/// The index's read surface. Public and unrestricted — revoke.rs,
/// routes.rs, and the CLI all read the index legally (ADR-0002 Decision
/// 2: only mutation is guarded, since a reader cannot violate a
/// write-path invariant). See [`IndexerWrite`] for the guarded half.
pub trait Indexer: Send + Sync {
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

/// The index's write surface. Every method requires a [`DeriveToken`],
/// constructible only inside this crate (or, under test/conformance
/// gating, via [`DeriveToken::for_conformance_tests`]) — see the module
/// docs' "Write invariant" section for why this is what actually closes
/// out-of-crate calls, not merely out-of-crate implementations.
pub trait IndexerWrite: Send + Sync {
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
        token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send;

    /// Clear the index, removing all indexed records.
    fn clear(
        &self,
        token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send;
}

#[cfg(test)]
mod tests;
