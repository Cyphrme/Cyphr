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
//! `StorageEngine::rebuild_index_from_manifests`, and `StorageEngine::rebuild_index_from_scratch`
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
    /// path (`ingest_commit`, `rebuild_index_from_manifests`, `rebuild_index_from_scratch`)
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

    /// A write would re-point a PG alias that already names a different
    /// principal. Nothing was written. (Digests are never exclusive.)
    #[error("index conflict: {0}")]
    Conflict(String),

    /// The stored index was written by a newer build than this one reads
    /// (a downgrade). Nothing was read or changed. An OLDER index is not an
    /// error: the index is a rebuildable cache (I1) and is discarded. The
    /// text names the variant so the refusal stays identifiable when a
    /// caller flattens it to a message.
    #[error(
        "UnsupportedVersion: index schema version {found} is newer than the supported \
         {supported}; refusing to read it"
    )]
    UnsupportedVersion {
        /// Version recorded in the store.
        found: u64,
        /// Newest version this build reads.
        supported: u64,
    },
}

/// Every `(digest, holder)` pair `commit` contributes to the digest table:
/// each coz's blob hash and czd, then the commit IDs and the PR, SR, AR and
/// CR variants. A digest is never an exclusive claim: SPEC 7.6 lets
/// principals that share keys reuse a coz, and two principals can honestly
/// reach the same state or auth root, so each digest names the set of its
/// holders (see [`merge_holder`]).
///
/// # Errors
///
/// [`IndexerError::Consistency`] when the commit names no blob.
pub fn digest_entries(commit: &IndexableCommit) -> Result<Vec<(String, EntityRef)>, IndexerError> {
    let first_blob = commit
        .blob_hashes
        .first()
        .copied()
        .ok_or_else(|| IndexerError::Consistency("commit has no blob hashes".into()))?;
    let holder = |digest: &str, blob_hash, entity_type, principal_root| EntityRef {
        digest: digest.to_string(),
        blob_hash,
        entity_type,
        sequence: Some(commit.sequence),
        principal_id: Some(commit.principal_id.clone()),
        principal_root,
    };
    let mut entries = Vec::new();
    for coz in &commit.cozies {
        let entity_type = coz_entity_type(&coz.typ);
        for digest in [coz.blob_hash.to_string(), coz.czd.clone()] {
            entries.push((
                digest.clone(),
                holder(&digest, coz.blob_hash, entity_type, false),
            ));
        }
    }
    for variant in commit
        .commit_ids
        .iter()
        .chain(&commit.prs)
        .chain(&commit.srs)
        .chain(&commit.ars)
        .chain(&commit.crs)
    {
        entries.push((
            variant.clone(),
            holder(
                variant,
                first_blob,
                EntityType::Commit,
                commit.prs.contains(variant),
            ),
        ));
    }
    Ok(entries)
}

/// Add `new` to a digest's holders so the result does not depend on the
/// order commits arrive in. A holder is a `(principal, entity type)`: one
/// principal repeating a root (a commit that leaves SR unchanged) keeps the
/// holder at the latest sequence, and holders at the same sequence merge
/// their `principal_root` flags. The list stays sorted by principal id,
/// entity type, then sequence.
pub fn merge_holder(holders: &mut Vec<EntityRef>, new: EntityRef) {
    match holders
        .iter_mut()
        .find(|h| h.principal_id == new.principal_id && h.entity_type == new.entity_type)
    {
        Some(held) if new.sequence > held.sequence => *held = new,
        Some(held) if new.sequence == held.sequence => held.principal_root |= new.principal_root,
        Some(_) => {},
        None => holders.push(new),
    }
    holders.sort_by(|a, b| {
        (&a.principal_id, a.entity_type as u8, a.sequence).cmp(&(
            &b.principal_id,
            b.entity_type as u8,
            b.sequence,
        ))
    });
}

/// Whether a coz of this `typ` is indexed as an action or a transaction.
pub fn coz_entity_type(typ: &str) -> EntityType {
    if typ.starts_with("cyphr/action") || typ.contains("/action") {
        EntityType::Action
    } else {
        EntityType::Transaction
    }
}

/// The index's read surface. Public and unrestricted — revoke.rs,
/// routes.rs, and the CLI all read the index legally (ADR-0002 Decision
/// 2: only mutation is guarded, since a reader cannot violate a
/// write-path invariant). See [`IndexerWrite`] for the guarded half.
pub trait Indexer: Send + Sync {
    /// Retrieve the current tip state for a principal.
    ///
    /// Returns `None` if the principal is unknown (never indexed).
    ///
    /// `principal_id` may also be any hash variant of the principal's PG
    /// (SPEC §3.7.1/§12.1): such an alias resolves to the one stored
    /// principal. A historical PR is not an alias. The alias table is
    /// derived from the `pg` of the PG-establishing commit and rebuilt with
    /// the index (I1); a
    /// stored principal id always outranks an alias, and an unknown or
    /// forged label resolves to nothing.
    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<TipState>, IndexerError>> + Send;

    /// Whether the principal stored under exactly `principal_id` has
    /// established its PG (an indexed commit carried `pg`). A cheap marker
    /// so a caller can refuse a PG-to-be claim without replaying history.
    /// Derived state, rebuilt with the index (I1).
    fn is_pg_established(
        &self,
        principal_id: &str,
    ) -> impl std::future::Future<Output = Result<bool, IndexerError>> + Send;

    /// Retrieve the commit chain between two sequence numbers.
    ///
    /// Returns commits in sequence order, inclusive of both endpoints.
    /// If `from` is `None`, starts from genesis. If `to` is `None`,
    /// extends to the current tip. Resolves aliases as [`Self::get_tip`].
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

    /// Every holder of a digest, in a canonical order (principal id, then
    /// entity type, then sequence). One signed coz may live in several
    /// principals (SPEC 7.6 lets principals that share keys reuse a coz),
    /// and two principals can honestly share a state or auth root, so a
    /// digest names a set, not a single entity. Empty when unknown.
    ///
    /// The default is the single-holder answer of [`Self::resolve_digest`];
    /// a backend that stores several holders overrides it.
    fn resolve_digest_holders(
        &self,
        digest: &TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Vec<EntityRef>, IndexerError>> + Send {
        let single = self.resolve_digest(digest);
        async move { Ok(single.await?.into_iter().collect()) }
    }

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
    /// Dry run of [`Self::index_commit`]'s one refusal: `Err(Conflict)`
    /// exactly when indexing `commit` would re-point a PG alias that names
    /// another principal; `Ok` for a commit that is already indexed. Writes
    /// nothing. The engine calls it before its first durable write, so a
    /// refused commit leaves no blob or manifest behind.
    fn check_commit(
        &self,
        commit: &IndexableCommit,
        token: &DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), IndexerError>> + Send;

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
