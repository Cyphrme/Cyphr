//! # Storage Engine
//!
//! Coordination layer that joins [`BlobStore`] and [`Indexer`] into
//! coherent read and write paths.
//!
//! The engine does not own storage or indexing logic — it orchestrates
//! both to serve assembled responses. This is the layer that the HTTP
//! server (Phase 4) programs against.
//!
//! ## Read Path
//!
//! - [`StorageEngine::get_tip`] — current principal state (index only)
//! - [`StorageEngine::get_patch`] — commit chain + blob content (index → blobs)
//! - [`StorageEngine::get_entity`] — digest resolution + blob fetch (index → blob)
//!
//! ## Write Path
//!
//! - [`StorageEngine::ingest_commit`] — store blobs, build index entry

mod branches;
mod death;
mod error;
mod ingest;
mod kept;
mod read;
mod rebuild;
mod records;
mod resync;

use std::collections::HashMap;
use std::sync::Arc;

pub use branches::{
    BRANCH_DEPTH, BRANCH_LIMIT, BRANCH_PER_KEY, BranchEntry, BranchTip, ErrorState, ForkEvidence,
    ForkView, HeldHead, PatchBranch, Recovery, Review,
};
use branches::{BranchStore, PairKept, Retained, held_of, in_error, retained_line, stays_errored};
pub use cyphr::fork::{Assessment, Consensus, Contest, ForkPoint};
use cyphr::fork::{Held, assessed_from, assessment};
use cyphr::replay::WireBundle;
use cyphr::state::{StateDigest, TaggedDigest};
use death::{Death, DeathSet, Revoked, dead_key_in, self_revoked_keys, verify_revoke};
pub use error::EngineError;
pub use ingest::{
    BundleAnswer, CommittedTip, IngestResult, PulledAnswers, PulledOffer, ResyncOffer,
};
use ingest::{
    Durability, PrincipalLocks, StagedBuild, authenticated_signers, bundle_signer,
    canonical_bundle, disclosed_genesis, no_disclosed_genesis, record_key,
};
pub use kept::AtTip;
use kept::{
    BoundedCache, Counter, Counters, DEFAULT_KEPT_CAPACITY, Kept, KeptStates, ROOTS_MEMO_CAPACITY,
    Verified, VerifiedFuture,
};
use read::{
    ActionBundle, ActionHistory, ActionStore, EMBED_DEPTH, Frame, Frames, HeldCache, HeldRead,
    HeldTips, NoTips, PinSource, Signed, StoredChain, action_bundle, bundle_czds, replay_first,
    replay_order, signed_of,
};
pub use read::{DerivedRoots, PatchActions, PatchFork, PatchResponse, StoredEntry};
use rebuild::HealGate;
pub use rebuild::{QuarantineReason, QuarantinedManifest, RebuildReport};
use records::*;
pub use records::{
    ACTION_MANIFEST_PREFIX, BRANCH_MANIFEST_PREFIX, COMMIT_MANIFEST_PREFIX, RESYNC_RECORD_PREFIX,
    REVOKE_RECORD_PREFIX,
};
pub use resync::ResyncReceipt;
use resync::{ResyncStore, Resyncs};

use crate::KeyEntry;
use crate::blob::{Blake3Hash, BlobStore};
use crate::index::{
    CommitRef, DeriveToken, IndexableCommit, IndexableCoz, Indexer, IndexerWrite, TipState,
};

/// The engine's clock, Unix seconds; `None` before the epoch.
fn unix_now() -> Option<i64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    i64::try_from(secs).ok()
}

/// The key entries of a commit's index keys: what the engine keeps of a
/// bundle's `keys` (`alg`, `pub`, `tmb`; `tag` and `now` are unsigned
/// labels).
fn key_entries(keys: &[crate::PublicKeyInfo]) -> Vec<KeyEntry> {
    keys.iter()
        .map(|k| KeyEntry {
            alg: k.algorithm.clone(),
            pub_key: k.public_key.clone(),
            tmb: k.thumbprint.clone(),
            tag: None,
            now: None,
        })
        .collect()
}

/// The key that signed a commit: its closing `commit/create` coz, else
/// the last coz.
fn commit_signer(commit: &IndexableCommit) -> String {
    cyphr::replay::commit_signer(
        commit
            .cozies
            .iter()
            .map(|c| (c.typ.as_str(), c.tmb.as_str())),
    )
    .map(str::to_owned)
    .unwrap_or_default()
}

/// Opens each principal's commit log (its EML, a cache of its canonical
/// chain, I1) by generation. A fork resolved by re-pointing the chain
/// leaves the old log holding the abandoned branch's leaves, so the engine
/// regenerates the log into the next generation and retires the old one;
/// the factory records which generation is current, beside the logs, so a
/// restart opens it. The record names a cache, never chain state: losing
/// it costs one more regeneration.
pub trait LogFactory<S>: Send + Sync {
    /// The current generation of `principal_id`'s log: the last one
    /// [`Self::retire_below`] made current, else 0.
    ///
    /// # Errors
    ///
    /// Why the record cannot be read.
    fn generation(&self, principal_id: &str) -> Result<u64, String>;

    /// Open generation `generation` of `principal_id`'s log, independent
    /// of every other principal's and generation's. A generation above the
    /// current one opens empty.
    ///
    /// # Errors
    ///
    /// Why the log cannot be opened.
    fn open(&self, principal_id: &str, generation: u64) -> Result<S, String>;

    /// Make `generation` the current generation of `principal_id`'s log,
    /// retiring the older ones.
    ///
    /// # Errors
    ///
    /// Why the record cannot be written.
    fn retire_below(&self, principal_id: &str, generation: u64) -> Result<(), String>;

    /// Whether a log outlives the principal that wrote it, so that opening
    /// it again finds the leaves it was given. Only then can a kept
    /// [`cyphr::PrincipalState`] resume over it; for a log that does not,
    /// the engine keeps no state.
    fn durable(&self) -> bool {
        true
    }
}

/// The [`LogFactory`] of in-memory logs: every open is a fresh, empty
/// [`cyphr::eml::MemoryStorage`], so a log never outlives its principal and
/// is never stale.
pub struct MemoryLogs;

impl LogFactory<cyphr::eml::MemoryStorage> for MemoryLogs {
    fn generation(&self, _principal_id: &str) -> Result<u64, String> {
        Ok(0)
    }

    fn open(
        &self,
        _principal_id: &str,
        _generation: u64,
    ) -> Result<cyphr::eml::MemoryStorage, String> {
        Ok(cyphr::eml::MemoryStorage::new())
    }

    fn retire_below(&self, _principal_id: &str, _generation: u64) -> Result<(), String> {
        Ok(())
    }

    fn durable(&self) -> bool {
        false
    }
}

// Compile-time proof that the engine's write path is `Send` for every
// backend, so the server's multi-threaded runtime can drive it over the
// durable store: a `!Send` value held across one of its awaits fails here.
const _: () = {
    fn assert_send<T: Send>(_: &T) {}
    #[allow(dead_code)]
    fn submit_commit_is_send<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage>(
        engine: &StorageEngine<B, I, S>,
    ) {
        assert_send(&engine.submit_commit("", None, &WireBundle::default()));
    }
};

/// Coordinated storage engine joining blob and index layers.
///
/// Generic over backend implementations. Use `MemoryBlobStore` +
/// `MemoryIndexer` for tests, production backends for deployment.
///
/// The third type parameter, `S`, is the storage backend for each
/// [`cyphr::Principal`]'s Commit Tree; it defaults to
/// [`cyphr::eml::MemoryStorage`] so every existing call site that spells the
/// bare `StorageEngine<B, I>` (via [`Self::new`]) continues to mean exactly
/// what it meant before this parameter existed. A durable backend is wired
/// up via [`Self::with_log_factory`] instead.
pub struct StorageEngine<B, I, S: cyphr::eml::Storage = cyphr::eml::MemoryStorage> {
    blob_store: B,
    indexer: I,
    /// Produces a fresh, independent `S` instance for each `Principal` this
    /// engine constructs or reconstructs. Never a single `S` instance
    /// shared/aliased across multiple live principals: `eml::Storage`'s
    /// methods take `&mut self` on an owned instance, so two principals can
    /// never validly share one. Fallible because opening a real
    /// disk-backed backend can fail.
    ///
    /// Keyed by the principal's `principal_id` and the log's generation, so
    /// a factory backed by a durable, physically-shared database can give
    /// each principal (and each regeneration of its log) an isolated
    /// keyspace instead of colliding on positional Commit Tree keys.
    logs: Box<dyn LogFactory<S>>,
    /// Per-principal serialization points for [`Self::submit_commit`].
    principal_locks: PrincipalLocks,
    /// Set once [`Self::ensure_healed`] has run [`Self::rebuild_index_from_manifests`]
    /// successfully for this engine instance. See `ensure_healed`'s docs for
    /// why this is scoped per-instance rather than per-backend.
    healed: HealGate,
    /// Retained non-canonical branches and the fork reads kept between
    /// uses.
    branches: BranchStore,
    /// Accepted action-only bundles per principal id: a cache of the action
    /// manifests in the blob store (I1), filled by the rebuild scan and by
    /// ingest.
    actions: ActionStore,
    /// How each stored chain commit's blobs group into its bundle, and the
    /// keys it introduced, by principal id and commit id: a cache of the
    /// commit manifests in the blob store (I1), filled by the rebuild scan
    /// and by ingest. The index's commit records name blobs only.
    frames: Frames,
    /// Revocations in force: a cache of the revoke records in the blob
    /// store (I1), filled by the rebuild scan and by
    /// [`Self::record_revoke`].
    deaths: DeathSet,
    /// The Principal Roots each principal's held resync PoPs assert
    /// ([`Self::submit_resync`]): a cache of the resync records in the
    /// blob store (I1), filled by the rebuild scan and by acceptance.
    resyncs: ResyncStore,
    /// Each principal's verified state between its uses ([`Kept`]), and
    /// whether every use is checked against a cold replay
    /// ([`Self::with_kept_shadow`]).
    kept: KeptStates,
    /// Whether the log factory's logs outlive a replay: states are kept
    /// only over logs that do.
    logs_durable: bool,
    /// The engine's cost counters, which tests pin.
    counters: Counters,
    /// The four roots at each commit this engine admitted or derived,
    /// by principal id and commit id: a commit's roots depend on its
    /// history alone, so an entry is exact for the commit that names it.
    roots_at: BoundedCache<(String, String), DerivedRoots>,
    /// Whether a record sync has failed, and the gate that orders syncs
    /// ([`Self::persist_record`]).
    durability: Durability,
}

impl<B: BlobStore, I: Indexer + IndexerWrite> StorageEngine<B, I, cyphr::eml::MemoryStorage> {
    /// Create a new engine wrapping the given backends, with each
    /// [`cyphr::Principal`]'s Commit Tree backed by an in-memory
    /// [`cyphr::eml::MemoryStorage`] instance (discarded when the principal
    /// is dropped — full history is always replayed from the blob/index
    /// layers on the next [`Self::load_principal`]).
    ///
    /// For a durable commit-tree backend, use [`Self::with_log_factory`].
    pub fn new(blob_store: B, indexer: I) -> Self {
        Self::with_log_factory(blob_store, indexer, MemoryLogs)
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Create a new engine wrapping the given backends, with `logs` opening
    /// each [`cyphr::Principal`]'s Commit Tree storage by principal and
    /// generation ([`LogFactory`]). See [`Self`]'s `logs` field docs for why
    /// this is a factory rather than a single shared `S` instance.
    pub fn with_log_factory(blob_store: B, indexer: I, logs: impl LogFactory<S> + 'static) -> Self {
        let logs_durable = logs.durable();
        Self {
            blob_store,
            indexer,
            logs: Box::new(logs),
            principal_locks: PrincipalLocks::new(),
            healed: HealGate::new(),
            branches: BranchStore::new(DEFAULT_KEPT_CAPACITY),
            actions: ActionStore::new(),
            frames: Frames::new(),
            deaths: DeathSet::new(),
            resyncs: ResyncStore::new(),
            kept: KeptStates::new(
                if logs_durable {
                    DEFAULT_KEPT_CAPACITY
                } else {
                    0
                },
                std::env::var_os("CYPHR_KEPT_SHADOW").is_some_and(|v| v != "0"),
            ),
            logs_durable,
            counters: Counters::default(),
            roots_at: BoundedCache::new(ROOTS_MEMO_CAPACITY),
            durability: Durability::new(),
        }
    }

    /// Keep at most `capacity` principals' verified states between their
    /// uses; 0 keeps none, so every write and every read replays the
    /// principal's history from the blob store. An engine over logs that do not outlive
    /// a replay ([`LogFactory::durable`]) keeps none whatever this says.
    #[must_use]
    pub fn with_kept_states(mut self, capacity: usize) -> Self {
        self.kept = self
            .kept
            .resized(if self.logs_durable { capacity } else { 0 });
        // The fork reads are a cache of the index, not of the logs, so they
        // are kept whatever the logs do.
        self.branches.resize_forks(capacity);
        self
    }

    /// Replay cold, and compare with the kept state, every time a write
    /// or a reader would use one: a divergence is counted ([`Self::kept_divergences`]),
    /// logged, and fails the write with [`EngineError::Storage`], so a
    /// run that exercises it cannot pass over one. Also on when the
    /// `CYPHR_KEPT_SHADOW` environment variable is set and not `0`.
    #[must_use]
    pub fn with_kept_shadow(mut self, on: bool) -> Self {
        self.kept.set_shadow(on);
        self
    }

    /// [`Self::with_kept_shadow`] on an engine already built, such as one a
    /// server state owns.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_kept_shadow(&mut self, on: bool) {
        self.kept.set_shadow(on);
    }

    /// Uses of a principal, by a write or a reader, served from a kept
    /// state, over this engine's lifetime.
    pub fn kept_hits(&self) -> u64 {
        self.counters.get(Counter::KeptHits)
    }

    /// Uses of a stored principal that replayed its history because no
    /// kept state matched.
    pub fn kept_misses(&self) -> u64 {
        self.counters.get(Counter::KeptMisses)
    }

    /// Shadow checks where a kept state differed from the replay. Must be
    /// 0: a kept state is a cache of the replay, never another answer.
    pub fn kept_divergences(&self) -> u64 {
        self.counters.get(Counter::KeptDivergences)
    }

    /// Stored commits replayed by whole-chain or bounded replays, over this
    /// engine's lifetime: what a write or a root derivation cost in
    /// protocol checks.
    pub fn commits_replayed(&self) -> u64 {
        self.counters.get(Counter::CommitsReplayed)
    }

    /// Commit records this engine has read from its index, over its
    /// lifetime: what a request cost in index reads, which the replay count
    /// cannot see (a walk of the chain checks no signature).
    pub fn chain_rows_read(&self) -> u64 {
        self.counters.get(Counter::ChainRowsRead)
    }

    /// The index's commit records of `principal_id` from `from` to `to`
    /// ([`Indexer::get_commit_chain`]), counted: every chain read the
    /// engine makes goes through here.
    async fn chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Vec<CommitRef>, crate::index::IndexerError> {
        let rows = self
            .indexer
            .get_commit_chain(principal_id, from, to)
            .await?;
        self.counters.add(Counter::ChainRowsRead, rows.len() as u64);
        Ok(rows)
    }

    /// The state the next write of `principal_id` would start from if it
    /// is kept and current (the tip it stands at is the principal's tip
    /// now). A cache of the replay of the stored chain, exposed so a test
    /// can hold it to that.
    pub async fn kept_state(&self, principal_id: &str) -> Option<cyphr::PrincipalState> {
        let key = self.resolve_key(principal_id).await.ok()?;
        let stored = key.as_deref().unwrap_or(principal_id);
        let lock = self.principal_lock(stored);
        let write = Self::lock_writes(&lock, stored).await;
        let tip = self.indexer.get_tip(stored).await.ok()??;
        let kept = self.kept.copy(&write)?;
        (kept.tip == tip.commit_id).then_some(kept.state)
    }

    /// The stored principal `principal_id`, verified, at its tip: the one
    /// way a reader gets a principal's verified state (a token check, a
    /// login, a proof, a gossip round, a root derivation). `None` for a
    /// principal that is not stored.
    ///
    /// Read from the state the engine keeps when that is at the tip the
    /// index names, at the cost of the state's unshared part and no check
    /// of the history. Otherwise (after a restart, an eviction, or a write
    /// that could not leave its state kept) the stored chain is replayed
    /// once and the state kept, so the next reader and the next write are
    /// served from it. Either way it is the state the replay of the blob
    /// store builds (I1). Serialized with the principal's writes.
    ///
    /// Over logs that do not outlive a replay nothing is kept
    /// ([`LogFactory::durable`]) and every call replays.
    ///
    /// # Errors
    ///
    /// As [`Self::load_principal`].
    pub async fn at_tip(&self, principal_id: &str) -> Result<Option<AtTip<S>>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let stored = key.as_deref().unwrap_or(principal_id);
        // Asked before the lock is made: an id that names nothing must not
        // grow the lock map.
        if self.indexer.get_tip(stored).await?.is_none() {
            return Ok(None);
        }
        let lock = self.principal_lock(stored);
        let write = Self::lock_writes(&lock, stored).await;
        let Some(tip) = self.indexer.get_tip(stored).await? else {
            return Ok(None);
        };
        let verified = self.verified(stored, None, &tip, &write).await?;
        self.keep(
            verified.principal.state().clone(),
            &tip.commit_id,
            tip.commit_count,
            verified.embeds,
            &write,
        );
        Ok(Some(AtTip::new(verified.principal)))
    }

    /// How many accepted commits have had their commit-log append fail
    /// after their manifest was stored, over this engine's lifetime. Each
    /// is repaired by the next load of its principal; a count that keeps
    /// rising means the log store is failing, which the push answers alone
    /// do not show.
    pub fn log_append_failures(&self) -> u64 {
        self.counters.get(Counter::LogAppendFailures)
    }

    /// Get a reference to the underlying blob store.
    pub fn blob_store(&self) -> &B {
        &self.blob_store
    }

    /// Get a reference to the underlying indexer.
    pub fn indexer(&self) -> &I {
        &self.indexer
    }
}

/// Hash labels an identifier may carry. A bare digest is mapped to one of
/// these only by finding which labelled spelling names a stored principal
/// (or, on first push, the one the genesis derives); the label is never
/// inferred from the digest's length.
const ID_LABELS: [&str; 3] = ["SHA-256", "SHA-384", "SHA-512"];

/// The digest part of a labelled id (`ALG:digest`); an unlabelled id is
/// returned as is. This is the wire spelling SPEC §2.2.3 gives identifiers
/// by default (the engine stores the labelled spelling).
pub fn bare_digest(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, digest)| digest)
}

/// The id `genesis` derives (SPEC §3.1): the Principal Root of its genesis
/// key, by singleton promotion that key's `tmb`, in the algorithm-labelled
/// `ALG:digest` form, the one canonical spelling every storage and index
/// key uses. It keys a principal with no commit (Levels 1 and 2); a
/// genesis commit keys its principal by PG instead (see `record_key`).
///
/// # Errors
///
/// `NoActiveKeys` for an explicit genesis listing no key; otherwise the
/// protocol error genesis construction raises.
pub fn genesis_principal_id(genesis: &crate::Genesis) -> Result<String, EngineError> {
    let key = genesis.key().ok_or(cyphr::Error::NoActiveKeys)?;
    Ok(cyphr::PrincipalState::genesis(key.clone())?.pr_tagged()?)
}

/// Format all variants of a [`MultihashDigest`] as tagged digest strings (`"alg:base64url"`).
fn format_multihash_all(
    mh: &cyphr::multihash::MultihashDigest,
) -> Result<Vec<String>, EngineError> {
    mh.algorithms()
        .map(|alg| Ok(mh.tagged(alg)?.to_string()))
        .collect()
}

/// [`format_multihash_all`] for a root that may be absent: an absent root
/// formats to no variants, which readers treat as "no such root".
fn format_multihash_opt(
    mh: Option<&cyphr::multihash::MultihashDigest>,
) -> Result<Vec<String>, EngineError> {
    mh.map_or_else(|| Ok(Vec::new()), format_multihash_all)
}

#[cfg(test)]
mod tests;
