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
mod kept;
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
use death::{Death, DeathSet, Revoked, dead_key_in, verify_revoke};
pub use error::EngineError;
pub use kept::AtTip;
use kept::{
    BoundedCache, Counter, Counters, DEFAULT_KEPT_CAPACITY, Kept, KeptStates, ROOTS_MEMO_CAPACITY,
    Verified, VerifiedFuture,
};
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

/// A commit's metadata paired with its bundle.
///
/// The bundle's cozies, in bundle order ([`WireBundle::cozies`]), are the
/// blobs `commit.blob_hashes` names, in order.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// Commit metadata from the index.
    pub commit: CommitRef,
    /// The commit's bundle, grouped by transaction as it was accepted.
    pub bundle: WireBundle,
}

/// Response from [`StorageEngine::get_patch`].
#[derive(Debug, Clone)]
pub struct PatchResponse {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Ordered commit entries with their blob contents.
    pub entries: Vec<PatchEntry>,
    /// The chain position the range starts at: the position just after the
    /// resync anchor, whichever algorithm spelled it; `None` for a full
    /// chain. An empty range with `from == tip.commit_count` is caught up.
    pub from: Option<u64>,
    /// Every action-only bundle the principal holds, by its earliest
    /// `now` (SPEC 4.8.1): actions hold no chain position, so a range
    /// bounds the commits only.
    pub actions: Vec<PatchActions>,
    /// In Error, for [`StorageEngine::get_served_patch`]: the fork point and
    /// each branch from it; `entries` then end below the fork point.
    /// `None` while Active, and always for `get_patch`.
    pub fork: Option<PatchFork>,
}

/// An Error principal's patch beyond the common chain.
#[derive(Debug, Clone)]
pub struct PatchFork {
    /// Where the branches part.
    pub fork_point: ForkPoint,
    /// Each branch, ordered by head commit id.
    pub branches: Vec<PatchBranch>,
}

/// One accepted action-only bundle (SPEC 4.8.1): its actions are recorded
/// in DT, not chained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchActions {
    /// The action cozies' raw blobs.
    pub blobs: Vec<Vec<u8>>,
}

/// Post-commit roots re-derived directly from the authoritative blob store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DerivedRoots {
    pub pr: String,
    /// `None` for a Dead principal with no data.
    pub sr: Option<String>,
    /// `None` for a Dead principal.
    pub ar: Option<String>,
    pub cr: String,
}

/// Result from [`StorageEngine::ingest_commit`] and
/// [`StorageEngine::submit_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// The canonical (genesis-derived) id the commit was stored under, which
    /// may differ from the spelling the caller submitted. Read back under
    /// this id: a claimed alias can stop resolving once the commit moves
    /// the principal's state.
    pub principal_id: String,
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
    /// BLAKE3 hash of this commit's durable [`CommitManifest`] blob.
    ///
    /// `None` for an action-only bundle (`submit_commit`'s action-only
    /// branch): no commit was formed, so there is no commit manifest (its
    /// actions are kept under an action manifest instead).
    pub manifest_hash: Option<Blake3Hash>,
    /// The tip this commit produced, computed during ingest from the same
    /// replayed state the index entry is written from, so a caller can
    /// report the committed state without re-reading the index (a re-read
    /// is a fallible step AFTER the commit is durable).
    ///
    /// For an action-only bundle no commit was formed, so this is the
    /// principal's unchanged tip, or `None` if it has no committed state.
    pub tip: Option<CommittedTip>,
}

/// The principal's tip immediately after one accepted commit, as the
/// indexer records it (primary-algorithm variant of each root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTip {
    /// The commit's 0-indexed position in the principal's chain.
    pub sequence: u64,
    /// Commit ID (tagged digest).
    pub commit_id: String,
    /// Principal Root after the commit.
    pub pr: String,
    /// State Root after the commit (`None` if absent).
    pub sr: Option<String>,
    /// Auth Root after the commit (`None` if absent).
    pub ar: Option<String>,
    /// Commit Root after the commit (empty if the EML log has no leaf yet,
    /// matching [`TipState::cr`]).
    pub cr: String,
}

impl CommittedTip {
    /// The tip `commit` leaves: the first (primary-algorithm) variant of
    /// each digest, the same selection every [`Indexer`] applies when it
    /// writes its tip, so this equals what a `get_tip` would then return.
    fn of(commit: &IndexableCommit) -> Self {
        let first = |v: &[String]| v.first().cloned().unwrap_or_default();
        Self {
            sequence: commit.sequence,
            commit_id: first(&commit.commit_ids),
            pr: first(&commit.prs),
            sr: commit.srs.first().cloned(),
            ar: commit.ars.first().cloned(),
            cr: first(&commit.crs),
        }
    }
}

/// Stored commits of one principal, replayable: each commit's entry and
/// the embedded principals it was admitted through, by position.
#[derive(Default)]
struct StoredChain {
    entries: Vec<crate::CommitEntry>,
    pins: Vec<Vec<EmbeddedPin>>,
    /// Each commit's PR, the first (primary) spelling.
    prs: Vec<String>,
}

/// A commit B holds, canonical or retained: what walking a PR's ancestry by
/// `pre` needs to know before loading it.
struct HeldCommit<'m> {
    sequence: u64,
    pr: String,
    pre: Option<String>,
    origin: HeldOrigin<'m>,
}

enum HeldOrigin<'m> {
    Canonical(crate::index::CommitRef),
    Retained(Box<Retained>),
    Manifest(&'m CommitManifest),
}

/// Where the principals a commit was admitted through are read from: the
/// engine's index, or, when rebuilding the index, the manifests being
/// replayed (the index is not built yet). It also holds the memo of one
/// call: each embedded principal's chain replayed once, forward, however
/// many states of it the call pins. A fold of held blobs dropped with the
/// call, never a cache that outlives it.
struct PinSource<'m> {
    /// The canonical manifests and the rest (displaced and retained).
    manifests: Option<ManifestLists<'m>>,
    memo: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<ChainMemo>>>>>,
}

type ManifestLists<'m> = (
    &'m [(Blake3Hash, CommitManifest)],
    &'m [(Blake3Hash, CommitManifest)],
);

/// An embedded principal's chain replayed as far as the call needed, with
/// the state at each PR passed.
struct ChainMemo {
    chain: StoredChain,
    principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    next: usize,
    at: HashMap<String, cyphr::PrincipalState>,
}

impl<'m> PinSource<'m> {
    fn stored() -> Self {
        Self {
            manifests: None,
            memo: std::sync::Mutex::default(),
        }
    }

    fn manifests(
        canonical: &'m [(Blake3Hash, CommitManifest)],
        rest: &'m [(Blake3Hash, CommitManifest)],
    ) -> Self {
        Self {
            manifests: Some((canonical, rest)),
            memo: std::sync::Mutex::default(),
        }
    }

    fn slot(&self, member: &str) -> Arc<tokio::sync::Mutex<Option<ChainMemo>>> {
        self.memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(member.to_string())
            .or_default()
            .clone()
    }
}

/// The held tips of embedded principals read during one call, by the digest
/// that names them (`None`: it names no held principal): each principal is
/// replayed once however many candidate states of the principal embedding it
/// the call tries. Dropped with the call, never a cache across calls.
type HeldCache<S> = HashMap<String, Option<HeldTip<S>>>;

/// A held embedded principal: the tip it gives, the PR it stands at, and the
/// principal itself.
type HeldTip<S> = (cyphr::Tip, String, cyphr::Principal<S>);

/// What reading a held tip yields, boxed ([`StorageEngine::held_tip`]).
type HeldRead<'a, S> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<HeldTip<S>>, EngineError>> + Send + 'a>,
>;

/// The tips of embedded principals this engine holds, for the core to
/// follow ([`StorageEngine::follow_held`]): the engine's own store, never a
/// network. A failure to read a held principal is kept, not swallowed, and
/// the digest meanwhile has no tip (fails closed).
struct HeldTips<'e, B, I, S: cyphr::eml::Storage> {
    engine: &'e StorageEngine<B, I, S>,
    own_id: &'e str,
    cache: &'e mut HeldCache<S>,
    /// The followed digests that name a held principal, read from `cache`.
    found: std::collections::BTreeSet<String>,
    failed: Option<EngineError>,
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> cyphr::TipSource
    for HeldTips<'_, B, I, S>
{
    async fn tip(&mut self, member: &str) -> Option<cyphr::Tip> {
        if !self.cache.contains_key(member) {
            match self.engine.held_tip(member, self.own_id).await {
                Ok(held) => {
                    self.cache.insert(member.to_string(), held);
                },
                Err(e) => {
                    self.failed.get_or_insert(e);
                    return None;
                },
            }
        }
        let (tip, ..) = self.cache.get(member)?.as_ref()?;
        self.found.insert(member.to_string());
        Some(tip.clone())
    }
}

/// A [`cyphr::TipSource`] that holds no tip.
struct NoTips;

impl cyphr::TipSource for NoTips {
    async fn tip(&mut self, _member: &str) -> Option<cyphr::Tip> {
        None
    }
}

/// How many embedded principals may nest when a pin is replayed. A pin
/// names a state held before its commit was admitted, so the real depth is
/// finite; the bound is for a store that forged a cycle.
const EMBED_DEPTH: u8 = 16;

/// What the index's commit record lacks for a stored chain commit: how its
/// blobs group into its bundle and the keys it introduced (to serve the
/// bundle), who signed it when (to judge it against a revocation), and
/// when it was first seen.
#[derive(Debug, Clone)]
struct Frame {
    shape: Shape,
    keys: Vec<KeyEntry>,
    signed: Signed,
    seen: Option<i64>,
    embedded: Vec<EmbeddedPin>,
}

/// The thumbprints that signed a commit's cozies, in coz order: who
/// settled a fork ([`Contest::by`]).
type Signed = Vec<String>;

fn signed_of(commit: &IndexableCommit) -> Signed {
    commit.cozies.iter().map(|c| c.tmb.clone()).collect()
}

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

/// An action-only bundle read back for replay.
struct ActionBundle {
    manifest: Blake3Hash,
    blobs: Vec<Blake3Hash>,
    embedded: Vec<EmbeddedPin>,
    bundle: cyphr::replay::Bundle,
}

impl ActionBundle {
    /// The engine's record of this bundle.
    fn stored(self) -> StoredActions {
        StoredActions {
            manifest: self.manifest,
            blobs: self.blobs,
            embedded: self.embedded,
        }
    }
}

/// A principal's action-only bundles, in replay order ([`replay_order`]).
type ActionHistory = Vec<ActionBundle>;

/// The key that signed a commit: its closing `commit/create` coz, else
/// the last coz.
fn commit_signer(commit: &IndexableCommit) -> String {
    commit
        .cozies
        .iter()
        .rev()
        .find(|c| is_commit_create_typ(&c.typ))
        .or(commit.cozies.last())
        .map(|c| c.tmb.clone())
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

/// Proof that the caller holds the write lock of one named principal:
/// built only by [`StorageEngine::lock_writes`] from that principal's own
/// lock, so another keyed lock (revoke, log generation, alias) cannot stand
/// for it.
struct WriteLock<'a> {
    principal: String,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl WriteLock<'_> {
    /// The one principal this lock is the write lock of.
    fn principal(&self) -> &str {
        &self.principal
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

/// A pushed bundle verified into the commit it forms, nothing yet written:
/// the commit's index record and the staged core commit whose log append
/// follows the blob store's record of it ([`StorageEngine::ingest_commit`]).
pub(crate) struct StagedBuild<'p, T: cyphr::eml::Storage> {
    commit: IndexableCommit,
    staged: cyphr::replay::StagedBundle<'p, T>,
    /// The embedded principals the commit was authorized through, set by
    /// the admission path that followed them; empty on a replay.
    embedded: Vec<EmbeddedPin>,
}

/// What a verified bundle forms ([`StorageEngine::build_staged`]).
pub(crate) enum Built<'p, T: cyphr::eml::Storage> {
    /// A commit, its log append not yet made.
    Commit(Box<StagedBuild<'p, T>>),
    /// Actions alone, verified and not yet held.
    Actions(cyphr::replay::StagedBundle<'p, T>),
}

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
    ///
    /// Keyed-mutex map: each `principal_id` gets its own
    /// `tokio::sync::Mutex`, so concurrent writers for the *same* principal
    /// serialize (each submit opens the principal's one durable log, so two
    /// at once would be two writers of it) while writers for *different*
    /// principals never contend. The outer
    /// `std::sync::Mutex` only ever guards the fast, non-blocking
    /// get-or-insert into the map itself, never the write critical section.
    ///
    /// Entries are never removed: the map's memory footprint grows with the
    /// number of distinct principals ever written to over the engine's
    /// lifetime. Acceptable for this in-process precursor (see root
    /// `AGENTS.md` I2); bounding it is future work alongside the
    /// cross-process write serialization this node explicitly defers.
    principal_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
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
    actions: std::sync::Mutex<HashMap<String, Vec<StoredActions>>>,
    /// How each stored chain commit's blobs group into its bundle, and the
    /// keys it introduced, by principal id and commit id: a cache of the
    /// commit manifests in the blob store (I1), filled by the rebuild scan
    /// and by ingest. The index's commit records name blobs only.
    frames: std::sync::Mutex<HashMap<(String, String), Frame>>,
    /// Revocations in force: a cache of the revoke records in the blob
    /// store (I1), filled by the rebuild scan and by
    /// [`Self::record_revoke`].
    deaths: DeathSet,
    /// The Principal Roots each principal's held resync PoPs assert
    /// ([`Self::submit_resync`]): a cache of the resync records in the
    /// blob store (I1), filled by the rebuild scan and by acceptance.
    resyncs: ResyncStore,
    /// Stored commits [`Self::retain_rival`] has replayed, ever. Retention
    /// is paid by refused bundles, so its cost is the quantity tests pin.
    /// Candidate positions [`Self::retain_rival`] has tried a bundle at.
    /// Commits whose manifest was stored but whose commit-log append failed
    /// ([`Self::log_append_failures`]): the log is behind until the next
    /// load repairs it.
    /// Each principal's verified state between its uses ([`Kept`]).
    kept: KeptStates,
    /// Whether the log factory's logs outlive a replay: states are kept
    /// only over logs that do.
    logs_durable: bool,
    /// Check every kept-state use against a cold replay
    /// ([`Self::with_kept_shadow`]).
    counters: Counters,
    /// Writes served from a kept state, and writes that replayed.
    /// Shadow checks where the kept state was not the replayed one.
    /// Stored commits re-applied by any replay path ([`Self::replay_pinned`]), ever.
    /// Not counted: commits re-applied while following embedded principals,
    /// and the re-application a rebuild of the index does.
    /// Commit records read from the index by [`Self::chain`], ever.
    /// The four roots at each commit this engine admitted or derived,
    /// by principal id and commit id: a commit's roots depend on its
    /// history alone, so an entry is exact for the commit that names it.
    roots_at: BoundedCache<(String, String), DerivedRoots>,
    /// Set by the first failed [`Self::persist_record`], never cleared: the
    /// engine refuses every write from then on ([`EngineError::DurabilityLost`]).
    durability_lost: std::sync::atomic::AtomicBool,
    /// Held for the whole of a record sync and the flag changes around it
    /// ([`Self::persist_record`]), so a sync queued behind a failed one
    /// finds the flag set instead of trusting a success over pages the
    /// failure dropped.
    sync_gate: tokio::sync::Mutex<()>,
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
            principal_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            healed: HealGate::new(),
            branches: BranchStore::new(DEFAULT_KEPT_CAPACITY),
            actions: std::sync::Mutex::new(HashMap::new()),
            frames: std::sync::Mutex::new(HashMap::new()),
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
            durability_lost: std::sync::atomic::AtomicBool::new(false),
            sync_gate: tokio::sync::Mutex::new(()),
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

    /// Fetch (or create) this `principal_id`'s serialization point.
    ///
    /// Never blocks on a write: only ever holds the map's own lock for the
    /// duration of a `HashMap` lookup/insert, not across any `.await`.
    fn principal_lock(&self, principal_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        // A poisoned std Mutex means some prior holder of THIS lock panicked
        // while holding it. The critical section below is only a HashMap
        // entry/insert/clone on an owned String key -- no `.await`, no
        // user-controlled Hash/Eq impl, nothing that can panic -- so
        // poisoning here would imply a bug already crashing the server
        // elsewhere, not a condition adversarial request input can trigger.
        let mut locks = self
            .principal_locks
            .lock()
            .expect("principal lock map poisoned");
        locks
            .entry(principal_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Take `principal_id`'s write lock, `lock` being its own entry of
    /// [`Self::principal_lock`].
    async fn lock_writes<'a>(
        lock: &'a Arc<tokio::sync::Mutex<()>>,
        principal_id: &str,
    ) -> WriteLock<'a> {
        WriteLock {
            principal: principal_id.to_string(),
            _guard: lock.lock().await,
        }
    }

    /// [`Self::lock_writes`] if the lock is free now, `None` if it is held.
    fn try_lock_writes<'a>(
        lock: &'a Arc<tokio::sync::Mutex<()>>,
        principal_id: &str,
    ) -> Option<WriteLock<'a>> {
        Some(WriteLock {
            principal: principal_id.to_string(),
            _guard: lock.try_lock().ok()?,
        })
    }

    /// Get a reference to the underlying blob store.
    pub fn blob_store(&self) -> &B {
        &self.blob_store
    }

    /// Get a reference to the underlying indexer.
    pub fn indexer(&self) -> &I {
        &self.indexer
    }

    // ========================================================================
    // Index heal gate
    // ========================================================================

    // ========================================================================
    // Read path
    // ========================================================================

    /// Retrieve the current tip state for a principal.
    ///
    /// Delegates directly to the indexer.
    #[tracing::instrument(skip(self))]
    pub async fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        Ok(self
            .indexer
            .get_tip(key.as_deref().unwrap_or(principal_id))
            .await?)
    }

    /// Retrieve a patch: commit chain metadata joined with blob content.
    ///
    /// For each commit in the range, fetches the raw blob bytes from
    /// the blob store. This is the engine's primary coordination value —
    /// neither trait can serve this alone.
    ///
    /// `from` is a content-digest resync anchor (Zami #140: "Content
    /// addressed digest for everything… Sequence is metadata"; S0.1 of the
    /// campaign IBC settles the anchor root as PR). It is resolved to the
    /// chain position it was produced at and the response starts
    /// immediately AFTER that position — sequence itself is never accepted
    /// as an anchor (see [`Self::resolve_anchor_position`]). `to` remains a
    /// bare sequence bound: only the resync ANCHOR needed content-addressing
    /// per #140, and widening `to` identically is out of this change's
    /// surface.
    #[tracing::instrument(skip(self))]
    pub async fn get_patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        self.patch(principal_id, from, to, false).await
    }

    /// [`Self::get_patch`] as a peer is served it (SPEC 15.7.1): while the
    /// principal is in Error, `entries` are the chain up to the fork point
    /// and [`PatchResponse::fork`] carries each branch, so no one
    /// branch is passed off as the chain. Active, it is `get_patch`.
    /// Callers that want the engine's canonical chain regardless use
    /// `get_patch`.
    #[tracing::instrument(skip(self))]
    pub async fn get_served_patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        self.patch(principal_id, from, to, true).await
    }

    async fn patch(
        &self,
        principal_id: &str,
        from: Option<&TaggedDigest>,
        to: Option<u64>,
        fork_aware: bool,
    ) -> Result<PatchResponse, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let principal_id = key.as_deref().unwrap_or(principal_id);
        let from_seq = match from {
            Some(anchor) => Some(self.resolve_anchor_position(principal_id, anchor).await?),
            None => None,
        };
        let error = if fork_aware {
            self.error_state_of(principal_id).await?
        } else {
            None
        };
        // In Error the common chain ends below the fork point: the chain
        // the index serves past it is one branch among several.
        let to = match &error {
            Some((point, _)) => point
                .height
                .checked_sub(1)
                .map(|last| to.map_or(last, |t| t.min(last))),
            None => to,
        };
        let chain = if error.as_ref().is_some_and(|(p, _)| p.height == 0) {
            Vec::new()
        } else {
            self.chain(principal_id, from_seq, to).await?
        };

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let bundle = self.commit_bundle(principal_id, &commit_ref).await?;
            entries.push(PatchEntry {
                commit: commit_ref,
                bundle,
            });
        }

        let fork = match error {
            Some((fork_point, heads)) => Some(PatchFork {
                branches: self.branches_of(principal_id, &fork_point, &heads).await?,
                fork_point,
            }),
            None => None,
        };

        let mut actions = Vec::new();
        for held in self.action_history(principal_id).await? {
            actions.push(PatchActions {
                blobs: self.read_blobs(&held.blobs).await?,
            });
        }

        Ok(PatchResponse {
            principal_id: principal_id.to_string(),
            entries,
            from: from_seq,
            actions,
            fork,
        })
    }

    /// Resolve a `/patch` resync anchor (a content digest) to the chain
    /// position immediately AFTER it — the inclusive `from` bound
    /// [`Indexer::get_commit_chain`] needs to serve exactly the entries a
    /// caller does not yet hold, never re-serving the anchored commit
    /// itself.
    ///
    /// An anchor that does not resolve to ANY indexed position at all is
    /// refused as [`EngineError::NotFound`] rather than silently degrading
    /// to "no anchor" (a full resync) or to sequence zero (which would
    /// silently wrap an unrecognized anchor onto genesis).
    ///
    /// Principal-scoped (forge #154): [`Indexer::resolve_digest_holders`]
    /// names every holder of the digest, and only a holder that is this
    /// principal's own commit bounds this chain. An anchor held solely by
    /// other principals is [`EngineError::NotFound`] here, never a position
    /// borrowed from a foreign chain; an anchor this principal holds at
    /// several positions is [`EngineError::Ambiguous`].
    async fn resolve_anchor_position(
        &self,
        principal_id: &str,
        anchor: &TaggedDigest,
    ) -> Result<u64, EngineError> {
        // A digest names a set of holders; only a holder that is this
        // principal's own commit bounds this chain. A digest held solely by
        // other principals names no position here (forge #154), and
        // holders at differing positions of this chain are ambiguous.
        let holders = self.indexer.resolve_digest_holders(anchor).await?;
        let mut own = holders
            .iter()
            .filter(|h| h.principal_id.as_deref() == Some(principal_id));
        let entity = own.next().ok_or_else(|| {
            EngineError::NotFound(format!(
                "resync anchor {anchor} not indexed (requested for principal {principal_id})"
            ))
        })?;
        if own.any(|other| other.sequence != entity.sequence) {
            return Err(EngineError::Ambiguous(format!(
                "resync anchor {anchor} is held at several positions of principal {principal_id}"
            )));
        }
        entity.sequence.map(|seq| seq + 1).ok_or_else(|| {
            EngineError::NotFound(format!(
                "resync anchor {anchor} carries no chain position (requested for principal \
                 {principal_id})"
            ))
        })
    }

    /// The bundle of a stored chain commit of `principal_id`: its blobs,
    /// grouped as the commit was accepted, with the keys it introduced.
    async fn commit_bundle(
        &self,
        principal_id: &str,
        commit: &CommitRef,
    ) -> Result<WireBundle, EngineError> {
        let mut blobs = Vec::with_capacity(commit.blob_hashes.len());
        for hash in &commit.blob_hashes {
            blobs.push(self.blob_store.get(hash).await?.ok_or_else(|| {
                EngineError::NotFound(format!(
                    "blob {hash} referenced by index commit {} missing",
                    commit.commit_id
                ))
            })?);
        }
        // An index entry no manifest backs is a corrupt index: the index is
        // a cache of the blob store (I1), and nothing recorded how its blobs
        // group. It is refused, never served.
        let Some(Frame { shape, keys, .. }) = self.frame(principal_id, commit) else {
            tracing::warn!(
                principal = %principal_id,
                commit = %commit.commit_id,
                "index entry with no commit manifest; refusing it as an inconsistent index"
            );
            return Err(EngineError::Indexer(
                crate::index::IndexerError::Consistency(format!(
                    "index commit {} of {principal_id} has no commit manifest",
                    commit.commit_id
                )),
            ));
        };
        shape.group(blobs, keys).ok_or_else(|| {
            EngineError::MalformedBlob(format!(
                "commit {}: its manifest groups a different number of blobs",
                commit.commit_id
            ))
        })
    }

    /// How the stored chain commit `commit` groups its blobs, if a manifest
    /// recorded it.
    fn frame(&self, principal_id: &str, commit: &CommitRef) -> Option<Frame> {
        self.frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(principal_id.to_string(), commit.commit_id.clone()))
            .cloned()
    }

    /// Record a chain commit's [`Frame`], in the `frames` cache.
    fn record_frame(
        &self,
        commit: &IndexableCommit,
        shape: &Shape,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) {
        let Some(id) = commit.commit_ids.first() else {
            return;
        };
        self.frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                (commit.principal_id.clone(), id.clone()),
                Frame {
                    shape: shape.clone(),
                    keys: key_entries(&commit.keys),
                    signed: signed_of(commit),
                    seen,
                    embedded: embedded.to_vec(),
                },
            );
    }

    /// Resolve a tagged digest to its raw blob content.
    ///
    /// Two-step: resolve digest → entity ref (index), then
    /// fetch blob content (blob store).
    #[tracing::instrument(skip(self))]
    pub async fn get_entity(&self, digest: &TaggedDigest) -> Result<Option<Vec<u8>>, EngineError> {
        self.ensure_healed().await?;
        let entity = match self.indexer.resolve_digest(digest).await? {
            Some(e) => e,
            None => return Ok(None),
        };

        let data = self.blob_store.get(&entity.blob_hash).await?;
        Ok(data)
    }

    /// Re-derive the current roots (`pr`, `sr`, `ar`, `cr`) for a principal
    /// directly from the authoritative blob store by replaying stored commits.
    ///
    /// Fails if the principal cannot be loaded from the blob store or if any
    /// referenced blob is missing or corrupt.
    #[tracing::instrument(skip(self))]
    pub async fn rederive_roots(&self, principal_id: &str) -> Result<DerivedRoots, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let genesis = self.resolve_genesis(&principal_id, &[]).await?;
        self.rederive_roots_with_genesis(&principal_id, genesis)
            .await
    }

    /// [`Self::rederive_roots`] for a caller that already holds the
    /// principal's genesis.
    #[tracing::instrument(skip(self, genesis))]
    pub async fn rederive_roots_with_genesis(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<DerivedRoots, EngineError> {
        self.ensure_healed().await?;
        let principal = self.load_principal(principal_id, genesis).await?;
        roots_of(&principal)
    }

    /// The roots `tip` names, read from the roots the index stored for that
    /// commit when it was admitted: nothing is replayed. A commit landing
    /// after `tip` was read changes nothing here, so what comes back is a
    /// statement about the commit `tip` names whatever the principal does
    /// meanwhile. `None` if the chain no longer has that commit at that
    /// position (a fork resolved under the read).
    ///
    /// Memoized by (principal, commit).
    ///
    /// # Errors
    ///
    /// [`EngineError`] if the index read fails.
    #[tracing::instrument(skip(self))]
    pub async fn derive_roots_at(
        &self,
        tip: &TipState,
    ) -> Result<Option<DerivedRoots>, EngineError> {
        self.ensure_healed().await?;
        let key = (tip.principal_id.clone(), tip.commit_id.clone());
        if let Some(hit) = self.roots_at.get(&key) {
            return Ok(Some(hit));
        }
        let Some(position) = tip.commit_count.checked_sub(1) else {
            return Ok(None);
        };
        let chain = self
            .indexer
            .get_commit_chain(&tip.principal_id, Some(position), Some(position))
            .await?;
        let Some(stored) = chain
            .into_iter()
            .find(|c| c.sequence == position && c.commit_id == tip.commit_id)
        else {
            return Ok(None);
        };
        let roots = DerivedRoots {
            pr: stored.pr,
            sr: stored.sr,
            ar: stored.ar,
            cr: stored.cr,
        };
        self.roots_at.insert(key, roots.clone());
        Ok(Some(roots))
    }

    // ========================================================================
    // Write path
    // ========================================================================

    /// Store this commit's coz blobs and its durable [`CommitManifest`],
    /// without touching the index.
    ///
    /// This is [`ingest_commit`](Self::ingest_commit)'s crash-safe first
    /// phase: once the manifest write here completes, the commit is
    /// durably recoverable from the blob store alone — a crash before it
    /// (mid coz-blob loop, or before the manifest itself lands) leaves
    /// only harmless, unreferenced content-addressed blobs behind, never
    /// a commit that's half-recorded. [`Self::rebuild_index_from_manifests`]
    /// is what completes the second phase (the index write) for a commit
    /// whose manifest landed but whose index write did not.
    async fn store_blobs_and_manifest(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        self.store_manifest(
            bundle,
            commit,
            COMMIT_MANIFEST_PREFIX,
            COMMIT_MANIFEST_KIND,
            seen,
            embedded,
        )
        .await
    }

    /// [`Self::store_blobs_and_manifest`] under a given manifest keyspace:
    /// a chain commit, or a retained branch ([`Self::keep_branch`]).
    async fn store_manifest(
        &self,
        bundle: &WireBundle,
        mut commit: IndexableCommit,
        prefix: &[u8],
        kind: &str,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        // Store each blob, in bundle order.
        let mut blob_hashes = Vec::with_capacity(commit.cozies.len());
        for (i, blob) in bundle.cozies().enumerate() {
            let hash = self.blob_store.put(blob).await?;
            blob_hashes.push(hash);
            if i < commit.cozies.len() {
                commit.cozies[i].blob_hash = hash;
            }
        }
        commit.blob_hashes = blob_hashes;

        // Durable commit point: once this manifest is stored, the full
        // IndexableCommit -- including the exact ingest-time order of its
        // cozies and how they group into transactions -- is recoverable
        // from the blob store alone.
        let manifest = CommitManifest {
            kind: kind.to_string(),
            commit: commit.clone(),
            shape: Shape::of(bundle),
            seen,
            embedded: embedded.to_vec(),
        };
        let mut manifest_bytes = prefix.to_vec();
        serde_json::to_writer(&mut manifest_bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("commit manifest serialize: {e}")))?;
        let manifest_hash = self.blob_store.put(&manifest_bytes).await?;

        Ok((commit, manifest_hash))
    }

    /// Ingest a pre-validated commit: store blobs and index metadata.
    ///
    /// Each coz of `bundle` is a raw coz byte slice. The engine:
    /// 1. Puts each blob into the blob store (content-addressed)
    /// 2. Builds an `IndexableCommit` from the metadata + blob hashes
    /// 3. Stores a durable [`CommitManifest`] recording that `IndexableCommit` and how its cozies
    ///    group into transactions (see [`Self::store_blobs_and_manifest`]) -- the crash-safe commit
    ///    point
    /// 4. Calls the indexer to record the commit's index entries
    ///
    /// Returns the BLAKE3 hashes of the stored blobs.
    ///
    /// **Note:** This method does NOT validate protocol-level
    /// signatures or state transitions. That responsibility belongs
    /// to the protocol validation layer (Phase 3b).
    ///
    /// # Locking
    ///
    /// This method holds no lock of its own: the read-then-write sequence
    /// it performs (resolving `commit.sequence` against the indexer's
    /// current tip, then writing) is only safe against concurrent writers
    /// for the same `principal_id` because [`Self::submit_commit`] -- its
    /// sole caller -- already holds that principal's serialization lock
    /// across its whole critical section, including this call.
    /// `pub(crate)` rather than `pub` so a caller outside this module
    /// cannot reach it without also reaching (and being reminded of) that
    /// invariant; call [`Self::submit_commit`] instead.
    ///
    /// ```compile_fail
    /// # async fn f(
    /// #     engine: &cyphr_storage::engine::StorageEngine<
    /// #         cyphr_storage::blob::MemoryBlobStore,
    /// #         cyphr_storage::index::MemoryIndexer,
    /// #     >,
    /// #     bundle: &cyphr::replay::WireBundle,
    /// #     commit: cyphr_storage::index::IndexableCommit,
    /// # ) {
    /// // ingest_commit is pub(crate): unreachable from outside this crate,
    /// // so a caller cannot bypass submit_commit's serialization lock.
    /// let _ = engine.ingest_commit(bundle, commit).await;
    /// # }
    /// ```
    pub(crate) async fn ingest_commit<T: cyphr::eml::Storage>(
        &self,
        bundle: &WireBundle,
        build: StagedBuild<'_, T>,
    ) -> Result<IngestResult, EngineError> {
        let StagedBuild {
            commit,
            staged,
            embedded,
        } = build;
        self.ingest(bundle, commit, Some(staged), &embedded).await
    }

    /// [`Self::ingest_commit`] of index metadata built by hand, with no
    /// core commit behind it (unit tests of the indexing path).
    #[cfg(test)]
    pub(crate) async fn ingest_metadata(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
    ) -> Result<IngestResult, EngineError> {
        self.ingest::<cyphr::eml::MemoryStorage>(bundle, commit, None, &[])
            .await
    }

    /// Make the record durable: one sync of the blob store's journal,
    /// which holds the blobs and the commit logs alike.
    ///
    /// The one durability point of every write that lands a commit, for
    /// every role (server, gossip, sync, CLI), because every such write
    /// goes through [`Self::submit_commit`]. It sits after the record
    /// (blobs, manifest, log) is written and before the first index write,
    /// with its error propagated: the commit is then refused rather than
    /// reported accepted without being durable. It is always on:
    ///
    /// - SPEC 19.5 (atomic commits): a power cut must not leave an index row whose blobs are gone,
    ///   which is what an unordered index sync could produce.
    /// - An attestor signs receipts and tip reports over the commit; if a power cut could erase it,
    ///   the restarted server would accept a rival at the same sequence and its two signatures
    ///   would meet `receipts.md`'s equivocation predicate against an honest server.
    /// - A client must not release a commit it could lose and then re-sign on the same `pre` (SPEC
    ///   2.3.2: implicit forks are prohibited).
    /// - A held statement (a principal in Error) is signed over its retained rivals, so a rival is
    ///   made durable before it is listed ([`Self::keep_branch`]), as is a revoke record, and an
    ///   action-only push is answered 201 only once its actions are durable.
    ///
    /// Only a keyless server needs none of this, and a sync costs it about
    /// 8 ms on a write of about 40, so there is no option to turn it off.
    ///
    /// A failed sync fails the engine closed. fjall poisons its database on
    /// a failed write, but not on a failed `persist`, and a sync that fails
    /// can drop the dirty pages it covered, so a later sync may succeed
    /// over them (fsyncgate). From the first failure every write is
    /// refused ([`Self::writable`]) until the process restarts and replays
    /// what actually reached the disk.
    ///
    /// Every sync runs under one async lock. Two writes to different
    /// principals can both pass [`Self::writable`]; if the first's sync
    /// fails, the kernel drops the dirty pages of both, and the second's
    /// sync, queued behind it, would report success over pages that are
    /// gone. Under the lock the second finds the flag the first set. The
    /// lock costs no throughput: the database's journal lock already
    /// serialises syncs.
    async fn persist_record(&self) -> Result<(), EngineError> {
        let _one_sync = self.sync_gate.lock().await;
        self.writable()?;
        if let Err(e) = self.blob_store.persist().await {
            self.durability_lost
                .store(true, std::sync::atomic::Ordering::SeqCst);
            tracing::error!(error = %e, "record sync failed; refusing writes until restart");
            return Err(EngineError::DurabilityLost(e.to_string()));
        }
        Ok(())
    }

    /// Whether a record sync has failed ([`Self::persist_record`]): the
    /// engine then refuses every write until the process restarts, so a
    /// health check reads this rather than probing a write that the flag
    /// would refuse anyway. Never cleared.
    pub fn durability_lost(&self) -> bool {
        self.durability_lost
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `Err` once a record sync has failed ([`Self::persist_record`]).
    /// Checked before a write stores anything, so a failed engine adds
    /// nothing to the record.
    fn writable(&self) -> Result<(), EngineError> {
        if self.durability_lost() {
            return Err(EngineError::DurabilityLost(
                "an earlier sync of the record failed".into(),
            ));
        }
        Ok(())
    }

    /// Store blobs and manifest, then the commit-log append (when there is
    /// a core commit), then the index: the I1 order.
    #[tracing::instrument(
        skip(self, bundle, commit, staged),
        fields(
            principal_id = %commit.principal_id,
            blob_count = bundle.cozies().count()
        )
    )]
    async fn ingest<T: cyphr::eml::Storage>(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
        staged: Option<cyphr::replay::StagedBundle<'_, T>>,
        embedded: &[EmbeddedPin],
    ) -> Result<IngestResult, EngineError> {
        // The one exclusive claim (a PG alias) is checked before the first
        // durable write: a refused commit must leave no blob or manifest
        // for a later rebuild to trip over. Two ingests for different
        // principals contend for one alias without sharing a principal
        // lock, so the check and the write it admits are held under a lock
        // per alias (in sorted order, so contenders cannot deadlock).
        let alias_locks = self.alias_locks(&[&commit]);
        let mut _alias_guards = Vec::with_capacity(alias_locks.len());
        for lock in &alias_locks {
            _alias_guards.push(lock.lock().await);
        }
        self.indexer
            .check_commit(&commit, &DeriveToken::new())
            .await?;
        let seen = unix_now();
        let (commit, manifest_hash) = self
            .store_blobs_and_manifest(bundle, commit, seen, embedded)
            .await?;
        let blob_hashes = commit.blob_hashes.clone();

        // The blob store now records the commit (I1), so its commit-log
        // append may follow: the log is never ahead of the record. The log
        // is a cache of that record, so a failed append does not unmake the
        // commit: the push still succeeds, and the next load repairs the
        // log by replaying the manifest's commit onto it (as after a crash
        // here).
        if let Some(Err(e)) = match staged {
            Some(staged) => Some(staged.commit().await),
            None => None,
        } {
            self.counters.bump(Counter::LogAppendFailures);
            tracing::warn!(
                principal = %commit.principal_id,
                error = %e,
                "commit stored but its log append failed; the next load replays it"
            );
        }

        // The record (blobs, manifest, log) is complete: make it durable
        // before the index can point into it, and before this call returns
        // and anything signs over or releases the commit. See
        // [`Self::persist_record`].
        self.persist_record().await?;

        // The roots of a commit this process just verified, by the commit
        // that names them, before the index can show the commit to a reader.
        let admitted = CommittedTip::of(&commit);
        self.roots_at.insert(
            (commit.principal_id.clone(), admitted.commit_id),
            DerivedRoots {
                pr: admitted.pr,
                sr: admitted.sr,
                ar: admitted.ar,
                cr: admitted.cr,
            },
        );
        // The manifest is stored, so its frame is known before the index
        // shows the commit: a reader that finds the commit in the index
        // must find its frame, or it refuses the index as inconsistent.
        self.record_frame(&commit, &Shape::of(bundle), seen, embedded);
        self.indexer
            .index_commit(&commit, &DeriveToken::new())
            .await?;
        // A commit refused while the principal was in Error and kept as
        // evidence is now canonical: it is listed once, as the chain.
        if let Some(id) = commit.commit_ids.first() {
            self.branches
                .forget(&commit.principal_id, id, commit.sequence);
        }

        Ok(IngestResult {
            principal_id: commit.principal_id.clone(),
            blob_hashes,
            manifest_hash: Some(manifest_hash),
            tip: Some(CommittedTip::of(&commit)),
        })
    }

    // ========================================================================
    // Principal lifecycle
    // ========================================================================

    /// Reconstruct a principal by replaying stored commits, as a read-only
    /// [`AtTip`]: it holds the engine's durable log but hands out only a
    /// shared reference, so the caller cannot append to it. Writes go
    /// through [`Self::submit_commit`].
    ///
    /// Fetches the full commit chain from the indexer, retrieves each
    /// blob from the blob store, and delegates to the existing
    /// [`import::replay_commits`] infrastructure, then holds the stored
    /// action-only bundles ([`Self::replay_onto`]).
    ///
    /// Always a replay, whatever state the engine keeps: for a caller that
    /// wants the replay itself (a store check, a one-shot tool). A reader
    /// that wants the principal's state takes [`Self::at_tip`].
    ///
    /// # Arguments
    ///
    /// * `principal_id` — The tagged-digest identifier for the principal.
    /// * `genesis` — How this principal was originally created.
    ///
    /// # Errors
    ///
    /// - `EngineError::Indexer` — commit chain lookup failed.
    /// - `EngineError::BlobStore` — blob retrieval failed.
    /// - `EngineError::NotFound` — blob referenced by index is missing.
    /// - `EngineError::MalformedBlob` — stored blob is not valid JSON.
    /// - `EngineError::Load` — replay/validation failed.
    #[tracing::instrument(skip(self, genesis))]
    pub async fn load_principal(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<AtTip<S>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let stored = key.as_deref().unwrap_or(principal_id);
        // The writer's lock: a push appends to the durable log before it
        // writes the index, and a load in that window sees a log one leaf
        // ahead of the chain and regenerates it for nothing.
        let lock = self.principal_lock(stored);
        let _no_write_in_flight = lock.lock().await;
        self.replay_stored(stored, genesis).await.map(AtTip::new)
    }

    /// [`load_principal`](Self::load_principal) for an id already known to
    /// be the stored spelling.
    async fn replay_stored(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let generation = self
            .logs
            .generation(principal_id)
            .map_err(EngineError::Storage)?;
        let replayed = self
            .replay_generation(principal_id, genesis.clone(), generation)
            .await;
        if !log_is_stale(&replayed) {
            return replayed;
        }
        // The log is not a cache of the canonical chain: a resolved fork
        // re-pointed the chain under it, or it was written before the
        // two-phase commit. It is a cache of the blob store (I1), so it is
        // regenerated into a fresh generation from the blobs, one
        // regeneration at a time (the write lock may already be held by
        // this caller, so this one is separate).
        let lock = self.principal_lock(&format!("eml-generation\0{principal_id}"));
        let _regenerating = lock.lock().await;
        let current = self
            .logs
            .generation(principal_id)
            .map_err(EngineError::Storage)?;
        if current != generation {
            return self.replay_generation(principal_id, genesis, current).await;
        }
        let next = generation + 1;
        let storage = self
            .logs
            .open(principal_id, next)
            .map_err(EngineError::Storage)?;
        let regenerated = self
            .replay_onto(principal_id, genesis, storage, None)
            .await?;
        self.logs
            .retire_below(principal_id, next)
            .map_err(EngineError::Storage)?;
        Ok(regenerated)
    }

    /// Replay `principal_id`'s canonical chain onto generation
    /// `generation` of its log.
    async fn replay_generation(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        generation: u64,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let storage = self
            .logs
            .open(principal_id, generation)
            .map_err(EngineError::Storage)?;
        self.replay_onto(principal_id, genesis, storage, None).await
    }

    /// Replay the first `through` stored commits (all of them for `None`)
    /// of `principal_id` onto a principal built from `genesis` over
    /// `storage`.
    ///
    /// The storage is the caller's so a retention check can replay over a
    /// private in-memory Commit Tree: a rival verified at an earlier
    /// position must never read, append to or mismatch the principal's
    /// durable log.
    ///
    /// The stored action-only bundles are held once the commits are in. An
    /// action the key history does not authorize at its own `now` (SPEC 6.2,
    /// 6.5), as when a commit dated before it removes its key, is held but
    /// not shown in DT, and shown again if a later commit restores its key;
    /// its blobs stay stored (I1). The naked revokes the engine holds are
    /// no part of the state: they gate each arriving bundle
    /// ([`dead_key_in`]).
    async fn replay_onto<T: cyphr::eml::Storage>(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        storage: T,
        through: Option<u64>,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        let mut principal = Self::principal_from_genesis(genesis.clone(), storage).await?;

        let stored = self.stored_entries(principal_id, through).await?;
        let source = PinSource::stored();
        for (position, (entry, pins)) in stored.entries.iter().zip(&stored.pins).enumerate() {
            self.replay_pinned(&mut principal, &source, entry, pins, position, EMBED_DEPTH)
                .await?;
        }
        // Held actions are held as they are, with no verdict: whether one
        // counts is read from the key timeline, whatever order they are
        // taken in.
        for held in self.action_history(principal_id).await? {
            if let Err(why) = self
                .apply_pins(&mut principal, &source, &held.embedded, EMBED_DEPTH)
                .await
            {
                tracing::warn!(
                    principal = %principal_id,
                    manifest = %held.manifest,
                    error = %why,
                    "an embedded principal a stored action bundle was judged through does not replay; left out of DT"
                );
                continue;
            }
            match cyphr::replay::replay_held(&mut principal, &held.bundle).await {
                Ok(_) => {},
                Err(refused) => tracing::warn!(
                    principal = %principal_id,
                    manifest = %held.manifest,
                    error = %refused,
                    "a stored action bundle does not replay; left out of DT"
                ),
            }
        }

        Ok(principal)
    }

    /// The action-only bundles accepted for `principal_id`, read back from
    /// the blob store, in replay order.
    async fn action_history(&self, principal_id: &str) -> Result<ActionHistory, EngineError> {
        let held = self
            .actions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .cloned()
            .unwrap_or_default();
        let mut history = ActionHistory::new();
        for stored in held {
            let blobs = self.read_blobs(&stored.blobs).await?;
            let bundle = action_bundle(blobs).map_err(|why| {
                EngineError::MalformedBlob(format!("action manifest {}: {why}", stored.manifest))
            })?;
            history.push(ActionBundle {
                manifest: stored.manifest,
                blobs: stored.blobs,
                embedded: stored.embedded,
                bundle,
            });
        }
        replay_order(&mut history);
        Ok(history)
    }

    /// The active key `tmb` of `principal`, as a resync's signer is read
    /// at the state a line reaches.
    fn active_key<T: cyphr::eml::Storage>(
        principal: &cyphr::Principal<T>,
        tmb: &coz::Thumbprint,
    ) -> Result<cyphr::Key, EngineError> {
        principal
            .state()
            .get_key(tmb)
            .filter(|_| principal.is_key_active(tmb))
            .cloned()
            .ok_or(EngineError::Protocol(cyphr::Error::UnknownKey))
    }

    /// A principal holding only its genesis key, over `storage`.
    async fn principal_from_genesis<T: cyphr::eml::Storage>(
        genesis: crate::Genesis,
        storage: T,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        let key = genesis
            .key()
            .ok_or_else(|| EngineError::InvalidInput("genesis requires at least one key".into()))?;
        Ok(cyphr::Principal::open(key.clone(), storage).await?)
    }

    /// The first `through` stored commits (all for `None`) of
    /// `principal_id` as replayable entries: each commit's bundle read and
    /// parsed. No protocol check.
    async fn stored_entries(
        &self,
        principal_id: &str,
        through: Option<u64>,
    ) -> Result<StoredChain, EngineError> {
        let last = match through {
            Some(0) => return Ok(StoredChain::default()),
            Some(count) => Some(count - 1),
            None => None,
        };
        let chain = self.chain(principal_id, None, last).await?;
        let mut stored = StoredChain::default();
        for commit_ref in &chain {
            let bundle = self.commit_bundle(principal_id, commit_ref).await?;
            stored.entries.push(replay_entry(
                &bundle,
                &commit_ref.commit_id,
                &commit_ref.pr,
            )?);
            stored.prs.push(commit_ref.pr.clone());
            stored.pins.push(
                self.frame(principal_id, commit_ref)
                    .map(|f| f.embedded)
                    .unwrap_or_default(),
            );
        }

        Ok(stored)
    }

    /// Replay `entry`, the `position`-th commit of a chain, onto
    /// `principal`, first pinning each embedded principal the commit was
    /// admitted through at the state it was admitted against (SPEC 6.2,
    /// 10.7: a commit once admitted is never judged against a later state).
    async fn replay_pinned<T: cyphr::eml::Storage>(
        &self,
        principal: &mut cyphr::Principal<T>,
        source: &PinSource<'_>,
        entry: &crate::CommitEntry,
        pins: &[EmbeddedPin],
        position: usize,
        depth: u8,
    ) -> Result<(), EngineError> {
        self.apply_pins(principal, source, pins, depth).await?;
        // The single count of replay: every commit of a chain re-applied
        // from stored blobs, on whichever path. Commits re-applied while
        // following an embedded principal (`depth` below the top) are part
        // of the commit that embeds it, not counted again.
        if depth == EMBED_DEPTH {
            self.counters.bump(Counter::CommitsReplayed);
        }
        crate::import::replay_commit(principal, entry, position).await?;
        Ok(())
    }

    /// Pin each of `pins` on `principal`: replay the embedded principal to
    /// the PR the admission recorded, and hold that as its tip. `b` was held
    /// before the commit was admitted, so a pin depends only on earlier
    /// admissions; `depth` bounds the walk for a store that says otherwise.
    async fn apply_pins<T: cyphr::eml::Storage>(
        &self,
        principal: &mut cyphr::Principal<T>,
        source: &PinSource<'_>,
        pins: &[EmbeddedPin],
        depth: u8,
    ) -> Result<(), EngineError> {
        for pin in pins {
            let b = self.state_at(source, &pin.member, &pin.b, depth).await?;
            principal
                .reveal_embedded(
                    &pin.member,
                    cyphr::Tracking::Pin(Box::new(cyphr::Tip::new(&b, 0))),
                )
                .map_err(EngineError::Protocol)?;
        }
        Ok(())
    }

    /// The state of the principal `member` names at the commit that left it
    /// at PR `b`, each of its own commits replayed against the embedded
    /// states it was admitted through. A `b` on B's canonical chain is read
    /// from one forward pass over it per call, resumed for a later `b`
    /// ([`PinSource`]). A `b` B has since reorganized away from is read from
    /// the ancestry of that commit alone ([`Self::ancestry`]). Boxed: it
    /// recurses through [`Self::apply_pins`].
    fn state_at<'a>(
        &'a self,
        source: &'a PinSource<'a>,
        member: &'a str,
        b: &'a str,
        depth: u8,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<cyphr::PrincipalState, EngineError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let Some(depth) = depth.checked_sub(1) else {
                return Err(EngineError::MalformedBlob(format!(
                    "embedded principals nest deeper than {EMBED_DEPTH} replaying {member}"
                )));
            };
            // A chain that pins itself (only a forged store can) finds its
            // own slot held: refused, not waited on.
            let cycle =
                || EngineError::MalformedBlob(format!("embedded principal {member} pins itself"));
            // The canonical pass over `member` is held further up this call
            // when `member` and the principal being replayed embed each
            // other (SPEC 10.7): the state asked for here is an earlier one
            // than that pass has reached, so it is read from its own
            // ancestry below. A true self-pin finds that line held as well.
            let slot = source.slot(member);
            if let Ok(mut canonical) = slot.try_lock() {
                if canonical.is_none()
                    && let Some(chain) = self.embedded_chain(source, member).await?
                {
                    *canonical = Some(Self::chain_memo(chain, member).await?);
                }
                if let Some(memo) = canonical.as_mut() {
                    match self.advance(memo, source, b, depth).await {
                        Ok(Some(state)) => return Ok(state),
                        Ok(None) => {},
                        Err(e) => {
                            *canonical = None;
                            return Err(e);
                        },
                    }
                }
            }
            let line = source.slot(&format!("{member}\0{b}"));
            let mut line = line.try_lock().map_err(|_| cycle())?;
            if line.is_none() {
                let chain = self.ancestry(source, member, b).await?;
                *line = Some(Self::chain_memo(chain, member).await?);
            }
            let Some(memo) = line.as_mut() else {
                return Err(EngineError::EmbeddedPinLost {
                    member: member.to_string(),
                    b: b.to_string(),
                });
            };
            let found = self.advance(memo, source, b, depth).await;
            if found.is_err() {
                *line = None;
            }
            found?.ok_or_else(|| EngineError::EmbeddedPinLost {
                member: member.to_string(),
                b: b.to_string(),
            })
        })
    }

    /// Replay `memo`'s chain forward until it stands at PR `b`, taking the
    /// state at every PR passed; `None` when `b` is not on this chain.
    async fn advance(
        &self,
        memo: &mut ChainMemo,
        source: &PinSource<'_>,
        b: &str,
        depth: u8,
    ) -> Result<Option<cyphr::PrincipalState>, EngineError> {
        if let Some(state) = memo.at.get(b) {
            return Ok(Some(state.clone()));
        }
        if !memo.chain.prs.iter().any(|pr| pr == b) {
            return Ok(None);
        }
        while let (Some(entry), Some(pins)) = (
            memo.chain.entries.get(memo.next),
            memo.chain.pins.get(memo.next),
        ) {
            self.replay_pinned(&mut memo.principal, source, entry, pins, memo.next, depth)
                .await?;
            memo.next += 1;
            let pr = memo.principal.pr_tagged().map_err(EngineError::Protocol)?;
            let state = (*memo.principal).clone();
            let done = pr == b;
            memo.at.insert(pr, state.clone());
            if done {
                return Ok(Some(state));
            }
        }
        Ok(None)
    }

    /// A principal at the genesis `chain` begins with, to replay it onto.
    async fn chain_memo(chain: StoredChain, member: &str) -> Result<ChainMemo, EngineError> {
        let first = chain.entries.first().ok_or_else(|| {
            EngineError::NotFound(format!("embedded principal {member} has no commits"))
        })?;
        let first = first
            .bundle()
            .map_err(|e| EngineError::MalformedBlob(e.to_string()))?;
        let genesis = Self::genesis_from_bundle(Some(&first))?;
        let principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new()).await?;
        Ok(ChainMemo {
            chain,
            principal,
            next: 0,
            at: HashMap::new(),
        })
    }

    /// The principal `member` names (SPEC 10.3: B's PG or a PR B held), by
    /// the PG alias or the index's PR holders: the stored key. `None` when
    /// it names no principal held, or several, which no verifier can follow
    /// to one tip. The index is a locator only: what B's key history says
    /// is replayed from B's blobs.
    async fn principal_named(&self, member: &str) -> Result<Option<String>, EngineError> {
        if let Some(id) = self.stored_id(member).await? {
            return Ok(Some(id));
        }
        let Ok(digest) = member.parse::<TaggedDigest>() else {
            return Ok(None);
        };
        let mut holders: Vec<String> = self
            .indexer
            .resolve_digest_holders(&digest)
            .await?
            .into_iter()
            .filter(|h| h.principal_root)
            .filter_map(|h| h.principal_id)
            .collect();
        holders.sort_unstable();
        holders.dedup();
        match holders.as_slice() {
            [one] => self.stored_id(one).await,
            _ => Ok(None),
        }
    }

    /// The stored commits of the principal `member` (its PG or a PR it
    /// held) names, or `None` when `source` holds no such principal.
    async fn embedded_chain(
        &self,
        source: &PinSource<'_>,
        member: &str,
    ) -> Result<Option<StoredChain>, EngineError> {
        let Some((manifests, _)) = source.manifests else {
            let Some(id) = self.principal_named(member).await? else {
                return Ok(None);
            };
            return self.stored_entries(&id, None).await.map(Some);
        };
        let Some(named) = manifest_principal(source, member) else {
            return Ok(None);
        };
        let mut chain = StoredChain::default();
        for (_, manifest) in manifests
            .iter()
            .filter(|(_, m)| m.commit.principal_id == named)
        {
            let (entry, pins) = self.manifest_entry(manifest).await?;
            chain.prs.push(entry.pr.clone());
            chain.entries.push(entry);
            chain.pins.push(pins);
        }
        Ok(Some(chain))
    }

    async fn manifest_entry(
        &self,
        manifest: &CommitManifest,
    ) -> Result<(crate::CommitEntry, Vec<EmbeddedPin>), EngineError> {
        let bundle = self.manifest_bundle(manifest).await?;
        let entry = replay_entry(
            &bundle,
            manifest
                .commit
                .commit_ids
                .first()
                .map_or("", String::as_str),
            manifest.commit.prs.first().map_or("", String::as_str),
        )?;
        Ok((entry, manifest.embedded.clone()))
    }

    /// The commits of B's that lead to the one at PR `b`, oldest first,
    /// walked back by `pre` over every commit B holds, canonical and
    /// retained alike (SPEC 2.3.2, 14.12: B choosing another branch undoes
    /// nothing A did through it). The commit at `b` is the last.
    ///
    /// # Errors
    ///
    /// [`EngineError::EmbeddedPinLost`] when the ancestry has a gap: held
    /// blobs were lost, and a pin never degrades to an opaque digest.
    async fn ancestry(
        &self,
        source: &PinSource<'_>,
        member: &str,
        b: &str,
    ) -> Result<StoredChain, EngineError> {
        let lost = || EngineError::EmbeddedPinLost {
            member: member.to_string(),
            b: b.to_string(),
        };
        let (id, held) = match source.manifests {
            Some((canonical, rest)) => {
                let id = manifest_principal(source, member)
                    .or_else(|| manifest_principal(source, b))
                    .ok_or_else(lost)?;
                let held = canonical
                    .iter()
                    .chain(rest)
                    .filter(|(_, m)| m.commit.principal_id == id)
                    .map(|(_, m)| HeldCommit {
                        sequence: m.commit.sequence,
                        pr: m.commit.prs.first().cloned().unwrap_or_default(),
                        pre: m.commit.pre.clone(),
                        origin: HeldOrigin::Manifest(m),
                    })
                    .collect::<Vec<_>>();
                (id, held)
            },
            None => {
                let retained_of = |pr: &str| self.branches.principal_of_pr(pr);
                let id = match self.principal_named(member).await? {
                    Some(id) => id,
                    None => retained_of(member)
                        .or_else(|| retained_of(b))
                        .ok_or_else(lost)?,
                };
                let mut held: Vec<HeldCommit<'_>> = self
                    .chain(&id, None, None)
                    .await?
                    .into_iter()
                    .map(|c| HeldCommit {
                        sequence: c.sequence,
                        pr: c.pr.clone(),
                        pre: c.pre.clone(),
                        origin: HeldOrigin::Canonical(c),
                    })
                    .collect();
                let retained = self.branches.retained(&id);
                held.extend(retained.into_iter().map(|r| HeldCommit {
                    sequence: r.tip.sequence,
                    pr: r.pr.clone(),
                    pre: r.tip.pre.clone(),
                    origin: HeldOrigin::Retained(Box::new(r)),
                }));
                (id, held)
            },
        };
        let mut at = held.iter().find(|h| h.pr == b).ok_or_else(lost)?;
        let mut line = vec![at];
        while let Some(pre) = &at.pre {
            at = held
                .iter()
                .find(|h| h.pr == *pre && h.sequence + 1 == at.sequence)
                .ok_or_else(lost)?;
            line.push(at);
        }
        let mut chain = StoredChain::default();
        for h in line.into_iter().rev() {
            let (entry, pins) = match &h.origin {
                HeldOrigin::Canonical(c) => {
                    let bundle = self.commit_bundle(&id, c).await?;
                    let pins = self.frame(&id, c).map(|f| f.embedded).unwrap_or_default();
                    (replay_entry(&bundle, &c.commit_id, &c.pr)?, pins)
                },
                HeldOrigin::Retained(r) => {
                    let blobs = self.read_blobs(&r.blobs).await?;
                    let bundle = r.shape.group(blobs, r.keys.clone()).ok_or_else(|| {
                        EngineError::MalformedBlob(format!(
                            "retained commit {}: its shape groups a different number of blobs",
                            r.tip.tip
                        ))
                    })?;
                    (
                        replay_entry(&bundle, &r.tip.tip, &r.pr)?,
                        r.embedded.clone(),
                    )
                },
                HeldOrigin::Manifest(m) => self.manifest_entry(m).await?,
            };
            chain.prs.push(h.pr.clone());
            chain.entries.push(entry);
            chain.pins.push(pins);
        }
        Ok(chain)
    }

    /// Submit a commit for protocol validation and persistence.
    ///
    /// This is the **validated write path** — the engine's primary API for
    /// authority-mode operation. Each incoming raw coz blob is
    /// cryptographically verified via [`CommitScope`] before any
    /// persistence occurs.
    ///
    /// # Flow
    ///
    /// 1. Resolve genesis (from argument, storage, or submitted blobs)
    /// 2. Take the verified principal at its tip, from the kept state or a replay
    ///    ([`Self::verified`]), or construct a new one from genesis
    /// 3. Open a `CommitScope`
    /// 4. Record the bundle's actions; for each transaction, verify its cozies (`{pay, sig}`, the
    ///    key a coz introduces taken from the bundle's `keys`) and apply them as one transaction
    ///    (`scope.apply_tx()`)
    /// 5. Finalize the scope → immutable `Commit`
    /// 6. Extract state digests from the finalized `Commit`
    /// 7. Store blobs + index via `ingest_commit`
    ///
    /// # Arguments
    ///
    /// * `principal_id` — The principal's id: its PG (SPEC 5.1 step 3; for a principal that never
    ///   committed, its genesis PR, the `tmb` by singleton promotion, SPEC 3.1), labelled
    ///   (`ALG:digest`, the stored spelling) or bare; a stored principal is also addressed by any
    ///   variant of its PG. Any other id is refused with [`EngineError::InvalidInput`]. The storage
    ///   key, and the id reported back, is the PG in the labelled spelling ([`record_key`]).
    /// * `genesis` — How this principal was originally created, or `None` to auto-detect from
    ///   storage (existing principal) or from the submitted blobs (new principal).
    /// * `bundle` — The pushed bundle (SPEC 4.6.2): `txs`, each transaction's raw coz JSON
    ///   envelopes (`{pay, sig}`), the commit transaction last; `keys`; and `actions`, data actions
    ///   recorded before the transactions.
    ///
    /// # Errors
    ///
    /// Any protocol violation (bad signature, broken chain, unknown signer,
    /// etc.) causes the entire submit to fail with no side effects — blobs
    #[tracing::instrument(
        skip(self, genesis, bundle),
        fields(blob_count = bundle.cozies().count())
    )]
    pub async fn submit_commit(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        bundle: &WireBundle,
    ) -> Result<IngestResult, EngineError> {
        // Type-erased: the write path's future is deep enough that proving
        // it `Send` at a caller that spawns a push overflows the compiler's
        // limit, so it is proved once, here.
        let write: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<IngestResult, EngineError>> + Send + '_>,
        > = Box::pin(self.submit_commit_with(principal_id, genesis, bundle, None));
        write.await
    }

    /// Offer a rival line root `parent` together with its one extension
    /// `bundle` (frame rule X): the two are kept both or neither. A root
    /// whose caps refuse it alone changes no verdict, so a holder whose
    /// quota is full could never place the extension that makes the fork
    /// two extended branches; the pair is judged as one offer, and kept
    /// when the caps allow it or when it moves the principal's standing or
    /// fork point. A root the engine already holds, or admits by itself,
    /// leaves `bundle` an ordinary submission.
    ///
    /// # Errors
    ///
    /// As [`Self::submit_commit`]; a pair the caps refuse and that changes
    /// nothing answers [`EngineError::BranchLimit`], or
    /// [`EngineError::Errored`] while the principal is in Error, and
    /// stores neither commit.
    pub async fn submit_pair(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        parent: &WireBundle,
        bundle: &WireBundle,
    ) -> Result<IngestResult, EngineError> {
        match self
            .submit_commit_with(principal_id, genesis.clone(), bundle, Some(parent))
            .await
        {
            // The extension is no rival of any chain held: its root is
            // held, or can be admitted alone, and the extension follows.
            Err(
                EngineError::Protocol(_)
                | EngineError::Errored { .. }
                | EngineError::BranchLimit { .. },
            ) => {
                match self
                    .submit_commit(principal_id, genesis.clone(), parent)
                    .await
                {
                    Ok(_)
                    | Err(
                        EngineError::Protocol(_)
                        | EngineError::Errored { .. }
                        | EngineError::BranchLimit { .. },
                    ) => {},
                    Err(other) => return Err(other),
                }
                self.submit_commit(principal_id, genesis, bundle).await
            },
            other => other,
        }
    }

    async fn submit_commit_with(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        bundle: &WireBundle,
        pair: Option<&WireBundle>,
    ) -> Result<IngestResult, EngineError> {
        self.writable()?;
        self.ensure_healed().await?;

        if bundle.is_empty() {
            return Err(EngineError::InvalidInput("empty commit bundle".into()));
        }

        // Everything below, storage included, sees only the canonical
        // bundle, never the caller's bytes.
        let canonical = canonical_bundle(bundle)?;
        let bundle = &canonical;
        let parent = pair.map(canonical_bundle).transpose()?;

        // 1. Resolve the principal's storage key.
        //
        // The key is a function of the record, never of the spelling the
        // caller used, so a rebuild from blobs reproduces it (I1): it is
        // [`record_key`] of the principal's first commit, its genesis
        // commit (SPEC 5.1). The key is also the id a response reports. An
        // id addresses a stored principal by its key or its PG (any
        // variant).
        let claimed = principal_id;
        let stored = self.stored_id(claimed).await?;
        let not_genesis_id = || {
            EngineError::InvalidInput(format!(
                "principal_id is not the genesis-derived id: {claimed}"
            ))
        };
        let (genesis, new_key) = match stored.as_deref() {
            // The record decides a stored principal's genesis: its first
            // commit, whatever genesis the caller names.
            Some(stored_id) => (self.genesis_of_stored(stored_id).await?, None),
            None => {
                // A new principal: these blobs are its genesis commit, and
                // the keys their `key/create`s disclose are its genesis.
                // Only when they disclose none does the caller's genesis
                // stand, for the core to refuse the commit with its reason.
                let genesis = match (disclosed_genesis(bundle), genesis) {
                    (Some(disclosed), _) => disclosed?,
                    (None, Some(given)) => given,
                    // Actions alone are not a genesis that failed to
                    // disclose its keys: the principal has no genesis
                    // commit yet (be0663f 2.3.2).
                    (None, None) if bundle.txs.is_empty() => {
                        return Err(EngineError::Protocol(cyphr::Error::GenesisIncomplete));
                    },
                    (None, None) => return Err(no_disclosed_genesis()),
                };
                let key = record_key(&genesis, bundle).await;
                let names_key = key
                    .as_ref()
                    .is_some_and(|key| claimed == key || claimed == bare_digest(key));
                // A commit that is no genesis commit derives no key; the
                // core refuses it with its own reason below.
                if key.is_some() && !names_key {
                    return Err(not_genesis_id());
                }
                let key = match key {
                    Some(key) => key,
                    None => genesis_principal_id(&genesis)?,
                };
                (genesis, Some(key))
            },
        };
        let canonical = stored.or(new_key).ok_or_else(not_genesis_id)?;
        let principal_id = canonical.as_str();

        // Serialize the whole sequence-resolution-through-ingest critical
        // section per principal_id: two concurrent callers for the SAME
        // principal must never both resolve `next_seq` before either has
        // ingested. Held for the remainder of this function; a concurrent
        // caller for a DIFFERENT principal_id never contends on this lock.
        let lock = self.principal_lock(principal_id);
        let write = Self::lock_writes(&lock, principal_id).await;

        // 2. Determine the tip this write extends, then take the verified
        // principal at it ([`Self::verified`]), or construct a new one
        // from its genesis.
        let tip_before = self.indexer.get_tip(principal_id).await?;
        let next_seq = tip_before.as_ref().map_or(0, |tip| tip.commit_count);
        let (mut principal, embeds) = match &tip_before {
            Some(tip) => {
                let v = self
                    .verified(principal_id, Some(&genesis), tip, &write)
                    .await?;
                (v.principal, v.embeds)
            },
            None => (
                self.replay_stored(principal_id, genesis.clone()).await?,
                false,
            ),
        };
        // The state as verified, for a principal the write's follow of its
        // embedded principals changes whether or not the bundle is admitted.
        let pristine = embeds.then(|| principal.state().clone());
        // Set once the write has stored anything of the bundle.
        let mut stored_any = false;

        // The write itself. Its refusals leave the stored chain as it was,
        // so the verified state goes back to the cache, whether it was read
        // from there or replayed, and the next write is served from it: a
        // refused bundle is free to send, and must cost no replay.
        let written: Result<(IngestResult, bool), EngineError> = async {
            // Key death (SPEC 6.4), read under the lock. A revoke recorded
            // concurrently is not serialized with it (it takes no principal
            // lock), so it acts as one that arrived just after this bundle.
            // A bundle the principal already holds is a repeat, judged by
            // nothing that arrived since (SPEC 14.12), so a revoke received
            // after the first push cannot change the answer to it: an
            // action repeat is ignored (SPEC 7.6), a commit repeat is
            // refused as the reuse it is. Held means every action's czd is included (an
            // action-only bundle) or the bundle is, blob for blob and in its
            // grouping, a commit already stored; anything else, or a bundle
            // that does not decode, runs the gate.
            let repeat = if bundle.txs.is_empty() {
                !bundle.actions.is_empty()
                    && bundle_czds(bundle)
                        .is_ok_and(|czds| czds.iter().all(|c| principal.has_included(c)))
            } else {
                self.is_already_stored(principal_id, bundle)
                    .await
                    .unwrap_or(false)
            };
            if !repeat && let Some(dead) = dead_key_in(bundle, &self.deaths.snapshot()) {
                return Err(dead);
            }

            // Whether every action the bundle carries is one the principal
            // already holds, before the bundle is applied to it: a client
            // cannot tell which actions a peer holds, so a push repeats them.
            let repeats =
                bundle_czds(bundle).map(|czds| czds.iter().all(|c| principal.has_included(c)));
            // A bundle may be signed through an embedded principal this node
            // holds (SPEC 10.3, 10.5); the manifest of what it forms, a commit
            // or the actions alone, records the state it was judged against.
            let embedded = self
                .follow_held(principal_id, &mut principal, bundle, &mut HeldCache::new())
                .await?;
            let built = Self::build_staged(&mut principal, bundle, principal_id, next_seq).await;
            // SPEC 15.5: while the principal is in Error, only a bundle that
            // leaves Error is processed; what it would leave is `in_error` of
            // the held commits plus the candidate. A fixed protocol rule, never
            // a recovery strategy's. The fork state is read only for a bundle
            // that verified on the chain: it costs the depth of the fork (the
            // canonical chain from one below the lowest retained commit), and
            // a bundle no key of the principal signed is refused before it,
            // so a stranger's push costs the victim nothing of its length.
            let held = if built.is_ok() {
                self.held(principal_id).await?
            } else {
                Vec::new()
            };
            let asserted = self.resyncs.asserted(principal_id);
            let errored = (built.is_ok() && in_error(&held, &asserted)).then_some(held.as_slice());
            let mut build = match built {
                Ok(Built::Commit(build))
                    if errored.is_some_and(|e| stays_errored(e, &asserted, &build.commit)) =>
                {
                    // Refused, and kept as evidence: it verifies on the chain.
                    self.keep_evidence(bundle, build.commit, &embedded).await;
                    return Err(EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    });
                },
                Ok(Built::Commit(build)) => build,
                Ok(Built::Actions(_)) if errored.is_some() => {
                    return Err(EngineError::Errored {
                        principal_id: principal_id.to_string(),
                    });
                },
                Ok(Built::Actions(staged)) => {
                    // An action is included only by a commit of its principal,
                    // and a principal's commits start at its genesis commit
                    // (be0663f 2.3.2): actions pushed ahead of it would be
                    // recorded under a key no chain includes.
                    if tip_before.is_none() {
                        return Err(EngineError::Protocol(cyphr::Error::GenesisIncomplete));
                    }
                    // Action-only bundle: no commit is formed and nothing is
                    // indexed, but its actions are in DT from now on, so every
                    // later replay records them. One whose every action DT
                    // already held is the same push repeated (a client cannot
                    // tell which actions a peer holds): it stores nothing
                    // (SPEC 7.6).
                    let blob_hashes = if repeats? {
                        bundle
                            .actions
                            .iter()
                            .map(|blob| Blake3Hash::from_bytes(*blake3::hash(blob).as_bytes()))
                            .collect()
                    } else {
                        stored_any = true;
                        let hashes = self
                            .store_actions(principal_id, &bundle.actions, &embedded)
                            .await?;
                        // Held on the state only once stored, so no refusal
                        // before this point leaves it holding an action the
                        // store does not. Verified when staged, so holding
                        // them checks nothing again, and holding actions in
                        // memory has no failure path: this `?` is the Commit
                        // variant's, which this one never takes.
                        staged
                            .commit()
                            .await
                            .map_err(|e| EngineError::Protocol(e.source))?;
                        hashes
                    };
                    // Built from the tip read before any write: once the blobs are
                    // durable this response cannot fail (an error would report a
                    // stored bundle as not stored).
                    let tip = tip_before.clone().and_then(|t| {
                        Some(CommittedTip {
                            sequence: t.commit_count.checked_sub(1)?,
                            commit_id: t.commit_id,
                            pr: t.pr,
                            sr: t.sr,
                            ar: t.ar,
                            cr: t.cr,
                        })
                    });
                    // The actions are held on the state already: it is the
                    // kept state of the next write.
                    return Ok((
                        IngestResult {
                            principal_id: principal_id.to_string(),
                            blob_hashes,
                            manifest_hash: None,
                            tip,
                        },
                        embedded.is_empty(),
                    ));
                },
                Err(refused) => {
                    // A genesis commit pushed to a principal that has one is a
                    // rival at position 0: its arrow binds the genesis key, not
                    // this tip (SPEC 5.1 step 4), whatever transaction of it the
                    // replay happened to refuse first. A replay of the stored
                    // genesis itself stays the reuse it is (SPEC 7.6).
                    let reuse = matches!(refused, EngineError::Protocol(cyphr::Error::CozReuse));
                    let refused = if tip_before.is_some() && !reuse && is_genesis_bundle(bundle) {
                        EngineError::Protocol(cyphr::Error::CommitMismatch)
                    } else {
                        refused
                    };
                    // Only a verification failure can be a fork; a malformed
                    // or unreadable bundle is nothing to keep.
                    if matches!(refused, EngineError::Protocol(_)) {
                        // A bundle that extends a retained rival resolves the
                        // fork (SPEC 15.8) or, below the head, forks anew.
                        match self
                            .resolve_fork(principal_id, &genesis, bundle, principal.state())
                            .await
                        {
                            Ok(Some(resolved)) => return Ok((resolved, false)),
                            Ok(None) => {},
                            Err(
                                refusal @ (EngineError::BranchLimit { .. }
                                | EngineError::Errored { .. }),
                            ) => return Err(self.answer_in_error(principal_id, refusal).await),
                            Err(err) => tracing::warn!(
                                principal = %principal_id,
                                error = %err,
                                "could not test a refused bundle as a resolution; retaining it"
                            ),
                        }
                        if let Some(parent) = &parent {
                            // Boxed: this future's type is already deep, and
                            // the auto-trait check of a spawned push would
                            // otherwise overflow the compiler's limit.
                            match Box::pin(self.retain_pair(
                                principal_id,
                                &genesis,
                                parent,
                                bundle,
                                principal.state(),
                            ))
                            .await
                            {
                                Ok(PairKept::Promoted(resolved)) => {
                                    return Ok((*resolved, false));
                                },
                                Ok(PairKept::Kept) => {
                                    return Err(EngineError::Protocol(
                                        cyphr::Error::CommitMismatch,
                                    ));
                                },
                                Ok(PairKept::No) => {},
                                Err(
                                    refusal @ (EngineError::BranchLimit { .. }
                                    | EngineError::Errored { .. }),
                                ) => {
                                    return Err(
                                        self.answer_in_error(principal_id, refusal).await
                                    );
                                },
                                Err(err) => tracing::warn!(
                                    principal = %principal_id,
                                    error = %err,
                                    "could not retain an offered pair; answering the original refusal"
                                ),
                            }
                        }
                        match self
                            .retain_rival(principal_id, genesis, bundle, principal.state())
                            .await
                        {
                            // Held as a fork participant: the answer says so
                            // (the arrow does not fit the tip), whichever
                            // tip-state refusal the replay hit first, a
                            // duplicate key among them.
                            Ok(true) => {
                                return Err(EngineError::Protocol(cyphr::Error::CommitMismatch));
                            },
                            Ok(false) => {},
                            // The one retention outcome that is a refusal in
                            // its own right: no slot left for this key.
                            Err(full @ EngineError::BranchLimit { .. }) => {
                                return Err(self.answer_in_error(principal_id, full).await);
                            },
                            // Retention is best-effort evidence keeping: a
                            // storage fault must not turn the fork's own
                            // refusal (409/422) into a 500.
                            Err(err) => tracing::warn!(
                                principal = %principal_id,
                                error = %err,
                                "could not retain a refused rival; answering the original refusal"
                            ),
                        }
                    }
                    // In Error every write the principal's own key signed is
                    // answered by the Error, whether or not it could be
                    // kept: a commit over a parent the engine does not hold
                    // (one past a cap) cannot be verified, and the answer
                    // does not depend on that.
                    if matches!(refused, EngineError::Protocol(_))
                        && authenticated_signers(
                            bundle,
                            principal.state(),
                            &self.branches.keys(principal_id),
                        )
                        .is_some()
                        && self.is_errored(principal_id).await.unwrap_or(false)
                    {
                        return Err(EngineError::Errored {
                            principal_id: principal_id.to_string(),
                        });
                    }
                    return Err(refused);
                },
            };
            let remembered = embedded.is_empty();
            build.embedded = embedded;
            stored_any = true;
            let result = self.ingest_commit(bundle, *build).await?;
            Ok((result, remembered))
        }
        .await;

        match written {
            Ok((result, remember)) => {
                // A write that followed an embedded principal leaves a
                // state the replay does not build ([`Kept::embeds`]).
                if remember
                    && !embeds
                    && let Some(tip) = &result.tip
                    && let Some(count) = tip.sequence.checked_add(1)
                {
                    let embeds = principal.has_kt_digests();
                    self.keep(
                        principal.into_state(),
                        &tip.commit_id,
                        count,
                        embeds,
                        &write,
                    );
                }
                Ok(result)
            },
            Err(refused) => {
                if let (false, Some(tip)) = (stored_any, &tip_before) {
                    let state = pristine.unwrap_or_else(|| principal.into_state());
                    self.keep(state, &tip.commit_id, tip.commit_count, embeds, &write);
                }
                Err(refused)
            },
        }
    }

    /// The stored principal `principal_id` at `tip`, verified: the one way
    /// the engine gets a principal's verified state at its tip, for a write
    /// ([`Self::submit_commit`]) and for every reader ([`Self::at_tip`]).
    /// Read from the kept state when that stands at `tip`, else replayed
    /// from the blob store. The caller keeps what it leaves
    /// ([`Self::keep`]).
    ///
    /// `genesis` when the caller holds it; `None` reads it from the stored
    /// chain if a replay needs it.
    ///
    /// Boxed, as is [`Self::follow_held`]: the auto-trait proof that
    /// `submit_commit` is `Send` would otherwise run through the replay and
    /// exceed the compiler's recursion limit for a caller with a concrete
    /// storage type.
    fn verified<'a>(
        &'a self,
        principal_id: &'a str,
        genesis: Option<&'a crate::Genesis>,
        tip: &'a TipState,
        write: &'a WriteLock<'_>,
    ) -> VerifiedFuture<'a, S> {
        Box::pin(async move {
            let genesis = match genesis {
                Some(genesis) => genesis.clone(),
                None => self.genesis_of_stored(principal_id).await?,
            };
            if let Some((principal, embeds)) =
                self.resume_kept(principal_id, &genesis, tip, write).await?
            {
                return Ok(Verified { principal, embeds });
            }
            let principal = self.replay_stored(principal_id, genesis).await?;
            // Read only where the answer is used: nothing is kept at
            // capacity 0. A history that cannot be read is taken to embed.
            let embeds = self.kept.enabled()
                && (principal.has_kt_digests()
                    || self.history_has_pins(principal_id).await.unwrap_or(true));
            Ok(Verified { principal, embeds })
        })
    }

    /// Keep `state`, verified at the commit `tip` that is the principal's
    /// `count`th, for the principal's next use. Not kept: a state that is
    /// not at that commit (the commit was stored but its log append
    /// failed: the next load repairs it).
    fn keep(
        &self,
        state: cyphr::PrincipalState,
        tip: &str,
        count: u64,
        embeds: bool,
        write: &WriteLock<'_>,
    ) {
        if state.commit_count() as u64 != count {
            return;
        }
        let kept = Kept {
            state,
            tip: tip.to_string(),
            embeds,
        };
        self.kept.put(kept, write);
    }

    /// The principal at `tip`, resumed from the state kept for it, with
    /// that state's [`Kept::embeds`], or `None` for a replay: nothing is
    /// kept, or what is kept stands at another commit or over another log.
    ///
    /// The kept state is moved out of the cache, never copied: a write
    /// applies to it in place, and whoever resumed it stores what it
    /// leaves ([`Self::keep`]). With shadow checking on, the state is also
    /// replayed cold and compared, and a difference fails the call.
    async fn resume_kept(
        &self,
        principal_id: &str,
        genesis: &crate::Genesis,
        tip: &TipState,
        write: &WriteLock<'_>,
    ) -> Result<Option<(cyphr::Principal<S>, bool)>, EngineError> {
        let resumed = match self.kept.take(write) {
            Some(kept) if kept.tip == tip.commit_id => self
                .resume_over_log(principal_id, kept.state)
                .await
                .map(|principal| (principal, kept.embeds)),
            _ => None,
        };
        let Some((resumed, embeds)) = resumed else {
            // A stale entry can never match again, and the replay is about
            // to replace it: it is already out of the cache.
            self.counters.bump(Counter::KeptMisses);
            return Ok(None);
        };
        if self.kept.shadow() {
            let cold = self.replay_stored(principal_id, genesis.clone()).await?;
            if cold.projection() != resumed.projection() {
                self.counters.bump(Counter::KeptDivergences);
                let why = format!(
                    "kept state of {principal_id} at {} differs from the replay of its stored \
                     chain",
                    tip.commit_id
                );
                tracing::error!("{why}");
                // Loud on purpose: shadow checking exists to fail a run that
                // would otherwise be answered, correctly, from the replay.
                return Err(EngineError::Storage(why));
            }
        }
        self.counters.bump(Counter::KeptHits);
        if self.kept.shadow() {
            // Under the server's own target so a run's log shows that the
            // check ran (the scenarios' `RUST_LOG` names `cyphr_server`).
            tracing::info!(
                target: "cyphr_server::kept_state",
                principal = %principal_id,
                "shadow check: kept state equals the replay"
            );
        }
        Ok(Some((resumed, embeds)))
    }

    /// `state` over its principal's current commit log, or `None` if that
    /// log is not the one it was folded from (a regenerated or lagging log
    /// is the replay's to repair).
    async fn resume_over_log(
        &self,
        principal_id: &str,
        state: cyphr::PrincipalState,
    ) -> Option<cyphr::Principal<S>> {
        let generation = self.logs.generation(principal_id).ok()?;
        let storage = self.logs.open(principal_id, generation).ok()?;
        cyphr::Principal::resume(state, storage).await.ok()
    }

    /// Whether any commit or held action bundle of `principal_id` was
    /// admitted through an embedded principal ([`EmbeddedPin`]).
    async fn history_has_pins(&self, principal_id: &str) -> Result<bool, EngineError> {
        let held_actions = self
            .actions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .is_some_and(|held| held.iter().any(|a| !a.embedded.is_empty()));
        if held_actions {
            return Ok(true);
        }
        let chain = self.chain(principal_id, None, None).await?;
        Ok(chain.iter().any(|commit| {
            self.frame(principal_id, commit)
                .is_none_or(|f| !f.embedded.is_empty())
        }))
    }

    /// Follow every Key Tree digest of `principal` that names a principal
    /// this node holds, to the tip held for it (SPEC 10.7: references
    /// trigger tip retrieval), so the verifier judges `bundle` against it
    /// (10.5: the signer is an active key of B at that tip). Returns the
    /// state of each embedded principal a signer of `bundle` was authorized
    /// through, to record in the commit's manifest. A digest naming nothing
    /// held stays opaque: it authorizes nothing (10.3).
    ///
    /// Boxed: the auto-trait proof that `submit_commit` is `Send` would
    /// otherwise run through the core's follow, the tip source and a replay
    /// of B, and exceed the compiler's recursion limit for a caller with a
    /// concrete storage type.
    fn follow_held<'a, T: cyphr::eml::Storage + Send>(
        &'a self,
        own_id: &'a str,
        principal: &'a mut cyphr::Principal<T>,
        bundle: &'a WireBundle,
        held: &'a mut HeldCache<S>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<EmbeddedPin>, EngineError>> + Send + 'a>,
    > {
        Box::pin(self.follow_held_unboxed(own_id, principal, bundle, held))
    }

    async fn follow_held_unboxed<T: cyphr::eml::Storage>(
        &self,
        own_id: &str,
        principal: &mut cyphr::Principal<T>,
        bundle: &WireBundle,
        held: &mut HeldCache<S>,
    ) -> Result<Vec<EmbeddedPin>, EngineError> {
        if !principal.has_kt_digests() {
            return Ok(Vec::new());
        }
        let decoded = decode_bundle(bundle)?;
        let outside = |p: &cyphr::Principal<T>, tmb: &coz::Thumbprint| {
            !(p.is_key_active(tmb) || decoded.introduced_keys().any(|k| k.tmb() == tmb))
        };
        // With every signer a key of the principal now, none can be an
        // embedded principal's and there is nothing to follow, which saves
        // every embedded principal's replay. A key the bundle introduces
        // does not count: one that signs before its own introduction is not
        // yet a key of the principal, and is judged through the embedded
        // views, which must be current (SPEC 10.5).
        if decoded
            .cozies()
            .all(|coz| principal.is_key_active(&coz.header().tmb))
        {
            return Ok(Vec::new());
        }
        // The core reports every Key Tree digest but offers no list of
        // them, and only a revealed digest is followed: a source with no
        // tips names them, then each is revealed as followed.
        let members: Vec<String> = principal
            .follow_embedded(&mut NoTips)
            .await
            .into_iter()
            .map(|report| report.member)
            .collect();
        for member in &members {
            principal
                .reveal_embedded(member, cyphr::Tracking::Follow)
                .map_err(EngineError::Protocol)?;
        }
        let mut tips = HeldTips {
            engine: self,
            own_id,
            cache: held,
            found: std::collections::BTreeSet::new(),
            failed: None,
        };
        principal.follow_embedded(&mut tips).await;
        if let Some(failed) = tips.failed {
            return Err(failed);
        }
        let found = tips.found;
        let mut pins: Vec<EmbeddedPin> = Vec::new();
        for coz in decoded.cozies() {
            let tmb = &coz.header().tmb;
            if !outside(principal, tmb) {
                continue;
            }
            for member in &found {
                let Some((_, b, state)) = held.get(member).and_then(Option::as_ref) else {
                    continue;
                };
                let pin = EmbeddedPin {
                    member: member.clone(),
                    b: b.clone(),
                };
                if state.held_key(tmb) && !pins.contains(&pin) {
                    pins.push(pin);
                }
            }
        }
        Ok(pins)
    }

    /// The tip this node holds of the principal `member` names, with the PR
    /// it stands at and the principal itself: read at its tip from the
    /// state the engine keeps, or replayed once and kept
    /// ([`Self::verified`]), the naked revokes held applied, `Error`
    /// marked.
    ///
    /// Boxed: it is the one way `follow_held` re-enters the engine, and a
    /// `Send` proof for `follow_held` otherwise runs through the whole
    /// replay call graph, past the compiler's recursion limit.
    fn held_tip<'a>(&'a self, member: &'a str, own_id: &'a str) -> HeldRead<'a, S> {
        Box::pin(async move {
            // A principal embedding itself names no other principal's tip; its
            // log is also the one the caller is writing.
            let Some(id) = self
                .principal_named(member)
                .await?
                .filter(|id| id != own_id)
            else {
                return Ok(None);
            };
            // B at its tip, by the one entry every reader takes, so a
            // bundle that merely names a signer A does not hold (anyone can
            // send one) replays B at most once and is then served from the
            // state kept for B. B's write lock is only tried: A's is held,
            // and two principals that embed each other, written at once,
            // would each wait on the other's. A B that is being written is
            // replayed without it, as B's own log repair allows: a push
            // appends B's log before it writes the index, so a replay that
            // does not hold B's lock can find the log one leaf ahead of the
            // chain and regenerate it for nothing. That costs a rebuild, never
            // a wrong state, because regeneration is serialized by its own
            // lock (`replay_stored`), not by B's write lock.
            let lock = self.principal_lock(&id);
            let state = match Self::try_lock_writes(&lock, &id) {
                Some(write) => match self.indexer.get_tip(&id).await? {
                    Some(tip) => {
                        let verified = self.verified(&id, None, &tip, &write).await?;
                        self.keep(
                            verified.principal.state().clone(),
                            &tip.commit_id,
                            tip.commit_count,
                            verified.embeds,
                            &write,
                        );
                        verified.principal
                    },
                    None => return Ok(None),
                },
                None => {
                    let genesis = self.genesis_of_stored(&id).await?;
                    self.replay_stored(&id, genesis).await?
                },
            };
            let pr = state.pr_tagged().map_err(EngineError::Protocol)?;
            let revoked = self.deaths.snapshot();
            let mut tip =
                cyphr::Tip::new(&state, unix_now().unwrap_or(0)).with_revoked(revoked.keys());
            if self.error_state_of(&id).await?.is_some() {
                tip = tip.in_error();
            }
            Ok(Some((tip, pr, state)))
        })
    }

    /// Store an accepted action-only bundle and its [`ActionManifest`],
    /// and list it for replay. Returns the blob hashes.
    async fn store_actions(
        &self,
        principal_id: &str,
        blobs: &[Vec<u8>],
        embedded: &[EmbeddedPin],
    ) -> Result<Vec<Blake3Hash>, EngineError> {
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            blob_hashes.push(self.blob_store.put(blob).await?);
        }
        let manifest = ActionManifest {
            kind: ACTION_MANIFEST_KIND.to_string(),
            principal_id: principal_id.to_string(),
            blob_hashes: blob_hashes.clone(),
            embedded: embedded.to_vec(),
        };
        let mut bytes = ACTION_MANIFEST_PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("action manifest serialize: {e}")))?;
        let hash = self.blob_store.put(&bytes).await?;
        // The push is answered 201 with these hashes, which tells the caller
        // the actions are recorded: durable before they are listed or the
        // answer is built.
        self.persist_record().await?;
        let mut held = self.actions.lock().unwrap_or_else(|p| p.into_inner());
        let of_principal = held.entry(principal_id.to_string()).or_default();
        if !of_principal.iter().any(|a| a.manifest == hash) {
            of_principal.push(StoredActions {
                manifest: hash,
                blobs: blob_hashes.clone(),
                embedded: embedded.to_vec(),
            });
        }
        Ok(blob_hashes)
    }

    /// Verify `bundle` against `principal`'s current state and build the
    /// commit they would form at `next_seq`, staged: nothing is written,
    /// to storage or to the principal's commit log, until the caller
    /// commits the returned [`StagedBuild`]. `Ok(None)` is an action-only
    /// bundle: it forms no commit (its actions are recorded on
    /// `principal`, in memory).
    ///
    /// Storage-free so a refused fork can be re-verified against an earlier
    /// state ([`Self::retain_rival`]) by the same code that admits a tip.
    async fn build_commit<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &str,
        next_seq: u64,
    ) -> Result<Option<StagedBuild<'p, T>>, EngineError> {
        Ok(
            match Self::build_staged(principal, bundle, principal_id, next_seq).await? {
                Built::Commit(build) => Some(*build),
                Built::Actions(_) => None,
            },
        )
    }

    /// [`Self::build_commit`], keeping the stage of an action-only bundle
    /// for the caller that holds its actions once stored, so they are
    /// verified once.
    async fn build_staged<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &str,
        next_seq: u64,
    ) -> Result<Built<'p, T>, EngineError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let active_algs = principal.active_algs().to_vec();

        let decoded = decode_bundle(bundle)?;
        let cozies: Vec<&cyphr::replay::StoredCoz> = decoded.cozies().collect();
        let extracted_keys: Vec<crate::PublicKeyInfo> = decoded
            .introduced_keys()
            .map(|key| crate::PublicKeyInfo {
                thumbprint: key.tmb().to_b64(),
                algorithm: key.alg().to_string(),
                public_key: Base64UrlUnpadded::encode_string(key.pub_key()),
            })
            .collect();
        let last_timestamp = cozies.last().map_or(0, |c| c.header().now);

        // The principal's state BEFORE this bundle: the chain link (`pre`) is
        // the previous commit's PR, and a PG established by this bundle is
        // the PR held before the `principal/create` commit (SPEC §3.7.1).
        let commit_pre = if next_seq == 0 {
            None
        } else {
            format_multihash_all(principal.pr().as_multihash())?
                .first()
                .cloned()
        };
        let had_pg = principal.pg().is_some();
        let staged = cyphr::replay::stage_bundle(principal, &decoded)
            .await
            .map_err(|e| EngineError::Protocol(e.source))?;
        let cyphr::replay::StagedBundle::Commit { staged: stage, .. } = &staged else {
            return Ok(Built::Actions(staged));
        };
        let principal = stage.state();
        let commit = principal
            .commits()
            .last()
            .ok_or(EngineError::Protocol(cyphr::Error::MissingCommit))?;
        let commit_ids = format_multihash_all(&commit.tr().0)?;
        let ar = format_multihash_opt(commit.auth_root().map(|a| a.as_multihash()))?;
        let sr = format_multihash_opt(commit.sr().map(|s| s.as_multihash()))?;
        let pr = format_multihash_all(commit.pr().as_multihash())?;
        let cr = principal
            .cr()
            .map(|c| format_multihash_all(c.as_multihash()))
            .transpose()?
            .unwrap_or_default();

        let pg = match principal.pg() {
            Some(pg) if !had_pg => format_multihash_all(pg.as_multihash())?,
            _ => Vec::new(),
        };

        let mut indexed = Vec::with_capacity(cozies.len());
        for coz in cozies {
            let source_alg = coz.hash_alg();
            let tagged = cyphr::state::TaggedCzd::new(coz.czd(), source_alg);

            let post_active_algs = active_algs.clone();
            let primary_alg = post_active_algs.first().copied().unwrap_or(source_alg);
            let converted = tagged.convert_to(primary_alg);
            let primary_czd = format!(
                "{primary_alg}:{}",
                Base64UrlUnpadded::encode_string(&converted)
            );

            indexed.push(IndexableCoz {
                blob_hash: Blake3Hash::from_bytes([0; 32]), // filled in by ingest_commit
                czd: primary_czd,
                typ: coz.header().typ.clone(),
                tmb: coz.header().tmb.to_b64(),
                alg: coz.alg().to_string(),
                now: coz.header().now,
                payload: serde_json::to_string(coz.pay()).ok(),
            });
        }

        let commit = IndexableCommit {
            principal_id: principal_id.to_string(),
            commit_ids,
            sequence: next_seq,
            pre: commit_pre,
            prs: pr,
            srs: sr,
            ars: ar,
            crs: cr,
            blob_hashes: Vec::new(), // filled in by ingest_commit
            cozies: indexed,
            timestamp: last_timestamp,
            keys: extracted_keys,
            pg,
        };

        Ok(Built::Commit(Box::new(StagedBuild {
            commit,
            staged,
            embedded: Vec::new(),
        })))
    }

    /// How many leading commits of `chain`, a peer's chain oldest first,
    /// this engine holds (canonical or retained): a PoP is offered with the
    /// line that starts after them ([`Self::submit_resync`]). A commit
    /// whose id cannot be read ends the prefix. Zero for a principal that
    /// is not stored.
    pub async fn held_prefix(
        &self,
        principal_id: &str,
        chain: &[WireBundle],
    ) -> Result<usize, EngineError> {
        let Some(tip) = self.get_tip(principal_id).await? else {
            return Ok(0);
        };
        let Ok(alg) = tip.commit_id.parse::<TaggedDigest>().map(|d| d.alg()) else {
            return Ok(0);
        };
        for (i, bundle) in chain.iter().enumerate() {
            let Some(id) = bundle.decode().ok().and_then(|d| d.commit_id(alg)) else {
                return Ok(i);
            };
            if !self.holds_commit(principal_id, &id.to_string()).await? {
                return Ok(i);
            }
        }
        Ok(chain.len())
    }

    /// The per-alias locks guarding the PG claims of `commits`, in sorted
    /// order so contenders cannot deadlock. The caller locks each.
    fn alias_locks(&self, commits: &[&IndexableCommit]) -> Vec<Arc<tokio::sync::Mutex<()>>> {
        let mut aliases: Vec<String> = commits
            .iter()
            .flat_map(|c| &c.pg)
            .map(|pg| format!("pg-alias\0{pg}"))
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        aliases.iter().map(|a| self.principal_lock(a)).collect()
    }

    async fn read_blobs(&self, hashes: &[Blake3Hash]) -> Result<Vec<Vec<u8>>, EngineError> {
        let mut blobs = Vec::with_capacity(hashes.len());
        for hash in hashes {
            blobs.push(
                self.blob_store
                    .get(hash)
                    .await?
                    .ok_or_else(|| EngineError::NotFound(format!("blob {hash} missing")))?,
            );
        }
        Ok(blobs)
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material from the first stored
    ///   commit's blobs.
    /// - If the principal is new, extracts key material from the first of the caller's `submitted`
    ///   bundles, its genesis commit.
    ///
    /// Both cases apply the identical genesis-discovery rule ([`disclosed_genesis`]) over their
    /// respective bundle.
    pub async fn resolve_genesis(
        &self,
        principal_id: &str,
        submitted: &[WireBundle],
    ) -> Result<crate::Genesis, EngineError> {
        self.ensure_healed().await?;

        if let Some(stored_id) = self.stored_id(principal_id).await? {
            // Existing principal: its genesis is in its first stored commit.
            self.genesis_of_stored(&stored_id).await
        } else {
            // New principal — the caller's own first bundle is its first commit.
            Self::genesis_from_bundle(submitted.first())
        }
    }

    /// Genesis of the principal stored under exactly `stored_id`, read from
    /// its first stored commit's blobs.
    async fn genesis_of_stored(&self, stored_id: &str) -> Result<crate::Genesis, EngineError> {
        let chain = self.chain(stored_id, Some(0), Some(0)).await?;
        let first_commit = chain.first().ok_or_else(|| {
            EngineError::NotFound(format!("principal {stored_id} has no stored commits"))
        })?;
        let bundle = self.commit_bundle(stored_id, first_commit).await?;
        Self::genesis_from_bundle(Some(&bundle))
    }

    /// The spelling under which `principal_id` is stored, if a principal is.
    ///
    /// A labelled id (`ALG:digest`) is its own spelling. A bare digest
    /// names whichever labelled spelling has a stored chain; at most one
    /// can, because [`submit_commit`](Self::submit_commit) stores only the
    /// canonical spelling. A Principal Root alias (the PG, or any other PR
    /// the principal has had) resolves to the principal's canonical id.
    async fn stored_id(&self, principal_id: &str) -> Result<Option<String>, EngineError> {
        let candidates: Vec<String> = if principal_id.contains(':') {
            vec![principal_id.to_string()]
        } else {
            ID_LABELS
                .iter()
                .map(|label| format!("{label}:{principal_id}"))
                .collect()
        };
        for candidate in candidates {
            // The index resolves a Principal Root alias to the stored id. A
            // tip with no stored chain is a corrupt index, not a stored
            // principal.
            let Some(tip) = self.indexer.get_tip(&candidate).await? else {
                continue;
            };
            let chain = self.chain(&candidate, Some(0), Some(0)).await?;
            if !chain.is_empty() {
                return Ok(Some(tip.principal_id));
            }
        }
        Ok(None)
    }

    /// The id a principal is stored and reported under (its key), or
    /// `principal_id` unchanged if no such principal is stored. Read paths
    /// resolve on the key, so every address (key, PG or PG variant) reaches
    /// one chain.
    pub async fn canonical_principal_id(&self, principal_id: &str) -> Result<String, EngineError> {
        self.ensure_healed().await?;
        Ok(self
            .resolve_key(principal_id)
            .await?
            .unwrap_or_else(|| principal_id.to_string()))
    }

    /// The storage key `principal_id` addresses, if any.
    async fn resolve_key(&self, principal_id: &str) -> Result<Option<String>, EngineError> {
        self.stored_id(principal_id).await
    }

    /// The genesis a principal's first commit bundle discloses
    /// ([`disclosed_genesis`]). Every chain begins with a genesis commit
    /// whose `key/create`s disclose its keys (SPEC 5.1), so a bundle that
    /// discloses none names no principal.
    fn genesis_from_bundle(bundle: Option<&WireBundle>) -> Result<crate::Genesis, EngineError> {
        let Some(bundle) = bundle.filter(|b| !b.is_empty()) else {
            return Err(EngineError::NotFound(
                "no blobs to resolve genesis from".into(),
            ));
        };
        disclosed_genesis(bundle).unwrap_or_else(|| Err(no_disclosed_genesis()))
    }
}

/// Whether a replay over a principal's log shows the log is not a cache of
/// its canonical chain: a leaf differs, or the log holds leaves past the
/// chain's last commit.
fn log_is_stale<S: cyphr::eml::Storage>(
    replayed: &Result<cyphr::Principal<S>, EngineError>,
) -> bool {
    match replayed {
        Ok(principal) => {
            principal.commit_trees().global_size() > principal.commits().count() as u64
        },
        Err(EngineError::Load(crate::import::LoadError::Protocol(
            cyphr::Error::DurableLeafMismatch(_),
        ))) => true,
        Err(_) => false,
    }
}

/// The principal the manifests name `member` as (its key, its PG or a PR
/// it held, in any manifest), if exactly one.
fn manifest_principal(source: &PinSource<'_>, member: &str) -> Option<String> {
    let (canonical, rest) = source.manifests?;
    let mut named: Vec<&str> = canonical
        .iter()
        .chain(rest)
        .filter(|(_, m)| {
            m.commit.principal_id == member
                || m.commit.prs.iter().chain(&m.commit.pg).any(|d| d == member)
        })
        .map(|(_, m)| m.commit.principal_id.as_str())
        .collect();
    named.sort_unstable();
    named.dedup();
    match named.as_slice() {
        [one] => Some((*one).to_string()),
        _ => None,
    }
}

/// The thumbprints that sign the transactions of `bundle`, if every coz
/// of the bundle is signed by a key the principal has ever held, or one a
/// principal it embeds has ever held, and its signature verifies under
/// that key; `None` otherwise, or if the bundle has no transaction. The
/// store's index of keys by thumbprint is never asked: it knows the keys of
/// every principal stored, a stranger's among them.
///
/// The key history is read from `tip`, the principal's
/// verified state at its tip, and from `retained`, the keys of the
/// principal's own retained rivals (a resolution may be signed by a key
/// only a rival branch introduced, SPEC 15.8), so this costs the bundle and
/// the retained keys and reads nothing of the stored chain: a bundle nobody of the principal signed
/// is settled here, before any of its history is read.
fn authenticated_signers(
    bundle: &WireBundle,
    tip: &cyphr::PrincipalState,
    retained: &[KeyEntry],
) -> Option<Vec<coz::Thumbprint>> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    // The keys of the bundle's signers: those the principal has held, and
    // those a principal it embeds has held (SPEC 10.3), by the views `tip`
    // holds of them. A key known to the store for some other principal is
    // nobody's here: a stranger's signature authenticates nothing, however
    // well the store knows the stranger.
    let mut history: HashMap<String, (String, Vec<u8>)> = HashMap::new();
    for blob in bundle.cozies() {
        let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
        for named in ["tmb", "id"] {
            let Some(tmb) = value
                .pointer(&format!("/pay/{named}"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let Ok(bytes) = Base64UrlUnpadded::decode_vec(tmb) else {
                continue;
            };
            let tmb_bytes = coz::Thumbprint::from_bytes(bytes);
            if let Some(key) = tip
                .key_ever_held(&tmb_bytes)
                .or_else(|| tip.embedded_key_ever_held(&tmb_bytes))
            {
                history.insert(
                    tmb.to_owned(),
                    (key.alg().to_owned(), key.pub_key().to_vec()),
                );
            } else if let Some(k) = retained.iter().find(|k| k.tmb == tmb)
                && let Ok(public) = Base64UrlUnpadded::decode_vec(&k.pub_key)
            {
                history.insert(tmb.to_owned(), (k.alg.clone(), public));
            }
        }
    }

    let mut signers = Vec::new();
    // Keys this bundle introduces: they are not held at any `pre`, so
    // they are not signers retention looks for there.
    let mut introduced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for blob in bundle.cozies() {
        let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
        let mut pay = value.get("pay")?.clone();
        crate::import::canonicalize_value(&mut pay);
        let header = cyphr::parsed_coz::CozHeader::parse(&pay).ok()?;
        let sig = Base64UrlUnpadded::decode_vec(value.get("sig")?.as_str()?).ok()?;
        let (alg, public) = history.get(&header.tmb.to_b64())?;
        let pay_json = serde_json::to_vec(&pay).ok()?;
        if coz::verify_json(&pay_json, &sig, alg, public) != Some(true) {
            return None;
        }
        // A key a verified coz of this bundle introduces (`key/create`,
        // `key/replace`) may sign the cozies after it, as its own commit
        // does when it finalizes a rotation; the bundle discloses it, bound
        // to the `id` by its thumbprint.
        if cyphr::parsed_coz::typ::is_key_introducing(&header.typ)
            && let Some(id) = pay.get("id").and_then(|v| v.as_str())
        {
            // A key the principal already held is no new signer.
            let disclosed = bundle
                .keys
                .iter()
                .find(|k| k.tmb == id && !history.contains_key(id));
            if let Some(k) = disclosed {
                let public = Base64UrlUnpadded::decode_vec(&k.pub_key).ok()?;
                let bound = coz::compute_thumbprint_for_alg(&k.alg, &public)
                    .is_some_and(|t| t.to_b64() == id);
                if bound {
                    history.insert(id.to_string(), (k.alg.clone(), public));
                    introduced.insert(id.to_string());
                }
            }
        }
        if cyphr::parsed_coz::typ::is_transaction(&header.typ)
            && !introduced.contains(&header.tmb.to_b64())
        {
            signers.push(header.tmb);
        }
    }
    (!signers.is_empty()).then_some(signers)
}

/// The genesis a principal's first commit discloses, in wire order: every
/// key a `key/create` transaction before the `principal/create` introduces
/// (the bundle's `keys` entry its `id` names), the genesis key first (SPEC
/// 5.1 steps 1-2, 5.3, 7.7 Example 1); with one such key it is that key's
/// genesis. `None` when the bundle carries no `principal/create`, or no
/// `key/create` before it: such a bundle is no genesis commit, so its
/// principal cannot be read from it. A key the genesis creates beyond its
/// first gives the same state whether it is read as a genesis key or as one
/// added in the genesis commit.
fn disclosed_genesis(bundle: &WireBundle) -> Option<Result<crate::Genesis, EngineError>> {
    use cyphr::parsed_coz::typ::{KEY_CREATE, PRINCIPAL_CREATE, has_suffix};

    let values: Vec<serde_json::Value> = bundle
        .txs
        .iter()
        .flatten()
        .filter_map(|b| serde_json::from_slice(b).ok())
        .collect();
    let typ = |v: &serde_json::Value| v.pointer("/pay/typ")?.as_str().map(str::to_owned);
    let to_key = |v: &serde_json::Value| -> Result<cyphr::Key, EngineError> {
        let id = v.pointer("/pay/id").and_then(serde_json::Value::as_str);
        let entry = bundle
            .keys
            .iter()
            .find(|k| Some(k.tmb.as_str()) == id)
            .ok_or_else(|| {
                EngineError::MalformedBlob("a genesis key/create discloses no key".into())
            })?;
        crate::import::key_entry_to_key(entry)
            .map_err(|e| EngineError::MalformedBlob(format!("genesis key conversion: {e}")))
    };
    if let Some(pc) = values
        .iter()
        .position(|v| typ(v).is_some_and(|t| has_suffix(&t, PRINCIPAL_CREATE)))
    {
        let keys = values[..pc]
            .iter()
            .filter(|v| typ(v).is_some_and(|t| has_suffix(&t, KEY_CREATE)))
            .map(to_key)
            .collect::<Result<Vec<_>, _>>();
        return match keys {
            Err(e) => Some(Err(e)),
            Ok(mut keys) if keys.len() == 1 => keys.pop().map(|k| Ok(crate::Genesis::Implicit(k))),
            Ok(keys) if keys.is_empty() => None,
            Ok(keys) => Some(Ok(crate::Genesis::Disclosed(keys))),
        };
    }
    None
}

/// The refusal of a first bundle that discloses no genesis.
fn no_disclosed_genesis() -> EngineError {
    EngineError::MalformedBlob(
        "the first commit is no genesis commit: no key/create before a principal/create discloses \
         its keys (SPEC 5.1)"
            .into(),
    )
}

/// The key that signed a stored commit's bundle: [`commit_signer`] of the
/// commit the bundle forms.
fn bundle_signer(bundle: &WireBundle) -> Result<String, EngineError> {
    let decoded = decode_bundle(bundle)?;
    let cozies: Vec<_> = decoded.cozies().collect();
    Ok(cozies
        .iter()
        .rev()
        .find(|c| is_commit_create_typ(&c.header().typ))
        .or(cozies.last())
        .map(|c| c.header().tmb.to_b64())
        .unwrap_or_default())
}

/// Whether `typ` is the protocol's `commit/create` (authority-qualified
/// suffix, SPEC 7.3), never a substring match: an application typ that
/// merely contains `/commit/create` is an ordinary coz.
fn is_commit_create_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::COMMIT_CREATE)
}

/// The four roots of `principal`'s state.
fn roots_of<T: cyphr::eml::Storage>(
    principal: &cyphr::Principal<T>,
) -> Result<DerivedRoots, EngineError> {
    let pr = format_multihash_all(principal.pr().as_multihash())?
        .into_iter()
        .next()
        .ok_or_else(|| EngineError::InvalidInput("empty PR".into()))?;

    // SR and AR are absent for a Dead principal (SPEC 3.7: an empty
    // component is omitted).
    let sr = format_multihash_opt(principal.sr().map(|s| s.as_multihash()))?
        .into_iter()
        .next();

    let ar = format_multihash_opt(principal.auth_root().map(|a| a.as_multihash()))?
        .into_iter()
        .next();

    let cr = match principal.cr() {
        Some(cr_obj) => format_multihash_all(cr_obj.as_multihash())?
            .into_iter()
            .next()
            .unwrap_or_default(),
        None => String::new(),
    };

    Ok(DerivedRoots { pr, sr, ar, cr })
}

/// The czds of an action-only bundle's actions.
fn bundle_czds(bundle: &WireBundle) -> Result<Vec<Vec<u8>>, EngineError> {
    let decoded = WireBundle::actions(bundle.actions.clone())
        .decode()
        .map_err(|e| EngineError::MalformedBlob(e.to_string()))?;
    Ok(decoded
        .cozies()
        .map(|c| c.czd().as_bytes().to_vec())
        .collect())
}

/// The action-only bundle of an action manifest's stored blobs, or why
/// they are not one.
fn action_bundle(blobs: Vec<Vec<u8>>) -> Result<cyphr::replay::Bundle, String> {
    if blobs.is_empty() {
        return Err("not an action-only bundle".into());
    }
    WireBundle::actions(blobs)
        .decode()
        .map_err(|e| e.to_string())
}

/// Order action-only bundles by their earliest `now`, then manifest hash
/// (SPEC 4.8.1: actions are ordered by `now`, then lexically).
fn replay_order(bundles: &mut [ActionBundle]) {
    bundles.sort_by_cached_key(|b| {
        let first = b.bundle.cozies().map(|c| c.header().now).min();
        (first, *b.manifest.as_bytes())
    });
}

/// The [`CommitEntry`](crate::CommitEntry) replay reads from a stored
/// commit's bundle. State digest fields are inert during replay.
fn replay_entry(
    bundle: &WireBundle,
    commit_id: &str,
    pr: &str,
) -> Result<crate::CommitEntry, EngineError> {
    let entry = crate::CommitEntry::from_bundle(bundle).map_err(|e| {
        EngineError::MalformedBlob(format!("commit {commit_id} blob is not valid JSON: {e}"))
    })?;
    Ok(crate::CommitEntry {
        commit_id: commit_id.to_string(),
        pr: pr.to_string(),
        ..entry
    })
}

/// The principal `bundle` replays to as its first bundle, or `None` when
/// it does not replay from `genesis`.
async fn replay_first(genesis: &crate::Genesis, bundle: &WireBundle) -> Option<cyphr::Principal> {
    let mut principal = cyphr::Principal::implicit(genesis.key()?.clone())
        .await
        .ok()?;
    let entry = replay_entry(bundle, "", "").ok()?;
    crate::import::replay_commits(&mut principal, &[entry])
        .await
        .ok()?;
    Some(principal)
}

/// The storage key a principal's first bundle derives, a
/// function of the record alone (I1). A genesis commit (SPEC 5.1) keys it
/// by its PG, in the spelling of [`genesis_principal_id`] (the first active
/// algorithm); the PG is the state at `principal/create`, so a nonce in the
/// genesis commit already makes it unique (5.1: "a nonce embedding for a
/// unique PG"). A bundle of data actions alone forms no commit: a Level 1/2
/// principal is keyed by its genesis PR. `None` when the bundle does not
/// replay.
async fn record_key(genesis: &crate::Genesis, bundle: &WireBundle) -> Option<String> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let principal = replay_first(genesis, bundle).await?;
    let Some(pg) = principal.pg() else {
        return (principal.commits().next().is_none())
            .then(|| genesis_principal_id(genesis).ok())
            .flatten();
    };
    let alg = principal.active_algs().first().copied()?;
    let digest = pg.as_multihash().get(alg)?;
    Some(format!(
        "{alg}:{}",
        Base64UrlUnpadded::encode_string(digest)
    ))
}

/// Whether `bundle` carries a `principal/create`: a genesis commit (SPEC
/// 5.1).
fn is_genesis_bundle(bundle: &WireBundle) -> bool {
    bundle.txs.iter().flatten().any(|blob| {
        serde_json::from_slice::<serde_json::Value>(blob)
            .ok()
            .and_then(|v| v.pointer("/pay/typ")?.as_str().map(str::to_owned))
            .is_some_and(|typ| {
                cyphr::parsed_coz::typ::has_suffix(&typ, cyphr::parsed_coz::typ::PRINCIPAL_CREATE)
            })
    })
}

/// The members of a stored wire coz: exactly what the signature and the
/// protocol need (`pay` and `sig`; key material travels in the bundle's
/// `keys`, SPEC 4.6.2). Coz allows
/// applications to add members, so extras are tolerated on the wire but
/// never stored; `cad`/`czd` are recalculatable, so a present value is
/// recomputed and a mismatch refused (and the value dropped, as any
/// consumer can recompute it).
///
/// One signed coz therefore has one blob address, and a stored wire blob
/// cannot be shaped like anything else the engine stores.
fn canonical_coz(blob: &[u8], i: usize) -> Result<Vec<u8>, EngineError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let bad = |why: String| EngineError::MalformedBlob(format!("blob {i}: {why}"));
    let value: serde_json::Value = serde_json::from_slice(blob).map_err(|e| bad(e.to_string()))?;
    let serde_json::Value::Object(members) = value else {
        return Err(bad("not a JSON object".into()));
    };
    let mut pay = members
        .get("pay")
        .cloned()
        .ok_or_else(|| bad("missing 'pay'".into()))?;
    let sig = members
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| bad("missing 'sig'".into()))?;
    crate::import::canonicalize_value(&mut pay);

    let present = |name: &str| -> Result<Option<&str>, EngineError> {
        members
            .get(name)
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| bad(format!("'{name}' is not a string")))
            })
            .transpose()
    };
    let (cad, czd) = (present("cad")?, present("czd")?);
    if cad.is_some() || czd.is_some() {
        let alg = pay
            .get("alg")
            .and_then(|a| a.as_str())
            .ok_or_else(|| bad("missing 'alg' in pay".into()))?;
        let pay_bytes = serde_json::to_vec(&pay).map_err(|e| bad(format!("pay serialize: {e}")))?;
        let sig_bytes =
            Base64UrlUnpadded::decode_vec(sig).map_err(|_| bad("invalid sig base64".into()))?;
        let recomputed = coz::canonical_hash_for_alg(&pay_bytes, alg, None)
            .ok_or_else(|| bad("cad computation failed".into()))?;
        if cad.is_some_and(|c| c != recomputed.to_b64()) {
            return Err(bad("'cad' does not match the pay".into()));
        }
        if let Some(claimed) = czd {
            let czd = coz::czd_for_alg(&recomputed, &sig_bytes, alg)
                .ok_or_else(|| bad("czd computation failed".into()))?;
            if claimed != czd.to_b64() {
                return Err(bad("'czd' does not match the pay and sig".into()));
            }
        }
    }

    let mut canonical = serde_json::Map::new();
    canonical.insert("pay".into(), pay);
    canonical.insert("sig".into(), sig.into());
    let mut canonical = serde_json::Value::Object(canonical);
    crate::import::canonicalize_value(&mut canonical);
    serde_json::to_vec(&canonical).map_err(|e| bad(format!("serialize: {e}")))
}

/// A pushed bundle in the form the engine verifies and stores: each coz
/// canonical ([`canonical_coz`]), and of `keys` exactly one entry per key a
/// coz of `txs` introduces, holding `alg`, `pub` and `tmb` once the core has
/// checked `tmb` is the thumbprint of `pub`. `tag` and `now` are unsigned
/// labels, and the protocol sets a key's first-seen time from the signed
/// `pay.now` when it applies the introducing coz; an entry no coz names is
/// not stored, so a commit has one stored form whatever unsigned material
/// travelled with it.
fn canonical_bundle(bundle: &WireBundle) -> Result<WireBundle, EngineError> {
    let mut canonical = bundle.try_map(|i, blob| canonical_coz(blob, i))?;
    let named: std::collections::HashSet<String> = canonical
        .txs
        .iter()
        .flatten()
        .filter_map(|blob| {
            let value: serde_json::Value = serde_json::from_slice(blob).ok()?;
            let typ = value.pointer("/pay/typ")?.as_str()?;
            crate::import::is_key_introducing_typ(typ)
                .then(|| value.pointer("/pay/id")?.as_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    let mut keys: Vec<KeyEntry> = Vec::new();
    for entry in &bundle.keys {
        if !named.contains(&entry.tmb) || keys.iter().any(|k| k.tmb == entry.tmb) {
            continue;
        }
        crate::import::key_entry_to_key(entry).map_err(|e| match e {
            // e.g. `TmbMismatch`: a client-facing protocol refusal, not a
            // malformed bundle.
            crate::import::LoadError::Protocol(p) => EngineError::Protocol(p),
            other => {
                EngineError::MalformedBlob(format!("key {} is not a valid key: {other}", entry.tmb))
            },
        })?;
        keys.push(KeyEntry {
            tag: None,
            now: None,
            ..entry.clone()
        });
    }
    canonical.keys = keys;
    Ok(canonical)
}

/// A canonical bundle decoded for the core.
fn decode_bundle(bundle: &WireBundle) -> Result<cyphr::replay::Bundle, EngineError> {
    use cyphr::replay::WireError;
    bundle.decode().map_err(|e| match e.error {
        // e.g. `TmbMismatch`: a client-facing protocol refusal, not an
        // infrastructure failure.
        WireError::Key(p) | WireError::Protocol(p) => EngineError::Protocol(p),
        other => match e.coz {
            Some(i) => EngineError::MalformedBlob(format!("blob {i}: {other}")),
            None => EngineError::MalformedBlob(format!("keys: {other}")),
        },
    })
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
