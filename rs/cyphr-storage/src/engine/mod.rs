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

mod error;

use std::collections::HashMap;
use std::sync::Arc;

use cyphr::replay::WireBundle;
use cyphr::state::{StateDigest, TaggedDigest};
pub use error::EngineError;

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
    /// The action-only bundles accepted in the served range, in accepted
    /// order. A `ds/create` includes exactly the actions before it
    /// (SPEC 4.8.2), so a replay needs them in place.
    pub actions: Vec<PatchActions>,
}

/// One accepted action-only bundle (SPEC 4.8.1): its actions are recorded
/// in DT, not chained.
#[derive(Debug, Clone)]
pub struct PatchActions {
    /// The commits the principal's chain held when the bundle was accepted:
    /// the bundle precedes the commit at this sequence.
    pub after: u64,
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

/// Discriminator embedded in every [`CommitManifest`]. Since manifests
/// moved behind [`COMMIT_MANIFEST_PREFIX`] it no longer separates them from
/// wire blobs; it survives as the shape of the legacy manifests
/// [`StorageEngine::rebuild_index_from_manifests`] refuses.
const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// Marks a blob as a [`CommitManifest`]: every stored manifest is these
/// bytes followed by its JSON.
///
/// This is the manifest keyspace inside the shared blob store. A wire blob
/// can never carry it: [`canonical_coz`] re-serializes every submitted coz
/// itself, so a stored wire blob is always a JSON object and begins with
/// `{`, while the leading NUL here is not valid at the start of any JSON
/// document. Separation therefore rests on the engine's own serializer,
/// never on inspecting caller bytes for a marker (an escaped member name
/// such as `"\u006bind"` would defeat any such inspection). Chosen over a
/// second backend keyspace because `BlobStore` has out-of-tree
/// implementors; a backend keyspace is the stronger form if that trait is
/// ever widened.
pub const COMMIT_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/commit-manifest/v1\0";

/// A durable, content-addressed record of one [`ingest_commit`](StorageEngine::ingest_commit)
/// call's fully-resolved [`IndexableCommit`] — written to the blob store
/// (never only to the index) so a commit's intra-commit transaction order
/// and derived state digests survive independently of the index.
///
/// This is the signal that lets an index rebuild ([`StorageEngine::rebuild_index_from_manifests`])
/// re-derive a commit directly, without the permutation search
/// that reconstructing same-timestamp mutation order would need. Per root `AGENTS.md` invariant I1,
/// the manifest is itself blob-store content, not a new index-only source of truth.
///
/// Stored as [`COMMIT_MANIFEST_PREFIX`] followed by this struct's JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CommitManifest {
    kind: String,
    commit: IndexableCommit,
    /// How the commit's blobs group into its bundle; required, so a
    /// manifest written before grouping was recorded is malformed rather
    /// than read as one transaction per coz.
    shape: Shape,
}

/// How a commit's blobs (`IndexableCommit::blob_hashes`, in bundle order)
/// group into its bundle: the first `actions` are its data actions, then
/// each entry of `txs` is the coz count of one transaction (SPEC 4.6.2).
/// The bundle's order is retained at ingest, never recovered (root U1).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Shape {
    actions: usize,
    txs: Vec<usize>,
}

impl Shape {
    fn of(bundle: &WireBundle) -> Self {
        Self {
            actions: bundle.actions.len(),
            txs: bundle.txs.iter().map(Vec::len).collect(),
        }
    }

    /// How many blobs the shape groups.
    fn len(&self) -> usize {
        self.actions + self.txs.iter().sum::<usize>()
    }

    /// `blobs` grouped by this shape, with `keys`; `None` when the count
    /// differs.
    fn group(&self, mut blobs: Vec<Vec<u8>>, keys: Vec<KeyEntry>) -> Option<WireBundle> {
        if blobs.len() != self.len() {
            return None;
        }
        let rest = blobs.split_off(self.actions);
        let mut rest = rest.into_iter();
        let txs = self
            .txs
            .iter()
            .map(|&n| rest.by_ref().take(n).collect())
            .collect();
        Some(WireBundle {
            actions: blobs,
            txs,
            keys,
        })
    }
}

/// How a stored chain commit's blobs group into its bundle, and the keys
/// it introduced: what the index's commit record lacks to serve the bundle.
type Frame = (Shape, Vec<KeyEntry>);

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

/// Discriminator of a [`CommitManifest`] that records a retained branch
/// instead of a chain commit.
const BRANCH_MANIFEST_KIND: &str = "cyphr-storage/branch-manifest/v1";

/// Marks a blob as a retained-branch manifest: these bytes followed by a
/// [`CommitManifest`]'s JSON whose `kind` is [`BRANCH_MANIFEST_KIND`].
///
/// A keyspace distinct from [`COMMIT_MANIFEST_PREFIX`] is the whole
/// mechanism: [`StorageEngine::rebuild_index_with_report`] indexes exactly
/// the blobs behind the commit prefix, so a branch can never be chosen as
/// (or flip) a principal's canonical chain whatever order manifest hashes
/// sort in. Branches are read back into the engine's branch table by the
/// same scan, never into the [`Indexer`].
pub const BRANCH_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/branch-manifest/v1\0";

/// Retained non-canonical branches kept per principal. A key holder can
/// mint any number of rivals at one position; the bound caps what one
/// principal can make the store keep, and the next rival is refused as
/// [`EngineError::BranchLimit`].
pub const BRANCH_LIMIT: usize = 16;

/// Retained rivals kept per signing key of one principal. A key that
/// forked once is already proven to equivocate by its first rival, so a
/// small quota loses no evidence. A principal can therefore hold at most
/// `min(BRANCH_LIMIT, BRANCH_PER_KEY * active keys)` rivals: a thief who
/// holds one key cannot starve rivals signed by the principal's other
/// keys, and shares that key's quota if it is the owner's only key. A
/// thief who first adds keys to the principal (each a further slot pair)
/// can still fill [`BRANCH_LIMIT`].
pub const BRANCH_PER_KEY: usize = 2;

/// Discriminator of an [`ActionManifest`].
const ACTION_MANIFEST_KIND: &str = "cyphr-storage/action-manifest/v1";

/// Marks a blob as an [`ActionManifest`]: these bytes followed by its
/// JSON. A keyspace of its own, separated from wire blobs as
/// [`COMMIT_MANIFEST_PREFIX`] is, so a rebuild never reads one as a commit.
pub const ACTION_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/action-manifest/v1\0";

/// The durable record of one accepted action-only bundle: its data
/// actions are recorded in DT, not chained (SPEC 4.8.1), so they form no
/// commit, yet a later `ds/create` includes them (4.8.2) and every replay
/// must record them where they were accepted. `after` is that place: the
/// commits the principal's chain held when the bundle was accepted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ActionManifest {
    kind: String,
    principal_id: String,
    after: u64,
    blob_hashes: Vec<Blake3Hash>,
}

/// An accepted action-only bundle as the engine tracks it: a cache of its
/// [`ActionManifest`] (I1).
#[derive(Debug, Clone)]
struct StoredActions {
    after: u64,
    manifest: Blake3Hash,
    blobs: Vec<Blake3Hash>,
}

/// An action-only bundle read back for replay.
struct ActionBundle {
    manifest: Blake3Hash,
    blobs: Vec<Blake3Hash>,
    bundle: cyphr::replay::Bundle,
}

/// A principal's action-only bundles by the chain position they were
/// accepted at, each position's in replay order ([`replay_order`]).
type ActionHistory = std::collections::BTreeMap<u64, Vec<ActionBundle>>;

/// A retained rival as the engine tracks it: the listed [`BranchTip`],
/// the key that signed its closing `commit/create`, and the stored blobs
/// the evidence route serves back.
#[derive(Debug, Clone)]
struct Retained {
    tip: BranchTip,
    signer: String,
    blobs: Vec<Blake3Hash>,
    shape: Shape,
    keys: Vec<KeyEntry>,
}

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

/// Whether `signer` may still retain a rival beside `kept`.
fn has_slot(kept: &[Retained], signer: &str) -> bool {
    kept.len() < BRANCH_LIMIT && kept.iter().filter(|r| r.signer == signer).count() < BRANCH_PER_KEY
}

/// A fork of a stored principal: two distinct commits that both verify at
/// the same `pre`, as the wire blobs of each. One is the canonical commit
/// at `sequence`, the other a retained rival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkEvidence {
    /// The chain position both commits take.
    pub sequence: u64,
    /// The Principal Root both extend, tagged; `None` at sequence 0.
    pub pre: Option<String>,
    /// The canonical commit's bundle.
    pub canonical: WireBundle,
    /// The retained rival's bundle.
    pub rival: WireBundle,
}

/// One branch head of a principal: its canonical chain's tip or a
/// retained rival, as listed by [`StorageEngine::list_branches`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BranchTip {
    /// The branch commit's id, in the form of [`TipState::commit_id`].
    pub tip: String,
    /// The Principal Root the commit was verified against (the parent PR,
    /// in the tagged anchor form `/patch` takes); `None` at sequence 0.
    pub pre: Option<String>,
    /// The commit's 0-indexed chain position.
    pub sequence: u64,
    /// Whether this is the head of the principal's canonical chain.
    pub canonical: bool,
}

/// Why a stored manifest was left out of a rebuilt index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineReason {
    /// The manifest blob is not a well-formed manifest.
    Malformed(String),
    /// The manifest names blobs the store does not hold.
    Unsupported(String),
    /// The manifest is not bound to the principal it names.
    Unbound(String),
    /// Indexing it would re-point an exclusive claim (a PG alias).
    Conflict(String),
    /// A different commit already holds this manifest's chain position
    /// `(principal, sequence)`: fork evidence (I2), kept out of the index.
    Fork(String),
    /// An earlier commit of the same principal was quarantined, so indexing
    /// this one would leave a gap in the chain.
    Orphaned(String),
    /// Replaying the manifest's blobs onto its principal does not yield the
    /// commit the manifest records (only a rebuild from scratch replays).
    Unreplayable(String),
}

/// A manifest a rebuild left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedManifest {
    /// BLAKE3 hash of the manifest blob.
    pub manifest: Blake3Hash,
    /// The principal id the manifest claims, when it parsed far enough.
    pub principal_id: Option<String>,
    /// Why it was left out.
    pub reason: QuarantineReason,
}

/// What a rebuild did: how many manifests it indexed, and which it
/// quarantined. A quarantined manifest never fails the rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReport {
    /// Manifests indexed (including those already indexed).
    pub indexed: usize,
    /// Manifests left out, in canonical order.
    pub quarantined: Vec<QuarantinedManifest>,
}

/// Produces a fresh, independent `S` instance for a `Principal`'s Commit
/// Tree, given that principal's `principal_id` as a scoping identifier — see
/// [`StorageEngine`]'s `storage_factory` field docs.
type StorageFactory<S> = Box<dyn Fn(&str) -> Result<S, String> + Send + Sync>;

/// A small insertion-ordered cache that never holds more than `capacity`
/// entries: when full, the oldest insertion is evicted.
///
/// Used only for memoizing replay-derived answers under keys that name the
/// exact tip they were derived at, so an entry can never be stale (a new
/// commit changes the key) and eviction costs only a recomputation.
pub struct BoundedCache<K, V> {
    capacity: usize,
    entries: std::sync::Mutex<(HashMap<K, V>, std::collections::VecDeque<K>)>,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> BoundedCache<K, V> {
    /// An empty cache holding at most `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: std::sync::Mutex::new((HashMap::new(), std::collections::VecDeque::new())),
        }
    }

    /// The value stored under `key`, if still held.
    pub fn get(&self, key: &K) -> Option<V> {
        let guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.get(key).cloned()
    }

    /// Store `value` under `key`, evicting the oldest entry if over capacity.
    pub fn insert(&self, key: K, value: V) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.insert(key.clone(), value).is_none() {
            order.push_back(key);
            while map.len() > self.capacity {
                match order.pop_front() {
                    Some(oldest) => {
                        map.remove(&oldest);
                    },
                    None => break,
                }
            }
        }
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
/// up via [`Self::with_storage_factory`] instead.
pub struct StorageEngine<B, I, S: cyphr::eml::Storage = cyphr::eml::MemoryStorage> {
    blob_store: B,
    indexer: I,
    /// Produces a fresh, independent `S` instance for each `Principal` this
    /// engine constructs or reconstructs. Never a single `S` instance
    /// shared/aliased across multiple live principals: `eml::Storage`'s
    /// methods take `&mut self` on an owned instance, so two principals can
    /// never validly share one. Fallible (`Result<S, String>`, not a bare
    /// `S`) because opening a real disk-backed backend can fail.
    ///
    /// Takes the principal's `principal_id` as a per-principal scoping
    /// identifier, so a factory backed by a durable, physically-shared
    /// database can give each principal an isolated keyspace instead of
    /// colliding on positional Commit Tree keys.
    storage_factory: StorageFactory<S>,
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
    healed: tokio::sync::OnceCell<()>,
    /// Retained non-canonical branches per canonical principal id: a cache
    /// of the branch manifests in the blob store (I1), filled by the
    /// rebuild scan and by retention, at most [`BRANCH_LIMIT`] per
    /// principal.
    branches: std::sync::Mutex<HashMap<String, Vec<Retained>>>,
    /// Accepted action-only bundles per principal id: a cache of the action
    /// manifests in the blob store (I1), filled by the rebuild scan and by
    /// ingest.
    actions: std::sync::Mutex<HashMap<String, Vec<StoredActions>>>,
    /// How each stored chain commit's blobs group into its bundle, and the
    /// keys it introduced, by principal id and commit id: a cache of the
    /// commit manifests in the blob store (I1), filled by the rebuild scan
    /// and by ingest. The index's commit records name blobs only.
    frames: std::sync::Mutex<HashMap<(String, String), Frame>>,
    /// Stored commits [`Self::retain_rival`] has replayed, ever. Retention
    /// is paid by refused bundles, so its cost is the quantity tests pin.
    retention_replays: std::sync::atomic::AtomicU64,
    /// Candidate positions [`Self::retain_rival`] has tried a bundle at.
    retention_trials: std::sync::atomic::AtomicU64,
}

impl<B: BlobStore, I: Indexer + IndexerWrite> StorageEngine<B, I, cyphr::eml::MemoryStorage> {
    /// Create a new engine wrapping the given backends, with each
    /// [`cyphr::Principal`]'s Commit Tree backed by an in-memory
    /// [`cyphr::eml::MemoryStorage`] instance (discarded when the principal
    /// is dropped — full history is always replayed from the blob/index
    /// layers on the next [`Self::load_principal`]).
    ///
    /// For a durable commit-tree backend, use [`Self::with_storage_factory`].
    pub fn new(blob_store: B, indexer: I) -> Self {
        Self {
            blob_store,
            indexer,
            storage_factory: Box::new(|_principal_id: &str| Ok(cyphr::eml::MemoryStorage::new())),
            principal_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            healed: tokio::sync::OnceCell::new(),
            branches: std::sync::Mutex::new(HashMap::new()),
            actions: std::sync::Mutex::new(HashMap::new()),
            frames: std::sync::Mutex::new(HashMap::new()),
            retention_replays: std::sync::atomic::AtomicU64::new(0),
            retention_trials: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Create a new engine wrapping the given backends, with `storage_factory`
    /// producing each [`cyphr::Principal`]'s Commit Tree storage backend from
    /// its `principal_id`.
    ///
    /// See [`Self`]'s `storage_factory` field docs for why this is a
    /// factory rather than a single shared `S` instance.
    pub fn with_storage_factory(
        blob_store: B,
        indexer: I,
        storage_factory: impl Fn(&str) -> Result<S, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            blob_store,
            indexer,
            storage_factory: Box::new(storage_factory),
            principal_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            healed: tokio::sync::OnceCell::new(),
            branches: std::sync::Mutex::new(HashMap::new()),
            actions: std::sync::Mutex::new(HashMap::new()),
            frames: std::sync::Mutex::new(HashMap::new()),
            retention_replays: std::sync::atomic::AtomicU64::new(0),
            retention_trials: std::sync::atomic::AtomicU64::new(0),
        }
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

    /// Ensure this engine's index has no pending crash-window recovery
    /// before any of its own methods read or write against it.
    ///
    /// Implements [recovery-reindex] (docs/specs/storage-engine.md:236-241)
    /// for the "no explicit call" case: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent index write (see the
    /// crash-window doc on [`Self::rebuild_index_from_manifests`] below)
    /// must heal automatically the next time the engine is opened,
    /// without any caller remembering to invoke
    /// [`Self::rebuild_index_from_manifests`] itself. "Opened" here means
    /// construct-plus-first-use (engine constructors are synchronous, so
    /// there is no async open step to hook): this lazy once-per-instance
    /// guard runs the full manifest scan on this engine's first call into
    /// any of the methods below, and never again for the lifetime of this
    /// instance.
    ///
    /// Cost strategy: always a full [`Self::rebuild_index_from_manifests`]
    /// scan rather than a cheaper orphan-detection pre-check. Against this
    /// crate's backends the scan is already the mechanism full recovery
    /// relies on, `index_commit` is idempotent so
    /// a healthy store's scan is a pure read with no re-indexing writes,
    /// and it runs at most once per instance -- an orphan pre-check would
    /// only save a single redundant scan's read cost per process lifetime,
    /// not a recurring cost, so the simpler always-scan is what ships.
    ///
    /// Scoped to this engine's own methods: [`Self::indexer`] and
    /// [`Self::blob_store`] are raw accessors that bypass this gate by
    /// design (see their docs) -- a caller reaching the backends directly
    /// is outside the invariant this method closes.
    ///
    /// A heal failure surfaces as an `EngineError` from the caller's first
    /// call, same as any other engine error -- not a swallowed or
    /// reordered error, and not a public-error-contract change. The guard
    /// is left uninitialized on error (`get_or_try_init` does not cache
    /// failures), so the next call retries rather than wedging this
    /// instance in a permanently-failed state.
    async fn ensure_healed(&self) -> Result<(), EngineError> {
        self.healed
            .get_or_try_init(|| async { self.rebuild_index_from_manifests().await.map(|_| ()) })
            .await?;
        Ok(())
    }

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
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        let principal_id = key.as_deref().unwrap_or(principal_id);
        let from_seq = match from {
            Some(anchor) => Some(self.resolve_anchor_position(principal_id, anchor).await?),
            None => None,
        };
        let chain = self
            .indexer
            .get_commit_chain(principal_id, from_seq, to)
            .await?;

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let bundle = self.commit_bundle(principal_id, &commit_ref).await?;
            entries.push(PatchEntry {
                commit: commit_ref,
                bundle,
            });
        }

        // Bundles accepted before the first served commit that the caller
        // already holds are skipped; those after the last served commit
        // ride along unless `to` bounds the range short of them.
        let held: Vec<(u64, Vec<Blake3Hash>)> = {
            let guard = self.actions.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .get(principal_id)
                .into_iter()
                .flatten()
                .filter(|a| a.after >= from_seq.unwrap_or(0) && to.is_none_or(|t| a.after <= t))
                .map(|a| (a.after, a.blobs.clone()))
                .collect()
        };
        let mut actions = Vec::with_capacity(held.len());
        for (after, hashes) in held {
            let mut blobs = Vec::with_capacity(hashes.len());
            for hash in &hashes {
                let data =
                    self.blob_store.get(hash).await?.ok_or_else(|| {
                        EngineError::NotFound(format!("action blob {hash} missing"))
                    })?;
                blobs.push(data);
            }
            actions.push(PatchActions { after, blobs });
        }
        actions.sort_by_key(|a| a.after);

        Ok(PatchResponse {
            principal_id: principal_id.to_string(),
            entries,
            actions,
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
        let Some((shape, keys)) = self.frame(principal_id, commit) else {
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

    /// Record how a chain commit groups its blobs, in the `frames` cache.
    fn record_frame(&self, commit: &IndexableCommit, shape: &Shape) {
        let Some(id) = commit.commit_ids.first() else {
            return;
        };
        self.frames
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                (commit.principal_id.clone(), id.clone()),
                (shape.clone(), key_entries(&commit.keys)),
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
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        self.store_manifest(bundle, commit, COMMIT_MANIFEST_PREFIX, COMMIT_MANIFEST_KIND)
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
        let StagedBuild { commit, staged } = build;
        self.ingest(bundle, commit, Some(staged)).await
    }

    /// [`Self::ingest_commit`] of index metadata built by hand, with no
    /// core commit behind it (unit tests of the indexing path).
    #[cfg(test)]
    pub(crate) async fn ingest_metadata(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
    ) -> Result<IngestResult, EngineError> {
        self.ingest::<cyphr::eml::MemoryStorage>(bundle, commit, None)
            .await
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
    ) -> Result<IngestResult, EngineError> {
        // The one exclusive claim (a PG alias) is checked before the first
        // durable write: a refused commit must leave no blob or manifest
        // for a later rebuild to trip over. Two ingests for different
        // principals contend for one alias without sharing a principal
        // lock, so the check and the write it admits are held under a lock
        // per alias (in sorted order, so contenders cannot deadlock).
        let mut aliases: Vec<String> = commit
            .pg
            .iter()
            .map(|pg| format!("pg-alias\0{pg}"))
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        let alias_locks: Vec<_> = aliases.iter().map(|a| self.principal_lock(a)).collect();
        let mut _alias_guards = Vec::with_capacity(alias_locks.len());
        for lock in &alias_locks {
            _alias_guards.push(lock.lock().await);
        }
        self.indexer
            .check_commit(&commit, &DeriveToken::new())
            .await?;
        let (commit, manifest_hash) = self.store_blobs_and_manifest(bundle, commit).await?;
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
            tracing::warn!(
                principal = %commit.principal_id,
                error = %e,
                "commit stored but its log append failed; the next load replays it"
            );
        }

        self.indexer
            .index_commit(&commit, &DeriveToken::new())
            .await?;
        self.record_frame(&commit, &Shape::of(bundle));

        Ok(IngestResult {
            principal_id: commit.principal_id.clone(),
            blob_hashes,
            manifest_hash: Some(manifest_hash),
            tip: Some(CommittedTip::of(&commit)),
        })
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, returning how many were indexed.
    /// [`Self::rebuild_index_with_report`] is the same pass with the
    /// quarantined manifests named.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_manifests(&self) -> Result<usize, EngineError> {
        let report = self.rebuild_index_with_report().await?;
        for q in &report.quarantined {
            tracing::warn!(
                manifest = %q.manifest,
                principal = ?q.principal_id,
                reason = ?q.reason,
                "manifest quarantined: left out of the index"
            );
        }
        Ok(report.indexed)
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, quarantining any it cannot index.
    ///
    /// Closes the ingest crash window: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent `indexer.index_commit` call
    /// leaves a manifest durably stored with no index entry yet; this
    /// completes the index write from the manifest's already-resolved
    /// `IndexableCommit`. It also serves full reconstruction: clearing the
    /// index and calling this rebuilds every manifest-backed commit from
    /// the blob store alone (root `AGENTS.md` invariant I1).
    ///
    /// **The index is a function of the blob set.** Manifests are indexed
    /// in canonical order (sequence, then principal id, then manifest
    /// hash), never the blob store's listing order, and every index write
    /// is order-independent (digests name sets of holders). The one
    /// exclusive claim is a principal's PG alias: if two manifests contest
    /// one, the earlier in canonical order wins.
    ///
    /// **A manifest the index cannot take never fails the rebuild.** It is
    /// quarantined with a typed [`QuarantineReason`] (malformed, naming
    /// blobs the store lacks, not bound to its principal, contesting a
    /// PG alias, or rivalling a commit already at its chain position), and so are that principal's
    /// later commits, so no chain is indexed with a gap. Backend failures and a manifest-shaped
    /// wire blob ([`EngineError::LegacyManifest`]) still fail the rebuild.
    ///
    /// This does not replay: it trusts the engine-written manifests plus
    /// the blob-presence and binding checks. The replaying rebuild is
    /// [`Self::rebuild_index_from_scratch_with_report`].
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_with_report(&self) -> Result<RebuildReport, EngineError> {
        self.rebuild_pass(false).await
    }

    /// The rebuild pass. With `replay`, every manifest's blobs are also
    /// replayed onto its principal from genesis by the admission path
    /// ([`Self::build_commit`]), and a manifest whose commit the replay
    /// does not reproduce is quarantined ([`QuarantineReason::Unreplayable`]).
    async fn rebuild_pass(&self, replay: bool) -> Result<RebuildReport, EngineError> {
        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;

        let mut quarantined = Vec::new();
        // The earliest sequence at which a principal's chain broke, for any
        // reason; every later commit of that principal is orphaned, so the
        // indexed chain is always a gapless prefix.
        let mut broken_from: HashMap<String, u64> = HashMap::new();
        let mut manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut branch_manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut action_manifests: Vec<(Blake3Hash, ActionManifest)> = Vec::new();
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
            if let Some(json) = data.strip_prefix(ACTION_MANIFEST_PREFIX) {
                // Actions are not chained: a bad action manifest costs only
                // itself here, and a commit whose `ds/create` needed it
                // fails its own replay.
                match serde_json::from_slice::<ActionManifest>(json) {
                    Ok(m) if m.kind == ACTION_MANIFEST_KIND => action_manifests.push((hash, m)),
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "action manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            if let Some(json) = data.strip_prefix(BRANCH_MANIFEST_PREFIX) {
                // Retained branches never reach the index, so a bad one
                // costs only its own listing, never a chain position.
                match serde_json::from_slice::<CommitManifest>(json) {
                    Ok(m) if m.kind == BRANCH_MANIFEST_KIND => {
                        match self.check_manifest_supported(&hash, &m).await? {
                            Ok(()) => branch_manifests.push((hash, m)),
                            Err(reason) => quarantined.push(QuarantinedManifest {
                                manifest: hash,
                                principal_id: Some(m.commit.principal_id.clone()),
                                reason,
                            }),
                        }
                    },
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.commit.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "branch manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            let Some(json) = data.strip_prefix(COMMIT_MANIFEST_PREFIX) else {
                // A wire blob. One shaped like a manifest cannot have been
                // written by this engine (it stores wire cozes in canonical
                // form only), so it is an old shared-store manifest or a
                // forged coz, and nothing here can tell which.
                if is_legacy_manifest(&data) {
                    return Err(EngineError::LegacyManifest { hash });
                }
                continue;
            };
            let manifest: CommitManifest = match serde_json::from_slice(json) {
                Ok(m) => m,
                Err(e) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    });
                    continue;
                },
            };
            if let Err(reason) = self.check_manifest_supported(&hash, &manifest).await? {
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason,
                });
                continue;
            }
            manifests.push((hash, manifest));
        }

        manifests.sort_by(|(ha, a), (hb, b)| {
            (a.commit.sequence, &a.commit.principal_id, ha.as_bytes()).cmp(&(
                b.commit.sequence,
                &b.commit.principal_id,
                hb.as_bytes(),
            ))
        });

        let unbound = self.unbound_principals(&manifests).await?;
        for (hash, manifest) in &manifests {
            if let Some(why) = unbound.get(&manifest.commit.principal_id) {
                quarantined.push(QuarantinedManifest {
                    manifest: *hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason: QuarantineReason::Unbound(why.clone()),
                });
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
            }
        }

        let mut indexed = 0;
        let mut replays: HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>> =
            HashMap::new();
        // What the last replaying rebuild quarantined: a pass that does
        // not replay cannot judge those manifests, so it keeps them out.
        let skip: HashMap<Blake3Hash, String> = if replay {
            HashMap::new()
        } else {
            self.indexer.quarantined().await?.into_iter().collect()
        };
        let mut histories = self
            .read_action_manifests(action_manifests, &skip, &mut quarantined)
            .await?;
        // Action manifests whose bundle the replay refused, and why.
        let mut refused_actions: Vec<(Blake3Hash, String)> = Vec::new();
        // The positions whose actions were replayed before a commit there.
        let mut replayed_at: std::collections::HashSet<(String, u64)> =
            std::collections::HashSet::new();
        for (hash, manifest) in manifests {
            let commit = &manifest.commit;
            if unbound.contains_key(&commit.principal_id) {
                continue;
            }
            if broken_from
                .get(&commit.principal_id)
                .is_some_and(|from| commit.sequence > *from)
            {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Orphaned(
                        "an earlier commit of this principal was quarantined".into(),
                    ),
                });
                continue;
            }
            let refused = match skip.get(&hash) {
                Some(why) => Err(format!("quarantined by the last scratch rebuild: {why}")),
                None if replay => {
                    replayed_at.insert((commit.principal_id.clone(), commit.sequence));
                    let actions = histories
                        .get(&commit.principal_id)
                        .and_then(|h| h.get(&commit.sequence))
                        .map_or(&[][..], Vec::as_slice);
                    self.replay_manifest(&mut replays, &manifest, actions, &mut refused_actions)
                        .await?
                },
                None => Ok(()),
            };
            if let Err(why) = refused {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Unreplayable(why),
                });
                broken_from
                    .entry(commit.principal_id.clone())
                    .or_insert(commit.sequence);
                continue;
            }
            match self.indexer.index_commit(commit, &DeriveToken::new()).await {
                Ok(()) => {
                    self.record_frame(commit, &manifest.shape);
                    indexed += 1;
                },
                Err(crate::index::IndexerError::Conflict(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Conflict(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(crate::index::IndexerError::Consistency(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Fork(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(e) => return Err(e.into()),
            }
        }

        // The actions accepted after each replayed chain's last commit,
        // unless a commit there failed its replay after them.
        for (principal_id, principal) in &mut replays {
            let tip = principal.commits().count() as u64;
            if replayed_at.contains(&(principal_id.clone(), tip)) {
                continue;
            }
            let actions = histories.get(principal_id).and_then(|h| h.get(&tip));
            for bundle in actions.into_iter().flatten() {
                if let Err(e) = cyphr::replay::replay_bundle(principal, &bundle.bundle).await {
                    refused_actions.push((bundle.manifest, e.to_string()));
                }
            }
        }
        for (manifest, why) in refused_actions {
            let principal_id = histories.iter_mut().find_map(|(id, h)| {
                h.values_mut().find_map(|bundles| {
                    let at = bundles.iter().position(|b| b.manifest == manifest)?;
                    bundles.remove(at);
                    Some(id.clone())
                })
            });
            quarantined.push(QuarantinedManifest {
                manifest,
                principal_id,
                reason: QuarantineReason::Unreplayable(why),
            });
        }
        let actions = self.place_actions(histories, &mut quarantined).await?;
        *self.actions.lock().unwrap_or_else(|p| p.into_inner()) = actions;

        let branches = self
            .classify_branches(branch_manifests, &mut quarantined)
            .await?;
        *self.branches.lock().unwrap_or_else(|p| p.into_inner()) = branches;

        quarantined.sort_by_key(|q| *q.manifest.as_bytes());
        Ok(RebuildReport {
            indexed,
            quarantined,
        })
    }

    /// Read back the scanned action manifests' bundles by principal and
    /// position, quarantining any whose blobs are missing or are not an
    /// action-only bundle, and, in a pass that does not replay, any the
    /// last scratch rebuild quarantined (`skip`).
    async fn read_action_manifests(
        &self,
        manifests: Vec<(Blake3Hash, ActionManifest)>,
        skip: &HashMap<Blake3Hash, String>,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, ActionHistory>, EngineError> {
        let mut histories: HashMap<String, ActionHistory> = HashMap::new();
        'manifests: for (hash, manifest) in manifests {
            let mut reject = |reason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.principal_id.clone()),
                    reason,
                });
            };
            if let Some(why) = skip.get(&hash) {
                reject(QuarantineReason::Unreplayable(format!(
                    "quarantined by the last scratch rebuild: {why}"
                )));
                continue;
            }
            let mut blobs = Vec::with_capacity(manifest.blob_hashes.len());
            for blob in &manifest.blob_hashes {
                let Some(data) = self.blob_store.get(blob).await? else {
                    reject(QuarantineReason::Unsupported(format!(
                        "action manifest {hash} names blob {blob}, which is not stored"
                    )));
                    continue 'manifests;
                };
                blobs.push(data);
            }
            match action_bundle(blobs) {
                Ok(bundle) => histories
                    .entry(manifest.principal_id.clone())
                    .or_default()
                    .entry(manifest.after)
                    .or_default()
                    .push(ActionBundle {
                        manifest: hash,
                        blobs: manifest.blob_hashes,
                        bundle,
                    }),
                Err(why) => reject(QuarantineReason::Malformed(format!(
                    "action manifest {hash}: {why}"
                ))),
            }
        }
        for bundles in histories.values_mut().flat_map(|h| h.values_mut()) {
            replay_order(bundles);
        }
        Ok(histories)
    }

    /// The action-only bundles the rebuilt index has a place for: one
    /// accepted after more commits than its principal's indexed chain holds
    /// would be replayed before a commit it never preceded, so it is
    /// quarantined as orphaned.
    async fn place_actions(
        &self,
        histories: HashMap<String, ActionHistory>,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, Vec<StoredActions>>, EngineError> {
        let mut placed: HashMap<String, Vec<StoredActions>> = HashMap::new();
        for (principal_id, history) in histories {
            let chain = self
                .indexer
                .get_tip(&principal_id)
                .await?
                .map_or(0, |tip| tip.commit_count);
            for (after, bundles) in history {
                for bundle in bundles {
                    if after > chain {
                        quarantined.push(QuarantinedManifest {
                            manifest: bundle.manifest,
                            principal_id: Some(principal_id.clone()),
                            reason: QuarantineReason::Orphaned(format!(
                                "actions accepted after commit {after}, the chain holds {chain}"
                            )),
                        });
                        continue;
                    }
                    placed
                        .entry(principal_id.clone())
                        .or_default()
                        .push(StoredActions {
                            after,
                            manifest: bundle.manifest,
                            blobs: bundle.blobs,
                        });
                }
            }
        }
        Ok(placed)
    }

    /// Decide which stored branch manifests are branches of the index just
    /// rebuilt. A branch is kept only if it forks the canonical chain: the
    /// canonical commit at its position exists and is a different commit,
    /// and its `pre` is the canonical parent's PR. The rest are quarantined.
    ///
    /// The index is already final when this runs and is never read to
    /// decide the canonical chain here, so the result is a function of the
    /// blob set: manifests are taken in hash order, which only decides
    /// which rivals survive [`BRANCH_LIMIT`] if a store holds more than the
    /// engine ever wrote.
    async fn classify_branches(
        &self,
        mut branch_manifests: Vec<(Blake3Hash, CommitManifest)>,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, Vec<Retained>>, EngineError> {
        branch_manifests.sort_by_key(|(hash, _)| *hash.as_bytes());
        let mut kept: HashMap<String, Vec<Retained>> = HashMap::new();
        for (hash, manifest) in branch_manifests {
            let CommitManifest { commit, shape, .. } = manifest;
            let tip = commit.commit_ids.first().cloned().unwrap_or_default();
            let mut reject = |reason: QuarantineReason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason,
                });
            };
            let from = commit.sequence.saturating_sub(1);
            let chain = self
                .indexer
                .get_commit_chain(&commit.principal_id, Some(from), Some(commit.sequence))
                .await?;
            let Some(canonical) = chain.iter().find(|c| c.sequence == commit.sequence) else {
                reject(QuarantineReason::Orphaned(
                    "no canonical commit at the branch's position".into(),
                ));
                continue;
            };
            if canonical.commit_id == tip {
                reject(QuarantineReason::Conflict(
                    "branch is the canonical commit at its position".into(),
                ));
                continue;
            }
            let parent = chain.iter().find(|c| c.sequence + 1 == commit.sequence);
            if commit.pre.as_ref() != parent.map(|c| &c.pr) {
                reject(QuarantineReason::Orphaned(
                    "branch's pre is not the canonical parent's PR".into(),
                ));
                continue;
            }
            let of_principal = kept.entry(commit.principal_id.clone()).or_default();
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                continue;
            }
            let signer = commit_signer(&commit);
            if !has_slot(of_principal, &signer) {
                reject(QuarantineReason::Conflict(format!(
                    "no retention slot left for key {signer}: at most {BRANCH_PER_KEY} per key, \
                     {BRANCH_LIMIT} per principal"
                )));
                continue;
            }
            of_principal.push(Retained {
                tip: BranchTip {
                    tip,
                    pre: commit.pre,
                    sequence: commit.sequence,
                    canonical: false,
                },
                signer,
                keys: key_entries(&commit.keys),
                blobs: commit.blob_hashes,
                shape,
            });
        }
        Ok(kept)
    }

    /// A corruption detector, not a security boundary. Without replay: the
    /// genesis a principal's first sequence-0 manifest (in canonical
    /// order) discloses in its blobs ([`disclosed_genesis`]) must derive
    /// the principal id the manifests carry ([`record_key`]). Returns each failing principal with
    /// why; they are quarantined.
    ///
    /// Scope: a principal whose blobs disclose no genesis is not judged
    /// here (the replaying rebuild quarantines it), and when several
    /// sequence-0 manifests claim one id only the first is checked. The
    /// guarantee that a forged manifest cannot re-point a principal comes
    /// from the manifest keyspace plus the single writer
    /// ([`COMMIT_MANIFEST_PREFIX`], [`canonical_coz`]), not from this
    /// check.
    async fn unbound_principals(
        &self,
        manifests: &[(Blake3Hash, CommitManifest)],
    ) -> Result<HashMap<String, String>, EngineError> {
        let mut firsts: HashMap<&str, &CommitManifest> = HashMap::new();
        for (_, manifest) in manifests {
            if manifest.commit.sequence == 0 {
                firsts
                    .entry(&manifest.commit.principal_id)
                    .or_insert(manifest);
            }
        }
        let mut unbound = HashMap::new();
        let mut principals: Vec<&str> = manifests
            .iter()
            .map(|(_, m)| m.commit.principal_id.as_str())
            .collect();
        principals.sort_unstable();
        principals.dedup();
        for principal_id in principals {
            let Some(first) = firsts.get(principal_id) else {
                unbound.insert(
                    principal_id.to_string(),
                    "no sequence-0 manifest for the principal".to_string(),
                );
                continue;
            };
            let bundle = self.manifest_bundle(first).await?;
            // Without a disclosed genesis the id cannot be proven from
            // blobs; this pass does not judge it (the replaying rebuild
            // quarantines it).
            let genesis = match disclosed_genesis(&bundle) {
                Some(Ok(genesis)) => genesis,
                None => continue,
                Some(Err(e)) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("genesis not derivable from its blobs: {e}"),
                    );
                    continue;
                },
            };
            // The key is a function of the record (I1: not of what a
            // manifest claims), so that one commit is replayed, not the
            // chain ([`record_key`]).
            let derived = record_key(&genesis, &bundle).await;
            // Strict by decision: the project is pre-1.0 with nothing
            // deployed, so a store keyed by a PG-to-be exists only in test
            // runs and needs no lenient branch.
            if derived.as_deref() != Some(principal_id) {
                unbound.insert(
                    principal_id.to_string(),
                    "its first commit does not derive this id as its key".to_string(),
                );
            }
        }
        Ok(unbound)
    }

    /// Replay `commit`'s blobs onto its principal (`replays` holds each
    /// principal's state, advanced manifest by manifest in sequence order)
    /// and compare the commit the admission path builds with the one the
    /// manifest records. `Ok(Err(why))` is a manifest to quarantine.
    ///
    /// A principal is replayed from the genesis its sequence-0 blobs
    /// disclose ([`disclosed_genesis`]): every chain begins with a genesis
    /// commit (SPEC 5.1), so one that discloses none is quarantined.
    ///
    /// `actions` are the action-only bundles accepted at the commit's
    /// position; they are recorded first, and each one the core refuses is
    /// added to `refused`.
    async fn replay_manifest(
        &self,
        replays: &mut HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>>,
        manifest: &CommitManifest,
        actions: &[ActionBundle],
        refused: &mut Vec<(Blake3Hash, String)>,
    ) -> Result<Result<(), String>, EngineError> {
        let commit = &manifest.commit;
        let bundle = self.manifest_bundle(manifest).await?;
        let principal = match replays.entry(commit.principal_id.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let Some(genesis) = disclosed_genesis(&bundle) else {
                    return Ok(Err("its first commit discloses no genesis".into()));
                };
                let opened = match genesis {
                    Ok(genesis) => {
                        Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new())
                            .await
                    },
                    Err(e) => Err(e),
                };
                match opened {
                    Ok(principal) => e.insert(principal),
                    Err(e) => return Ok(Err(format!("genesis does not replay: {e}"))),
                }
            },
        };
        for held in actions {
            if let Err(e) = cyphr::replay::replay_bundle(principal, &held.bundle).await {
                refused.push((held.manifest, e.to_string()));
            }
        }
        let StagedBuild {
            commit: mut replayed,
            staged,
        } = match Self::build_commit(principal, &bundle, &commit.principal_id, commit.sequence)
            .await
        {
            Ok(Some(build)) => build,
            Ok(None) => return Ok(Err("its blobs form no commit".into())),
            Err(e) => return Ok(Err(format!("its blobs do not replay: {e}"))),
        };
        if let Err(e) = staged.commit().await {
            return Ok(Err(format!("its blobs do not replay: {e}")));
        }
        // `store_manifest` fills these in at ingest.
        replayed.blob_hashes.clone_from(&commit.blob_hashes);
        for (coz, hash) in replayed.cozies.iter_mut().zip(&commit.blob_hashes) {
            coz.blob_hash = *hash;
        }
        let same = serde_json::to_value(&replayed).ok() == serde_json::to_value(commit).ok();
        Ok(if same {
            Ok(())
        } else {
            Err("it records a commit its blobs do not yield".into())
        })
    }

    /// The bundle a commit manifest records: its blobs grouped by its
    /// shape, with the keys its commit introduced.
    async fn manifest_bundle(&self, manifest: &CommitManifest) -> Result<WireBundle, EngineError> {
        let blobs = self.read_blobs(&manifest.commit.blob_hashes).await?;
        manifest
            .shape
            .group(blobs, key_entries(&manifest.commit.keys))
            .ok_or_else(|| {
                EngineError::MalformedBlob(
                    "a commit manifest's shape groups a different number of blobs".into(),
                )
            })
    }

    /// Whether a manifest's commit names blobs the store holds: the index
    /// is a cache of the blobs (I1), so a manifest field the blobs do not
    /// support must not reach it. `Ok(Err(reason))` is a manifest to
    /// quarantine; `Err` is a backend failure.
    async fn check_manifest_supported(
        &self,
        manifest_hash: &Blake3Hash,
        manifest: &CommitManifest,
    ) -> Result<Result<(), QuarantineReason>, EngineError> {
        let commit = &manifest.commit;
        if manifest.shape.len() != commit.blob_hashes.len() {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest_hash}: its shape groups a different number of blobs"
            ))));
        }
        let manifest = manifest_hash;
        if commit.blob_hashes.is_empty()
            || commit.cozies.len() != commit.blob_hashes.len()
            || commit
                .cozies
                .iter()
                .zip(&commit.blob_hashes)
                .any(|(coz, hash)| coz.blob_hash != *hash)
        {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest}: cozies and blob hashes disagree"
            ))));
        }
        for hash in &commit.blob_hashes {
            if !self.blob_store.exists(hash).await? {
                return Ok(Err(QuarantineReason::Unsupported(format!(
                    "commit manifest {manifest} names blob {hash}, which is not stored"
                ))));
            }
        }
        Ok(Ok(()))
    }

    // ========================================================================
    // Principal lifecycle
    // ========================================================================

    /// Reconstruct a live [`cyphr::Principal`] by replaying stored commits.
    ///
    /// Fetches the full commit chain from the indexer, retrieves each
    /// blob from the blob store, and delegates to the existing
    /// [`import::replay_commits`] infrastructure, with the action-only
    /// bundles accepted between commits recorded where they were accepted.
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
    ) -> Result<cyphr::Principal<S>, EngineError> {
        self.ensure_healed().await?;
        let key = self.resolve_key(principal_id).await?;
        self.replay_stored(key.as_deref().unwrap_or(principal_id), genesis)
            .await
    }

    /// [`load_principal`](Self::load_principal) for an id already known to
    /// be the stored spelling.
    async fn replay_stored(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let storage = (self.storage_factory)(principal_id).map_err(EngineError::Storage)?;
        let replayed = self.replay_onto(principal_id, genesis, storage, None).await;
        if let Err(EngineError::Load(crate::import::LoadError::Protocol(
            cyphr::Error::DurableLeafMismatch(leaf),
        ))) = &replayed
        {
            // Only a log written before the two-phase commit can hold a
            // leaf ahead of its commit: the log is a cache of the blob
            // store (I1), so rebuilding it from the blobs repairs it.
            tracing::warn!(
                principal = %principal_id,
                leaf,
                "legacy commit log: leaf written ahead of its commit; rebuild the log"
            );
        }
        replayed
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
    /// The action-only bundles accepted at each position are recorded
    /// before the commit there, and those accepted after the last replayed
    /// commit at the end, so DT is what it was when each commit was
    /// admitted.
    async fn replay_onto<T: cyphr::eml::Storage>(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        storage: T,
        through: Option<u64>,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        use crate::import::replay_commit;

        let mut principal = Self::principal_from_genesis(genesis, storage).await?;

        let commit_entries = self.stored_entries(principal_id, through).await?;
        let actions = self.action_history(principal_id).await?;

        for (position, entry) in commit_entries.iter().enumerate() {
            replay_actions_at(&mut principal, &actions, position as u64).await?;
            replay_commit(&mut principal, entry, position).await?;
        }
        replay_actions_at(&mut principal, &actions, commit_entries.len() as u64).await?;

        Ok(principal)
    }

    /// The action-only bundles accepted for `principal_id`, read back from
    /// the blob store.
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
            history.entry(stored.after).or_default().push(ActionBundle {
                manifest: stored.manifest,
                blobs: stored.blobs,
                bundle,
            });
        }
        for bundles in history.values_mut() {
            replay_order(bundles);
        }
        Ok(history)
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
    ) -> Result<Vec<crate::CommitEntry>, EngineError> {
        let last = match through {
            Some(0) => return Ok(Vec::new()),
            Some(count) => Some(count - 1),
            None => None,
        };
        let chain = self
            .indexer
            .get_commit_chain(principal_id, None, last)
            .await?;
        if chain.is_empty() {
            return Ok(Vec::new());
        }

        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let bundle = self.commit_bundle(principal_id, commit_ref).await?;
            commit_entries.push(replay_entry(
                &bundle,
                &commit_ref.commit_id,
                &commit_ref.pr,
            )?);
        }

        Ok(commit_entries)
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
    /// 2. Load existing principal from storage (or construct from genesis)
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
        self.ensure_healed().await?;

        if bundle.is_empty() {
            return Err(EngineError::InvalidInput("empty commit bundle".into()));
        }

        // Everything below, storage included, sees only the canonical
        // bundle, never the caller's bytes.
        let canonical = canonical_bundle(bundle)?;
        let bundle = &canonical;

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
        let _serialize_writes = lock.lock().await;

        // 2. Load (or construct) the principal from existing state.
        let mut principal = self.replay_stored(principal_id, genesis.clone()).await?;

        // 3. Determine the next sequence number.
        let tip_before = self.indexer.get_tip(principal_id).await?;
        let next_seq = tip_before.as_ref().map_or(0, |tip| tip.commit_count);

        let build = match Self::build_commit(&mut principal, bundle, principal_id, next_seq).await {
            Ok(Some(build)) => build,
            Ok(None) => {
                // Action-only bundle: no commit is formed and nothing is
                // indexed, but its actions are in DT from now on, so every
                // later replay records them here (`after` = `next_seq`).
                let blob_hashes = self
                    .store_actions(principal_id, next_seq, &bundle.actions)
                    .await?;
                // Built from the tip read before any write: once the blobs are
                // durable this response cannot fail (an error would report a
                // stored bundle as not stored).
                let tip = tip_before.and_then(|t| {
                    Some(CommittedTip {
                        sequence: t.commit_count.checked_sub(1)?,
                        commit_id: t.commit_id,
                        pr: t.pr,
                        sr: t.sr,
                        ar: t.ar,
                        cr: t.cr,
                    })
                });
                return Ok(IngestResult {
                    principal_id: principal_id.to_string(),
                    blob_hashes,
                    manifest_hash: None,
                    tip,
                });
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
                    match self.retain_rival(principal_id, genesis, bundle).await {
                        Ok(()) => {},
                        // The one retention outcome that is a refusal in
                        // its own right: no slot left for this key.
                        Err(full @ EngineError::BranchLimit { .. }) => return Err(full),
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
                return Err(refused);
            },
        };
        self.ingest_commit(bundle, build).await
    }

    /// Store an accepted action-only bundle and its [`ActionManifest`],
    /// and list it for replay. Returns the blob hashes.
    async fn store_actions(
        &self,
        principal_id: &str,
        after: u64,
        blobs: &[Vec<u8>],
    ) -> Result<Vec<Blake3Hash>, EngineError> {
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            blob_hashes.push(self.blob_store.put(blob).await?);
        }
        let manifest = ActionManifest {
            kind: ACTION_MANIFEST_KIND.to_string(),
            principal_id: principal_id.to_string(),
            after,
            blob_hashes: blob_hashes.clone(),
        };
        let mut bytes = ACTION_MANIFEST_PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("action manifest serialize: {e}")))?;
        let hash = self.blob_store.put(&bytes).await?;
        let mut held = self.actions.lock().unwrap_or_else(|p| p.into_inner());
        let of_principal = held.entry(principal_id.to_string()).or_default();
        if !of_principal.iter().any(|a| a.manifest == hash) {
            of_principal.push(StoredActions {
                after,
                manifest: hash,
                blobs: blob_hashes.clone(),
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
        let principal = match &staged {
            cyphr::replay::StagedBundle::Actions(_) => None,
            cyphr::replay::StagedBundle::Commit { staged, .. } => Some(staged.state()),
        };
        let digest_info = match principal {
            None => None,
            Some(principal) => {
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
                Some((commit_ids, ar, sr, pr, cr))
            },
        };

        if let (Some((commit_ids, ar, sr, pr, cr)), Some(principal)) = (digest_info, principal) {
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

            Ok(Some(StagedBuild { commit, staged }))
        } else {
            Ok(None)
        }
    }

    /// Retain a refused bundle as a non-canonical branch if it is a fork:
    /// a bundle that verifies against the principal's state at an earlier
    /// position, where the chain already holds a different commit. The
    /// bundle is still refused as the tip by the caller (I2: a fork is
    /// detected, never merged); this only keeps the evidence.
    ///
    /// The refusal is attacker-reachable, so the search is bounded:
    ///
    /// 1. **Authenticate first, replaying nothing.** Every coz of the bundle must name a key this
    ///    principal has ever held (its genesis keys and every key a stored coz introduced) and
    ///    verify under that key's public key. Anyone else costs blob reads only.
    /// 2. **One forward pass.** The stored chain is replayed once onto a private in-memory Commit
    ///    Tree. At each position where the bundle's transaction signers are active, a clone of that
    ///    prefix state tries the bundle through [`Self::build_commit`], the admission path's own
    ///    verification. At most one replay per stored commit.
    ///
    /// A bundle that verifies at no position (a key not active at its
    /// `pre`, an arrow that fits no state) is not retained. The private
    /// tree matters: replaying a rival over the principal's durable log
    /// would hit `DurableLeafMismatch`.
    ///
    /// Caller holds the principal's write lock.
    async fn retain_rival(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        bundle: &WireBundle,
    ) -> Result<(), EngineError> {
        use crate::import::replay_commits;

        if self.is_already_stored(principal_id, bundle).await? {
            return Ok(());
        }
        let entries = self.stored_entries(principal_id, None).await?;
        let Some(signers) = authenticated_signers(bundle, &genesis, &entries) else {
            return Ok(());
        };
        let actions = self.action_history(principal_id).await?;
        let mut principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new()).await?;
        for (position, entry) in entries.iter().enumerate() {
            // A rival at this position competes with a commit admitted
            // over the actions accepted before it. Two bases are tried: the
            // state with those actions (a rival that relies on actions the
            // principal already holds), then the state without them, which
            // is the fork point as the rival saw it. A rival whose commits
            // carry data brings its OWN actions inline, so replaying it over
            // the stored branch's actions would mismatch its data root.
            let active = signers.iter().all(|t| principal.is_key_active(t));
            let fork_point = if active {
                Some(principal.fork().await?)
            } else {
                None
            };
            replay_actions_at(&mut principal, &actions, position as u64).await?;
            if let Some(fork_point) = fork_point {
                self.retention_trials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Verified on a fork and never committed: the staged build
                // is dropped, and only its manifest is kept.
                let mut candidates = [principal.fork().await?, fork_point];
                for candidate in &mut candidates {
                    if let Ok(Some(build)) =
                        Self::build_commit(candidate, bundle, principal_id, position as u64).await
                    {
                        return self.keep_branch(bundle, build.commit).await;
                    }
                }
            }
            // The last commit's own state is never a `pre` of a rival.
            if position + 1 < entries.len() {
                self.retention_replays
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                replay_commits(&mut principal, std::slice::from_ref(entry)).await?;
            }
        }
        Ok(())
    }

    /// Whether `bundle` is, byte for byte and in its grouping, a commit this engine already
    /// holds: on the canonical chain or retained as a rival. Such a bundle
    /// is nobody's rival at any other position, since its arrow binds
    /// exactly one `pre`, so it settles with no replay and no clone. This
    /// is the cheap check made before any state is cloned: the arrow binds
    /// `pre` only through the post-state root, which cannot be recomputed
    /// without applying the bundle, so a hash identity is the one sound
    /// filter that needs no state.
    async fn is_already_stored(
        &self,
        principal_id: &str,
        bundle: &WireBundle,
    ) -> Result<bool, EngineError> {
        let hashes: Vec<Blake3Hash> = bundle
            .cozies()
            .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
            .collect();
        // The same cozies grouped otherwise are another commit (its arrow
        // binds another TMR), so the grouping is part of the identity.
        let shape = Shape::of(bundle);
        let kept = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal_id)
            .is_some_and(|rs| rs.iter().any(|r| r.blobs == hashes && r.shape == shape));
        if kept {
            return Ok(true);
        }
        let chain = self
            .indexer
            .get_commit_chain(principal_id, None, None)
            .await?;
        let frames = self.frames.lock().unwrap_or_else(|p| p.into_inner());
        Ok(chain.iter().any(|c| {
            c.blob_hashes == hashes
                && frames
                    .get(&(principal_id.to_string(), c.commit_id.clone()))
                    .is_some_and(|(s, _)| *s == shape)
        }))
    }

    /// Store a verified rival `commit` and its blobs behind
    /// [`BRANCH_MANIFEST_PREFIX`] and list it. A rival that is the
    /// canonical commit or an already-kept branch is a no-op; the
    /// rival of a key past [`BRANCH_PER_KEY`], or past [`BRANCH_LIMIT`] in all,
    /// is [`EngineError::BranchLimit`] and stores nothing.
    async fn keep_branch(
        &self,
        bundle: &WireBundle,
        commit: IndexableCommit,
    ) -> Result<(), EngineError> {
        let tip = commit.commit_ids.first().cloned().unwrap_or_default();
        let canonical = self
            .indexer
            .get_commit_chain(
                &commit.principal_id,
                Some(commit.sequence),
                Some(commit.sequence),
            )
            .await?;
        if canonical.first().is_none_or(|c| c.commit_id == tip) {
            return Ok(());
        }
        let signer = commit_signer(&commit);
        {
            let kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
            let of_principal = kept
                .get(&commit.principal_id)
                .map_or(&[][..], Vec::as_slice);
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                return Ok(());
            }
            if !has_slot(of_principal, &signer) {
                return Err(EngineError::BranchLimit { key: signer });
            }
        }
        let branch = BranchTip {
            tip,
            pre: commit.pre.clone(),
            sequence: commit.sequence,
            canonical: false,
        };
        let principal_id = commit.principal_id.clone();
        let (stored, _) = self
            .store_manifest(bundle, commit, BRANCH_MANIFEST_PREFIX, BRANCH_MANIFEST_KIND)
            .await?;
        self.branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(principal_id)
            .or_default()
            .push(Retained {
                tip: branch,
                signer,
                keys: key_entries(&stored.keys),
                blobs: stored.blob_hashes,
                shape: Shape::of(bundle),
            });
        Ok(())
    }

    /// How many stored commits retention has replayed so far: the cost
    /// refused bundles have put on this engine. Exposed so a test can pin
    /// that an unauthenticated bundle costs none.
    pub fn retention_replays(&self) -> u64 {
        self.retention_replays
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many positions retention has tried a bundle at so far (the
    /// positions where the bundle's signers were active).
    pub fn retention_trials(&self) -> u64 {
        self.retention_trials
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Every branch head of a principal: the canonical chain's tip
    /// (`canonical`, the commit [`Self::get_tip`] reports) and each
    /// retained rival, by position (the canonical head first at a shared
    /// position).
    ///
    /// A rival is a commit that verified at its `pre` but took a position
    /// the chain already held, so it was refused as the tip
    /// ([`Self::submit_commit`]) and kept as evidence of a fork. A
    /// principal that is not stored is [`EngineError::NotFound`].
    #[tracing::instrument(skip(self))]
    pub async fn list_branches(&self, principal_id: &str) -> Result<Vec<BranchTip>, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let not_stored = || EngineError::NotFound(format!("principal {principal_id} not found"));
        let tip = self
            .indexer
            .get_tip(&principal_id)
            .await?
            .ok_or_else(not_stored)?;
        let last = tip.commit_count.checked_sub(1).ok_or_else(not_stored)?;
        let head = self
            .indexer
            .get_commit_chain(&principal_id, Some(last), Some(last))
            .await?
            .into_iter()
            .next()
            .ok_or_else(not_stored)?;
        let mut branches = vec![BranchTip {
            tip: head.commit_id,
            pre: head.pre,
            sequence: head.sequence,
            canonical: true,
        }];
        if let Some(kept) = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&principal_id)
        {
            branches.extend(kept.iter().map(|r| r.tip.clone()));
        }
        branches.sort_by(|a, b| {
            (a.sequence, !a.canonical, &a.tip).cmp(&(b.sequence, !b.canonical, &b.tip))
        });
        Ok(branches)
    }

    /// Every fork of a principal the store can prove: for each retained
    /// rival, the canonical commit it took the position of and the rival
    /// itself, as wire blobs. A principal that is not stored is
    /// [`EngineError::NotFound`]; a principal never forked yields none.
    #[tracing::instrument(skip(self))]
    pub async fn fork_evidence(
        &self,
        principal_id: &str,
    ) -> Result<(String, Vec<ForkEvidence>), EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        if self.indexer.get_tip(&principal_id).await?.is_none() {
            return Err(EngineError::NotFound(format!(
                "principal {principal_id} not found"
            )));
        }
        let rivals = self
            .branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&principal_id)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(rivals.len());
        for rival in rivals {
            let at = rival.tip.sequence;
            let chain = self
                .indexer
                .get_commit_chain(&principal_id, Some(at), Some(at))
                .await?;
            let Some(canonical) = chain.first() else {
                continue;
            };
            let rival_bundle = rival
                .shape
                .group(self.read_blobs(&rival.blobs).await?, rival.keys.clone())
                .ok_or_else(|| {
                    EngineError::MalformedBlob(
                        "a retained branch's shape groups a different number of blobs".into(),
                    )
                })?;
            out.push(ForkEvidence {
                sequence: at,
                pre: rival.tip.pre.clone(),
                canonical: self.commit_bundle(&principal_id, canonical).await?,
                rival: rival_bundle,
            });
        }
        out.sort_by(|a, b| {
            let key = |e: &ForkEvidence| {
                (
                    e.sequence,
                    e.rival.cozies().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                )
            };
            key(a).cmp(&key(b))
        });
        Ok((principal_id, out))
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
        let chain = self
            .indexer
            .get_commit_chain(stored_id, Some(0), Some(0))
            .await?;
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
            let chain = self
                .indexer
                .get_commit_chain(&candidate, Some(0), Some(0))
                .await?;
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

    /// Discard the index and rebuild it from every durable manifest.
    ///
    /// The full-recovery form of [`Self::rebuild_index_from_manifests`]
    /// ([recovery-reindex], [recovery-convergence]): the index is a
    /// rebuildable cache of the blob store (root `AGENTS.md` I1), so
    /// clearing it first also drops any entry no manifest backs. `clear`
    /// requires a [`DeriveToken`] that only this crate can mint, which is
    /// why the clear lives here rather than at the call site.
    ///
    /// Unlike the heal pass, this rebuild trusts no manifest it can check:
    /// each principal is replayed from genesis through the admission path
    /// ([`Self::build_commit`]), manifest by manifest in sequence order, and
    /// a manifest recording a commit its blobs do not yield is quarantined
    /// ([`QuarantineReason::Unreplayable`]) with the rest of its chain, as
    /// is a principal whose sequence-0 blobs disclose no genesis (every
    /// chain begins with a genesis commit, SPEC 5.1).
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch(&self) -> Result<usize, EngineError> {
        Ok(self.rebuild_index_from_scratch_with_report().await?.indexed)
    }

    /// [`Self::rebuild_index_from_scratch`], reporting what it quarantined.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch_with_report(
        &self,
    ) -> Result<RebuildReport, EngineError> {
        self.indexer.clear(&DeriveToken::new()).await?;
        let report = self.rebuild_pass(true).await?;
        let set: Vec<(Blake3Hash, String)> = report
            .quarantined
            .iter()
            .map(|q| (q.manifest, format!("{:?}", q.reason)))
            .collect();
        self.indexer
            .set_quarantined(&set, &DeriveToken::new())
            .await?;
        // This pass is a full heal: without marking it, the first read
        // would run the trusting heal pass and re-index the manifests this
        // one quarantined. Already set means a heal ran earlier, which the
        // clear above has superseded either way.
        let _already_healed = self.healed.set(());
        Ok(report)
    }
}

/// The thumbprints that sign the transactions of `bundle`, if every coz
/// of the bundle is signed by a key the principal has ever held and its
/// signature verifies under that key; `None` otherwise, or if the bundle
/// has no transaction. Reads no principal state: `genesis` and the keys the
/// stored `entries` introduced are the whole key history.
fn authenticated_signers(
    bundle: &WireBundle,
    genesis: &crate::Genesis,
    entries: &[crate::CommitEntry],
) -> Option<Vec<coz::Thumbprint>> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut history: HashMap<String, (String, Vec<u8>)> = HashMap::new();
    let genesis_keys: &[cyphr::Key] = match genesis {
        crate::Genesis::Implicit(key) => std::slice::from_ref(key),
        crate::Genesis::Explicit(keys) => keys,
    };
    for key in genesis_keys {
        history.insert(
            key.tmb().to_b64(),
            (key.alg().to_owned(), key.pub_key().to_vec()),
        );
    }
    for key in entries.iter().flat_map(|e| &e.keys) {
        if let Ok(public) = Base64UrlUnpadded::decode_vec(&key.pub_key) {
            history.insert(key.tmb.clone(), (key.alg.clone(), public));
        }
    }

    let mut signers = Vec::new();
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
        if cyphr::parsed_coz::typ::is_transaction(&header.typ) {
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
            Ok(keys) => Some(Ok(crate::Genesis::Explicit(keys))),
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

/// Whether `typ` is the protocol's `commit/create` (authority-qualified
/// suffix, SPEC 7.3), never a substring match: an application typ that
/// merely contains `/commit/create` is an ordinary coz.
fn is_commit_create_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::COMMIT_CREATE)
}

/// Record the action-only bundles `history` holds at `position` onto
/// `principal`, through the core's replay entry point.
async fn replay_actions_at<T: cyphr::eml::Storage>(
    principal: &mut cyphr::Principal<T>,
    history: &ActionHistory,
    position: u64,
) -> Result<(), EngineError> {
    for held in history.get(&position).into_iter().flatten() {
        cyphr::replay::replay_bundle(principal, &held.bundle)
            .await
            .map_err(|e| crate::import::LoadError::Protocol(e.source))?;
    }
    Ok(())
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

/// Order the action-only bundles accepted at one position as they were
/// accepted. Each was accepted only if no action of it was older than
/// DT's latest (`TimestampPast`), so accepted bundles never overlap in `now`:
/// ordering by earliest `now` restores the acceptance order, and the
/// manifest hash orders bundles of one instant, where order cannot change
/// DT (DR sorts by `now`, then digest, SPEC 3.7.7).
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

/// Whether `data` parses as the pre-keyspace manifest shape. Parsed, not
/// searched: JSON lets any member name be spelled with escapes.
fn is_legacy_manifest(data: &[u8]) -> bool {
    /// The pre-keyspace manifest's shape: a kind and a commit, whatever
    /// else it carried (it predates the recorded transaction shape).
    #[derive(serde::Deserialize)]
    struct Legacy {
        kind: String,
        #[serde(rename = "commit")]
        _commit: IndexableCommit,
    }
    serde_json::from_slice::<Legacy>(data).is_ok_and(|m| m.kind == COMMIT_MANIFEST_KIND)
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
