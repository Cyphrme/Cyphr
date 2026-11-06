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

use cyphr::state::{StateDigest, TaggedDigest};
pub use error::EngineError;

use crate::blob::{Blake3Hash, BlobStore};
use crate::index::{
    CommitRef, DeriveToken, EntityType, IndexableCommit, IndexableCoz, Indexer, IndexerWrite,
    TipState,
};

/// A commit's metadata paired with its blob contents.
///
/// Each entry in `blobs` corresponds positionally to a
/// `CommitRef::blob_hashes` entry.
#[derive(Debug, Clone)]
pub struct PatchEntry {
    /// Commit metadata from the index.
    pub commit: CommitRef,
    /// Raw blob contents, ordered to match `commit.blob_hashes`.
    pub blobs: Vec<Vec<u8>>,
}

/// Response from [`StorageEngine::get_patch`].
#[derive(Debug, Clone)]
pub struct PatchResponse {
    /// Principal genesis identifier.
    pub principal_id: String,
    /// Ordered commit entries with their blob contents.
    pub entries: Vec<PatchEntry>,
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

/// Metadata for ingesting a pre-validated commit.
///
/// The engine does not validate protocol-level signatures or state
/// transitions — that responsibility belongs to the protocol layer
/// (Phase 3b). This struct carries the metadata needed to store
/// blobs and build an index entry.
#[derive(Clone, Debug)]
struct ParsedCozInfo {
    pay_json: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
    typ: String,
    tmb: String,
    now: i64,
    alg: String,
    new_key: Option<cyphr::Key>,
    key_info: Option<crate::PublicKeyInfo>,
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
    /// branch): no commit was formed, so there is no manifest to hash.
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

/// Entries the pre-PG classification memo holds. One entry per
/// (principal, tip, claim) a peer has asked about, so the bound is what
/// limits the memory an unauthenticated peer can pin.
const PRE_PG_CACHE_CAPACITY: usize = 4096;

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
    /// serialize (making [`CloneableLog`](cyphr::commit_root::CloneableLog)'s
    /// documented fresh-Principal-per-call assumption hold by construction)
    /// while writers for *different* principals never contend. The outer
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
    /// Memo of [`Self::pending_pg_owner`]'s replay-decided answer, keyed by
    /// (owner, owner's commit count, claimed id): the answer is a pure
    /// function of the owner's chain, which a new commit extends and so
    /// re-keys. Without it, an unauthenticated peer naming a pre-PG
    /// principal's current PR replays that principal's whole history on
    /// every request.
    pre_pg_owner: BoundedCache<(String, u64, String), bool>,
    /// Retained non-canonical branches per canonical principal id: a cache
    /// of the branch manifests in the blob store (I1), filled by the
    /// rebuild scan and by retention, at most [`BRANCH_LIMIT`] per
    /// principal.
    branches: std::sync::Mutex<HashMap<String, Vec<BranchTip>>>,
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
            pre_pg_owner: BoundedCache::new(PRE_PG_CACHE_CAPACITY),
            branches: std::sync::Mutex::new(HashMap::new()),
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
            pre_pg_owner: BoundedCache::new(PRE_PG_CACHE_CAPACITY),
            branches: std::sync::Mutex::new(HashMap::new()),
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
        let principal_id = self.canonical_principal_id(principal_id).await?;
        Ok(self.indexer.get_tip(&principal_id).await?)
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
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let principal_id = principal_id.as_str();
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
            let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "blob {hash} referenced by index commit {} missing",
                        commit_ref.commit_id
                    ))
                })?;
                blobs.push(data);
            }
            entries.push(PatchEntry {
                commit: commit_ref,
                blobs,
            });
        }

        Ok(PatchResponse {
            principal_id: principal_id.to_string(),
            entries,
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
    /// **Not principal-scoped — a known, tracked gap (issue #154), not an
    /// enforced property.** `principal_id` is a parameter of this function
    /// only to compose the error messages below; [`Indexer::resolve_digest`]
    /// takes no principal, and the [`EntityRef`](crate::index::EntityRef) it
    /// returns carries no principal field, so digest→position resolution is
    /// a GLOBAL namespace. An anchor genuinely produced by a DIFFERENT
    /// principal's chain resolves here exactly as it would for its own
    /// principal — nothing below compares the resolved entity against
    /// `principal_id` at all. This is the identity-binding gap #154 already
    /// tracks elsewhere in this file (storage never binds a derived genesis
    /// to the identifier it is filed under); this is a third instance of
    /// that same structural gap, not a distinct defect.
    ///
    /// Reachable: `from` is attacker-rewritable on the wire (see
    /// `request_side_from_rewrite_withholding_rejected`,
    /// `cyphr-server/tests/witness_mode.rs`), so a rewritten anchor
    /// belonging to principal A can resolve a position that then bounds
    /// principal B's own `get_commit_chain` query. `get_commit_chain`
    /// itself stays principal-scoped, so only B's own entries are ever
    /// served — no cross-principal data leak — but the POSITION used to
    /// bound them is unverified against which principal it actually names.
    /// Every downstream branch traced fails closed behind N2's post-apply
    /// authenticated-channel comparison (`EntryCommitmentMismatch`) --
    /// but only when the syncing witness has `authority_identity` (K10)
    /// configured (`cyphr-server/src/sync.rs`'s `authenticated_report`
    /// gate: the comparison runs inside `if let Some(report) =
    /// &authenticated_report`, itself populated only when
    /// `state.config.authority_identity` is `Some`). A witness with no
    /// `authority_identity` configured has no downstream check that
    /// would catch a wrongly-bounded response, so this is
    /// defence-in-depth for the K10 case only, not a demonstrated path
    /// to forged or leaked state under every configuration.
    async fn resolve_anchor_position(
        &self,
        principal_id: &str,
        anchor: &TaggedDigest,
    ) -> Result<u64, EngineError> {
        // A digest names a set of holders; the anchor is for this
        // principal's chain, so take the holder that is this principal.
        let holders = self.indexer.resolve_digest_holders(anchor).await?;
        let entity = holders
            .iter()
            .find(|h| h.principal_id.as_deref() == Some(principal_id))
            .or_else(|| holders.first())
            .ok_or_else(|| {
                EngineError::NotFound(format!(
                    "resync anchor {anchor} not indexed (requested for principal {principal_id})"
                ))
            })?;
        entity.sequence.map(|seq| seq + 1).ok_or_else(|| {
            EngineError::NotFound(format!(
                "resync anchor {anchor} carries no chain position (requested for principal \
                 {principal_id})"
            ))
        })
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
    ///
    /// Needed for an explicit-genesis principal (such as the server's own),
    /// whose genesis key set cannot be read back from its stored blobs: the
    /// blob-derived genesis [`Self::rederive_roots`] resolves is always
    /// implicit.
    #[tracing::instrument(skip(self, genesis))]
    pub async fn rederive_roots_with_genesis(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<DerivedRoots, EngineError> {
        self.ensure_healed().await?;
        let principal_id = self.canonical_principal_id(principal_id).await?;
        let principal = self.load_principal(&principal_id, genesis).await?;

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
        blobs: &[&[u8]],
        commit: IndexableCommit,
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        self.store_manifest(blobs, commit, COMMIT_MANIFEST_PREFIX, COMMIT_MANIFEST_KIND)
            .await
    }

    /// [`Self::store_blobs_and_manifest`] under a given manifest keyspace:
    /// a chain commit, or a retained branch ([`Self::keep_branch`]).
    async fn store_manifest(
        &self,
        blobs: &[&[u8]],
        mut commit: IndexableCommit,
        prefix: &[u8],
        kind: &str,
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        // Store each blob.
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for (i, blob) in blobs.iter().enumerate() {
            let hash = self.blob_store.put(blob).await?;
            blob_hashes.push(hash);
            if i < commit.cozies.len() {
                commit.cozies[i].blob_hash = hash;
            }
        }
        commit.blob_hashes = blob_hashes;

        // Durable commit point: once this manifest is stored, the full
        // IndexableCommit -- including the exact ingest-time order of its
        // cozies -- is recoverable from the blob store alone.
        let manifest = CommitManifest {
            kind: kind.to_string(),
            commit: commit.clone(),
        };
        let mut manifest_bytes = prefix.to_vec();
        serde_json::to_writer(&mut manifest_bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("commit manifest serialize: {e}")))?;
        let manifest_hash = self.blob_store.put(&manifest_bytes).await?;

        Ok((commit, manifest_hash))
    }

    /// Ingest a pre-validated commit: store blobs and index metadata.
    ///
    /// Each entry in `blobs` is a raw coz byte slice. The engine:
    /// 1. Puts each blob into the blob store (content-addressed)
    /// 2. Builds an `IndexableCommit` from the metadata + blob hashes
    /// 3. Stores a durable [`CommitManifest`] recording that `IndexableCommit` (see
    ///    [`Self::store_blobs_and_manifest`]) -- the crash-safe commit point
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
    /// #     blobs: &[&[u8]],
    /// #     commit: cyphr_storage::index::IndexableCommit,
    /// # ) {
    /// // ingest_commit is pub(crate): unreachable from outside this crate,
    /// // so a caller cannot bypass submit_commit's serialization lock.
    /// let _ = engine.ingest_commit(blobs, commit).await;
    /// # }
    /// ```
    #[tracing::instrument(
        skip(self, blobs),
        fields(
            principal_id = %commit.principal_id,
            blob_count = blobs.len()
        )
    )]
    pub(crate) async fn ingest_commit(
        &self,
        blobs: &[&[u8]],
        commit: IndexableCommit,
    ) -> Result<IngestResult, EngineError> {
        // The one exclusive claim (a PG alias) is checked before the first
        // durable write: a refused commit must leave no blob or manifest
        // for a later rebuild to trip over.
        self.indexer
            .check_commit(&commit, &DeriveToken::new())
            .await?;
        let (commit, manifest_hash) = self.store_blobs_and_manifest(blobs, commit).await?;
        let blob_hashes = commit.blob_hashes.clone();

        self.indexer
            .index_commit(&commit, &DeriveToken::new())
            .await?;

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
    /// the blob-presence and binding checks. Replay is the audit path
    /// ([`Self::rederive_roots`]).
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_with_report(&self) -> Result<RebuildReport, EngineError> {
        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;

        let mut quarantined = Vec::new();
        // The earliest sequence at which a principal's chain broke, for any
        // reason; every later commit of that principal is orphaned, so the
        // indexed chain is always a gapless prefix.
        let mut broken_from: HashMap<String, u64> = HashMap::new();
        let mut manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut branch_manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
            if let Some(json) = data.strip_prefix(BRANCH_MANIFEST_PREFIX) {
                // Retained branches never reach the index, so a bad one
                // costs only its own listing, never a chain position.
                match serde_json::from_slice::<CommitManifest>(json) {
                    Ok(m) if m.kind == BRANCH_MANIFEST_KIND => {
                        match self.check_manifest_supported(&hash, &m.commit).await? {
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
            if let Err(reason) = self
                .check_manifest_supported(&hash, &manifest.commit)
                .await?
            {
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
            match self.indexer.index_commit(commit, &DeriveToken::new()).await {
                Ok(()) => indexed += 1,
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
    ) -> Result<HashMap<String, Vec<BranchTip>>, EngineError> {
        branch_manifests.sort_by_key(|(hash, _)| *hash.as_bytes());
        let mut kept: HashMap<String, Vec<BranchTip>> = HashMap::new();
        for (hash, manifest) in branch_manifests {
            let commit = manifest.commit;
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
                .any(|b| b.tip == tip && b.sequence == commit.sequence)
            {
                continue;
            }
            if of_principal.len() >= BRANCH_LIMIT {
                reject(QuarantineReason::Conflict(format!(
                    "more than {BRANCH_LIMIT} retained branches"
                )));
                continue;
            }
            of_principal.push(BranchTip {
                tip,
                pre: commit.pre,
                sequence: commit.sequence,
                canonical: false,
            });
        }
        Ok(kept)
    }

    /// A corruption detector for principals whose blobs carry their
    /// genesis, not a security boundary. Without replay: if a principal's
    /// first sequence-0 manifest (in canonical order) names a
    /// `commit/create` blob carrying a key, the genesis-derived id of that
    /// key must equal the principal id the manifests carry. Returns each
    /// failing principal with why; they are quarantined.
    ///
    /// Scope: a principal with no such carrier (explicit genesis, whose
    /// key set is never in blobs) is not judged, and when several
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
            let mut blobs = Vec::with_capacity(first.commit.blob_hashes.len());
            for blob in &first.commit.blob_hashes {
                blobs.push(self.blob_store.get(blob).await?.ok_or_else(|| {
                    EngineError::NotFound(format!("blob {blob} of a sequence-0 manifest"))
                })?);
            }
            // Only a `commit/create` blob carrying a key is a genesis
            // carrier (the wire convention). Without one the id cannot be
            // proven from blobs, so the manifest is not judged here.
            let Some(carrier) = blobs.iter().find(|b| {
                serde_json::from_slice::<serde_json::Value>(b).is_ok_and(|v| {
                    v.get("key").is_some()
                        && v.pointer("/pay/typ")
                            .and_then(|t| t.as_str())
                            .is_some_and(is_commit_create_typ)
                })
            }) else {
                continue;
            };
            match Self::genesis_from_blob(carrier).and_then(|g| genesis_principal_id(&g)) {
                Ok(derived) if derived == principal_id => {},
                Ok(derived) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("its blobs derive principal {derived}"),
                    );
                },
                Err(e) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("genesis not derivable from its blobs: {e}"),
                    );
                },
            }
        }
        Ok(unbound)
    }

    /// Whether a manifest's commit names blobs the store holds: the index
    /// is a cache of the blobs (I1), so a manifest field the blobs do not
    /// support must not reach it. `Ok(Err(reason))` is a manifest to
    /// quarantine; `Err` is a backend failure.
    async fn check_manifest_supported(
        &self,
        manifest: &Blake3Hash,
        commit: &IndexableCommit,
    ) -> Result<Result<(), QuarantineReason>, EngineError> {
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
    /// [`import::replay_commits`] infrastructure.
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
        let principal_id = self.canonical_principal_id(principal_id).await?;
        self.replay_stored(&principal_id, genesis).await
    }

    /// [`load_principal`](Self::load_principal) for an id already known to
    /// be the stored spelling. Separate so resolving a PG-to-be
    /// ([`pending_pg_owner`](Self::pending_pg_owner)) can replay without
    /// re-entering id resolution.
    async fn replay_stored(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
    ) -> Result<cyphr::Principal<S>, EngineError> {
        let storage = (self.storage_factory)(principal_id).map_err(EngineError::Storage)?;
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
    async fn replay_onto<T: cyphr::eml::Storage>(
        &self,
        principal_id: &str,
        genesis: crate::Genesis,
        storage: T,
        through: Option<u64>,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        use crate::import::replay_commits;

        let mut principal = Self::principal_from_genesis(genesis, storage)?;

        let commit_entries = self.stored_entries(principal_id, through).await?;

        replay_commits(&mut principal, &commit_entries)?;

        Ok(principal)
    }

    /// A principal holding only its genesis keys, over `storage`.
    fn principal_from_genesis<T: cyphr::eml::Storage>(
        genesis: crate::Genesis,
        storage: T,
    ) -> Result<cyphr::Principal<T>, EngineError> {
        match genesis {
            crate::Genesis::Implicit(key) => {
                Ok(cyphr::Principal::implicit_with_storage(key, storage)?)
            },
            crate::Genesis::Explicit(keys) => {
                if keys.is_empty() {
                    return Err(EngineError::InvalidInput(
                        "genesis requires at least one key".into(),
                    ));
                }
                Ok(cyphr::Principal::explicit_with_storage(keys, storage)?)
            },
        }
    }

    /// The first `through` stored commits (all for `None`) of
    /// `principal_id` as replayable entries: blobs read and parsed, key
    /// material taken from each coz's `key` member. No protocol check.
    async fn stored_entries(
        &self,
        principal_id: &str,
        through: Option<u64>,
    ) -> Result<Vec<crate::CommitEntry>, EngineError> {
        use crate::CommitEntry;

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

        // 3. For each CommitRef, fetch blobs and build a CommitEntry.
        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let mut cozies = Vec::with_capacity(commit_ref.blob_hashes.len());
            let mut keys = Vec::new();

            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "blob {hash} referenced by index commit {} missing",
                        commit_ref.commit_id
                    ))
                })?;

                // Parse blob as JSON.
                let json_str = String::from_utf8(data).map_err(|e| {
                    EngineError::MalformedBlob(format!("blob {hash} is not UTF-8: {e}"))
                })?;
                let value: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                    EngineError::MalformedBlob(format!("blob {hash} is not valid JSON: {e}"))
                })?;

                // Extract key material from the coz envelope's "key" field
                // (for key-introducing transactions).
                if let Some(key_obj) = value.get("key") {
                    if let Some(ke) = key_value_to_entry(key_obj) {
                        keys.push(ke);
                    }
                }

                cozies.push(value);
            }

            // replay_commits only reads `cozies` and `keys`;
            // state digest fields are inert during replay.
            commit_entries.push(CommitEntry::new(
                cozies,
                keys,
                commit_ref.commit_id.clone(),
                None, // ar — unused during replay
                None, // sr — unused during replay
                commit_ref.pr.clone(),
            ));
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
    /// 4. For each raw coz blob: parse `{pay, sig}`, extract key material, compute `czd`, call
    ///    `scope.verify_and_apply()`
    /// 5. Finalize the scope → immutable `Commit`
    /// 6. Extract state digests from the finalized `Commit`
    /// 7. Store blobs + index via `ingest_commit`
    ///
    /// # Arguments
    ///
    /// * `principal_id` — The principal's genesis-derived id (SPEC §3.1), labelled (`ALG:digest`,
    ///   the stored spelling) or bare, or any Principal Root variant the principal has had (its PG
    ///   among them, SPEC §3.7.1/§12.1), labelled or bare. Any other id is refused with
    ///   [`EngineError::InvalidInput`]; every key below is the genesis-derived labelled spelling.
    /// * `genesis` — How this principal was originally created, or `None` to auto-detect from
    ///   storage (existing principal) or from the submitted blobs (new principal).
    /// * `raw_blobs` — Raw coz JSON envelopes (`{pay, sig, key?}`).
    ///
    /// # Errors
    ///
    /// Any protocol violation (bad signature, broken chain, unknown signer,
    /// etc.) causes the entire submit to fail with no side effects — blobs
    #[tracing::instrument(skip(self, genesis, raw_blobs), fields(blob_count = raw_blobs.len()))]
    pub async fn submit_commit(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        raw_blobs: &[&[u8]],
    ) -> Result<IngestResult, EngineError> {
        self.ensure_healed().await?;

        if raw_blobs.is_empty() {
            return Err(EngineError::InvalidInput("empty commit bundle".into()));
        }

        // Everything below, storage included, sees only the canonical
        // coz, never the caller's bytes.
        let canonical = raw_blobs
            .iter()
            .enumerate()
            .map(|(i, blob)| canonical_coz(blob, i))
            .collect::<Result<Vec<_>, _>>()?;
        let raw_blobs: Vec<&[u8]> = canonical.iter().map(Vec::as_slice).collect();
        let raw_blobs = raw_blobs.as_slice();

        // 1. Resolve genesis, then the one canonical spelling of the id.
        //
        // SPEC §3.1: a principal's identifier is derived from its genesis,
        // never chosen by the caller. The derived id has one stored
        // spelling (the algorithm-labelled `ALG:digest`); the bare digest
        // is accepted as input only when it names that same id. Every
        // lock, index and storage key below is the canonical spelling, so
        // one identity cannot be stored as two independent principals
        // (a fork refused under one spelling accepted under the other, or a
        // revoked key committing under an alias).
        let mut stored = self.stored_id(principal_id).await?;
        if stored.is_none() {
            stored = self.pending_pg_owner(principal_id).await?;
        }
        let genesis = match (genesis, &stored) {
            (Some(g), _) => g,
            (None, Some(stored_id)) => self.genesis_of_stored(stored_id).await?,
            (None, None) => Self::genesis_from_raw_blobs(raw_blobs)?,
        };
        let canonical = genesis_principal_id(&genesis)?;
        let claimed = principal_id;
        // A spelling other than the genesis-derived id is honoured only
        // when it already resolves to this stored principal, or (a new
        // principal) when its own first commit yields that Principal Root
        // (checked once the commit is applied, below).
        let alias_claim = claimed != canonical && claimed != bare_digest(&canonical);
        if stored
            .as_deref()
            .is_some_and(|stored_id| stored_id != canonical)
        {
            return Err(EngineError::InvalidInput(format!(
                "principal_id is not the genesis-derived id: {claimed}"
            )));
        }
        let unproven_alias = alias_claim && stored.is_none();
        let principal_id = canonical.as_str();

        // Serialize the whole sequence-resolution-through-ingest critical
        // section per principal_id: two concurrent callers for the SAME
        // principal must never both resolve `next_seq` before either has
        // ingested. Held for the remainder of this function; a concurrent
        // caller for a DIFFERENT principal_id never contends on this lock.
        let lock = self.principal_lock(principal_id);
        let _serialize_writes = lock.lock().await;

        // 2. Load (or construct) the principal from existing state.
        let mut principal = self.load_principal(principal_id, genesis.clone()).await?;

        // 3. Determine the next sequence number.
        let tip_before = self.indexer.get_tip(principal_id).await?;
        let next_seq = tip_before.as_ref().map_or(0, |tip| tip.commit_count);

        let commit = match Self::build_commit(
            &mut principal,
            raw_blobs,
            principal_id,
            claimed,
            unproven_alias,
            next_seq,
        ) {
            Ok(Some(commit)) => commit,
            Ok(None) => {
                // Action-only bundle: just store blobs in blob store without
                // indexing. No commit was formed, so there is no manifest.
                let mut blob_hashes = Vec::with_capacity(raw_blobs.len());
                for blob in raw_blobs {
                    let hash = self.blob_store.put(blob).await?;
                    blob_hashes.push(hash);
                }
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
                // Only a verification failure can be a fork; a malformed
                // or unreadable bundle is nothing to keep.
                if matches!(refused, EngineError::Protocol(_)) {
                    self.retain_rival(principal_id, genesis, raw_blobs, claimed, unproven_alias)
                        .await?;
                }
                return Err(refused);
            },
        };
        self.ingest_commit(raw_blobs, commit).await
    }

    /// Verify `raw_blobs` against `principal`'s current state and build the
    /// commit they would form at `next_seq`, without touching storage.
    /// `Ok(None)` is an action-only bundle: it forms no commit.
    ///
    /// Synchronous and storage-free so a refused fork can be re-verified
    /// against an earlier state ([`Self::retain_rival`]) by the same code
    /// that admits a tip.
    fn build_commit<T: cyphr::eml::Storage>(
        principal: &mut cyphr::Principal<T>,
        raw_blobs: &[&[u8]],
        principal_id: &str,
        claimed: &str,
        unproven_alias: bool,
        next_seq: u64,
    ) -> Result<Option<IndexableCommit>, EngineError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        use crate::import::{is_key_introducing_typ, is_transaction_typ};

        let active_algs = principal.active_algs().to_vec();

        let mut first_tx_idx = None;
        for (i, blob_bytes) in raw_blobs.iter().enumerate() {
            let value: serde_json::Value = serde_json::from_slice(blob_bytes)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: {e}")))?;
            let pay = value
                .get("pay")
                .ok_or_else(|| EngineError::MalformedBlob(format!("blob {i}: missing 'pay'")))?;
            let header = cyphr::parsed_coz::CozHeader::parse(pay)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: {e}")))?;
            if is_transaction_typ(&header.typ) {
                first_tx_idx = Some(i);
                break;
            }
        }

        let parse_coz = |blob_bytes: &[u8], i: usize| -> Result<ParsedCozInfo, EngineError> {
            let value: serde_json::Value = serde_json::from_slice(blob_bytes)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: {e}")))?;

            let pay = value
                .get("pay")
                .ok_or_else(|| EngineError::MalformedBlob(format!("blob {i}: missing 'pay'")))?;
            let sig_b64 = value
                .get("sig")
                .and_then(|s| s.as_str())
                .ok_or_else(|| EngineError::MalformedBlob(format!("blob {i}: missing 'sig'")))?;

            let sig = Base64UrlUnpadded::decode_vec(sig_b64)
                .map_err(|_| EngineError::MalformedBlob(format!("blob {i}: invalid sig base64")))?;

            let mut pay_val = pay.clone();
            crate::import::canonicalize_value(&mut pay_val);
            let pay_json = serde_json::to_vec(&pay_val)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: pay serialize: {e}")))?;

            let header = cyphr::parsed_coz::CozHeader::parse(pay)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: {e}")))?;
            let typ = header.typ;

            let alg_str = pay
                .get("alg")
                .and_then(|a| a.as_str())
                .ok_or_else(|| {
                    EngineError::MalformedBlob(format!("blob {i}: missing 'alg' in pay"))
                })?
                .to_string();
            let czd = cyphr::compute_czd(&pay_json, &sig, &alg_str).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {i}: czd computation failed"))
            })?;

            let tmb = header.tmb.to_b64();
            let now = header.now;

            let mut key_info = None;
            let new_key = if is_key_introducing_typ(&typ) {
                match value.get("key") {
                    // A missing sidecar is the protocol layer's to reject
                    // (`MalformedPayload`); a PRESENT one that is not a
                    // valid key is reported as such, never swallowed.
                    None => None,
                    Some(k) => {
                        let ke = key_value_to_entry(k).ok_or_else(|| {
                            EngineError::MalformedBlob(format!(
                                "blob {i}: 'key' missing required fields (alg, pub, tmb)"
                            ))
                        })?;
                        key_info = Some(crate::PublicKeyInfo {
                            thumbprint: ke.tmb.clone(),
                            algorithm: ke.alg.clone(),
                            public_key: ke.pub_key.clone(),
                        });
                        Some(crate::import::key_entry_to_key(&ke).map_err(|e| match e {
                            // e.g. `TmbMismatch`: a client-facing protocol
                            // refusal, not an infrastructure failure.
                            crate::import::LoadError::Protocol(p) => EngineError::Protocol(p),
                            other => EngineError::MalformedBlob(format!("blob {i}: {other}")),
                        })?)
                    },
                }
            } else {
                None
            };

            Ok(ParsedCozInfo {
                pay_json,
                sig,
                czd,
                typ,
                tmb,
                now,
                alg: alg_str,
                new_key,
                key_info,
            })
        };

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

        let mut parsed_cozies = Vec::with_capacity(raw_blobs.len());
        let mut last_timestamp: i64 = 0;
        let mut extracted_keys = Vec::new();

        let digest_info = if let Some(idx) = first_tx_idx {
            // 4.1 Process pre-actions (before the first transaction).
            for (i, blob_bytes) in raw_blobs.iter().enumerate().take(idx) {
                let parsed = parse_coz(blob_bytes, i)?;
                if let Some(info) = &parsed.key_info {
                    extracted_keys.push(info.clone());
                }
                last_timestamp = parsed.now;

                principal.verify_and_record_action(
                    &parsed.pay_json,
                    &parsed.sig,
                    parsed.czd.clone(),
                )?;
                parsed_cozies.push(parsed);
            }

            // 4.2 Open commit scope and process transactions and deferred actions.
            let (commit_ids, ar, sr, pr, deferred) = {
                let mut scope = principal.begin_commit();
                let mut deferred = Vec::new();

                for (i, blob_bytes) in raw_blobs.iter().enumerate().skip(idx) {
                    let parsed = parse_coz(blob_bytes, i)?;
                    if let Some(info) = &parsed.key_info {
                        extracted_keys.push(info.clone());
                    }
                    last_timestamp = parsed.now;

                    if is_transaction_typ(&parsed.typ) {
                        scope.verify_and_apply(
                            &parsed.pay_json,
                            &parsed.sig,
                            parsed.czd.clone(),
                            parsed.new_key.clone(),
                        )?;
                    } else {
                        deferred.push(parsed.clone());
                    }
                    parsed_cozies.push(parsed);
                }

                let commit = scope.finalize()?;
                let commit_ids = format_multihash_all(&commit.tr().0)?;
                let ar = format_multihash_opt(commit.auth_root().map(|a| a.as_multihash()))?;
                let sr = format_multihash_opt(commit.sr().map(|s| s.as_multihash()))?;
                let pr = format_multihash_all(commit.pr().as_multihash())?;
                (commit_ids, ar, sr, pr, deferred)
            };

            // 4.3 Process post-actions (after scope is finalized and dropped).
            for parsed in deferred {
                principal.verify_and_record_action(&parsed.pay_json, &parsed.sig, parsed.czd)?;
            }

            // Read after the commit scope's borrow has ended: finalize()
            // already updated principal's CR (the EML log gained a leaf).
            let cr = principal
                .cr()
                .map(|c| format_multihash_all(c.as_multihash()))
                .transpose()?
                .unwrap_or_default();

            Some((commit_ids, ar, sr, pr, cr))
        } else {
            // Action-only bundle.
            for (i, blob_bytes) in raw_blobs.iter().enumerate() {
                let parsed = parse_coz(blob_bytes, i)?;
                if let Some(info) = &parsed.key_info {
                    extracted_keys.push(info.clone());
                }
                last_timestamp = parsed.now;

                principal.verify_and_record_action(
                    &parsed.pay_json,
                    &parsed.sig,
                    parsed.czd.clone(),
                )?;
                parsed_cozies.push(parsed);
            }
            None
        };

        if let Some((commit_ids, ar, sr, pr, cr)) = digest_info {
            // A new principal's non-genesis id must be its PG-to-be: the PR
            // it holds after this commit, and only while this commit does
            // not itself establish the PG (then the PG is the genesis-time
            // PR, and the post-commit PR is a historical root, not an id).
            let names_pg_to_be = principal.pg().is_none()
                && pr.iter().any(|v| v == claimed || bare_digest(v) == claimed);
            if unproven_alias && !names_pg_to_be {
                return Err(EngineError::InvalidInput(format!(
                    "principal_id is not the genesis-derived id: {claimed}"
                )));
            }
            let pg = match principal.pg() {
                Some(pg) if !had_pg => format_multihash_all(pg.as_multihash())?,
                _ => Vec::new(),
            };

            let mut cozies = Vec::with_capacity(parsed_cozies.len());
            for parsed in parsed_cozies {
                let source_alg = cyphr::state::hash_alg_from_str(&parsed.alg)
                    .unwrap_or(cyphr::state::HashAlg::Sha256);
                let tagged = cyphr::state::TaggedCzd::new(&parsed.czd, source_alg);

                let post_active_algs = active_algs.clone();
                let primary_alg = post_active_algs.first().copied().unwrap_or(source_alg);
                let converted = tagged.convert_to(primary_alg);
                let primary_czd = format!(
                    "{primary_alg}:{}",
                    Base64UrlUnpadded::encode_string(&converted)
                );

                let payload = serde_json::from_slice::<serde_json::Value>(&parsed.pay_json)
                    .ok()
                    .and_then(|v| serde_json::to_string(&v).ok());

                cozies.push(IndexableCoz {
                    blob_hash: Blake3Hash::from_bytes([0; 32]), // filled in by ingest_commit
                    czd: primary_czd,
                    typ: parsed.typ,
                    tmb: parsed.tmb,
                    alg: parsed.alg,
                    now: parsed.now,
                    payload,
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
                cozies,
                timestamp: last_timestamp,
                keys: extracted_keys,
                pg,
            };

            Ok(Some(commit))
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
        raw_blobs: &[&[u8]],
        claimed: &str,
        unproven_alias: bool,
    ) -> Result<(), EngineError> {
        use crate::import::replay_commits;

        let entries = self.stored_entries(principal_id, None).await?;
        let Some(signers) = authenticated_signers(raw_blobs, &genesis, &entries) else {
            return Ok(());
        };
        let mut principal =
            Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new())?;
        for (position, entry) in entries.iter().enumerate() {
            if signers.iter().all(|t| principal.is_key_active(t)) {
                self.retention_trials
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut candidate = principal.clone();
                if let Ok(Some(commit)) = Self::build_commit(
                    &mut candidate,
                    raw_blobs,
                    principal_id,
                    claimed,
                    unproven_alias,
                    position as u64,
                ) {
                    return self.keep_branch(raw_blobs, commit).await;
                }
            }
            // The last commit's own state is never a `pre` of a rival.
            if position + 1 < entries.len() {
                self.retention_replays
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                replay_commits(&mut principal, std::slice::from_ref(entry))?;
            }
        }
        Ok(())
    }

    /// Store a verified rival `commit` and its blobs behind
    /// [`BRANCH_MANIFEST_PREFIX`] and list it. A rival that is the
    /// canonical commit or an already-kept branch is a no-op; the
    /// (`BRANCH_LIMIT`+1)th distinct rival is [`EngineError::BranchLimit`]
    /// and stores nothing.
    async fn keep_branch(
        &self,
        raw_blobs: &[&[u8]],
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
        {
            let kept = self.branches.lock().unwrap_or_else(|p| p.into_inner());
            let of_principal = kept
                .get(&commit.principal_id)
                .map_or(&[][..], Vec::as_slice);
            if of_principal
                .iter()
                .any(|b| b.tip == tip && b.sequence == commit.sequence)
            {
                return Ok(());
            }
            if of_principal.len() >= BRANCH_LIMIT {
                return Err(EngineError::BranchLimit);
            }
        }
        let branch = BranchTip {
            tip,
            pre: commit.pre.clone(),
            sequence: commit.sequence,
            canonical: false,
        };
        let principal_id = commit.principal_id.clone();
        self.store_manifest(
            raw_blobs,
            commit,
            BRANCH_MANIFEST_PREFIX,
            BRANCH_MANIFEST_KIND,
        )
        .await?;
        self.branches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(principal_id)
            .or_default()
            .push(branch);
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
            branches.extend(kept.iter().cloned());
        }
        branches.sort_by(|a, b| {
            (a.sequence, !a.canonical, &a.tip).cmp(&(b.sequence, !b.canonical, &b.tip))
        });
        Ok(branches)
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material from the first stored
    ///   commit's blobs.
    /// - If the principal is new, extracts key material from the first submitted commit's blobs.
    ///
    /// Both cases apply the identical genesis-discovery rule (see
    /// [`Self::genesis_from_raw_blobs`]) over their respective blob set: this system's wire
    /// convention embeds the genesis key on the bundle's `commit/create` cozy, not on whichever
    /// blob happens to be first -- a mutation-introducing cozy earlier in the same bundle (e.g. a
    /// `key/create` adding a second key) carries the *new* key in its own `"key"` field, never
    /// genesis.
    pub async fn resolve_genesis(
        &self,
        principal_id: &str,
        raw_blobs: &[&[u8]],
    ) -> Result<crate::Genesis, EngineError> {
        self.ensure_healed().await?;

        if let Some(stored_id) = self.stored_id(principal_id).await? {
            // Existing principal: its genesis is in its first stored commit.
            self.genesis_of_stored(&stored_id).await
        } else {
            // New principal — the caller's own submitted blobs are the first commit.
            Self::genesis_from_raw_blobs(raw_blobs)
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
        let mut blobs = Vec::with_capacity(first_commit.blob_hashes.len());
        for hash in &first_commit.blob_hashes {
            let data =
                self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!("blob {hash} not found in store"))
                })?;
            blobs.push(data);
        }
        Self::genesis_from_raw_blobs(&blobs)
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

    /// The stored principal for which `claimed` (labelled or bare) is the
    /// PG-to-be: the Principal Root it holds NOW, while it has no PG yet
    /// (SPEC §3.7.1: the PG is the PR before the `principal/create`
    /// commit). Before that commit no alias exists, so a client may push
    /// and read under the PG it is about to establish. The index only
    /// locates the candidate; replayed state decides, so a historical PR,
    /// or any PR once the PG exists, names nothing.
    ///
    /// A non-create commit pushed under the PG-to-be is accepted: it lands
    /// on the one principal, so no fork is possible (exercised by
    /// `principal_with_keys_before_create_is_pushable_under_its_pg`, whose
    /// commit 0 is a `key/create` pushed under the PG).
    async fn pending_pg_owner(&self, claimed: &str) -> Result<Option<String>, EngineError> {
        let Some((owner, sequence)) = self.locate_by_pr(claimed).await? else {
            return Ok(None);
        };
        // An established PG is settled from the index alone: no replay,
        // so naming a public current PR cannot amplify into history loads.
        if self.indexer.is_pg_established(&owner).await? {
            return Ok(None);
        }
        // Cheap filter before the replay: the claim must be the owner's
        // current PR, i.e. its latest commit.
        let Some(tip) = self.indexer.get_tip(&owner).await? else {
            return Ok(None);
        };
        if tip.commit_count.checked_sub(1) != Some(sequence) {
            return Ok(None);
        }
        let memo_key = (owner.clone(), tip.commit_count, claimed.to_string());
        if let Some(holds_claim) = self.pre_pg_owner.get(&memo_key) {
            return Ok(holds_claim.then_some(owner));
        }
        let genesis = self.genesis_of_stored(&owner).await?;
        let principal = self.replay_stored(&owner, genesis).await?;
        let holds_claim = principal.pg().is_none()
            && format_multihash_all(principal.pr().as_multihash())?
                .iter()
                .any(|v| v == claimed || bare_digest(v) == claimed);
        self.pre_pg_owner.insert(memo_key, holds_claim);
        Ok(holds_claim.then_some(owner))
    }

    /// The principal and commit sequence whose commit has `principal_id`
    /// (labelled or bare) as a Principal Root variant, as a locator only:
    /// the caller must verify against replayed state. Any other digest of
    /// a commit (id, SR, AR, CR) is not located, so it cannot trigger a
    /// replay.
    async fn locate_by_pr(&self, principal_id: &str) -> Result<Option<(String, u64)>, EngineError> {
        let candidates: Vec<String> = if principal_id.contains(':') {
            vec![principal_id.to_string()]
        } else {
            ID_LABELS
                .iter()
                .map(|label| format!("{label}:{principal_id}"))
                .collect()
        };
        for candidate in candidates {
            let Ok(digest) = candidate.parse::<cyphr::state::TaggedDigest>() else {
                continue;
            };
            let holders = self.indexer.resolve_digest_holders(&digest).await?;
            // A PR names one principal; if a digest has several holders,
            // take the first that is a Principal Root (canonical order).
            if let Some(entity) = holders
                .into_iter()
                .find(|h| h.entity_type == EntityType::Commit && h.principal_root)
            {
                if let (Some(principal), Some(sequence)) = (entity.principal_id, entity.sequence) {
                    return Ok(Some((principal, sequence)));
                }
            }
        }
        Ok(None)
    }

    /// The canonical (stored) spelling of `principal_id`, or `principal_id`
    /// unchanged if no such principal is stored. Read paths key on this so
    /// the bare and labelled spellings of one id reach one chain.
    pub async fn canonical_principal_id(&self, principal_id: &str) -> Result<String, EngineError> {
        self.ensure_healed().await?;
        let stored = match self.stored_id(principal_id).await? {
            Some(id) => Some(id),
            None => self.pending_pg_owner(principal_id).await?,
        };
        Ok(stored.unwrap_or_else(|| principal_id.to_string()))
    }

    /// Scan `blobs` (a single commit bundle, in wire order) for a `commit/create`-typed cozy
    /// carrying a `"key"` field -- this system's genesis-key carrier -- falling back to `blobs[0]`
    /// only if that scan finds nothing.
    fn genesis_from_raw_blobs<D: AsRef<[u8]>>(blobs: &[D]) -> Result<crate::Genesis, EngineError> {
        if blobs.is_empty() {
            return Err(EngineError::NotFound(
                "no blobs to resolve genesis from".into(),
            ));
        }

        for (idx, data) in blobs.iter().enumerate() {
            let data = data.as_ref();
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                let pay = value.get("pay");
                let typ = pay
                    .and_then(|p| p.get("typ"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                let has_key = value.get("key").is_some();
                tracing::debug!(
                    "genesis_from_raw_blobs: blob idx={}, typ={}, has_key={}",
                    idx,
                    typ,
                    has_key
                );
                if is_commit_create_typ(typ) && has_key {
                    tracing::debug!("genesis_from_raw_blobs: found genesis key in commit/create!");
                    return Self::genesis_from_blob(data);
                }
            }
        }

        tracing::debug!("genesis_from_raw_blobs: fallback to first blob");
        Self::genesis_from_blob(blobs[0].as_ref())
    }

    /// Extract an implicit genesis key from a raw coz blob's `"key"` field.
    fn genesis_from_blob(blob: &[u8]) -> Result<crate::Genesis, EngineError> {
        let value: serde_json::Value = serde_json::from_slice(blob)
            .map_err(|e| EngineError::MalformedBlob(format!("genesis blob: {e}")))?;

        let key_obj = value.get("key").ok_or_else(|| {
            EngineError::MalformedBlob("genesis blob must contain a 'key' field".into())
        })?;

        let ke = key_value_to_entry(key_obj).ok_or_else(|| {
            EngineError::MalformedBlob(
                "genesis blob 'key' missing required fields (alg, pub, tmb)".into(),
            )
        })?;

        let key = crate::import::key_entry_to_key(&ke)
            .map_err(|e| EngineError::MalformedBlob(format!("genesis key conversion: {e}")))?;

        Ok(crate::Genesis::Implicit(key))
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
    /// Rebuild trusts the engine-written manifests (the prefixed blobs),
    /// checks only that each names stored blobs and that its principal id
    /// is bound to its sequence-0 genesis carrier, and does not replay.
    /// The audit path is to replay each principal from its blobs
    /// ([`Self::rederive_roots`]) and compare with the rebuilt index; this
    /// method is the cheap recovery, not the audit.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch(&self) -> Result<usize, EngineError> {
        self.indexer.clear(&DeriveToken::new()).await?;
        self.rebuild_index_from_manifests().await
    }
}

/// The thumbprints that sign the transactions of `raw_blobs`, if every coz
/// of the bundle is signed by a key the principal has ever held and its
/// signature verifies under that key; `None` otherwise, or if the bundle
/// has no transaction. Reads no principal state: `genesis` and the keys the
/// stored `entries` introduced are the whole key history.
fn authenticated_signers(
    raw_blobs: &[&[u8]],
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
    for blob in raw_blobs {
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
        if crate::import::is_transaction_typ(&header.typ) {
            signers.push(header.tmb);
        }
    }
    (!signers.is_empty()).then_some(signers)
}

/// Whether `typ` is the protocol's `commit/create` (authority-qualified
/// suffix, SPEC 7.3), never a substring match: an application typ that
/// merely contains `/commit/create` is an ordinary coz.
fn is_commit_create_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::COMMIT_CREATE)
}

/// Whether `data` parses as the pre-keyspace manifest shape. Parsed, not
/// searched: JSON lets any member name be spelled with escapes.
fn is_legacy_manifest(data: &[u8]) -> bool {
    serde_json::from_slice::<CommitManifest>(data).is_ok_and(|m| m.kind == COMMIT_MANIFEST_KIND)
}

/// The members of a stored wire coz: exactly what the signature and the
/// protocol need (`pay`, `sig`, and a disclosed `key`). Coz allows
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
    // The unsigned `key` member is kept only where the protocol needs it:
    // on a key-introducing coz and on the `commit/create` genesis carrier,
    // and only once its `tmb` is checked to be the thumbprint of its `pub`.
    // Every other coz is stored without it and resolved by `tmb`, so a czd
    // names exactly one canonical blob: a replayer cannot attach a `key` of
    // its choosing to bytes that `/e/{czd}` then serves.
    let typ = canonical
        .get("pay")
        .and_then(|p| p.get("typ"))
        .and_then(|t| t.as_str());
    let pay_tmb = canonical
        .get("pay")
        .and_then(|p| p.get("tmb"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let introduces = typ.is_some_and(crate::import::is_key_introducing_typ);
    let carrier = typ.is_some_and(is_commit_create_typ);
    if let Some(key) = members.get("key").filter(|_| introduces || carrier) {
        let entry = key_value_to_entry(key)
            .ok_or_else(|| bad("'key' missing required fields (alg, pub, tmb)".into()))?;
        crate::import::key_entry_to_key(&entry).map_err(|e| match e {
            // e.g. `TmbMismatch`: a client-facing protocol refusal, not a
            // malformed blob (the status the sidecar check always gave).
            crate::import::LoadError::Protocol(p) => EngineError::Protocol(p),
            other => bad(format!("'key' is not a valid key: {other}")),
        })?;
        // A genesis carrier is signed by its own key, so its sidecar is the
        // signer's: a `commit/create` whose key is anyone else's carries a
        // relayer's attachment and keeps none. Only `alg`, `pub` and `tmb`
        // are kept: `tag` and `now` are unsigned labels, and the protocol
        // sets a key's first-seen time from the signed `pay.now` when it
        // applies the introducing coz.
        if introduces || pay_tmb.as_deref() == Some(entry.tmb.as_str()) {
            let mut key = serde_json::Map::new();
            key.insert("alg".into(), entry.alg.into());
            key.insert("pub".into(), entry.pub_key.into());
            key.insert("tmb".into(), entry.tmb.into());
            canonical.insert("key".into(), key.into());
        }
    }
    let mut canonical = serde_json::Value::Object(canonical);
    crate::import::canonicalize_value(&mut canonical);
    serde_json::to_vec(&canonical).map_err(|e| bad(format!("serialize: {e}")))
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

/// The id `genesis` derives (SPEC §3.1): its genesis-time Principal Root in
/// the algorithm-labelled `ALG:digest` form, the one canonical spelling
/// every storage and index key uses (for an implicit genesis the digest is
/// the genesis key's `tmb`).
///
/// # Errors
///
/// Returns the protocol error genesis construction raises (e.g. an empty
/// key set).
pub fn genesis_principal_id(genesis: &crate::Genesis) -> Result<String, EngineError> {
    let principal = match genesis {
        crate::Genesis::Implicit(key) => cyphr::Principal::implicit(key.clone())?,
        crate::Genesis::Explicit(keys) => cyphr::Principal::explicit(keys.clone())?,
    };
    Ok(principal.pr_tagged()?)
}

/// Extract a [`KeyEntry`] from a coz envelope's `"key"` JSON object.
///
/// Returns `None` if the object is missing required fields.
fn key_value_to_entry(key_obj: &serde_json::Value) -> Option<crate::KeyEntry> {
    let alg = key_obj.get("alg")?.as_str()?;
    let pub_key = key_obj.get("pub")?.as_str()?;
    let tmb = key_obj.get("tmb")?.as_str()?;
    let tag = key_obj
        .get("tag")
        .and_then(|t| t.as_str())
        .map(String::from);
    let now = key_obj.get("now").and_then(|n| n.as_i64());

    Some(crate::KeyEntry {
        alg: alg.to_string(),
        pub_key: pub_key.to_string(),
        tmb: tmb.to_string(),
        tag,
        now,
    })
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
