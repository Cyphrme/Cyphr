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
    pub sr: String,
    pub ar: String,
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
    /// State Root after the commit.
    pub sr: String,
    /// Auth Root after the commit.
    pub ar: String,
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
            sr: first(&commit.srs),
            ar: first(&commit.ars),
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

        let sr_obj = principal
            .sr()
            .ok_or_else(|| EngineError::InvalidInput("missing SR".into()))?;
        let sr = format_multihash_all(sr_obj.as_multihash())?
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::InvalidInput("empty SR".into()))?;

        let ar = format_multihash_all(principal.auth_root().as_multihash())?
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::InvalidInput("empty AR".into()))?;

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
        mut commit: IndexableCommit,
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
            kind: COMMIT_MANIFEST_KIND.to_string(),
            commit: commit.clone(),
        };
        let mut manifest_bytes = COMMIT_MANIFEST_PREFIX.to_vec();
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
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
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

        quarantined.sort_by_key(|q| *q.manifest.as_bytes());
        Ok(RebuildReport {
            indexed,
            quarantined,
        })
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
            let genesis = match Self::genesis_from_blob(carrier) {
                Ok(genesis) => genesis,
                Err(e) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("genesis not derivable from its blobs: {e}"),
                    );
                    continue;
                },
            };
            match genesis_principal_id(&genesis) {
                Ok(derived) if derived == principal_id => {},
                // Filed under its PG-to-be: the key must be a Principal
                // Root the first commit really yields, so that one commit
                // is replayed (not the chain).
                Ok(derived) => {
                    let yields_id = self
                        .first_commit_prs(genesis, principal_id, &blobs)
                        .is_ok_and(|prs| prs.iter().any(|pr| pr == principal_id));
                    if !yields_id {
                        unbound.insert(
                            principal_id.to_string(),
                            format!(
                                "its blobs derive principal {derived}, and its first commit does \
                                 not yield this id as a Principal Root"
                            ),
                        );
                    }
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

    /// The Principal Root variants after replaying `blobs` (a principal's
    /// sequence-0 commit) from `genesis`.
    fn first_commit_prs(
        &self,
        genesis: crate::Genesis,
        principal_id: &str,
        blobs: &[Vec<u8>],
    ) -> Result<Vec<String>, EngineError> {
        let storage = (self.storage_factory)(principal_id).map_err(EngineError::Storage)?;
        let mut principal = match genesis {
            crate::Genesis::Implicit(key) => {
                cyphr::Principal::implicit_with_storage(key, storage)?
            },
            crate::Genesis::Explicit(keys) => {
                cyphr::Principal::explicit_with_storage(keys, storage)?
            },
        };
        let entry = replay_entry(blobs, "", "")?;
        crate::import::replay_commits(&mut principal, &[entry])?;
        format_multihash_all(principal.pr().as_multihash())
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
        use crate::import::replay_commits;

        // 1. Construct the principal from genesis (no commits yet), backed
        // by a fresh storage instance from this engine's factory.
        let mut principal = match genesis {
            crate::Genesis::Implicit(key) => {
                let storage = (self.storage_factory)(principal_id).map_err(EngineError::Storage)?;
                cyphr::Principal::implicit_with_storage(key, storage)?
            },
            crate::Genesis::Explicit(keys) => {
                if keys.is_empty() {
                    return Err(EngineError::InvalidInput(
                        "genesis requires at least one key".into(),
                    ));
                }
                let storage = (self.storage_factory)(principal_id).map_err(EngineError::Storage)?;
                cyphr::Principal::explicit_with_storage(keys, storage)?
            },
        };

        // 2. Get the full commit chain from the indexer.
        let chain = self
            .indexer
            .get_commit_chain(principal_id, None, None)
            .await?;
        if chain.is_empty() {
            return Ok(principal);
        }

        // 3. For each CommitRef, fetch blobs and build a CommitEntry.
        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
            for hash in &commit_ref.blob_hashes {
                blobs.push(self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "blob {hash} referenced by index commit {} missing",
                        commit_ref.commit_id
                    ))
                })?);
            }
            commit_entries.push(replay_entry(&blobs, &commit_ref.commit_id, &commit_ref.pr)?);
        }

        // 4. Replay commits onto the principal.
        replay_commits(&mut principal, &commit_entries)?;

        Ok(principal)
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
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        use crate::import::{is_key_introducing_typ, is_transaction_typ};

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
        let genesis_id = genesis_principal_id(&genesis)?;
        let claimed = principal_id;
        // A spelling other than the genesis-derived id is honoured only
        // when it already resolves to this stored principal, or (a new
        // principal) when its own first commit yields that Principal Root
        // (checked once the commit is applied, below).
        let alias_claim = claimed != genesis_id && claimed != bare_digest(&genesis_id);
        if let Some(stored_id) = stored.as_deref() {
            // A principal stored under its PG-to-be (not the bare genesis
            // key, which sibling principals can share) is still this
            // genesis's principal only if its own first commit derives it.
            let bound = stored_id == genesis_id
                || genesis_principal_id(&self.genesis_of_stored(stored_id).await?)? == genesis_id;
            if !bound {
                return Err(EngineError::InvalidInput(format!(
                    "principal_id is not the genesis-derived id: {claimed}"
                )));
            }
        }
        let unproven_alias = alias_claim && stored.is_none();
        // The storage key (SPEC 5.1 line 764: principals sharing a key
        // differ by nonce, so the bare key is not an identity): an existing
        // principal keeps its key; a new one whose first push names its
        // PG-to-be is filed under that PR (the PG once `principal/create`
        // lands), and any other new principal under its genesis state root.
        let canonical = match &stored {
            Some(stored_id) => stored_id.clone(),
            None if alias_claim => labelled_claim(claimed, &genesis_id),
            None => genesis_id.clone(),
        };
        let principal_id = canonical.as_str();

        // Serialize the whole sequence-resolution-through-ingest critical
        // section per principal_id: two concurrent callers for the SAME
        // principal must never both resolve `next_seq` before either has
        // ingested. Held for the remainder of this function; a concurrent
        // caller for a DIFFERENT principal_id never contends on this lock.
        let lock = self.principal_lock(principal_id);
        let _serialize_writes = lock.lock().await;

        // 2. Load (or construct) the principal from existing state.
        let mut principal = self.load_principal(principal_id, genesis).await?;

        // 3. Determine the next sequence number.
        let tip_before = self.indexer.get_tip(principal_id).await?;
        let next_seq = tip_before.as_ref().map_or(0, |tip| tip.commit_count);

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
                let ar = format_multihash_all(commit.auth_root().as_multihash())?;
                let sr = format_multihash_all(commit.sr().as_multihash())?;
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
            let names_pg_to_be = principal.pg().is_none() && pr.iter().any(|v| v == principal_id);
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

            self.ingest_commit(raw_blobs, commit).await
        } else {
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
            Ok(IngestResult {
                principal_id: principal_id.to_string(),
                blob_hashes,
                manifest_hash: None,
                tip,
            })
        }
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
        let located = self.locate_by_pr(claimed).await?;
        let Some((owner, _)) = located.first().cloned() else {
            return Ok(None);
        };
        if located.iter().any(|(other, _)| *other != owner) {
            return Err(EngineError::Ambiguous(format!(
                "Principal Root {claimed} is held by several principals; address one by its PG"
            )));
        }
        // The same principal may hold a PR at several positions; only its
        // latest commit can be its current PR.
        let sequence = located.iter().map(|(_, seq)| *seq).max().unwrap_or_default();
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

    /// Every principal and commit sequence whose commit has `principal_id`
    /// (labelled or bare) as a Principal Root variant, as a locator only:
    /// the caller must verify against replayed state. Any other digest of
    /// a commit (id, SR, AR, CR) is not located, so it cannot trigger a
    /// replay. All holders are returned, never one of them: a PR shared by
    /// several principals is the caller's ambiguity to refuse.
    async fn locate_by_pr(&self, principal_id: &str) -> Result<Vec<(String, u64)>, EngineError> {
        let candidates: Vec<String> = if principal_id.contains(':') {
            vec![principal_id.to_string()]
        } else {
            ID_LABELS
                .iter()
                .map(|label| format!("{label}:{principal_id}"))
                .collect()
        };
        let mut located = Vec::new();
        for candidate in candidates {
            let Ok(digest) = candidate.parse::<cyphr::state::TaggedDigest>() else {
                continue;
            };
            let holders = self.indexer.resolve_digest_holders(&digest).await?;
            for entity in holders
                .into_iter()
                .filter(|h| h.entity_type == EntityType::Commit && h.principal_root)
            {
                if let (Some(principal), Some(sequence)) = (entity.principal_id, entity.sequence) {
                    located.push((principal, sequence));
                }
            }
        }
        located.sort_unstable();
        located.dedup();
        Ok(located)
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

/// Whether `typ` is the protocol's `commit/create` (authority-qualified
/// suffix, SPEC 7.3), never a substring match: an application typ that
/// merely contains `/commit/create` is an ordinary coz.
fn is_commit_create_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::COMMIT_CREATE)
}

/// The [`CommitEntry`](crate::CommitEntry) replay reads from a stored
/// commit's `blobs`: the cozies plus the key material their envelopes
/// carry. State digest fields are inert during replay.
fn replay_entry(
    blobs: &[Vec<u8>],
    commit_id: &str,
    pr: &str,
) -> Result<crate::CommitEntry, EngineError> {
    let mut cozies = Vec::with_capacity(blobs.len());
    let mut keys = Vec::new();
    for data in blobs {
        let value: serde_json::Value = serde_json::from_slice(data).map_err(|e| {
            EngineError::MalformedBlob(format!("commit {commit_id} blob is not valid JSON: {e}"))
        })?;
        // Key material of a key-introducing transaction.
        if let Some(ke) = value.get("key").and_then(key_value_to_entry) {
            keys.push(ke);
        }
        cozies.push(value);
    }
    Ok(crate::CommitEntry::new(
        cozies,
        keys,
        commit_id.to_string(),
        String::new(),
        String::new(),
        pr.to_string(),
    ))
}

/// The labelled spelling of a claimed id: as given when already labelled,
/// else bare digest under the label of `genesis_id` (the same hash family
/// as the genesis it is claimed for).
fn labelled_claim(claimed: &str, genesis_id: &str) -> String {
    if claimed.contains(':') {
        return claimed.to_string();
    }
    let label = genesis_id.split_once(':').map_or("", |(label, _)| label);
    format!("{label}:{claimed}")
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

#[cfg(test)]
mod tests;
