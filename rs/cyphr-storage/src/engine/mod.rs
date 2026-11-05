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
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
    /// BLAKE3 hash of this commit's durable [`CommitManifest`] blob.
    ///
    /// `None` for an action-only bundle (`submit_commit`'s action-only
    /// branch): no commit was formed, so there is no manifest to hash.
    pub manifest_hash: Option<Blake3Hash>,
}

/// Discriminator embedded in every [`CommitManifest`], distinguishing it
/// from an ordinary coz blob during a full blob-store scan.
const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// A durable, content-addressed record of one [`ingest_commit`](StorageEngine::ingest_commit)
/// call's fully-resolved [`IndexableCommit`] — written to the blob store
/// (never only to the index) so a commit's intra-commit transaction order
/// and derived state digests survive independently of the index.
///
/// This is the signal that lets an index rebuild ([`StorageEngine::rebuild_index_from_manifests`])
/// re-derive a commit directly, without the permutation search
/// that reconstructing same-timestamp mutation order would need. Per root `AGENTS.md` invariant I1,
/// the manifest is itself blob-store content, not a new index-only source of truth.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CommitManifest {
    kind: String,
    commit: IndexableCommit,
}

/// Produces a fresh, independent `S` instance for a `Principal`'s Commit
/// Tree, given that principal's `principal_id` as a scoping identifier — see
/// [`StorageEngine`]'s `storage_factory` field docs.
type StorageFactory<S> = Box<dyn Fn(&str) -> Result<S, String> + Send + Sync>;

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
        let entity = self.indexer.resolve_digest(anchor).await?.ok_or_else(|| {
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
        let manifest_bytes = serde_json::to_vec(&manifest)
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
        let (commit, manifest_hash) = self.store_blobs_and_manifest(blobs, commit).await?;
        let blob_hashes = commit.blob_hashes.clone();

        self.indexer
            .index_commit(&commit, &DeriveToken::new())
            .await?;

        Ok(IngestResult {
            blob_hashes,
            manifest_hash: Some(manifest_hash),
        })
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently.
    ///
    /// Closes the ingest crash window: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent `indexer.index_commit` call
    /// leaves a manifest durably stored with no index entry yet -- calling
    /// this after such a crash (e.g. on the next engine open) completes
    /// the index write directly from the manifest's already-resolved
    /// `IndexableCommit`, with no permutation search needed since the
    /// manifest already carries the resolved order and digests.
    ///
    /// Also serves full index reconstruction: since every manifest is
    /// itself blob-store content (root `AGENTS.md` invariant I1), clearing
    /// the index entirely and calling this rebuilds every manifest-backed
    /// commit from the blob store alone.
    ///
    /// `indexer.index_commit` is documented idempotent (a no-op for a
    /// `commit_id` already indexed), so calling this is always safe,
    /// whether or not any manifest is actually pending.
    ///
    /// Returns the number of manifests found (indexed or already-indexed).
    ///
    /// Manifests are indexed in ascending `commit.sequence` order (not the
    /// blob store's own, unspecified iteration order): each `index_commit`
    /// call unconditionally overwrites the indexer's per-principal tip
    /// (last write wins, by design -- see `Indexer::index_commit`), so for a
    /// principal with more than one commit, tip correctness depends on the
    /// truly-latest commit being applied last. The blob store's iteration
    /// order is not guaranteed to correlate with sequence (`MemoryBlobStore`
    /// is a `HashMap`, genuinely unordered), so sorting here is what makes
    /// that guarantee hold rather than merely happening to hold by luck of
    /// hash placement.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_manifests(&self) -> Result<usize, EngineError> {
        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;

        let mut manifests = Vec::new();
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
            let Ok(manifest) = serde_json::from_slice::<CommitManifest>(&data) else {
                continue;
            };
            if manifest.kind != COMMIT_MANIFEST_KIND {
                continue;
            }
            manifests.push(manifest);
        }

        manifests.sort_by_key(|m| m.commit.sequence);

        let mut count = 0;
        for manifest in manifests {
            self.indexer
                .index_commit(&manifest.commit, &DeriveToken::new())
                .await?;
            count += 1;
        }

        Ok(count)
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
        use crate::CommitEntry;
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
                String::new(), // ar — unused during replay
                String::new(), // sr — unused during replay
                commit_ref.pr.clone(),
            ));
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
        let mut principal = self.load_principal(principal_id, genesis).await?;

        // 3. Determine the next sequence number.
        let next_seq = self
            .indexer
            .get_tip(principal_id)
            .await?
            .map(|tip| tip.commit_count)
            .unwrap_or(0);

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
            if unproven_alias && !pr.iter().any(|v| v == claimed || bare_digest(v) == claimed) {
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
            Ok(IngestResult {
                blob_hashes,
                manifest_hash: None,
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
        let genesis = self.genesis_of_stored(&owner).await?;
        let principal = self.replay_stored(&owner, genesis).await?;
        let holds_claim = principal.pg().is_none()
            && format_multihash_all(principal.pr().as_multihash())?
                .iter()
                .any(|v| v == claimed || bare_digest(v) == claimed);
        Ok(holds_claim.then_some(owner))
    }

    /// The principal and commit sequence whose commit has `principal_id`
    /// (labelled or bare) as a digest variant, as a locator only: the
    /// caller must verify against replayed state.
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
            if let Some(entity) = self.indexer.resolve_digest(&digest).await? {
                if entity.entity_type == EntityType::Commit {
                    if let (Some(principal), Some(sequence)) =
                        (entity.principal_id, entity.sequence)
                    {
                        return Ok(Some((principal, sequence)));
                    }
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
                if typ.contains("/commit/create") && has_key {
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
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch(&self) -> Result<usize, EngineError> {
        self.indexer.clear(&DeriveToken::new()).await?;
        self.rebuild_index_from_manifests().await
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
