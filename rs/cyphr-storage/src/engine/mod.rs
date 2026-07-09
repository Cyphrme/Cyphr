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
use crate::index::{CommitRef, IndexableCommit, IndexableCoz, Indexer, TipState};

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

/// Metadata for ingesting a pre-validated commit.
///
/// The engine does not validate protocol-level signatures or state
/// transitions — that responsibility belongs to the protocol layer
/// (Phase 3b). This struct carries the metadata needed to store
/// blobs and build an index entry.
#[derive(Clone, Debug)]
struct ParsedCozInfo {
    hash: Blake3Hash,
    pay_json: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
    typ: String,
    pre: Option<String>,
    tmb: String,
    now: i64,
    alg: String,
    new_key: Option<cyphr::Key>,
    key_info: Option<crate::PublicKeyInfo>,
}

fn map_coz_info(parsed: &ParsedCozInfo, active_algs: &[cyphr::state::HashAlg]) -> IndexableCoz {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let source_alg =
        cyphr::state::hash_alg_from_str(&parsed.alg).unwrap_or(cyphr::state::HashAlg::Sha256);
    let tagged = cyphr::state::TaggedCzd::new(&parsed.czd, source_alg);

    let primary_alg = active_algs.first().copied().unwrap_or(source_alg);
    let converted = tagged.convert_to(primary_alg);
    let primary_czd = format!(
        "{primary_alg}:{}",
        Base64UrlUnpadded::encode_string(&converted)
    );

    let payload = serde_json::from_slice::<serde_json::Value>(&parsed.pay_json)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok());

    IndexableCoz {
        blob_hash: parsed.hash,
        czd: primary_czd,
        typ: parsed.typ.clone(),
        tmb: parsed.tmb.clone(),
        alg: parsed.alg.clone(),
        now: parsed.now,
        payload,
    }
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
/// [`StorageEngine::reindex`] otherwise needs to reconstruct same-timestamp
/// mutation order. Per root `AGENTS.md` invariant I1, the manifest is
/// itself blob-store content, not a new index-only source of truth.
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
}

impl<B: BlobStore, I: Indexer> StorageEngine<B, I, cyphr::eml::MemoryStorage> {
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
        }
    }
}

impl<B: BlobStore, I: Indexer, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
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
    // Read path
    // ========================================================================

    /// Retrieve the current tip state for a principal.
    ///
    /// Delegates directly to the indexer.
    #[tracing::instrument(skip(self))]
    pub async fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, EngineError> {
        Ok(self.indexer.get_tip(principal_id).await?)
    }

    /// Retrieve a patch: commit chain metadata joined with blob content.
    ///
    /// For each commit in the range, fetches the raw blob bytes from
    /// the blob store. This is the engine's primary coordination value —
    /// neither trait can serve this alone.
    #[tracing::instrument(skip(self))]
    pub async fn get_patch(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        let chain = self
            .indexer
            .get_commit_chain(principal_id, from, to)
            .await?;

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "blob {hash} referenced by commit {} not found in store",
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

    /// Resolve a tagged digest to its raw blob content.
    ///
    /// Two-step: resolve digest → entity ref (index), then
    /// fetch blob content (blob store).
    #[tracing::instrument(skip(self))]
    pub async fn get_entity(&self, digest: &TaggedDigest) -> Result<Option<Vec<u8>>, EngineError> {
        let entity = match self.indexer.resolve_digest(digest).await? {
            Some(e) => e,
            None => return Ok(None),
        };

        let data = self.blob_store.get(&entity.blob_hash).await?;
        Ok(data)
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
    /// 4. Calls the indexer to record relational data
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

        self.indexer.index_commit(&commit).await?;

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
            self.indexer.index_commit(&manifest.commit).await?;
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
                        "blob {hash} referenced by commit {} missing",
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
    /// * `principal_id` — Tagged-digest identifier for this principal.
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

        if raw_blobs.is_empty() {
            return Err(EngineError::InvalidInput("empty commit bundle".into()));
        }

        // Serialize the whole sequence-resolution-through-ingest critical
        // section per principal_id: two concurrent callers for the SAME
        // principal must never both resolve `next_seq` before either has
        // ingested. Held for the remainder of this function; a concurrent
        // caller for a DIFFERENT principal_id never contends on this lock.
        let lock = self.principal_lock(principal_id);
        let _serialize_writes = lock.lock().await;

        // 1. Resolve genesis.
        let genesis = match genesis {
            Some(g) => g,
            None => self.resolve_genesis(principal_id, raw_blobs).await?,
        };

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
            let typ = pay.get("typ").and_then(|t| t.as_str()).unwrap_or("");
            if is_transaction_typ(typ) {
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

            let typ = pay
                .get("typ")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

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

            let tmb = pay
                .get("tmb")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let now = pay.get("now").and_then(|n| n.as_i64()).unwrap_or(0);
            let pre = pay
                .get("pre")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string());

            let mut key_info = None;
            let new_key = if is_key_introducing_typ(&typ) {
                value.get("key").and_then(|k| {
                    let ke = key_value_to_entry(k)?;
                    key_info = Some(crate::PublicKeyInfo {
                        thumbprint: ke.tmb.clone(),
                        algorithm: ke.alg.clone(),
                        public_key: ke.pub_key.clone(),
                    });
                    crate::import::key_entry_to_key(&ke).ok()
                })
            } else {
                None
            };

            Ok(ParsedCozInfo {
                hash: Blake3Hash::from_bytes([0; 32]), // populated on ingest
                pay_json,
                sig,
                czd,
                typ,
                pre,
                tmb,
                now,
                alg: alg_str,
                new_key,
                key_info,
            })
        };

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
            let commit_pre = if next_seq == 0 {
                None
            } else {
                format_multihash_all(principal.pr().as_multihash())?
                    .first()
                    .cloned()
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
        // Check if the principal already exists.
        let chain = self
            .indexer
            .get_commit_chain(principal_id, Some(0), Some(0))
            .await?;

        if let Some(first_commit) = chain.first() {
            // Existing principal — fetch the first stored commit's blobs from the blob store.
            let mut blobs = Vec::with_capacity(first_commit.blob_hashes.len());
            for hash in &first_commit.blob_hashes {
                let data = self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!("blob {hash} not found in store"))
                })?;
                blobs.push(data);
            }
            Self::genesis_from_raw_blobs(&blobs)
        } else {
            // New principal — the caller's own submitted blobs are the first commit.
            Self::genesis_from_raw_blobs(raw_blobs)
        }
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

    /// Reindex the relational database from durable content in the BlobStore.
    ///
    /// Implements recovery verification/convergance [recovery-reindex] and
    /// [recovery-convergence]. Two independent recovery paths run in the same
    /// pass:
    ///
    /// - Raw blobs with no manifest (legacy content, or content seeded directly into the blob store
    ///   bypassing `ingest_commit`) are scanned first and, where they resolve to a genesis
    ///   bootstrap or a deterministically-orderable commit, indexed.
    /// - Manifest-backed commits -- anything ingested via [`Self::ingest_commit`]/`submit_commit`
    ///   -- are recovered last, directly from their [`CommitManifest`] via
    ///   [`Self::rebuild_index_from_manifests`]: their exact ingest-time order and derived digests
    ///   are read, never searched for. Running this pass last makes a manifest-backed principal's
    ///   real tip always win over any raw content indexed above for the same `principal_id`.
    #[tracing::instrument(skip(self, keys))]
    pub async fn reindex(&self, keys: &[cyphr::Key], total_check: bool) -> Result<(), EngineError> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        use crate::import::is_transaction_typ;

        if total_check {
            self.indexer.clear().await?;
        }

        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;
        tracing::debug!("reindex: found {} blobs in store", hashes.len());

        // Blobs already covered by a durable CommitManifest must never be
        // reconstructed from raw content: their exact ingest-time order and
        // derived digests are authoritative via `rebuild_index_from_manifests`
        // (run last, below), not the deterministic-but-unverified sort order
        // raw recovery falls back to. Detected unconditionally (not gated on
        // `total_check`), since a manifest's own referenced blobs would
        // otherwise still be swept into a `total_check` full raw rescan.
        //
        // Also tally each principal's manifest-backed commit count: a
        // durable indexer backend (e.g. SQL) enforces a real uniqueness
        // constraint on (principal_id, sequence), so a raw-bootstrapped
        // genesis (below) must start numbering *after* any manifest-backed
        // commits already known for that same principal_id, never at a
        // sequence a manifest-backed commit will also occupy.
        let mut manifested_hashes = std::collections::HashSet::new();
        let mut manifest_commit_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for hash in &hashes {
            let Some(data) = self.blob_store.get(hash).await? else {
                continue;
            };
            let Ok(manifest) = serde_json::from_slice::<CommitManifest>(&data) else {
                continue;
            };
            if manifest.kind != COMMIT_MANIFEST_KIND {
                continue;
            }
            manifested_hashes.insert(*hash);
            manifested_hashes.extend(manifest.commit.blob_hashes.iter().copied());
            let count = manifest_commit_counts
                .entry(manifest.commit.principal_id.clone())
                .or_insert(0);
            *count = (*count).max(manifest.commit.sequence + 1);
        }

        let mut cozies = Vec::new();
        for hash in hashes {
            if manifested_hashes.contains(&hash) {
                continue;
            }
            if !total_check && self.indexer.is_blob_indexed(&hash).await? {
                continue;
            }

            let data = match self.blob_store.get(&hash).await? {
                Some(d) => d,
                None => continue,
            };

            #[derive(serde::Deserialize)]
            struct CozExtractor<'a> {
                #[serde(borrow)]
                pay: &'a serde_json::value::RawValue,
                sig: String,
                key: Option<serde_json::Value>,
            }

            let ext: CozExtractor = match serde_json::from_slice(&data) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(
                        "reindex: CozExtractor deserialize failed: {:?}, data = '{}'",
                        e,
                        String::from_utf8_lossy(&data)
                    );
                    continue;
                },
            };

            let sig = match Base64UrlUnpadded::decode_vec(&ext.sig) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "reindex: base64 decode of sig '{}' failed: {:?}",
                        ext.sig,
                        e
                    );
                    continue;
                },
            };

            let pay_json = ext.pay.get().as_bytes().to_vec();

            #[derive(serde::Deserialize)]
            struct PayFields {
                typ: String,
                pre: Option<String>,
                tmb: String,
                now: i64,
                alg: String,
            }

            let pay: PayFields = match serde_json::from_str(ext.pay.get()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        "reindex: PayFields deserialize failed: {:?}, pay = '{}'",
                        e,
                        ext.pay.get()
                    );
                    continue;
                },
            };

            let mut key_info = None;
            let new_key = if let Some(k) = &ext.key {
                if let Some(ke) = key_value_to_entry(k) {
                    key_info = Some(crate::PublicKeyInfo {
                        thumbprint: ke.tmb.clone(),
                        algorithm: ke.alg.clone(),
                        public_key: ke.pub_key.clone(),
                    });
                    crate::import::key_entry_to_key(&ke).ok()
                } else {
                    None
                }
            } else {
                None
            };

            let czd = cyphr::compute_czd(&pay_json, &sig, &pay.alg).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {hash}: czd computation failed"))
            })?;

            cozies.push(ParsedCozInfo {
                hash,
                pay_json,
                sig,
                czd,
                typ: pay.typ,
                pre: pay.pre,
                tmb: pay.tmb,
                now: pay.now,
                alg: pay.alg,
                new_key,
                key_info,
            });
        }

        tracing::debug!("total cozies parsed: {}", cozies.len());

        // Separate transactions and actions
        let (mut tx_cozies, action_cozies): (Vec<_>, Vec<_>) =
            cozies.into_iter().partition(|c| is_transaction_typ(&c.typ));

        tracing::debug!(
            "tx_cozies count: {}, action_cozies count: {}",
            tx_cozies.len(),
            action_cozies.len()
        );

        let mut bootstrapped = Vec::new();

        // Note: principals already fully indexed via manifest recovery
        // (above) need no further bootstrapping here -- there is no
        // remaining raw, non-manifest content for them to append, since
        // every commit reaching this store through `ingest_commit`/
        // `submit_commit` durably retains a manifest. Only genuinely
        // un-manifested raw content (steps 1 and 2 below) needs a fresh
        // `Principal` constructed to process it.

        // 1. Bootstrap from raw, non-manifest genesis markers: a standalone
        // coz whose `pre` is present AND explicitly empty. This is never true
        // for an ordinary mutation cozy, which omits `pre` entirely
        // (deserializing to `None`) now that the field was dropped from every
        // mutation, not just genesis ones -- only a deliberately-marked
        // legacy/synthetic genesis coz sets it to `Some("")`.
        // Exclude finalizer commit/create cozies from being consumed as mock genesis cozies
        let mut mock_genesis_cozies = Vec::new();
        for c in &tx_cozies {
            if !c.typ.contains("/commit/create") && c.pre.as_deref() == Some("") {
                if let Some(key) = &c.new_key {
                    mock_genesis_cozies.push((c.clone(), key.clone()));
                }
            }
        }

        // Remove mock genesis cozies from tx_cozies
        tx_cozies.retain(|c| !mock_genesis_cozies.iter().any(|(m, _)| m.hash == c.hash));

        for (mock_coz, key) in mock_genesis_cozies {
            let principal_id = implicit_genesis_principal_id(&key)?;
            let storage = (self.storage_factory)(&principal_id).map_err(EngineError::Storage)?;
            let principal = cyphr::Principal::implicit_with_storage(key, storage)?;

            // Start numbering after any manifest-backed commits this
            // principal_id already has (see the manifest pre-scan above) --
            // never at a sequence one of them will also occupy.
            let mut sequence: u64 = manifest_commit_counts
                .get(&principal_id)
                .copied()
                .unwrap_or(0);

            // Index the mock genesis cozy at the next free sequence.
            let genesis_commit_ids = format_multihash_all(principal.pr().as_multihash())?;
            let genesis_prs = format_multihash_all(principal.pr().as_multihash())?;
            // `implicit_with_storage` (two lines above) unconditionally sets
            // `sr: Some(sr)` -- a freshly constructed implicit principal
            // always has an SR, never None.
            let genesis_srs = format_multihash_all(principal.sr().unwrap().as_multihash())?;
            let genesis_ars = format_multihash_all(principal.auth_root().as_multihash())?;

            let mut genesis_keys = Vec::new();
            if let Some(info) = &mock_coz.key_info {
                genesis_keys.push(info.clone());
            }

            let genesis_indexable = IndexableCommit {
                principal_id: principal_id.clone(),
                commit_ids: genesis_commit_ids,
                sequence,
                pre: None,
                prs: genesis_prs,
                srs: genesis_srs,
                ars: genesis_ars,
                // No CR at genesis: PR = SR until the first real commit
                // populates the EML log.
                crs: Vec::new(),
                blob_hashes: vec![mock_coz.hash],
                cozies: vec![map_coz_info(&mock_coz, &principal.active_algs())],
                timestamp: mock_coz.now,
                keys: genesis_keys,
            };
            self.indexer.index_commit(&genesis_indexable).await?;
            sequence += 1;

            bootstrapped.push((principal, principal_id, sequence));
        }

        // 2. Bootstrap explicitly-supplied genesis keys (e.g. loaded from a
        // keystore at startup, per `cyphr-cli`'s parse_store). Trusted
        // directly rather than filtered by any in-band cozy signal: since `pre`
        // was removed from every ordinary mutation cozy, no reliable
        // per-cozy marker distinguishes a genesis key/create from a later
        // one, so the caller-supplied candidate is the only signal left.
        // Skips any key whose principal is already bootstrapped above.
        for key in keys {
            let principal_id = implicit_genesis_principal_id(key)?;
            if bootstrapped.iter().any(|(_, pid, _)| pid == &principal_id) {
                continue;
            }
            let storage = (self.storage_factory)(&principal_id).map_err(EngineError::Storage)?;
            let principal = cyphr::Principal::implicit_with_storage(key.clone(), storage)?;
            let sequence = manifest_commit_counts
                .get(&principal_id)
                .copied()
                .unwrap_or(0);
            bootstrapped.push((principal, principal_id, sequence));
        }

        // Recombine remaining transactions and actions into a single chronological pool.
        let mut pool = tx_cozies;
        pool.extend(action_cozies);

        // Sort pool by timestamp to facilitate sequential application.
        // For cozies with the same timestamp, ensure actions come first, then mutation
        // transactions, then finalizer commit/create cozies last.
        // If they are in the same category, use lexical byte order of their czd as the tie-breaker.
        // This is the single, deterministic order applied to same-timestamp
        // mutations below -- no search over alternate orderings.
        pool.sort_by(|a, b| match a.now.cmp(&b.now) {
            std::cmp::Ordering::Equal => {
                let a_is_commit = a.typ.contains("/commit/create");
                let b_is_commit = b.typ.contains("/commit/create");
                if a_is_commit != b_is_commit {
                    a_is_commit.cmp(&b_is_commit)
                } else {
                    let a_is_tx = is_transaction_typ(&a.typ);
                    let b_is_tx = is_transaction_typ(&b.typ);
                    if a_is_tx != b_is_tx {
                        b_is_tx.cmp(&a_is_tx)
                    } else {
                        a.czd.as_bytes().cmp(b.czd.as_bytes())
                    }
                }
            },
            other => other,
        });

        for (mut principal, principal_id, mut sequence) in bootstrapped {
            loop {
                let mut commit_blobs = Vec::new();
                let mut commit_cozies = Vec::new();

                let mut first_tx_idx = None;
                for (idx, coz) in pool.iter().enumerate() {
                    if is_transaction_typ(&coz.typ) {
                        first_tx_idx = Some(idx);
                        break;
                    }
                }

                let Some(tx_start_idx) = first_tx_idx else {
                    break;
                };

                // 1.1 Apply all pre-actions before the first transaction.
                for coz in pool.iter().take(tx_start_idx) {
                    let tmb_bytes = match Base64UrlUnpadded::decode_vec(&coz.tmb) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                    if principal.is_key_active(&signer_tmb) {
                        let alg = &coz.alg;
                        let czd = match cyphr::compute_czd(&coz.pay_json, &coz.sig, alg) {
                            Some(c) => c,
                            None => continue,
                        };

                        let res = principal.verify_and_record_action(
                            &coz.pay_json,
                            &coz.sig,
                            czd.clone(),
                        );
                        tracing::debug!(
                            "reindex pre-action: typ={}, now={}, res={:?}",
                            coz.typ,
                            coz.now,
                            res
                        );
                        if res.is_ok() {
                            commit_blobs.push(coz.hash);
                            commit_cozies.push(coz.clone());
                        }
                    }
                }

                // 1.2 Gather mutation transactions and finalizers for the
                // current commit. `mutations` is already in the pool's
                // single deterministic sorted order (timestamp, category,
                // then lexical czd tie-break) -- applied directly below,
                // with no search over alternate orderings.
                let target_time = pool[tx_start_idx].now;

                let mutations: Vec<_> = pool
                    .iter()
                    .filter(|c| {
                        c.now == target_time
                            && is_transaction_typ(&c.typ)
                            && !c.typ.contains("/commit/create")
                    })
                    .cloned()
                    .collect();

                let finalizers: Vec<_> = pool
                    .iter()
                    .filter(|c| c.now == target_time && c.typ.contains("/commit/create"))
                    .cloned()
                    .collect();

                if finalizers.is_empty() {
                    // No completing finalizer at this timestamp: an
                    // incomplete/crashed commit, not an error -- its raw
                    // content stays harmlessly unindexed until a finalizer
                    // arrives.
                    break;
                }

                let mut matched_combination = None;

                for finalizer_coz in &finalizers {
                    let alg = &finalizer_coz.alg;
                    let finalizer_czd = match cyphr::compute_czd(
                        &finalizer_coz.pay_json,
                        &finalizer_coz.sig,
                        alg,
                    ) {
                        Some(c) => c,
                        None => continue,
                    };

                    let claimed_arrow = if let Ok(value) =
                        serde_json::from_slice::<serde_json::Value>(&finalizer_coz.pay_json)
                    {
                        value
                            .get("arrow")
                            .and_then(|v| v.as_str())
                            .and_then(|arrow_val| {
                                arrow_val
                                    .parse::<cyphr::state::TaggedDigest>()
                                    .ok()
                                    .and_then(|tagged| {
                                        cyphr::multihash::MultihashDigest::from_single(
                                            tagged.alg(),
                                            tagged.as_bytes().to_vec(),
                                        )
                                        .ok()
                                    })
                            })
                    } else {
                        None
                    };

                    let claimed_arrow = match claimed_arrow {
                        Some(arr) => arr,
                        None => continue,
                    };

                    let mut test_principal = principal.clone();
                    let mut scope = test_principal.begin_commit();
                    let mut ok = true;
                    let mut commit_keys = Vec::new();

                    for coz in &mutations {
                        let alg = &coz.alg;
                        let czd = match cyphr::compute_czd(&coz.pay_json, &coz.sig, alg) {
                            Some(c) => c,
                            None => {
                                ok = false;
                                break;
                            },
                        };

                        let new_key = if let Some(info) = &coz.key_info {
                            crate::import::key_entry_to_key(&crate::KeyEntry {
                                alg: info.algorithm.clone(),
                                pub_key: info.public_key.clone(),
                                tmb: info.thumbprint.clone(),
                                tag: None,
                                now: None,
                            })
                            .ok()
                        } else {
                            None
                        };

                        if scope
                            .verify_and_apply(&coz.pay_json, &coz.sig, czd.clone(), new_key)
                            .is_ok()
                        {
                            if let Some(info) = &coz.key_info {
                                commit_keys.push(info.clone());
                            }
                        } else {
                            ok = false;
                            break;
                        }
                    }

                    if ok && scope.matches_arrow(&claimed_arrow) {
                        // Finalize the commit using the finalizer cozy
                        let res = scope.verify_and_apply(
                            &finalizer_coz.pay_json,
                            &finalizer_coz.sig,
                            finalizer_czd.clone(),
                            finalizer_coz.new_key.clone(),
                        );
                        if res.is_ok() {
                            if let Some(info) = &finalizer_coz.key_info {
                                commit_keys.push(info.clone());
                            }

                            let commit = match scope.finalize() {
                                Ok(c) => c,
                                Err(_) => continue,
                            };
                            let commit_ids = match format_multihash_all(&commit.tr().0) {
                                Ok(ids) => ids,
                                Err(_) => continue,
                            };
                            let ar = match format_multihash_all(commit.auth_root().as_multihash()) {
                                Ok(val) => val,
                                Err(_) => continue,
                            };
                            let sr = match format_multihash_all(commit.sr().as_multihash()) {
                                Ok(val) => val,
                                Err(_) => continue,
                            };
                            let pr = match format_multihash_all(commit.pr().as_multihash()) {
                                Ok(val) => val,
                                Err(_) => continue,
                            };

                            matched_combination = Some((
                                test_principal,
                                commit_ids,
                                ar,
                                sr,
                                pr,
                                finalizer_coz.clone(),
                                commit_keys,
                            ));
                            break;
                        }
                    }
                }

                let Some((
                    mut next_principal,
                    commit_ids,
                    ar,
                    sr,
                    pr,
                    matched_finalizer,
                    commit_keys,
                )) = matched_combination
                else {
                    return Err(EngineError::MalformedBlob(format!(
                        "reindex: principal {principal_id}'s commit at timestamp {target_time} \
                         has {} candidate finalizer(s) but none verify against the deterministic \
                         mutation order recovered from raw content -- recovery cannot silently \
                         guess an alternate order",
                        finalizers.len()
                    )));
                };

                // Gather all consumed cozies' hashes.
                let mut consumed_hashes: std::collections::HashSet<Blake3Hash> =
                    pool.iter().take(tx_start_idx).map(|c| c.hash).collect();
                for m_coz in &mutations {
                    consumed_hashes.insert(m_coz.hash);
                }
                consumed_hashes.insert(matched_finalizer.hash);

                // Collect deferred actions (not yet consumed, at or before this commit's time).
                let mut deferred_actions = Vec::new();
                for coz in pool.iter() {
                    if coz.now <= target_time
                        && !is_transaction_typ(&coz.typ)
                        && !consumed_hashes.contains(&coz.hash)
                    {
                        let tmb_bytes = match Base64UrlUnpadded::decode_vec(&coz.tmb) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                        let alg = &coz.alg;
                        let czd = match cyphr::compute_czd(&coz.pay_json, &coz.sig, alg) {
                            Some(c) => c,
                            None => continue,
                        };
                        deferred_actions.push((coz.clone(), czd, signer_tmb));
                    }
                }

                for m_coz in &mutations {
                    commit_blobs.push(m_coz.hash);
                    commit_cozies.push(m_coz.clone());
                }
                commit_blobs.push(matched_finalizer.hash);
                commit_cozies.push(matched_finalizer.clone());

                for (coz, czd, signer_tmb) in deferred_actions {
                    if next_principal.is_key_active(&signer_tmb)
                        && next_principal
                            .verify_and_record_action(&coz.pay_json, &coz.sig, czd.clone())
                            .is_ok()
                    {
                        commit_blobs.push(coz.hash);
                        commit_cozies.push(coz.clone());
                        consumed_hashes.insert(coz.hash);
                    }
                }

                let commit_pre = if sequence == 0 {
                    None
                } else {
                    format_multihash_all(principal.pr().as_multihash())?
                        .first()
                        .cloned()
                };

                let cozies = commit_cozies
                    .iter()
                    .map(|coz| map_coz_info(coz, &next_principal.active_algs()))
                    .collect();

                let cr = next_principal
                    .cr()
                    .map(|c| format_multihash_all(c.as_multihash()))
                    .transpose()?
                    .unwrap_or_default();

                // Index this commit
                let indexable = IndexableCommit {
                    principal_id: principal_id.clone(),
                    commit_ids,
                    sequence,
                    pre: commit_pre,
                    prs: pr,
                    srs: sr,
                    ars: ar,
                    crs: cr,
                    blob_hashes: commit_blobs,
                    cozies,
                    timestamp: target_time,
                    keys: commit_keys,
                };
                self.indexer.index_commit(&indexable).await?;
                sequence += 1;

                // Remove consumed items from pool
                pool.retain(|coz| !consumed_hashes.contains(&coz.hash));
                principal = next_principal;
            }
        }

        // Manifest-backed commits are authoritative: read their durably
        // retained order and digests directly (no search) last, so a
        // manifest-backed principal's real tip always wins over any raw,
        // non-manifest content indexed above for the same principal_id
        // (e.g. a legacy/synthetic genesis marker bootstrapped in step 1).
        self.rebuild_index_from_manifests().await?;

        Ok(())
    }
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

/// Compute the `principal_id` a single genesis key resolves to, without
/// needing durable storage — `reindex`'s bootstrap loops must call
/// `storage_factory` with this identifier, but the identifier is only
/// knowable *after* constructing a `Principal`, and `storage_factory` is
/// what constructs one.
///
/// Breaks that cycle by building a throwaway `Principal` against the
/// always-available [`cyphr::eml::MemoryStorage`] purely to read off its
/// `pr()`. This is safe — not an approximation — because a genesis PR is a
/// pure function of the genesis key(s) and active algorithms alone: no CR
/// exists yet (`PR = SR`, per SPEC §3.7.1's implicit promotion), and SR/AR/KR
/// are all derived from key thumbprints, never from the storage backend. The
/// throwaway principal and the one `storage_factory` goes on to build from
/// the *same* key are therefore guaranteed to compute byte-identical PRs,
/// which is what keeps this identifier consistent with the one
/// `load_principal`/`submit_commit` compute for the same principal later.
fn implicit_genesis_principal_id(key: &cyphr::Key) -> Result<String, EngineError> {
    let throwaway = cyphr::Principal::implicit(key.clone())?;
    format_multihash_all(throwaway.pr().as_multihash())?
        .into_iter()
        .next()
        .ok_or_else(|| EngineError::InvalidInput("empty PR".into()))
}

#[cfg(test)]
mod tests;
