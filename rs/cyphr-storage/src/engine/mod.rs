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

/// Result from [`StorageEngine::ingest_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
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
        }
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

    /// Ingest a pre-validated commit: store blobs and index metadata.
    ///
    /// Each entry in `blobs` is a raw coz byte slice. The engine:
    /// 1. Puts each blob into the blob store (content-addressed)
    /// 2. Builds an `IndexableCommit` from the metadata + blob hashes
    /// 3. Calls the indexer to record relational data
    ///
    /// Returns the BLAKE3 hashes of the stored blobs.
    ///
    /// **Note:** This method does NOT validate protocol-level
    /// signatures or state transitions. That responsibility belongs
    /// to the protocol validation layer (Phase 3b).
    #[tracing::instrument(
        skip(self, blobs),
        fields(
            principal_id = %commit.principal_id,
            blob_count = blobs.len()
        )
    )]
    pub async fn ingest_commit(
        &self,
        blobs: &[&[u8]],
        mut commit: IndexableCommit,
    ) -> Result<IngestResult, EngineError> {
        // Store each blob.
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for (i, blob) in blobs.iter().enumerate() {
            let hash = self.blob_store.put(blob).await?;
            blob_hashes.push(hash);
            if i < commit.cozies.len() {
                commit.cozies[i].blob_hash = hash;
            }
        }
        commit.blob_hashes = blob_hashes.clone();

        // Build and submit index entry.
        self.indexer.index_commit(&commit).await?;

        Ok(IngestResult { blob_hashes })
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
            let cad = coz::canonical_hash_for_alg(&pay_json, &alg_str, None).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {i}: czd computation failed"))
            })?;
            let czd = coz::czd_for_alg(&cad, &sig, &alg_str).ok_or_else(|| {
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
            // Action-only bundle: just store blobs in blob store without indexing
            let mut blob_hashes = Vec::with_capacity(raw_blobs.len());
            for blob in raw_blobs {
                let hash = self.blob_store.put(blob).await?;
                blob_hashes.push(hash);
            }
            Ok(IngestResult { blob_hashes })
        }
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material from the first stored
    ///   commit's blobs.
    /// - If the principal is new, extracts key material from the first submitted blob's `"key"`
    ///   field.
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
            // Existing principal — scan blobs of the first commit to find the genesis key
            // (stored in the commit/create cozy's "key" field, or fallback to the first blob's key
            // field).
            let mut fallback_data = None;
            tracing::debug!(
                "resolve_genesis: first commit has {} blobs",
                first_commit.blob_hashes.len()
            );
            for (idx, hash) in first_commit.blob_hashes.iter().enumerate() {
                let data = self.blob_store.get(hash).await?.ok_or_else(|| {
                    EngineError::NotFound(format!("blob {hash} not found in store"))
                })?;
                if idx == 0 {
                    fallback_data = Some(data.clone());
                }

                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) {
                    let pay = value.get("pay");
                    let typ = pay
                        .and_then(|p| p.get("typ"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let has_key = value.get("key").is_some();
                    tracing::debug!(
                        "resolve_genesis: blob idx={}, typ={}, has_key={}",
                        idx,
                        typ,
                        has_key
                    );
                    if typ.contains("/commit/create") && has_key {
                        tracing::debug!("resolve_genesis: found genesis key in commit/create!");
                        return Self::genesis_from_blob(&data);
                    }
                }
            }

            if let Some(data) = fallback_data {
                tracing::debug!("resolve_genesis: fallback to first blob");
                if let Ok(genesis_val) = self.genesis_val_from_blob(&data) {
                    return Ok(genesis_val);
                }
            }
            Err(EngineError::NotFound(
                "genesis key not found in first commit".into(),
            ))
        } else {
            // New principal — extract genesis from the first submitted blob.
            Self::genesis_from_blob(raw_blobs[0])
        }
    }

    /// Extract an implicit genesis key from a raw coz blob's "key" field.
    fn genesis_val_from_blob(&self, blob: &[u8]) -> Result<crate::Genesis, EngineError> {
        Self::genesis_from_blob(blob)
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

    /// Reindex the relational database from all raw blobs in the BlobStore.
    ///
    /// Implements recovery verification/convergance [recovery-reindex] and
    /// [recovery-convergence]. Traces the transaction/action chain from genesis
    /// and idempotently indexes everything.
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

        let mut cozies = Vec::new();
        for hash in hashes {
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

            let cad = coz::canonical_hash_for_alg(&pay_json, &pay.alg, None).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {hash}: czd computation failed"))
            })?;
            let czd = coz::czd_for_alg(&cad, &sig, &pay.alg).ok_or_else(|| {
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

        // 0. Bootstrap from existing principals in the indexer (if not doing a total check)
        if !total_check {
            let existing_principals = self.indexer.list_principals().await?;
            for p_summary in existing_principals {
                let genesis = self.resolve_genesis(&p_summary.principal_id, &[]).await?;
                let principal = self
                    .load_principal(&p_summary.principal_id, genesis)
                    .await?;
                let next_seq = p_summary.commit_count;
                bootstrapped.push((principal, p_summary.principal_id, next_seq));
            }
        }

        // 1. Bootstrap from mock genesis cozies (pre is empty/missing and key is present)
        // Exclude finalizer commit/create cozies from being consumed as mock genesis cozies
        let mut mock_genesis_cozies = Vec::new();
        for c in &tx_cozies {
            if !c.typ.contains("/commit/create")
                && (c.pre.is_none() || c.pre.as_ref().unwrap().is_empty())
            {
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

            let mut sequence: u64 = 0;

            // Index the mock genesis cozy as sequence 0
            let genesis_commit_ids = format_multihash_all(principal.pr().as_multihash())?;
            let genesis_prs = format_multihash_all(principal.pr().as_multihash())?;
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

        // 2. Bootstrap from keys in keys slice (from keystore) and keys in commit/create cozies
        // Only bootstrap keys that are identified as genesis keys (present as signer or new_key in
        // a cozy with empty/missing pre).
        let mut genesis_key_tmbs = std::collections::HashSet::new();
        for c in &tx_cozies {
            if c.pre.is_none() || c.pre.as_ref().unwrap().is_empty() {
                genesis_key_tmbs.insert(c.tmb.clone());
                if let Some(key) = &c.new_key {
                    genesis_key_tmbs.insert(key.tmb.to_b64());
                }
            }
        }

        let mut bootstrap_keys = Vec::new();
        for key in keys {
            if genesis_key_tmbs.contains(&key.tmb.to_b64()) {
                bootstrap_keys.push(key.clone());
            }
        }
        for c in &tx_cozies {
            if c.typ.contains("/commit/create") {
                if let Some(key) = &c.new_key {
                    if genesis_key_tmbs.contains(&key.tmb.to_b64())
                        && !bootstrap_keys.iter().any(|k| k.tmb == key.tmb)
                    {
                        bootstrap_keys.push(key.clone());
                    }
                }
            }
        }

        for key in bootstrap_keys {
            let principal_id = implicit_genesis_principal_id(&key)?;
            if bootstrapped.iter().any(|(_, pid, _)| pid == &principal_id) {
                continue;
            }
            let storage = (self.storage_factory)(&principal_id).map_err(EngineError::Storage)?;
            let principal = cyphr::Principal::implicit_with_storage(key.clone(), storage)?;
            bootstrapped.push((principal, principal_id, 0));
        }

        // Recombine remaining transactions and actions into a single chronological pool.
        let mut pool = tx_cozies;
        pool.extend(action_cozies);

        // Sort pool by timestamp to facilitate sequential application.
        // For cozies with the same timestamp, ensure actions come first, then mutation
        // transactions, then finalizer commit/create cozies last.
        // If they are in the same category, use lexical byte order of their czd as the tie-breaker.
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
                let _active_algs = principal.active_algs().to_vec();
                let mut commit_blobs = Vec::new();
                let mut commit_cozies = Vec::new();
                let mut consumed_indices = std::collections::HashSet::new();

                let mut first_tx_idx = None;
                for (idx, coz) in pool.iter().enumerate() {
                    if is_transaction_typ(&coz.typ) {
                        first_tx_idx = Some(idx);
                        break;
                    }
                }

                if let Some(tx_start_idx) = first_tx_idx {
                    // 1.1 Apply all pre-actions before the first transaction.
                    for (idx, coz) in pool.iter().enumerate().take(tx_start_idx) {
                        let tmb_bytes = match Base64UrlUnpadded::decode_vec(&coz.tmb) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                        if principal.is_key_active(&signer_tmb) {
                            let alg = &coz.alg;
                            let cad = match coz::canonical_hash_for_alg(&coz.pay_json, alg, None) {
                                Some(c) => c,
                                None => continue,
                            };
                            let czd = match coz::czd_for_alg(&cad, &coz.sig, alg) {
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
                                consumed_indices.insert(idx);
                            }
                        }
                    }

                    // 1.2 Gather mutation transactions and finalizers for the current commit.
                    let target_time = pool[tx_start_idx].now;

                    let mut mutations = Vec::new();
                    for coz in pool.iter() {
                        if coz.now == target_time
                            && is_transaction_typ(&coz.typ)
                            && !coz.typ.contains("/commit/create")
                        {
                            mutations.push(coz.clone());
                        }
                    }

                    let mut finalizers = Vec::new();
                    for coz in pool.iter() {
                        if coz.now == target_time && coz.typ.contains("/commit/create") {
                            finalizers.push(coz.clone());
                        }
                    }

                    let mut matched_combination = None;

                    // Generate all permutations of the mutation cozies.
                    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
                        if items.is_empty() {
                            return vec![vec![]];
                        }
                        let mut result = Vec::new();
                        for (i, item) in items.iter().enumerate() {
                            let mut rest = items.to_vec();
                            rest.remove(i);
                            for mut p in permutations(&rest) {
                                p.insert(0, item.clone());
                                result.push(p);
                            }
                        }
                        result
                    }

                    if mutations.len() > 8 {
                        tracing::warn!(
                            "reindex: too many mutations ({}) at same timestamp. skipping to \
                             prevent complexity explosion",
                            mutations.len()
                        );
                        break;
                    }

                    let mutation_perms = permutations(&mutations);

                    'outer: for finalizer_coz in &finalizers {
                        let alg = &finalizer_coz.alg;
                        let cad =
                            match coz::canonical_hash_for_alg(&finalizer_coz.pay_json, alg, None) {
                                Some(c) => c,
                                None => continue,
                            };
                        let finalizer_czd = match coz::czd_for_alg(&cad, &finalizer_coz.sig, alg) {
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

                        for perm in &mutation_perms {
                            let mut test_principal = principal.clone();
                            let mut scope = test_principal.begin_commit();
                            let mut ok = true;
                            let mut perm_keys = Vec::new();

                            for coz in perm {
                                let alg = &coz.alg;
                                let cad =
                                    match coz::canonical_hash_for_alg(&coz.pay_json, alg, None) {
                                        Some(c) => c,
                                        None => {
                                            ok = false;
                                            break;
                                        },
                                    };
                                let czd = match coz::czd_for_alg(&cad, &coz.sig, alg) {
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
                                        perm_keys.push(info.clone());
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
                                        perm_keys.push(info.clone());
                                    }

                                    let commit = match scope.finalize() {
                                        Ok(c) => c,
                                        Err(_) => continue,
                                    };
                                    let commit_ids = match format_multihash_all(&commit.tr().0) {
                                        Ok(ids) => ids,
                                        Err(_) => continue,
                                    };
                                    let ar = match format_multihash_all(
                                        commit.auth_root().as_multihash(),
                                    ) {
                                        Ok(val) => val,
                                        Err(_) => continue,
                                    };
                                    let sr = match format_multihash_all(commit.sr().as_multihash())
                                    {
                                        Ok(val) => val,
                                        Err(_) => continue,
                                    };
                                    let pr = match format_multihash_all(commit.pr().as_multihash())
                                    {
                                        Ok(val) => val,
                                        Err(_) => continue,
                                    };

                                    matched_combination = Some((
                                        test_principal,
                                        commit_ids,
                                        ar,
                                        sr,
                                        pr,
                                        perm.clone(),
                                        finalizer_coz.clone(),
                                        perm_keys,
                                    ));
                                    break 'outer;
                                }
                            }
                        }
                    }

                    if let Some((
                        mut next_principal,
                        commit_ids,
                        ar,
                        sr,
                        pr,
                        matched_perm,
                        matched_finalizer,
                        perm_keys,
                    )) = matched_combination
                    {
                        // We successfully finalized this commit!
                        // Let's gather all consumed cozies' hashes:
                        let mut consumed_indices = std::collections::HashSet::new();
                        // 1. Pre-actions are already consumed (index 0..tx_start_idx)
                        for idx in 0..tx_start_idx {
                            consumed_indices.insert(idx);
                        }
                        // 2. Matched mutations:
                        for m_coz in &matched_perm {
                            if let Some(idx) = pool.iter().position(|c| c.hash == m_coz.hash) {
                                consumed_indices.insert(idx);
                            }
                        }
                        // 3. Matched finalizer:
                        if let Some(idx) =
                            pool.iter().position(|c| c.hash == matched_finalizer.hash)
                        {
                            consumed_indices.insert(idx);
                        }

                        // Collect deferred actions
                        let mut deferred_actions = Vec::new();
                        for (idx, coz) in pool.iter().enumerate() {
                            if coz.now <= target_time
                                && !is_transaction_typ(&coz.typ)
                                && !consumed_indices.contains(&idx)
                            {
                                let tmb_bytes = match Base64UrlUnpadded::decode_vec(&coz.tmb) {
                                    Ok(b) => b,
                                    Err(_) => continue,
                                };
                                let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                                let alg = &coz.alg;
                                let cad =
                                    match coz::canonical_hash_for_alg(&coz.pay_json, alg, None) {
                                        Some(c) => c,
                                        None => continue,
                                    };
                                let czd = match coz::czd_for_alg(&cad, &coz.sig, alg) {
                                    Some(c) => c,
                                    None => continue,
                                };
                                deferred_actions.push((idx, coz.clone(), czd, signer_tmb));
                            }
                        }

                        // Apply deferred actions to next_principal
                        let mut commit_blobs = commit_blobs;
                        let mut commit_cozies = commit_cozies;
                        for m_coz in &matched_perm {
                            commit_blobs.push(m_coz.hash);
                            commit_cozies.push(m_coz.clone());
                        }
                        commit_blobs.push(matched_finalizer.hash);
                        commit_cozies.push(matched_finalizer.clone());

                        for (idx, coz, czd, signer_tmb) in deferred_actions {
                            if next_principal.is_key_active(&signer_tmb)
                                && next_principal
                                    .verify_and_record_action(&coz.pay_json, &coz.sig, czd.clone())
                                    .is_ok()
                            {
                                commit_blobs.push(coz.hash);
                                commit_cozies.push(coz.clone());
                                consumed_indices.insert(idx);
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
                            keys: perm_keys,
                        };
                        self.indexer.index_commit(&indexable).await?;
                        sequence += 1;

                        // Remove consumed items from pool
                        let mut remaining = Vec::new();
                        for (idx, coz) in pool.into_iter().enumerate() {
                            if !consumed_indices.contains(&idx) {
                                remaining.push(coz);
                            }
                        }
                        pool = remaining;
                        principal = next_principal;
                    } else {
                        // No combination matched!
                        break;
                    }
                } else {
                    break;
                }
            }
        }

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
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut results = Vec::new();
    for alg in mh.algorithms() {
        let bytes = mh
            .get(alg)
            .ok_or_else(|| EngineError::InvalidInput(format!("missing variant for {alg:?}")))?;
        results.push(format!("{alg}:{}", Base64UrlUnpadded::encode_string(bytes)));
    }
    Ok(results)
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
