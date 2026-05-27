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

pub use error::EngineError;

use cyphr::state::{StateDigest, TaggedDigest};

use crate::blob::{Blake3Hash, BlobStore, BlobStoreError};
use crate::index::{CommitRef, IndexableCommit, Indexer, TipState};

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
#[derive(Debug, Clone)]
pub struct IngestMeta {
    /// Principal genesis identifier (tagged digest string).
    pub principal_id: String,
    /// Commit ID variants (tagged digest strings).
    pub commit_ids: Vec<String>,
    /// Commit sequence number within this principal (0-indexed).
    pub sequence: u64,
    /// Principal Root variants after this commit.
    pub prs: Vec<String>,
    /// State Root variants after this commit.
    pub srs: Vec<String>,
    /// Auth Root variants after this commit.
    pub ars: Vec<String>,
    /// Transaction type identifiers (e.g., "key/create").
    pub transaction_types: Vec<String>,
    /// Transaction ID variants (czd tagged digests) for each coz in this commit.
    pub transaction_ids: Vec<Vec<String>>,
    /// Timestamp of the commit.
    pub timestamp: i64,
}

/// Result from [`StorageEngine::ingest_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// BLAKE3 hashes of the stored blobs.
    pub blob_hashes: Vec<Blake3Hash>,
}

/// Coordinated storage engine joining blob and index layers.
///
/// Generic over backend implementations. Use `MemoryBlobStore` +
/// `MemoryIndexer` for tests, production backends for deployment.
pub struct StorageEngine<B, I> {
    blob_store: B,
    indexer: I,
}

impl<B: BlobStore, I: Indexer> StorageEngine<B, I> {
    /// Create a new engine wrapping the given backends.
    pub fn new(blob_store: B, indexer: I) -> Self {
        Self {
            blob_store,
            indexer,
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
    #[tracing::instrument(skip(self, blobs), fields(principal_id = %metadata.principal_id, blob_count = blobs.len()))]
    pub async fn ingest_commit(
        &self,
        blobs: &[&[u8]],
        metadata: IngestMeta,
    ) -> Result<IngestResult, EngineError> {
        use tokio::io::AsyncWriteExt;

        // Store each blob.
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let mut handle = self.blob_store.open_write().await?;
            handle.write_all(blob).await.map_err(BlobStoreError::Io)?;
            let hash = self.blob_store.close(handle).await?;
            blob_hashes.push(hash);
        }

        // Build and submit index entry.
        let indexable = IndexableCommit {
            principal_id: metadata.principal_id,
            commit_ids: metadata.commit_ids,
            sequence: metadata.sequence,
            prs: metadata.prs,
            srs: metadata.srs,
            ars: metadata.ars,
            blob_hashes: blob_hashes.clone(),
            transaction_types: metadata.transaction_types,
            transaction_ids: metadata.transaction_ids,
            timestamp: metadata.timestamp,
        };
        self.indexer.index_commit(&indexable).await?;

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
    ) -> Result<cyphr::Principal, EngineError> {
        use crate::CommitEntry;
        use crate::import::replay_commits;

        // 1. Construct the principal from genesis (no commits yet).
        let mut principal = match genesis {
            crate::Genesis::Implicit(key) => cyphr::Principal::implicit(key)?,
            crate::Genesis::Explicit(keys) => {
                if keys.is_empty() {
                    return Err(EngineError::InvalidInput(
                        "genesis requires at least one key".into(),
                    ));
                }
                cyphr::Principal::explicit(keys)?
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
    /// 4. For each raw coz blob: parse `{pay, sig}`, extract key material,
    ///    compute `czd`, call `scope.verify_and_apply()`
    /// 5. Finalize the scope → immutable `Commit`
    /// 6. Extract state digests from the finalized `Commit`
    /// 7. Store blobs + index via `ingest_commit`
    ///
    /// # Arguments
    ///
    /// * `principal_id` — Tagged-digest identifier for this principal.
    /// * `genesis` — How this principal was originally created, or `None`
    ///   to auto-detect from storage (existing principal) or from the
    ///   submitted blobs (new principal).
    /// * `raw_blobs` — Raw coz JSON envelopes (`{pay, sig, key?}`).
    ///
    /// # Errors
    ///
    /// Any protocol violation (bad signature, broken chain, unknown signer,
    /// etc.) causes the entire submit to fail with no side effects — blobs
    /// are only stored after successful validation.
    #[tracing::instrument(skip(self, genesis, raw_blobs), fields(blob_count = raw_blobs.len()))]
    pub async fn submit_commit(
        &self,
        principal_id: &str,
        genesis: Option<crate::Genesis>,
        raw_blobs: &[&[u8]],
    ) -> Result<IngestResult, EngineError> {
        use crate::import::{is_key_introducing_typ, is_transaction_typ};
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

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

        // 4. Open a commit scope and process each blob.
        let mut scope = principal.begin_commit();
        let mut transaction_types = Vec::new();
        let mut last_timestamp: i64 = 0;
        let mut pending_czds = Vec::new();

        for (i, blob_bytes) in raw_blobs.iter().enumerate() {
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

            let pay_json = serde_json::to_vec(pay)
                .map_err(|e| EngineError::MalformedBlob(format!("blob {i}: pay serialize: {e}")))?;

            let typ = pay.get("typ").and_then(|t| t.as_str()).unwrap_or("");

            if let Some(now) = pay.get("now").and_then(|n| n.as_i64()) {
                last_timestamp = now;
            }

            // Compute czd for all cozies (both transactions and actions)
            let alg = match scope.principal_hash_alg() {
                cyphr::state::HashAlg::Sha256 => "ES256",
                cyphr::state::HashAlg::Sha384 => "ES384",
                cyphr::state::HashAlg::Sha512 => "ES512",
            };
            let cad = coz::canonical_hash_for_alg(&pay_json, alg, None).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {i}: czd computation failed"))
            })?;
            let czd = coz::czd_for_alg(&cad, &sig, alg).ok_or_else(|| {
                EngineError::MalformedBlob(format!("blob {i}: czd computation failed"))
            })?;

            pending_czds.push((czd.clone(), alg.to_string()));
            transaction_types.push(typ.to_string());

            if is_transaction_typ(typ) {
                // Extract key material for key-introducing transactions.
                let new_key = if is_key_introducing_typ(typ) {
                    value.get("key").and_then(|k| {
                        let ke = key_value_to_entry(k)?;
                        crate::import::key_entry_to_key(&ke).ok()
                    })
                } else {
                    None
                };

                // Verify signature and apply state mutation.
                scope.verify_and_apply(&pay_json, &sig, czd, new_key)?;
            }
        }

        // 5. Finalize the commit scope.
        let commit = scope.finalize()?;

        // Now scope is gone. We can access principal safely.
        let mut transaction_ids = Vec::new();
        for (czd, alg_str) in pending_czds {
            let mut czd_variants = Vec::new();
            let source_alg = match cyphr::state::hash_alg_from_str(&alg_str) {
                Ok(a) => a,
                Err(_) => cyphr::state::HashAlg::Sha256,
            };
            let tagged = cyphr::state::TaggedCzd::new(&czd, source_alg);
            for &active_alg in &active_algs {
                let converted = tagged.convert_to(active_alg);
                czd_variants.push(format!(
                    "{active_alg}:{}",
                    Base64UrlUnpadded::encode_string(&converted)
                ));
            }
            transaction_ids.push(czd_variants);
        }

        // 6. Extract state digests from the finalized Commit.
        let commit_ids = format_multihash_all(&commit.tr().0)?;
        let ar = format_multihash_all(commit.auth_root().as_multihash())?;
        let sr = format_multihash_all(commit.sr().as_multihash())?;
        let pr = format_multihash_all(commit.pr().as_multihash())?;

        // 7. Persist via the storage layer.
        let meta = IngestMeta {
            principal_id: principal_id.to_string(),
            commit_ids,
            sequence: next_seq,
            prs: pr,
            srs: sr,
            ars: ar,
            transaction_types,
            transaction_ids,
            timestamp: last_timestamp,
        };

        self.ingest_commit(raw_blobs, meta).await
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material
    ///   from the first stored commit's blobs.
    /// - If the principal is new, extracts key material from the first
    ///   submitted blob's `"key"` field.
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
            // (stored in the commit/create cozy's "key" field, or fallback to the first blob's key field).
            let mut fallback_data = None;
            eprintln!(
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
                    eprintln!(
                        "resolve_genesis: blob idx={}, typ={}, has_key={}",
                        idx, typ, has_key
                    );
                    if typ.contains("/commit/create") && has_key {
                        eprintln!("resolve_genesis: found genesis key in commit/create!");
                        return Self::genesis_from_blob(&data);
                    }
                }
            }

            if let Some(data) = fallback_data {
                eprintln!("resolve_genesis: fallback to first blob");
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
    pub async fn reindex(&self, keys: &[cyphr::Key]) -> Result<(), EngineError> {
        use crate::import::is_transaction_typ;
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        #[derive(Clone)]
        struct ParsedCozInfo {
            hash: Blake3Hash,
            pay_json: Vec<u8>,
            sig: Vec<u8>,
            typ: String,
            pre: Option<String>,
            tmb: String,
            now: i64,
            new_key: Option<cyphr::Key>,
        }

        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;
        eprintln!("reindex: found {} blobs in store", hashes.len());

        let mut cozies = Vec::new();
        for hash in hashes {
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
                    eprintln!(
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
                    eprintln!(
                        "reindex: base64 decode of sig '{}' failed: {:?}",
                        ext.sig, e
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
            }

            let pay: PayFields = match serde_json::from_str(ext.pay.get()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "reindex: PayFields deserialize failed: {:?}, pay = '{}'",
                        e,
                        ext.pay.get()
                    );
                    continue;
                },
            };

            let new_key = if let Some(k) = &ext.key {
                if let Some(ke) = key_value_to_entry(k) {
                    crate::import::key_entry_to_key(&ke).ok()
                } else {
                    None
                }
            } else {
                None
            };

            cozies.push(ParsedCozInfo {
                hash,
                pay_json,
                sig,
                typ: pay.typ,
                pre: pay.pre,
                tmb: pay.tmb,
                now: pay.now,
                new_key,
            });
        }

        tracing::debug!("total cozies parsed: {}", cozies.len());

        // Separate transactions and actions
        let (mut tx_cozies, mut action_cozies): (Vec<_>, Vec<_>) =
            cozies.into_iter().partition(|c| is_transaction_typ(&c.typ));

        tracing::debug!(
            "tx_cozies count: {}, action_cozies count: {}",
            tx_cozies.len(),
            action_cozies.len()
        );

        let mut bootstrapped = Vec::new();

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
            let principal = cyphr::Principal::implicit(key)?;
            let pr_variants = format_multihash_all(principal.pr().as_multihash())?;
            let principal_id = pr_variants
                .first()
                .cloned()
                .ok_or_else(|| EngineError::InvalidInput("empty PR".into()))?;

            let mut sequence: u64 = 0;

            // Index the mock genesis cozy as sequence 0
            let genesis_commit_ids = format_multihash_all(principal.pr().as_multihash())?;
            let genesis_prs = format_multihash_all(principal.pr().as_multihash())?;
            let genesis_srs = format_multihash_all(principal.sr().unwrap().as_multihash())?;
            let genesis_ars = format_multihash_all(principal.auth_root().as_multihash())?;

            let genesis_indexable = IndexableCommit {
                principal_id: principal_id.clone(),
                commit_ids: genesis_commit_ids,
                sequence,
                prs: genesis_prs,
                srs: genesis_srs,
                ars: genesis_ars,
                blob_hashes: vec![mock_coz.hash],
                transaction_types: vec![mock_coz.typ.clone()],
                transaction_ids: vec![vec![mock_coz.typ.clone()]],
                timestamp: mock_coz.now,
            };
            self.indexer.index_commit(&genesis_indexable).await?;
            sequence += 1;

            bootstrapped.push((principal, principal_id, sequence));
        }

        // 2. Bootstrap from keys in keys slice (from keystore) and keys in commit/create cozies
        // Only bootstrap keys that are identified as genesis keys (present as signer or new_key in a cozy with empty/missing pre).
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
            let principal = cyphr::Principal::implicit(key.clone())?;
            let pr_variants = format_multihash_all(principal.pr().as_multihash())?;
            let principal_id = pr_variants
                .first()
                .cloned()
                .ok_or_else(|| EngineError::InvalidInput("empty PR".into()))?;

            if !bootstrapped.iter().any(|(_, pid, _)| pid == &principal_id) {
                bootstrapped.push((principal, principal_id, 0));
            }
        }

        // Sort pool by timestamp to facilitate sequential application.
        // For cozies with the same timestamp, ensure commit/create finality markers
        // sort after state-mutating transactions.
        tx_cozies.sort_by(|a, b| match a.now.cmp(&b.now) {
            std::cmp::Ordering::Equal => {
                let a_is_commit = a.typ.contains("/commit/create");
                let b_is_commit = b.typ.contains("/commit/create");
                a_is_commit.cmp(&b_is_commit)
            },
            other => other,
        });
        action_cozies.sort_by_key(|c| c.now);

        for (i, c) in tx_cozies.iter().enumerate() {
            eprintln!(
                "sorted tx_cozy [{}]: typ={}, now={}, pre={:?}, hash={}",
                i, c.typ, c.now, c.pre, c.hash
            );
        }

        for (mut principal, principal_id, mut sequence) in bootstrapped {
            loop {
                let active_algs = principal.active_algs().to_vec();
                eprintln!(
                    "loop iteration: tx_cozies.len() = {}, principal PR = {:?}",
                    tx_cozies.len(),
                    principal.pr()
                );
                let mut scope = principal.begin_commit();
                let mut applied_any = false;
                let mut commit_blobs = Vec::new();
                let mut commit_transaction_types = Vec::new();
                let mut commit_pending_czds = Vec::new();
                let mut commit_timestamp = 0;

                let mut remaining_txs = Vec::new();
                let mut mutation_cozies = Vec::new();
                let mut commit_cozies = Vec::new();

                for coz in tx_cozies.clone() {
                    if coz.typ.contains("/commit/create") {
                        commit_cozies.push(coz);
                    } else {
                        mutation_cozies.push(coz);
                    }
                }

                // 1. Eagerly apply as many mutation cozies as possible in this commit scope
                loop {
                    let mut applied_this_round = false;
                    let mut unapplied = Vec::new();
                    for coz in mutation_cozies {
                        let alg = match scope.principal_hash_alg() {
                            cyphr::state::HashAlg::Sha256 => "ES256",
                            cyphr::state::HashAlg::Sha384 => "ES384",
                            cyphr::state::HashAlg::Sha512 => "ES512",
                        };
                        let cad = match coz::canonical_hash_for_alg(&coz.pay_json, alg, None) {
                            Some(c) => c,
                            None => {
                                unapplied.push(coz);
                                continue;
                            },
                        };
                        let czd = match coz::czd_for_alg(&cad, &coz.sig, alg) {
                            Some(c) => c,
                            None => {
                                unapplied.push(coz);
                                continue;
                            },
                        };

                        match scope.verify_and_apply(
                            &coz.pay_json,
                            &coz.sig,
                            czd.clone(),
                            coz.new_key.clone(),
                        ) {
                            Ok(_) => {
                                commit_blobs.push(coz.hash);
                                commit_transaction_types.push(coz.typ.clone());
                                commit_pending_czds.push((czd, alg.to_string()));
                                commit_timestamp = coz.now;
                                applied_any = true;
                                applied_this_round = true;
                            },
                            Err(_) => {
                                unapplied.push(coz);
                            },
                        }
                    }
                    mutation_cozies = unapplied;
                    if !applied_this_round {
                        break;
                    }
                }

                // 2. Find and apply the matching commit/create cozy
                let mut matched_commit = None;
                let mut unapplied_commits = Vec::new();
                for coz in commit_cozies {
                    let alg = match scope.principal_hash_alg() {
                        cyphr::state::HashAlg::Sha256 => "ES256",
                        cyphr::state::HashAlg::Sha384 => "ES384",
                        cyphr::state::HashAlg::Sha512 => "ES512",
                    };
                    let cad = match coz::canonical_hash_for_alg(&coz.pay_json, alg, None) {
                        Some(c) => c,
                        None => {
                            unapplied_commits.push(coz);
                            continue;
                        },
                    };
                    let czd = match coz::czd_for_alg(&cad, &coz.sig, alg) {
                        Some(c) => c,
                        None => {
                            unapplied_commits.push(coz);
                            continue;
                        },
                    };

                    // Extract claimed arrow to check match
                    let claimed_arrow = if let Ok(value) =
                        serde_json::from_slice::<serde_json::Value>(&coz.pay_json)
                    {
                        if let Some(arrow_val) = value.get("arrow").and_then(|v| v.as_str()) {
                            if let Ok(tagged) = arrow_val.parse::<cyphr::state::TaggedDigest>() {
                                cyphr::multihash::MultihashDigest::from_single(
                                    tagged.alg(),
                                    tagged.as_bytes().to_vec(),
                                )
                                .ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let matches = if let Some(arr) = &claimed_arrow {
                        scope.matches_arrow(arr)
                    } else {
                        false
                    };

                    if matches && matched_commit.is_none() {
                        // Apply this finalizer cozy!
                        match scope.verify_and_apply(
                            &coz.pay_json,
                            &coz.sig,
                            czd.clone(),
                            coz.new_key.clone(),
                        ) {
                            Ok(_) => {
                                commit_blobs.push(coz.hash);
                                commit_transaction_types.push(coz.typ.clone());
                                commit_pending_czds.push((czd, alg.to_string()));
                                commit_timestamp = coz.now;
                                applied_any = true;
                                matched_commit = Some(coz);
                            },
                            Err(e) => {
                                eprintln!("failed to apply matched commit/create: {:?}", e);
                                unapplied_commits.push(coz);
                            },
                        }
                    } else {
                        unapplied_commits.push(coz);
                    }
                }

                // Restore remaining_txs
                remaining_txs.extend(mutation_cozies);
                remaining_txs.extend(unapplied_commits);

                // Update the pool
                tx_cozies = remaining_txs;

                if !applied_any {
                    break;
                }

                // Finalize commit
                let commit = scope.finalize()?;

                // Extract state roots immediately (ends the borrow of principal by commit)
                let commit_ids = format_multihash_all(&commit.tr().0)?;
                let ar = format_multihash_all(commit.auth_root().as_multihash())?;
                let sr = format_multihash_all(commit.sr().as_multihash())?;
                let pr = format_multihash_all(commit.pr().as_multihash())?;

                tracing::info!(
                    "successfully finalized commit sequence={}, PR={:?}",
                    sequence,
                    pr
                );

                // Compute transaction ids
                let mut commit_transaction_ids = Vec::new();
                for (czd, alg_str) in commit_pending_czds {
                    let mut czd_variants = Vec::new();
                    let source_alg = match cyphr::state::hash_alg_from_str(&alg_str) {
                        Ok(a) => a,
                        Err(_) => cyphr::state::HashAlg::Sha256,
                    };
                    let tagged = cyphr::state::TaggedCzd::new(&czd, source_alg);
                    for &active_alg in &active_algs {
                        let converted = tagged.convert_to(active_alg);
                        czd_variants.push(format!(
                            "{active_alg}:{}",
                            Base64UrlUnpadded::encode_string(&converted)
                        ));
                    }
                    commit_transaction_ids.push(czd_variants);
                }

                // Find any action cozies that match this commit
                let mut remaining_actions = Vec::new();
                for action in action_cozies {
                    let tmb_bytes = match Base64UrlUnpadded::decode_vec(&action.tmb) {
                        Ok(b) => b,
                        Err(_) => {
                            remaining_actions.push(action);
                            continue;
                        },
                    };
                    let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                    if principal.is_key_active(&signer_tmb) && action.now <= commit_timestamp {
                        let alg = match principal.hash_alg() {
                            cyphr::state::HashAlg::Sha256 => "ES256",
                            cyphr::state::HashAlg::Sha384 => "ES384",
                            cyphr::state::HashAlg::Sha512 => "ES512",
                        };
                        let cad = match coz::canonical_hash_for_alg(&action.pay_json, alg, None) {
                            Some(c) => c,
                            None => {
                                remaining_actions.push(action);
                                continue;
                            },
                        };
                        let czd = match coz::czd_for_alg(&cad, &action.sig, alg) {
                            Some(c) => c,
                            None => {
                                remaining_actions.push(action);
                                continue;
                            },
                        };

                        if principal
                            .verify_and_record_action(&action.pay_json, &action.sig, czd.clone())
                            .is_ok()
                        {
                            commit_blobs.push(action.hash);
                            commit_transaction_types.push(action.typ.clone());

                            let mut czd_variants = Vec::new();
                            let source_alg = match cyphr::state::hash_alg_from_str(alg) {
                                Ok(a) => a,
                                Err(_) => cyphr::state::HashAlg::Sha256,
                            };
                            let tagged = cyphr::state::TaggedCzd::new(&czd, source_alg);
                            for &active_alg in &active_algs {
                                let converted = tagged.convert_to(active_alg);
                                czd_variants.push(format!(
                                    "{active_alg}:{}",
                                    Base64UrlUnpadded::encode_string(&converted)
                                ));
                            }
                            commit_transaction_ids.push(czd_variants);
                        } else {
                            remaining_actions.push(action);
                        }
                    } else {
                        remaining_actions.push(action);
                    }
                }
                action_cozies = remaining_actions;

                // Index this commit
                let indexable = IndexableCommit {
                    principal_id: principal_id.clone(),
                    commit_ids,
                    sequence,
                    prs: pr,
                    srs: sr,
                    ars: ar,
                    blob_hashes: commit_blobs,
                    transaction_types: commit_transaction_types,
                    transaction_ids: commit_transaction_ids,
                    timestamp: commit_timestamp,
                };
                self.indexer.index_commit(&indexable).await?;
                sequence += 1;
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

#[cfg(test)]
mod tests;
