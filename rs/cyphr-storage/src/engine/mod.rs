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

use cyphr::state::TaggedDigest;

use crate::blob::{Blake3Hash, BlobStore};
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
    /// Commit ID (tagged digest string).
    pub commit_id: String,
    /// Commit sequence number within this principal (0-indexed).
    pub sequence: u64,
    /// Principal Root after this commit.
    pub pr: String,
    /// State Root after this commit.
    pub sr: String,
    /// Auth Root after this commit.
    pub ar: String,
    /// Transaction type identifiers (e.g., "key/create").
    pub transaction_types: Vec<String>,
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

    // ========================================================================
    // Read path
    // ========================================================================

    /// Retrieve the current tip state for a principal.
    ///
    /// Delegates directly to the indexer.
    pub fn get_tip(&self, principal_id: &str) -> Result<Option<TipState>, EngineError> {
        Ok(self.indexer.get_tip(principal_id)?)
    }

    /// Retrieve a patch: commit chain metadata joined with blob content.
    ///
    /// For each commit in the range, fetches the raw blob bytes from
    /// the blob store. This is the engine's primary coordination value —
    /// neither trait can serve this alone.
    pub fn get_patch(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<PatchResponse, EngineError> {
        let chain = self.indexer.get_commit_chain(principal_id, from, to)?;

        let mut entries = Vec::with_capacity(chain.len());
        for commit_ref in chain {
            let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash)?.ok_or_else(|| {
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
    pub fn get_entity(&self, digest: &TaggedDigest) -> Result<Option<Vec<u8>>, EngineError> {
        let entity = match self.indexer.resolve_digest(digest)? {
            Some(e) => e,
            None => return Ok(None),
        };

        let data = self.blob_store.get(&entity.blob_hash)?;
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
    pub fn ingest_commit(
        &self,
        blobs: &[&[u8]],
        metadata: IngestMeta,
    ) -> Result<IngestResult, EngineError> {
        // Store each blob.
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let hash = self.blob_store.put(blob)?;
            blob_hashes.push(hash);
        }

        // Build and submit index entry.
        let indexable = IndexableCommit {
            principal_id: metadata.principal_id,
            commit_id: metadata.commit_id,
            sequence: metadata.sequence,
            pr: metadata.pr,
            sr: metadata.sr,
            ar: metadata.ar,
            blob_hashes: blob_hashes.clone(),
            transaction_types: metadata.transaction_types,
            timestamp: metadata.timestamp,
        };
        self.indexer.index_commit(&indexable)?;

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
    pub fn load_principal(
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
        let chain = self.indexer.get_commit_chain(principal_id, None, None)?;
        if chain.is_empty() {
            return Ok(principal);
        }

        // 3. For each CommitRef, fetch blobs and build a CommitEntry.
        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let mut cozies = Vec::with_capacity(commit_ref.blob_hashes.len());
            let mut keys = Vec::new();

            for hash in &commit_ref.blob_hashes {
                let data = self.blob_store.get(hash)?.ok_or_else(|| {
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
    pub fn submit_commit(
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
            None => self.resolve_genesis(principal_id, raw_blobs)?,
        };

        // 2. Load (or construct) the principal from existing state.
        let mut principal = self.load_principal(principal_id, genesis)?;

        // 3. Determine the next sequence number.
        let next_seq = self
            .indexer
            .get_tip(principal_id)?
            .map(|tip| tip.commit_count)
            .unwrap_or(0);

        // 4. Open a commit scope and process each blob.
        let mut scope = principal.begin_commit();
        let mut transaction_types = Vec::new();
        let mut last_timestamp: i64 = 0;

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

            if is_transaction_typ(typ) {
                transaction_types.push(typ.to_string());

                // Extract key material for key-introducing transactions.
                let new_key = if is_key_introducing_typ(typ) {
                    value.get("key").and_then(|k| {
                        let ke = key_value_to_entry(k)?;
                        crate::import::key_entry_to_key(&ke).ok()
                    })
                } else {
                    None
                };

                // Compute czd.
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

                // Verify signature and apply state mutation.
                scope.verify_and_apply(&pay_json, &sig, czd, new_key)?;
            }
            // Actions within submit_commit are not yet supported.
            // They would need scope.finalize() then principal.verify_and_record_action().
        }

        // 5. Finalize the commit scope.
        let commit = scope.finalize()?;

        // 6. Extract state digests from the finalized Commit.
        let commit_id = format_multihash(&commit.tr().0)?;
        let ar = format_multihash(commit.auth_root().as_multihash())?;
        let sr = format_multihash(commit.sr().as_multihash())?;
        let pr = format_multihash(commit.pr().as_multihash())?;

        // 7. Persist via the storage layer.
        let meta = IngestMeta {
            principal_id: principal_id.to_string(),
            commit_id,
            sequence: next_seq,
            pr,
            sr,
            ar,
            transaction_types,
            timestamp: last_timestamp,
        };

        self.ingest_commit(raw_blobs, meta)
    }

    /// Resolve genesis for a principal, auto-detecting from stored or submitted data.
    ///
    /// - If the principal already exists in storage, extracts key material
    ///   from the first stored commit's blobs.
    /// - If the principal is new, extracts key material from the first
    ///   submitted blob's `"key"` field.
    fn resolve_genesis(
        &self,
        principal_id: &str,
        raw_blobs: &[&[u8]],
    ) -> Result<crate::Genesis, EngineError> {
        // Check if the principal already exists.
        let chain = self
            .indexer
            .get_commit_chain(principal_id, Some(0), Some(0))?;

        if let Some(first_commit) = chain.first() {
            // Existing principal — extract genesis from the first stored blob.
            let first_hash = first_commit
                .blob_hashes
                .first()
                .ok_or_else(|| EngineError::InvalidInput("first commit has no blobs".into()))?;
            let data = self.blob_store.get(first_hash)?.ok_or_else(|| {
                EngineError::NotFound(format!("genesis blob {first_hash} not found in store"))
            })?;
            Self::genesis_from_blob(&data)
        } else {
            // New principal — extract genesis from the first submitted blob.
            Self::genesis_from_blob(raw_blobs[0])
        }
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

/// Format a [`MultihashDigest`] as a tagged digest string (`"alg:base64url"`).
///
/// Extracts the first algorithm variant and encodes its bytes. Used by
/// [`StorageEngine::submit_commit`] to serialize state roots for the index.
fn format_multihash(mh: &cyphr::multihash::MultihashDigest) -> Result<String, EngineError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let alg = mh
        .algorithms()
        .next()
        .ok_or_else(|| EngineError::InvalidInput("empty multihash".into()))?;
    let bytes = mh
        .first_variant()
        .map_err(|e| EngineError::InvalidInput(format!("multihash extract: {e}")))?;

    Ok(format!("{alg}:{}", Base64UrlUnpadded::encode_string(bytes)))
}

#[cfg(test)]
mod tests;
