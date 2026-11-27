//! # Write path
//!
//! Admission of commits and action bundles: the per-principal write lock,
//! verification against the principal's kept or replayed state, the I1
//! write order (blobs, manifest, log, index) and the durability latch that
//! refuses writes after a failed sync.

use std::sync::Arc;

use super::*;

/// What a manifest is assumed to add to the bytes a write is counted at,
/// beyond its blobs: the manifest is written after the check, so its size
/// is estimated.
const MANIFEST_SLACK_BYTES: u64 = 4096;

/// Result from [`StorageEngine::ingest_commit`] and
/// [`StorageEngine::submit_commit`].
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// The canonical (genesis-derived) id the commit was stored under, which
    /// may differ from the spelling the caller submitted. Read back under
    /// this id: a claimed alias can stop resolving once the commit moves
    /// the principal's state.
    pub principal_id: PrincipalGenesis,
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
    pub(super) fn of(commit: &IndexableCommit) -> Self {
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

/// Proof that the caller holds the write lock of one named principal:
/// built only by [`StorageEngine::lock_writes`] from that principal's own
/// lock, so another keyed lock (revoke, log generation, alias) cannot stand
/// for it.
pub(super) struct WriteLock<'a> {
    pub(super) principal: PrincipalGenesis,
    pub(super) _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl WriteLock<'_> {
    /// The one principal this lock is the write lock of.
    pub(super) fn principal(&self) -> &PrincipalGenesis {
        &self.principal
    }
}

/// A pushed bundle verified into the commit it forms, nothing yet written:
/// the commit's index record and the staged core commit whose log append
/// follows the blob store's record of it ([`StorageEngine::ingest_commit`]).
pub(crate) struct StagedBuild<'p, T: cyphr::eml::Storage> {
    pub(super) commit: IndexableCommit,
    pub(super) staged: cyphr::replay::StagedBundle<'p, T>,
    /// The embedded principals the commit was authorized through, set by
    /// the admission path that followed them; empty on a replay.
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// What a verified bundle forms ([`StorageEngine::build_staged`]).
pub(crate) enum Built<'p, T: cyphr::eml::Storage> {
    /// A commit, its log append not yet made.
    Commit(Box<StagedBuild<'p, T>>),
    /// Actions alone, verified and not yet held.
    Actions(cyphr::replay::StagedBundle<'p, T>),
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
pub(super) fn canonical_coz(blob: &[u8], i: usize) -> Result<Vec<u8>, EngineError> {
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
pub(super) fn canonical_bundle(bundle: &WireBundle) -> Result<WireBundle, EngineError> {
    let mut canonical = bundle.try_map(|i, blob| canonical_coz(blob, i))?;
    // The keys the canonical cozies name by `id`, unresolved: a `keys` entry
    // that is malformed is refused by the core with its own typed error
    // when the commit is verified, not dropped here.
    let mut named: std::collections::HashSet<String> = std::collections::HashSet::new();
    for blob in canonical.txs.iter().flatten() {
        let coz = cyphr::replay::StoredCoz::from_wire(blob).map_err(|e| match e {
            // The core's own refusal, as `decode_bundle` gives it: an
            // `alg` outside the table is `UnknownAlg`, not a malformed blob.
            cyphr::replay::WireError::Key(p) | cyphr::replay::WireError::Protocol(p) => {
                EngineError::Protocol(p)
            },
            other => EngineError::MalformedBlob(format!("a stored coz: {other}")),
        })?;
        if let Some(id) = coz.introduces() {
            named.insert(id.to_owned());
        }
    }
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

/// A peer's resync proofs for one principal and the chain they were served
/// beside: what [`StorageEngine::ingest_pulled`] offers the fork rule
/// (SPEC 15.8 item 2).
#[derive(Debug, Clone, Copy)]
pub struct ResyncOffer<'a> {
    /// The `{pay, sig}` proofs of possession.
    pub pops: &'a [serde_json::Value],
    /// The peer's chain, from which the line up to each asserted tip is
    /// taken, starting at the first commit this engine does not hold.
    pub chain: &'a [WireBundle],
}

/// What one pull handed over for one principal, in the order the engine
/// applies it ([`StorageEngine::ingest_pulled`]).
#[derive(Debug, Clone, Copy)]
pub struct PulledOffer<'a> {
    /// The genesis the principal's first commit is read against, when the
    /// caller holds one (a verifier that anchored on a key); `None` reads
    /// it from storage or the bundle.
    pub genesis: Option<&'a crate::Genesis>,
    /// The commits the pull verified past this engine's tip, in order.
    pub commits: &'a [WireBundle],
    /// Commits of other branches the peers served: refused as a tip, kept
    /// as evidence of the fork (I2) when they verify.
    pub branches: &'a [WireBundle],
    /// Resync proofs, each with the chain it was served beside.
    pub resyncs: &'a [ResyncOffer<'a>],
}

/// The engine's answer to one bundle of a [`PulledOffer`].
#[derive(Debug)]
pub struct BundleAnswer {
    /// Whether the answer is to the bundle offered together with the one
    /// after it: a branch commit the caps refused alone may be a line root
    /// whose extension changes the verdict (rule X).
    pub paired: bool,
    /// What the engine did with it.
    pub result: Result<IngestResult, EngineError>,
}

/// The engine's answers to a [`PulledOffer`], one per bundle and proof, in
/// the order offered. A refusal is an answer (a commit already held, a fork
/// kept as evidence); [`EngineError::is_store_fault`] names the ones that
/// are not.
#[derive(Debug, Default)]
pub struct PulledAnswers {
    pub commits: Vec<BundleAnswer>,
    pub branches: Vec<BundleAnswer>,
    pub resyncs: Vec<Result<crate::engine::ResyncReceipt, EngineError>>,
}

/// Per-principal serialization points for [`StorageEngine::submit_commit`].
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
#[derive(Debug, Default)]
pub(super) struct PrincipalLocks(
    std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
);

impl PrincipalLocks {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Fetch (or create) `principal_id`'s lock.
    pub(super) fn get(&self, principal_id: &PrincipalGenesis) -> Arc<tokio::sync::Mutex<()>> {
        self.keyed(principal_id.to_string())
    }

    /// Fetch (or create) the lock of a serialization point that is not a
    /// principal's: `name` carries a NUL, which no parsed principal id can.
    pub(super) fn named(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.keyed(name.to_owned())
    }

    fn keyed(&self, key: String) -> Arc<tokio::sync::Mutex<()>> {
        // A poisoned std Mutex means some prior holder of THIS lock panicked
        // while holding it. The critical section below is only a HashMap
        // entry/insert/clone on an owned String key -- no `.await`, no
        // user-controlled Hash/Eq impl, nothing that can panic -- so
        // poisoning here would imply a bug already crashing the server
        // elsewhere, not a condition adversarial request input can trigger.
        let mut locks = self.0.lock().expect("principal lock map poisoned");
        locks
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

/// Whether a record sync has failed, and the gate that orders syncs.
///
/// Set by the first failed [`StorageEngine::persist_record`], never
/// cleared: the engine refuses every write from then on
/// ([`EngineError::DurabilityLost`]). The gate is held for the whole of a
/// record sync and the flag changes around it, so a sync queued behind a
/// failed one finds the flag set instead of trusting a success over pages
/// the failure dropped.
#[derive(Debug, Default)]
pub(super) struct Durability {
    lost: std::sync::atomic::AtomicBool,
    sync_gate: tokio::sync::Mutex<()>,
}

impl Durability {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn lost(&self) -> bool {
        self.lost.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn mark_lost(&self) {
        self.lost.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Wait for the one sync in flight, if any, and hold the gate.
    pub(super) async fn one_sync(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.sync_gate.lock().await
    }
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Apply what a pull handed over for `principal_id`: the verified
    /// commits, then each branch commit, then the resync proofs. This is
    /// the one place a pulled bundle meets the engine, whoever pulled it.
    ///
    /// A commit is offered alone ([`Self::submit_commit`]). A branch commit
    /// a cap refuses alone ([`EngineError::BranchLimit`],
    /// [`EngineError::Errored`]) is offered again with the branch commit
    /// after it ([`Self::submit_pair`]); where none follows, the cap's answer
    /// stands. Each proof is offered with the line of its peer's chain from
    /// the first commit not held ([`Self::held_prefix`]).
    ///
    /// Revokes are not applied here: a caller records the verified revokes
    /// it holds first, where it keeps its own death store ([`Self::record_revoke`]), so
    /// admission refuses what a dead key signed after its death.
    ///
    /// Nothing here fails the call: each bundle's answer is returned for the
    /// caller to log or to treat as a fault.
    pub async fn ingest_pulled(
        &self,
        principal_id: &PrincipalGenesis,
        offer: &PulledOffer<'_>,
    ) -> PulledAnswers {
        let genesis = || offer.genesis.cloned();
        let mut answers = PulledAnswers::default();
        for bundle in offer.commits {
            answers.commits.push(BundleAnswer {
                paired: false,
                result: self.submit_commit(principal_id, genesis(), bundle).await,
            });
        }
        for (i, bundle) in offer.branches.iter().enumerate() {
            let alone = self.submit_commit(principal_id, genesis(), bundle).await;
            let answer = match (alone, offer.branches.get(i + 1)) {
                (
                    Err(EngineError::BranchLimit { .. } | EngineError::Errored { .. }),
                    Some(next),
                ) => BundleAnswer {
                    paired: true,
                    result: self
                        .submit_pair(principal_id, genesis(), bundle, next)
                        .await,
                },
                (result, _) => BundleAnswer {
                    paired: false,
                    result,
                },
            };
            answers.branches.push(answer);
        }
        for resync in offer.resyncs {
            let start = self
                .held_prefix(principal_id, resync.chain)
                .await
                .unwrap_or(resync.chain.len());
            for pop in resync.pops {
                answers.resyncs.push(
                    self.submit_resync(principal_id, pop, &resync.chain[start..])
                        .await,
                );
            }
        }
        answers
    }

    /// Fetch (or create) this `principal_id`'s serialization point.
    ///
    /// Never blocks on a write: only ever holds the map's own lock for the
    /// duration of a `HashMap` lookup/insert, not across any `.await`.
    pub(super) fn principal_lock(
        &self,
        principal_id: &PrincipalGenesis,
    ) -> Arc<tokio::sync::Mutex<()>> {
        self.principal_locks.get(principal_id)
    }

    /// Fetch (or create) the serialization point named `name`, for work
    /// that is not one principal's ([`PrincipalLocks::named`]).
    pub(super) fn named_lock(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.principal_locks.named(name)
    }

    /// Take `principal_id`'s write lock, `lock` being its own entry of
    /// [`Self::principal_lock`].
    pub(super) async fn lock_writes<'a>(
        lock: &'a Arc<tokio::sync::Mutex<()>>,
        principal_id: &PrincipalGenesis,
    ) -> WriteLock<'a> {
        WriteLock {
            principal: principal_id.clone(),
            _guard: lock.lock().await,
        }
    }

    /// [`Self::lock_writes`] if the lock is free now, `None` if it is held.
    pub(super) fn try_lock_writes<'a>(
        lock: &'a Arc<tokio::sync::Mutex<()>>,
        principal_id: &PrincipalGenesis,
    ) -> Option<WriteLock<'a>> {
        Some(WriteLock {
            principal: principal_id.clone(),
            _guard: lock.try_lock().ok()?,
        })
    }

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
    pub(super) async fn store_blobs_and_manifest(
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
    pub(super) async fn store_manifest(
        &self,
        bundle: &WireBundle,
        mut commit: IndexableCommit,
        prefix: &[u8],
        kind: &str,
        seen: Option<i64>,
        embedded: &[EmbeddedPin],
    ) -> Result<(IndexableCommit, Blake3Hash), EngineError> {
        // Before anything is written, so a refusal leaves no blob behind.
        self.ensure_room(
            bundle
                .cozies()
                .map(|b| u64::try_from(b.len()).unwrap_or(u64::MAX))
                .fold(MANIFEST_SLACK_BYTES, u64::saturating_add),
        )?;
        // Store each blob, in bundle order.
        let mut blob_hashes = Vec::with_capacity(commit.cozies.len());
        for (i, blob) in bundle.cozies().enumerate() {
            let hash = self.put_counted(blob).await?;
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
        let manifest_hash = self.put_counted(&manifest_bytes).await?;
        commit.manifest = Some(manifest_hash);
        // The key a commit revokes is dead from its receipt, whichever
        // branch the commit is kept on. Noted here, where the record that
        // derives it is written, so a rebuild reaches the same set; the
        // caller's sync follows, and an engine whose sync fails refuses
        // every write until it restarts and re-derives the set.
        for tmb in self_revoked_keys(&commit) {
            self.deaths.note(
                tmb.to_owned(),
                Death::new(seen.unwrap_or_default(), *manifest_hash.as_bytes()),
            );
        }

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
    pub(super) async fn persist_record(&self) -> Result<(), EngineError> {
        let _one_sync = self.durability.one_sync().await;
        self.writable()?;
        if let Err(e) = self.blob_store.persist().await {
            self.durability.mark_lost();
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
        self.durability.lost()
    }

    /// `Err` once a record sync has failed ([`Self::persist_record`]).
    /// Checked before a write stores anything, so a failed engine adds
    /// nothing to the record.
    pub(super) fn writable(&self) -> Result<(), EngineError> {
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
    pub(super) async fn ingest<T: cyphr::eml::Storage>(
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
        principal_id: &PrincipalGenesis,
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
        principal_id: &PrincipalGenesis,
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

    pub(super) async fn submit_commit_with(
        &self,
        principal_id: &PrincipalGenesis,
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
        let (genesis, new_key) = match stored.as_ref() {
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
                let names_key = key.as_ref().is_some_and(|key| claimed == key);
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
        let principal_id = &canonical;

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
                        principal_id: principal_id.clone(),
                    });
                },
                Ok(Built::Commit(build)) => build,
                Ok(Built::Actions(_)) if errored.is_some() => {
                    return Err(EngineError::Errored {
                        principal_id: principal_id.clone(),
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
                            principal_id: principal_id.clone(),
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
                            principal_id: principal_id.clone(),
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
    pub(super) fn verified<'a>(
        &'a self,
        principal_id: &'a PrincipalGenesis,
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
    pub(super) fn keep(
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
    pub(super) async fn resume_kept(
        &self,
        principal_id: &PrincipalGenesis,
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
    pub(super) async fn resume_over_log(
        &self,
        principal_id: &PrincipalGenesis,
        state: cyphr::PrincipalState,
    ) -> Option<cyphr::Principal<S>> {
        let generation = self.logs.generation(principal_id).ok()?;
        let storage = self.logs.open(principal_id, generation).ok()?;
        cyphr::Principal::resume(state, storage).await.ok()
    }

    /// Whether any commit or held action bundle of `principal_id` was
    /// admitted through an embedded principal ([`EmbeddedPin`]).
    pub(super) async fn history_has_pins(
        &self,
        principal_id: &PrincipalGenesis,
    ) -> Result<bool, EngineError> {
        if self.actions.has_pins(principal_id) {
            return Ok(true);
        }
        let chain = self.chain(principal_id, None, None).await?;
        for commit in &chain {
            if self
                .frame(commit)
                .await?
                .is_none_or(|f| !f.embedded.is_empty())
            {
                return Ok(true);
            }
        }
        Ok(false)
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
    pub(super) fn follow_held<'a, T: cyphr::eml::Storage + Send>(
        &'a self,
        own_id: &'a PrincipalGenesis,
        principal: &'a mut cyphr::Principal<T>,
        bundle: &'a WireBundle,
        held: &'a mut HeldCache<S>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<EmbeddedPin>, EngineError>> + Send + 'a>,
    > {
        Box::pin(self.follow_held_unboxed(own_id, principal, bundle, held))
    }

    pub(super) async fn follow_held_unboxed<T: cyphr::eml::Storage>(
        &self,
        own_id: &PrincipalGenesis,
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
    pub(super) fn held_tip<'a>(
        &'a self,
        member: &'a str,
        own_id: &'a PrincipalGenesis,
    ) -> HeldRead<'a, S> {
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
    pub(super) async fn store_actions(
        &self,
        principal_id: &PrincipalGenesis,
        blobs: &[Vec<u8>],
        embedded: &[EmbeddedPin],
    ) -> Result<Vec<Blake3Hash>, EngineError> {
        self.ensure_room(
            blobs
                .iter()
                .map(|b| u64::try_from(b.len()).unwrap_or(u64::MAX))
                .fold(MANIFEST_SLACK_BYTES, u64::saturating_add),
        )?;
        let mut blob_hashes = Vec::with_capacity(blobs.len());
        for blob in blobs {
            blob_hashes.push(self.put_counted(blob).await?);
        }
        let manifest = ActionManifest {
            kind: ACTION_MANIFEST_KIND.to_string(),
            principal_id: principal_id.clone(),
            blob_hashes: blob_hashes.clone(),
            embedded: embedded.to_vec(),
        };
        let mut bytes = ACTION_MANIFEST_PREFIX.to_vec();
        serde_json::to_writer(&mut bytes, &manifest)
            .map_err(|e| EngineError::MalformedBlob(format!("action manifest serialize: {e}")))?;
        let hash = self.put_counted(&bytes).await?;
        // The push is answered 201 with these hashes, which tells the caller
        // the actions are recorded: durable before they are listed or the
        // answer is built.
        self.persist_record().await?;
        self.actions.add(
            principal_id,
            StoredActions {
                manifest: hash,
                blobs: blob_hashes.clone(),
                embedded: embedded.to_vec(),
            },
        );
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
    pub(super) async fn build_commit<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &PrincipalGenesis,
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
    pub(super) async fn build_staged<'p, T: cyphr::eml::Storage>(
        principal: &'p mut cyphr::Principal<T>,
        bundle: &WireBundle,
        principal_id: &PrincipalGenesis,
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
            Some(pg) if !had_pg => variant_ids(pg.as_multihash())?,
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
            principal_id: principal_id.clone(),
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
            manifest: None,
        };

        Ok(Built::Commit(Box::new(StagedBuild {
            commit,
            staged,
            embedded: Vec::new(),
        })))
    }

    /// The per-alias locks guarding the PG claims of `commits`, in sorted
    /// order so contenders cannot deadlock. The caller locks each.
    pub(super) fn alias_locks(
        &self,
        commits: &[&IndexableCommit],
    ) -> Vec<Arc<tokio::sync::Mutex<()>>> {
        let mut aliases: Vec<String> = commits
            .iter()
            .flat_map(|c| &c.pg)
            .map(|pg| format!("pg-alias\0{pg}"))
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        aliases.iter().map(|a| self.named_lock(a)).collect()
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
pub(super) fn authenticated_signers(
    bundle: &WireBundle,
    tip: &cyphr::PrincipalState,
    retained: &[KeyEntry],
) -> Option<Vec<coz::Thumbprint>> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let decoded = bundle.decode().ok()?;
    // The keys of the bundle's signers: those the principal has held, and
    // those a principal it embeds has held (SPEC 10.3), by the views `tip`
    // holds of them. A key known to the store for some other principal is
    // nobody's here: a stranger's signature authenticates nothing, however
    // well the store knows the stranger.
    let mut history: HashMap<String, (String, Vec<u8>)> = HashMap::new();
    for named in decoded.named_keys() {
        let tmb = named.to_b64();
        if let Some(key) = tip
            .key_ever_held(&named)
            .or_else(|| tip.embedded_key_ever_held(&named))
        {
            history.insert(tmb, (key.alg().to_owned(), key.pub_key().to_vec()));
        } else if let Some(k) = retained.iter().find(|k| k.tmb == tmb)
            && let Ok(public) = Base64UrlUnpadded::decode_vec(&k.pub_key)
        {
            history.insert(tmb, (k.alg.clone(), public));
        }
    }

    let mut signers = Vec::new();
    // Keys this bundle introduces: they are not held at any `pre`, so
    // they are not signers retention looks for there.
    let mut introduced: std::collections::HashSet<String> = std::collections::HashSet::new();
    for coz in decoded.cozies() {
        let header = coz.header();
        let (alg, public) = history.get(&header.tmb.to_b64())?;
        if coz::verify_json(coz.pay_json(), coz.sig(), alg, public) != Some(true) {
            return None;
        }
        // A key a verified coz of this bundle introduces (`key/create`,
        // `key/replace`) may sign the cozies after it, as its own commit
        // does when it finalizes a rotation; the bundle discloses it, bound
        // to the `id` by its thumbprint. A key the principal already held
        // is no new signer.
        if let Some(key) = decoded.introduced_key(coz) {
            let id = key.tmb().to_b64();
            if !history.contains_key(&id) {
                history.insert(id.clone(), (key.alg().to_owned(), key.pub_key().to_vec()));
                introduced.insert(id);
            }
        }
        if coz.is_transaction() && !introduced.contains(&header.tmb.to_b64()) {
            signers.push(header.tmb.clone());
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
pub(super) fn disclosed_genesis(
    bundle: &WireBundle,
) -> Option<Result<crate::Genesis, EngineError>> {
    // A bundle that does not decode discloses nothing: the admission or the
    // replay that follows names what is malformed.
    let decoded = bundle.decode().ok()?;
    let keys = match decoded.genesis_keys()? {
        Ok(keys) => keys,
        Err(_) => {
            return Some(Err(EngineError::MalformedBlob(
                "a genesis key/create discloses no key".into(),
            )));
        },
    };
    match keys.as_slice() {
        [] => None,
        [only] => Some(Ok(crate::Genesis::Implicit((*only).clone()))),
        _ => Some(Ok(crate::Genesis::Disclosed(
            keys.into_iter().cloned().collect(),
        ))),
    }
}

/// The refusal of a first bundle that discloses no genesis.
pub(super) fn no_disclosed_genesis() -> EngineError {
    EngineError::MalformedBlob(
        "the first commit is no genesis commit: no key/create before a principal/create discloses \
         its keys (SPEC 5.1)"
            .into(),
    )
}

/// The key that signed a stored commit's bundle: [`commit_signer`] of the
/// commit the bundle forms.
pub(super) fn bundle_signer(bundle: &WireBundle) -> Result<String, EngineError> {
    Ok(decode_bundle(bundle)?
        .commit_signer()
        .map(|tmb| tmb.to_b64())
        .unwrap_or_default())
}

/// The storage key a principal's first bundle derives, a
/// function of the record alone (I1). A genesis commit (SPEC 5.1) keys it
/// by its PG, in the spelling of [`genesis_principal_id`] (the first active
/// algorithm); the PG is the state at `principal/create`, so a nonce in the
/// genesis commit already makes it unique (5.1: "a nonce embedding for a
/// unique PG"). A bundle of data actions alone forms no commit: a Level 1/2
/// principal is keyed by its genesis PR. `None` when the bundle does not
/// replay.
pub(super) async fn record_key(
    genesis: &crate::Genesis,
    bundle: &WireBundle,
) -> Option<PrincipalGenesis> {
    let principal = replay_first(genesis, bundle).await?;
    let Some(pg) = principal.pg() else {
        return (principal.commits().next().is_none())
            .then(|| genesis_principal_id(genesis).ok())
            .flatten();
    };
    let alg = principal.active_algs().first().copied()?;
    let digest = pg.as_multihash().get(alg)?;
    PrincipalGenesis::from_digest(alg, digest.to_vec()).ok()
}

/// Whether `bundle` carries a `principal/create`: a genesis commit (SPEC
/// 5.1).
pub(super) fn is_genesis_bundle(bundle: &WireBundle) -> bool {
    bundle.txs.iter().flatten().any(|blob| {
        serde_json::from_slice::<serde_json::Value>(blob)
            .ok()
            .and_then(|v| v.pointer("/pay/typ")?.as_str().map(str::to_owned))
            .is_some_and(|typ| {
                cyphr::parsed_coz::typ::has_suffix(&typ, cyphr::parsed_coz::typ::PRINCIPAL_CREATE)
            })
    })
}

/// A canonical bundle decoded for the core.
pub(super) fn decode_bundle(bundle: &WireBundle) -> Result<cyphr::replay::Bundle, EngineError> {
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
