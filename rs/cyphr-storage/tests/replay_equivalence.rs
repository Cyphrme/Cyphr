//! Replay equivalence: one stored commit means one thing on every path.
//!
//! The core's public replay entry point (`cyphr::replay`), the engine's
//! ingest (`submit_commit`) and the engine's rebuild from blobs alone
//! (`rebuild_index_from_scratch`) must reach the same roots and the same
//! Data Tree for every chain of the golden corpus, data actions pushed on
//! their own included, and the rebuild must trust no manifest it cannot
//! replay (root `AGENTS.md` I1: the blob store is the only source of
//! truth).

use std::path::PathBuf;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr::replay::{StoredCoz, WireBundle, replay_bundle};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{
    ACTION_MANIFEST_PREFIX, COMMIT_MANIFEST_PREFIX, QuarantineReason, StorageEngine,
    genesis_principal_id,
};
use cyphr_storage::index::{Indexer, MemoryIndexer};

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

/// One corpus chain, as stored: its genesis and each commit's wire blobs.
struct Chain {
    name: String,
    genesis: Genesis,
    bundles: Vec<WireBundle>,
    expected_pr: String,
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden")
}

fn domain_key(gk: &serde_json::Value) -> cyphr::Key {
    let field = |f: &str| {
        Base64UrlUnpadded::decode_vec(gk[f].as_str().expect("key field")).expect("base64url")
    };
    cyphr::Key::new(
        gk["alg"].as_str().expect("alg"),
        coz::Thumbprint::from_bytes(field("tmb")),
        field("pub"),
    )
    .expect("key binds its tmb")
}

/// Every corpus chain a fresh principal can replay: vectors that expect an
/// error, or need a setup step or an embedded principal's tip no stored
/// chain carries, are left out.
fn corpus() -> Vec<Chain> {
    let mut chains = Vec::new();
    let mut categories: Vec<_> = std::fs::read_dir(golden_dir())
        .expect("golden dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.is_dir() && !p.ends_with("errors"))
        .collect();
    categories.sort();
    for category in categories {
        let mut files: Vec<_> = std::fs::read_dir(&category)
            .expect("category dir")
            .map(|e| e.expect("entry").path())
            .collect();
        files.sort();
        for path in files {
            let golden: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
            let (Some(commits), Some(genesis_keys), Some(pr)) = (
                golden["commits"].as_array(),
                golden["genesis_keys"].as_array(),
                golden["expected"]["pr"].as_str(),
            ) else {
                continue;
            };
            // QUARANTINE(#200): an embedded-member vector needs the
            // embedded principal's tip, which no stored chain carries, and
            // the engine refuses such a commit as `EmbeddedUnsupported`
            // until replay can resolve embedded principals (GitHub #200).
            let embedded = golden["peer"]["embedded"].as_bool() == Some(true);
            if golden.get("setup").is_some()
                || embedded
                || golden["expected"].get("error").is_some()
                || commits.is_empty()
            {
                continue;
            }
            let keys: Vec<cyphr::Key> = genesis_keys.iter().map(domain_key).collect();
            let implicit = keys.len() == 1;
            let genesis = if implicit {
                Genesis::Implicit(keys[0].clone())
            } else {
                Genesis::Disclosed(keys)
            };
            // Each line is pushed as the bundle it is: a commit, or one data
            // action on its own (SPEC 4.8.1: actions are not chained).
            let bundles = commits.iter().map(wire_blobs).collect();
            chains.push(Chain {
                name: path.display().to_string(),
                genesis,
                bundles,
                expected_pr: pr.to_string(),
            });
        }
    }
    chains
}

/// A golden commit line as the wire carries it (SPEC 4.6.2): `txs` by
/// transaction, the keys they introduce in `keys`, data actions in
/// `actions`. A chain's first commit is its genesis commit, whose
/// `key/create`s name its keys, so a rebuild reads the genesis from the
/// stored record alone.
fn wire_blobs(commit: &serde_json::Value) -> WireBundle {
    serde_json::from_value::<cyphr_storage::CommitEntry>(commit.clone())
        .expect("golden line")
        .bundle()
        .expect("bundle")
}

/// `bundle` decoded and replayed onto `p` through the core's entry point.
async fn core_replay(
    p: &mut cyphr::Principal,
    bundle: &WireBundle,
) -> Result<cyphr::replay::BundleId, cyphr::replay::ReplayError> {
    replay_bundle(p, &bundle.decode().expect("wire bundle")).await
}

async fn principal(genesis: &Genesis) -> cyphr::Principal {
    cyphr::Principal::implicit(genesis.key().expect("genesis key").clone())
        .await
        .expect("genesis")
}

/// The id the engine stores `chain` under, derived by the core alone: the
/// PG its genesis commit establishes (a nonce in it is part of the PG). A
/// chain of data actions alone forms no commit and is keyed by its genesis
/// PR.
async fn principal_id(chain: &Chain) -> String {
    let mut p = principal(&chain.genesis).await;
    core_replay(&mut p, &chain.bundles[0])
        .await
        .expect("first commit replays");
    match p.pg() {
        Some(pg) => {
            let alg = p.active_algs()[0];
            format!(
                "{alg}:{}",
                Base64UrlUnpadded::encode_string(pg.as_multihash().get(alg).expect("pg variant"))
            )
        },
        None => genesis_principal_id(&chain.genesis).expect("principal id"),
    }
}

async fn ingest(engine: &Engine, chain: &Chain) -> String {
    let id = principal_id(chain).await;
    for (i, bundle) in chain.bundles.iter().enumerate() {
        engine
            .submit_commit(&id, Some(chain.genesis.clone()), bundle)
            .await
            .unwrap_or_else(|e| panic!("{}: engine ingests commit {i}: {e}", chain.name));
    }
    id
}

/// Claim: for every chain of the golden corpus, replay through the core's
/// public entry point, engine ingest, and a rebuild of the index from the
/// blob store alone all reach the PR the vector records; the engine indexes
/// each commit's TR under every algorithm the core computed it in (so
/// mixed-algorithm chains keep every variant), its CR is the core's, and
/// the rebuilt index equals the one ingest built.
///
/// Turns red if: the engine or the core classifies or orders a bundle's
/// cozies differently from the other; ingest drops a TR variant; or the
/// rebuild indexes anything other than what ingest did.
/// End-to-end scenario: yes (the whole corpus through engine ingest and
/// recovery).
#[test]
fn corpus_chains_agree_across_core_ingest_and_rebuild() {
    let chains = corpus();
    assert!(chains.len() > 30, "the corpus was found ({})", chains.len());
    // Each chain has its own store, so they are checked on parallel
    // threads: the 256-item arity vectors would otherwise serialize the
    // run (minutes in a debug build).
    std::thread::scope(|s| {
        for chain in &chains {
            s.spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime")
                    .block_on(check_chain(chain));
            });
        }
    });
}

async fn check_chain(chain: &Chain) {
    {
        let mut core = principal(&chain.genesis).await;
        for (i, bundle) in chain.bundles.iter().enumerate() {
            core_replay(&mut core, bundle)
                .await
                .unwrap_or_else(|e| panic!("{}: core replays commit {i}: {e}", chain.name));
        }
        assert_eq!(
            core.pr_tagged().expect("pr"),
            chain.expected_pr,
            "{}: core replay reaches the recorded PR",
            chain.name
        );

        // One store per chain: corpus vectors share genesis keys, so their
        // principals would collide in one store.
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        if core.commits().next().is_none() {
            // A chain of data actions alone has no genesis commit, and
            // commits (and what they include) start at it (be0663f 2.3.2):
            // the engine refuses each bundle and records nothing.
            let id = principal_id(chain).await;
            for (i, bundle) in chain.bundles.iter().enumerate() {
                let refused = engine
                    .submit_commit(&id, Some(chain.genesis.clone()), bundle)
                    .await;
                assert!(
                    matches!(
                        refused,
                        Err(cyphr_storage::engine::EngineError::Protocol(
                            cyphr::Error::GenesisIncomplete
                        ))
                    ),
                    "{}: bundle {i} before any genesis commit: {refused:?}",
                    chain.name
                );
            }
            assert!(
                engine.get_tip(&id).await.expect("tip").is_none(),
                "{}: no commit, no tip",
                chain.name
            );
            return;
        }
        let id = ingest(&engine, chain).await;
        same_history(&engine, &id, chain, &core, "ingest").await;
        let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
        // The tip is the last commit's; actions after it are in DT only and
        // form no commit.
        let last = core.commits().last().expect("a commit");
        let last_pr = last.pr().0.tagged_first().expect("pr").to_string();
        assert_eq!(tip.pr, last_pr, "{}: ingest PR", chain.name);
        let core_cr = core
            .cr()
            .map(|cr| cr.as_multihash().tagged_first().expect("cr").to_string());
        assert_eq!(Some(tip.cr.clone()), core_cr, "{}: ingest CR", chain.name);
        for commit in core.commits() {
            let tr = &commit.tr().0;
            for alg in tr.algorithms() {
                let digest = tr.tagged(alg).expect("tagged tr");
                assert!(
                    engine
                        .indexer()
                        .resolve_digest_holders(&digest)
                        .await
                        .expect("holders")
                        .iter()
                        .any(|h| h.principal_id.as_deref() == Some(id.as_str())),
                    "{}: TR variant {digest} is indexed",
                    chain.name
                );
            }
        }

        let before = engine
            .indexer()
            .get_commit_chain(&id, None, None)
            .await
            .expect("chain");
        let report = engine
            .rebuild_index_from_scratch_with_report()
            .await
            .expect("rebuild");
        assert!(
            report.quarantined.is_empty(),
            "{}: an honest store rebuilds whole: {:?}",
            chain.name,
            report.quarantined
        );
        let after = engine
            .indexer()
            .get_commit_chain(&id, None, None)
            .await
            .expect("chain");
        assert_eq!(
            after, before,
            "{}: the rebuilt index equals the ingest index",
            chain.name
        );
        same_history(&engine, &id, chain, &core, "rebuild").await;
    }
}

/// What a replay must agree on: the PR, every commit's TR, and each data
/// action with the number of commits recorded before it (so DT, and the DR
/// a `ds/create` includes, at every point of the history).
fn history(p: &cyphr::Principal) -> (String, Vec<String>, Vec<(String, usize)>) {
    (
        p.pr_tagged().expect("pr"),
        p.commits()
            .map(|c| c.tr().0.tagged_first().expect("tr").to_string())
            .collect(),
        p.actions()
            .map(|a| (a.czd().to_b64(), a.recorded_after()))
            .collect(),
    )
}

/// The principal the engine replays from its store holds `core`'s history.
async fn same_history(
    engine: &Engine,
    id: &str,
    chain: &Chain,
    core: &cyphr::Principal,
    path: &str,
) {
    let loaded = engine
        .load_principal(id, chain.genesis.clone())
        .await
        .unwrap_or_else(|e| panic!("{}: {path}: the stored principal replays: {e}", chain.name));
    assert_eq!(
        history(&loaded),
        history(core),
        "{}: {path}: the same history, actions included",
        chain.name
    );
}

/// Ingest a corpus chain of a genesis commit and three more into an honest
/// store, then copy every
/// blob into `forged_store`, replacing the manifest of commit 1 with one
/// that records commit 0's PR for the same blobs. Returns the principal id
/// and commit 0's PR.
async fn forge_into(forged_store: &impl BlobStore) -> (String, String) {
    let chain = corpus()
        .into_iter()
        .find(|c| c.name.ends_with("transaction_sequence_replay.json"))
        .expect("a three-commit chain");
    let honest = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let id = ingest(&honest, &chain).await;
    let held = honest
        .indexer()
        .get_commit_chain(&id, None, None)
        .await
        .expect("chain");
    assert_eq!(held.len(), 4, "the genesis commit and three");

    let mut forged = false;
    for hash in honest.blob_store().iter().await.expect("iter") {
        let hash = hash.expect("hash");
        let data = honest
            .blob_store()
            .get(&hash)
            .await
            .expect("get")
            .expect("blob");
        let data = match data.strip_prefix(COMMIT_MANIFEST_PREFIX) {
            Some(json) => {
                let mut manifest: serde_json::Value = serde_json::from_slice(json).expect("json");
                if manifest["commit"]["sequence"] == 1 {
                    manifest["commit"]["prs"] = serde_json::json!([held[0].pr]);
                    forged = true;
                }
                [
                    COMMIT_MANIFEST_PREFIX,
                    &serde_json::to_vec(&manifest).expect("json"),
                ]
                .concat()
            },
            None => data,
        };
        forged_store.put(&data).await.expect("put");
    }
    assert!(forged, "the commit-1 manifest was found");
    (id, held[0].pr.clone())
}

/// Claim: the rebuild from scratch trusts no manifest it cannot replay: a
/// store whose manifest for a commit records roots its blobs do not yield
/// (the honest manifest replaced by a forged one naming the same blobs) has
/// that manifest quarantined, the chain's later commits orphaned, and the
/// principal's tip is the last commit that replays, never the forged roots.
///
/// Turns red if: the rebuild indexes a manifest's recorded roots without
/// replaying its blobs (the pre-replay rebuild trusted engine-written
/// manifests).
/// End-to-end scenario: yes (ingest, forged store, recovery).
#[tokio::test]
async fn forged_manifest_is_quarantined_by_the_scratch_rebuild() {
    let forged_store = MemoryBlobStore::new();
    let (id, held_pr) = forge_into(&forged_store).await;

    let recovered = StorageEngine::new(forged_store, MemoryIndexer::new());
    let report = recovered
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    let reasons: Vec<_> = report
        .quarantined
        .iter()
        .filter(|q| q.principal_id.as_deref() == Some(id.as_str()))
        .map(|q| &q.reason)
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, QuarantineReason::Unreplayable(_))),
        "the forged manifest is quarantined as unreplayable: {reasons:?}"
    );
    let tip = recovered.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        (tip.commit_count, tip.pr.as_str()),
        (1, held_pr.as_str()),
        "the chain is indexed up to the last commit that replays"
    );
}

/// Claim: what the scratch rebuild quarantined stays out of the index when
/// a fresh engine opens on the same durable store: the startup heal pass,
/// which does not replay, skips the manifests the last scratch rebuild
/// quarantined instead of trusting them again.
///
/// Turns red if: the quarantine set lives only in the rebuilding process,
/// so the next start's heal pass re-indexes the forged manifest.
/// End-to-end scenario: yes (forged durable store, scratch rebuild,
/// restart on the same files).
#[tokio::test]
async fn scratch_quarantine_survives_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let open = || {
        let db = fjall::Database::builder(dir.path().join("db"))
            .open()
            .expect("open db");
        let blobs = cyphr_blob_fjall::FjallBlobStore::from_database(db).expect("blob store");
        let index =
            cyphr_index_fjall::FjallIndexer::open(&dir.path().join("index")).expect("open index");
        StorageEngine::new(blobs, index)
    };

    let first = open();
    let (id, held_pr) = forge_into(first.blob_store()).await;
    first
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    drop(first);

    let restarted = open();
    let tip = restarted.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        (tip.commit_count, tip.pr.as_str()),
        (1, held_pr.as_str()),
        "the restart's heal pass keeps the scratch rebuild's quarantine"
    );
}

/// An [`Indexer`] over a shared [`MemoryIndexer`] whose `index_commit`
/// fails once `clear` has run while armed: a crash after a scratch rebuild
/// cleared the index and before it indexed anything.
struct FailsAfterClear {
    inner: std::sync::Arc<MemoryIndexer>,
    armed: bool,
    cleared: std::sync::atomic::AtomicBool,
}

impl Indexer for FailsAfterClear {
    fn get_tip(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<Option<cyphr_storage::index::TipState>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.get_tip(id)
    }

    fn is_pg_established(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<bool, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.is_pg_established(id)
    }

    fn get_commit_chain(
        &self,
        id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl std::future::Future<Output = Result<Vec<cyphr_storage::index::CommitRef>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.get_commit_chain(id, from, to)
    }

    fn resolve_digest(
        &self,
        digest: &cyphr::state::TaggedDigest,
    ) -> impl std::future::Future<Output = Result<Option<cyphr_storage::index::EntityRef>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.resolve_digest(digest)
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<cyphr_storage::index::PrincipalSummary>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.list_principals()
    }

    fn is_blob_indexed(
        &self,
        hash: &cyphr_storage::blob::Blake3Hash,
    ) -> impl std::future::Future<Output = Result<bool, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.is_blob_indexed(hash)
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl std::future::Future<Output = Result<Option<cyphr_storage::index::PublicKeyInfo>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.get_key(thumbprint)
    }
}

impl cyphr_storage::index::IndexerWrite for FailsAfterClear {
    fn check_commit(
        &self,
        commit: &cyphr_storage::index::IndexableCommit,
        token: &cyphr_storage::index::DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.check_commit(commit, token)
    }

    fn index_commit(
        &self,
        commit: &cyphr_storage::index::IndexableCommit,
        token: &cyphr_storage::index::DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), cyphr_storage::index::IndexerError>> + Send
    {
        let fail = self.armed && self.cleared.load(std::sync::atomic::Ordering::SeqCst);
        let inner = self.inner.index_commit(commit, token);
        async move {
            if fail {
                return Err(cyphr_storage::index::IndexerError::Backend(
                    "injected fault after the clear".into(),
                ));
            }
            inner.await
        }
    }

    fn replace_chain_from(
        &self,
        id: &str,
        sequence: u64,
        commits: &[cyphr_storage::index::IndexableCommit],
        token: &cyphr_storage::index::DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.replace_chain_from(id, sequence, commits, token)
    }

    fn clear(
        &self,
        token: &cyphr_storage::index::DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), cyphr_storage::index::IndexerError>> + Send
    {
        self.cleared
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.clear(token)
    }

    fn set_quarantined(
        &self,
        manifests: &[(cyphr_storage::blob::Blake3Hash, String)],
        token: &cyphr_storage::index::DeriveToken,
    ) -> impl std::future::Future<Output = Result<(), cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.set_quarantined(manifests, token)
    }

    fn quarantined(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<(cyphr_storage::blob::Blake3Hash, String)>, cyphr_storage::index::IndexerError>> + Send
    {
        self.inner.quarantined()
    }
}

/// Claim (architect ruling: the scratch rebuild writes its quarantine set
/// before it clears the index): a rebuild that fails after the clear and
/// before it re-indexes leaves a store whose next start does not index the
/// manifest the rebuild would have quarantined. Scenario: a store holding a
/// forged manifest (no earlier scratch rebuild, so no earlier set), a scratch
/// rebuild that fails once the index is cleared, then a fresh engine on the
/// same blobs and index: its heal pass, which trusts manifests but honours
/// the quarantine set, indexes the chain only up to the last commit that
/// replays.
///
/// Turns red if: the set is written only after the re-index, so the restart
/// heals the forged manifest back in. End-to-end scenario: yes (forged
/// store, failing rebuild, restart on the same files).
#[tokio::test]
async fn quarantine_is_written_before_the_index_is_cleared() {
    let blobs = MemoryBlobStore::new();
    let (id, held_pr) = forge_into(&blobs).await;
    let index = std::sync::Arc::new(MemoryIndexer::new());
    let engine = |armed| {
        StorageEngine::new(
            blobs.clone(),
            FailsAfterClear {
                inner: index.clone(),
                armed,
                cleared: std::sync::atomic::AtomicBool::new(false),
            },
        )
    };

    let rebuild = engine(true).rebuild_index_from_scratch_with_report().await;
    assert!(rebuild.is_err(), "the injected fault stops the rebuild");

    let tip = engine(false)
        .get_tip(&id)
        .await
        .expect("tip")
        .expect("a tip");
    assert_eq!(
        (tip.commit_count, tip.pr.as_str()),
        (1, held_pr.as_str()),
        "the restart's heal pass kept the forged manifest out"
    );
}

/// A pool key that signs: its domain key and raw key material.
struct Signer {
    key: cyphr::Key,
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
}

fn signer(name: &str) -> Signer {
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let pk = pool.get(name).expect("pool key");
    let decode = |v: &str| Base64UrlUnpadded::decode_vec(v).expect("base64url");
    let pub_key = decode(&pk.pub_key);
    Signer {
        key: cyphr::Key::new(
            pk.alg.clone(),
            pk.compute_tmb().expect("tmb"),
            pub_key.clone(),
        )
        .expect("key binds its tmb"),
        alg: pk.alg.clone(),
        prv: decode(pk.prv.as_deref().expect("prv")),
        pub_key,
    }
}

impl Signer {
    /// Sign `pay` (fields already in canonical, sorted order).
    fn sign(&self, pay: &serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        let bytes = serde_json::to_vec(pay).expect("pay json");
        let (sig, cad) = coz::sign_json(&bytes, &self.alg, &self.prv, &self.pub_key).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &self.alg).expect("czd");
        (bytes, sig, czd)
    }

    /// The wire blob `{pay, sig}` of `pay`.
    fn blob(&self, pay: &serde_json::Value) -> Vec<u8> {
        let (_, sig, _) = self.sign(pay);
        let coz = serde_json::json!({ "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) });
        serde_json::to_vec(&coz).expect("json")
    }

    /// Record a data action on `writer`; returns its wire blob.
    fn action(&self, writer: &mut cyphr::Principal, now: i64) -> Vec<u8> {
        let pay = serde_json::json!({
            "alg": self.alg, "now": now, "tmb": self.key.tmb().to_b64(),
            "typ": "cyphr.me/app/post/create",
        });
        let (bytes, sig, czd) = self.sign(&pay);
        writer
            .verify_and_record_action(&bytes, &sig, czd)
            .expect("action records");
        self.blob(&pay)
    }

    /// Commit a `key/create` of `new` on `writer`; returns the commit's wire
    /// bundle.
    async fn key_create(
        &self,
        writer: &mut cyphr::Principal,
        new: &cyphr::Key,
        now: i64,
    ) -> WireBundle {
        let pay = serde_json::json!({
            "alg": self.alg, "id": new.tmb().to_b64(), "now": now,
            "tmb": self.key.tmb().to_b64(), "typ": "cyphr.me/cyphr/key/create",
        });
        let (bytes, sig, czd) = self.sign(&pay);
        let mut scope = writer.begin_commit();
        scope
            .verify_and_apply(&bytes, &sig, czd, Some(new.clone().with_first_seen(now)))
            .expect("key/create applies");
        let signer =
            cyphr::signer::SoftwareSigner::new(&self.alg, &self.prv, &self.pub_key, self.key.tmb());
        let commit = scope
            .finalize_with_software(&signer, now, "cyphr.me")
            .await
            .expect("finalizes");
        WireBundle::of_commit(commit).expect("bundle")
    }
}

/// Claim: engine ingest applies the order rule: a push's data actions are
/// recorded before its transactions (SPEC 4.6.2 `actions`), and an action
/// pushed after a commit, as an action-only bundle, is judged against the
/// post-commit state: an action signed by the key the commit's own
/// `key/create` introduced is accepted, the indexed tip is the commit the
/// writer formed, and replaying the stored chain reaches the writer's PR.
///
/// Turns red if: the leading action is recorded after the commit, or the
/// following action-only bundle is judged against a state without the
/// commit (its signer is not yet a key: `UnknownKey`).
/// End-to-end scenario: yes (a commit with a leading action, then an
/// action-only push, through engine ingest and a stored-chain replay).
#[tokio::test]
async fn action_after_a_transaction_is_judged_after_the_commit() {
    let golden = signer("golden");
    let key_a = signer("key_a");
    let key_b = signer("alice");
    let mut writer = cyphr::Principal::implicit(golden.key.clone())
        .await
        .expect("genesis");
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let genesis_commit = test_fixtures::bundle::genesis_bundle(
        &mut writer,
        pool.get("golden").expect("golden"),
        &[],
        1_700_000_050,
    )
    .await
    .expect("genesis commit");
    let first = golden
        .key_create(&mut writer, &key_a.key, 1_700_000_100)
        .await;
    let leading = golden.action(&mut writer, 1_700_000_150);
    let with_action = WireBundle {
        actions: vec![leading],
        ..golden
            .key_create(&mut writer, &key_b.key, 1_700_000_200)
            .await
    };
    let commit_pr = writer.pr_tagged().expect("pr");
    let after = WireBundle::actions(vec![key_b.action(&mut writer, 1_700_000_250)]);

    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for bundle in [genesis_commit, first, with_action, after] {
        engine
            .submit_commit(&id, Some(genesis.clone()), &bundle)
            .await
            .expect("the bundle is admitted by the order rule");
    }
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        (tip.commit_count, tip.pr),
        (3, commit_pr),
        "the indexed tip is the writer's commit"
    );
    let loaded = engine
        .load_principal(&id, genesis)
        .await
        .expect("the stored chain replays");
    assert_eq!(
        loaded.pr_tagged().expect("pr"),
        writer.pr_tagged().expect("pr"),
        "replaying the stored chain reaches the writer's PR"
    );
    assert_eq!(
        history(&loaded),
        history(&writer),
        "and the writer's actions"
    );
}

/// Claim (SPEC 5.1 steps 1-4, 3.3; I1): a genesis commit whose keys are
/// created out of thumbprint order, one of them by a key the genesis itself
/// just created, means one thing to ingest and to the rebuild from blobs
/// alone: the rebuild reads the genesis from the commit's `key/create`s, not
/// from how the producer seeded its principal, and reaches the same chain,
/// tip and roots as ingest, quarantining nothing.
///
/// Turns red if: the rebuild reads the genesis keys in another order or
/// seeding than the arrow binds (a genesis `pre` over the seeded set rather
/// than the genesis key), refuses a genesis key/create signed by a key
/// created earlier in the commit, or keys the principal other than by its
/// PG.
/// End-to-end scenario: yes (core producer, engine ingest, scratch rebuild).
#[tokio::test]
async fn genesis_order_is_read_alike_by_ingest_and_the_scratch_rebuild() {
    let (golden, alice, key_a) = (signer("golden"), signer("alice"), signer("key_a"));
    let order = [&golden.key, &alice.key, &key_a.key];
    let mut sorted: Vec<String> = order.iter().map(|k| k.tmb().to_b64()).collect();
    sorted.sort();
    assert_ne!(
        order.iter().map(|k| k.tmb().to_b64()).collect::<Vec<_>>(),
        sorted,
        "premise: the creation order is not thumbprint order"
    );

    let now = 1_700_000_000;
    let mut writer = cyphr::Principal::implicit(golden.key.clone())
        .await
        .expect("genesis");
    let mut txs = Vec::new();
    let software =
        |s: &Signer| cyphr::signer::SoftwareSigner::new(&s.alg, &s.prv, &s.pub_key, s.key.tmb());
    let mut scope = writer.begin_commit();
    for (by, new) in [
        (&golden, &golden.key),
        (&golden, &alice.key),
        (&alice, &key_a.key),
    ] {
        let pay = serde_json::json!({
            "alg": by.alg, "id": new.tmb().to_b64(), "now": now,
            "tmb": by.key.tmb().to_b64(), "typ": "cyphr.me/cyphr/key/create",
        });
        let (bytes, sig, czd) = by.sign(&pay);
        scope
            .verify_and_apply(&bytes, &sig, czd, Some(new.clone()))
            .expect("genesis key/create applies");
        txs.push(vec![by.blob(&pay)]);
    }
    let created = scope
        .create_principal(&software(&golden), now, "cyphr.me")
        .await
        .expect("principal/create");
    txs.push(vec![serde_json::to_vec(&created).expect("json")]);
    let commit = scope
        .finalize_with_software(&software(&golden), now, "cyphr.me")
        .await
        .expect("genesis commit");
    let closing = commit.commit_tx().0.first().expect("commit/create").raw();
    txs.push(vec![serde_json::to_vec(closing).expect("json")]);
    let blobs = WireBundle {
        txs,
        keys: order
            .iter()
            .map(|k| cyphr_storage::KeyEntry::of(k))
            .collect(),
        ..WireBundle::default()
    };

    let alg = writer.active_algs()[0];
    let pg = writer
        .pg()
        .expect("pg")
        .as_multihash()
        .get(alg)
        .expect("pg variant");
    let id = format!("{alg}:{}", Base64UrlUnpadded::encode_string(pg));
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    engine
        .submit_commit(&id, None, &blobs)
        .await
        .expect("ingest reads the genesis from its blobs");
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        tip.pr,
        writer.pr_tagged().expect("pr"),
        "ingest reaches the producer's PR"
    );

    let before = engine
        .indexer()
        .get_commit_chain(&id, None, None)
        .await
        .expect("chain");
    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(
        report.quarantined.is_empty(),
        "the rebuild replays the genesis: {:?}",
        report.quarantined
    );
    let after = engine
        .indexer()
        .get_commit_chain(&id, None, None)
        .await
        .expect("chain");
    assert_eq!(after, before, "the rebuilt chain equals the ingested one");
}

impl Signer {
    /// Commit a `ds/create` naming MR(DT) on `writer`; returns the commit's
    /// wire bundle.
    async fn ds_create(&self, writer: &mut cyphr::Principal, now: i64) -> WireBundle {
        let mut scope = writer.begin_commit();
        let id = scope
            .data_tree_id()
            .expect("DR")
            .expect("DT holds an action");
        let pay = serde_json::json!({
            "alg": self.alg, "id": id, "now": now,
            "tmb": self.key.tmb().to_b64(), "typ": "cyphr.me/cyphr/ds/create",
        });
        let (bytes, sig, czd) = self.sign(&pay);
        scope
            .verify_and_apply(&bytes, &sig, czd, None)
            .expect("ds/create applies");
        let signer =
            cyphr::signer::SoftwareSigner::new(&self.alg, &self.prv, &self.pub_key, self.key.tmb());
        let commit = scope
            .finalize_with_software(&signer, now, "cyphr.me")
            .await
            .expect("finalizes");
        WireBundle::of_commit(commit).expect("bundle")
    }

    /// A data action's wire blob, not recorded anywhere.
    fn unrecorded_action(&self, now: i64, msg: &str) -> Vec<u8> {
        let pay = serde_json::json!({
            "alg": self.alg, "msg": msg, "now": now, "tmb": self.key.tmb().to_b64(),
            "typ": "cyphr.me/app/post/create",
        });
        self.blob(&pay)
    }
}

/// Record a wire action on `writer`, as a client does after pushing it.
fn record(writer: &mut cyphr::Principal, blob: &[u8]) {
    let coz = StoredCoz::from_wire(blob).expect("wire coz");
    writer
        .verify_and_record_action(coz.pay_json(), coz.sig(), coz.czd().clone())
        .expect("action records");
}

async fn push(engine: &Engine, id: &str, genesis: &Genesis, bundle: &WireBundle) {
    engine
        .submit_commit(id, Some(genesis.clone()), bundle)
        .await
        .expect("the bundle is accepted");
}

/// Claim (SPEC 4.8.1: data actions "are not chained, and are recorded in
/// DT", "Ordered by `now`"; 4.8.2: a `ds/create` names MR(DT)): data
/// actions pushed on their own, in any order within their bundle, are
/// recorded in DT on every path. Engine ingest accepts a `ds/create` over
/// them; the principal the engine replays from its store, the one a scratch
/// rebuild replays, the one a restarted engine (a fresh index healed from
/// the blobs) replays, and the one imported from the client's export all
/// hold the client's PR and the same actions at the same places, so a
/// second `ds/create` over a later action is accepted after the restart.
///
/// Turns red if: the engine stores an action-only bundle without listing
/// it for replay (the `ds/create` is refused as `StateMismatch`); a bundle
/// out of `now` order is replayed in carriage order (`TimestampPast`);
/// rebuild or restart drops the action manifests; or the export leaves the
/// actions out (the import's `ds/create` fails).
/// End-to-end scenario: yes (client, engine ingest, scratch rebuild,
/// restart, export and import).
#[tokio::test]
async fn actions_pushed_alone_replay_alike_on_every_path() {
    let golden = signer("golden");
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let t = 1_700_000_000;
    let mut writer = cyphr::Principal::implicit(golden.key.clone())
        .await
        .expect("genesis");
    let genesis_commit = test_fixtures::bundle::genesis_bundle(
        &mut writer,
        pool.get("golden").expect("golden"),
        &[],
        t,
    )
    .await
    .expect("genesis commit");
    // Two actions travel in one bundle, the later one first.
    let (early, late) = (
        golden.unrecorded_action(t + 10, "early"),
        golden.unrecorded_action(t + 20, "late"),
    );
    record(&mut writer, &early);
    record(&mut writer, &late);
    let included = golden.ds_create(&mut writer, t + 30).await;
    let trailing = golden.unrecorded_action(t + 40, "after the ds/create");
    record(&mut writer, &trailing);

    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for bundle in [
        genesis_commit,
        WireBundle::actions(vec![late.clone(), early.clone()]),
        included,
        WireBundle::actions(vec![trailing.clone()]),
    ] {
        push(&engine, &id, &genesis, &bundle).await;
    }
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        tip.pr,
        writer.pr_tagged().expect("pr"),
        "the engine's PR includes the DR over the actions pushed alone"
    );

    let lines = history;
    let history = lines(&writer);
    let loaded = async |engine: &Engine| engine.load_principal(&id, genesis.clone()).await;
    assert_eq!(
        lines(&loaded(&engine).await.expect("ingest replays")),
        history,
        "ingest: the same commits and actions"
    );

    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(report.quarantined.is_empty(), "{:?}", report.quarantined);
    assert_eq!(
        lines(&loaded(&engine).await.expect("rebuild replays")),
        history,
        "scratch rebuild: the same commits and actions"
    );

    let imported = cyphr_storage::load_principal_from_commits(
        genesis.clone(),
        &cyphr_storage::export_commits(&writer).expect("export"),
    )
    .await
    .expect("the export imports");
    assert_eq!(lines(&imported), history, "export and import");

    // A restarted engine: the same blobs, a fresh index healed from them.
    let copy = MemoryBlobStore::new();
    for hash in engine.blob_store().iter().await.expect("iter") {
        let blob = engine
            .blob_store()
            .get(&hash.expect("hash"))
            .await
            .expect("get")
            .expect("blob");
        copy.put(&blob).await.expect("put");
    }
    let restarted = StorageEngine::new(copy, MemoryIndexer::new());
    let later = golden.unrecorded_action(t + 50, "after the restart");
    record(&mut writer, &later);
    let again = golden.ds_create(&mut writer, t + 60).await;
    push(&restarted, &id, &genesis, &WireBundle::actions(vec![later])).await;
    push(&restarted, &id, &genesis, &again).await;
    let tip = restarted.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        tip.pr,
        writer.pr_tagged().expect("pr"),
        "after a restart, a ds/create over every action is accepted"
    );
    assert_eq!(
        lines(&loaded(&restarted).await.expect("restart replays")),
        lines(&writer),
        "restart: the same commits and actions"
    );
}

/// Claim (I1: the blob store is the only source of truth, and the scratch
/// rebuild trusts no manifest it cannot replay): an action manifest whose
/// action the principal's keys did not sign (here one by a key the
/// principal never held, slipped into the store with a well-formed
/// manifest) is quarantined by the scratch rebuild, and the principal is
/// not bricked by it: it replays without the action and takes a further
/// action and `ds/create`.
///
/// Turns red if: the scratch rebuild lists an action manifest whose replay
/// the core refuses (every later load of the principal then fails with
/// `UnknownKey`).
/// End-to-end scenario: yes (ingest, forged store, recovery, ingest).
#[tokio::test]
async fn forged_actions_are_quarantined_by_the_scratch_rebuild() {
    let (golden, alice) = (signer("golden"), signer("alice"));
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let t = 1_700_000_000;
    let mut writer = cyphr::Principal::implicit(golden.key.clone())
        .await
        .expect("genesis");
    let genesis_commit = test_fixtures::bundle::genesis_bundle(
        &mut writer,
        pool.get("golden").expect("golden"),
        &[],
        t,
    )
    .await
    .expect("genesis commit");
    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&engine, &id, &genesis, &genesis_commit).await;

    let forged = alice.unrecorded_action(t + 10, "not this principal's key");
    let blob = engine.blob_store().put(&forged).await.expect("put");
    let manifest = serde_json::json!({
        "kind": "cyphr-storage/action-manifest/v1",
        "principal_id": id,
        "after": 1,
        "blob_hashes": [blob],
    });
    let manifest = [
        ACTION_MANIFEST_PREFIX,
        &serde_json::to_vec(&manifest).expect("json"),
    ]
    .concat();
    let manifest = engine.blob_store().put(&manifest).await.expect("put");

    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(
        report.quarantined.iter().any(
            |q| q.manifest == manifest && matches!(q.reason, QuarantineReason::Unreplayable(_))
        ),
        "the forged action manifest is quarantined: {:?}",
        report.quarantined
    );
    let loaded = engine
        .load_principal(&id, genesis.clone())
        .await
        .expect("the principal replays without the forged action");
    assert_eq!(history(&loaded), history(&writer));

    let own = golden.unrecorded_action(t + 20, "its own");
    record(&mut writer, &own);
    let included = golden.ds_create(&mut writer, t + 30).await;
    push(&engine, &id, &genesis, &WireBundle::actions(vec![own])).await;
    push(&engine, &id, &genesis, &included).await;
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(tip.pr, writer.pr_tagged().expect("pr"));
}

/// A copy of `store`'s blobs in a fresh in-memory store.
async fn copy_store(store: &MemoryBlobStore) -> MemoryBlobStore {
    let copy = MemoryBlobStore::new();
    for hash in store.iter().await.expect("iter") {
        let blob = store
            .get(&hash.expect("hash"))
            .await
            .expect("get")
            .expect("blob");
        copy.put(&blob).await.expect("put");
    }
    copy
}

/// Write an action manifest for `id` at `after` naming `blobs` straight
/// into `store`, as a forged store would hold it; returns its hash.
async fn forge_action_manifest(
    store: &MemoryBlobStore,
    id: &str,
    after: u64,
    blobs: &[Vec<u8>],
) -> cyphr_storage::blob::Blake3Hash {
    let mut hashes = Vec::new();
    for blob in blobs {
        hashes.push(store.put(blob).await.expect("put"));
    }
    let manifest = serde_json::json!({
        "kind": "cyphr-storage/action-manifest/v1",
        "principal_id": id,
        "after": after,
        "blob_hashes": hashes,
    });
    store
        .put(
            &[
                ACTION_MANIFEST_PREFIX,
                &serde_json::to_vec(&manifest).expect("json"),
            ]
            .concat(),
        )
        .await
        .expect("put")
}

/// Claim (I1; SPEC 4.8.1: actions are not transactions): an action
/// manifest is only ever a bundle of data actions. One naming a
/// transaction blob (here a validly signed `key/create` of the principal's
/// own key, slipped into the store) is quarantined as malformed by the
/// scratch rebuild and by the heal pass of a fresh engine, and the
/// principal loads unchanged: no transaction reaches the chain by the
/// action keyspace.
///
/// Turns red if: the action-only check accepts a bundle holding a
/// transaction (the rebuild then replays the forged bundle as a commit and
/// calls it unreplayable, and the heal pass lists it, so every later load
/// of the principal fails).
/// End-to-end scenario: yes (ingest, forged store, scratch rebuild,
/// restart, load).
#[tokio::test]
async fn action_manifest_with_a_transaction_is_malformed() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let t = 1_700_000_000;
    let mut writer = cyphr::Principal::implicit(golden.key.clone())
        .await
        .expect("genesis");
    let genesis_commit = test_fixtures::bundle::genesis_bundle(
        &mut writer,
        pool.get("golden").expect("golden"),
        &[],
        t,
    )
    .await
    .expect("genesis commit");
    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    push(&engine, &id, &genesis, &genesis_commit).await;

    // A signed key/create by the principal's own key: a transaction.
    let mut other = writer.fork().await.expect("fork");
    let tx = golden
        .key_create(&mut other, &key_a.key, t + 10)
        .await
        .txs
        .remove(0)
        .remove(0);
    let forged = forge_action_manifest(engine.blob_store(), &id, 1, &[tx]).await;
    let malformed = |q: &[cyphr_storage::engine::QuarantinedManifest]| {
        q.iter()
            .any(|q| q.manifest == forged && matches!(q.reason, QuarantineReason::Malformed(_)))
    };

    let restarted = StorageEngine::new(copy_store(engine.blob_store()).await, MemoryIndexer::new());
    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(
        malformed(&report.quarantined),
        "scratch rebuild: {:?}",
        report.quarantined
    );
    let loaded = engine
        .load_principal(&id, genesis.clone())
        .await
        .expect("loads");
    assert_eq!(
        history(&loaded),
        history(&writer),
        "scratch rebuild: unchanged"
    );

    let healed = restarted
        .load_principal(&id, genesis.clone())
        .await
        .expect("the healed engine loads the principal");
    assert_eq!(history(&healed), history(&writer), "heal pass: unchanged");
    let report = restarted
        .rebuild_index_with_report()
        .await
        .expect("heal pass");
    assert!(
        malformed(&report.quarantined),
        "heal pass: {:?}",
        report.quarantined
    );
}

/// Claim (SPEC 4.8.1: DT is "Ordered by `now`"): action-only bundles
/// accepted at one chain position are replayed in the order they were
/// accepted, whatever order their manifests are stored in. Two bundles
/// whose manifest hashes sort opposite to their `now` order (the order a
/// durable store lists them in) survive a scratch rebuild unquarantined,
/// and a `ds/create` over both is accepted after it.
///
/// Turns red if: bundles at one position are replayed in manifest-hash
/// order (the later action first, so the earlier one is refused as
/// `TimestampPast`).
/// End-to-end scenario: yes (ingest into a durable store, scratch rebuild,
/// ingest).
#[tokio::test]
async fn actions_at_one_position_rebuild_in_now_order() {
    let golden = signer("golden");
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let t = 1_700_000_000;
    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let fresh = async || {
        let mut writer = cyphr::Principal::implicit(golden.key.clone())
            .await
            .expect("genesis");
        let commit = test_fixtures::bundle::genesis_bundle(
            &mut writer,
            pool.get("golden").expect("golden"),
            &[],
            t,
        )
        .await
        .expect("genesis commit");
        (writer, commit)
    };

    // The action manifests' hashes in `now` order, as an engine writes
    // them for `actions` pushed one bundle each after the genesis.
    async fn manifest_order(
        id: &str,
        genesis: &Genesis,
        commit: &WireBundle,
        actions: &[Vec<u8>],
    ) -> Vec<[u8; 32]> {
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        push(&engine, id, genesis, commit).await;
        for a in actions {
            push(&engine, id, genesis, &WireBundle::actions(vec![a.clone()])).await;
        }
        let store = engine.blob_store();
        let mut found = Vec::new();
        for hash in store.iter().await.expect("iter") {
            let hash = hash.expect("hash");
            let data = store.get(&hash).await.expect("get").expect("blob");
            let Some(json) = data.strip_prefix(ACTION_MANIFEST_PREFIX) else {
                continue;
            };
            let manifest: serde_json::Value = serde_json::from_slice(json).expect("json");
            let blob: cyphr_storage::blob::Blake3Hash =
                serde_json::from_value(manifest["blob_hashes"][0].clone()).expect("hash");
            let coz: serde_json::Value =
                serde_json::from_slice(&store.get(&blob).await.expect("get").expect("blob"))
                    .expect("coz");
            found.push((coz["pay"]["now"].as_i64().expect("now"), *hash.as_bytes()));
        }
        found.sort();
        found.into_iter().map(|(_, h)| h).collect()
    }

    // Search messages until the later action's manifest sorts first.
    let mut pair = None;
    for i in 0..64 {
        let early = golden.unrecorded_action(t + 10, &format!("early {i}"));
        let late = golden.unrecorded_action(t + 20, &format!("late {i}"));
        let (_, commit) = fresh().await;
        let order = manifest_order(&id, &genesis, &commit, &[early.clone(), late.clone()]).await;
        if order[1] < order[0] {
            pair = Some((early, late));
            break;
        }
    }
    let (early, late) = pair.expect("a pair whose manifest hashes sort against now");

    let (mut writer, commit) = fresh().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let db = fjall::Database::builder(dir.path().join("db"))
        .open()
        .expect("open db");
    let blobs = cyphr_blob_fjall::FjallBlobStore::from_database(db).expect("blob store");
    let index =
        cyphr_index_fjall::FjallIndexer::open(&dir.path().join("index")).expect("open index");
    let engine = StorageEngine::new(blobs, index);
    let push_to = async |bundle: &WireBundle| {
        engine
            .submit_commit(&id, Some(genesis.clone()), bundle)
            .await
            .expect("the bundle is accepted");
    };
    push_to(&commit).await;
    for a in [&early, &late] {
        record(&mut writer, a);
        push_to(&WireBundle::actions(vec![a.clone()])).await;
    }

    let report = engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(report.quarantined.is_empty(), "{:?}", report.quarantined);
    let included = golden.ds_create(&mut writer, t + 30).await;
    push_to(&included).await;
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(tip.pr, writer.pr_tagged().expect("pr"));
}

/// Claim (SPEC 2.3.2: a principal genesis is required for commits; the
/// architect's ruling extends it to data actions): an action-only bundle
/// for a principal with no genesis commit is refused with
/// `GenesisIncomplete`, not recorded under a key its later genesis commit
/// never reads (silent orphaning).
///
/// Turns red if: the engine accepts the bundle (it does today; DEBT2).
/// End-to-end scenario: yes (engine ingest of a first bundle).
#[tokio::test]
#[ignore = "RED(DEBT2): SPEC 2.3.2"]
async fn actions_before_the_genesis_commit_are_refused() {
    let golden = signer("golden");
    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let action = golden.unrecorded_action(1_700_000_010, "before any commit");
    let refused = engine
        .submit_commit(&id, Some(genesis), &WireBundle::actions(vec![action]))
        .await;
    assert!(
        matches!(
            refused,
            Err(cyphr_storage::engine::EngineError::Protocol(
                cyphr::Error::GenesisIncomplete
            ))
        ),
        "a pre-genesis action is refused, got {refused:?}"
    );
}
