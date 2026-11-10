//! Replay equivalence: one stored commit means one thing on every path.
//!
//! The core's public replay entry point (`cyphr::replay`), the engine's
//! ingest (`submit_commit`) and the engine's rebuild from blobs alone
//! (`rebuild_index_from_scratch`) must reach the same roots for every
//! chain of the golden corpus, and the rebuild must trust no manifest it
//! cannot replay (root `AGENTS.md` I1: the blob store is the only source of
//! truth).

use std::path::PathBuf;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr::replay::{StoredCoz, replay_bundle};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{
    COMMIT_MANIFEST_PREFIX, QuarantineReason, StorageEngine, genesis_principal_id,
};
use cyphr_storage::index::{Indexer, MemoryIndexer};

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

/// One corpus chain, as stored: its genesis and each commit's wire blobs.
struct Chain {
    name: String,
    genesis: Genesis,
    bundles: Vec<Vec<Vec<u8>>>,
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
/// error or need a setup step no stored chain carries are left out.
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
            if golden.get("setup").is_some()
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
                Genesis::Explicit(keys)
            };
            let bundles = carried(commits.iter().map(wire_blobs).collect());
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

/// A golden commit as the wire carries it: each coz `{pay, sig}` and the key
/// a key-introducing coz adds as its `key` sidecar. A chain's first commit is
/// its genesis commit, whose `key/create`s disclose its keys, so a rebuild
/// reads the genesis from these blobs alone.
fn wire_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let mut keys = commit["keys"].as_array().into_iter().flatten();
    let txs = commit["txs"].as_array().expect("txs");
    txs.iter()
        .map(|coz| {
            let mut coz = coz.clone();
            let typ = coz["pay"]["typ"].as_str().expect("typ").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) {
                if let Some(key) = keys.next() {
                    coz["key"] = key.clone();
                }
            }
            serde_json::to_vec(&coz).expect("json")
        })
        .collect()
}

/// The bundles as a client carries them: a vector records each data action
/// as its own entry, but the engine replays only bundles that form a
/// commit, so actions that a later commit's `ds/create` includes (SPEC
/// 4.8.2) travel ahead of that commit's transactions, the order the replay
/// rule records them in. Actions after the last commit stay on their own.
fn carried(entries: Vec<Vec<Vec<u8>>>) -> Vec<Vec<Vec<u8>>> {
    let forms_commit = |bundle: &[Vec<u8>]| {
        bundle
            .iter()
            .any(|b| StoredCoz::from_wire(b).expect("wire coz").is_transaction())
    };
    let mut bundles = Vec::new();
    let mut pending: Vec<Vec<u8>> = Vec::new();
    for entry in entries {
        if forms_commit(&entry) {
            pending.extend(entry);
            bundles.push(std::mem::take(&mut pending));
        } else {
            pending.extend(entry);
        }
    }
    if !pending.is_empty() {
        bundles.push(pending);
    }
    bundles
}

fn principal(genesis: &Genesis) -> cyphr::Principal {
    match genesis {
        Genesis::Implicit(key) => cyphr::Principal::implicit(key.clone()),
        Genesis::Explicit(keys) => cyphr::Principal::explicit(keys.clone()),
    }
    .expect("genesis")
}

/// The id the engine stores `chain` under, derived by the core alone: the
/// PG its genesis commit establishes (a nonce in it is part of the PG). A
/// chain of data actions alone forms no commit and is keyed by its genesis
/// PR.
fn principal_id(chain: &Chain) -> String {
    let mut p = principal(&chain.genesis);
    let cozies: Vec<StoredCoz> = chain.bundles[0]
        .iter()
        .map(|b| StoredCoz::from_wire(b).expect("wire coz"))
        .collect();
    replay_bundle(&mut p, &cozies).expect("first commit replays");
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
    let id = principal_id(chain);
    for (i, bundle) in chain.bundles.iter().enumerate() {
        let refs: Vec<&[u8]> = bundle.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(&id, Some(chain.genesis.clone()), &refs)
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
        let mut core = principal(&chain.genesis);
        for (i, bundle) in chain.bundles.iter().enumerate() {
            let cozies: Vec<StoredCoz> = bundle
                .iter()
                .map(|blob| StoredCoz::from_wire(blob).expect("wire coz"))
                .collect();
            replay_bundle(&mut core, &cozies)
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
        let id = ingest(&engine, chain).await;
        let tip = engine.get_tip(&id).await.expect("tip");
        if core.commits().next().is_none() {
            // Action-only bundles form no commit, so nothing is indexed.
            assert!(tip.is_none(), "{}: no commit, no tip", chain.name);
            return;
        }
        let tip = tip.expect("a tip");
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
    }
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

    /// The wire blob of `pay` with an optional `key` sidecar.
    fn blob(&self, pay: &serde_json::Value, sidecar: Option<&cyphr::Key>) -> Vec<u8> {
        let (_, sig, _) = self.sign(pay);
        let mut coz =
            serde_json::json!({ "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) });
        if let Some(key) = sidecar {
            coz["key"] = serde_json::json!({
                "alg": key.alg(),
                "pub": Base64UrlUnpadded::encode_string(key.pub_key()),
                "tmb": key.tmb().to_b64(),
            });
        }
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
        self.blob(&pay, None)
    }

    /// Commit a `key/create` of `new` on `writer`; returns the commit's wire
    /// blobs.
    fn key_create(
        &self,
        writer: &mut cyphr::Principal,
        new: &cyphr::Key,
        now: i64,
    ) -> Vec<Vec<u8>> {
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
            .expect("finalizes");
        let closing = commit
            .iter_all_cozies()
            .last()
            .expect("commit/create")
            .raw()
            .pay
            .clone();
        vec![self.blob(&pay, Some(new)), self.blob(&closing, None)]
    }
}

/// Claim: engine ingest applies a bundle of data action, transaction, data
/// action by the order rule (leading actions, then the commit, then the
/// trailing actions against the post-commit state): a trailing action
/// signed by the key the bundle's own `key/create` introduced is accepted,
/// the indexed tip is the commit the writer formed, and replaying the
/// stored chain reaches the writer's PR.
///
/// Turns red if: replay records every data action before the commit scope
/// (the trailing action's signer is not yet a key: `UnknownKey`).
/// End-to-end scenario: yes (a real mixed bundle through engine ingest and
/// a stored-chain replay).
#[tokio::test]
async fn action_after_a_transaction_is_judged_after_the_commit() {
    let golden = signer("golden");
    let key_a = signer("key_a");
    let key_b = signer("alice");
    let mut writer = cyphr::Principal::implicit(golden.key.clone()).expect("genesis");
    let pool = test_fixtures::Pool::load(&golden_dir().join("../keys/pool.toml")).expect("pool");
    let genesis_commit = test_fixtures::bundle::genesis_bundle(
        &mut writer,
        pool.get("golden").expect("golden"),
        1_700_000_050,
    )
    .expect("genesis commit");
    let first = golden.key_create(&mut writer, &key_a.key, 1_700_000_100);
    let mut mixed = vec![golden.action(&mut writer, 1_700_000_150)];
    mixed.extend(golden.key_create(&mut writer, &key_b.key, 1_700_000_200));
    let commit_pr = writer.pr_tagged().expect("pr");
    mixed.push(key_b.action(&mut writer, 1_700_000_250));

    let genesis = Genesis::Implicit(golden.key.clone());
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for bundle in [genesis_commit, first, mixed] {
        let refs: Vec<&[u8]> = bundle.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(&id, Some(genesis.clone()), &refs)
            .await
            .expect("the bundle is admitted by the order rule");
    }
    let tip = engine.get_tip(&id).await.expect("tip").expect("a tip");
    assert_eq!(
        (tip.commit_count, tip.pr),
        (3, commit_pr),
        "the indexed tip is the writer's commit"
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
    let mut writer = cyphr::Principal::implicit(golden.key.clone()).expect("genesis");
    let mut blobs = Vec::new();
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
        blobs.push(by.blob(&pay, Some(new)));
    }
    let created = scope
        .create_principal(&software(&golden), now, "cyphr.me")
        .expect("principal/create");
    blobs.push(serde_json::to_vec(&created).expect("json"));
    let commit = scope
        .finalize_with_software(&software(&golden), now, "cyphr.me")
        .expect("genesis commit");
    let closing = commit.commit_tx().0.first().expect("commit/create").raw();
    blobs.push(serde_json::to_vec(closing).expect("json"));

    let alg = writer.active_algs()[0];
    let pg = writer
        .pg()
        .expect("pg")
        .as_multihash()
        .get(alg)
        .expect("pg variant");
    let id = format!("{alg}:{}", Base64UrlUnpadded::encode_string(pg));
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(&id, None, &refs)
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
