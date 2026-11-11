//! The index is derivable from the blobs alone, fork resolution included
//! (root `AGENTS.md` I1; SPEC 15.8).
//!
//! A fork is resolved by a new commit whose `pre` is the tip of the chosen
//! branch; nothing else records the choice. A store therefore holds the
//! abandoned commit under its ordinary commit manifest, the chosen rival
//! under its branch manifest, and the resolving commit as an ordinary
//! commit manifest one position higher. A rebuild walks each principal
//! from its highest sequence down: the canonical commit at each position
//! is the one its canonical successor's `pre` extends, and every other
//! commit is a retained branch.
//!
//! Every scenario runs on real signed commits over the engine seam. The
//! resolving commit cannot be pushed to a store that holds the rival only
//! as a branch (that push rule is later work), so it is pushed to a second
//! store where the rival is canonical and its blobs are copied across:
//! exactly the bytes the first store would hold after the push.

use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{IngestResult, StorageEngine};
use cyphr_storage::index::{Indexer, MemoryIndexer};

const NOW: i64 = 1_700_200_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

fn pool() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

/// `signer` creates `new` and finalizes the commit itself; distinct `now`
/// values give distinct commits at one position.
async fn create_key(p: &mut cyphr::Principal, signer: &str, new: &str, now: i64) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let pool = pool();
    let (s, n) = (
        pool.get(signer).expect("signer"),
        pool.get(new).expect("new"),
    );
    let tmb = s.compute_tmb().expect("tmb");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": s.alg, "id": n.compute_tmb().expect("tmb").to_b64(), "now": now,
        "tmb": tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(s.prv.as_deref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&s.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &s.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &s.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(n.key().expect("key")))
        .expect("apply");
    scope
        .finalize_with_software(&s.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalize");
}

fn last(p: &cyphr::Principal) -> WireBundle {
    test_fixtures::bundle::last_commit_bundle(p).expect("bundle")
}

/// A principal with genesis commit G at position 0, rival commits A and B
/// at position 1, C at position 2 extending B, and A2 at position 2
/// extending A. Each is valid on its own.
struct Scenario {
    id: String,
    genesis: Genesis,
    g: WireBundle,
    a: WireBundle,
    b: WireBundle,
    c: WireBundle,
    a2: WireBundle,
    /// The principal after G, B, C: the canonical chain once C resolves.
    resolved: cyphr::Principal,
}

impl Scenario {
    async fn new() -> Self {
        let pool = pool();
        let golden = pool.get("golden").expect("golden");
        let key_a = pool.get("key_a").expect("key_a").key().expect("key_a");
        let mut base = cyphr::Principal::implicit(golden.key().expect("golden"))
            .await
            .expect("implicit");
        let g = test_fixtures::bundle::genesis_bundle(&mut base, golden, &[key_a.clone()], NOW)
            .await
            .expect("genesis");
        let id = test_fixtures::bundle::genesis_id(&g).expect("genesis id");

        let mut a = base.fork().await.expect("fork");
        create_key(&mut a, "golden", "key_b", NOW + 1).await;
        let mut b = base.fork().await.expect("fork");
        create_key(&mut b, "golden", "alice", NOW + 2).await;
        let mut resolved = b.fork().await.expect("fork");
        create_key(&mut resolved, "golden", "bob", NOW + 3).await;
        let mut a2 = a.fork().await.expect("fork");
        create_key(&mut a2, "golden", "carol", NOW + 4).await;

        Self {
            id,
            genesis: Genesis::Explicit(vec![golden.key().expect("golden"), key_a]),
            g,
            a: last(&a),
            b: last(&b),
            c: last(&resolved),
            a2: last(&a2),
            resolved,
        }
    }

    async fn push(&self, e: &Engine, bundle: &WireBundle) -> Result<IngestResult, String> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), bundle)
            .await
            .map_err(|e| e.to_string())
    }

    /// A store holding G and A canonical and B retained as a branch, then C
    /// written as the commit manifest a push resolving onto B leaves.
    /// Returns the store and C's commit id.
    async fn resolved_store(&self) -> (Engine, String) {
        let e = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        self.push(&e, &self.g).await.expect("G");
        self.push(&e, &self.a).await.expect("A");
        assert!(
            self.push(&e, &self.b).await.is_err(),
            "B is refused as the tip"
        );
        assert_eq!(
            e.list_branches(&self.id).await.expect("branches").len(),
            2,
            "B is retained"
        );

        let other = Engine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        self.push(&other, &self.g).await.expect("G");
        self.push(&other, &self.b).await.expect("B");
        let c = self.push(&other, &self.c).await.expect("C");
        copy(&other, &e, &c).await;
        (e, c.tip.expect("tip").commit_id)
    }
}

/// Copy one commit's blobs and its manifest from `from` to `to`.
async fn copy(from: &Engine, to: &Engine, commit: &IngestResult) {
    let hashes: Vec<Blake3Hash> = commit
        .blob_hashes
        .iter()
        .copied()
        .chain(commit.manifest_hash)
        .collect();
    for hash in hashes {
        let data = from
            .blob_store()
            .get(&hash)
            .await
            .expect("get")
            .expect("held");
        to.blob_store().put(&data).await.expect("put");
    }
}

/// The commit id at each position of the served chain.
async fn chain(e: &Engine, id: &str) -> Vec<String> {
    e.get_patch(id, None, None)
        .await
        .expect("patch")
        .entries
        .into_iter()
        .map(|entry| entry.commit.commit_id)
        .collect()
}

/// The ids of the retained (non-canonical) branch heads.
async fn retained(e: &Engine, id: &str) -> Vec<String> {
    let mut held: Vec<String> = e
        .list_branches(id)
        .await
        .expect("branches")
        .into_iter()
        .filter(|b| !b.canonical)
        .map(|b| b.tip)
        .collect();
    held.sort();
    held
}

/// Claim: a store holding A, the rival B, and C extending B serves C as its
/// tip, B beneath it, and A as a retained branch, whether the index is
/// rebuilt from the blobs alone or a stale index (one that holds A) is
/// healed. The commit ids of A and B come from the store itself. Turns red
/// if the rebuild serves A, drops a branch, or leaves the stale index
/// serving A under C. End-to-end scenario (SPEC 15.8 resolution 1, I1).
#[tokio::test]
async fn rebuild_serves_the_branch_the_resolving_commit_extends() {
    let s = Scenario::new().await;
    let (stale, c) = s.resolved_store().await;
    let before = chain(&stale, &s.id).await;
    let (g, a) = (before[0].clone(), before[1].clone());
    let b = retained(&stale, &s.id).await.remove(0);

    let fresh = Engine::new(stale.blob_store().clone(), MemoryIndexer::new());
    stale
        .rebuild_index_with_report()
        .await
        .expect("heal the stale index");
    for e in [&fresh, &stale] {
        assert_eq!(chain(e, &s.id).await, vec![g.clone(), b.clone(), c.clone()]);
        assert_eq!(retained(e, &s.id).await, vec![a.clone()], "A is retained");
        let tip = e.get_tip(&s.id).await.expect("tip").expect("stored");
        assert_eq!((tip.commit_id.as_str(), tip.commit_count), (c.as_str(), 3));
        let roots = e.rederive_roots(&s.id).await.expect("replay");
        assert_eq!(roots.pr, s.resolved.pr_tagged().expect("pr"));
    }
}

/// Claim: a store whose two commits at one position are both extended (A
/// by A2, the rival B by C) leaves no branch unambiguously selected
/// (SPEC 15.8), so the rebuilt index marks the principal Error, serves the
/// head first in manifest-hash order with its own ancestry beneath it, and
/// keeps every other commit as a retained branch. Turns red if the rebuild
/// picks a winner by any other rule, drops a branch, or leaves the
/// principal unmarked. End-to-end scenario (SPEC 15.8, I1).
#[tokio::test]
async fn two_extended_heads_mark_the_principal_error() {
    let s = Scenario::new().await;
    let (e, c) = s.resolved_store().await;
    let a2 = s.push(&e, &s.a2).await;
    // The index of `e` still serves A, so A2 is accepted as its tip.
    let a2 = a2.expect("A2 extends the served A");
    let a2_id = a2.tip.clone().expect("tip").commit_id;

    let fresh = Engine::new(e.blob_store().clone(), MemoryIndexer::new());
    let served = fresh.get_tip(&s.id).await.expect("tip").expect("stored");
    assert!(fresh.indexer().is_errored(&s.id).await.expect("errored"));

    // The hash-order head: the commit manifests of A2 and C, compared.
    let c_manifest = manifest_of(&fresh, &c).await;
    let a2_manifest = a2.manifest_hash.expect("A2 manifest");
    let head = if a2_manifest.as_bytes() < c_manifest.as_bytes() {
        &a2_id
    } else {
        &c
    };
    assert_eq!(&served.commit_id, head, "the hash-order head is served");

    let mut every: Vec<String> = chain(&fresh, &s.id).await;
    every.extend(retained(&fresh, &s.id).await);
    every.sort();
    every.dedup();
    assert_eq!(every.len(), 5, "G, A, B, A2 and C are all held: {every:?}");
}

/// The hash of the commit manifest that records commit `commit_id`.
async fn manifest_of(e: &Engine, commit_id: &str) -> Blake3Hash {
    let store = e.blob_store();
    for hash in store.iter().await.expect("iter") {
        let hash = hash.expect("hash");
        let data = store.get(&hash).await.expect("get").expect("held");
        if let Some(json) = data.strip_prefix(cyphr_storage::engine::COMMIT_MANIFEST_PREFIX) {
            let m: serde_json::Value = serde_json::from_slice(json).expect("manifest");
            if m["commit"]["commit_ids"][0] == commit_id {
                return hash;
            }
        }
    }
    panic!("no commit manifest records {commit_id}");
}

mod eml {
    //! The commit log (EML) stays a cache of the canonical chain (I1).

    use std::sync::{Arc, Mutex};

    use cyphr_blob_fjall::storage_fjall::FjallStorage;
    use cyphr_blob_fjall::{EmlLogs, FjallBlobStore};
    use cyphr_index_fjall::FjallIndexer;
    use cyphr_storage::engine::LogFactory;

    use super::*;

    type Durable = StorageEngine<FjallBlobStore, FjallIndexer, FjallStorage>;

    /// The durable logs, recording each generation the engine opens.
    struct Recorded {
        logs: EmlLogs,
        opened: Arc<Mutex<Vec<u64>>>,
    }

    impl LogFactory<FjallStorage> for Recorded {
        fn generation(&self, principal_id: &str) -> Result<u64, String> {
            self.logs.generation(principal_id)
        }

        fn open(&self, principal_id: &str, generation: u64) -> Result<FjallStorage, String> {
            self.opened.lock().expect("lock").push(generation);
            self.logs.open(principal_id, generation)
        }

        fn retire_below(&self, principal_id: &str, generation: u64) -> Result<(), String> {
            self.logs.retire_below(principal_id, generation)
        }
    }

    /// The durable store under `dir`, as a process opens it at start.
    fn open(dir: &std::path::Path) -> (Durable, Arc<Mutex<Vec<u64>>>) {
        let db = fjall::Database::builder(dir.join("blobs"))
            .open()
            .expect("db");
        let opened = Arc::new(Mutex::new(Vec::new()));
        let logs = Recorded {
            logs: EmlLogs::new(db.clone()).expect("logs"),
            opened: opened.clone(),
        };
        let engine = StorageEngine::with_log_factory(
            FjallBlobStore::from_database(db).expect("blobs"),
            FjallIndexer::open(&dir.join("index")).expect("index"),
            logs,
        );
        (engine, opened)
    }

    /// Claim: when a resolving commit re-points the chain under a durable
    /// log, the next start regenerates the log into a fresh generation
    /// whose roots match a replay of the canonical chain, retires the old
    /// one, and every later start opens the current generation directly.
    /// Turns red if the old log is reused (its leaf for A refuses B), or a
    /// restart opens a retired generation. End-to-end scenario: a durable
    /// store restarted twice (I1).
    #[tokio::test]
    async fn eml_is_regenerated_when_the_chain_is_repointed() {
        let s = Scenario::new().await;
        let (resolved, _) = s.resolved_store().await;
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let (e, _) = open(dir.path());
            e.submit_commit(&s.id, Some(s.genesis.clone()), &s.g)
                .await
                .expect("G");
            e.submit_commit(&s.id, Some(s.genesis.clone()), &s.a)
                .await
                .expect("A");
            // The resolving commit lands as blobs: every blob of the
            // resolved store, C's among them.
            for hash in resolved.blob_store().iter().await.expect("iter") {
                let hash = hash.expect("hash");
                let data = resolved.blob_store().get(&hash).await.expect("get");
                e.blob_store().put(&data.expect("held")).await.expect("put");
            }
        }

        let replayed = Engine::new(resolved.blob_store().clone(), MemoryIndexer::new())
            .rederive_roots(&s.id)
            .await
            .expect("replay of the canonical chain");
        let (e, opened) = open(dir.path());
        let roots = e.rederive_roots(&s.id).await.expect("regenerated");
        assert_eq!(
            roots, replayed,
            "the regenerated log is the canonical chain's"
        );
        assert_eq!(
            *opened.lock().expect("lock"),
            [0, 1],
            "generation 0 is stale"
        );
        assert_eq!(
            LogFactory::generation(&EmlLogs::new(db_of(&e)).expect("logs"), &s.id),
            Ok(1)
        );
        drop(e);

        let (e, opened) = open(dir.path());
        assert_eq!(e.rederive_roots(&s.id).await.expect("restart"), replayed);
        assert_eq!(
            *opened.lock().expect("lock"),
            [1],
            "a restart opens the current log"
        );
    }

    fn db_of(e: &Durable) -> fjall::Database {
        e.blob_store().database().clone()
    }
}
