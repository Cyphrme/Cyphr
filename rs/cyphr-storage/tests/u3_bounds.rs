//! U3 cost bounds of the storage engine, pinned as counts (never time):
//! what an operation reads and replays must not grow with the length of
//! the principal's history. Each operation runs on a principal of each of
//! three sizes (see `suite!` below); a bound that holds shows the same
//! count at all three, so an O(n) path is red at once, and an O(log n) one
//! too (an exact-equality bound sees log2 grow), and no timing is involved.
//! The timed counterpart is `cargo bench -p cyphr-storage --bench
//! u3_engine`.
//!
//! The engines these tests build have the kept-state shadow check
//! (`CYPHR_KEPT_SHADOW`) off: it replays cold on every use and those
//! replays and reads are counted too, so with it on the counts would measure
//! the check and not the engine.
//!
//! A red test is a bound the engine does not yet meet: the finding, not a
//! defect of the test.
//!
//! "Index rows" counts only the engine's `chain()` rows, so an O(n) read
//! through any other indexer call is not seen by these tests.

#[path = "../benches/common/mod.rs"]
mod common;

use common::{Chain, Disk, bad_signature};
use cyphr::state::TaggedDigest;
use tokio::sync::OnceCell;

/// What one operation cost: commits replayed, index rows and blobs read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    replayed: u64,
    idx_rows: u64,
    blobs: u64,
}

#[derive(Debug)]
struct Obs {
    write: Counts,
    tip: Counts,
    patch: Counts,
    error_state: Counts,
    holds_commit: Counts,
    bad_signature: Counts,
    unknown_key: Counts,
    restart_first: Counts,
    restart_second: Counts,
    n: u64,
}

async fn observe(n: usize) -> Obs {
    use std::sync::atomic::Ordering::Relaxed;
    let d = Disk::new();
    let mut e = d.engine();
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let g = Some(chain.genesis.clone());
    let id = chain.id.clone();
    e.submit_commit(&id, g.clone(), &chain.first())
        .await
        .expect("genesis");
    while chain.commits < n {
        let b = chain.next().await;
        e.submit_commit(&id, g.clone(), &b).await.expect("history");
    }

    macro_rules! counted {
        ($e:expr) => {{
            let before = (
                e.commits_replayed(),
                d.ctr.idx_rows.load(Relaxed),
                d.ctr.blob_gets.load(Relaxed),
            );
            let _ = $e.await;
            Counts {
                replayed: e.commits_replayed() - before.0,
                idx_rows: d.ctr.idx_rows.load(Relaxed) - before.1,
                blobs: d.ctr.blob_gets.load(Relaxed) - before.2,
            }
        }};
    }

    let w = chain.next().await;
    let write = counted!(async { e.submit_commit(&id, g.clone(), &w).await.expect("write") });
    let tip = counted!(e.get_tip(&id));
    let tip_id = e.get_tip(&id).await.expect("tip").expect("some").commit_id;
    let anchor: TaggedDigest = tip_id.parse().expect("commit id digest");
    let patch = counted!(e.get_served_patch(&id, Some(&anchor), None));

    let error_state = counted!(e.error_state(&id));
    let holds_commit = counted!(e.holds_commit(&id, &tip_id));

    let next = chain.next().await;
    let bad = bad_signature(&next);
    let bad_signature = counted!(async {
        e.submit_commit(&id, g.clone(), &bad)
            .await
            .expect_err("bad signature refused")
    });
    let mut other = Chain::new("alice", "key_a", "key_b").await;
    let _ = other.next().await;
    let stranger = other.next().await;
    let unknown_key = counted!(async {
        e.submit_commit(&id, g.clone(), &stranger)
            .await
            .expect_err("a stranger's commit refused")
    });
    e.submit_commit(&id, g.clone(), &next).await.expect("next");

    e = d.engine();
    let (w1, w2) = (chain.next().await, chain.next().await);
    let restart_first =
        counted!(async { e.submit_commit(&id, g.clone(), &w1).await.expect("write") });
    let restart_second =
        counted!(async { e.submit_commit(&id, g.clone(), &w2).await.expect("write") });
    Obs {
        write,
        tip,
        patch,
        error_state,
        holds_commit,
        bad_signature,
        unknown_key,
        restart_first,
        restart_second,
        n: chain.commits as u64,
    }
}

/// What operations cost a principal whose retained rival sits at position
/// 1, the shape theft recovery leaves for good. Measured apart from
/// [`observe`]: the other counts there are of a principal with no fork.
#[derive(Debug)]
struct RivalObs {
    n: u64,
    stranger: Counts,
    error_state: Counts,
    write: Counts,
}

async fn rival_observe(n: usize) -> RivalObs {
    use std::sync::atomic::Ordering::Relaxed;
    let d = Disk::new();
    let e = d.engine();
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let g = Some(chain.genesis.clone());
    let id = chain.id.clone();
    e.submit_commit(&id, g.clone(), &chain.first())
        .await
        .expect("genesis");
    while chain.commits < n {
        let b = chain.next().await;
        e.submit_commit(&id, g.clone(), &b).await.expect("history");
    }
    let mut rival = Chain::new("golden", "key_a", "key_b").await;
    rival.diverge("diana_es384");
    let at_one = rival.next().await;
    e.submit_commit(&id, g.clone(), &at_one)
        .await
        .expect_err("a rival at position 1 is retained, not served");

    macro_rules! counted {
        ($e:expr) => {{
            let before = (
                e.commits_replayed(),
                d.ctr.idx_rows.load(Relaxed),
                d.ctr.blob_gets.load(Relaxed),
            );
            let _ = $e.await;
            Counts {
                replayed: e.commits_replayed() - before.0,
                idx_rows: d.ctr.idx_rows.load(Relaxed) - before.1,
                blobs: d.ctr.blob_gets.load(Relaxed) - before.2,
            }
        }};
    }
    let mut other = Chain::new("alice", "key_a", "key_b").await;
    let _ = other.next().await;
    let stranger_bundle = other.next().await;
    let stranger = counted!(async {
        e.submit_commit(&id, g.clone(), &stranger_bundle)
            .await
            .expect_err("a stranger's commit refused")
    });
    let error_state = counted!(e.error_state(&id));
    let next = chain.next().await;
    let write = counted!(async { e.submit_commit(&id, g.clone(), &next).await.expect("write") });
    RivalObs {
        n: chain.commits as u64,
        stranger,
        error_state,
        write,
    }
}
/// Principals `(signer, added)` of the pool, each with its own id.
const PAIRS: [(&str, &str); 3] = [("golden", "key_a"), ("alice", "bob"), ("carol", "key_b")];

/// Bound: the fork reads kept between uses are bounded. Reading the tip of
/// more principals than the capacity leaves the map at or under it, and a
/// principal with no rival, whose fork read is one row, is not kept at all
/// (an anonymous walk of `GET /tip` over every principal must not fill it).
#[tokio::test]
async fn kept_fork_reads_are_bounded_and_only_for_rivals() {
    const CAPACITY: usize = 1;
    let d = common::Disk::new();
    let e = d.engine().with_kept_states(CAPACITY);
    let mut ids = Vec::new();
    for (signer, added) in PAIRS {
        let mut chain = Chain::new(signer, added, "diana_es384").await;
        let g = Some(chain.genesis.clone());
        let id = chain.id.clone();
        e.submit_commit(&id, g.clone(), &chain.first())
            .await
            .expect("genesis");
        let b = chain.next().await;
        e.submit_commit(&id, g, &b).await.expect("history");
        ids.push((id, signer, added, chain));
    }
    for (id, ..) in &ids {
        e.get_tip(id).await.expect("tip");
    }
    assert_eq!(e.forks_cached(), 0, "principals with no rival are not kept");

    for (id, signer, added, chain) in &ids {
        let mut rival = Chain::new(signer, added, "diana_es384").await;
        rival.diverge("eve_ed25519");
        let at_one = rival.next().await;
        e.submit_commit(id, Some(chain.genesis.clone()), &at_one)
            .await
            .expect_err("a rival at position 1 is retained");
    }
    for (id, ..) in &ids {
        e.get_tip(id).await.expect("tip");
    }
    assert!(
        e.forks_cached() <= CAPACITY,
        "{} fork reads kept over a capacity of {CAPACITY}",
        e.forks_cached()
    );
}

/// An in-memory commit log that counts the leaf and node reads made of it.
#[derive(Clone, Default)]
struct Reads {
    inner: cyphr::eml::MemoryStorage,
    reads: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Reads {
    fn bump(&self) {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

type Inner = cyphr::eml::MemoryStorage;
type InnerError = <Inner as cyphr::eml::Storage>::Error;

impl cyphr::eml::Storage for Reads {
    type Error = InnerError;

    async fn get_leaf(&self, index: u64) -> Result<Vec<u8>, InnerError> {
        self.bump();
        self.inner.get_leaf(index).await
    }

    async fn len(&self) -> Result<u64, InnerError> {
        self.inner.len().await
    }

    async fn get_node(
        &self,
        alg_id: u64,
        left: u64,
        height: u32,
    ) -> Result<Option<Vec<u8>>, InnerError> {
        self.bump();
        self.inner.get_node(alg_id, left, height).await
    }

    async fn load_algorithm_metas(&self) -> Result<cyphr::eml::AlgorithmMetas, InnerError> {
        self.inner.load_algorithm_metas().await
    }

    async fn append_count(&self) -> Result<u64, InnerError> {
        self.inner.append_count().await
    }

    async fn apply(&mut self, ops: &[cyphr::eml::WriteOp<'_>]) -> Result<(), InnerError> {
        self.inner.apply(ops).await
    }
}

/// Leaf and node reads one `detach` of a principal of `n` commits costs, on
/// a chain where SHA-256 joined (an ES256 key paired in) and left (that key
/// deleted) at the start, so its log holds a closed algorithm.
async fn detach_reads(n: usize) -> u64 {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr::signer::SoftwareSigner;
    use serde_json::json;

    struct Kp(coz::Alg, String, Vec<u8>, Vec<u8>, coz::Thumbprint);
    let kp = |alg: coz::Alg| {
        let k = alg.generate_keypair();
        let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("tmb");
        Kp(alg, k.alg.name().to_string(), k.prv_bytes, k.pub_bytes, tmb)
    };
    let key = |k: &Kp| cyphr::Key::new(k.1.clone(), k.4.clone(), k.3.clone()).expect("key");
    let (owner, paired, spare) = (
        kp(coz::Alg::Ed25519),
        kp(coz::Alg::ES256),
        kp(coz::Alg::Ed25519),
    );
    let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());

    let storage = Reads::default();
    let reads = storage.reads.clone();
    let mut p = cyphr::Principal::open(key(&owner), storage)
        .await
        .expect("open");
    let signer = SoftwareSigner::new(&owner.1, &owner.2, &owner.3, &owner.4);
    p.commit_genesis(&signer, &[], 1_700_000_000, "cyphr.me")
        .await
        .expect("genesis");
    // Each commit creates or deletes one key; the paired ES256 key leaves
    // for good at commit 2, the spare toggles for the rest.
    let steps: Vec<(&str, &Kp)> = ["create", "delete"]
        .into_iter()
        .map(|t| (t, &paired))
        .chain(
            (0..n.saturating_sub(3))
                .map(|i| (if i % 2 == 0 { "create" } else { "delete" }, &spare)),
        )
        .collect();
    for (i, (typ, id)) in steps.into_iter().enumerate() {
        let now = 1_700_000_010 + 10 * i as i64;
        let mut pay = json!({"alg": owner.1, "id": b64(&id.4), "now": now, "tmb": b64(&owner.4),
                             "typ": format!("cyphr.me/cyphr/key/{typ}")});
        pay.as_object_mut().expect("object").sort_keys();
        let v = serde_json::to_vec(&pay).expect("pay");
        let (sig, cad) = coz::sign_json(&v, &owner.1, &owner.2, &owner.3).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &owner.1).expect("czd");
        let mut scope = p.begin_commit();
        scope
            .verify_and_apply(&v, &sig, czd, (typ == "create").then(|| key(id)))
            .expect("apply");
        scope
            .finalize_with_software(&signer, now + 1, "cyphr.me")
            .await
            .expect("commit");
    }
    let _ = (&owner.0, &spare.0);
    let before = reads.load(std::sync::atomic::Ordering::Relaxed);
    let _detached = p.detach().await.expect("detach");
    reads.load(std::sync::atomic::Ordering::Relaxed) - before
}

/// The bounds above, run on principals of each of the sizes `$sizes` and
/// generated twice (below): `fast`, in the normal test run, and `large`,
/// `#[ignore]`d for its build time.
macro_rules! suite {
    ($m:ident, $sizes:expr $(, #[$attr:meta])?) => {
        mod $m {
            use super::*;

            const SIZES: [usize; 3] = $sizes;

    static OBS: OnceCell<Vec<Obs>> = OnceCell::const_new();

    async fn obs() -> &'static [Obs] {
        OBS.get_or_init(|| async {
            let mut all = Vec::new();
            for n in SIZES {
                all.push(observe(n).await);
            }
            all
        })
        .await
    }

    /// Every size's count of `what` equals the smallest size's.
    fn same(what: &str, pick: impl Fn(&Obs) -> Counts, o: &[Obs]) {
        let first = pick(&o[0]);
        for later in &o[1..] {
            assert_eq!(
                pick(later),
                first,
                "{what}: counts at n={} and n={} differ",
                o[0].n,
                later.n
            );
        }
    }

    /// Bound: a write to a kept principal replays 0 old commits, at any n.
    #[tokio::test]
    $(#[$attr])?
    async fn write_replays_no_old_commit() {
        for o in obs().await {
            assert_eq!(o.write.replayed, 0, "n={}: {:?}", o.n, o.write);
        }
    }

    /// Bound: a write to a kept principal reads a number of blobs independent
    /// of n.
    #[tokio::test]
    $(#[$attr])?
    async fn write_blob_reads_do_not_grow() {
        same("write blobs", |o| Counts { replayed: 0, idx_rows: 0, blobs: o.write.blobs }, obs().await);
    }

    /// Bound: a write reads O(1) index rows, independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn write_index_rows_do_not_grow() {
        same("write idx rows", |o| Counts { replayed: 0, idx_rows: o.write.idx_rows, blobs: 0 }, obs().await);
    }

    /// Bound: reading the tip replays 0 commits and reads O(1) index rows,
    /// independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn tip_read_is_constant() {
        let o = obs().await;
        same("get_tip", |o| o.tip, o);
        assert!(o.iter().all(|o| o.tip.replayed == 0), "{o:?}");
    }

    /// Bound: serving a patch from the tip replays 0 commits and reads O(1)
    /// index rows, independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn patch_from_tip_is_constant() {
        let o = obs().await;
        same("get_served_patch from tip", |o| o.patch, o);
    }

    /// Bound: asking whether a principal is in Error (read by /tip, /patch
    /// and /proof before they answer) reads O(1) index rows,
    /// independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn error_state_is_constant() {
        let o = obs().await;
        same("error_state", |o| o.error_state, o);
    }

    /// Bound: asking whether the engine holds a commit (the gossip idle gate
    /// asks it per peer head) reads O(1) index rows, independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn holds_commit_is_constant() {
        let o = obs().await;
        same("holds_commit", |o| o.holds_commit, o);
    }

    /// Bound: a refused push (bad signature, or signed by a key the principal
    /// does not hold) costs O(bundle): replays, index rows and blobs read are
    /// independent of n.
    #[tokio::test]
    $(#[$attr])?
    async fn refused_push_cost_is_independent_of_history() {
        let o = obs().await;
        same("bad signature", |o| o.bad_signature, o);
        same("unknown key", |o| o.unknown_key, o);
    }

    /// Bound: a refused push replays 0 commits, at any n.
    #[tokio::test]
    $(#[$attr])?
    async fn refused_push_replays_nothing() {
        for o in obs().await {
            assert_eq!(o.bad_signature.replayed, 0, "{o:?}");
            assert_eq!(o.unknown_key.replayed, 0, "{o:?}");
        }
    }

    /// Bound: after a restart the first write replays the history once (at
    /// most n plus the commits being written), the second replays 0.
    #[tokio::test]
    $(#[$attr])?
    async fn restart_replays_once_then_nothing() {
        for o in obs().await {
            assert!(
                o.restart_first.replayed <= o.n + 2,
                "n={}: first write replayed {}",
                o.n,
                o.restart_first.replayed
            );
            assert_eq!(o.restart_second.replayed, 0, "n={}: {:?}", o.n, o);
        }
    }

    static RIVAL_OBS: OnceCell<Vec<RivalObs>> = OnceCell::const_new();

    async fn rival_obs() -> &'static [RivalObs] {
        RIVAL_OBS
            .get_or_init(|| async {
                let mut all = Vec::new();
                for n in SIZES {
                    all.push(rival_observe(n).await);
                }
                all
            })
            .await
    }

    async fn rival_same(what: &str, pick: impl Fn(&RivalObs) -> Counts) {
        let o = rival_obs().await;
        let first = pick(&o[0]);
        for later in &o[1..] {
            assert_eq!(
                pick(later),
                first,
                "{what}: counts at n={} and n={} differ",
                o[0].n,
                later.n
            );
        }
    }

    /// Bound: a stranger's refused push to a principal holding a retained rival
    /// at position 1 costs O(bundle): the same replays, index rows and blobs at
    /// any n, and no replay. A fork-state read made for every write, before the
    /// bundle is authenticated, makes it O(n).
    #[tokio::test]
    $(#[$attr])?
    async fn refused_push_cost_is_independent_of_history_with_a_rival_at_one() {
        rival_same("stranger", |o| o.stranger).await;
        for o in rival_obs().await {
            assert_eq!(o.stranger.replayed, 0, "{o:?}");
        }
    }

    /// Bound: `error_state` of a principal holding a retained rival at position
    /// 1 reads the same rows at any n. The fork assessment is read for every
    /// reader (`/tip`, `/patch`, `/proof`), so a read of the canonical
    /// chain from the rival down is O(n) for anyone, unauthenticated.
    #[tokio::test]
    $(#[$attr])?
    async fn error_state_is_constant_with_a_rival_at_one() {
        rival_same("error_state", |o| o.error_state).await;
    }

    /// Bound: an honest write to a principal holding a retained rival at
    /// position 1 reads the same rows at any n.
    #[tokio::test]
    $(#[$attr])?
    async fn write_cost_is_independent_of_history_with_a_rival_at_one() {
        rival_same("write", |o| o.write).await;
    }


    /// Bound: detaching a principal whose log holds an algorithm that left
    /// (SHA-256 closed by deleting its last key) reads O(log n) leaves and
    /// nodes, not O(n): the seal carries the closed algorithm's frontier, so
    /// nothing is copied leaf by leaf. A frontier read grows with the peaks of
    /// the size, so the bound is a small multiple, which a copy of every leaf
    /// (n reads) exceeds at once.
    #[tokio::test]
    $(#[$attr])?
    async fn detach_with_a_closed_algorithm_is_not_linear() {
        let short = detach_reads(SIZES[0]).await;
        for n in &SIZES[1..] {
            let long = detach_reads(*n).await;
            assert!(
                long <= 2 * short + 2,
                "log reads by detach: {short} at n={}, {long} at n={n}",
                SIZES[0]
            );
        }
    }

        }
    };
}

// Span 16x (one order of magnitude): n grows x16, log n x2, so a count
// that is O(n) or O(log n) is red against an exact-equality bound.
suite!(fast, [16, 64, 256]);
// Span 128x (two orders): the same bounds at a size where the gap between
// log n (x2.75) and n (x128) is not arguable. About 2 minutes of build.
suite!(
    large,
    [16, 256, 2048],
    #[ignore = "large: 2048-commit principals take about 2 minutes to build"]
);
