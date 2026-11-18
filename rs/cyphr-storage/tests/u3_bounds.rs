//! U3 cost bounds of the storage engine, pinned as counts (never time):
//! what an operation reads and replays must not grow with the length of
//! the principal's history. Each operation runs once on a principal of 8
//! commits and once on one of 40; a bound that holds shows the same count
//! at both, so an O(n) path is red at once and no timing is involved.
//! The timed counterpart is `cargo bench -p cyphr-storage --bench
//! u3_engine`.
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

const SHORT: usize = 8;
const LONG: usize = 40;

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

static OBS: OnceCell<[Obs; 2]> = OnceCell::const_new();

async fn obs() -> &'static [Obs; 2] {
    OBS.get_or_init(|| async { [observe(SHORT).await, observe(LONG).await] })
        .await
}

fn same(what: &str, pick: impl Fn(&Obs) -> Counts, o: &[Obs; 2]) {
    let (s, l) = (pick(&o[0]), pick(&o[1]));
    assert_eq!(
        s, l,
        "{what}: counts at n={} and n={} differ (short {s:?}, long {l:?})",
        o[0].n, o[1].n
    );
}

/// Bound: a write to a kept principal replays 0 old commits, at any n.
#[tokio::test]
async fn write_replays_no_old_commit() {
    for o in obs().await {
        assert_eq!(o.write.replayed, 0, "n={}: {:?}", o.n, o.write);
    }
}

/// Bound: a write to a kept principal reads a number of blobs independent
/// of n.
#[tokio::test]
async fn write_blob_reads_do_not_grow() {
    let o = obs().await;
    assert_eq!(o[0].write.blobs, o[1].write.blobs, "{o:?}");
}

/// Bound: a write reads O(1) index rows, independent of n.
#[tokio::test]
async fn write_index_rows_do_not_grow() {
    let o = obs().await;
    assert_eq!(o[0].write.idx_rows, o[1].write.idx_rows, "{o:?}");
}

/// Bound: reading the tip replays 0 commits and reads O(1) index rows,
/// independent of n.
#[tokio::test]
async fn tip_read_is_constant() {
    let o = obs().await;
    same("get_tip", |o| o.tip, o);
    assert_eq!(o[1].tip.replayed, 0);
}

/// Bound: serving a patch from the tip replays 0 commits and reads O(1)
/// index rows, independent of n.
#[tokio::test]
async fn patch_from_tip_is_constant() {
    let o = obs().await;
    same("get_served_patch from tip", |o| o.patch, o);
}

/// Bound: asking whether a principal is in Error (read by /tip, /patch,
/// /consistency and /inclusion before they answer) reads O(1) index rows,
/// independent of n.
#[tokio::test]
async fn error_state_is_constant() {
    let o = obs().await;
    same("error_state", |o| o.error_state, o);
}

/// Bound: asking whether the engine holds a commit (the gossip idle gate
/// asks it per peer head) reads O(1) index rows, independent of n.
#[tokio::test]
async fn holds_commit_is_constant() {
    let o = obs().await;
    same("holds_commit", |o| o.holds_commit, o);
}

/// Bound: a refused push (bad signature, or signed by a key the principal
/// does not hold) costs O(bundle): replays, index rows and blobs read are
/// independent of n.
#[tokio::test]
async fn refused_push_cost_is_independent_of_history() {
    let o = obs().await;
    same("bad signature", |o| o.bad_signature, o);
    same("unknown key", |o| o.unknown_key, o);
}

/// Bound: a refused push replays 0 commits, at any n.
#[tokio::test]
async fn refused_push_replays_nothing() {
    for o in obs().await {
        assert_eq!(o.bad_signature.replayed, 0, "{o:?}");
        assert_eq!(o.unknown_key.replayed, 0, "{o:?}");
    }
}

/// Bound: after a restart the first write replays the history once (at
/// most n plus the commits being written), the second replays 0.
#[tokio::test]
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

static RIVAL_OBS: OnceCell<[RivalObs; 2]> = OnceCell::const_new();

async fn rival_obs() -> &'static [RivalObs; 2] {
    RIVAL_OBS
        .get_or_init(|| async { [rival_observe(SHORT).await, rival_observe(LONG).await] })
        .await
}

async fn rival_same(what: &str, pick: impl Fn(&RivalObs) -> Counts) {
    let o = rival_obs().await;
    let (s, l) = (pick(&o[0]), pick(&o[1]));
    assert_eq!(
        s, l,
        "{what}: counts at n={} and n={} differ (short {s:?}, long {l:?})",
        o[0].n, o[1].n
    );
}

/// Bound: a stranger's refused push to a principal holding a retained rival
/// at position 1 costs O(bundle): the same replays, index rows and blobs at
/// any n, and no replay. A fork-state read made for every write, before the
/// bundle is authenticated, makes it O(n).
#[tokio::test]
async fn refused_push_cost_is_independent_of_history_with_a_rival_at_one() {
    rival_same("stranger", |o| o.stranger).await;
    for o in rival_obs().await {
        assert_eq!(o.stranger.replayed, 0, "{o:?}");
    }
}

/// Bound: `error_state` of a principal holding a retained rival at position
/// 1 reads the same rows at any n. The fork assessment is read for every
/// reader (`/tip`, `/consistency`, `/inclusion`), so a read of the canonical
/// chain from the rival down is O(n) for anyone, unauthenticated.
#[tokio::test]
async fn error_state_is_constant_with_a_rival_at_one() {
    rival_same("error_state", |o| o.error_state).await;
}

/// Bound: an honest write to a principal holding a retained rival at
/// position 1 reads the same rows at any n.
#[tokio::test]
async fn write_cost_is_independent_of_history_with_a_rival_at_one() {
    rival_same("write", |o| o.write).await;
}
