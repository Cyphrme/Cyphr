//! U3 engine-level scaling bench: what each storage operation costs as a
//! principal's history grows, beside the bound it is held to. Counts the
//! engine's replayed commits, kept-state hits, the blob and index reads
//! (counting wrappers around the real fjall stores), data-action
//! signatures (the core's probe), and wall time.
//!
//! Run: `cargo bench -p cyphr-storage --bench u3_engine` (see
//! `rs/bench-u3.sh` for the whole suite). `U3_NS=10,100` overrides the
//! history lengths.

mod common;

use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use common::{Chain, Ctr, Disk, Engine, bad_signature, median};
use cyphr::state::TaggedDigest;
use cyphr::replay::WireBundle;

/// One operation's measured cost.
#[derive(Default, Clone, Copy)]
struct Cost {
    replayed: u64,
    sigs: u64,
    idx_calls: u64,
    idx_rows: u64,
    blobs: u64,
    blob_kb: f64,
    ms: f64,
}

struct Probe<'a>(&'a Engine, &'a Ctr, u64, u64, u64, u64, u64, u64, Instant);

fn start<'a>(e: &'a Engine, c: &'a Ctr) -> Probe<'a> {
    Probe(
        e,
        c,
        e.commits_replayed(),
        cyphr::probe::signatures_checked(),
        c.idx_calls.load(Relaxed),
        c.idx_rows.load(Relaxed),
        c.blob_gets.load(Relaxed),
        c.blob_bytes.load(Relaxed),
        Instant::now(),
    )
}

impl Probe<'_> {
    fn stop(self) -> Cost {
        Cost {
            replayed: self.0.commits_replayed() - self.2,
            sigs: cyphr::probe::signatures_checked() - self.3,
            idx_calls: self.1.idx_calls.load(Relaxed) - self.4,
            idx_rows: self.1.idx_rows.load(Relaxed) - self.5,
            blobs: self.1.blob_gets.load(Relaxed) - self.6,
            blob_kb: (self.1.blob_bytes.load(Relaxed) - self.7) as f64 / 1024.0,
            ms: self.8.elapsed().as_secs_f64() * 1e3,
        }
    }
}

fn row(n: usize, op: &str, bound: &str, c: Cost) {
    println!(
        "| {n} | {op} | {bound} | {} | {} | {} | {} | {} | {:.1} | {:.3} |",
        c.replayed, c.sigs, c.idx_calls, c.idx_rows, c.blobs, c.blob_kb, c.ms
    );
}

/// Measure `f` against `e`, repeated `reps` times: per-rep medians of time,
/// the last rep's counts (they do not vary).
async fn measure<F, Fut>(e: &Engine, d: &Disk, reps: usize, mut f: F) -> Cost
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut times = Vec::new();
    let mut last = Cost::default();
    for _ in 0..reps {
        let p = start(e, &d.ctr);
        f().await;
        last = p.stop();
        times.push(last.ms);
    }
    last.ms = median(times);
    last
}

async fn run(n: usize) {
    let d = Disk::new();
    let e = d.engine();
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let t = Instant::now();
    e.submit_commit(&chain.id, Some(chain.genesis.clone()), &chain.first())
        .await
        .expect("genesis");
    while chain.commits < n {
        let b = chain.next().await;
        e.submit_commit(&chain.id, Some(chain.genesis.clone()), &b)
            .await
            .expect("history commit");
    }
    eprintln!("n={n}: history built in {:.1}s", t.elapsed().as_secs_f64());
    let g = Some(chain.genesis.clone());
    let id = chain.id.clone();

    // write to a kept principal: each rep is a real next commit.
    let mut pending: Vec<WireBundle> = Vec::new();
    for _ in 0..5 {
        pending.push(chain.next().await);
    }
    let mut it = pending.into_iter();
    let c = measure(&e, &d, 5, || {
        let b = it.next().expect("bundle");
        let (e, id, g) = (&e, &id, g.clone());
        async move {
            e.submit_commit(id, g, &b).await.expect("write");
        }
    })
    .await;
    row(n, "write 1 commit (kept)", "replayed 0", c);

    let c = measure(&e, &d, 5, || async {
        e.get_tip(&id).await.expect("tip").expect("some");
    })
    .await;
    row(n, "read /tip (get_tip)", "replayed 0, O(1) rows", c);

    let tip = e.get_tip(&id).await.expect("tip").expect("some");
    let anchor: TaggedDigest = tip.commit_id.parse().expect("commit id digest");
    let c = measure(&e, &d, 5, || async {
        e.get_served_patch(&id, Some(&anchor), None)
            .await
            .expect("patch");
    })
    .await;
    row(n, "read /patch from tip", "replayed 0, O(1) rows", c);

    let next = chain.next().await;
    let bad = bad_signature(&next);
    let c = measure(&e, &d, 3, || async {
        e.submit_commit(&id, g.clone(), &bad)
            .await
            .expect_err("bad signature refused");
    })
    .await;
    row(n, "refused push, bad signature", "O(bundle), indep. of n", c);

    let mut other = Chain::new("alice", "key_a", "key_b").await;
    let _ = other.next().await;
    let stranger = other.next().await;
    let c = measure(&e, &d, 3, || async {
        e.submit_commit(&id, g.clone(), &stranger)
            .await
            .expect_err("stranger's commit refused");
    })
    .await;
    row(n, "refused push, unknown key", "O(bundle), indep. of n", c);

    // The accepted commit after the refusals still extends the kept state.
    let c = measure(&e, &d, 1, || async {
        e.submit_commit(&id, g.clone(), &next).await.expect("write");
    })
    .await;
    row(n, "write after refusals (kept)", "replayed 0", c);

    // Restart: a fresh engine over the same durable stores keeps nothing.
    drop(e);
    let e = d.engine();
    let w1 = chain.next().await;
    let w2 = chain.next().await;
    let c = measure(&e, &d, 1, || async {
        e.submit_commit(&id, g.clone(), &w1).await.expect("write");
    })
    .await;
    row(n, "restart: 1st write", "replayed O(n) once", c);
    let c = measure(&e, &d, 1, || async {
        e.submit_commit(&id, g.clone(), &w2).await.expect("write");
    })
    .await;
    row(n, "restart: 2nd write", "replayed 0", c);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ns: Vec<usize> = std::env::var("U3_NS")
        .unwrap_or_else(|_| "10,100,1000".into())
        .split(',')
        .map(|s| s.trim().parse().expect("U3_NS is a list of counts"))
        .collect();
    println!("| n | operation | bound | replayed | data sigs | idx calls | idx rows | blobs read | blob KB | ms |");
    println!("|--:|---|---|--:|--:|--:|--:|--:|--:|--:|");
    for n in ns {
        run(n).await;
    }
}
