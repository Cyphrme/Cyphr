// NETSIM-1: the honest network, randomized.
//
// 5 gossiping attestors, 12 principals each published to 3-5 of them, 150
// seeded ops in 3 epochs (data commits, recorded actions, key add / replace /
// delete, device pairing, two devices committing at once, new principals,
// link partitions and degradation, peer stop and restart), at the servers'
// default limits. Barriers check N1 (every holder agrees with the owner's
// chain), N2 (honest ops are accepted, or refused Stale then accepted after
// rebase) and N6 (no 5xx, no 429, no panic, summed over every peer lifetime).
//
// Size and replay:
//   CYPHR_SCENARIO_SEED=n       another seed (the pinned one is the gate)
//   CYPHR_NETSIM_SIZE=large     9 peers, 60 principals, 2000 ops (manual)
//   CYPHR_NETSIM_OPS=n          only the first n ops of the log
//   CYPHR_NETSIM_REPLAY=file    run a recorded op log instead of generating
// A failing run prints the seed and keeps its op log; replaying that file
// repeats the same ops.

use std::path::PathBuf;
use std::time::Duration;

use cyphr_scenarios::Harness;
use cyphr_scenarios::netsim::plan::{self, Op};
use cyphr_scenarios::netsim::{Size, check, run};
use cyphr_scenarios::peer::Limits;

/// The gate's seed. A seed that goes red twice on an unrelated change is
/// moved to the scheduled run and filed, not retried.
const PINNED_SEED: u64 = 20_261_116;

fn seed() -> u64 {
    std::env::var("CYPHR_SCENARIO_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(PINNED_SEED)
}

// ---- the generator and the model need no network ----

#[test]
fn same_seed_same_op_log() {
    let size = Size::ci();
    assert_eq!(plan::generate(7, &size), plan::generate(7, &size));
    assert_ne!(plan::generate(7, &size), plan::generate(8, &size));
}

#[test]
fn an_op_log_survives_its_text_form() {
    let ops = plan::generate(3, &Size::ci());
    assert_eq!(plan::parse(&plan::render(&ops)).expect("parses"), ops);
}

// `generate` panics on an op the model refuses, so completing is the
// property: no seed produces an invalid log (a last-key delete, a write
// through a stopped peer, a heal of an uncut link).
#[test]
fn every_seed_generates_a_valid_log_that_covers_the_mix() {
    let size = Size::ci();
    let mut seen = std::collections::BTreeSet::new();
    for s in 0..40 {
        for op in plan::generate(s, &size) {
            seen.insert(op.to_string().split_whitespace().next().unwrap().to_owned());
        }
    }
    for kind in [
        "create",
        "commit",
        "record",
        "addkey",
        "pair",
        "replace",
        "delkey",
        "concurrent",
        "partition",
        "heal",
        "degrade",
        "calm",
        "stop",
        "start",
        "barrier",
    ] {
        assert!(
            seen.contains(kind),
            "no seed in 0..40 ever generates `{kind}`"
        );
    }
    let ops = plan::generate(PINNED_SEED, &size);
    assert_eq!(
        ops.iter().filter(|o| **o == Op::Barrier).count(),
        size.epochs
    );
}

// N6's verdict, on counters the live servers never produce.
#[test]
fn n6_names_every_kind_of_violation() {
    let counters = |s: &str| cyphr_scenarios::harness::counters(s);
    let clean = counters("cyphr_refusals_total{kind=\"stale\"} 4\n");
    assert_eq!(check::n6_diff("p0", &clean, &[]), None);
    let bad = counters(
        "cyphr_refusals_total{kind=\"server_error\"} \
         1\ncyphr_refusals_total{kind=\"rate_limited\"} 2\n",
    );
    let why = check::n6_diff("p0", &bad, &["thread 'x' panicked at".into()]).expect("red");
    for part in ["server_error", "rate_limited", "panic"] {
        assert!(why.contains(part), "{why}");
    }
}

// ---- the network ----

/// Keeps the op log where a failing run can be replayed from.
struct LogDir(Option<tempfile::TempDir>);

impl LogDir {
    fn path(&self) -> PathBuf {
        self.0.as_ref().expect("log dir").path().join("ops.log")
    }

    fn keep(mut self) -> PathBuf {
        self.0.take().expect("log dir").keep().join("ops.log")
    }
}

impl Drop for LogDir {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(d) = self.0.take()
        {
            eprintln!("op log kept at {}", d.keep().join("ops.log").display());
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn netsim_honest_network() {
    let (seed, size) = (seed(), Size::from_env());
    let ops = run::plan_from_env(seed, &size).unwrap_or_else(|e| panic!("op log: {e}"));
    let dir = LogDir(Some(
        tempfile::Builder::new()
            .prefix("cyphr-netsim-")
            .tempdir()
            .expect("log dir"),
    ));
    std::fs::write(dir.path(), plan::render(&ops)).expect("writing the op log");
    eprintln!(
        "NETSIM seed={seed} size={size:?} ops={} log={}",
        ops.len(),
        dir.path().display()
    );

    let names = size.peer_names();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let h = Harness::start_gossiping_seeded(&names, 1, Limits::default(), seed)
        .await
        .expect("start peers");

    match run::run(&h, &size, &ops).await {
        Ok(out) => {
            let slowest = out
                .convergence
                .iter()
                .max()
                .copied()
                .unwrap_or(Duration::ZERO);
            eprintln!(
                "NETSIM ok: {} ops, {} stale retries for {} concurrent ops, convergence {:?}, \
                 wall {:?}",
                out.ops, out.stale_retries, out.concurrent_ops, out.convergence, out.wall
            );
            eprintln!("NETSIM slowest convergence {slowest:?}");
        },
        Err(f) => {
            let log = dir.keep();
            panic!(
                "NETSIM FAILED {f}\n  seed = {seed}\n  size = {size:?}\n  op log: {}\n  replay: \
                 CYPHR_SCENARIO_SEED={seed} CYPHR_NETSIM_REPLAY={} cargo test -p cyphr-scenarios \
                 --test netsim netsim_honest_network",
                log.display(),
                log.display(),
            );
        },
    }
}
