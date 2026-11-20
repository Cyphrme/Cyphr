//! Property: `EmlLogs` behaves as a model of per-principal, per-generation
//! logs over any interleaving of appends, regenerations, interrupted
//! regenerations, crashes between recording a generation and retiring its
//! predecessor, and reopens, for principal ids that are byte-prefixes of
//! one another.
//!
//! Claims checked after every operation:
//!
//! - the current generation of every principal's log equals the model (principals never see each
//!   other's leaves, whatever their ids);
//! - no retired generation's keys remain (immediately after a clean regeneration; after the next
//!   open of the current generation if a crash intervened);
//! - opening a generation above the current one starts empty (what an interrupted regeneration left
//!   is discarded);
//! - the database's keyspace set never changes: creating a keyspace costs about fourteen fsyncs
//!   under a database-wide lock, so no operation may create one.

use std::collections::BTreeSet;

use cyphr_blob_fjall::EmlLogs;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_storage::engine::LogFactory;
use eml::Storage as _;
use fjall::{Database, KeyspaceCreateOptions};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Append {
        p: usize,
        data: Vec<u8>,
    },
    /// Rebuild a principal's log under the next generation. `crash`
    /// records the generation but dies before retiring the previous one.
    Regenerate {
        p: usize,
        leaves: Vec<Vec<u8>>,
        crash: bool,
    },
    /// A regeneration interrupted before it was recorded.
    Stray {
        p: usize,
        leaves: Vec<Vec<u8>>,
    },
    Reopen,
}

fn data() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..6)
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (any::<usize>(), data()).prop_map(|(p, data)| Op::Append { p, data }),
        2 => (any::<usize>(), prop::collection::vec(data(), 0..3), any::<bool>())
            .prop_map(|(p, leaves, crash)| Op::Regenerate { p, leaves, crash }),
        1 => (any::<usize>(), prop::collection::vec(data(), 1..3))
            .prop_map(|(p, leaves)| Op::Stray { p, leaves }),
        1 => Just(Op::Reopen),
    ]
}

/// Ids that are prefixes of one another by construction.
fn principals() -> impl Strategy<Value = Vec<String>> {
    prop::collection::btree_set("SHA-256:[ab]{0,3}", 2..5).prop_map(|ids| ids.into_iter().collect())
}

type Log = FjallStorage;

async fn leaves(log: &Log) -> Vec<Vec<u8>> {
    let n = log.len().await.expect("len");
    let mut out = Vec::new();
    for i in 0..n {
        out.push(log.get_leaf(i).await.expect("leaf"));
    }
    out
}

async fn append(log: &mut Log, data: &[u8]) {
    let at = log.len().await.expect("len");
    log.apply(&[eml::WriteOp::AppendLeaf {
        at,
        data,
        nodes: &[],
    }])
    .await
    .expect("append");
}

fn keyspace_names(db: &Database) -> BTreeSet<String> {
    db.list_keyspace_names()
        .into_iter()
        .map(|n| n.to_string())
        .collect()
}

#[derive(Clone, Default)]
struct Model {
    generation: u64,
    leaves: Vec<Vec<u8>>,
    /// A crash left the previous generation's keys until the next open of
    /// the current one.
    unswept: bool,
}

async fn run(ids: Vec<String>, ops: Vec<Op>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::builder(dir.path()).open().expect("db");
    let mut logs = EmlLogs::new(db.clone()).expect("logs");
    let generations = db
        .keyspace("eml_generations", KeyspaceCreateOptions::default)
        .expect("generations");
    let keyspaces = keyspace_names(&db);
    let mut model = vec![Model::default(); ids.len()];

    for op in ops {
        match op {
            Op::Append { p, data } => {
                let p = p % ids.len();
                let mut log = logs.open(&ids[p], model[p].generation).expect("open");
                append(&mut log, &data).await;
                model[p].unswept = false;
                model[p].leaves.push(data);
            },
            Op::Regenerate {
                p,
                leaves: new,
                crash,
            } => {
                let p = p % ids.len();
                let next = model[p].generation + 1;
                let mut log = logs.open(&ids[p], next).expect("open next");
                assert_eq!(
                    log.len().await.expect("len"),
                    0,
                    "a regeneration starts empty"
                );
                for leaf in &new {
                    append(&mut log, leaf).await;
                }
                if crash {
                    generations
                        .insert(ids[p].as_bytes(), next.to_be_bytes())
                        .expect("record");
                } else {
                    logs.retire_below(&ids[p], next).expect("retire");
                }
                model[p] = Model {
                    generation: next,
                    leaves: new,
                    unswept: crash,
                };
            },
            Op::Stray { p, leaves: stray } => {
                let p = p % ids.len();
                let mut log = logs
                    .open(&ids[p], model[p].generation + 1)
                    .expect("open stray");
                for leaf in &stray {
                    append(&mut log, leaf).await;
                }
            },
            Op::Reopen => {
                drop(logs);
                logs = EmlLogs::new(db.clone()).expect("logs");
            },
        }

        for (p, id) in ids.iter().enumerate() {
            let m = &model[p];
            if !m.unswept {
                for older in 0..m.generation {
                    let log = logs.open(id, older).expect("open older");
                    assert_eq!(
                        log.len().await.expect("len"),
                        0,
                        "{id}: generation {older} kept keys"
                    );
                }
            }
            assert_eq!(
                LogFactory::<Log>::generation(&logs, id).expect("generation"),
                m.generation,
                "{id}: recorded generation"
            );
            let log = logs.open(id, m.generation).expect("open current");
            assert_eq!(leaves(&log).await, m.leaves, "{id}: current log");
            for older in 0..m.generation {
                let log = logs.open(id, older).expect("open older");
                assert_eq!(
                    log.len().await.expect("len"),
                    0,
                    "{id}: generation {older} survived the sweep"
                );
            }
            model[p].unswept = false;
        }
        assert_eq!(
            keyspace_names(&db),
            keyspaces,
            "the keyspace set must not change"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn eml_logs_match_the_model(ids in principals(), ops in prop::collection::vec(op(), 1..24)) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(run(ids, ops));
    }
}
