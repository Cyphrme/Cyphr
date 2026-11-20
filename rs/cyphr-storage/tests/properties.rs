//! Property-based tests for the cyphr-storage library.

use std::path::PathBuf;

use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_blob_fjall::{EmlLogs, FjallBlobStore};
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;
use cyphr_storage::{CommitEntry, Genesis};
use proptest::prelude::*;

const POOL_KEYS: &[&str] = &[
    "golden",
    "key_a",
    "alice",
    "bob",
    "carol",
    "diana_es384",
    "eve_ed25519",
];

#[derive(Debug, Clone, Copy)]
enum Step {
    CreateKey {
        target_idx: usize,
        signer_idx: usize,
        finalize_commit: bool,
    },
    RevokeKey {
        target_idx: usize,
        signer_idx: usize,
        finalize_commit: bool,
    },
    AddAction {
        signer_idx: usize,
        msg_idx: usize,
    },
}

fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        (any::<usize>(), any::<usize>(), any::<bool>()).prop_map(
            |(target_idx, signer_idx, finalize_commit)| Step::CreateKey {
                target_idx,
                signer_idx,
                finalize_commit
            }
        ),
        (any::<usize>(), any::<usize>(), any::<bool>()).prop_map(
            |(target_idx, signer_idx, finalize_commit)| Step::RevokeKey {
                target_idx,
                signer_idx,
                finalize_commit
            }
        ),
        (any::<usize>(), any::<usize>()).prop_map(|(signer_idx, msg_idx)| Step::AddAction {
            signer_idx,
            msg_idx
        }),
    ]
}

fn test_case_strategy() -> impl Strategy<Value = (usize, Vec<Step>)> {
    (
        any::<usize>(),
        prop::collection::vec(step_strategy(), 1..10),
    )
}

fn load_pool() -> test_fixtures::Pool {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent of cyphr-storage")
        .parent()
        .expect("parent of rs")
        .join("tests")
        .join("keys")
        .join("pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

fn golden_key_to_domain(gk: &test_fixtures::GoldenKey) -> cyphr::Key {
    use coz::Thumbprint;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&gk.pub_key).expect("invalid pub base64");
    let tmb_bytes = Base64UrlUnpadded::decode_vec(&gk.tmb).expect("invalid tmb base64");

    cyphr::Key::new(gk.alg.clone(), Thumbprint::from_bytes(tmb_bytes), pub_bytes)
        .expect("key binds its tmb")
}

fn build_intent(genesis_key_idx: usize, steps: Vec<Step>) -> test_fixtures::intent::TestIntent {
    let pool_keys = POOL_KEYS;
    let genesis_key = pool_keys[genesis_key_idx % pool_keys.len()].to_string();

    let mut active_keys = vec![genesis_key.clone()];
    let mut unused_keys: Vec<String> = pool_keys
        .iter()
        .filter(|&&k| k != genesis_key)
        .map(|&k| k.to_string())
        .collect();
    let mut revoked_keys = Vec::new();

    let mut commits = Vec::new();
    let mut actions = Vec::new();
    let mut current_txs = Vec::new();
    let mut now = 1000000i64;

    for step in steps {
        match step {
            Step::CreateKey {
                target_idx,
                signer_idx,
                finalize_commit,
            } => {
                if !unused_keys.is_empty() && !active_keys.is_empty() {
                    let target = unused_keys.remove(target_idx % unused_keys.len());
                    let signer = active_keys[signer_idx % active_keys.len()].clone();
                    active_keys.push(target.clone());

                    current_txs.push(vec![test_fixtures::intent::TxIntent {
                        typ: "cyphr.me/cyphr/key/create".to_string(),
                        now,
                        signer,
                        target: Some(target),
                        ..Default::default()
                    }]);

                    if finalize_commit {
                        commits.push(test_fixtures::intent::CommitIntent {
                            tx: std::mem::take(&mut current_txs),
                        });
                        now += 10;
                    }
                }
            },
            Step::RevokeKey {
                target_idx,
                signer_idx,
                finalize_commit,
            } => {
                if active_keys.len() > 1 {
                    let target = active_keys.remove(target_idx % active_keys.len());
                    revoked_keys.push(target.clone());
                    let signer = active_keys[signer_idx % active_keys.len()].clone();

                    current_txs.push(vec![test_fixtures::intent::TxIntent {
                        typ: "cyphr.me/cyphr/key/revoke".to_string(),
                        now,
                        signer,
                        target: Some(target),
                        rvk: Some(now + 5),
                        ..Default::default()
                    }]);

                    if finalize_commit {
                        commits.push(test_fixtures::intent::CommitIntent {
                            tx: std::mem::take(&mut current_txs),
                        });
                        now += 10;
                    }
                }
            },
            Step::AddAction {
                signer_idx,
                msg_idx,
            } => {
                if !active_keys.is_empty() {
                    let signer = active_keys[signer_idx % active_keys.len()].clone();
                    actions.push(test_fixtures::intent::ActionIntent {
                        typ: "cyphr.me/action".to_string(),
                        now,
                        signer,
                        msg: Some(format!("msg_{}", msg_idx)),
                        id: None,
                    });
                    now += 10;
                }
            },
        }
    }

    if !current_txs.is_empty() {
        commits.push(test_fixtures::intent::CommitIntent {
            tx: std::mem::take(&mut current_txs),
        });
    }

    // Guarantee we have at least one commit
    if commits.is_empty() {
        let signer = active_keys[0].clone();
        let target = unused_keys.remove(0);
        commits.push(test_fixtures::intent::CommitIntent {
            tx: vec![vec![test_fixtures::intent::TxIntent {
                typ: "cyphr.me/cyphr/key/create".to_string(),
                now: now + 10,
                signer,
                target: Some(target),
                ..Default::default()
            }]],
        });
    }

    test_fixtures::intent::TestIntent {
        name: format!("prop_test_{}", genesis_key_idx),
        principal: vec![genesis_key],
        commit: commits,
        action: actions,
        ..Default::default()
    }
}

/// A generated principal's history as the wire commits a client would
/// push: its id, its genesis, and its commit lines with each action-only
/// line carried into the next commit's bundle (SPEC 4.6.2 `actions`).
struct History {
    principal_id: String,
    genesis: Genesis,
    commits: Vec<CommitEntry>,
}

/// `None` for a generated intent that is cryptographically invalid or
/// commits nothing.
async fn history(
    pool: &test_fixtures::Pool,
    intent: test_fixtures::intent::TestIntent,
) -> Option<History> {
    let golden = test_fixtures::Generator::new(pool)
        .generate_test(&intent)
        .await
        .ok()?;
    let genesis_keys = golden.genesis_keys.as_ref()?;
    let mut commits = Vec::new();
    let mut pending_actions = Vec::new();
    for commit in golden.commits.as_ref()? {
        if commit.txs.is_empty() {
            pending_actions.extend(commit.actions.clone());
        } else {
            let mut actions = std::mem::take(&mut pending_actions);
            actions.extend(commit.actions.clone());
            commits.push(CommitEntry {
                actions,
                ..commit.clone()
            });
        }
    }
    if commits.is_empty() {
        return None;
    }
    let genesis = if genesis_keys.len() == 1 {
        Genesis::Implicit(golden_key_to_domain(&genesis_keys[0]))
    } else {
        Genesis::Disclosed(genesis_keys.iter().map(golden_key_to_domain).collect())
    };
    let principal_id = cyphr_storage::engine::genesis_principal_id(&genesis).ok()?;
    Some(History {
        principal_id,
        genesis,
        commits,
    })
}

async fn run_engine_recovery_test<B, I>(
    pool: &test_fixtures::Pool,
    intent: test_fixtures::intent::TestIntent,
    engine: cyphr_storage::engine::StorageEngine<B, I>,
) where
    B: cyphr_storage::blob::BlobStore + 'static,
    I: cyphr_storage::index::Indexer + cyphr_storage::index::IndexerWrite + 'static,
{
    let Some(History {
        principal_id,
        genesis,
        commits: merged_commits,
    }) = history(pool, intent).await
    else {
        return;
    };

    async {
        // Ingest commits sequentially
        for commit in &merged_commits {
            let bundle = commit.bundle().unwrap();
            engine
                .submit_commit(&principal_id, Some(genesis.clone()), &bundle)
                .await
                .expect("submit_commit failed");
        }

        // Get original tip state
        let original_tip = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("original tip should exist");

        // Read before the rebuild: an entity read after it would compare the
        // rebuilt index with itself and could never fail.
        let tagged_pr: cyphr::state::TaggedDigest = original_tip.pr.parse().unwrap();
        let original_entity = engine
            .indexer()
            .resolve_digest(&tagged_pr)
            .await
            .unwrap()
            .unwrap();

        // Re-submit the last commit to test idempotency
        let last_commit = merged_commits.last().unwrap();
        let bundle = last_commit.bundle().unwrap();

        let _ = engine
            .submit_commit(&principal_id, Some(genesis.clone()), &bundle)
            .await;

        let tip_after_dup = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("tip should still exist");
        assert_eq!(tip_after_dup.commit_count, original_tip.commit_count);
        assert_eq!(tip_after_dup.pr, original_tip.pr);
        assert_eq!(tip_after_dup.cr, original_tip.cr);

        // Discard the index and rebuild it from the durable manifests alone.
        engine
            .rebuild_index_from_scratch()
            .await
            .expect("rebuild failed");

        let recovered_tip = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("recovered tip should exist");

        assert_eq!(recovered_tip.commit_count, original_tip.commit_count);
        assert_eq!(recovered_tip.pr, original_tip.pr);
        assert_eq!(recovered_tip.sr, original_tip.sr);
        assert_eq!(recovered_tip.ar, original_tip.ar);
        // CR equality is checked explicitly, not just inferred from PR: PR
        // folds CR in, but a rebuild bug that recomputed a wrong CR while
        // still landing on the same PR (e.g. by chance collision in a
        // malformed fold) would slip past a PR-only check.
        assert!(
            !original_tip.cr.is_empty(),
            "fixture with real commits should produce a non-empty CR"
        );
        assert_eq!(recovered_tip.cr, original_tip.cr);

        let recovered_principals = engine.indexer().list_principals().await.unwrap();
        assert_eq!(recovered_principals.len(), 1);

        let recovered_entity = engine
            .indexer()
            .resolve_digest(&tagged_pr)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original_entity.blob_hash, recovered_entity.blob_hash);
    }
    .await;
}

type LogEngine = StorageEngine<FjallBlobStore, FjallIndexer, FjallStorage>;

/// Everything a principal's commit log determines: the tip's digests, its
/// commit count, and every registered algorithm's tree root.
#[derive(Debug, PartialEq, Eq)]
struct Projection {
    tip: cyphr_storage::index::TipState,
    global_size: u64,
    roots: Vec<(u64, Vec<u8>)>,
}

async fn project(engine: &LogEngine, h: &History) -> Projection {
    let tip = engine
        .get_tip(&h.principal_id)
        .await
        .expect("tip")
        .expect("a pushed principal has a tip");
    let principal = engine
        .load_principal(&h.principal_id, h.genesis.clone())
        .await
        .expect("load principal");
    let trees = principal.commit_trees();
    let roots = [1u64, 2, 3]
        .into_iter()
        .filter(|alg| trees.has_algorithm(*alg))
        .map(|alg| (alg, trees.root(alg).expect("root")))
        .collect();
    Projection {
        tip,
        global_size: trees.global_size(),
        roots,
    }
}

fn open_engine(dir: &std::path::Path) -> (LogEngine, fjall::Database) {
    let db = fjall::Database::builder(dir.join("db")).open().expect("db");
    let engine = StorageEngine::with_log_factory(
        FjallBlobStore::from_database(db.clone()).expect("blobs"),
        FjallIndexer::open(&dir.join("index")).expect("index"),
        EmlLogs::new(db.clone()).expect("logs"),
    );
    (engine, db)
}

async fn push_all(engine: &LogEngine, histories: &[History]) {
    for h in histories {
        for commit in &h.commits {
            engine
                .submit_commit(
                    &h.principal_id,
                    Some(h.genesis.clone()),
                    &commit.bundle().unwrap(),
                )
                .await
                .expect("submit_commit");
        }
    }
}

/// What a store written under the per-principal keyspace layout holds that
/// the fixed layout does not: three keyspaces per principal (and per
/// retired generation) named `<id with ':' as '$3a'>[$g<n>]_eml_<part>`,
/// holding bytes the migration never reads, and the log generation
/// recorded. The old code is not runnable here, so its layout is
/// imitated; the fixed keyspaces are emptied because the legacy data lived
/// only in the per-principal ones.
fn make_legacy(db: &fjall::Database, histories: &[History]) {
    for fixed in ["eml_leaves", "eml_nodes", "eml_metadata"] {
        db.keyspace(fixed, fjall::KeyspaceCreateOptions::default)
            .expect("fixed keyspace")
            .clear()
            .expect("clear");
    }
    let generations = db
        .keyspace("eml_generations", fjall::KeyspaceCreateOptions::default)
        .expect("generations");
    for h in histories {
        let id = h.principal_id.replace(':', "$3a");
        for generation in ["", "$g2"] {
            for part in ["leaves", "nodes", "metadata"] {
                db.keyspace(
                    &format!("{id}{generation}_eml_{part}"),
                    fjall::KeyspaceCreateOptions::default,
                )
                .expect("legacy keyspace")
                .insert(b"legacy-key", b"legacy-value")
                .expect("legacy row");
            }
        }
        generations
            .insert(h.principal_id.as_bytes(), 2u64.to_be_bytes())
            .expect("record generation");
    }
}

/// Histories of distinct principals: genesis keys are consecutive pool
/// entries from `base`.
async fn histories(base: usize, steps: Vec<Vec<Step>>) -> Vec<History> {
    let pool = load_pool();
    let mut out = Vec::new();
    for (i, steps) in steps.into_iter().enumerate() {
        if let Some(h) = history(&pool, build_intent(base + i, steps)).await {
            out.push(h);
        }
    }
    out
}

proptest! {
    // Each case replays whole histories into two databases.
    #![proptest_config(ProptestConfig::with_cases(12))]
    /// Backs I1 across the log layout change: a store written under the
    /// per-principal keyspace layout, opened by the fixed-keyspace code,
    /// answers exactly as a store built fresh by it (same tips, same tree
    /// roots, same leaf counts for every principal), and no legacy
    /// `*_eml_*` keyspace survives the open.
    #[test]
    fn migrated_legacy_store_equals_fresh_store(
        base in any::<usize>(),
        steps in prop::collection::vec(prop::collection::vec(step_strategy(), 1..6), 1..4),
    ) {
        block_on(async move {
            let histories = histories(base, steps).await;
            prop_assume!(!histories.is_empty());

            let fresh_dir = tempfile::tempdir().unwrap();
            let fresh = {
                let (engine, _db) = open_engine(fresh_dir.path());
                push_all(&engine, &histories).await;
                let mut out = Vec::new();
                for h in &histories {
                    out.push(project(&engine, h).await);
                }
                out
            };

            let legacy_dir = tempfile::tempdir().unwrap();
            {
                let (engine, db) = open_engine(legacy_dir.path());
                push_all(&engine, &histories).await;
                drop(engine);
                make_legacy(&db, &histories);
            }
            let (engine, db) = open_engine(legacy_dir.path());
            let legacy: Vec<String> = db
                .list_keyspace_names()
                .into_iter()
                .map(|n| n.to_string())
                .filter(|n| n.contains("_eml_"))
                .collect();
            prop_assert!(legacy.is_empty(), "legacy keyspaces survived: {:?}", legacy);
            for (h, want) in histories.iter().zip(&fresh) {
                prop_assert_eq!(&project(&engine, h).await, want);
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

proptest! {
    // Each case replays a whole random history; 24 histories find the same
    // divergences (256 cost ~55 s per test).
    #![proptest_config(ProptestConfig::with_cases(24))]
    /// Backs I1 (the index is a rebuildable cache): for random histories, an
    /// index rebuilt from the in-memory blob store equals the one built at ingest.
    #[test]
    fn test_memory_engine_rebuild_recovery((genesis_key_idx, steps) in test_case_strategy()) {
        block_on(async move {
        let pool = load_pool();
        let intent = build_intent(genesis_key_idx, steps);
        let blob_store = MemoryBlobStore::new();
        let indexer = MemoryIndexer::new();
        let engine = StorageEngine::new(blob_store, indexer);
        run_engine_recovery_test(&pool, intent, engine).await;
            Ok::<(), TestCaseError>(())
        })?;
    }

    /// Backs I1 on the durable fjall backends: the same property after real
    /// on-disk ingest.
    #[test]
    fn test_persistent_engine_rebuild_recovery((genesis_key_idx, steps) in test_case_strategy()) {
        block_on(async move {
        let pool = load_pool();
        let intent = build_intent(genesis_key_idx, steps);
        let temp_dir_blob = tempfile::tempdir().unwrap();
        let temp_dir_index = tempfile::tempdir().unwrap();
        let blob_store = FjallBlobStore::open(temp_dir_blob.path()).unwrap();
        let indexer = FjallIndexer::open(&temp_dir_index.path().join("index")).unwrap();
        let engine = StorageEngine::new(blob_store, indexer);
        run_engine_recovery_test(&pool, intent, engine).await;
            Ok::<(), TestCaseError>(())
        })?;
    }
}

/// Drive one proptest case's async body: `proptest!` bodies are
/// synchronous, so each case runs on its own current-thread runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}
