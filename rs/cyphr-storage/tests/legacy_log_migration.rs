//! A store written under the per-principal keyspace layout opens under the
//! fixed-keyspace layout: the legacy keyspaces are deleted, the log
//! regenerates from the blobs (the source of truth, I1), and every
//! principal's state is unchanged.
//!
//! The legacy layout is simulated rather than captured: the old code's
//! keyspaces are named `<id with ':' as '$3a'>_eml_{leaves,nodes,metadata}`
//! and the migration deletes by that name pattern alone, never reading
//! their contents, so a keyspace of that name holding arbitrary bytes
//! exercises the same code path a real one does. (A real store built by
//! the base commit was migrated by hand; see the node report.)

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::engine::{LogFactory, StorageEngine};
use fjall::KeyspaceCreateOptions;

fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();
    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();
    cyphr::Key::new(
        alg.to_string(),
        coz::Thumbprint::from_bytes(tmb_bytes),
        pub_bytes,
    )
    .expect("key binds its tmb")
}

/// A golden fixture's commit line as the wire bundle a client would push
/// (SPEC 4.6.2: `txs` by transaction, the keys they introduce in `keys`).
fn build_bundle(commit: &serde_json::Value) -> cyphr::replay::WireBundle {
    serde_json::from_value::<cyphr_storage::CommitEntry>(commit.clone())
        .expect("fixture commit line")
        .bundle()
        .expect("fixture bundle")
}

async fn submit_all_commits(
    engine: &StorageEngine<FjallBlobStore, FjallIndexer, FjallStorage>,
    principal_id: &str,
    genesis_key: &cyphr::Key,
    commits: &[serde_json::Value],
) {
    let genesis = Genesis::Implicit(genesis_key.clone());
    for commit in commits {
        let bundle = build_bundle(commit);
        engine
            .submit_commit(principal_id, Some(genesis.clone()), &bundle)
            .await
            .expect("submit_commit failed");
    }
}

/// The EML-derived state a reconstruction must reproduce exactly: every
/// registered algorithm's tree root, the log's total leaf count, and the
/// state digests that fold the tree root upward (SR excludes it; CR and PR
/// do not).
struct EmlSnapshot {
    pr: cyphr::state::PrincipalRoot,
    cr: Option<cyphr::CommitRoot>,
    sr: Option<cyphr::state::StateRoot>,
    global_size: u64,
    roots: Vec<(u64, Vec<u8>)>,
}

async fn snapshot(
    engine: &StorageEngine<FjallBlobStore, FjallIndexer, FjallStorage>,
    principal_id: &str,
    genesis: Genesis,
) -> EmlSnapshot {
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .unwrap_or_else(|e| panic!("load_principal({principal_id}) failed: {e}"));

    let trees = principal.commit_trees();
    let mut roots = Vec::new();
    // Every hash algorithm this crate's EML wiring knows about (see
    // `cyphr::commit_root::hash_alg_to_u64`) -- probe each rather than
    // assuming a fixture uses exactly one, so the assertion below covers
    // whatever algorithm set the genesis key actually activated.
    for alg_id in [1u64, 2, 3] {
        if trees.has_algorithm(alg_id) {
            let root = trees
                .root(alg_id)
                .unwrap_or_else(|e| panic!("root({alg_id}) for {principal_id} failed: {e}"));
            roots.push((alg_id, root));
        }
    }
    assert!(
        !roots.is_empty(),
        "principal {principal_id} must have at least one registered EML algorithm"
    );

    EmlSnapshot {
        pr: principal.pr().clone(),
        cr: principal.cr().cloned(),
        sr: principal.sr().cloned(),
        global_size: trees.global_size(),
        roots,
    }
}

/// Legacy keyspace names a principal's old log used, plus a retired
/// generation's.
fn legacy_names(principal_id: &str) -> Vec<String> {
    let id = principal_id.replace(':', "$3a");
    let mut names = Vec::new();
    for generation in ["", "$g2"] {
        for part in ["_eml_leaves", "_eml_nodes", "_eml_metadata"] {
            names.push(format!("{id}{generation}{part}"));
        }
    }
    names
}

/// Behaviour: opening the logs of a store holding legacy per-principal
/// keyspaces deletes them, resets the generation records, and the
/// principals then replay to the same state as before. Red at base: the
/// legacy keyspaces survive `EmlLogs::new`.
#[tokio::test]
async fn legacy_log_keyspaces_are_dropped_and_logs_regenerate() {
    let fixture_a = load_golden("mutations", "transaction_sequence_replay");
    let fixture_b = load_golden("edge_cases", "transaction_replay_order");
    let key_a = golden_key_to_domain(&fixture_a["genesis_keys"][0]);
    let key_b = golden_key_to_domain(&fixture_b["genesis_keys"][0]);
    let commits_a = fixture_a["commits"].as_array().unwrap().clone();
    let commits_b = fixture_b["commits"].as_array().unwrap().clone();
    let id_a = cyphr_storage::engine::genesis_principal_id(&Genesis::Implicit(key_a.clone()))
        .expect("id a");
    let id_b = cyphr_storage::engine::genesis_principal_id(&Genesis::Implicit(key_b.clone()))
        .expect("id b");

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    // Phase 1 -- populate, then make the log look as a legacy store's
    // does under the new code: the fixed keyspaces empty (the old data
    // lives only in per-principal keyspaces), the legacy keyspaces
    // present with a recorded generation.
    let (before_a, before_b) = {
        let db = fjall::Database::builder(&db_path).open().expect("open db");
        let engine = StorageEngine::with_log_factory(
            FjallBlobStore::from_database(db.clone()).expect("blob store"),
            FjallIndexer::open(&index_path).expect("open indexer"),
            cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
        );
        submit_all_commits(&engine, &id_a, &key_a, &commits_a).await;
        submit_all_commits(&engine, &id_b, &key_b, &commits_b).await;
        let before_a = snapshot(&engine, &id_a, Genesis::Implicit(key_a.clone())).await;
        let before_b = snapshot(&engine, &id_b, Genesis::Implicit(key_b.clone())).await;
        drop(engine);

        for fixed in ["eml_leaves", "eml_nodes", "eml_metadata"] {
            db.keyspace(fixed, KeyspaceCreateOptions::default)
                .expect("fixed keyspace")
                .clear()
                .expect("clear fixed keyspace");
        }
        let generations = db
            .keyspace("eml_generations", KeyspaceCreateOptions::default)
            .expect("generations");
        for id in [&id_a, &id_b] {
            for name in legacy_names(id) {
                db.keyspace(&name, KeyspaceCreateOptions::default)
                    .expect("legacy keyspace")
                    .insert(b"legacy-key", b"legacy-value")
                    .expect("legacy row");
            }
            generations
                .insert(id.as_bytes(), 2u64.to_be_bytes())
                .expect("record generation");
        }
        (before_a, before_b)
    };

    // Phase 2 -- reopen under the new code.
    let db = fjall::Database::builder(&db_path)
        .open()
        .expect("reopen db");
    let logs = cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs");
    let names: Vec<String> = db
        .list_keyspace_names()
        .into_iter()
        .map(|n| n.to_string())
        .collect();
    let legacy: Vec<&String> = names.iter().filter(|n| n.contains("_eml_")).collect();
    assert!(legacy.is_empty(), "legacy keyspaces survived: {legacy:?}");
    for id in [&id_a, &id_b] {
        assert_eq!(
            LogFactory::<FjallStorage>::generation(&logs, id).expect("generation"),
            0,
            "the generation record of {id} must be reset"
        );
    }

    let engine = StorageEngine::with_log_factory(
        FjallBlobStore::from_database(db.clone()).expect("blob store"),
        FjallIndexer::open(&index_path).expect("open indexer"),
        logs,
    );
    for (label, id, key, before) in [("a", &id_a, key_a, before_a), ("b", &id_b, key_b, before_b)] {
        let after = snapshot(&engine, id, Genesis::Implicit(key)).await;
        assert_eq!(after.global_size, before.global_size, "{label}: leaf count");
        assert_eq!(after.roots, before.roots, "{label}: tree roots");
        assert_eq!(after.pr, before.pr, "{label}: PR");
        assert_eq!(after.cr, before.cr, "{label}: CR");
        assert_eq!(after.sr, before.sr, "{label}: SR");
    }
}
