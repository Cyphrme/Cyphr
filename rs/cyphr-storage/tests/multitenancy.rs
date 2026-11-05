//! Proves two principals can safely share one physical fjall database
//! through the real production wiring shape — `StorageEngine`'s
//! `with_storage_factory` plus `cyphr-blob-fjall`'s scoped EML open.
//!
//! Mirrors `durable_commit_trees.rs`'s golden-fixture-driven pattern.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::engine::StorageEngine;

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
    cyphr::Key::new(alg.to_string(), coz::Thumbprint::from_bytes(tmb_bytes), pub_bytes).expect("key binds its tmb")
}

/// Build raw coz blobs from a golden fixture's commit, embedding key
/// material — the shape `StorageEngine::submit_commit` expects from a real
/// client.
fn build_raw_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    let mut blobs = Vec::new();

    for coz_value in cozies {
        let mut coz = coz_value.clone();
        let typ = coz["pay"]["typ"].as_str().unwrap_or("");
        let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(typ);

        if is_key_introducing {
            if let Some(ks) = keys {
                if key_idx < ks.len() {
                    coz.as_object_mut()
                        .unwrap()
                        .insert("key".to_string(), ks[key_idx].clone());
                    key_idx += 1;
                }
            }
        }

        blobs.push(serde_json::to_vec(&coz).unwrap());
    }

    blobs
}

async fn submit_all_commits(
    engine: &StorageEngine<FjallBlobStore, FjallIndexer, FjallStorage>,
    principal_id: &str,
    genesis_key: &cyphr::Key,
    commits: &[serde_json::Value],
) {
    let genesis = Genesis::Implicit(genesis_key.clone());
    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        engine
            .submit_commit(principal_id, Some(genesis.clone()), &blob_refs)
            .await
            .expect("submit_commit failed");
    }
}

/// c2 — Two principals, each with a genuinely distinct genesis identity,
/// submit real commits through one `StorageEngine` sharing ONE physical
/// fjall `Database` (via `with_storage_factory` + `open_eml_storage_scoped`
/// — the actual production wiring shape, not eml's own unit-level scoped
/// test). After a full drop-and-reload of that database, each principal's
/// PR/CR/commit count must reflect only its own history.
#[test]
fn two_principals_share_one_database_without_collision() {
    let fixture_a = load_golden("mutations", "transaction_sequence_replay");
    let fixture_b = load_golden("edge_cases", "transaction_replay_order");

    let genesis_key_a = golden_key_to_domain(&fixture_a["genesis_keys"][0]);
    let genesis_key_b = golden_key_to_domain(&fixture_b["genesis_keys"][0]);
    // The two fixtures must carry genuinely distinct genesis identities —
    // otherwise this test would not actually exercise multitenancy.
    assert_ne!(
        genesis_key_a.tmb(), genesis_key_b.tmb(),
        "fixtures must have distinct genesis keys to exercise multitenancy"
    );

    let commits_a = fixture_a["commits"].as_array().unwrap().clone();
    let commits_b = fixture_b["commits"].as_array().unwrap().clone();
    assert!(commits_a.len() >= 2, "fixture a needs multiple commits");
    assert!(commits_b.len() >= 2, "fixture b needs multiple commits");

    let principal_id_a = "tenant-a";
    let principal_id_b = "tenant-b";

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db = fjall::Database::builder(&db_path).open().expect("open db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let indexer = FjallIndexer::open(&index_path).expect("open indexer");
        let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
        });

        submit_all_commits(&engine, principal_id_a, &genesis_key_a, &commits_a).await;
        submit_all_commits(&engine, principal_id_b, &genesis_key_b, &commits_b).await;
    });

    // Fresh reload — a new Database/FjallIndexer/StorageEngine, not clones
    // of the ones above — to prove the isolation is genuinely durable.
    let (pr_a, cr_a, count_a, pr_b, cr_b, count_b) = rt.block_on(async {
        let db = fjall::Database::builder(&db_path)
            .open()
            .expect("reopen db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let indexer = FjallIndexer::open(&index_path).expect("reopen indexer");
        let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
        });

        let genesis_a = Genesis::Implicit(genesis_key_a.clone());
        let genesis_b = Genesis::Implicit(genesis_key_b.clone());

        let principal_a = engine
            .load_principal(principal_id_a, genesis_a)
            .await
            .expect("load_principal a failed");
        let principal_b = engine
            .load_principal(principal_id_b, genesis_b)
            .await
            .expect("load_principal b failed");

        (
            principal_a.pr().clone(),
            principal_a.cr().cloned(),
            principal_a.commit_trees().global_size(),
            principal_b.pr().clone(),
            principal_b.cr().cloned(),
            principal_b.commit_trees().global_size(),
        )
    });

    assert_ne!(pr_a, pr_b, "distinct principals must have distinct PRs");
    assert_ne!(cr_a, cr_b, "distinct principals must have distinct CRs");
    assert!(cr_a.is_some(), "principal a must have a CR");
    assert!(cr_b.is_some(), "principal b must have a CR");
    assert_eq!(
        count_a,
        commits_a.len() as u64,
        "principal a's durable log must carry exactly its own commits, not principal b's"
    );
    assert_eq!(
        count_b,
        commits_b.len() as u64,
        "principal b's durable log must carry exactly its own commits, not principal a's"
    );
}
