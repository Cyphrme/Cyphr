//! N04 — durable ingest: proves the crash-window closure and order
//! retention added to `StorageEngine::ingest_commit` (see
//! `cyphr-storage/src/engine/mod.rs`'s `CommitManifest`) against real,
//! disk-backed backends.
//!
//! c4 (root `AGENTS.md` invariant I1: the blob store is the sole source
//! of truth): if the index is deleted entirely and rebuilt from the blob
//! store alone via `StorageEngine::rebuild_index_from_manifests`, the
//! commit chain -- including each commit's exact intra-commit blob order
//! -- must come back byte-identical, using only the durable manifests
//! `ingest_commit` wrote, never a permutation search over the raw cozies.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_sqlite::SqliteIndexer;
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
    cyphr::Key {
        alg: alg.to_string(),
        tmb: coz::Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Build raw coz blobs from a golden fixture's commit, the same shape
/// `StorageEngine::submit_commit` expects from a real client.
fn build_raw_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    let mut blobs = Vec::new();

    for coz_value in cozies {
        let mut coz = coz_value.clone();
        let typ = coz["pay"]["typ"].as_str().unwrap_or("");
        let is_key_introducing = typ.contains("/key/create") || typ.contains("/key/replace");

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

/// c4 — deleting the index entirely and rebuilding it from the blob store
/// alone (via the durable manifests `ingest_commit` wrote) must recover
/// the exact same tip state and per-commit blob order as the original
/// index, with real disk-backed `FjallBlobStore`/`SqliteIndexer` backends.
#[tokio::test]
async fn rebuild_index_from_manifests_survives_index_deletion() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert!(
        commits.len() >= 3,
        "fixture must have at least 3 commits to meaningfully exercise recovery"
    );

    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    let genesis = Genesis::Explicit(keys);
    let principal_id = "durable-ingest-recovery-test";

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index.db");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = SqliteIndexer::open(&index_path).expect("open indexer");
    let engine = StorageEngine::with_storage_factory(blob_store, indexer, {
        let db = db.clone();
        move |_principal_id: &str| {
            cyphr_blob_fjall::open_eml_storage(db.clone()).map_err(|e| e.to_string())
        }
    });

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        engine
            .submit_commit(principal_id, Some(genesis.clone()), &blob_refs)
            .await
            .expect("submit_commit failed");
    }

    let original_tip = engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    let original_chain = engine
        .get_patch(principal_id, None, None)
        .await
        .expect("get_patch failed")
        .entries;
    assert_eq!(original_chain.len(), commits.len());

    // Delete the index entirely -- not just clear it in place, a genuine
    // fresh SQLite file at the same path -- proving recovery does not
    // depend on any residual index state.
    drop(engine);
    std::fs::remove_file(&index_path).expect("remove index file");

    let blob_store = FjallBlobStore::from_database(db.clone()).expect("reopen blob store");
    let fresh_indexer = SqliteIndexer::open(&index_path).expect("open fresh indexer");
    let recovery_engine = StorageEngine::with_storage_factory(blob_store, fresh_indexer, {
        let db = db.clone();
        move |_principal_id: &str| {
            cyphr_blob_fjall::open_eml_storage(db.clone()).map_err(|e| e.to_string())
        }
    });

    // Confirm the index is genuinely gone before rebuilding.
    assert!(
        recovery_engine
            .get_tip(principal_id)
            .await
            .unwrap()
            .is_none(),
        "fresh index must start empty"
    );

    let recovered_count = recovery_engine
        .rebuild_index_from_manifests()
        .await
        .expect("rebuild_index_from_manifests failed");
    assert_eq!(
        recovered_count,
        commits.len(),
        "one manifest per submitted commit"
    );

    let recovered_tip = recovery_engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist after rebuild");
    assert_eq!(recovered_tip.pr, original_tip.pr);
    assert_eq!(recovered_tip.sr, original_tip.sr);
    assert_eq!(recovered_tip.ar, original_tip.ar);
    assert_eq!(recovered_tip.commit_count, original_tip.commit_count);

    let recovered_chain = recovery_engine
        .get_patch(principal_id, None, None)
        .await
        .expect("get_patch failed")
        .entries;
    assert_eq!(
        recovered_chain.len(),
        original_chain.len(),
        "every commit must come back"
    );
    for (original, recovered) in original_chain.iter().zip(recovered_chain.iter()) {
        assert_eq!(
            recovered.commit.blob_hashes, original.commit.blob_hashes,
            "each commit's intra-commit blob order must survive the rebuild byte-for-byte, \
             recovered directly from its manifest rather than reconstructed via search"
        );
    }
}
