//! Proves two principals can safely share one physical fjall database
//! through the real production wiring shape — `StorageEngine`'s
//! `with_storage_factory` plus `cyphr-blob-fjall`'s scoped EML open — and
//! that a principal `reindex` bootstraps from a bare genesis key resolves
//! to the exact same durable storage scope a later `load_principal`/
//! `submit_commit` call computes for it.
//!
//! Mirrors `durable_commit_trees.rs`'s golden-fixture-driven pattern.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::blob::BlobStore;
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
        genesis_key_a.tmb, genesis_key_b.tmb,
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

/// c3 — A principal bootstrapped through `reindex`'s bare-genesis-key path
/// (simulating a durable-storage recovery scenario: its first commit exists
/// in the blob store but was never indexed) must resolve to the exact same
/// durable storage scope a subsequent `submit_commit`/`load_principal` call
/// computes for it — no orphaned keyspace, correct CR continuity.
#[test]
fn reindex_bootstrapped_principal_resolves_same_scope_as_load_principal() {
    let fixture = load_golden("edge_cases", "transaction_replay_order");
    let genesis_key = golden_key_to_domain(&fixture["genesis_keys"][0]);
    let commits = fixture["commits"].as_array().unwrap().clone();
    assert!(commits.len() >= 2, "fixture needs at least 2 commits");

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let rt = tokio::runtime::Runtime::new().unwrap();

    let principal_id = rt.block_on(async {
        let db = fjall::Database::builder(&db_path).open().expect("open db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");

        // Seed the blob store directly with the first commit's raw blobs,
        // bypassing submit_commit/the indexer entirely — simulating a
        // principal whose blobs survived a crash/restore but was never
        // indexed, exactly the scenario `reindex` exists to recover.
        let first_commit_blobs = build_raw_blobs(&commits[0]);
        for blob in &first_commit_blobs {
            blob_store.put(blob).await.expect("seed blob");
        }

        let indexer = FjallIndexer::open(&index_path).expect("open indexer");
        let db_for_inspection = db.clone();
        let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
        });

        // Bootstrap from the bare genesis key, exactly as cyphr-cli's
        // parse_store does on startup with keys loaded from a keystore.
        engine
            .reindex(std::slice::from_ref(&genesis_key), false)
            .await
            .expect("reindex failed");

        // Discover the principal_id reindex assigned, by listing what the
        // indexer now knows about.
        use cyphr_storage::index::Indexer;
        let principals = engine.indexer().list_principals().await.expect("list");
        assert_eq!(
            principals.len(),
            1,
            "reindex must have bootstrapped exactly one principal"
        );
        let principal_id = principals[0].principal_id.clone();
        assert_eq!(
            principals[0].commit_count, 1,
            "reindex must have indexed exactly the one seeded commit"
        );

        // Directly inspect the physical scoped keyspace reindex wrote to —
        // proving it actually persisted the bootstrapped commit's leaf
        // durably, not just indexed metadata. Reuses the same live `db`
        // handle (fjall databases are single-process-exclusive) rather
        // than opening a second one at the same path.
        let scoped = cyphr_blob_fjall::open_eml_storage_scoped(db_for_inspection, &principal_id)
            .expect("scoped open");
        let trees: cyphr::commit_root::CommitTrees<FjallStorage> =
            cyphr::commit_root::CommitTrees::open(scoped).expect("open commit trees");
        assert_eq!(
            trees.global_size(),
            1,
            "reindex's bootstrapped commit must be durably present in the principal_id-scoped \
             keyspace"
        );

        principal_id
    });

    // Submit the fixture's second commit on top of the reindex-bootstrapped
    // principal, through the normal validated write path.
    rt.block_on(async {
        let db = fjall::Database::builder(&db_path)
            .open()
            .expect("reopen db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let indexer = FjallIndexer::open(&index_path).expect("reopen indexer");
        let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
        });

        let genesis = Genesis::Implicit(genesis_key.clone());
        let blobs = build_raw_blobs(&commits[1]);
        let blob_refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        engine
            .submit_commit(&principal_id, Some(genesis.clone()), &blob_refs)
            .await
            .expect(
                "submit_commit onto a reindex-bootstrapped principal must succeed — a scope \
                 mismatch would break the commit chain",
            );

        let principal = engine
            .load_principal(&principal_id, genesis)
            .await
            .expect("load_principal failed");
        assert_eq!(
            principal.commit_trees().global_size(),
            2,
            "both the reindex-bootstrapped commit and the newly-submitted commit must land in the \
             same durable log, with no duplication"
        );
        assert!(principal.cr().is_some());
    });

    // Directly re-inspect the same scoped keyspace one more time, fresh
    // from disk, to prove submit_commit's leaf landed in the SAME physical
    // keyspace reindex used — not a second, orphaned one.
    rt.block_on(async {
        let db = fjall::Database::builder(&db_path)
            .open()
            .expect("reopen db");
        let scoped =
            cyphr_blob_fjall::open_eml_storage_scoped(db, &principal_id).expect("scoped open");
        let trees: cyphr::commit_root::CommitTrees<FjallStorage> =
            cyphr::commit_root::CommitTrees::open(scoped).expect("open commit trees");
        assert_eq!(
            trees.global_size(),
            2,
            "the principal_id-scoped keyspace must carry both commits — proving reindex and \
             submit_commit resolved to the same scope"
        );
    });
}
