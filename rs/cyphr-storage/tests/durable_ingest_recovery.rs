//! Durable ingest: proves the crash-window closure and order
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
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::Indexer;

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

/// F25 — a `freeze/create` commit submitted through the real
/// `submit_commit` path must be recognized as a transaction (not
/// silently misfiled as a deferred action) and its effect must survive a
/// full reload of the principal from the durable blob/index store, not
/// just persist in the in-memory scope used during ingest.
#[tokio::test]
async fn freeze_create_commit_survives_reload() {
    let fixture = load_golden("lifecycle", "freeze_create_transitions_to_frozen");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    assert_eq!(keys.len(), 1, "fixture uses implicit single-key genesis");
    let genesis = Genesis::Implicit(keys[0].clone());
    let principal_id =
        cyphr_storage::engine::genesis_principal_id(&genesis).expect("genesis-derived id");
    let principal_id = principal_id.as_str();

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
    let engine = StorageEngine::with_log_factory(
        blob_store,
        indexer,
        cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
    );

    for commit in commits {
        let bundle = build_bundle(commit);
        engine
            .submit_commit(principal_id, Some(genesis.clone()), &bundle)
            .await
            .expect("submit_commit failed: freeze/create must be applied as a transaction");
    }

    // Reload the principal from durable storage (index + blob store), not
    // the in-memory scope used during ingest -- this proves the freeze
    // was actually persisted, not just applied transiently.
    let reloaded = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    assert_eq!(
        reloaded.lifecycle_state(),
        cyphr::lifecycle::LifecycleState::Frozen,
        "freeze/create must transition the reloaded principal to Frozen"
    );
}

/// c4 — deleting the index entirely and rebuilding it from the blob store
/// alone (via the durable manifests `ingest_commit` wrote) must recover
/// the exact same tip state and per-commit blob order as the original
/// index, with real disk-backed `FjallBlobStore`/`FjallIndexer` backends.
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
    let principal_id =
        cyphr_storage::engine::genesis_principal_id(&genesis).expect("genesis-derived id");
    let principal_id = principal_id.as_str();

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
    let engine = StorageEngine::with_log_factory(
        blob_store,
        indexer,
        cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
    );

    for commit in commits {
        let bundle = build_bundle(commit);
        engine
            .submit_commit(principal_id, Some(genesis.clone()), &bundle)
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
    // fresh fjall database directory at the same path -- proving recovery
    // does not depend on any residual index state.
    drop(engine);
    std::fs::remove_dir_all(&index_path).expect("remove index directory");

    let blob_store = FjallBlobStore::from_database(db.clone()).expect("reopen blob store");
    let fresh_indexer = FjallIndexer::open(&index_path).expect("open fresh indexer");
    let recovery_engine = StorageEngine::with_log_factory(
        blob_store,
        fresh_indexer,
        cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
    );

    // Confirm the index is genuinely gone before rebuilding. Probed via
    // the raw indexer accessor: `recovery_engine.get_tip()` itself would
    // now auto-heal from the manifests still present in the shared blob
    // store on its first call (S3-ingest-crash-recovery's heal-at-open
    // wiring) -- the raw accessor is the documented escape hatch outside
    // that guarantee, needed here to observe the genuinely fresh state.
    assert!(
        recovery_engine
            .indexer()
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
