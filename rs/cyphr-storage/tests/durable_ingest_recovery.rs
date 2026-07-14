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
use cyphr::StateDigest;
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
    let principal_id = "freeze-create-roundtrip-test";

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
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
    let principal_id = "durable-ingest-recovery-test";

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
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
    // fresh fjall database directory at the same path -- proving recovery
    // does not depend on any residual index state.
    drop(engine);
    std::fs::remove_dir_all(&index_path).expect("remove index directory");

    let blob_store = FjallBlobStore::from_database(db.clone()).expect("reopen blob store");
    let fresh_indexer = FjallIndexer::open(&index_path).expect("open fresh indexer");
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

/// F27 -- a same-timestamp action and transaction are NOT provably
/// order-independent, and the two possible tie-breaks are not
/// interchangeable. Sorting the transaction first (current behavior) is
/// the deliberately-chosen, safer order: an action sorted *before* a
/// same-timestamp transaction becomes a "pre-action" applied directly to
/// `principal` (see `reindex` step 1.1), mutating the very state a
/// same-timestamp commit's already-signed `arrow` was computed against
/// -- which would make every candidate finalizer fail to verify and
/// hard-fail `reindex` entirely for that principal (this runs on every
/// server startup, so that failure mode takes the whole server down, not
/// just one principal). Sorting the transaction first avoids that: the
/// action instead falls into the "deferred" bucket, applied only after
/// the commit finalizes. The narrower, strictly-safer trade-off this
/// still leaves: if that same-timestamp transaction also deactivates the
/// action's signer (`key/replace`/`key/revoke`), the deferred action
/// fails its own key-liveness check and is silently dropped -- one
/// action lost in a rare same-timestamp coincidence during best-effort
/// raw recovery, not a server that fails to boot.
#[tokio::test]
async fn reindex_same_timestamp_action_does_not_corrupt_concurrent_key_replace() {
    // "golden" replaces itself with "key_a" at now=1700000000. Reused
    // verbatim from the golden fixture -- its signatures are already
    // valid for these exact payloads.
    let fixture = load_golden("mutations", "key_replace_single_key");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis_key = &genesis_keys[0];
    let commit = &fixture["commits"][0];
    let tx_blobs = build_raw_blobs(commit);
    assert_eq!(tx_blobs.len(), 2, "expected key/replace + commit/create");

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    // Two independent handles onto the same underlying database: one for
    // the engine, one for writing raw (unmanifested) blobs directly below.
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let raw_blob_store = FjallBlobStore::from_database(db.clone()).expect("raw blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
    let engine = StorageEngine::with_storage_factory(blob_store, indexer, {
        let db = db.clone();
        move |_principal_id: &str| {
            cyphr_blob_fjall::open_eml_storage(db.clone()).map_err(|e| e.to_string())
        }
    });

    // Compute "golden"'s derived principal_id (implicit single-key genesis).
    let golden_key = golden_key_to_domain(genesis_key);
    let temp_principal = cyphr::Principal::implicit(golden_key.clone()).unwrap();
    let pr_bytes = temp_principal
        .pr()
        .as_multihash()
        .get(cyphr::state::HashAlg::Sha256)
        .unwrap();
    let principal_id = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(pr_bytes));

    // Mock genesis coz (raw, unmanifested) so reindex can bootstrap "golden".
    let genesis_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/key/create",
            "now": 1_600_000_000i64,
            "pre": "",
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig",
        "key": genesis_key,
    });
    raw_blob_store
        .put(&serde_json::to_vec(&genesis_coz_json).unwrap())
        .await
        .unwrap();

    // Raw key/replace + commit/create blobs, same `now` as the action below.
    for blob in &tx_blobs {
        raw_blob_store.put(blob).await.unwrap();
    }

    // A data action signed by "golden" -- the OLD key being replaced --
    // sharing the EXACT SAME `now` (1700000000) as the key/replace above.
    let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    let pool = test_fixtures::pool::Pool::load(&pool_path).expect("load key pool");
    let golden_pool_key = pool.get("golden").expect("golden key in pool");
    let action_typ = "cyphr.me/comment/create";
    let action_now: i64 = 1_700_000_000;
    let action_pay = serde_json::json!({
        "alg": golden_pool_key.alg,
        "now": action_now,
        "tmb": genesis_key["tmb"].as_str().unwrap(),
        "typ": action_typ,
        "msg": "concurrent with key/replace",
    });
    let action_pay_bytes = serde_json::to_vec(&action_pay).unwrap();
    let prv_bytes =
        Base64UrlUnpadded::decode_vec(golden_pool_key.prv.as_ref().expect("golden has prv"))
            .unwrap();
    let pub_bytes = Base64UrlUnpadded::decode_vec(&golden_pool_key.pub_key).unwrap();
    let (sig_bytes, _cad) = coz::sign_json(
        &action_pay_bytes,
        &golden_pool_key.alg,
        &prv_bytes,
        &pub_bytes,
    )
    .expect("sign action");
    let action_coz_json = serde_json::json!({
        "pay": action_pay,
        "sig": Base64UrlUnpadded::encode_string(&sig_bytes),
    });
    raw_blob_store
        .put(&serde_json::to_vec(&action_coz_json).unwrap())
        .await
        .unwrap();

    // The regression this guards: reindex must not hard-fail just because
    // a raw action and a raw transaction happen to share a timestamp. If
    // the tie-break ever regresses to sorting actions first, the action
    // becomes a pre-action that corrupts this same-timestamp commit's
    // `fwd` before its finalizer's already-signed `arrow` is checked, and
    // this call returns `Err(MalformedBlob(..))` instead.
    engine
        .reindex(&[], true)
        .await
        .expect("reindex must not hard-fail on a same-timestamp action/transaction tie");

    // The transaction (key/replace) must still have taken effect: only
    // "key_a" is active afterward, matching the fixture's own expectation.
    let recovered_tip = engine
        .get_tip(&principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(
        recovered_tip.ar,
        fixture["expected"]["ar"].as_str().unwrap(),
        "key/replace must take effect regardless of the concurrent action"
    );

    // Documented, intentional trade-off: the action, signed by the
    // now-replaced key and deferred until after the commit finalizes,
    // fails its key-liveness check and is dropped -- the safer of the
    // two possible outcomes (see the tie-break's doc comment in
    // `reindex`). If this ever starts passing, the tie-break changed and
    // the `ar` assertion above should be re-checked for the hard-fail
    // this test exists to catch.
    let patch = engine
        .get_patch(&principal_id, None, None)
        .await
        .expect("get_patch failed");
    let recorded_action = patch.entries.iter().any(|e| {
        e.blobs.iter().any(|b| {
            serde_json::from_slice::<serde_json::Value>(b)
                .ok()
                .and_then(|v| v["pay"]["typ"].as_str().map(|t| t == action_typ))
                .unwrap_or(false)
        })
    });
    assert!(
        !recorded_action,
        "action signed by the replaced key, sharing the key/replace \
         transaction's exact timestamp, is expected to be dropped under \
         the current, deliberately-chosen tie-break -- see this test's \
         doc comment for why the alternative is worse"
    );
}
