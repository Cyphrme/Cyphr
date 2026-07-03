//! c4 — proves `Principal`'s Commit Tree is genuinely disk-backed end to
//! end, through the `cyphr`/`cyphr-storage`/`cyphr-blob-fjall` layers
//! together, one level above what `cyphr-blob-fjall`'s own
//! `eml_log_survives_disk_reload_sharing_blob_database` test already
//! proves at the raw `eml::Storage` layer alone.
//!
//! # Why this test does not route commits through
//! `StorageEngine::submit_commit`/`load_principal` twice
//!
//! `StorageEngine::load_principal` reconstructs a principal by full replay
//! from genesis: for each historical commit it calls
//! `Principal::finalize_commit`, which unconditionally appends that
//! commit's TR to the live `CommitTrees`. That is correct and cheap for the
//! in-memory-only default (`eml::MemoryStorage`), where a freshly
//! constructed genesis principal's tree always starts empty. It is **not**
//! correct against a storage backend whose physical location already
//! carries prior state: `eml`'s `root_for`/`commit_root_from_trees` report
//! the tree's **current, final** root, not "the root as of N leaves" — so a
//! commit tree reconstructed up front from an already-fully-populated
//! durable location produces the *final* CR at every intermediate replay
//! step, not the *as-of-this-commit* CR each historical `pre` field was
//! signed against, and replay fails with a broken-chain `pre` mismatch on
//! the second historical commit onward (reproduced empirically while
//! building this test — `StorageEngine::load_principal` now detects this
//! specific case and returns a dedicated `EngineError::Storage` rather than
//! a confusing signature-shaped failure). Closing that gap needs either a
//! historical/checkpoint-root query on `eml::Storage` (a change to the
//! sibling `eml`/`storage-fjall` crates) or `StorageEngine` caching an
//! already-loaded live principal instead of replaying from genesis on
//! every call (a real design change, not mere storage wiring).
//!
//! What *is* safe today, and what this test proves: a `Principal<S>`
//! constructed once against a durable storage instance, with every commit
//! applied directly to that one live instance (never reloaded via replay
//! mid-lifetime — exactly how a long-lived server process would use it),
//! genuinely persists its Commit Tree to disk; and a *fresh* reconstruction
//! via [`cyphr::commit_root::CommitTrees::open`] plus
//! [`cyphr::Principal::from_checkpoint_with_trees`] (no replay involved)
//! recovers byte-identical PR/CR after a full drop and reopen of the same
//! physical `fjall::Database` — proving the durability the standalone
//! `cyphr-blob-fjall` test already proved is faithfully reachable through
//! `Principal`'s own API.
//!
//! The storage instance itself is still produced via
//! [`cyphr_storage::engine::StorageEngine`]'s `with_storage_factory` /
//! `cyphr_blob_fjall::open_eml_storage`, sharing one physical `Database`
//! with the blob store — this test exercises that exact production wiring,
//! just not `submit_commit`'s replay-based reload path.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::CommitTrees;
use cyphr::eml;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_storage::blob::BlobStore;

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

fn canonicalize(val: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = val {
        map.sort_keys();
        for (_, v) in map.iter_mut() {
            canonicalize(v);
        }
    } else if let serde_json::Value::Array(arr) = val {
        for v in arr {
            canonicalize(v);
        }
    }
}

/// Apply every coz in a golden fixture commit directly to a live
/// `Principal<S>` via one `CommitScope`, mirroring the transaction half of
/// `StorageEngine::submit_commit`'s own coz-parsing logic (this fixture's
/// commits carry no pre-actions, only transactions).
fn apply_golden_commit<S: eml::Storage>(
    principal: &mut cyphr::Principal<S>,
    commit: &serde_json::Value,
) {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;

    let mut scope = principal.begin_commit();
    for coz_value in cozies {
        let coz = coz_value.clone();
        let pay = coz["pay"].clone();
        let typ = pay["typ"].as_str().unwrap_or("").to_string();
        let is_key_introducing = typ.contains("/key/create") || typ.contains("/key/replace");

        let mut new_key = None;
        if is_key_introducing {
            if let Some(ks) = keys {
                if key_idx < ks.len() {
                    new_key = Some(golden_key_to_domain(&ks[key_idx]));
                    key_idx += 1;
                }
            }
        }

        let sig_b64 = coz["sig"].as_str().expect("sig");
        let sig = Base64UrlUnpadded::decode_vec(sig_b64).expect("sig base64");

        let mut pay_val = pay.clone();
        canonicalize(&mut pay_val);
        let pay_json = serde_json::to_vec(&pay_val).expect("pay serialize");

        let alg = pay["alg"].as_str().expect("alg");
        let cad = coz::canonical_hash_for_alg(&pay_json, alg, None).expect("cad");
        let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");

        scope
            .verify_and_apply(&pay_json, &sig, czd, new_key)
            .expect("verify_and_apply failed");
    }
    scope.finalize().expect("finalize failed");
}

#[test]
fn principal_commit_tree_survives_disk_drop_and_reload() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert!(
        commits.len() >= 2,
        "fixture must have at least 2 commits to exercise this test (c4)"
    );

    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");

    let (original_pr, original_cr, ar, keys_snapshot, pg, blob_hash) = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            let db = fjall::Database::builder(&db_path).open().expect("open db");

            // c5: the blob store and the EML commit-tree storage genuinely
            // share this one physical `Database` — not two uncoordinated
            // databases — via `FjallBlobStore::from_database` and
            // `open_eml_storage` on the same handle.
            let blob_store =
                cyphr_blob_fjall::FjallBlobStore::from_database(db.clone()).expect("blob store");
            let eml_storage = cyphr_blob_fjall::open_eml_storage(db.clone()).expect("eml storage");

            let blob_hash = blob_store
                .put(b"a blob living beside the durable commit tree")
                .await
                .expect("blob put");

            let mut principal =
                cyphr::Principal::explicit_with_storage(keys.clone(), eml_storage).unwrap();

            for commit in commits {
                apply_golden_commit(&mut principal, commit);
            }

            let pr = principal.pr().clone();
            let cr = principal.cr().cloned();
            let ar = principal.auth_root().clone();
            let keys_snapshot: Vec<cyphr::Key> = principal.active_keys().cloned().collect();
            let pg = principal.pg().cloned();
            (pr, cr, ar, keys_snapshot, pg, blob_hash)
            // `principal`, `blob_store`, and `db` all drop here, releasing
            // the on-disk database before it's reopened below.
        });

    assert!(
        original_cr.is_some(),
        "a fixture with real commits must produce a CR"
    );

    // Reopen from scratch at the same path — a fresh `Database`, not a
    // clone of the one above — to prove the state is genuinely durable.
    let (restored_pr, restored_cr, blob_survived) = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async {
            let db = fjall::Database::builder(&db_path).open().expect("reopen db");
            let blob_store =
                cyphr_blob_fjall::FjallBlobStore::from_database(db.clone()).expect("blob store");
            let eml_storage =
                cyphr_blob_fjall::open_eml_storage(db.clone()).expect("reopen eml storage");
            let trees: CommitTrees<FjallStorage> =
                CommitTrees::open(eml_storage).expect("reconstruct commit tree from disk");

            let restored =
                cyphr::Principal::from_checkpoint_with_trees(pg, ar, keys_snapshot, trees)
                    .unwrap();

            let blob_survived = blob_store.get(&blob_hash).await.expect("blob get").is_some();
            (restored.pr().clone(), restored.cr().cloned(), blob_survived)
        });

    assert_eq!(
        restored_pr, original_pr,
        "PR must survive a disk drop-and-reload byte-for-byte"
    );
    assert_eq!(
        restored_cr, original_cr,
        "CR must survive a disk drop-and-reload byte-for-byte"
    );
    assert!(
        blob_survived,
        "the blob written beside the commit tree must also survive the reload, proving the \
         blob and EML partitions truly share one database rather than each independently \
         persisting to its own file"
    );
}
