//! c4 — proves `Principal`'s Commit Tree is genuinely disk-backed end to
//! end, through the `cyphr`/`cyphr-storage`/`cyphr-blob-fjall` layers
//! together.
//!
//! # Why this test does not route commits through
//! `StorageEngine::submit_commit`/`load_principal` twice
//!
//! `StorageEngine::load_principal` reconstructs a principal by full replay
//! from genesis: for each historical commit it calls
//! `PrincipalState::stage_commit`, which unconditionally appends that
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
//! via [`cyphr::commit_root::CommitTrees::open`] (no replay involved)
//! recovers a byte-identical CR after a full drop and reopen of the same
//! physical `fjall::Database` — proving the durability the standalone
//! `cyphr-blob-fjall` test already proved is faithfully reachable through
//! `Principal`'s own API.
//!
//! The storage instance itself is still produced via
//! [`cyphr_storage::engine::StorageEngine`]'s `with_log_factory` /
//! `cyphr_blob_fjall::EmlLogs`, sharing one physical `Database`
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
    cyphr::Key::new(
        alg.to_string(),
        coz::Thumbprint::from_bytes(tmb_bytes),
        pub_bytes,
    )
    .expect("key binds its tmb")
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
/// commits carry no pre-actions, only transactions). Returns `finalize()`'s
/// result rather than panicking on it, so callers can assert on error paths
/// (e.g. the orphan-leaf guard test below).
async fn apply_golden_commit<S: eml::Storage>(
    principal: &mut cyphr::Principal<S>,
    commit: &serde_json::Value,
) -> cyphr::error::Result<()> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;

    let mut scope = principal.begin_commit();
    // The fixture's transactions are one coz each, so applying coz by coz
    // forms the same transactions.
    for coz_value in cozies
        .iter()
        .flat_map(|tx| tx.as_array().expect("transaction"))
    {
        let coz = coz_value.clone();
        let pay = coz["pay"].clone();
        let typ = pay["typ"].as_str().unwrap_or("").to_string();
        let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(&typ);

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
    scope.finalize().await?;
    Ok(())
}

/// F31 / F-A regression (blocker from Fable's pre-merge review of PR #6):
/// replay's `already_durable` branch must not silently adopt an orphan
/// leaf's TR as a commit's CR. A principal now writes its log only in the
/// one write that commits it, so an orphan (a leaf with no commit behind
/// it) exists only in a log written before the two-phase commit; this test
/// plants one with a second writer of the same durable store, then replays
/// the chain over it: the commit that meets the orphan is refused with
/// `DurableLeafMismatch` rather than deriving CR from the orphan.
#[test]
fn finalize_commit_rejects_mismatched_orphan_leaf() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert!(
        commits.len() >= 3,
        "fixture must have at least 3 commits to exercise this test"
    );

    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = fjall::Database::builder(&db_path).open().expect("open db");
        let open = || cyphr_blob_fjall::open_eml_storage(db.clone()).expect("eml storage");

        // The first two commits, written live: real leaves at 0 and 1.
        {
            let mut principal = cyphr::Principal::open(keys[0].clone(), open())
                .await
                .unwrap();
            apply_golden_commit(&mut principal, &commits[0])
                .await
                .expect("commit 0 finalize failed");
            apply_golden_commit(&mut principal, &commits[1])
                .await
                .expect("commit 1 finalize failed");
            assert_eq!(principal.commit_trees().global_size(), 2);
        }

        // Plant the legacy orphan: a FOREIGN leaf (commit 0's payload, a
        // genuinely different commit's TR) at the position the 3rd commit
        // would occupy, written by another writer of the same store.
        {
            let mut log = CommitTrees::open(open()).await.expect("reopen log");
            let orphan_leaf = log.get_leaf(0).await.expect("read leaf 0");
            log.append(&orphan_leaf).await.expect("append orphan leaf");
            assert_eq!(log.global_size(), 3);
        }

        // Replay the chain over the store. Commits 0 and 1 find their own
        // leaves (the already-durable path); commit 2 finds the orphan at
        // index 2 and must hard-error rather than derive CR from it.
        let mut principal = cyphr::Principal::open(keys[0].clone(), open())
            .await
            .unwrap();
        apply_golden_commit(&mut principal, &commits[0])
            .await
            .expect("commit 0 replays");
        apply_golden_commit(&mut principal, &commits[1])
            .await
            .expect("commit 1 replays");
        assert_eq!(principal.commits().count(), 2);
        let result = apply_golden_commit(&mut principal, &commits[2]).await;
        match result {
            Err(cyphr::Error::DurableLeafMismatch(idx)) => assert_eq!(idx, 2),
            other => panic!(
                "expected Err(Error::DurableLeafMismatch(2)) for the orphan-leaf crash scenario, \
                 got {other:?}"
            ),
        }
    });
}

/// Backs the Commit Tree (SPEC be0663f section 12.1 EML) surviving a disk drop
/// and reload: the reopened log yields the same roots for a multi-commit
/// principal.
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

    let (original_cr, algs, blob_hash) = tokio::runtime::Runtime::new().unwrap().block_on(async {
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

        let mut principal = cyphr::Principal::open(keys[0].clone(), eml_storage)
            .await
            .unwrap();

        for commit in commits {
            apply_golden_commit(&mut principal, commit)
                .await
                .expect("finalize failed");
        }

        let cr = principal.cr().cloned();
        (cr, principal.active_algs(), blob_hash)
        // `principal`, `blob_store`, and `db` all drop here, releasing
        // the on-disk database before it's reopened below.
    });

    assert!(
        original_cr.is_some(),
        "a fixture with real commits must produce a CR"
    );

    // Reopen from scratch at the same path — a fresh `Database`, not a
    // clone of the one above — to prove the state is genuinely durable.
    let (restored_cr, blob_survived) = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let db = fjall::Database::builder(&db_path)
            .open()
            .expect("reopen db");
        let blob_store =
            cyphr_blob_fjall::FjallBlobStore::from_database(db.clone()).expect("blob store");
        let eml_storage =
            cyphr_blob_fjall::open_eml_storage(db.clone()).expect("reopen eml storage");
        let trees: CommitTrees<FjallStorage> = CommitTrees::open(eml_storage)
            .await
            .expect("reconstruct commit tree from disk");

        let restored_cr = cyphr::commit_root::commit_root_from_trees(&trees, &algs)
            .expect("commit root from reopened trees");

        let blob_survived = blob_store
            .get(&blob_hash)
            .await
            .expect("blob get")
            .is_some();
        (restored_cr, blob_survived)
    });

    assert_eq!(
        Some(restored_cr),
        original_cr,
        "CR must survive a disk drop-and-reload byte-for-byte"
    );
    assert!(
        blob_survived,
        "the blob written beside the commit tree must also survive the reload, proving the blob \
         and EML partitions truly share one database rather than each independently persisting to \
         its own file"
    );
}

/// A golden fixture's commit line as the wire bundle a client would push
/// (SPEC 4.6.2: `txs` by transaction, the keys they introduce in `keys`).
fn build_bundle(commit: &serde_json::Value) -> cyphr::replay::WireBundle {
    serde_json::from_value::<cyphr_storage::CommitEntry>(commit.clone())
        .expect("fixture commit line")
        .bundle()
        .expect("fixture bundle")
}

/// c2/c3 (P6c) — `StorageEngine::load_principal`'s NORMAL replay path (not
/// `CommitTrees::open` alone, which the test above
/// deliberately avoids) must correctly reconstruct a multi-commit principal
/// from a durable Commit Tree that already carries every leaf from a prior
/// session, without duplicating any of them.
///
/// Exercises the real production write path too: each `submit_commit` call
/// itself calls `load_principal` internally (see
/// `StorageEngine::submit_commit`'s step 2), so this test already replays
/// against progressively-more-populated durable storage on its 2nd and 3rd
/// commit, before the explicit drop-and-reload at the end replays all 3 at
/// once from a truly fresh process-equivalent engine instance.
#[test]
fn principal_replay_survives_disk_drop_and_reload() {
    use cyphr_blob_fjall::FjallBlobStore;
    use cyphr_index_fjall::FjallIndexer;
    use cyphr_storage::Genesis;
    use cyphr_storage::engine::StorageEngine;

    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert!(
        commits.len() >= 3,
        "fixture must have at least 3 commits to exercise this test (c2)"
    );

    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    let genesis = Genesis::Disclosed(keys);
    let principal_id =
        cyphr_storage::engine::genesis_principal_id(&genesis).expect("genesis-derived id");
    let principal_id = principal_id.as_str();

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    let (original_pr, original_cr, original_leaf_count) =
        tokio::runtime::Runtime::new().unwrap().block_on(async {
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

            let principal = engine
                .load_principal(principal_id, genesis.clone())
                .await
                .expect("load_principal failed");

            (
                principal.pr().clone(),
                principal.cr().cloned(),
                principal.commit_trees().global_size(),
            )
            // `engine`, `blob_store`, and `db` all drop here, releasing the
            // on-disk database before it's reopened below.
        });

    assert!(original_cr.is_some(), "3 real commits must produce a CR");
    assert_eq!(
        original_leaf_count,
        commits.len() as u64,
        "the durable log must carry exactly one leaf per commit, not duplicated"
    );

    // Reopen from scratch — a fresh `Database`/`FjallIndexer`/`StorageEngine`,
    // not clones of the ones above — to prove reconstruction genuinely
    // replays from durable storage rather than reusing live state.
    let (restored_pr, restored_cr, restored_leaf_count) =
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let db = fjall::Database::builder(&db_path)
                .open()
                .expect("reopen db");
            let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
            let indexer = FjallIndexer::open(&index_path).expect("reopen indexer");
            let engine = StorageEngine::with_log_factory(
                blob_store,
                indexer,
                cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
            );

            let principal = engine
                .load_principal(principal_id, genesis.clone())
                .await
                .expect("load_principal failed after disk drop-and-reload");

            (
                principal.pr().clone(),
                principal.cr().cloned(),
                principal.commit_trees().global_size(),
            )
        });

    assert_eq!(
        restored_pr, original_pr,
        "PR must survive a disk drop-and-reload byte-for-byte through replay"
    );
    assert_eq!(
        restored_cr, original_cr,
        "CR must survive a disk drop-and-reload byte-for-byte through replay"
    );
    assert_eq!(
        restored_leaf_count, original_leaf_count,
        "replay must not duplicate leaves — the durable log's size after reconstruction must \
         match the true commit count exactly"
    );
}
