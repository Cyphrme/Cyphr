//! EML-keyspace-deletion recovery baseline.
//!
//! FRAMING (root `AGENTS.md` invariant I1, corrected): the EML commit tree
//! is not a disposable cache. Its root is signed into every commit's Arrow
//! (`docs/specs/SPEC.md:114`, `:333-339`, `:587-588`), so the tree is
//! RECORD, not a cache -- destroying it and being unable to recover would
//! be data loss, not the eviction of a rebuildable index. This test proves
//! a disaster-recovery property of that record: after a principal's own
//! EML keyspaces are destroyed on disk, `StorageEngine::load_principal`'s
//! ordinary replay path reconstructs the exact same tree -- every
//! registered algorithm's root and the log's total leaf count -- byte-for-
//! byte, purely from the commit content already durable in the blob store.
//! It is evidence the record can reconstruct its own attested structure,
//! never evidence the structure is disposable.
//!
//! Mirrors `durable_ingest_recovery.rs`'s
//! `rebuild_index_from_manifests_survives_index_deletion`, which proves the
//! analogous property for the index. The EML log had no such test before
//! this one. Deleting a principal's EML keyspaces is never a documented
//! operation -- this is the crash/corruption case the reconstruction
//! property exists to survive, not a client-facing feature.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_blob_fjall::storage_fjall::FjallStorage;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::engine::StorageEngine;
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

/// Destroy every keyspace backing `principal_id`'s EML log -- real,
/// observable deletion via fjall's own `delete_keyspace`, not a fresh store
/// that never had the data in the first place. Mirrors the fixed keyspace
/// suffixes `storage_fjall::FjallStorage::with_database_scoped` opens.
fn delete_principal_eml_keyspaces(db: &fjall::Database, principal_id: &str) {
    for suffix in ["_eml_leaves", "_eml_nodes", "_eml_metadata"] {
        let name = format!("{principal_id}{suffix}");
        let handle = db
            .keyspace(&name, KeyspaceCreateOptions::default)
            .unwrap_or_else(|e| panic!("open keyspace {name} for deletion failed: {e}"));
        db.delete_keyspace(handle)
            .unwrap_or_else(|e| panic!("delete_keyspace {name} failed: {e}"));
    }
}

/// The record-reconstruction property this node exists to check: destroy a
/// principal's durable EML keyspaces (leaving the blob store and the
/// separately-pathed index untouched), reopen, and confirm replay through
/// the ordinary `load_principal` path reconstructs the exact same tree --
/// for two principals sharing one physical database, so the recovery is
/// shown to be genuinely per-principal, not an artifact of there being only
/// one keyspace triplet in play.
#[tokio::test]
async fn replay_reconstructs_eml_after_keyspace_deletion() {
    let fixture_a = load_golden("mutations", "transaction_sequence_replay");
    let fixture_b = load_golden("edge_cases", "transaction_replay_order");

    let genesis_key_a = golden_key_to_domain(&fixture_a["genesis_keys"][0]);
    let genesis_key_b = golden_key_to_domain(&fixture_b["genesis_keys"][0]);
    assert_ne!(
        genesis_key_a.tmb, genesis_key_b.tmb,
        "fixtures must have distinct genesis keys to exercise per-principal recovery"
    );

    let commits_a = fixture_a["commits"].as_array().unwrap().clone();
    let commits_b = fixture_b["commits"].as_array().unwrap().clone();
    assert!(
        commits_a.len() >= 3,
        "fixture a must have at least 3 commits to meaningfully exercise recovery"
    );
    assert!(commits_b.len() >= 2, "fixture b needs multiple commits");

    let principal_id_a = "eml-recovery-tenant-a";
    let principal_id_b = "eml-recovery-tenant-b";

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");

    // Phase 1 -- populate through the engine and capture the pre-deletion
    // baseline, then let every handle (db, engine, blob store, indexer)
    // drop at the end of this block, exactly like `multitenancy.rs`'s
    // two-block pattern: a genuine reopen of the same physical database
    // below requires no live handle onto it still outstanding.
    let (before_a, before_b) = {
        let db = fjall::Database::builder(&db_path).open().expect("open db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let indexer = FjallIndexer::open(&index_path).expect("open indexer");
        let engine = StorageEngine::with_storage_factory(blob_store, indexer, {
            let db = db.clone();
            move |pid: &str| {
                cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
            }
        });

        submit_all_commits(&engine, principal_id_a, &genesis_key_a, &commits_a).await;
        submit_all_commits(&engine, principal_id_b, &genesis_key_b, &commits_b).await;

        let before_a = snapshot(
            &engine,
            principal_id_a,
            Genesis::Implicit(genesis_key_a.clone()),
        )
        .await;
        let before_b = snapshot(
            &engine,
            principal_id_b,
            Genesis::Implicit(genesis_key_b.clone()),
        )
        .await;

        // c-real-deletion's other half: the pre-deletion state must
        // genuinely differ from empty, or the deletion below would be
        // proving nothing.
        assert!(
            before_a.global_size > 0,
            "principal a must have durable EML leaves before deletion"
        );
        assert!(
            before_b.global_size > 0,
            "principal b must have durable EML leaves before deletion"
        );
        assert_eq!(before_a.global_size, commits_a.len() as u64);
        assert_eq!(before_b.global_size, commits_b.len() as u64);

        (before_a, before_b)
    };

    // Phase 2 -- reopen the same physical database, destroy each
    // principal's EML keyspaces, confirm the destruction is real, then
    // recover through the ordinary replay path.
    let db = fjall::Database::builder(&db_path)
        .open()
        .expect("reopen db");

    for pid in [principal_id_a, principal_id_b] {
        delete_principal_eml_keyspaces(&db, pid);

        // Observable deletion: reopening scoped storage over the now-empty
        // keyspaces must report zero leaves, not silently inherit anything
        // left behind.
        let scoped = cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid)
            .unwrap_or_else(|e| panic!("reopen scoped storage for {pid} failed: {e}"));
        let trees: cyphr::commit_root::CommitTrees<FjallStorage> =
            cyphr::commit_root::CommitTrees::open(scoped)
                .unwrap_or_else(|e| panic!("open commit trees for {pid} failed: {e}"));
        assert_eq!(
            trees.global_size(),
            0,
            "EML keyspace for {pid} must be genuinely empty after deletion"
        );
    }

    let blob_store = FjallBlobStore::from_database(db.clone()).expect("reopen blob store");
    let indexer = FjallIndexer::open(&index_path).expect("reopen indexer");
    let recovery_engine = StorageEngine::with_storage_factory(blob_store, indexer, {
        let db = db.clone();
        move |pid: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
        }
    });

    let after_a = snapshot(
        &recovery_engine,
        principal_id_a,
        Genesis::Implicit(genesis_key_a),
    )
    .await;
    let after_b = snapshot(
        &recovery_engine,
        principal_id_b,
        Genesis::Implicit(genesis_key_b),
    )
    .await;

    for (label, before, after) in [("a", before_a, after_a), ("b", before_b, after_b)] {
        assert_eq!(
            after.global_size, before.global_size,
            "{label}: leaf count must be reconstructed exactly"
        );
        assert_eq!(
            after.roots, before.roots,
            "{label}: every registered algorithm's EML root must be reconstructed byte-for-byte"
        );
        assert_eq!(after.sr, before.sr, "{label}: SR must match");
        assert_eq!(
            after.cr, before.cr,
            "{label}: CR (which folds the EML root) must match"
        );
        assert_eq!(
            after.pr, before.pr,
            "{label}: PR (which folds CR, which folds the EML root) must match"
        );
    }
}
