//! Ingest crash-window closure at engine open (GitHub issue #31, ruling
//! D2: heal at open, no cross-domain atomic batching).
//!
//! `StorageEngine::store_blobs_and_manifest` durably writes a
//! `CommitManifest` blob before `ingest_commit`'s subsequent
//! `indexer.index_commit` call. A process crash between those two writes
//! leaves a manifest durably stored with no index entry -- recoverable by
//! `StorageEngine::rebuild_index_from_manifests` (see
//! `rs/cyphr-storage/src/engine/mod.rs:429-489`), but only if something
//! actually calls it. This file proves that call now happens
//! automatically the next time the engine is opened, per
//! docs/specs/storage-engine.md's [recovery-reindex] clause -- no caller
//! needs to remember an explicit recovery call.
//!
//! Crash simulation: a manifest-shaped blob is written directly to the
//! blob store via the public `BlobStore::put`, bypassing the index write
//! entirely -- exactly what a crash between the manifest write and the
//! index write leaves behind. The JSON shape (`{"kind": ..., "commit":
//! ...}`) mirrors `engine::mod.rs`'s private `CommitManifest` struct and
//! `COMMIT_MANIFEST_KIND` constant, neither reachable from this external
//! test crate.

use cyphr_storage::blob::{Blake3Hash, BlobStore, MemoryBlobStore};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{IndexableCommit, IndexableCoz, MemoryIndexer};

/// Mirrors the private `COMMIT_MANIFEST_KIND` constant at
/// `rs/cyphr-storage/src/engine/mod.rs:116`.
const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// Mirrors the private `CommitManifest` struct at
/// `rs/cyphr-storage/src/engine/mod.rs:129` -- only the JSON shape needs
/// to match, so this crate doesn't need access to the real type.
#[derive(serde::Serialize)]
struct RawManifest<'a> {
    kind: &'a str,
    commit: &'a IndexableCommit,
}

/// Build a durable-shaped commit for a given principal/sequence/timestamp,
/// mirroring `engine::tests::make_meta`'s fixture shape.
fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let dummy_hash = Blake3Hash::from_bytes([0; 32]);
    IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec![format!("SHA-256:commit-{principal_id}-{seq}")],
        sequence: seq,
        pre: if seq == 0 {
            None
        } else {
            Some(format!("SHA-256:pr-{principal_id}-{}", seq - 1))
        },
        prs: vec![format!("SHA-256:pr-{principal_id}-{seq}")],
        srs: vec![format!("SHA-256:sr-{principal_id}-{seq}")],
        ars: vec![format!("SHA-256:ar-{principal_id}-{seq}")],
        crs: vec![format!("SHA-256:cr-{principal_id}-{seq}")],
        blob_hashes: vec![dummy_hash],
        cozies: vec![IndexableCoz {
            blob_hash: dummy_hash,
            czd: format!("SHA-256:czd-{principal_id}-{seq}"),
            typ: "key/create".to_string(),
            tmb: "thumbprint".to_string(),
            alg: "ED25519".to_string(),
            now: timestamp,
            payload: None,
        }],
        timestamp,
        keys: Vec::new(),
    }
}

/// Write a manifest blob directly, with no accompanying index write --
/// the crash-window state: durably stored, unindexed.
async fn write_orphan_manifest(blob_store: &MemoryBlobStore, commit: &IndexableCommit) {
    let manifest = RawManifest {
        kind: COMMIT_MANIFEST_KIND,
        commit,
    };
    let bytes = serde_json::to_vec(&manifest).expect("manifest serialize");
    blob_store.put(&bytes).await.expect("manifest put");
}

/// ac-crash-heals-at-open / c-red-first-crash: a manifest left with no
/// index entry (simulated crash) must serve a fully-healed index after a
/// plain engine open -- construct, then first use -- with no explicit
/// `rebuild_index_from_manifests()` call anywhere in this test.
#[tokio::test]
async fn crash_heals_at_plain_engine_open() {
    let principal_id = "alice";
    let commit = make_commit(principal_id, 0, 1000);

    let blob_store = MemoryBlobStore::new();
    write_orphan_manifest(&blob_store, &commit).await;

    // "A plain engine open": construct, then the engine's first public
    // call. No recovery call is made anywhere in this test.
    let engine = StorageEngine::new(blob_store, MemoryIndexer::new());

    let tip = engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect(
            "index must be healed automatically at open -- the orphan \
             manifest's commit must be visible with no explicit recovery call",
        );
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.pr, commit.prs[0]);
}

/// ac-heal-idempotent / c-idempotent-heal: independent opens of the same
/// crashed store must converge to the identical healed result, and
/// repeated reads against an already-healed instance must not
/// double-index or otherwise mutate the tip.
#[tokio::test]
async fn heal_is_idempotent_across_repeated_opens() {
    let principal_id = "bob";
    let commit = make_commit(principal_id, 0, 2000);

    let blob_store = MemoryBlobStore::new();
    write_orphan_manifest(&blob_store, &commit).await;

    // Two independent "opens" of the same crashed store -- each its own
    // engine instance with its own fresh indexer, as a real process
    // restart would produce.
    let first_open = StorageEngine::new(blob_store.clone(), MemoryIndexer::new());
    let first_tip = first_open
        .get_tip(principal_id)
        .await
        .unwrap()
        .expect("first open must heal");

    let second_open = StorageEngine::new(blob_store.clone(), MemoryIndexer::new());
    let second_tip = second_open
        .get_tip(principal_id)
        .await
        .unwrap()
        .expect("second open must heal identically");

    assert_eq!(first_tip.commit_count, second_tip.commit_count);
    assert_eq!(first_tip.pr, second_tip.pr);

    // Repeated reads against the SAME already-healed instance must not
    // re-trigger indexing or otherwise change the tip.
    for _ in 0..3 {
        let tip_again = first_open.get_tip(principal_id).await.unwrap().unwrap();
        assert_eq!(
            tip_again.commit_count, 1,
            "repeated reads on an already-healed instance must not double-index"
        );
    }
}

/// c-idempotent-heal: opening a healthy store (no orphan manifest at all)
/// must not error and must leave the index empty -- the heal scan is a
/// correctness-preserving no-op when there is nothing to heal.
#[tokio::test]
async fn healthy_store_open_is_unaffected() {
    let blob_store = MemoryBlobStore::new();
    let engine = StorageEngine::new(blob_store, MemoryIndexer::new());

    let tip = engine.get_tip("nobody").await.expect("get_tip failed");
    assert!(
        tip.is_none(),
        "no manifest exists, so nothing should be indexed"
    );
}
