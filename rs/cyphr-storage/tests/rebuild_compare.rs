//! S3a mutation-armed rebuild-and-compare (c-compare-armed, c-registry-generated).
//!
//! The design's licence to treat the index as disposable rests on one
//! property: the index is a pure, deterministic derivation of the blob
//! store's durable manifests. That property has been asserted in prose
//! (root `AGENTS.md` I1; docs/proposals/storage-layering.md §3.1-3.3) and
//! enforced by nothing -- nothing in the tree has ever demonstrated that a
//! violation of it is even DETECTABLE. This file is that demonstration.
//!
//! ## Architecture
//!
//! Two independent `FjallIndexer` instances are derived from the SAME
//! blob-store content, via the legitimate deriver path
//! (`StorageEngine::rebuild_index_from_manifests`, fed manifests written
//! directly to the blob store the way a crash-recovered write would find
//! them -- see `tests/crash_recovery.rs`'s identical `RawManifest`
//! mirror). A clean rebuild of both from identical content must match
//! byte-for-byte: same physical keyspace set, same key/value pairs in
//! every keyspace, same registry.
//!
//! Each mutation test then plants ONE divergence directly against the
//! LIVE instance's on-disk fjall state, using raw `fjall::Database`
//! access -- never through `Indexer` or `StorageEngine`, which is
//! exactly the path whose exclusivity this property depends on (S3a's
//! sealing). Planting through the deriver would prove nothing, since the
//! deriver is the thing being sealed.
//!
//! ## Two independent comparison paths
//!
//! - [`compare_physical`]: raw fjall keyspace-name-set equality plus per-keyspace key/value
//!   equality, reached with NO new capability -- this crate's existing dev-dependency on `fjall` is
//!   enough. Catches m1 (an extra keyspace, planted physically) and m2 (one divergent row, planted
//!   physically) at the storage layer directly, independent of any read path.
//! - The registry compare (m3, and folded into the clean case for assurance): calls
//!   `FjallIndexer::registry()`, a NEW accessor this node's implementation phase must add
//!   (c-registry-generated: "the registry the store reports is derivation output"). This is
//!   deliberately a SEPARATE check from `compare_physical`: `registry()` must report a claim the
//!   deriver itself produces and durably records, not a value recomputed by scanning physical
//!   keyspace existence at call time -- if it were the latter, m3 (a registry entry present but
//!   never produced by any derivation) would be physically indistinguishable from m1, and
//!   c-compare-armed's three named mutations would collapse to two. `registry()` does not exist
//!   yet, so this whole file currently fails to compile -- verified baseline red, `cargo test -p
//!   cyphr-storage --test rebuild_compare`: `error[E0599]: no method named 'registry' found for
//!   struct 'FjallIndexer'` -- a missing capability, not a typo.
//!
//! m3's mutation writes directly into the `index_meta` keyspace (the
//! same keyspace `cyphr-index-fjall/src/lib.rs`'s current write-once
//! `IndexMeta` occupies), using a locally mirrored struct with today's
//! `{version, partitions}` shape -- exactly the "mirror a private type
//! by its documented JSON shape" pattern `tests/crash_recovery.rs`
//! already uses for `CommitManifest`. If the implementation phase
//! changes the registry's on-disk representation, this mirror (and
//! `plant_bogus_registry_entry` below) needs its shape updated to
//! match -- a syntactic follow, not a weakening of what the test
//! asserts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::blob::{Blake3Hash, BlobStore};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{IndexableCommit, IndexableCoz, PublicKeyInfo};
use fjall::KeyspaceCreateOptions;

/// Mirrors the private `COMMIT_MANIFEST_KIND` constant at
/// `rs/cyphr-storage/src/engine/mod.rs:116` (same mirror
/// `tests/crash_recovery.rs` uses).
const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// Mirrors the private `CommitManifest` struct at
/// `rs/cyphr-storage/src/engine/mod.rs:129` -- only the JSON shape needs
/// to match.
#[derive(serde::Serialize)]
struct RawManifest<'a> {
    kind: &'a str,
    commit: &'a IndexableCommit,
}

/// Mirrors `cyphr-index-fjall/src/lib.rs:54-58`'s private `IndexMeta`
/// shape, for m3's out-of-band registry tamper. See this file's module
/// doc for why the mirror -- not a shared type -- is deliberate.
#[derive(serde::Serialize)]
struct RawIndexMeta {
    version: u32,
    partitions: Vec<String>,
}

/// The fixed partition names `cyphr-index-fjall/src/lib.rs:167-172`
/// opens today. Mirrored here only to name the EXISTING keyspace m2
/// tampers with (`index_tips`) and the baseline set m3's bogus registry
/// entry is appended to -- not a claim about what the generated registry
/// must contain going forward.
const META_KEYSPACE: &str = "index_meta";
const META_KEY: &[u8] = b"index-meta";
const KNOWN_PARTITIONS: &[&str] = &[
    "index_tips",
    "index_principals",
    "index_commits",
    "index_digests",
    "index_public_keys",
];

/// Build a durable-shaped commit, mirroring `tests/crash_recovery.rs`'s
/// `make_commit` fixture, extended with one key so `index_public_keys`
/// is populated too (exercised by the per-keyspace physical compare).
fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = principal_id.as_bytes()[0];
    hash_bytes[1] = seq as u8;
    let dummy_hash = Blake3Hash::from_bytes(hash_bytes);

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
        keys: vec![PublicKeyInfo {
            thumbprint: format!("thumbprint-{principal_id}-{seq}"),
            algorithm: "ED25519".to_string(),
            public_key: format!("pubkey-{principal_id}-{seq}"),
        }],
    }
}

/// Write a manifest blob directly (the durable, unindexed shape a crash
/// -- or, here, a from-scratch corpus -- leaves for `rebuild_index_from_manifests`
/// to pick up).
async fn write_manifest(blob_store: &FjallBlobStore, commit: &IndexableCommit) {
    let manifest = RawManifest {
        kind: COMMIT_MANIFEST_KIND,
        commit,
    };
    let bytes = serde_json::to_vec(&manifest).expect("manifest serialize");
    blob_store.put(&bytes).await.expect("manifest put");
}

/// A small fixed corpus: three principals, some with more than one
/// commit, enough to populate every partition (`index_tips`,
/// `index_principals`, `index_commits`, `index_digests`,
/// `index_public_keys`) non-trivially.
fn corpus() -> Vec<IndexableCommit> {
    vec![
        make_commit("alice", 0, 1_000),
        make_commit("alice", 1, 1_001),
        make_commit("bob", 0, 2_000),
        make_commit("carol", 0, 3_000),
        make_commit("carol", 1, 3_001),
        make_commit("carol", 2, 3_002),
    ]
}

/// Derive a fresh on-disk `FjallIndexer` at `index_path` from every
/// manifest already durable in `blob_db`, via the legitimate deriver
/// path (`StorageEngine::rebuild_index_from_manifests`) -- never a
/// direct `Indexer::index_commit` call. Drops the engine (and its fjall
/// handles) before returning so the caller can freely reopen `index_path`
/// raw afterward.
async fn derive_into(blob_db: &fjall::Database, index_path: &Path, expected_commits: usize) {
    let blob_store = FjallBlobStore::from_database(blob_db.clone()).expect("open blob store");
    let indexer = FjallIndexer::open(index_path).expect("open fresh indexer");
    let engine = StorageEngine::new(blob_store, indexer);

    let count = engine
        .rebuild_index_from_manifests()
        .await
        .expect("rebuild_index_from_manifests failed");
    assert_eq!(
        count, expected_commits,
        "every manifest in the corpus must be picked up by the legitimate derivation path"
    );
    // `engine` (and the `FjallIndexer`/fjall::Database handle it owns)
    // drops here, releasing index_path for a raw reopen.
}

/// Physical per-keyspace compare between two independently-derived fjall
/// index directories: same keyspace-NAME set, same key/value pairs
/// within every keyspace. Reached with NO new capability -- raw
/// `fjall::Database` reads only -- so it exercises what is PHYSICALLY
/// durable, independent of any `Indexer`-level read path (which a
/// tampered store could not be trusted to report honestly anyway).
fn compare_physical(fresh_path: &Path, live_path: &Path) -> Result<(), String> {
    let fresh_db = fjall::Database::builder(fresh_path)
        .open()
        .expect("open fresh raw db");
    let live_db = fjall::Database::builder(live_path)
        .open()
        .expect("open live raw db");

    let fresh_names: BTreeSet<String> = fresh_db
        .list_keyspace_names()
        .iter()
        .map(|k| k.to_string())
        .collect();
    let live_names: BTreeSet<String> = live_db
        .list_keyspace_names()
        .iter()
        .map(|k| k.to_string())
        .collect();
    if fresh_names != live_names {
        return Err(format!(
            "keyspace name sets differ: fresh={fresh_names:?} live={live_names:?}"
        ));
    }

    for name in &fresh_names {
        let fresh_ks = fresh_db
            .keyspace(name, KeyspaceCreateOptions::default)
            .expect("open fresh keyspace");
        let live_ks = live_db
            .keyspace(name, KeyspaceCreateOptions::default)
            .expect("open live keyspace");

        let fresh_kv: BTreeMap<Vec<u8>, Vec<u8>> = fresh_ks
            .iter()
            .map(|guard| {
                let (k, v) = guard.into_inner().expect("read fresh kv");
                (k.to_vec(), v.to_vec())
            })
            .collect();
        let live_kv: BTreeMap<Vec<u8>, Vec<u8>> = live_ks
            .iter()
            .map(|guard| {
                let (k, v) = guard.into_inner().expect("read live kv");
                (k.to_vec(), v.to_vec())
            })
            .collect();

        if fresh_kv != live_kv {
            return Err(format!(
                "keyspace '{name}' diverges between the fresh derivation and the live index"
            ));
        }
    }

    Ok(())
}

/// Plant an extra keyspace directly on the on-disk store at `path`,
/// bypassing every deriver and every `Indexer` method -- exactly the
/// class of write S3a's sealing exists to make unreachable through the
/// legitimate API, reached here through the raw backend on purpose (m1).
fn plant_extra_keyspace(path: &Path) {
    let db = fjall::Database::builder(path)
        .open()
        .expect("reopen live raw db for m1");
    let ghost = db
        .keyspace(
            "index_ghost_extra_partition",
            KeyspaceCreateOptions::default,
        )
        .expect("create ghost keyspace");
    ghost
        .insert(b"ghost-key", b"ghost-value")
        .expect("insert ghost row");
    db.persist(fjall::PersistMode::SyncAll)
        .expect("persist m1 tamper");
}

/// Overwrite one EXISTING row's value directly, bypassing the deriver
/// (m2). Targets `index_tips`'s entry for "alice", who the corpus gives
/// two commits, so the untampered value is well-defined and non-trivial.
fn plant_divergent_row(path: &Path) {
    let db = fjall::Database::builder(path)
        .open()
        .expect("reopen live raw db for m2");
    let tips = db
        .keyspace("index_tips", KeyspaceCreateOptions::default)
        .expect("open index_tips");
    tips.insert(b"alice", b"tampered-out-of-band-not-a-real-tip")
        .expect("insert divergent row");
    db.persist(fjall::PersistMode::SyncAll)
        .expect("persist m2 tamper");
}

/// Append a bogus name to the store's registry claim WITHOUT producing
/// any corresponding physical partition for it -- "a registry entry
/// present but not produced by the derivation" (m3), planted by writing
/// straight into the `index_meta` keyspace's tracking record.
fn plant_bogus_registry_entry(path: &Path) {
    let db = fjall::Database::builder(path)
        .open()
        .expect("reopen live raw db for m3");
    let meta = db
        .keyspace(META_KEYSPACE, KeyspaceCreateOptions::default)
        .expect("open index_meta");
    let mut partitions: Vec<String> = KNOWN_PARTITIONS.iter().map(|s| s.to_string()).collect();
    partitions.push("index_never_produced_by_any_derivation".to_string());
    let bogus = RawIndexMeta {
        version: 1,
        partitions,
    };
    meta.insert(
        META_KEY,
        serde_json::to_vec(&bogus).expect("serialize bogus registry"),
    )
    .expect("insert bogus registry entry");
    db.persist(fjall::PersistMode::SyncAll)
        .expect("persist m3 tamper");
}

/// Clean case: two independent derivations of identical blob content
/// must match byte-for-byte, both physically and in their reported
/// registry. This is the case that PROVES the mutation tests below are
/// not vacuous -- a compare that can never be satisfied on a clean store
/// would make every "reds on mutation" result meaningless.
#[tokio::test]
async fn clean_rebuild_matches_physically_and_by_registry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob_db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("open blob db");
    let blob_store = FjallBlobStore::from_database(blob_db.clone()).expect("blob store");

    let commits = corpus();
    for commit in &commits {
        write_manifest(&blob_store, commit).await;
    }

    let fresh_path = dir.path().join("fresh");
    let live_path = dir.path().join("live");
    derive_into(&blob_db, &fresh_path, commits.len()).await;
    derive_into(&blob_db, &live_path, commits.len()).await;

    compare_physical(&fresh_path, &live_path)
        .expect("two clean derivations of identical content must match physically");

    let fresh_registry = FjallIndexer::open(&fresh_path)
        .expect("reopen fresh")
        .registry()
        .expect("fresh registry");
    let live_registry = FjallIndexer::open(&live_path)
        .expect("reopen live")
        .registry()
        .expect("live registry");
    assert_eq!(
        fresh_registry, live_registry,
        "two clean derivations of identical content must report the same registry"
    );
}

/// m1: an extra keyspace planted out-of-band reds the physical compare.
#[tokio::test]
async fn m1_extra_keyspace_reds_the_compare() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob_db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("open blob db");
    let blob_store = FjallBlobStore::from_database(blob_db.clone()).expect("blob store");

    let commits = corpus();
    for commit in &commits {
        write_manifest(&blob_store, commit).await;
    }

    let fresh_path = dir.path().join("fresh");
    let live_path = dir.path().join("live");
    derive_into(&blob_db, &fresh_path, commits.len()).await;
    derive_into(&blob_db, &live_path, commits.len()).await;

    plant_extra_keyspace(&live_path);

    let result = compare_physical(&fresh_path, &live_path);
    assert!(
        result.is_err(),
        "an extra keyspace planted directly on the live store, absent from the fresh derivation, \
         must be caught by the physical compare"
    );
}

/// m2: one divergent row planted out-of-band reds the physical compare.
#[tokio::test]
async fn m2_divergent_row_reds_the_compare() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob_db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("open blob db");
    let blob_store = FjallBlobStore::from_database(blob_db.clone()).expect("blob store");

    let commits = corpus();
    for commit in &commits {
        write_manifest(&blob_store, commit).await;
    }

    let fresh_path = dir.path().join("fresh");
    let live_path = dir.path().join("live");
    derive_into(&blob_db, &fresh_path, commits.len()).await;
    derive_into(&blob_db, &live_path, commits.len()).await;

    plant_divergent_row(&live_path);

    let result = compare_physical(&fresh_path, &live_path);
    assert!(
        result.is_err(),
        "a row overwritten directly on the live store, diverging from what the fresh derivation \
         produced for the same key, must be caught by the physical compare"
    );
}

/// m3: a registry entry present but not produced by any derivation reds
/// the registry set-compare specifically -- distinct from m1's physical
/// compare, since the bogus name here names no physical partition at
/// all (see this file's module doc for why that distinction only holds
/// if `registry()` reports a derivation-produced claim rather than a
/// live rescan of physical keyspace existence).
#[tokio::test]
async fn m3_unproduced_registry_entry_reds_the_registry_compare() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob_db = fjall::Database::builder(dir.path().join("blobs"))
        .open()
        .expect("open blob db");
    let blob_store = FjallBlobStore::from_database(blob_db.clone()).expect("blob store");

    let commits = corpus();
    for commit in &commits {
        write_manifest(&blob_store, commit).await;
    }

    let fresh_path = dir.path().join("fresh");
    let live_path = dir.path().join("live");
    derive_into(&blob_db, &fresh_path, commits.len()).await;
    derive_into(&blob_db, &live_path, commits.len()).await;

    plant_bogus_registry_entry(&live_path);

    let fresh_registry = FjallIndexer::open(&fresh_path)
        .expect("reopen fresh")
        .registry()
        .expect("fresh registry");
    let live_registry = FjallIndexer::open(&live_path)
        .expect("reopen live")
        .registry()
        .expect("live registry");

    assert_ne!(
        fresh_registry, live_registry,
        "a registry entry written directly into index_meta, with no corresponding derivation ever \
         having produced it, must diverge from the fresh derivation's registry -- the registry \
         set-compare this constraint names"
    );
    assert!(
        live_registry.contains("index_never_produced_by_any_derivation"),
        "sanity: the tamper must actually be visible in what registry() reports, or this test is \
         asserting nothing about the property it claims to guard"
    );
}
