//! Stored formats are versioned, and an incompatible one is refused with a
//! typed error rather than read as if it were current (N13).
//!
//! Conventions pinned here: a JSON document carries a top-level integer `v`;
//! a refusal is a typed `UnsupportedVersion` variant of the format's own
//! error enum, pinned by `matches!` on the variant and its offending number
//! (only the plain-serde path flattens it to a message). An index is a
//! rebuildable cache (I1), so an OLD or MISSING index version is discarded
//! and rebuilt from the blob store, never refused; only the blob store's
//! own legacy layout is refused, naming the offline re-ingest.
//!
//! Each test states the claim it backs and the defect that turns it red.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::blob::{Blake3Hash, BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{EngineError, StorageEngine};
use cyphr_storage::index::{IndexableCommit, IndexableCoz, Indexer, MemoryIndexer};
use cyphr_storage::{BundleError, CommitEntry, Genesis};
use fjall::{Database, KeyspaceCreateOptions, PersistMode};

type Durable =
    StorageEngine<FjallBlobStore, FjallIndexer, cyphr_blob_fjall::storage_fjall::FjallStorage>;

/// A bundle line as the CLI's `export` writes it.
fn entry() -> CommitEntry {
    CommitEntry {
        commit_id: "c".into(),
        auth_root: Some("a".into()),
        sr: Some("s".into()),
        pr: "p".into(),
        ..CommitEntry::default()
    }
}

/// Claim: an exported bundle line states the format version it was written
/// at, and a reader refuses a line from a version it does not know -- both
/// through `from_json` and through the plain `serde_json::from_str` the CLI
/// `import` uses. Turns red on a writer that stamps nothing, or a reader that
/// accepts any `v` (including the unknown 0 and 99).
#[test]
fn version_bundle_unknown_is_refused() {
    let line = entry().to_json().expect("serialize");
    let mut doc: serde_json::Value = serde_json::from_str(&line).expect("json");
    assert!(
        doc["v"].is_u64(),
        "a bundle line must be stamped with a numeric `v`: {line}"
    );
    CommitEntry::from_json(&line).expect("the current version round-trips");
    for unknown in [0u64, 99] {
        doc["v"] = unknown.into();
        let text = doc.to_string();
        let via_json = CommitEntry::from_json(&text).err();
        assert!(
            matches!(via_json, Some(BundleError::UnsupportedVersion { found, .. }) if found == unknown),
            "bundle v={unknown} must be refused as UnsupportedVersion: {via_json:?}"
        );
        // Through plain serde the typed error is flattened to its message,
        // which names the variant (no typed path exists across serde).
        let via_serde = format!("{:?}", serde_json::from_str::<CommitEntry>(&text).err());
        assert!(
            via_serde.contains("UnsupportedVersion") && via_serde.contains(&unknown.to_string()),
            "bundle v={unknown} must be refused as UnsupportedVersion: {via_serde}"
        );
    }
}

// ---- legacy index: discarded and rebuilt from blobs ----------------------

fn golden(name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("tests/golden/lifecycle")
        .join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("golden")).expect("json")
}

fn genesis_of(fx: &serde_json::Value) -> Genesis {
    let k = &fx["genesis_keys"][0];
    let b = |f: &str| Base64UrlUnpadded::decode_vec(k[f].as_str().unwrap()).unwrap();
    Genesis::Implicit(
        cyphr::Key::new(
            k["alg"].as_str().unwrap().to_string(),
            coz::Thumbprint::from_bytes(b("tmb")),
            b("pub"),
        )
        .expect("key binds its tmb"),
    )
}

/// Wire blobs for a fixture commit: each key-introducing coz carries its key.
fn wire_blobs(commit: &serde_json::Value) -> cyphr::replay::WireBundle {
    serde_json::from_value::<CommitEntry>(commit.clone())
        .expect("fixture line")
        .bundle()
        .expect("bundle")
}

fn open_durable(dir: &std::path::Path) -> Durable {
    let db = Database::builder(dir.join("db")).open().expect("open db");
    let blobs = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let index =
        FjallIndexer::open(&dir.join("index")).expect("an index of ANY older version opens");
    StorageEngine::with_log_factory(
        blobs,
        index,
        cyphr_blob_fjall::EmlLogs::new(db.clone()).expect("logs"),
    )
}

/// Rewrite the index's meta record to `version` (`None` removes it, as a
/// store from before versions were recorded would look) and plant a derived
/// row only an old build could have written.
fn age_index(index_dir: &std::path::Path, version: Option<u64>) {
    let db = Database::builder(index_dir).open().expect("raw open");
    let open = |n: &str| db.keyspace(n, KeyspaceCreateOptions::default).expect(n);
    let meta = open("index_meta");
    match version {
        Some(v) => {
            let raw = meta.get(b"index-meta").unwrap().expect("a stamped record");
            let mut rec: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            rec["version"] = v.into();
            meta.insert(b"index-meta", serde_json::to_vec(&rec).unwrap())
                .unwrap();
        },
        None => meta.remove(b"index-meta").unwrap(),
    }
    open("index_tips")
        .insert(b"SHA-256:stale", b"written by an older schema")
        .unwrap();
    db.persist(PersistMode::SyncAll).expect("persist");
}

/// Claim: an index written by an older schema (version 1 or 2, or no version
/// at all) is a stale cache: opening it discards its derived rows -- none is
/// served -- and rebuilding from the blob store brings back the identical
/// tip, which then survives a reopen at the current version. Turns red on an
/// `open` that serves the old rows (no version check) or refuses the store
/// instead of rebuilding it. End-to-end over real durable backends.
#[tokio::test]
async fn legacy_store_index_is_rebuilt_from_blobs() {
    let fx = golden("freeze_create_transitions_to_frozen");
    let genesis = genesis_of(&fx);
    let pid = cyphr_storage::engine::genesis_principal_id(&genesis).expect("id");
    let dir = tempfile::tempdir().expect("tempdir");

    let engine = open_durable(dir.path());
    for commit in fx["commits"].as_array().unwrap() {
        let blobs = wire_blobs(commit);
        engine
            .submit_commit(&pid, Some(genesis.clone()), &blobs)
            .await
            .expect("ingest");
    }
    let tip = engine
        .get_tip(&pid)
        .await
        .unwrap()
        .expect("tip after ingest");
    drop(engine);

    for aged in [Some(1), Some(2), Some(3), None] {
        age_index(&dir.path().join("index"), aged);
        {
            let index = FjallIndexer::open(&dir.path().join("index")).expect("opens");
            let stale = index.get_tip("SHA-256:stale").await;
            assert!(
                matches!(stale, Ok(None)),
                "version {aged:?}: a row from an old schema was served: {stale:?}"
            );
        }
        let engine = open_durable(dir.path());
        engine
            .rebuild_index_from_scratch()
            .await
            .expect("rebuild from blobs");
        assert_eq!(
            engine.get_tip(&pid).await.unwrap(),
            Some(tip.clone()),
            "version {aged:?}"
        );
        drop(engine);
        let reopened = open_durable(dir.path());
        assert_eq!(
            reopened.get_tip(&pid).await.unwrap(),
            Some(tip.clone()),
            "after reopen"
        );
    }
}

// ---- legacy blob store: refused ------------------------------------------

fn digest(tag: u8) -> String {
    format!(
        "SHA-256:{}",
        char::from(b'A' + tag % 26).to_string().repeat(42) + "A"
    )
}

/// Claim: a blob store still in the pre-H1F shared-manifest layout (a
/// manifest posing as a wire blob) is refused, never indexed, with a typed
/// error that names the offline re-ingest. Characterization: the typed
/// variant and its remedy exist at the base, and a change that dropped
/// either would turn this red.
#[tokio::test]
async fn legacy_store_shared_manifest_is_refused_naming_reingest() {
    let hash = Blake3Hash::from_bytes([7; 32]);
    let commit = IndexableCommit {
        principal_id: digest(1),
        commit_ids: vec![digest(2)],
        sequence: 0,
        pre: None,
        prs: vec![digest(3)],
        srs: vec![digest(4)],
        ars: vec![digest(5)],
        crs: vec![digest(6)],
        blob_hashes: vec![hash],
        cozies: vec![IndexableCoz {
            blob_hash: hash,
            czd: digest(7),
            typ: "cyphr.me/cyphr/key/create".into(),
            tmb: "t".into(),
            alg: "Ed25519".into(),
            now: 1,
            payload: None,
        }],
        timestamp: 1,
        keys: Vec::new(),
        pg: Vec::new(),
    };
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let legacy = serde_json::json!({"kind": "cyphr-storage/commit-manifest/v1", "commit": commit});
    BlobStore::put(engine.blob_store(), &serde_json::to_vec(&legacy).unwrap())
        .await
        .unwrap();

    let err = engine
        .rebuild_index_from_manifests()
        .await
        .expect_err("refused");
    assert!(matches!(err, EngineError::LegacyManifest { .. }), "{err:?}");
    assert!(
        err.to_string().contains("re-ingest"),
        "remedy not named: {err}"
    );
}
