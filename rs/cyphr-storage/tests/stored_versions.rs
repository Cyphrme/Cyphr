//! Stored formats are versioned, and an incompatible one is refused with a
//! typed, named error rather than read as if it were current (N13).
//!
//! Convention pinned here for every JSON document: a top-level integer `v`
//! (the envelope already uses it). The refusal text must say "version", name
//! the offending value and the format; a superseded store must also name the
//! remedy, an offline re-ingest. The variant names are the implementer's.
//!
//! Each test states the claim it backs and the defect that turns it red; none
//! is an end-to-end scenario -- the reader is the unit under claim and no
//! scenario reaches an on-disk format cheaply.

use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::CommitEntry;
use fjall::{Database, KeyspaceCreateOptions, PersistMode};

/// A bundle line as the CLI's `export` writes it.
fn entry() -> CommitEntry {
    CommitEntry::new(vec![], vec![], "c".into(), "a".into(), "s".into(), "p".into())
}

/// Claim: an exported bundle line states the format version it was written
/// at, and a reader refuses a line from a version it does not know, naming
/// the format and the version. Turns red on a writer that stamps nothing, or
/// a `from_json` that accepts any `v` (including the unknown 0 and 99).
#[test]
#[ignore = "RED(N13): bundle lines carry no version and any `v` is accepted"]
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
        let err = CommitEntry::from_json(&doc.to_string())
            .expect_err("an unknown bundle version must be refused")
            .to_string()
            .to_lowercase();
        assert!(
            err.contains("version") && err.contains("bundle") && err.contains(&unknown.to_string()),
            "refusal must name the format and the version: {err}"
        );
    }
}

/// A legacy index at `dir`: stamped `version`, with a pre-H1F digest record
/// (one bare `EntityRef` under the digest's own key) and no holder tables.
fn plant_legacy_index(dir: &std::path::Path, version: u64) {
    {
        let indexer = FjallIndexer::open(dir).expect("open fresh");
        drop(indexer);
    }
    let db = Database::builder(dir).open().expect("raw open");
    let open = |n: &str| db.keyspace(n, KeyspaceCreateOptions::default).expect(n);
    let digest = format!("SHA-256:{}", "B".repeat(42) + "A");
    open("index_digests")
        .insert(
            digest.as_bytes(),
            serde_json::to_vec(&serde_json::json!({
                "digest": digest,
                "blob_hash": vec![9u8; 32],
                "entity_type": "Transaction",
                "sequence": 0,
                "principal_id": "SHA-256:old",
                "principal_root": false,
            }))
            .unwrap(),
        )
        .expect("legacy digest");
    open("index_meta")
        .insert(
            b"index-meta",
            serde_json::to_vec(&serde_json::json!({
                "version": version,
                "partitions": ["index_tips", "index_principals", "index_commits", "index_digests", "index_public_keys"],
            }))
            .unwrap(),
        )
        .expect("legacy meta");
    db.persist(PersistMode::SyncAll).expect("persist");
}

/// Claim: a store written before the holder-keyed digest tables or the PG
/// alias table (index schema 1 and 2) is detected by its version and refused
/// at open with the remedy -- never silently re-indexed or read through a
/// compatibility shim -- and the refusal is repeatable, so the first open did
/// not quietly upgrade it. Turns red on an `open` that accepts the old
/// schema, that upgrades in place, or that refuses without naming the remedy.
#[test]
#[ignore = "RED(N13): a pre-H1F index (schema 2) opens and is read through a shim"]
fn legacy_store_index_is_refused_with_the_remedy() {
    for old in [1u64, 2] {
        let dir = tempfile::tempdir().expect("tempdir");
        plant_legacy_index(dir.path(), old);
        for attempt in 1..=2 {
            let msg = match FjallIndexer::open(dir.path()) {
                Err(e) => e.to_string().to_lowercase(),
                Ok(_) => panic!("schema {old} opened on attempt {attempt}"),
            };
            assert!(
                msg.contains("re-ingest") && msg.contains("version"),
                "schema {old} refusal must name the version and the remedy: {msg}"
            );
        }
    }
}
