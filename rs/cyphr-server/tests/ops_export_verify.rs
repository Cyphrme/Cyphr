//! Export and verify-all: an operator proves the store whole.

use std::process::Output;

mod common;
use common::ops::*;
use cyphr_server::AppState;
use cyphr_server::ops::chains::import;

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Claim: export writes every stored principal chain in a form import
/// reads back to the same tips, and verify-all passes on a whole store.
/// Red when: a chain is missing from the export, does not re-admit, or
/// lands on another tip. End to end: real binary and the admission path.
#[tokio::test]
async fn export_round_trips_and_a_whole_store_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let (_, first, second) = golden_chain().await;
    let (_, alice) = alice_chain().await;
    push_all(&data, vec![first, second, alice]).await;

    let out_dir = dir.path().join("out");
    let out = server(&data, &["export"], &[out_dir.to_str().expect("utf8")]);
    assert!(out.status.success(), "{:?}", out);
    assert!(
        stdout(&out).contains("exported 2 principal(s)"),
        "{}",
        stdout(&out)
    );

    let fresh = dir.path().join("fresh");
    {
        let state = AppState::new(config_at(&fresh)).expect("open fresh store");
        let read = import(&state, &out_dir).await.expect("import");
        assert_eq!(read.len(), 2);
    }
    assert_eq!(
        tips(&fresh).await,
        tips(&data).await,
        "same tips after import"
    );

    let out = server(&data, &["verify-all"], &[]);
    assert!(out.status.success(), "{} {:?}", stdout(&out), out);
    assert!(stdout(&out).contains("2 principal(s) replayed, 0 failure(s)"));
}

/// Claim: verify-all names a chain whose stored blob was damaged and
/// exits non-zero, while an untouched chain is not blamed.
/// Red when: a damaged store passes. End to end: real binary on a store
/// whose blob is overwritten in place.
#[tokio::test]
async fn verify_all_names_a_corrupted_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let (golden, first, second) = golden_chain().await;
    let (alice_id, alice) = alice_chain().await;
    push_all(&data, vec![first, second, alice]).await;

    // Damage one coz blob of the golden principal's chain: overwrite the
    // first stored blob that is not a manifest.
    {
        let db = fjall::Database::builder(data.join("record").join("blobs"))
            .open()
            .expect("open blobs");
        let blobs = db
            .keyspace("blobs", fjall::KeyspaceCreateOptions::default)
            .expect("blobs keyspace");
        let mut hit = None;
        for guard in blobs.iter() {
            let (k, v) = guard.into_inner().expect("entry");
            if v.first() != Some(&0)
                && String::from_utf8_lossy(&v)
                    .contains(&golden[golden.find(':').map_or(0, |i| i + 1)..])
            {
                hit = Some(k);
                break;
            }
        }
        let key = hit.expect("a coz blob of the golden principal");
        blobs.insert(key, b"not a coz".to_vec()).expect("overwrite");
        db.persist(fjall::PersistMode::SyncAll).expect("persist");
    }

    let out = server(&data, &["verify-all"], &[]);
    assert!(
        !out.status.success(),
        "damage must fail verify-all: {}",
        stdout(&out)
    );
    let report = stdout(&out);
    assert!(report.contains("FAIL"), "{report}");
    assert!(!report.contains(&format!("FAIL {alice_id}")), "{report}");
}
