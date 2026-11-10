//! Backup and restore as an operator runs them (S06's server half,
//! GOSSIP-MIN: no watermark; a restored peer catches up).

use std::process::Output;

mod common;
use common::ops::*;

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// Claim: an operator can restore a snapshot without harming any
/// principal: the restore reports the lost window, serves the snapshot's
/// tip, and a re-push of the lost commit extends it and is accepted.
/// Red when: the snapshot misses a commit, the lost window goes
/// unreported, or the re-push is refused. End to end: real binary, real
/// router.
#[tokio::test]
async fn restore_reports_the_lost_window_and_accepts_the_repush() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let backup = dir.path().join("snap");
    let (pr, first, second) = golden_chain().await;

    push_all(&data, vec![first]).await;
    let out = server(&data, &["backup"], &[backup.to_str().expect("utf8")]);
    assert!(out.status.success(), "backup: {:?}", text(&out));
    push_all(&data, vec![second.clone()]).await;
    assert_eq!(tips(&data).await[0].1, 2);

    let out = server(&data, &["restore"], &[backup.to_str().expect("utf8")]);
    let (stdout, stderr) = text(&out);
    assert!(out.status.success(), "restore: {stdout} {stderr}");
    assert!(
        stdout.contains("lost window: 1 commit(s) across 1 principal(s)"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("lost {pr}: had 2, restored 1")),
        "{stdout}"
    );

    assert_eq!(tips(&data).await[0].1, 1, "the snapshot's tip is served");
    push_all(&data, vec![second]).await;
    assert_eq!(
        tips(&data).await[0].1,
        2,
        "the re-push extends the restored tip"
    );
}

/// Claim: a backup never copies private key material: with the signing key
/// inside `record/`, backup refuses and writes nothing.
/// Red when: the backup runs anyway. End to end: real binary.
#[tokio::test]
async fn backup_refuses_a_signing_key_inside_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let (_, first, _) = golden_chain().await;
    push_all(&data, vec![first]).await;
    let key = data.join("record").join("signing-key.json");
    std::fs::write(&key, "{}").expect("write key");
    let backup = dir.path().join("snap");

    let out = server(
        &data,
        &["backup"],
        &[
            backup.to_str().expect("utf8"),
            "--signing-key-path",
            key.to_str().expect("utf8"),
        ],
    );
    assert!(!out.status.success());
    assert!(text(&out).1.contains("signing key"), "{:?}", text(&out));
    assert!(!backup.exists(), "nothing is written");
}
