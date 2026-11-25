//! Backup and restore as an operator runs them (no watermark: a restored
//! peer catches up).

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

/// Claim: a backup whose source changes during the copy is refused and
/// leaves nothing behind (the copy is checked against the counts taken
/// before it). Red when: the torn backup is published. Library-level
/// because the window cannot be hit through the binary; the real backup
/// code runs, the hook only writes into the window.
#[tokio::test]
async fn backup_whose_source_changes_during_the_copy_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let dest = dir.path().join("snap");
    let (_, first, second) = golden_chain().await;
    push_all(&data, vec![first]).await;

    let err = cyphr_server::ops::snapshot::backup_with(
        &config_at(&data),
        &dest,
        push_all(&data, vec![second]),
    )
    .await
    .expect_err("a changed source must refuse");
    assert!(
        err.to_string().contains("changed while it was copied"),
        "{err}"
    );
    assert!(!dest.exists());
    assert!(!dir.path().join("snap.partial").exists());
}

/// Claim: a restore whose copy fails leaves the original record in place
/// and serving its tip. Red when: the failed restore leaves the store
/// replaced or missing. End to end: real binary, an unreadable file in
/// the backup.
#[tokio::test]
async fn failed_restore_leaves_the_original_record_serving() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    let backup = dir.path().join("snap");
    let (_, first, second) = golden_chain().await;
    push_all(&data, vec![first]).await;
    let out = server(&data, &["backup"], &[backup.to_str().expect("utf8")]);
    assert!(out.status.success(), "backup: {:?}", text(&out));
    push_all(&data, vec![second]).await;

    let victim = std::fs::read_dir(backup.join("record").join("blobs"))
        .expect("blobs")
        .map(|e| e.expect("entry").path())
        .find(|p| p.is_file())
        .expect("a file in the backup");
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read(&victim).is_ok() {
        return; // running as a user who ignores file modes: cannot make a copy fail
    }

    let out = server(&data, &["restore"], &[backup.to_str().expect("utf8")]);
    assert!(!out.status.success(), "restore must fail");
    assert!(!data.join("record.pre-restore").exists(), "rolled back");
    assert_eq!(
        tips(&data).await[0].1,
        2,
        "the original record still serves its tip"
    );
}
