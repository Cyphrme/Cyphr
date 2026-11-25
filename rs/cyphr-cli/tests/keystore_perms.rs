//! End to end: the key file's on-disk custody posture, observed through
//! the real `cyphr` binary. Unix-only because the claim is about modes.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn cyphr(keystore: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cyphr"))
        .arg("--keystore")
        .arg(keystore)
        .args(["--format", "json"])
        .args(args)
        .output()
        .expect("running cyphr")
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).expect("stat").permissions().mode() & 0o777
}

fn set_mode(p: &Path, m: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(m)).expect("chmod");
}

/// Claim: generating a key creates the key file 0600 inside a 0700
/// directory (created if absent), leaving no temp file beside it.
#[test]
fn keystore_created_private() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("fresh");
    let ks = dir.join("keys.json");
    let out = cyphr(&ks, &["key", "generate", "--algo", "ES256"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(mode(&dir), 0o700, "directory");
    assert_eq!(mode(&ks), 0o600, "file");
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["keys.json"], "no temp file left behind");
}

/// Claim: an existing key file with looser modes is tightened on use and
/// reported on stderr; an existing directory that is open to others is
/// warned about and left alone; a private store reports nothing. Keys
/// survive the tightening.
#[test]
fn keystore_loose_modes_tightened_and_reported() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("loose");
    let ks = dir.join("keys.json");
    let first = cyphr(&ks, &["key", "generate", "--algo", "ES256"]);
    assert!(first.status.success());
    assert!(
        first.stderr.is_empty(),
        "a private store reports nothing: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    set_mode(&dir, 0o755);
    set_mode(&ks, 0o644);

    let out = cyphr(&ks, &["key", "list"]);
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("0644") && err.contains("0600"),
        "file change reported: {err}"
    );
    assert!(
        err.contains("0755") && err.contains(&dir.display().to_string()),
        "dir warned with its path: {err}"
    );
    assert_eq!(mode(&dir), 0o755, "an existing directory is never chmodded");
    assert_eq!(mode(&ks), 0o600);
    let keys: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keys.as_array().unwrap().len(), 1, "key survives");

    set_mode(&dir, 0o700);
    let again = cyphr(&ks, &["key", "list"]);
    assert!(again.stderr.is_empty(), "nothing left to report");
}

/// Claim: `key list` states the custody of every key: software-held,
/// unencrypted, in both output formats.
#[test]
fn key_list_labels_custody() {
    let root = tempfile::tempdir().unwrap();
    let ks = root.path().join("keys.json");
    assert!(
        cyphr(&ks, &["key", "generate", "--algo", "ES256"])
            .status
            .success()
    );
    let out = cyphr(&ks, &["key", "list"]);
    let keys: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keys[0]["custody"], "software-held, unencrypted");

    let table = Command::new(env!("CARGO_BIN_EXE_cyphr"))
        .arg("--keystore")
        .arg(&ks)
        .args(["--format", "table", "key", "list"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&table.stdout).contains("software-held, unencrypted"));
}

/// Claim: with no `--keystore`, the default `./cyphr-keys.json` lives in the
/// working directory, whose mode is left unchanged (warned about if open),
/// while the key file is 0600.
#[test]
fn default_keystore_leaves_cwd_mode() {
    let cwd = tempfile::tempdir().unwrap();
    set_mode(cwd.path(), 0o755);
    let out = Command::new(env!("CARGO_BIN_EXE_cyphr"))
        .current_dir(cwd.path())
        .args(["--format", "json", "key", "generate", "--algo", "ES256"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(mode(cwd.path()), 0o755, "cwd untouched");
    assert_eq!(mode(&cwd.path().join("cyphr-keys.json")), 0o600);
}

/// Claim: a pre-existing shared directory (here root-owned-like 1777, as
/// `/tmp`) is neither chmodded nor an error; the command succeeds, warns
/// with the path, and the key file is 0600.
#[test]
fn shared_directory_unchanged_and_warned() {
    let shared = tempfile::tempdir().unwrap();
    set_mode(shared.path(), 0o1777);
    let ks = shared.path().join("keys.json");
    let out = cyphr(&ks, &["key", "generate", "--algo", "ES256"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&shared.path().display().to_string()), "{err}");
    assert_eq!(
        fs::metadata(shared.path()).unwrap().permissions().mode() & 0o7777,
        0o1777
    );
    assert_eq!(mode(&ks), 0o600);
}

/// Claim: a key file the user made stricter (0400) keeps that mode across
/// a write; a write never widens it.
#[test]
fn stricter_file_mode_survives_write() {
    let root = tempfile::tempdir().unwrap();
    let ks = root.path().join("keys.json");
    assert!(
        cyphr(&ks, &["key", "generate", "--algo", "ES256"])
            .status
            .success()
    );
    set_mode(&ks, 0o400);
    assert!(
        cyphr(&ks, &["key", "generate", "--algo", "ES256"])
            .status
            .success()
    );
    assert_eq!(mode(&ks), 0o400);
    let keys: serde_json::Value =
        serde_json::from_slice(&cyphr(&ks, &["key", "list"]).stdout).unwrap();
    assert_eq!(keys.as_array().unwrap().len(), 2);
}

/// Claim: a read-only command on a missing store creates nothing, and an
/// I/O failure names the operation and the path.
#[test]
fn read_only_creates_nothing_and_errors_name_path() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("absent");
    let ks = dir.join("keys.json");
    let out = cyphr(&ks, &["key", "list"]);
    assert!(out.status.success());
    assert!(!dir.exists(), "key list must not create the directory");

    // A file where the directory should be: the write fails, naming operation and path.
    let blocker = root.path().join("blocker");
    fs::write(&blocker, b"x").unwrap();
    let bad = blocker.join("keys.json");
    let out = cyphr(&bad, &["key", "generate", "--algo", "ES256"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("creating temp file") && err.contains(&blocker.display().to_string()),
        "{err}"
    );
}
