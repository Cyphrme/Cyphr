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
        .args(["--output", "json"])
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

/// Claim: an existing key file or directory with looser modes is
/// tightened on use and the change is reported on stderr; a store that is
/// already private reports nothing. Keys survive the tightening.
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
        err.contains("0755") && err.contains("0700"),
        "dir change reported: {err}"
    );
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&ks), 0o600);
    let keys: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(keys.as_array().unwrap().len(), 1, "key survives");

    let again = cyphr(&ks, &["key", "list"]);
    assert!(again.stderr.is_empty(), "nothing left to tighten");
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
        .args(["--output", "table", "key", "list"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&table.stdout).contains("software-held, unencrypted"));
}
