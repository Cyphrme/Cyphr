//! Integration tests for cyphr CLI.
//!
//! These tests exercise the CLI binary through `std::process::Command`,
//! validating complete workflows in isolation.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Test helper for invoking the CLI.
struct CliTest {
    /// Temporary directory for test isolation.
    temp_dir: TempDir,
    /// Path to the CLI binary.
    binary: PathBuf,
}

impl CliTest {
    fn new() -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");

        // Cargo sets CARGO_BIN_EXE_<name> for integration tests, so the
        // path stays correct under any target-dir or build-dir layout.
        let binary = PathBuf::from(env!("CARGO_BIN_EXE_cyphr"));

        Self { temp_dir, binary }
    }

    fn keystore_path(&self) -> PathBuf {
        self.temp_dir.path().join("keys.json")
    }

    fn store_path(&self) -> PathBuf {
        self.temp_dir.path().join("data")
    }

    fn store_uri(&self) -> String {
        format!("file:{}", self.store_path().display())
    }

    /// Run the CLI with given arguments, returning stdout.
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--keystore")
            .arg(self.keystore_path())
            .arg("--store")
            .arg(self.store_uri())
            .args(args);

        let output = cmd.output().expect("failed to execute CLI");

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Run and assert success, returning stdout.
    fn run_ok(&self, args: &[&str]) -> String {
        match self.run(args) {
            Ok(out) => out,
            Err(err) => panic!("CLI command failed: {err}\nArgs: {args:?}"),
        }
    }

    /// Run with JSON output and parse a field.
    fn run_json(&self, args: &[&str]) -> serde_json::Value {
        let mut full_args = vec!["--output", "json"];
        full_args.extend(args);
        let out = self.run_ok(&full_args);
        serde_json::from_str(&out).expect("invalid JSON output")
    }
}

/// Claim: a Level 2 (single key, no principal/create) Ed25519 identity survives export then
/// import into a fresh store: its identity is the key's SHA-512 thumbprint, read under the key's
/// own hash (SPEC 2.2.1), not SHA-256.
/// End-to-end: yes (CLI processes, two stores).
/// Turns red on: an import that builds the identity's PG as a SHA-256 digest ("digest length
/// mismatch for SHA-256: expected 32 bytes, got 64").
#[test]
fn test_ed25519_level2_export_import_roundtrip() {
    let cli = CliTest::new();
    let genesis = cli.run_json(&["key", "generate", "--algo", "Ed25519"]);
    let tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={tmb}");
    let signer_arg = format!("--signer={tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    let _ = cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    let export_path = cli.temp_dir.path().join("export.jsonl");
    let output_path_arg = format!("--output={}", export_path.to_str().unwrap());
    let _ = cli.run_ok(&["export", &identity_arg, &output_path_arg]);

    let import_uri = format!("file:{}", cli.temp_dir.path().join("import-data").display());
    let out = Command::new(&cli.binary)
        .arg("--keystore")
        .arg(cli.keystore_path())
        .args([
            "--store",
            &import_uri,
            "--output",
            "json",
            "import",
            "--input",
        ])
        .arg(&export_path)
        .output()
        .expect("import failed to run");
    assert!(
        out.status.success(),
        "Ed25519 import must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).expect("import JSON");
    assert_eq!(
        result["identity"], tmb,
        "imported identity is the key's thumbprint"
    );
}

/// Backs: user-visible export then import into a fresh store preserves the identity.
#[test]
fn test_export_import_roundtrip() {
    let cli = CliTest::new();

    // 1. Generate key and create identity with coz
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    let _ = cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // 2. Export to file
    let export_path = cli.temp_dir.path().join("export.jsonl");
    let output_path_arg = format!("--output={}", export_path.to_str().unwrap());
    let _ = cli.run_ok(&["export", &identity_arg, &output_path_arg]);

    assert!(export_path.exists(), "export file should exist");

    // 3. Create new storage location for import
    let import_store = cli.temp_dir.path().join("import-data");
    let import_uri = format!("file:{}", import_store.display());

    // 4. Import to new storage
    let mut cmd = Command::new(&cli.binary);
    cmd.arg("--keystore")
        .arg(cli.keystore_path())
        .arg("--store")
        .arg(&import_uri)
        .arg("import")
        .arg("--input")
        .arg(&export_path);

    let output = cmd.output().expect("import failed");
    assert!(
        output.status.success(),
        "import should succeed, but got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 5. List keys from imported store to verify (field is "active_keys")
    let mut cmd = Command::new(&cli.binary);
    cmd.arg("--keystore")
        .arg(cli.keystore_path())
        .arg("--store")
        .arg(&import_uri)
        .arg("--output")
        .arg("json")
        .arg("key")
        .arg("list")
        .arg(&identity_arg);

    let output = cmd.output().expect("list failed");
    assert!(output.status.success(), "list should succeed");

    let list: serde_json::Value = serde_json::from_slice(&output.stdout).expect("invalid JSON");
    let keys = list["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "imported identity should have 2 keys");
}

/// Backs: `key list --identity=<tmb>` works for a thumbprint that begins with `-`, which a
/// separate-argument `--identity <tmb>` would parse as a flag (#111, the cause of the former
/// intermittent failure). One in 64 generated thumbprints qualifies, so the test generates until
/// one does.
#[test]
fn test_key_list_accepts_thumbprint_starting_with_dash() {
    let cli = CliTest::new();

    let tmb = (0..1000)
        .map(|_| {
            let key = cli.run_json(&["key", "generate", "--algo", "ES256"]);
            key["tmb"].as_str().unwrap().to_owned()
        })
        .find(|tmb| tmb.starts_with('-'))
        .expect("no thumbprint starting with '-' in 1000 keys");

    let identity_arg = format!("--identity={tmb}");
    let signer_arg = format!("--signer={tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    let list = cli.run_json(&["key", "list", &identity_arg]);
    assert_eq!(list["active_keys"].as_array().unwrap().len(), 2);
}

/// Backs: a peer URL that is plain http:// to a non-loopback host is refused before any
/// connection, and the refusal names the `--allow-cleartext` opt-in.
#[test]
fn test_cleartext_peer_refused_and_names_opt_in_flag() {
    let cli = CliTest::new();

    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={tmb}");

    let err = cli
        .run(&["fetch", &identity_arg, "--peer=http://192.0.2.1:8080"])
        .expect_err("cleartext to a remote host must be refused");
    assert!(err.contains("--allow-cleartext"), "stderr: {err}");
}

/// Backs: an exported commit record carries its real auth root and state root (SPEC 4 commit
/// fields), not placeholders.
#[test]
fn test_exported_commits_carry_real_auth_root_and_state_root() {
    // Regression test: exported CommitEntry lines used to hardcode empty
    // "ar" (auth_root) and "sr" (state root) placeholders even though the
    // indexer already computes and stores real values for both -- the
    // export just never wired them through. An exported JSONL file
    // claiming a full commit record should not silently drop two of its
    // core digest fields.
    let cli = CliTest::new();

    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    let export_path = cli.temp_dir.path().join("export.jsonl");
    let output_path_arg = format!("--output={}", export_path.to_str().unwrap());
    cli.run_ok(&["export", &identity_arg, &output_path_arg]);

    let content = std::fs::read_to_string(&export_path).expect("read export file");
    let line = content.lines().next().expect("at least one commit line");
    let entry: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");

    assert!(
        !entry["ar"].as_str().unwrap_or("").is_empty(),
        "exported commit's auth_root (ar) must not be an empty placeholder"
    );
    assert!(
        !entry["sr"].as_str().unwrap_or("").is_empty(),
        "exported commit's state root (sr) must not be an empty placeholder"
    );
}

/// Backs: inspect at genesis shows PG unset and PR/KS/AS equal to the sole key thumbprint (SPEC
/// 2.2.10 singleton promotion, 2.3.2 PG).
#[test]
fn test_inspect_genesis() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Inspect genesis state
    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let inspect = cli.run_json(&["inspect", &identity_arg]);

    // At genesis, PG is not yet established
    assert_eq!(inspect["pg"].as_str().unwrap(), "<none>");
    assert_eq!(inspect["pr"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["ks"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["as"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["commit_count"], 0);

    let keys = inspect["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
}

/// Backs: inspect after a key add shows the PG established (the CLI commits the
/// genesis before its first key add; a single-key PG is the key's thumbprint),
/// the new KS, two commits (genesis, add) and two active keys.
#[test]
fn test_inspect_after_transactions() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Add a key
    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // Inspect after coz
    let inspect = cli.run_json(&["inspect", &identity_arg]);

    // The genesis commit's principal/create established the PG; for a
    // single-key genesis it is that key's thumbprint.
    assert_eq!(inspect["pg"].as_str().unwrap(), genesis_tmb);
    assert_ne!(
        inspect["ks"].as_str().unwrap(),
        genesis_tmb,
        "KS should change after key add"
    );
    assert_eq!(inspect["commit_count"], 2, "genesis commit + key add");

    let keys = inspect["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "should have 2 keys after add");
}

/// Backs: a multi-key genesis reloads with every genesis key before any push (user-visible
/// init/inspect).
#[test]
fn test_explicit_multi_key_genesis_reload() {
    // An identity created with a multi-key genesis must be reloadable
    // before it has been pushed to a server; `init --keys` commits its
    // genesis (SPEC 5.1: a multi-key principal is Level 3+, which exists
    // only through its genesis commit). Regression test for a bug
    // where the load path unconditionally treated a never-yet-committed
    // identity as implicit (single-key) genesis, so it tried to look up
    // the combined multi-key digest as if it were a single key's
    // thumbprint in the keystore, and failed with a confusing
    // "key not found" error even though both genesis keys were present
    // locally.
    let cli = CliTest::new();

    let key1 = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "k1"]);
    let key1_tmb = key1["tmb"].as_str().unwrap().to_string();
    let key2 = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "k2"]);
    let key2_tmb = key2["tmb"].as_str().unwrap().to_string();

    let keys_arg = format!("--keys={key1_tmb},{key2_tmb}");
    let init = cli.run_json(&["init", &keys_arg]);
    let pr = init["pg"].as_str().unwrap().to_string();

    // Reload without ever having pushed anywhere -- same store, same
    // keystore, brand new process invocation.
    let identity_arg = format!("--identity={pr}");
    let inspect = cli.run_json(&["inspect", &identity_arg]);

    assert_eq!(inspect["commit_count"], 1, "the genesis commit");
    let active_keys: Vec<_> = inspect["active_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["tmb"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        active_keys.len(),
        2,
        "explicit genesis must reload with both original keys, not silently drop one"
    );
    assert!(active_keys.contains(&key1_tmb));
    assert!(active_keys.contains(&key2_tmb));
}

/// Backs: commits chain on a multi-key explicit genesis across separate CLI invocations (F40).
#[test]
fn test_explicit_multi_key_genesis_accepts_commits() {
    // F40 regression: a genuinely fresh multi-key genesis (2+ keys) must
    // accept commits signed on top of it --
    // not just reload (test_explicit_multi_key_genesis_reload, above).
    // A multi-key principal replays from its genesis key alone: its
    // genesis commit's key/creates add the rest (SPEC 5.1), so every
    // commit after it is signed against, and replayed onto, the same key
    // set.
    let cli = CliTest::new();

    let key1 = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "k1"]);
    let key1_tmb = key1["tmb"].as_str().unwrap().to_string();
    let key2 = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "k2"]);
    let key2_tmb = key2["tmb"].as_str().unwrap().to_string();

    let keys_arg = format!("--keys={key1_tmb},{key2_tmb}");
    let init = cli.run_json(&["init", &keys_arg]);
    let pr = init["pg"].as_str().unwrap().to_string();
    let identity_arg = format!("--identity={pr}");
    let signer_arg = format!("--signer={key1_tmb}");

    // The first key add on top of the fresh multi-key genesis -- the exact
    // F40 scenario. `init` committed the genesis commit (both genesis
    // keys' key/creates + principal/create); this is the second commit.
    let add1 = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let key3_tmb = add1["added_key"].as_str().unwrap().to_string();

    // Second add: reload (replaying the stored commits) and resubmit.
    let add2 = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let key4_tmb = add2["added_key"].as_str().unwrap().to_string();

    // Third add, for good measure -- proves this isn't merely "the second
    // commit specifically" but genuinely fixed for the general case.
    let add3 = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let key5_tmb = add3["added_key"].as_str().unwrap().to_string();

    let inspect = cli.run_json(&["inspect", &identity_arg]);
    assert_eq!(inspect["commit_count"], 4, "genesis commit + 3 adds");
    let active_keys: Vec<_> = inspect["active_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["tmb"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(active_keys.len(), 5, "genesis's 2 keys plus 3 added keys");
    for tmb in [&key1_tmb, &key2_tmb, &key3_tmb, &key4_tmb, &key5_tmb] {
        assert!(
            active_keys.contains(tmb),
            "expected key {tmb} to be active after 3 commits on a multi-key genesis"
        );
    }
}

/// Backs: an unknown identity is refused with a clear error, never misread as another genesis.
#[test]
fn test_unresolvable_identity_fails_loudly() {
    // An identity that matches neither a keystore key nor any stored
    // commit must fail with a clear
    // error -- not silently misinterpret it as some other identity's
    // genesis.
    let cli = CliTest::new();

    // Never generated, never initialized: a syntactically valid but
    // otherwise unknown base64url digest.
    let bogus = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let identity_arg = format!("--identity={bogus}");

    let result = cli.run(&["inspect", &identity_arg]);
    assert!(
        result.is_err(),
        "reload of an unresolvable identity must fail, not silently succeed"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("cannot resolve genesis"),
        "error should honestly explain genesis could not be resolved, got: {err}"
    );
}

/// Backs: end-to-end CLI lifecycle - generate, list, tx list, inspect, add, export, revoke (SPEC
/// 4.2.4 self-revoke); subsumes the single-step key/list/tx-list checks.
#[test]
fn test_full_workflow() {
    // Comprehensive test mimicking the demo script
    let cli = CliTest::new();

    // 1. Generate genesis key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "genesis"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");

    // 2. Verify keystore has the key
    let keystore_list = cli.run_json(&["key", "list"]);
    assert_eq!(keystore_list.as_array().unwrap().len(), 1);

    // 3. Check tx list at genesis (0 cozies)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);
    assert_eq!(tx_list["transaction_count"], 0);

    // 4. Check inspect at genesis
    let inspect = cli.run_json(&["inspect", &identity_arg]);
    assert_eq!(inspect["commit_count"], 0);

    // 5. Upgrade (the genesis commit), then add a key
    cli.run_ok(&["upgrade", &identity_arg]);
    let add_result = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let second_key = add_result["added_key"].as_str().unwrap();
    let key_arg = format!("--key={second_key}");

    // 6. List keys - should have 2
    let key_list = cli.run_json(&["key", "list", &identity_arg]);
    assert_eq!(key_list["active_keys"].as_array().unwrap().len(), 2);

    // 7. Check tx list after coz: the genesis commit (key/create of the
    // genesis key, principal/create, commit/create) then the add (mutation +
    // commit/create)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);
    assert_eq!(tx_list["transaction_count"], 5);

    // 8. Check inspect after coz (genesis commit + add)
    let inspect = cli.run_json(&["inspect", &identity_arg]);
    assert_eq!(inspect["commit_count"], 2);
    assert_eq!(inspect["active_keys"].as_array().unwrap().len(), 2);

    // 9. Export
    let export_path = cli.temp_dir.path().join("export.jsonl");
    let output_arg = format!("--output={}", export_path.display());
    cli.run_ok(&["export", &identity_arg, &output_arg]);
    assert!(export_path.exists());

    // 10. Revoke the second key (self-revoke: the key signs its own revocation)
    let second_key_signer = format!("--signer={second_key}");
    cli.run_ok(&["key", "revoke", &identity_arg, &key_arg, &second_key_signer]);

    // 11. Verify final state - only genesis key remains
    let final_list = cli.run_json(&["key", "list", &identity_arg]);
    let final_keys = final_list["active_keys"].as_array().unwrap();
    assert_eq!(final_keys.len(), 1);
    // Key order is not guaranteed, check that genesis key is present
    assert!(
        final_keys
            .iter()
            .any(|k| k["tmb"].as_str() == Some(genesis_tmb)),
        "genesis key should be in final active keys"
    );

    // 12. Check tx list shows 7 cozies: the genesis commit's 3, then 2 commits
    // × 2 each (mutation + commit/create)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);
    assert_eq!(tx_list["transaction_count"], 7);
}

/// Backs: tx verify accepts a real commit chain (PR/arrow consistency, SPEC 4).
#[test]
fn test_tx_verify_after_transactions() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");

    // Add a key (the CLI commits the genesis commit first, then the add)
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // Verify coz chain - THIS IS THE CRITICAL TEST
    // If PR Mismatch bug exists, this will fail
    let verify = cli.run_json(&["tx", "verify", &identity_arg]);

    assert_eq!(verify["status"], "OK", "tx verify should succeed");
    // genesis commit (3 cozies) + add (2 cozies)
    assert_eq!(verify["commits_verified"], 2);
    assert_eq!(verify["transactions_verified"], 5);
}

/// Backs: tx verify fails loudly when stored commit data is unreadable, never reporting a false OK.
#[test]
fn test_tx_verify_reports_storage_errors_instead_of_false_success() {
    // Regression test: `tx verify` used to collapse any storage error
    // while loading commits into an empty list via `unwrap_or_default()`,
    // making a real failure (corrupted index, missing blob, etc.)
    // indistinguishable from a legitimate zero-commit genesis identity --
    // and then reporting "OK, genesis state verified" over data that
    // actually failed to load.
    let cli = CliTest::new();

    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");

    // Create a real commit so this identity is NOT legitimately empty.
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);
    let verify_before = cli.run_json(&["tx", "verify", &identity_arg]);
    assert_eq!(verify_before["status"], "OK");
    assert_eq!(verify_before["commits_verified"], 2, "genesis commit + add");

    // Simulate real data loss: wipe the blob store contents while
    // leaving the index's references to them intact, so retrieving this
    // identity's commits now genuinely fails instead of finding nothing.
    let blobs_dir = cli.store_path().join("blobs");
    std::fs::remove_dir_all(&blobs_dir).expect("remove blobs dir");
    std::fs::create_dir_all(&blobs_dir).expect("recreate empty blobs dir");

    let result = cli.run(&["tx", "verify", &identity_arg]);
    assert!(
        result.is_err(),
        "tx verify must fail loudly when the underlying commit data cannot be read, not silently \
         report genesis-state success"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("not found"),
        "error should surface the real storage failure, got: {err}"
    );
}

fn wall_second() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

/// Backs the key-timeline tie rule (forge #213): a data action signed by a key, then
/// `key replace` of that key in the same second (a signature dated at a
/// removal is judged after it), must not fail the replace. The action is a
/// verdict its history flipped: ignored, not refused as `unknown key`.
/// End-to-end: yes (CLI processes, one store). Red before the fix: `key
/// replace` exits non-zero with `unknown key` while saving the action.
#[test]
fn test_key_replace_in_the_second_of_an_action_is_not_refused() {
    let cli = CliTest::new();
    let genesis = cli.run_json(&["key", "generate", "--algo", "Ed25519", "--tag", "genesis"]);
    let tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={tmb}");
    let signer_arg = format!("--signer={tmb}");
    cli.run_ok(&["upgrade", &identity_arg]);
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // Both commands sign with one fixed `now`, so they share a second
    // however slowly each process runs.
    let now = format!("--now={}", wall_second());
    cli.run_ok(&[
        "data",
        "action",
        &identity_arg,
        &signer_arg,
        "--msg=held",
        &now,
    ]);
    cli.run_ok(&["key", "replace", &identity_arg, &signer_arg, &now]);
}
