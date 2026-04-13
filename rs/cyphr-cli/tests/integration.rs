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

        // Find the binary - cargo test puts it in target/debug
        let binary = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("parent")
            .parent()
            .expect("parent")
            .join("cyphr");

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

#[test]
fn test_key_generate() {
    let cli = CliTest::new();

    let json = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "test-key"]);

    assert_eq!(json["alg"], "ES256");
    assert_eq!(json["tag"], "test-key");
    assert!(json["tmb"].as_str().is_some(), "should have thumbprint");
}

#[test]
fn test_key_lifecycle() {
    let cli = CliTest::new();

    // 1. Generate genesis key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256", "--tag", "genesis"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // 2. Add a new key to identity (this creates the first coz)
    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
    let add_result = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let new_key_tmb = add_result["added_key"].as_str().unwrap();

    // 3. List keys - should show both (field is "active_keys")
    let list_result = cli.run_json(&["key", "list", &identity_arg]);
    let keys = list_result["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "should have 2 active keys");

    // 4. Revoke the new key (self-revoke: the key signs its own revocation)
    // Per SPEC §4.2.4, only self-revoke is supported
    let key_arg = format!("--key={new_key_tmb}");
    let new_key_signer = format!("--signer={new_key_tmb}");
    let _ = cli.run_ok(&["key", "revoke", &identity_arg, &key_arg, &new_key_signer]);

    // 5. List keys - should show only genesis
    let list_result = cli.run_json(&["key", "list", &identity_arg]);
    let keys = list_result["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "should have 1 active key after revoke");
    // Key order is not guaranteed, check that genesis key is present
    assert!(
        keys.iter().any(|k| k["tmb"].as_str() == Some(genesis_tmb)),
        "genesis key should be in active keys"
    );
}

#[test]
fn test_export_import_roundtrip() {
    let cli = CliTest::new();

    // 1. Generate key and create identity with coz
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
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
        .arg("--identity")
        .arg(genesis_tmb);

    let output = cmd.output().expect("list failed");
    assert!(output.status.success(), "list should succeed");

    let list: serde_json::Value = serde_json::from_slice(&output.stdout).expect("invalid JSON");
    let keys = list["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "imported identity should have 2 keys");
}

#[test]
fn test_keystore_list() {
    let cli = CliTest::new();

    // Generate a few keys
    cli.run_ok(&["key", "generate", "--algo", "ES256", "--tag", "key1"]);
    cli.run_ok(&["key", "generate", "--algo", "ES256", "--tag", "key2"]);

    // List keystore keys (no identity specified)
    let list = cli.run_json(&["key", "list"]);
    let keys = list.as_array().unwrap();
    assert_eq!(keys.len(), 2, "should have 2 keys in keystore");
}

#[test]
fn test_tx_list_genesis() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // List cozies (should be empty for genesis)
    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);

    assert_eq!(tx_list["transaction_count"], 0);
}

#[test]
fn test_tx_list_after_transactions() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    // Add a key (creates first coz)
    // Use --arg=value format to handle thumbprints starting with -
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // List cozies - should show 2 (key/create + commit/create per commit)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);

    assert_eq!(tx_list["transaction_count"], 2);
    let cozies = tx_list["cozies"].as_array().unwrap();
    assert_eq!(cozies.len(), 2);
}

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

    // At genesis, PR is not yet established
    assert_eq!(inspect["pr"].as_str().unwrap(), "<none>");
    assert_eq!(inspect["ps"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["ks"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["as"].as_str().unwrap(), genesis_tmb);
    assert_eq!(inspect["commit_count"], 0);

    let keys = inspect["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
}

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
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // Inspect after coz
    let inspect = cli.run_json(&["inspect", &identity_arg]);

    // PR is still <none> until a principal/create coz establishes it
    assert_eq!(inspect["pr"].as_str().unwrap(), "<none>");
    assert_ne!(
        inspect["ks"].as_str().unwrap(),
        genesis_tmb,
        "KS should change after key add"
    );
    assert_eq!(inspect["commit_count"], 1);

    let keys = inspect["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "should have 2 keys after add");
}

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

    // 5. Add a key
    let add_result = cli.run_json(&["key", "add", &identity_arg, &signer_arg]);
    let second_key = add_result["added_key"].as_str().unwrap();
    let key_arg = format!("--key={second_key}");

    // 6. List keys - should have 2
    let key_list = cli.run_json(&["key", "list", &identity_arg]);
    assert_eq!(key_list["active_keys"].as_array().unwrap().len(), 2);

    // 7. Check tx list after coz (mutation + commit/create per commit)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);
    assert_eq!(tx_list["transaction_count"], 2);

    // 8. Check inspect after coz
    let inspect = cli.run_json(&["inspect", &identity_arg]);
    assert_eq!(inspect["commit_count"], 1);
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

    // 12. Check tx list shows 4 cozies (2 commits × 2 each: mutation + commit/create)
    let tx_list = cli.run_json(&["tx", "list", &identity_arg]);
    assert_eq!(tx_list["transaction_count"], 4);
}

#[test]
fn test_tx_verify_genesis() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={genesis_tmb}");

    // Verify genesis state (no cozies yet)
    let verify = cli.run_json(&["tx", "verify", &identity_arg]);

    assert_eq!(verify["status"], "OK");
    assert_eq!(verify["commits_verified"], 0);
    assert_eq!(verify["transactions_verified"], 0);
}

#[test]
fn test_tx_verify_after_transactions() {
    let cli = CliTest::new();

    // Generate key
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();
    let identity_arg = format!("--identity={genesis_tmb}");
    let signer_arg = format!("--signer={genesis_tmb}");

    // Add a key (creates first coz)
    cli.run_ok(&["key", "add", &identity_arg, &signer_arg]);

    // Verify coz chain - THIS IS THE CRITICAL TEST
    // If PS Mismatch bug exists, this will fail
    let verify = cli.run_json(&["tx", "verify", &identity_arg]);

    assert_eq!(verify["status"], "OK", "tx verify should succeed");
    assert_eq!(verify["commits_verified"], 1);
    assert_eq!(verify["transactions_verified"], 2);
}
