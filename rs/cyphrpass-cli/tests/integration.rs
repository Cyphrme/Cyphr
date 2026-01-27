//! Integration tests for cyphrpass CLI.
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
            .join("cyphrpass");

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

    // 2. Add a new key to identity (this creates the first transaction)
    let add_result = cli.run_json(&[
        "key",
        "add",
        "--identity",
        genesis_tmb,
        "--signer",
        genesis_tmb,
    ]);
    let new_key_tmb = add_result["added_key"].as_str().unwrap();

    // 3. List keys - should show both (field is "active_keys")
    let list_result = cli.run_json(&["key", "list", "--identity", genesis_tmb]);
    let keys = list_result["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "should have 2 active keys");

    // 4. Revoke the new key
    let _ = cli.run_ok(&[
        "key",
        "revoke",
        "--identity",
        genesis_tmb,
        "--key",
        new_key_tmb,
        "--signer",
        genesis_tmb,
    ]);

    // 5. List keys - should show only genesis
    let list_result = cli.run_json(&["key", "list", "--identity", genesis_tmb]);
    let keys = list_result["active_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "should have 1 active key after revoke");
    assert_eq!(keys[0]["tmb"], genesis_tmb);
}

#[test]
fn test_export_import_roundtrip() {
    let cli = CliTest::new();

    // 1. Generate key and create identity with transaction
    let genesis = cli.run_json(&["key", "generate", "--algo", "ES256"]);
    let genesis_tmb = genesis["tmb"].as_str().unwrap();

    let _ = cli.run_ok(&[
        "key",
        "add",
        "--identity",
        genesis_tmb,
        "--signer",
        genesis_tmb,
    ]);

    // 2. Export to file
    let export_path = cli.temp_dir.path().join("export.jsonl");
    let _ = cli.run_ok(&[
        "export",
        "--identity",
        genesis_tmb,
        "--output",
        export_path.to_str().unwrap(),
    ]);

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
    assert!(output.status.success(), "import should succeed");

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

    // List transactions (should be empty for genesis)
    let tx_list = cli.run_json(&["tx", "list", "--identity", genesis_tmb]);

    assert_eq!(tx_list["transaction_count"], 0);
}
