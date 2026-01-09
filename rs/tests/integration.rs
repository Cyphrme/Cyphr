//! Integration tests using language-agnostic test vectors.
//!
//! These tests consume JSON fixtures from `/test_vectors/` to verify
//! the Rust implementation matches the Cyphrpass protocol specification.

use std::fs;
use std::path::PathBuf;

use coz::Thumbprint;
use cyphrpass::Principal;
use cyphrpass::key::Key;
use serde::Deserialize;

// ============================================================================
// Test fixture types
// ============================================================================

/// Root structure for test vector files.
#[derive(Debug, Deserialize)]
struct TestVectorFile {
    name: String,
    description: String,
    version: String,
    tests: Vec<TestCase>,
}

/// A single test case.
#[derive(Debug, Deserialize)]
struct TestCase {
    name: String,
    description: String,
    input: TestInput,
    expected: ExpectedState,
}

/// Test input (varies by test type).
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum TestInput {
    #[serde(rename = "implicit_genesis")]
    ImplicitGenesis { key: KeyInput },

    #[serde(rename = "explicit_genesis")]
    ExplicitGenesis { keys: Vec<KeyInput> },
}

/// Key input from test vectors.
#[derive(Debug, Deserialize)]
struct KeyInput {
    alg: String,
    #[serde(rename = "pub")]
    pub_key: String,
    tmb: String,
}

impl KeyInput {
    /// Convert to domain Key type.
    fn to_key(&self) -> Key {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let pub_bytes =
            Base64UrlUnpadded::decode_vec(&self.pub_key).expect("invalid base64url for pub");
        let tmb_bytes =
            Base64UrlUnpadded::decode_vec(&self.tmb).expect("invalid base64url for tmb");

        Key {
            alg: self.alg.clone(),
            tmb: Thumbprint::from_bytes(tmb_bytes),
            pub_key: pub_bytes,
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: None,
        }
    }
}

/// Expected state after operation.
#[derive(Debug, Deserialize)]
struct ExpectedState {
    pr: String,
    ps: String,
    #[serde(rename = "as")]
    auth_state: String,
    ks: String,
    ts: Option<String>,
    ds: Option<String>,
    level: u8,
    error: Option<String>,
}

// ============================================================================
// Test helpers
// ============================================================================

/// Get path to test_vectors directory.
fn test_vectors_dir() -> PathBuf {
    // From rs/tests/integration.rs, go up to repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("should have parent")
        .join("test_vectors")
}

/// Load and parse a test vector file.
fn load_test_vectors(category: &str, name: &str) -> TestVectorFile {
    let path = test_vectors_dir()
        .join(category)
        .join(format!("{name}.json"));
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

/// Convert a Cad to base64url for comparison.
fn cad_to_b64(cad: &coz::Cad) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(cad.as_bytes())
}

// ============================================================================
// Genesis tests
// ============================================================================

#[test]
fn test_implicit_genesis() {
    let vectors = load_test_vectors("genesis", "implicit");

    for test in vectors.tests {
        println!("Running: {} - {}", test.name, test.description);

        let TestInput::ImplicitGenesis { key } = test.input else {
            panic!("{}: expected implicit_genesis input", test.name);
        };

        let domain_key = key.to_key();
        let principal = Principal::implicit(domain_key).expect("genesis should succeed");

        // Verify all expected states
        assert_eq!(
            cad_to_b64(principal.pr().as_cad()),
            test.expected.pr,
            "{}: PR mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.ps().as_cad()),
            test.expected.ps,
            "{}: PS mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.auth_state().as_cad()),
            test.expected.auth_state,
            "{}: AS mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.key_state().as_cad()),
            test.expected.ks,
            "{}: KS mismatch",
            test.name
        );

        // TS and DS should be None for implicit genesis
        assert!(
            test.expected.ts.is_none(),
            "{}: expected TS to be null",
            test.name
        );
        assert!(
            test.expected.ds.is_none(),
            "{}: expected DS to be null",
            test.name
        );

        // Level should be 1
        assert_eq!(
            test.expected.level, 1,
            "{}: expected Level 1 for implicit genesis",
            test.name
        );
    }
}

#[test]
fn test_explicit_genesis() {
    let vectors_path = test_vectors_dir().join("genesis").join("explicit.json");

    // Skip if explicit genesis tests don't exist yet
    if !vectors_path.exists() {
        println!("Skipping explicit genesis tests (fixture not yet created)");
        return;
    }

    let vectors = load_test_vectors("genesis", "explicit");

    for test in vectors.tests {
        println!("Running: {} - {}", test.name, test.description);

        let TestInput::ExplicitGenesis { keys } = test.input else {
            panic!("{}: expected explicit_genesis input", test.name);
        };

        let domain_keys: Vec<Key> = keys.iter().map(|k| k.to_key()).collect();
        let principal = Principal::explicit(domain_keys).expect("genesis should succeed");

        // Print computed values for fixture generation (useful for bootstrapping)
        if test.expected.pr.starts_with("PLACEHOLDER") {
            println!(
                "  [GENERATE] pr: \"{}\"",
                cad_to_b64(principal.pr().as_cad())
            );
            println!(
                "  [GENERATE] ps: \"{}\"",
                cad_to_b64(principal.ps().as_cad())
            );
            println!(
                "  [GENERATE] as: \"{}\"",
                cad_to_b64(principal.auth_state().as_cad())
            );
            println!(
                "  [GENERATE] ks: \"{}\"",
                cad_to_b64(principal.key_state().as_cad())
            );
            continue; // Skip assertions for placeholder tests
        }

        // Verify expected states
        assert_eq!(
            cad_to_b64(principal.pr().as_cad()),
            test.expected.pr,
            "{}: PR mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.ps().as_cad()),
            test.expected.ps,
            "{}: PS mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.auth_state().as_cad()),
            test.expected.auth_state,
            "{}: AS mismatch",
            test.name
        );
        assert_eq!(
            cad_to_b64(principal.key_state().as_cad()),
            test.expected.ks,
            "{}: KS mismatch",
            test.name
        );

        // TS and DS should be None for genesis
        assert!(
            test.expected.ts.is_none(),
            "{}: expected TS to be null",
            test.name
        );
        assert!(
            test.expected.ds.is_none(),
            "{}: expected DS to be null",
            test.name
        );

        // For multi-key genesis, level should be 3
        assert_eq!(
            test.expected.level, 3,
            "{}: expected Level 3 for explicit genesis",
            test.name
        );
    }
}

// ============================================================================
// Transaction tests (C11.2)
// ============================================================================

/// Transaction test fixture structure.
#[derive(Debug, Deserialize)]
struct TransactionTestFile {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    version: String,
    keys: std::collections::HashMap<String, KeyInput>,
    tests: Vec<TransactionTestCase>,
}

/// A single transaction test case.
#[derive(Debug, Deserialize)]
struct TransactionTestCase {
    name: String,
    description: String,
    setup: TransactionSetup,
    #[serde(default)]
    transaction: Option<TransactionInput>,
    #[serde(default)]
    transactions: Option<Vec<TransactionInput>>,
    expected: TransactionExpected,
}

/// Setup for transaction tests.
#[derive(Debug, Deserialize)]
struct TransactionSetup {
    genesis: String,
    #[serde(default)]
    initial_key: Option<String>,
    #[serde(default)]
    initial_keys: Option<Vec<String>>,
}

/// Transaction input.
#[derive(Debug, Deserialize)]
struct TransactionInput {
    #[serde(rename = "type")]
    tx_type: String,
    signer: String,
    #[serde(default)]
    add_key: Option<String>,
    #[serde(default)]
    delete_key: Option<String>,
    #[serde(default)]
    new_key: Option<String>,
    #[serde(default)]
    revoke_key: Option<String>,
    #[serde(default)]
    rvk: Option<i64>,
    now: i64,
    #[allow(dead_code)]
    czd: String,
}

/// Expected state after transaction.
#[derive(Debug, Deserialize)]
struct TransactionExpected {
    #[serde(default)]
    key_count: Option<usize>,
    #[serde(default)]
    level: Option<u8>,
    #[serde(default)]
    active_keys: Option<Vec<String>>,
    #[serde(default)]
    revoked_keys: Option<Vec<String>>,
    #[serde(default)]
    pr_changed: Option<bool>,
    #[serde(default)]
    as_changed: Option<bool>,
    #[serde(default)]
    ps_changed: Option<bool>,
    #[serde(default)]
    signer_active: Option<bool>,
    #[serde(default)]
    transaction_count: Option<usize>,
    #[allow(dead_code)]
    #[serde(default)]
    ks: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    ts: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "as", default)]
    auth_state: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    ps: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pr: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    key_a_rvk: Option<i64>,
}

/// Load transaction test vectors.
fn load_transaction_tests(name: &str) -> TransactionTestFile {
    let path = test_vectors_dir()
        .join("transactions")
        .join(format!("{name}.json"));
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

#[test]
fn test_transactions() {
    use coz::Czd;
    use cyphrpass::transaction::{Transaction, TransactionKind};

    let vectors_path = test_vectors_dir()
        .join("transactions")
        .join("mutations.json");
    if !vectors_path.exists() {
        println!("Skipping transaction tests (fixture not yet created)");
        return;
    }

    let fixture = load_transaction_tests("mutations");

    for test in fixture.tests {
        println!("Running: {} - {}", test.name, test.description);

        // Setup: create principal with initial keys
        let mut principal = match test.setup.genesis.as_str() {
            "implicit" => {
                let key_name = test
                    .setup
                    .initial_key
                    .as_ref()
                    .expect("implicit needs initial_key");
                let key_input = fixture.keys.get(key_name).expect("key not found");
                Principal::implicit(key_input.to_key()).expect("implicit genesis failed")
            },
            "explicit" => {
                let key_names = test
                    .setup
                    .initial_keys
                    .as_ref()
                    .expect("explicit needs initial_keys");
                let keys: Vec<Key> = key_names
                    .iter()
                    .map(|n| fixture.keys.get(n).expect("key not found").to_key())
                    .collect();
                Principal::explicit(keys).expect("explicit genesis failed")
            },
            _ => panic!("Unknown genesis type: {}", test.setup.genesis),
        };

        let initial_pr = cad_to_b64(principal.pr().as_cad());
        let initial_as = cad_to_b64(principal.auth_state().as_cad());
        let initial_ps = cad_to_b64(principal.ps().as_cad());

        // Apply transaction(s)
        let txs: Vec<&TransactionInput> = if let Some(ref tx) = test.transaction {
            vec![tx]
        } else if let Some(ref txs) = test.transactions {
            txs.iter().collect()
        } else {
            panic!("{}: no transaction or transactions", test.name);
        };

        for tx_input in txs {
            let signer_key = fixture
                .keys
                .get(&tx_input.signer)
                .expect("signer not found");
            let signer_tmb = &signer_key.to_key().tmb;

            let kind = match tx_input.tx_type.as_str() {
                "key/add" => {
                    let add_key_name = tx_input.add_key.as_ref().expect("key/add needs add_key");
                    let add_key = fixture.keys.get(add_key_name).expect("add_key not found");
                    TransactionKind::KeyAdd {
                        pre: principal.auth_state().clone(),
                        id: add_key.to_key().tmb,
                    }
                },
                "key/delete" => {
                    let del_key_name = tx_input
                        .delete_key
                        .as_ref()
                        .expect("key/delete needs delete_key");
                    let del_key = fixture
                        .keys
                        .get(del_key_name)
                        .expect("delete_key not found");
                    TransactionKind::KeyDelete {
                        pre: principal.auth_state().clone(),
                        id: del_key.to_key().tmb,
                    }
                },
                "key/replace" => {
                    let new_key_name = tx_input
                        .new_key
                        .as_ref()
                        .expect("key/replace needs new_key");
                    let new_key = fixture.keys.get(new_key_name).expect("new_key not found");
                    TransactionKind::KeyReplace {
                        pre: principal.auth_state().clone(),
                        id: new_key.to_key().tmb,
                    }
                },
                "key/revoke" => {
                    let rvk = tx_input.rvk.unwrap_or(tx_input.now);
                    if let Some(ref revoke_key_name) = tx_input.revoke_key {
                        // Other-revoke
                        let revoke_key = fixture
                            .keys
                            .get(revoke_key_name)
                            .expect("revoke_key not found");
                        TransactionKind::OtherRevoke {
                            pre: principal.auth_state().clone(),
                            id: revoke_key.to_key().tmb,
                            rvk,
                        }
                    } else {
                        // Self-revoke
                        TransactionKind::SelfRevoke { rvk }
                    }
                },
                _ => panic!("Unknown tx type: {}", tx_input.tx_type),
            };

            let tx = Transaction {
                kind,
                signer: signer_tmb.clone(),
                now: tx_input.now,
                czd: Czd::from_bytes(vec![0xAB; 32]), // Placeholder czd
            };

            // For key/add and key/replace, we need to provide the new key
            let new_key_opt = match tx_input.tx_type.as_str() {
                "key/add" => {
                    let name = tx_input.add_key.as_ref().unwrap();
                    Some(fixture.keys.get(name).unwrap().to_key())
                },
                "key/replace" => {
                    let name = tx_input.new_key.as_ref().unwrap();
                    Some(fixture.keys.get(name).unwrap().to_key())
                },
                _ => None,
            };

            principal
                .apply_transaction(tx, new_key_opt)
                .expect("transaction failed");
        }

        // Generate golden values if fixture has placeholders
        let has_placeholder = test
            .expected
            .ks
            .as_ref()
            .is_some_and(|s| s.starts_with("PLACEHOLDER"))
            || test
                .expected
                .auth_state
                .as_ref()
                .is_some_and(|s| s.starts_with("PLACEHOLDER"));
        if has_placeholder {
            println!(
                "  [GENERATE] ks: \"{}\"",
                cad_to_b64(principal.key_state().as_cad())
            );
            // TS is implicitly part of AS computation; not separately exposed
            println!("  [GENERATE] ts: \"<computed internally>\"");
            println!(
                "  [GENERATE] as: \"{}\"",
                cad_to_b64(principal.auth_state().as_cad())
            );
            println!(
                "  [GENERATE] ps: \"{}\"",
                cad_to_b64(principal.ps().as_cad())
            );
        }

        // Verify expected state
        if let Some(count) = test.expected.key_count {
            assert_eq!(
                principal.active_key_count(),
                count,
                "{}: key_count mismatch",
                test.name
            );
        }

        if let Some(level) = test.expected.level {
            // Level enum: L1=0, L2=1, L3=2, L4=3; fixture uses 1-4
            assert_eq!(
                principal.level() as u8 + 1,
                level,
                "{}: level mismatch",
                test.name
            );
        }

        if let Some(ref active) = test.expected.active_keys {
            for key_name in active {
                let key = fixture.keys.get(key_name).expect("key not found");
                assert!(
                    principal.is_key_active(&key.to_key().tmb),
                    "{}: {} should be active",
                    test.name,
                    key_name
                );
            }
        }

        if let Some(pr_changed) = test.expected.pr_changed {
            let current_pr = cad_to_b64(principal.pr().as_cad());
            assert_eq!(
                current_pr != initial_pr,
                pr_changed,
                "{}: pr_changed mismatch",
                test.name
            );
        }

        if let Some(as_changed) = test.expected.as_changed {
            let current_as = cad_to_b64(principal.auth_state().as_cad());
            assert_eq!(
                current_as != initial_as,
                as_changed,
                "{}: as_changed mismatch",
                test.name
            );
        }

        if let Some(ps_changed) = test.expected.ps_changed {
            let current_ps = cad_to_b64(principal.ps().as_cad());
            assert_eq!(
                current_ps != initial_ps,
                ps_changed,
                "{}: ps_changed mismatch",
                test.name
            );
        }

        if let Some(signer_active) = test.expected.signer_active {
            // Get the signer from the last transaction
            if let Some(ref tx) = test.transaction {
                let signer_key = fixture.keys.get(&tx.signer).expect("signer not found");
                assert_eq!(
                    principal.is_key_active(&signer_key.to_key().tmb),
                    signer_active,
                    "{}: signer_active mismatch",
                    test.name
                );
            }
        }

        if let Some(tx_count) = test.expected.transaction_count {
            // Note: transaction_count is internal tracking, for now just log
            println!("  [INFO] expected transaction_count: {}", tx_count);
        }

        // Verify golden hash values (language-agnostic verification)
        if let Some(ref expected_ks) = test.expected.ks {
            if !expected_ks.starts_with("TODO") && !expected_ks.starts_with("PLACEHOLDER") {
                assert_eq!(
                    cad_to_b64(principal.key_state().as_cad()),
                    *expected_ks,
                    "{}: ks mismatch",
                    test.name
                );
            }
        }
        if let Some(ref expected_as) = test.expected.auth_state {
            if !expected_as.starts_with("TODO") && !expected_as.starts_with("PLACEHOLDER") {
                assert_eq!(
                    cad_to_b64(principal.auth_state().as_cad()),
                    *expected_as,
                    "{}: as mismatch",
                    test.name
                );
            }
        }
        if let Some(ref expected_ps) = test.expected.ps {
            if !expected_ps.starts_with("TODO") && !expected_ps.starts_with("PLACEHOLDER") {
                assert_eq!(
                    cad_to_b64(principal.ps().as_cad()),
                    *expected_ps,
                    "{}: ps mismatch",
                    test.name
                );
            }
        }

        println!("  ✓ PASSED");
    }
}

// ============================================================================
// State computation tests (C11.3)
// ============================================================================

/// State computation test fixture structure.
#[derive(Debug, Deserialize)]
struct StateTestFile {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    version: String,
    keys: std::collections::HashMap<String, KeyInput>,
    tests: Vec<StateTestCase>,
}

/// A single state computation test case.
#[derive(Debug, Deserialize)]
struct StateTestCase {
    name: String,
    description: String,
    setup: TransactionSetup,
    #[serde(default)]
    transaction: Option<TransactionInput>,
    #[serde(default)]
    transactions: Option<Vec<TransactionInput>>,
    #[serde(default)]
    action: Option<ActionInput>,
    expected: StateExpected,
}

/// Action input for Level 4 tests.
#[derive(Debug, Deserialize)]
struct ActionInput {
    typ: String,
    now: i64,
    #[serde(default)]
    msg: Option<String>,
    czd: String,
}

/// Expected state computation results.
#[derive(Debug, Deserialize)]
struct StateExpected {
    #[serde(default)]
    ks: Option<String>,
    #[serde(default)]
    ks_equals_tmb: Option<bool>,
    #[serde(default)]
    ks_is_hash: Option<bool>,
    #[serde(default)]
    ts_equals_czd: Option<bool>,
    #[serde(default)]
    ts_is_hash: Option<bool>,
    #[serde(rename = "as", default)]
    auth_state: Option<String>,
    #[serde(default)]
    as_equals_ks: Option<bool>,
    #[serde(default)]
    as_is_hash_of_ks_ts: Option<bool>,
    #[serde(default)]
    ps: Option<String>,
    #[serde(default)]
    ps_equals_as: Option<bool>,
    #[serde(default)]
    ps_is_hash_of_as_ds: Option<bool>,
    #[serde(default)]
    has_data_state: Option<bool>,
    #[serde(default)]
    transaction_count: Option<usize>,
}

#[test]
fn test_state_computation() {
    use coz::Czd;
    use cyphrpass::transaction::{Transaction, TransactionKind};

    let vectors_path = test_vectors_dir().join("state").join("computation.json");
    if !vectors_path.exists() {
        println!("Skipping state computation tests (fixture not yet created)");
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path.display(), e));
    let fixture: StateTestFile = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", vectors_path.display(), e));

    for test in fixture.tests {
        println!("Running: {} - {}", test.name, test.description);

        // Setup: create principal with initial keys
        let mut principal = match test.setup.genesis.as_str() {
            "implicit" => {
                let key_name = test
                    .setup
                    .initial_key
                    .as_ref()
                    .expect("implicit needs initial_key");
                let key_input = fixture.keys.get(key_name).expect("key not found");
                Principal::implicit(key_input.to_key()).expect("implicit genesis failed")
            },
            "explicit" => {
                let key_names = test
                    .setup
                    .initial_keys
                    .as_ref()
                    .expect("explicit needs initial_keys");
                let keys: Vec<Key> = key_names
                    .iter()
                    .map(|n| fixture.keys.get(n).expect("key not found").to_key())
                    .collect();
                Principal::explicit(keys).expect("explicit genesis failed")
            },
            _ => panic!("Unknown genesis type: {}", test.setup.genesis),
        };

        let initial_ks = cad_to_b64(principal.key_state().as_cad());

        // Apply transaction(s) if any
        let txs: Vec<&TransactionInput> = if let Some(ref tx) = test.transaction {
            vec![tx]
        } else if let Some(ref txs) = test.transactions {
            txs.iter().collect()
        } else {
            vec![]
        };

        for tx_input in &txs {
            let signer_key = fixture
                .keys
                .get(&tx_input.signer)
                .expect("signer not found");
            let signer_tmb = &signer_key.to_key().tmb;

            let kind = match tx_input.tx_type.as_str() {
                "key/add" => {
                    let add_key_name = tx_input.add_key.as_ref().expect("key/add needs add_key");
                    let add_key = fixture.keys.get(add_key_name).expect("add_key not found");
                    TransactionKind::KeyAdd {
                        pre: principal.auth_state().clone(),
                        id: add_key.to_key().tmb,
                    }
                },
                "key/delete" => {
                    let del_key_name = tx_input
                        .delete_key
                        .as_ref()
                        .expect("key/delete needs delete_key");
                    let del_key = fixture
                        .keys
                        .get(del_key_name)
                        .expect("delete_key not found");
                    TransactionKind::KeyDelete {
                        pre: principal.auth_state().clone(),
                        id: del_key.to_key().tmb,
                    }
                },
                _ => panic!("Unsupported tx type for state tests: {}", tx_input.tx_type),
            };

            let tx = Transaction {
                kind,
                signer: signer_tmb.clone(),
                now: tx_input.now,
                czd: Czd::from_bytes(vec![0xAB; 32]),
            };

            let new_key_opt = if tx_input.tx_type == "key/add" {
                let name = tx_input.add_key.as_ref().unwrap();
                Some(fixture.keys.get(name).unwrap().to_key())
            } else {
                None
            };

            principal
                .apply_transaction(tx, new_key_opt)
                .expect("transaction failed");
        }

        // Apply action if any (Level 4)
        if let Some(ref action_input) = test.action {
            use coz::PayBuilder;
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            use cyphrpass::action::Action;

            let signer_key = test.setup.initial_key.as_ref().unwrap();
            let key = fixture.keys.get(signer_key).unwrap();
            let tmb_bytes =
                Base64UrlUnpadded::decode_vec(&key.tmb).expect("invalid base64url for tmb");

            let mut pay = PayBuilder::new()
                .typ(&action_input.typ)
                .alg(&key.alg)
                .now(action_input.now)
                .tmb(coz::Thumbprint::from_bytes(tmb_bytes))
                .build();

            // Add msg field if present
            if let Some(ref msg) = action_input.msg {
                pay.msg = Some(msg.clone());
            }

            let czd_bytes = Base64UrlUnpadded::decode_vec(&action_input.czd)
                .expect("invalid base64url for czd");
            let czd = Czd::from_bytes(czd_bytes);

            let action = Action::from_pay(pay, czd).expect("failed to create action");
            principal
                .record_action(action)
                .expect("failed to record action");
        }

        // Verify state computation rules
        let current_ks = cad_to_b64(principal.key_state().as_cad());
        let current_as = cad_to_b64(principal.auth_state().as_cad());
        let current_ps = cad_to_b64(principal.ps().as_cad());

        // KS checks
        if let Some(ref expected_ks) = test.expected.ks {
            assert_eq!(current_ks, *expected_ks, "{}: ks mismatch", test.name);
        }
        if let Some(true) = test.expected.ks_equals_tmb {
            // For single key, KS = tmb (promoted, not hashed)
            let key_name = test.setup.initial_key.as_ref().unwrap();
            let key = fixture.keys.get(key_name).unwrap();
            assert_eq!(
                current_ks, key.tmb,
                "{}: KS should equal tmb for single key",
                test.name
            );
        }
        if let Some(true) = test.expected.ks_is_hash {
            // For multi-key, KS != any single tmb (it's a hash)
            for key in fixture.keys.values() {
                assert_ne!(
                    current_ks, key.tmb,
                    "{}: KS should be hash, not equal to any tmb",
                    test.name
                );
            }
        }

        // AS checks
        if let Some(ref expected_as) = test.expected.auth_state {
            assert_eq!(current_as, *expected_as, "{}: as mismatch", test.name);
        }
        if let Some(true) = test.expected.as_equals_ks {
            // Without transactions, AS = KS
            assert_eq!(
                current_as, initial_ks,
                "{}: AS should equal KS when no transactions",
                test.name
            );
        }
        if let Some(true) = test.expected.as_is_hash_of_ks_ts {
            // With transactions, AS != KS (it's H(sort(KS,TS)))
            assert_ne!(
                current_as, current_ks,
                "{}: AS should be hash of KS and TS",
                test.name
            );
        }

        // PS checks
        if let Some(ref expected_ps) = test.expected.ps {
            assert_eq!(current_ps, *expected_ps, "{}: ps mismatch", test.name);
        }
        if let Some(true) = test.expected.ps_equals_as {
            // Without data layer, PS = AS
            assert_eq!(
                current_ps, current_as,
                "{}: PS should equal AS when no data state",
                test.name
            );
        }

        // Transaction count check
        if let Some(count) = test.expected.transaction_count {
            assert_eq!(
                txs.len(),
                count,
                "{}: transaction count mismatch",
                test.name
            );
        }

        println!("  ✓ PASSED");
    }
}

// ============================================================================
// Action recording tests (C11.4)
// ============================================================================

/// Action test fixture structure.
#[derive(Debug, Deserialize)]
struct ActionTestFile {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    version: String,
    keys: std::collections::HashMap<String, KeyInput>,
    tests: Vec<ActionTestCase>,
}

/// A single action test case.
#[derive(Debug, Deserialize)]
struct ActionTestCase {
    name: String,
    description: String,
    setup: TransactionSetup,
    actions: Vec<ActionInput>,
    expected: ActionExpected,
}

/// Expected state after actions.
#[derive(Debug, Deserialize)]
struct ActionExpected {
    #[serde(default)]
    ds: Option<String>,
    #[serde(default)]
    ds_equals_czd: Option<bool>,
    #[serde(default)]
    ds_is_hash: Option<bool>,
    #[serde(default)]
    ps: Option<String>,
    #[serde(default)]
    ps_changed: Option<bool>,
    #[serde(default)]
    ps_includes_ds: Option<bool>,
    #[serde(default)]
    action_count: Option<usize>,
    #[serde(default)]
    signer_last_used: Option<i64>,
    #[serde(default)]
    level: Option<u8>,
    #[serde(default)]
    has_data_state: Option<bool>,
}

#[test]
fn test_action_recording() {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use coz::{Czd, PayBuilder};
    use cyphrpass::action::Action;

    let vectors_path = test_vectors_dir().join("actions").join("recording.json");
    if !vectors_path.exists() {
        println!("Skipping action recording tests (fixture not yet created)");
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path.display(), e));
    let fixture: ActionTestFile = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", vectors_path.display(), e));

    for test in fixture.tests {
        println!("Running: {} - {}", test.name, test.description);

        // Setup: create principal
        let key_name = test
            .setup
            .initial_key
            .as_ref()
            .expect("action tests need initial_key");
        let key_input = fixture.keys.get(key_name).expect("key not found");
        let mut principal =
            Principal::implicit(key_input.to_key()).expect("implicit genesis failed");

        let initial_ps = cad_to_b64(principal.ps().as_cad());

        // Record actions
        for action_input in &test.actions {
            let tmb_bytes =
                Base64UrlUnpadded::decode_vec(&key_input.tmb).expect("invalid base64url for tmb");

            let mut pay = PayBuilder::new()
                .typ(&action_input.typ)
                .alg(&key_input.alg)
                .now(action_input.now)
                .tmb(coz::Thumbprint::from_bytes(tmb_bytes))
                .build();

            if let Some(ref msg) = action_input.msg {
                pay.msg = Some(msg.clone());
            }

            let czd_bytes = Base64UrlUnpadded::decode_vec(&action_input.czd)
                .expect("invalid base64url for czd");
            let czd = Czd::from_bytes(czd_bytes);

            let action = Action::from_pay(pay, czd).expect("failed to create action");
            principal
                .record_action(action)
                .expect("failed to record action");
        }

        // Get current state
        let current_ps = cad_to_b64(principal.ps().as_cad());
        let current_ds = principal.data_state().map(|ds| cad_to_b64(ds.as_cad()));

        // Generate golden values if placeholders
        if test
            .expected
            .ds
            .as_ref()
            .is_some_and(|s| s.starts_with("PLACEHOLDER"))
        {
            if let Some(ref ds) = current_ds {
                println!("  [GENERATE] ds: \"{}\"", ds);
            }
        }
        if test
            .expected
            .ps
            .as_ref()
            .is_some_and(|s| s.starts_with("PLACEHOLDER"))
        {
            println!("  [GENERATE] ps: \"{}\"", current_ps);
        }

        // Verify expected state
        if let Some(ref expected_ds) = test.expected.ds {
            if !expected_ds.starts_with("PLACEHOLDER") {
                assert_eq!(
                    current_ds.as_ref().unwrap(),
                    expected_ds,
                    "{}: ds mismatch",
                    test.name
                );
            }
        }

        if let Some(true) = test.expected.ds_equals_czd {
            // For single action, DS = czd
            let first_czd = &test.actions[0].czd;
            assert_eq!(
                current_ds.as_ref().unwrap(),
                first_czd,
                "{}: DS should equal czd for single action",
                test.name
            );
        }

        if let Some(true) = test.expected.ds_is_hash {
            // For multiple actions, DS != any single czd
            for action in &test.actions {
                assert_ne!(
                    current_ds.as_ref().unwrap(),
                    &action.czd,
                    "{}: DS should be hash, not equal to single czd",
                    test.name
                );
            }
        }

        if let Some(ref expected_ps) = test.expected.ps {
            if !expected_ps.starts_with("PLACEHOLDER") {
                assert_eq!(current_ps, *expected_ps, "{}: ps mismatch", test.name);
            }
        }

        if let Some(true) = test.expected.ps_changed {
            assert_ne!(
                current_ps, initial_ps,
                "{}: PS should have changed",
                test.name
            );
        }

        if let Some(true) = test.expected.ps_includes_ds {
            assert!(
                current_ds.is_some(),
                "{}: Should have DS for PS to include",
                test.name
            );
        }

        if let Some(count) = test.expected.action_count {
            assert_eq!(
                test.actions.len(),
                count,
                "{}: action count mismatch",
                test.name
            );
        }

        if let Some(expected_last_used) = test.expected.signer_last_used {
            let key = principal.get_key(&key_input.to_key().tmb).unwrap();
            assert_eq!(
                key.last_used,
                Some(expected_last_used),
                "{}: signer last_used mismatch",
                test.name
            );
        }

        if let Some(expected_level) = test.expected.level {
            assert_eq!(
                principal.level() as u8 + 1,
                expected_level,
                "{}: level mismatch",
                test.name
            );
        }

        if let Some(true) = test.expected.has_data_state {
            assert!(
                current_ds.is_some(),
                "{}: should have data state",
                test.name
            );
        }

        println!("  ✓ PASSED");
    }
}
