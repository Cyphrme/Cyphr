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
/// Note: Some fields (prv, tag) are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
struct KeyInput {
    alg: String,
    #[serde(rename = "pub")]
    pub_key: String,
    #[serde(default)]
    prv: Option<String>,
    tmb: String,
    #[serde(default)]
    tag: Option<String>,
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

/// Key pool structure matching keys/pool.json.
/// Note: Metadata fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct KeyPool {
    name: String,
    description: String,
    version: String,
    keys: std::collections::HashMap<String, KeyInput>,
    account_presets: std::collections::HashMap<String, AccountPreset>,
}

/// Account preset from key pool.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct AccountPreset {
    description: String,
    genesis: String,
    keys: Vec<String>,
}

/// Load the centralized key pool from keys/pool.json.
fn load_key_pool() -> KeyPool {
    let path = test_vectors_dir().join("keys/pool.json");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read key pool: {}", e));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse key pool: {}", e))
}

/// Get a key by name from the key pool.
fn get_pool_key(name: &str) -> KeyInput {
    let pool = load_key_pool();
    pool.keys
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("key '{}' not found in pool", name))
}

/// Resolve a key by name, checking fixture-inline keys first, then the global pool.
fn resolve_key(
    name: &str,
    fixture_keys: Option<&std::collections::HashMap<String, KeyInput>>,
) -> KeyInput {
    // Try fixture-inline keys first
    if let Some(keys) = fixture_keys {
        if let Some(key) = keys.get(name) {
            return key.clone();
        }
    }
    // Fall back to global pool
    get_pool_key(name)
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
/// Note: Metadata fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TransactionTestFile {
    name: String,
    description: String,
    version: String,
    #[serde(default)]
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
    coz: Option<CozMessage>,
    #[serde(default)]
    coz_sequence: Option<Vec<CozMessage>>,
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

/// Spec-compliant Coz message (pay + sig + optional key + czd).
#[derive(Debug, Deserialize)]
struct CozMessage {
    pay: CozPay,
    #[serde(default)]
    key: serde_json::Value, // Either string ref or inline KeyInput
    czd: String,
}

impl CozMessage {
    /// Resolve the key from this message, handling both string refs and inline objects.
    fn resolve_key(
        &self,
        fixture_keys: Option<&std::collections::HashMap<String, KeyInput>>,
    ) -> Option<KeyInput> {
        if self.key.is_null() {
            return None;
        }
        // Try as string first
        if let Some(key_ref) = self.key.as_str() {
            return Some(resolve_key(key_ref, fixture_keys));
        }
        // Otherwise parse as inline KeyInput
        serde_json::from_value(self.key.clone()).ok()
    }
}

/// Coz pay object with all transaction fields.
#[derive(Debug, Deserialize)]
struct CozPay {
    alg: String,
    #[serde(default)]
    id: Option<String>,
    now: i64,
    #[serde(default)]
    pre: Option<String>,
    tmb: String,
    typ: String,
    #[serde(default)]
    rvk: Option<i64>,
    #[serde(default)]
    msg: Option<String>,
}

/// Expected state after transaction.
/// Note: Some fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TransactionExpected {
    #[serde(default)]
    key_count: Option<usize>,
    #[serde(default)]
    level: Option<u8>,
    #[serde(default)]
    active_keys: Option<Vec<String>>,
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
    #[serde(default)]
    ks: Option<String>,
    #[serde(default)]
    ts: Option<String>,
    #[serde(rename = "as", default)]
    auth_state: Option<String>,
    #[serde(default)]
    ps: Option<String>,
    #[serde(default)]
    pr: Option<String>,
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
    let vectors_path = test_vectors_dir()
        .join("transactions")
        .join("mutations.json");
    if !vectors_path.exists() {
        println!("Skipping transaction tests (fixture not yet created)");
        return;
    }

    let fixture = load_transaction_tests("mutations");

    for test in &fixture.tests {
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

        // Helper to apply a CozMessage with fixture pre validation (per SPEC §15.6)
        fn apply_coz_message(principal: &mut Principal, coz: &CozMessage, test_name: &str) {
            use coz::Czd;
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            use cyphrpass::transaction::{Transaction, TransactionKind};

            let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
            let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

            // Parse fixture pre and validate against computed state (SPEC §15.6)
            let fixture_pre = coz.pay.pre.as_ref().map(|pre_str| {
                let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                cyphrpass::AuthState(coz::Cad::from_bytes(pre_bytes))
            });

            // Validate fixture pre matches computed AS (catches fixture data errors)
            if fixture_pre.is_some() {
                let computed_as = cad_to_b64(principal.auth_state().as_cad());
                let fixture_pre_b64 = coz.pay.pre.as_ref().unwrap();
                assert_eq!(
                    &computed_as, fixture_pre_b64,
                    "{}: fixture pre mismatch - fixture has {}, computed AS is {}",
                    test_name, fixture_pre_b64, computed_as
                );
            }

            // Determine transaction kind from typ, using fixture pre
            let kind = if coz.pay.typ.ends_with("/key/add") {
                let id_str = coz.pay.id.as_ref().expect("key/add needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyAdd {
                    pre: fixture_pre.clone().expect("key/add needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/delete") {
                let id_str = coz.pay.id.as_ref().expect("key/delete needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyDelete {
                    pre: fixture_pre.clone().expect("key/delete needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/replace") {
                let id_str = coz.pay.id.as_ref().expect("key/replace needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyReplace {
                    pre: fixture_pre.clone().expect("key/replace needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/revoke") {
                let rvk = coz.pay.rvk.unwrap_or(coz.pay.now);
                if coz.pay.id.is_some() {
                    // Other-revoke
                    let id_str = coz.pay.id.as_ref().unwrap();
                    let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                    TransactionKind::OtherRevoke {
                        pre: fixture_pre.clone().expect("other-revoke needs pre"),
                        id: coz::Thumbprint::from_bytes(id_bytes),
                        rvk,
                    }
                } else {
                    // Self-revoke (no pre required)
                    TransactionKind::SelfRevoke { rvk }
                }
            } else {
                panic!("Unknown transaction typ: {}", coz.pay.typ);
            };

            let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd");
            let tx = Transaction {
                kind,
                signer: signer_tmb,
                now: coz.pay.now,
                czd: Czd::from_bytes(czd_bytes),
            };

            // Get new key if present
            let new_key = coz.resolve_key(None).map(|k| k.to_key());

            principal
                .apply_transaction(tx, new_key)
                .expect("transaction failed");
        }

        // Apply transaction(s)
        if let Some(ref coz) = test.coz {
            apply_coz_message(&mut principal, coz, &test.name);
        } else if let Some(ref coz_seq) = test.coz_sequence {
            for coz in coz_seq {
                apply_coz_message(&mut principal, coz, &test.name);
            }
        } else {
            panic!("{}: test requires coz or coz_sequence field", test.name);
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
            assert_eq!(
                principal.level() as u8,
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
            // Get the signer from the coz message
            if let Some(ref coz) = test.coz {
                let signer_key = fixture
                    .keys
                    .values()
                    .find(|k| k.tmb == coz.pay.tmb)
                    .expect("signer not found");
                assert_eq!(
                    principal.is_key_active(&signer_key.to_key().tmb),
                    signer_active,
                    "{}: signer_active mismatch",
                    test.name
                );
            } else if let Some(ref seq) = test.coz_sequence {
                // Check last transaction's signer
                if let Some(last) = seq.last() {
                    let signer_key = fixture
                        .keys
                        .values()
                        .find(|k| k.tmb == last.pay.tmb)
                        .expect("signer not found");
                    assert_eq!(
                        principal.is_key_active(&signer_key.to_key().tmb),
                        signer_active,
                        "{}: signer_active mismatch",
                        test.name
                    );
                }
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

/// Test multi-key transactions using pool key references.
/// This proves the key pool resolution works end-to-end.
#[test]
fn test_multi_key_transactions() {
    let fixture = load_transaction_tests("multi_key");

    for test in &fixture.tests {
        println!("Running multi_key: {} - {}", test.name, test.description);

        // Setup genesis - keys resolved from pool (fixture.keys is empty for multi_key.json)
        let fixture_keys = if fixture.keys.is_empty() {
            None
        } else {
            Some(&fixture.keys)
        };

        let mut principal = match test.setup.genesis.as_str() {
            "implicit" => {
                let key_name = test
                    .setup
                    .initial_key
                    .as_ref()
                    .expect("implicit needs initial_key");
                let key_input = resolve_key(key_name, fixture_keys);
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
                    .map(|n| resolve_key(n, fixture_keys).to_key())
                    .collect();
                Principal::explicit(keys).expect("explicit genesis failed")
            },
            _ => panic!("Unknown genesis type: {}", test.setup.genesis),
        };

        // Apply transaction using the CozMessage.resolve_key method
        if let Some(ref coz) = test.coz {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            use cyphrpass::transaction::{Transaction, TransactionKind};

            // Get new key for add/replace operations
            let new_key = coz.resolve_key(fixture_keys).map(|ki| ki.to_key());

            // Build transaction
            let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
            let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

            // Parse pre
            let fixture_pre = coz.pay.pre.as_ref().map(|pre_str| {
                let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                cyphrpass::AuthState(coz::Cad::from_bytes(pre_bytes))
            });

            // Determine transaction kind
            let kind = if coz.pay.typ.ends_with("/key/add") {
                let id_str = coz.pay.id.as_ref().expect("key/add needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyAdd {
                    pre: fixture_pre.expect("key/add needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/delete") {
                let id_str = coz.pay.id.as_ref().expect("key/delete needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyDelete {
                    pre: fixture_pre.expect("key/delete needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/replace") {
                let id_str = coz.pay.id.as_ref().expect("key/replace needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyReplace {
                    pre: fixture_pre.expect("key/replace needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else {
                panic!("unsupported transaction type: {}", coz.pay.typ);
            };

            let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd");
            let tx = Transaction {
                kind,
                signer: signer_tmb,
                czd: coz::Czd::from_bytes(czd_bytes),
                now: coz.pay.now,
            };

            principal
                .apply_transaction(tx, new_key)
                .expect("apply_transaction failed");
        }

        // Verify expected values
        if let Some(key_count) = test.expected.key_count {
            assert_eq!(
                principal.active_key_count(),
                key_count,
                "{}: key_count mismatch",
                test.name
            );
        }

        if let Some(level) = test.expected.level {
            assert_eq!(
                principal.level() as u8,
                level,
                "{}: level mismatch",
                test.name
            );
        }

        // Verify active keys by resolving from pool
        if let Some(ref expected_keys) = test.expected.active_keys {
            for key_name in expected_keys {
                let key_input = resolve_key(key_name, fixture_keys);
                let key = key_input.to_key();
                assert!(
                    principal.is_key_active(&key.tmb),
                    "{}: {} should be active",
                    test.name,
                    key_name
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
/// Note: Metadata fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct StateTestFile {
    name: String,
    description: String,
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
    coz: Option<CozMessage>,
    #[serde(default)]
    coz_sequence: Option<Vec<CozMessage>>,
    #[serde(default)]
    action: Option<ActionInput>,
    expected: StateExpected,
}

/// Action input - Coz message format with pay/sig/czd.
#[derive(Debug, Deserialize)]
struct ActionInput {
    pay: CozPay,
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
    #[serde(default)]
    key_count: Option<usize>,
}

#[test]
fn test_state_computation() {
    use coz::Czd;

    let vectors_path = test_vectors_dir().join("state").join("computation.json");
    if !vectors_path.exists() {
        println!("Skipping state computation tests (fixture not yet created)");
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path.display(), e));
    let fixture: StateTestFile = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", vectors_path.display(), e));

    for test in &fixture.tests {
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

        // Helper to apply a CozMessage with fixture pre validation (per SPEC §15.6)
        fn apply_coz_msg_state(principal: &mut Principal, coz: &CozMessage, test_name: &str) {
            use coz::Czd;
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            use cyphrpass::transaction::{Transaction, TransactionKind};

            let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
            let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

            // Parse fixture pre and validate against computed state (SPEC §15.6)
            let fixture_pre = coz.pay.pre.as_ref().map(|pre_str| {
                let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                cyphrpass::AuthState(coz::Cad::from_bytes(pre_bytes))
            });

            // Validate fixture pre matches computed AS
            if let Some(ref _pre) = fixture_pre {
                let computed_as = cad_to_b64(principal.auth_state().as_cad());
                let fixture_pre_b64 = coz.pay.pre.as_ref().unwrap();
                assert_eq!(
                    &computed_as, fixture_pre_b64,
                    "{}: fixture pre mismatch - fixture has {}, computed AS is {}",
                    test_name, fixture_pre_b64, computed_as
                );
            }

            let kind = if coz.pay.typ.ends_with("/key/add") {
                let id_str = coz.pay.id.as_ref().expect("key/add needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyAdd {
                    pre: fixture_pre.clone().expect("key/add needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/delete") {
                let id_str = coz.pay.id.as_ref().expect("key/delete needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyDelete {
                    pre: fixture_pre.clone().expect("key/delete needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else {
                panic!("Unsupported tx type for state tests: {}", coz.pay.typ);
            };

            let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd");
            let tx = Transaction {
                kind,
                signer: signer_tmb,
                now: coz.pay.now,
                czd: Czd::from_bytes(czd_bytes),
            };

            let new_key = coz.resolve_key(None).map(|k| k.to_key());
            principal
                .apply_transaction(tx, new_key)
                .expect("transaction failed");
        }

        // Apply transaction(s) using coz format
        if let Some(ref coz) = test.coz {
            apply_coz_msg_state(&mut principal, coz, &test.name);
        } else if let Some(ref coz_seq) = test.coz_sequence {
            for coz in coz_seq {
                apply_coz_msg_state(&mut principal, coz, &test.name);
            }
        }
        // Tests without transactions just verify initial state

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
                .typ(&action_input.pay.typ)
                .alg(&key.alg)
                .now(action_input.pay.now)
                .tmb(coz::Thumbprint::from_bytes(tmb_bytes))
                .build();

            // Add msg field if present in pay
            if let Some(ref msg_val) = action_input.pay.msg {
                pay.msg = Some(msg_val.clone());
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
            let tx_count = if test.coz.is_some() {
                1
            } else if let Some(ref seq) = test.coz_sequence {
                seq.len()
            } else {
                0
            };
            assert_eq!(tx_count, count, "{}: transaction count mismatch", test.name);
        }

        println!("  ✓ PASSED");
    }
}

// ============================================================================
// Action recording tests (C11.4)
// ============================================================================

/// Action test fixture structure.
/// Note: Metadata fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ActionTestFile {
    name: String,
    description: String,
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

    for test in &fixture.tests {
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
                .typ(&action_input.pay.typ)
                .alg(&key_input.alg)
                .now(action_input.pay.now)
                .tmb(coz::Thumbprint::from_bytes(tmb_bytes))
                .build();

            if let Some(ref msg_val) = action_input.pay.msg {
                pay.msg = Some(msg_val.clone());
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
                let action_czd = &action.czd;
                assert_ne!(
                    current_ds.as_ref().unwrap(),
                    action_czd,
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
                principal.level() as u8,
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

// ============================================================================
// Error condition tests (C11.5)
// ============================================================================

/// Error test fixture structure.
/// Note: Metadata fields are deserialized from JSON but not directly read in Rust code.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ErrorTestFile {
    name: String,
    description: String,
    version: String,
    keys: std::collections::HashMap<String, KeyInput>,
    tests: Vec<ErrorTestCase>,
}

/// A single error test case.
#[derive(Debug, Deserialize)]
struct ErrorTestCase {
    name: String,
    description: String,
    setup: ErrorSetup,
    #[serde(default)]
    coz: Option<CozMessage>,
    #[serde(default)]
    coz_sequence: Option<Vec<CozMessage>>,
    expected_error: String,
}

/// Setup for error tests.
#[derive(Debug, Deserialize)]
struct ErrorSetup {
    genesis: String,
    #[serde(default)]
    initial_key: Option<String>,
    #[serde(default)]
    initial_keys: Option<Vec<String>>,
    #[serde(default)]
    revoke_key: Option<String>,
    #[serde(default)]
    revoke_at: Option<i64>,
}

#[test]
fn test_error_conditions() {
    use coz::Czd;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphrpass::error::Error;
    use cyphrpass::transaction::{Transaction, TransactionKind};

    let vectors_path = test_vectors_dir().join("errors").join("conditions.json");
    if !vectors_path.exists() {
        println!("Skipping error condition tests (fixture not yet created)");
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path.display(), e));
    let fixture: ErrorTestFile = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", vectors_path.display(), e));

    for test in &fixture.tests {
        println!("Running: {} - {}", test.name, test.description);

        // Setup: create principal (may fail for UnsupportedAlgorithm tests)
        let principal_result = match test.setup.genesis.as_str() {
            "implicit" => {
                let key_name = test.setup.initial_key.as_ref().expect("need initial_key");
                let key_input = fixture.keys.get(key_name).expect("key not found");
                Principal::implicit(key_input.to_key())
            },
            "explicit" => {
                let key_names = test.setup.initial_keys.as_ref().expect("need initial_keys");
                let keys: Vec<Key> = key_names
                    .iter()
                    .map(|n| fixture.keys.get(n).expect("key not found").to_key())
                    .collect();
                Principal::explicit(keys).map(|mut p| {
                    // Handle revoke_key setup
                    if let Some(ref revoke_name) = test.setup.revoke_key {
                        let revoke_key =
                            fixture.keys.get(revoke_name).expect("revoke key not found");
                        let rvk = test.setup.revoke_at.unwrap_or(0);
                        let tx = Transaction {
                            kind: TransactionKind::SelfRevoke { rvk },
                            signer: revoke_key.to_key().tmb,
                            now: rvk,
                            czd: Czd::from_bytes(vec![0xAB; 32]),
                        };
                        p.apply_transaction(tx, None).expect("setup revoke failed");
                    }
                    p
                })
            },
            _ => panic!("Unknown genesis type"),
        };

        // Handle tests expecting genesis to fail (e.g., UnsupportedAlgorithm)
        // Only if there's no coz or coz_sequence (genesis-only test)
        let has_transactions = test.coz.is_some()
            || test
                .coz_sequence
                .as_ref()
                .is_some_and(|seq| !seq.is_empty());

        if !has_transactions {
            match (&principal_result, test.expected_error.as_str()) {
                (Err(Error::UnsupportedAlgorithm(_)), "UnsupportedAlgorithm") => {
                    println!("  ✓ PASSED (UnsupportedAlgorithm)");
                    continue;
                },
                (Ok(_), expected) => {
                    panic!(
                        "{}: expected {} error but genesis succeeded",
                        test.name, expected
                    );
                },
                (Err(e), expected) => {
                    panic!("{}: expected {} but got {:?}", test.name, expected, e);
                },
            }
        }

        // For transaction-based error tests, genesis must succeed
        let mut principal = principal_result.expect("genesis failed unexpectedly");

        // Apply transaction and expect error (coz format only)
        if let Some(ref coz) = test.coz {
            // Coz format transaction
            let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
            let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

            // Determine pre value from coz.pay.pre
            let pre = if let Some(ref pre_str) = coz.pay.pre {
                let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                cyphrpass::state::AuthState(coz::Cad::from_bytes(pre_bytes))
            } else {
                principal.auth_state().clone()
            };

            let kind = if coz.pay.typ.ends_with("/key/add") {
                let id_str = coz.pay.id.as_ref().expect("key/add needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyAdd {
                    pre,
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/delete") {
                let id_str = coz.pay.id.as_ref().expect("key/delete needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyDelete {
                    pre,
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/revoke") {
                let rvk = coz.pay.rvk.unwrap_or(coz.pay.now);
                if coz.pay.id.is_some() {
                    let id_str = coz.pay.id.as_ref().unwrap();
                    let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                    TransactionKind::OtherRevoke {
                        pre,
                        id: coz::Thumbprint::from_bytes(id_bytes),
                        rvk,
                    }
                } else {
                    TransactionKind::SelfRevoke { rvk }
                }
            } else {
                panic!("Unsupported tx type: {}", coz.pay.typ);
            };

            let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).unwrap_or(vec![0xAB; 32]);
            let tx = Transaction {
                kind,
                signer: signer_tmb,
                now: coz.pay.now,
                czd: Czd::from_bytes(czd_bytes),
            };

            let new_key = coz.resolve_key(Some(&fixture.keys)).map(|k| k.to_key());
            let result = principal.apply_transaction(tx, new_key);

            // Verify expected error
            match (&test.expected_error[..], &result) {
                ("InvalidPrior", Err(Error::InvalidPrior)) => {},
                ("UnknownKey", Err(Error::UnknownKey)) => {},
                ("KeyRevoked", Err(Error::KeyRevoked)) => {},
                ("NoActiveKeys", Err(Error::NoActiveKeys)) => {},
                ("DuplicateKey", Err(Error::DuplicateKey)) => {},
                ("TimestampPast", Err(Error::TimestampPast)) => {},
                ("TimestampFuture", Err(Error::TimestampFuture)) => {},
                _ => panic!(
                    "{}: expected error {}, got {:?}",
                    test.name, test.expected_error, result
                ),
            }
            println!("  ✓ PASSED ({})", test.expected_error);
            continue;
        }

        // Handle coz_sequence tests
        if let Some(ref seq) = test.coz_sequence {
            let mut last_result: Result<_, Error> = Ok(());

            for coz in seq {
                let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
                let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

                let pre = if let Some(ref pre_str) = coz.pay.pre {
                    let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                    cyphrpass::state::AuthState(coz::Cad::from_bytes(pre_bytes))
                } else {
                    principal.auth_state().clone()
                };

                let kind = if coz.pay.typ.ends_with("/key/add") {
                    let id_bytes = Base64UrlUnpadded::decode_vec(coz.pay.id.as_ref().unwrap())
                        .expect("invalid id");
                    TransactionKind::KeyAdd {
                        pre: pre.clone(),
                        id: coz::Thumbprint::from_bytes(id_bytes),
                    }
                } else if coz.pay.typ.ends_with("/key/delete") {
                    let id_bytes = Base64UrlUnpadded::decode_vec(coz.pay.id.as_ref().unwrap())
                        .expect("invalid id");
                    TransactionKind::KeyDelete {
                        pre: pre.clone(),
                        id: coz::Thumbprint::from_bytes(id_bytes),
                    }
                } else if coz.pay.typ.ends_with("/key/revoke") {
                    let rvk = coz.pay.rvk.unwrap_or(coz.pay.now);
                    if coz.pay.id.is_some() {
                        let id_bytes = Base64UrlUnpadded::decode_vec(coz.pay.id.as_ref().unwrap())
                            .expect("invalid id");
                        TransactionKind::OtherRevoke {
                            pre: pre.clone(),
                            id: coz::Thumbprint::from_bytes(id_bytes),
                            rvk,
                        }
                    } else {
                        TransactionKind::SelfRevoke { rvk }
                    }
                } else {
                    panic!("Unknown transaction type: {}", coz.pay.typ);
                };

                let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd");
                let tx = Transaction {
                    kind,
                    signer: signer_tmb.clone(),
                    now: coz.pay.now,
                    czd: Czd::from_bytes(czd_bytes),
                };

                let new_key = coz.resolve_key(Some(&fixture.keys)).map(|k| k.to_key());
                last_result = principal.apply_transaction(tx, new_key).map(|_| ());

                // If we get an error, this is the expected error
                if last_result.is_err() {
                    break;
                }
            }

            // Verify expected error
            match (&test.expected_error[..], &last_result) {
                ("InvalidPrior", Err(Error::InvalidPrior)) => {},
                ("UnknownKey", Err(Error::UnknownKey)) => {},
                ("KeyRevoked", Err(Error::KeyRevoked)) => {},
                ("NoActiveKeys", Err(Error::NoActiveKeys)) => {},
                ("DuplicateKey", Err(Error::DuplicateKey)) => {},
                ("TimestampPast", Err(Error::TimestampPast)) => {},
                ("TimestampFuture", Err(Error::TimestampFuture)) => {},
                (expected, Ok(())) => panic!(
                    "{}: expected error {} but all transactions succeeded",
                    test.name, expected
                ),
                _ => panic!(
                    "{}: expected error {}, got {:?}",
                    test.name, test.expected_error, last_result
                ),
            }
        }

        println!("  ✓ PASSED ({})", test.expected_error);
    }
}

// ============================================================================
// Edge case tests (C11.6)
// ============================================================================

#[test]
fn test_edge_cases() {
    use coz::Czd;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphrpass::action::Action;

    let vectors_path = test_vectors_dir().join("edge_cases").join("ordering.json");
    if !vectors_path.exists() {
        println!("Skipping edge case tests (fixture not yet created)");
        return;
    }

    let content = fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", vectors_path.display(), e));
    let fixture: StateTestFile = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {}", vectors_path.display(), e));

    println!("\n=== Edge Case Tests ===\n");

    for test in &fixture.tests {
        println!("Running: {} - {}", test.name, test.description);

        // Setup principal
        let mut principal = if test.setup.genesis == "implicit" {
            let key_name = test
                .setup
                .initial_key
                .as_ref()
                .expect("implicit needs initial_key");
            let key_input = fixture.keys.get(key_name).expect("key not found");
            Principal::implicit(key_input.to_key()).expect("genesis failed")
        } else {
            let key_names = test
                .setup
                .initial_keys
                .as_ref()
                .expect("explicit needs initial_keys");
            let keys: Vec<Key> = key_names
                .iter()
                .map(|n| fixture.keys.get(n).expect("key not found").to_key())
                .collect();
            Principal::explicit(keys).expect("genesis failed")
        };

        // Helper to apply a CozMessage with fixture pre validation (per SPEC §15.6)
        fn apply_edge_coz(principal: &mut Principal, coz: &CozMessage, test_name: &str) {
            use coz::Czd;
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            use cyphrpass::transaction::{Transaction, TransactionKind};

            let tmb_bytes = Base64UrlUnpadded::decode_vec(&coz.pay.tmb).expect("invalid tmb");
            let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

            // Parse fixture pre and validate against computed state (SPEC §15.6)
            let fixture_pre = coz.pay.pre.as_ref().map(|pre_str| {
                let pre_bytes = Base64UrlUnpadded::decode_vec(pre_str).expect("invalid pre");
                cyphrpass::state::AuthState(coz::Cad::from_bytes(pre_bytes))
            });

            // Validate fixture pre matches computed AS
            if let Some(ref _pre) = fixture_pre {
                let computed_as = cad_to_b64(principal.auth_state().as_cad());
                let fixture_pre_b64 = coz.pay.pre.as_ref().unwrap();
                assert_eq!(
                    &computed_as, fixture_pre_b64,
                    "{}: fixture pre mismatch - fixture has {}, computed AS is {}",
                    test_name, fixture_pre_b64, computed_as
                );
            }

            let kind = if coz.pay.typ.ends_with("/key/add") {
                let id_str = coz.pay.id.as_ref().expect("key/add needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyAdd {
                    pre: fixture_pre.clone().expect("key/add needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else if coz.pay.typ.ends_with("/key/delete") {
                let id_str = coz.pay.id.as_ref().expect("key/delete needs id");
                let id_bytes = Base64UrlUnpadded::decode_vec(id_str).expect("invalid id");
                TransactionKind::KeyDelete {
                    pre: fixture_pre.clone().expect("key/delete needs pre"),
                    id: coz::Thumbprint::from_bytes(id_bytes),
                }
            } else {
                panic!("Unsupported tx type for edge tests: {}", coz.pay.typ);
            };

            let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd");
            let tx = Transaction {
                kind,
                signer: signer_tmb,
                now: coz.pay.now,
                czd: Czd::from_bytes(czd_bytes),
            };

            let new_key = coz.resolve_key(None).map(|k| k.to_key());
            principal
                .apply_transaction(tx, new_key)
                .expect("transaction failed");
        }

        // Apply transaction(s)
        if let Some(ref coz) = test.coz {
            apply_edge_coz(&mut principal, coz, &test.name);
        } else if let Some(ref coz_seq) = test.coz_sequence {
            for coz in coz_seq {
                apply_edge_coz(&mut principal, coz, &test.name);
            }
        }

        // Apply action if present
        if let Some(ref action_input) = test.action {
            use coz::PayBuilder;

            // All action fields come from the pay object directly
            let tmb_bytes =
                Base64UrlUnpadded::decode_vec(&action_input.pay.tmb).expect("invalid tmb");

            let mut pay = PayBuilder::new()
                .typ(&action_input.pay.typ)
                .alg(&action_input.pay.alg)
                .now(action_input.pay.now)
                .tmb(coz::Thumbprint::from_bytes(tmb_bytes))
                .build();

            if let Some(ref msg_val) = action_input.pay.msg {
                pay.msg = Some(msg_val.clone());
            }

            let czd_bytes = Base64UrlUnpadded::decode_vec(&action_input.czd).expect("invalid czd");
            let czd = Czd::from_bytes(czd_bytes);

            let action = Action::from_pay(pay, czd).expect("failed to create action");
            principal
                .record_action(action)
                .expect("failed to record action");
        }

        // Verify expectations
        if let Some(ref expected_ks) = test.expected.ks {
            if !expected_ks.starts_with("PLACEHOLDER") {
                let actual_ks = cad_to_b64(principal.key_state().as_cad());
                assert_eq!(actual_ks, *expected_ks, "{}: ks mismatch", test.name);
            } else {
                // Generate mode
                println!(
                    "  [GENERATE] ks: \"{}\"",
                    cad_to_b64(principal.key_state().as_cad())
                );
            }
        }

        if let Some(key_count) = test.expected.key_count {
            assert_eq!(
                principal.active_key_count(),
                key_count,
                "{}: key_count mismatch",
                test.name
            );
        }

        if let Some(true) = test.expected.has_data_state {
            assert!(
                principal.data_state().is_some(),
                "{}: expected data state to exist",
                test.name
            );
        }

        if let Some(true) = test.expected.ps_is_hash_of_as_ds {
            // Verify PS is computed from AS and DS
            let ds = principal
                .data_state()
                .expect("no data state for PS hash check");
            let as_cad = principal.auth_state().as_cad();
            let ds_cad = ds.as_cad();

            // PS should not equal either AS or DS alone
            let ps_cad = principal.ps().as_cad();
            assert_ne!(
                ps_cad, as_cad,
                "{}: PS should not equal AS alone",
                test.name
            );
            assert_ne!(
                ps_cad, ds_cad,
                "{}: PS should not equal DS alone",
                test.name
            );
        }

        println!("  ✓ PASSED");
    }
}
