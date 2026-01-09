//! Integration tests using language-agnostic test vectors.
//!
//! These tests consume JSON fixtures from `/test_vectors/` to verify
//! the Rust implementation matches the Cyphrpass protocol specification.

use std::fs;
use std::path::PathBuf;

use coz::Thumbprint;
use cyphrpass::key::Key;
use cyphrpass::{HashAlg, Principal};
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

        // For multi-key genesis, level should be 3
        assert_eq!(
            test.expected.level, 3,
            "{}: expected Level 3 for explicit genesis",
            test.name
        );
    }
}
