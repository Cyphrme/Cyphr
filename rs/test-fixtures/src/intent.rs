//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.
//!
//! ## Canonical Format (v2)
//!
//! Transactions use `[[test.commit.tx]]` — one syntax, no shortcuts.
//! Actions use `[[test.action]]` — unified, no singular/plural split.
//! See `.sketches/2026-02-18-fixture-format-alignment.md` for design rationale.
//!
//! ## Transition Bridge
//!
//! Legacy types (`PayIntent`, `CryptoIntent`, `StepIntent`) and legacy fields
//! (`pay`, `crypto`, `step`, `action`, `action_step`) are preserved so the
//! generator (`golden.rs`) compiles and old TOML files parse during migration.
//! These will be removed in Phase 4b when the generator is rewritten.

use std::{path::Path, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::Error;

/// A test intent file containing one or more test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// Test cases defined in this file.
    #[serde(default)]
    pub test: Vec<TestIntent>,
}

/// A single test case intent.
///
/// Supports both the new v2 format (`commit` + unified `action`) and the legacy
/// format (`pay`/`crypto`/`step` + `action`/`action_step`). Legacy fields will
/// be removed once all TOML files are migrated and the generator is rewritten.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestIntent {
    /// Test name.
    pub name: String,
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Setup modifiers (e.g., pre-revoke keys).
    #[serde(default)]
    pub setup: Option<SetupIntent>,

    // ── New canonical fields (v2) ──────────────────────────────────
    /// Commit sequence. Each commit contains one or more transactions.
    /// Used by new `[[test.commit.tx]]` format.
    #[serde(default)]
    pub commit: Vec<CommitIntent>,

    // ── Legacy fields (bridge for generator + old TOML parsing) ────
    /// Legacy: payload intent for single-step tests (`[test.pay]`).
    #[serde(default)]
    pub pay: Option<PayIntent>,
    /// Legacy: crypto intent for single-step tests (`[test.crypto]`).
    #[serde(default)]
    pub crypto: Option<CryptoIntent>,
    /// Legacy: steps for multi-step tests (`[[test.step]]`).
    #[serde(default)]
    pub step: Vec<StepIntent>,
    /// Single action for single-action tests (`[test.action]`).
    /// In v2, `[[test.action]]` parses as array of tables into `action_list`.
    #[serde(default)]
    pub action: Option<ActionIntent>,
    /// Action sequence for multi-action tests (`[[test.action_step]]`).
    /// In v2, replaced by `[[test.action]]` → `action_list`.
    #[serde(default)]
    pub action_step: Vec<ActionIntent>,

    /// Override fields (for error tests).
    #[serde(default, rename = "override")]
    pub override_: Option<OverrideIntent>,
    /// Expected assertions.
    #[serde(default)]
    pub expected: Option<ExpectedAssertions>,
}

// ── New canonical types (v2) ─────────────────────────────────────────

/// A single commit containing one or more transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIntent {
    /// Transactions within this commit.
    #[serde(default)]
    pub tx: Vec<TxIntent>,
}

/// A single transaction within a commit.
///
/// Merges the old `PayIntent` + `CryptoIntent` into one flat struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIntent {
    /// Transaction type (e.g., "cyphr.me/key/create").
    pub typ: String,
    /// Timestamp.
    pub now: i64,
    /// Signer key name (from pool).
    pub signer: String,
    /// Target key name (for key/create, key/revoke).
    #[serde(default)]
    pub target: Option<String>,
    /// Optional message.
    #[serde(default)]
    pub msg: Option<String>,
    /// Optional revocation timestamp.
    #[serde(default)]
    pub rvk: Option<i64>,
}

// ── Legacy types (bridge for generator) ──────────────────────────────

/// Legacy: payload fields for a test step.
///
/// Deprecated: use `TxIntent` instead. Kept for generator compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayIntent {
    /// Transaction/action type.
    pub typ: String,
    /// Timestamp.
    pub now: i64,
    /// Optional message.
    #[serde(default)]
    pub msg: Option<String>,
    /// Optional revocation timestamp.
    #[serde(default)]
    pub rvk: Option<i64>,
    /// Legacy commit flag (vestigial, always true). Remove in Phase 4b.
    #[serde(default)]
    pub commit: Option<bool>,
}

/// Legacy: crypto fields for a test step.
///
/// Deprecated: use `TxIntent` instead. Kept for generator compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIntent {
    /// Signer key name (from pool).
    pub signer: String,
    /// Target key name (for key/create, key/revoke).
    #[serde(default)]
    pub target: Option<String>,
}

/// Legacy: a single step in a multi-step test.
///
/// Deprecated: use `CommitIntent` + `TxIntent` instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepIntent {
    /// Payload intent.
    pub pay: PayIntent,
    /// Crypto intent.
    pub crypto: CryptoIntent,
}

// ── Types used by both old and new formats ───────────────────────────

/// Setup modifiers for test.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetupIntent {
    /// Key name to pre-revoke before test.
    #[serde(default)]
    pub revoke_key: Option<String>,
    /// Timestamp for the revocation.
    #[serde(default)]
    pub revoke_at: Option<i64>,
}

/// Override fields for error tests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OverrideIntent {
    /// Override `pre` field value (for InvalidPrior tests).
    #[serde(default)]
    pub pre: Option<String>,
    /// Override `tmb` field value (for UnknownKey tests).
    #[serde(default)]
    pub tmb: Option<String>,
}

/// An action intent (Level 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionIntent {
    /// Action type (e.g., "cyphr.me/action").
    pub typ: String,
    /// Timestamp.
    pub now: i64,
    /// Signer key name (from pool).
    pub signer: String,
    /// Optional message content.
    #[serde(default)]
    pub msg: Option<String>,
}

/// Expected assertions after test execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpectedAssertions {
    /// Expected key count.
    #[serde(default)]
    pub key_count: Option<usize>,
    /// Expected level.
    #[serde(default)]
    pub level: Option<u8>,
    /// Expected key state digest.
    #[serde(default)]
    pub ks: Option<String>,
    /// Expected auth state digest.
    #[serde(rename = "as", default)]
    pub auth_state: Option<String>,
    /// Expected commit state digest.
    #[serde(default)]
    pub cs: Option<String>,
    /// Expected principal state digest.
    #[serde(default)]
    pub ps: Option<String>,
    /// Expected commit ID digest.
    #[serde(default)]
    pub commit_id: Option<String>,
    /// Expected error (for error tests).
    #[serde(default)]
    pub error: Option<String>,
}

impl Intent {
    /// Load an intent file from TOML.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let content = std::fs::read_to_string(path).map_err(|e| Error::Read {
            path: path.display().to_string(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| Error::TomlParse {
            path: path.display().to_string(),
            source: e,
        })
    }
}

impl FromStr for Intent {
    type Err = toml::de::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s)
    }
}

impl TestIntent {
    // ── New canonical dispatch helpers (v2) ───────────────────────

    /// Returns true if this test has commits (state-mutating transactions).
    /// Checks both new `commit` field and legacy `pay`/`step` fields.
    pub fn has_commits(&self) -> bool {
        !self.commit.is_empty() || self.pay.is_some() || !self.step.is_empty()
    }

    /// Returns true if this test has actions (Level 4 data recording).
    /// Checks both new and legacy action fields.
    pub fn has_action(&self) -> bool {
        self.action.is_some() || !self.action_step.is_empty()
    }

    /// Returns true if this is a genesis-only test (no transactions or actions).
    pub fn is_genesis_only(&self) -> bool {
        self.commit.is_empty()
            && self.pay.is_none()
            && self.step.is_empty()
            && self.action.is_none()
            && self.action_step.is_empty()
    }

    /// Returns true if this test has both transactions and actions.
    pub fn has_tx_and_action(&self) -> bool {
        self.has_commits() && self.has_action()
    }

    /// Returns true if this test expects an error.
    pub fn is_error_test(&self) -> bool {
        self.expected.as_ref().map_or(false, |e| e.error.is_some())
    }

    // ── Legacy dispatch helpers (bridge for generator) ───────────

    /// Legacy: returns true if this is a multi-step transaction test.
    pub fn is_multi_step(&self) -> bool {
        !self.step.is_empty()
    }

    /// Legacy: returns true if this test has multi-step actions.
    pub fn is_multi_action(&self) -> bool {
        !self.action_step.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── New format (v2) tests ────────────────────────────────────

    const SINGLE_COMMIT_INTENT: &str = r#"
[[test]]
name = "key_add_increases_count"
principal = ["golden"]

[[test.commit]]
[[test.commit.tx]]
typ = "cyphr.me/key/create"
now = 1700000000
signer = "golden"
target = "key_a"

[test.expected]
key_count = 2
level = 3
"#;

    const MULTI_COMMIT_INTENT: &str = r#"
[[test]]
name = "transaction_sequence"
principal = ["golden"]

[[test.commit]]
[[test.commit.tx]]
typ = "cyphr.me/key/create"
now = 1700000001
signer = "golden"
target = "key_a"

[[test.commit]]
[[test.commit.tx]]
typ = "cyphr.me/key/create"
now = 1700000002
signer = "golden"
target = "key_b"

[test.expected]
key_count = 3
"#;

    const ACTION_INTENT: &str = r#"
[[test]]
name = "single_action"
principal = ["golden"]

[[test.action_step]]
typ = "cyphr.me/action"
now = 1700000001
signer = "golden"
msg = "Only action"

[test.expected]
level = 4
"#;

    const MULTI_ACTION_INTENT: &str = r#"
[[test]]
name = "multi_action"
principal = ["golden"]

[[test.action_step]]
typ = "cyphr.me/action"
now = 1700000001
signer = "golden"
msg = "First"

[[test.action_step]]
typ = "cyphr.me/action"
now = 1700000002
signer = "golden"
msg = "Second"

[test.expected]
level = 4
"#;

    const GENESIS_ONLY_INTENT: &str = r#"
[[test]]
name = "genesis_only"
principal = ["golden"]

[test.expected]
key_count = 1
level = 1
"#;

    #[test]
    fn test_parse_single_commit() {
        let intent = Intent::from_str(SINGLE_COMMIT_INTENT).expect("failed to parse");
        assert_eq!(intent.test.len(), 1);

        let test = &intent.test[0];
        assert_eq!(test.name, "key_add_increases_count");
        assert_eq!(test.principal, vec!["golden"]);
        assert!(test.has_commits());
        assert!(!test.is_genesis_only());

        // Single commit with one tx
        assert_eq!(test.commit.len(), 1);
        assert_eq!(test.commit[0].tx.len(), 1);

        let tx = &test.commit[0].tx[0];
        assert_eq!(tx.typ, "cyphr.me/key/create");
        assert_eq!(tx.now, 1700000000);
        assert_eq!(tx.signer, "golden");
        assert_eq!(tx.target.as_deref(), Some("key_a"));

        let expected = test.expected.as_ref().expect("missing expected");
        assert_eq!(expected.key_count, Some(2));
        assert_eq!(expected.level, Some(3));
    }

    #[test]
    fn test_parse_multi_commit() {
        let intent = Intent::from_str(MULTI_COMMIT_INTENT).expect("failed to parse");
        assert_eq!(intent.test.len(), 1);

        let test = &intent.test[0];
        assert!(test.has_commits());
        assert_eq!(test.commit.len(), 2);

        // First commit
        assert_eq!(test.commit[0].tx.len(), 1);
        assert_eq!(test.commit[0].tx[0].now, 1700000001);
        assert_eq!(test.commit[0].tx[0].target.as_deref(), Some("key_a"));

        // Second commit
        assert_eq!(test.commit[1].tx.len(), 1);
        assert_eq!(test.commit[1].tx[0].now, 1700000002);
        assert_eq!(test.commit[1].tx[0].target.as_deref(), Some("key_b"));

        let expected = test.expected.as_ref().expect("missing expected");
        assert_eq!(expected.key_count, Some(3));
    }

    #[test]
    fn test_parse_action() {
        let intent = Intent::from_str(ACTION_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.has_action());
        // Parsed through action_step (v2 uses [[test.action_step]] for now)
        assert_eq!(test.action_step.len(), 1);
        assert_eq!(test.action_step[0].typ, "cyphr.me/action");
        assert_eq!(test.action_step[0].msg.as_deref(), Some("Only action"));
    }

    #[test]
    fn test_parse_multi_action() {
        let intent = Intent::from_str(MULTI_ACTION_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.has_action());
        assert!(test.is_multi_action());
        assert_eq!(test.action_step.len(), 2);
        assert_eq!(test.action_step[0].msg.as_deref(), Some("First"));
        assert_eq!(test.action_step[1].msg.as_deref(), Some("Second"));
    }

    #[test]
    fn test_parse_genesis_only() {
        let intent = Intent::from_str(GENESIS_ONLY_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.is_genesis_only());
        assert!(!test.has_commits());
        assert!(!test.has_action());
    }

    // ── Legacy format compatibility tests ────────────────────────

    const LEGACY_SINGLE_STEP: &str = r#"
[[test]]
name = "legacy_single_step"
principal = ["golden"]

[test.pay]
typ = "cyphr.me/key/create"
now = 1700000000

[test.crypto]
signer = "golden"
target = "key_a"

[test.expected]
key_count = 2
"#;

    const LEGACY_MULTI_STEP: &str = r#"
[[test]]
name = "legacy_multi_step"
principal = ["golden"]

[[test.step]]
pay.typ = "cyphr.me/key/create"
pay.now = 1700000001
crypto.signer = "golden"
crypto.target = "key_a"

[[test.step]]
pay.typ = "cyphr.me/key/create"
pay.now = 1700000002
crypto.signer = "golden"
crypto.target = "key_b"

[test.expected]
key_count = 3
"#;

    const LEGACY_SINGLE_ACTION: &str = r#"
[[test]]
name = "legacy_single_action"
principal = ["golden"]

[test.action]
typ = "cyphr.me/action"
now = 1700000001
signer = "golden"
msg = "First action"

[test.expected]
level = 4
"#;

    #[test]
    fn test_parse_legacy_single_step() {
        let intent = Intent::from_str(LEGACY_SINGLE_STEP).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.pay.is_some());
        assert!(test.crypto.is_some());
        assert!(test.has_commits()); // pay.is_some() triggers this
        let pay = test.pay.as_ref().unwrap();
        assert_eq!(pay.typ, "cyphr.me/key/create");
        assert_eq!(pay.now, 1700000000);
    }

    #[test]
    fn test_parse_legacy_multi_step() {
        let intent = Intent::from_str(LEGACY_MULTI_STEP).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.is_multi_step());
        assert_eq!(test.step.len(), 2);
    }

    #[test]
    fn test_parse_legacy_single_action() {
        let intent = Intent::from_str(LEGACY_SINGLE_ACTION).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.has_action());
        assert!(test.action.is_some());
        assert_eq!(test.action.as_ref().unwrap().typ, "cyphr.me/action");
    }

    #[test]
    fn test_expected_has_cs_field() {
        let toml_str = r#"
[[test]]
name = "with_cs"
principal = ["golden"]

[test.expected]
cs = "SHA-256:abc123"
"#;
        let intent = Intent::from_str(toml_str).expect("failed to parse");
        let expected = intent.test[0].expected.as_ref().unwrap();
        assert_eq!(expected.cs.as_deref(), Some("SHA-256:abc123"));
    }
}
