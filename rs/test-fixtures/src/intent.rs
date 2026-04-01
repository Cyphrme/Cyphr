//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.
//!
//! ## Canonical Format
//!
//! Transactions use `[[test.commit]]` + `[[test.commit.cz]]`.
//! Actions use `[[test.action]]`.
//! See `.sketches/2026-02-18-fixture-format-alignment.md` for design rationale.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestIntent {
    /// Test name.
    pub name: String,
    /// Genesis key set (key names from pool).
    pub principal: Vec<String>,
    /// Setup modifiers (e.g., pre-revoke keys).
    #[serde(default)]
    pub setup: Option<SetupIntent>,
    /// Commit sequence. Each commit contains one or more cozies.
    #[serde(default)]
    pub commit: Vec<CommitIntent>,
    /// Action sequence (Level 4 data recording).
    #[serde(default)]
    pub action: Vec<ActionIntent>,
    /// Override fields (for error tests).
    #[serde(default, rename = "override")]
    pub override_: Option<OverrideIntent>,
    /// Expected assertions.
    #[serde(default)]
    pub expected: Option<ExpectedAssertions>,
}

/// A single commit containing one or more cozies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIntent {
    /// Transactions within this commit.
    #[serde(default)]
    pub cz: Vec<TxIntent>,
}

/// A single coz within a commit.
///
/// Flat struct merging the old `PayIntent` + `CryptoIntent` fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIntent {
    /// ParsedCoz type (e.g., "cyphr.me/key/create").
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
    /// Expected key root digest.
    #[serde(default)]
    pub kr: Option<String>,
    /// Expected auth root digest.
    #[serde(rename = "ar", default)]
    pub auth_root: Option<String>,
    /// Expected state root digest.
    #[serde(rename = "sr", default)]
    pub sr: Option<String>,
    /// Expected principal root digest.
    #[serde(default)]
    pub pr: Option<String>,
    /// Expected commit ID digest.
    #[serde(default)]
    pub tr: Option<String>,
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
    /// Returns true if this test has commits (state-mutating cozies).
    pub fn has_commits(&self) -> bool {
        !self.commit.is_empty()
    }

    /// Returns true if this test has actions (Level 4 data recording).
    pub fn has_action(&self) -> bool {
        !self.action.is_empty()
    }

    /// Returns true if this is a genesis-only test (no commits or actions).
    pub fn is_genesis_only(&self) -> bool {
        self.commit.is_empty() && self.action.is_empty()
    }

    /// Returns true if this test has both commits and actions.
    pub fn has_tx_and_action(&self) -> bool {
        !self.commit.is_empty() && !self.action.is_empty()
    }

    /// Returns true if this test expects an error.
    pub fn is_error_test(&self) -> bool {
        self.expected.as_ref().is_some_and(|e| e.error.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE_COMMIT_INTENT: &str = r#"
[[test]]
name = "key_add_increases_count"
principal = ["golden"]

[[test.commit]]
[[test.commit.cz]]
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
[[test.commit.cz]]
typ = "cyphr.me/key/create"
now = 1700000001
signer = "golden"
target = "key_a"

[[test.commit]]
[[test.commit.cz]]
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

[[test.action]]
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

[[test.action]]
typ = "cyphr.me/action"
now = 1700000001
signer = "golden"
msg = "First"

[[test.action]]
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
        assert_eq!(test.commit.len(), 1);
        assert_eq!(test.commit[0].cz.len(), 1);
        let cz = &test.commit[0].cz[0];
        assert_eq!(cz.typ, "cyphr.me/key/create");
        assert_eq!(cz.now, 1700000000);
        assert_eq!(cz.signer, "golden");
        assert_eq!(cz.target.as_deref(), Some("key_a"));
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
        assert_eq!(test.commit[0].cz[0].now, 1700000001);
        assert_eq!(test.commit[0].cz[0].target.as_deref(), Some("key_a"));
        assert_eq!(test.commit[1].cz[0].now, 1700000002);
        assert_eq!(test.commit[1].cz[0].target.as_deref(), Some("key_b"));
        let expected = test.expected.as_ref().expect("missing expected");
        assert_eq!(expected.key_count, Some(3));
    }

    #[test]
    fn test_parse_action() {
        let intent = Intent::from_str(ACTION_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.has_action());
        assert_eq!(test.action.len(), 1);
        assert_eq!(test.action[0].typ, "cyphr.me/action");
        assert_eq!(test.action[0].msg.as_deref(), Some("Only action"));
    }

    #[test]
    fn test_parse_multi_action() {
        let intent = Intent::from_str(MULTI_ACTION_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.has_action());
        assert_eq!(test.action.len(), 2);
        assert_eq!(test.action[0].msg.as_deref(), Some("First"));
        assert_eq!(test.action[1].msg.as_deref(), Some("Second"));
    }

    #[test]
    fn test_parse_genesis_only() {
        let intent = Intent::from_str(GENESIS_ONLY_INTENT).expect("failed to parse");
        let test = &intent.test[0];
        assert!(test.is_genesis_only());
        assert!(!test.has_commits());
        assert!(!test.has_action());
    }

    #[test]
    fn test_expected_has_sr_field() {
        let toml_str = r#"
[[test]]
name = "with_sr"
principal = ["golden"]

[test.expected]
sr = "SHA-256:abc123"
"#;
        let intent = Intent::from_str(toml_str).expect("failed to parse");
        let expected = intent.test[0].expected.as_ref().unwrap();
        assert_eq!(expected.sr.as_deref(), Some("SHA-256:abc123"));
    }
}
