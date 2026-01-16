//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.

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
    /// Payload intent (for single-step tests).
    #[serde(default)]
    pub pay: Option<PayIntent>,
    /// Crypto intent (for single-step tests).
    #[serde(default)]
    pub crypto: Option<CryptoIntent>,
    /// Steps (for multi-step transaction tests).
    #[serde(default)]
    pub step: Vec<StepIntent>,
    /// Single action (for single-action tests).
    #[serde(default)]
    pub action: Option<ActionIntent>,
    /// Action sequence (for multi-action tests).
    #[serde(default)]
    pub action_step: Vec<ActionIntent>,
    /// Override fields (for error tests).
    #[serde(default, rename = "override")]
    pub override_: Option<OverrideIntent>,
    /// Expected assertions.
    #[serde(default)]
    pub expected: Option<ExpectedAssertions>,
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

/// Payload fields for a test step.
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
}

/// Crypto fields for a test step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoIntent {
    /// Signer key name (from pool).
    pub signer: String,
    /// Target key name (for key/add, key/revoke).
    #[serde(default)]
    pub target: Option<String>,
}

/// A single step in a multi-step test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepIntent {
    /// Payload intent.
    pub pay: PayIntent,
    /// Crypto intent.
    pub crypto: CryptoIntent,
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
    /// Expected principal state digest.
    #[serde(default)]
    pub ps: Option<String>,
    /// Expected transaction state digest.
    #[serde(default)]
    pub ts: Option<String>,
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
    /// Returns true if this is a multi-step transaction test.
    pub fn is_multi_step(&self) -> bool {
        !self.step.is_empty()
    }

    /// Returns true if this test has actions.
    pub fn has_action(&self) -> bool {
        self.action.is_some() || !self.action_step.is_empty()
    }

    /// Returns true if this test has multi-step actions.
    pub fn is_multi_action(&self) -> bool {
        !self.action_step.is_empty()
    }

    /// Returns true if this is a genesis-only test (no transactions or actions).
    pub fn is_genesis_only(&self) -> bool {
        self.pay.is_none()
            && self.step.is_empty()
            && self.action.is_none()
            && self.action_step.is_empty()
    }

    /// Returns true if this test has both a transaction and an action.
    /// This is a combined test: first apply tx, then apply action.
    pub fn has_tx_and_action(&self) -> bool {
        self.pay.is_some() && self.action.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE_STEP_INTENT: &str = r#"
[[test]]
name = "key_add_increases_count"
principal = ["golden"]

[test.pay]
typ = "cyphr.me/key/add"
now = 1700000000

[test.crypto]
signer = "golden"
target = "key_a"

[test.expected]
key_count = 2
level = 3
"#;

    const MULTI_STEP_INTENT: &str = r#"
[[test]]
name = "transaction_sequence"
principal = ["golden"]

[[test.step]]
pay.typ = "cyphr.me/key/add"
pay.now = 1700000001
crypto.signer = "golden"
crypto.target = "key_a"

[[test.step]]
pay.typ = "cyphr.me/key/add"
pay.now = 1700000002
crypto.signer = "golden"
crypto.target = "key_b"

[test.expected]
key_count = 3
"#;

    #[test]
    fn test_parse_single_step_intent() {
        let intent = Intent::from_str(SINGLE_STEP_INTENT).expect("failed to parse");
        assert_eq!(intent.test.len(), 1);

        let test = &intent.test[0];
        assert_eq!(test.name, "key_add_increases_count");
        assert_eq!(test.principal, vec!["golden"]);
        assert!(!test.is_multi_step());

        let pay = test.pay.as_ref().expect("missing pay");
        assert_eq!(pay.typ, "cyphr.me/key/add");
        assert_eq!(pay.now, 1700000000);

        let crypto = test.crypto.as_ref().expect("missing crypto");
        assert_eq!(crypto.signer, "golden");
        assert_eq!(crypto.target.as_deref(), Some("key_a"));

        let expected = test.expected.as_ref().expect("missing expected");
        assert_eq!(expected.key_count, Some(2));
        assert_eq!(expected.level, Some(3));
    }

    #[test]
    fn test_parse_multi_step_intent() {
        let intent = Intent::from_str(MULTI_STEP_INTENT).expect("failed to parse");
        assert_eq!(intent.test.len(), 1);

        let test = &intent.test[0];
        assert_eq!(test.name, "transaction_sequence");
        assert!(test.is_multi_step());
        assert_eq!(test.step.len(), 2);

        let step1 = &test.step[0];
        assert_eq!(step1.pay.typ, "cyphr.me/key/add");
        assert_eq!(step1.pay.now, 1700000001);
        assert_eq!(step1.crypto.signer, "golden");
        assert_eq!(step1.crypto.target.as_deref(), Some("key_a"));

        let step2 = &test.step[1];
        assert_eq!(step2.pay.now, 1700000002);
        assert_eq!(step2.crypto.target.as_deref(), Some("key_b"));

        let expected = test.expected.as_ref().expect("missing expected");
        assert_eq!(expected.key_count, Some(3));
    }
}
