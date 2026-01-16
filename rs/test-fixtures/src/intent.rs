//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.

use serde::{Deserialize, Serialize};

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
    /// Payload intent (for single-step tests).
    #[serde(default)]
    pub pay: Option<PayIntent>,
    /// Crypto intent (for single-step tests).
    #[serde(default)]
    pub crypto: Option<CryptoIntent>,
    /// Steps (for multi-step tests).
    #[serde(default)]
    pub step: Vec<StepIntent>,
    /// Expected assertions.
    #[serde(default)]
    pub expected: Option<ExpectedAssertions>,
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
