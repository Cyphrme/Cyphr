//! Intent types and parsing.
//!
//! Intent files define test cases in human-editable TOML format.
//!
//! ## Canonical Format
//!
//! Transactions use `[[test.commit]]` + `[[test.commit.tx]]`.
//! Actions use `[[test.action]]`.
//! See `.sketches/2026-02-18-fixture-format-alignment.md` for design rationale.

use std::path::Path;
use std::str::FromStr;

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

/// A single commit containing transactions.
/// Each transaction is a list of cozies (list-of-lists per SPEC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitIntent {
    /// Transactions within this commit.
    /// Each transaction is a list of cozies.
    #[serde(default)]
    pub tx: Vec<Vec<TxIntent>>,
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
    /// Target key name (for key/create, key/revoke). `raw:<id>` instead
    /// states the pay `id` verbatim.
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
    /// Override `tmb` field value (for UnknownKey tests).
    #[serde(default)]
    pub tmb: Option<String>,
    /// Override timestamp (for TimestampPast tests).
    #[serde(default)]
    pub now: Option<i64>,
    /// Force-inject a `pre` field onto actions (for [data-action-no-pre] tests).
    #[serde(default)]
    pub inject_pre: Option<bool>,
    /// Bypass the empty commit validation to force an empty commit generation (for
    /// [commit-one-or-more] tests).
    #[serde(default)]
    pub empty_commit: Option<bool>,
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
    /// Optional payload ID (e.g. for witness/register/*).
    #[serde(default)]
    pub id: Option<String>,
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
    /// Expected `Principal::is_deleted()` (SPEC.md §11.1 `Deleted`).
    #[serde(default)]
    pub deleted: Option<bool>,
    /// Expected `Principal::is_frozen()` (SPEC.md §11.1 `Frozen`).
    #[serde(default)]
    pub frozen: Option<bool>,
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
