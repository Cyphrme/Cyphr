//! Golden output types and generation.
//!
//! Golden files contain real Coz messages with hardcoded cryptographic values.

use serde::{Deserialize, Serialize};

/// A golden test case with real cryptographic values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Golden {
    /// Test name.
    pub name: String,
    /// Coz message(s).
    #[serde(default)]
    pub coz: Option<GoldenCoz>,
    /// Coz message sequence (for multi-step tests).
    #[serde(default)]
    pub coz_sequence: Option<Vec<GoldenCoz>>,
    /// Expected state after execution.
    pub expected: GoldenExpected,
}

/// A Coz message with computed cryptographic values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenCoz {
    /// Pay object (preserved as raw JSON for bit-perfect signing).
    pub pay: serde_json::Value,
    /// Signature (base64url).
    pub sig: String,
    /// Coz digest (base64url).
    pub czd: String,
    /// Embedded key (for key/add transactions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<GoldenKey>,
}

/// A key embedded in a golden Coz message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenKey {
    /// Algorithm.
    pub alg: String,
    /// Public key (base64url).
    #[serde(rename = "pub")]
    pub pub_key: String,
    /// Thumbprint (base64url).
    pub tmb: String,
}

/// Expected state in golden output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoldenExpected {
    /// Expected key count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
    /// Expected level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    /// Expected key state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ks: Option<String>,
    /// Expected auth state digest.
    #[serde(rename = "as", default, skip_serializing_if = "Option::is_none")]
    pub auth_state: Option<String>,
    /// Expected principal state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    /// Expected transaction state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    /// Expected error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
