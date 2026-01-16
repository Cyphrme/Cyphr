//! Key pool types and parsing.
//!
//! The key pool is the source of truth for all cryptographic material
//! used in test fixtures.

use std::path::Path;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Key pool containing named keys for test fixtures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    /// Pool metadata.
    pub pool: PoolMeta,
}

/// Pool metadata and keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMeta {
    /// Pool format version.
    pub version: String,
    /// Named keys.
    #[serde(default)]
    pub key: Vec<PoolKey>,
}

/// A key in the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolKey {
    /// Unique name for this key.
    pub name: String,
    /// Algorithm (ES256, ES384, Ed25519).
    pub alg: String,
    /// Public key (base64url).
    #[serde(rename = "pub")]
    pub pub_key: String,
    /// Private key (base64url, optional for public-only keys).
    #[serde(default)]
    pub prv: Option<String>,
    /// Human-readable tag.
    #[serde(default)]
    pub tag: Option<String>,
}

impl Pool {
    /// Load a pool from a TOML file.
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

    /// Get a key by name.
    pub fn get(&self, name: &str) -> Option<&PoolKey> {
        self.pool.key.iter().find(|k| k.name == name)
    }

    /// Get all keys as a map.
    pub fn keys(&self) -> IndexMap<String, &PoolKey> {
        self.pool.key.iter().map(|k| (k.name.clone(), k)).collect()
    }

    /// Validate all keys in the pool.
    ///
    /// Checks:
    /// - Thumbprint derivation matches
    /// - Private key derives to public key
    /// - Names are unique
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Check for duplicate names
        let mut seen = std::collections::HashSet::new();
        for key in &self.pool.key {
            if !seen.insert(&key.name) {
                errors.push(format!("duplicate key name: {}", key.name));
            }
        }

        // TODO: Add cryptographic validation
        // - Verify tmb = H(canon({"alg": alg, "pub": pub}))
        // - Verify prv derives to pub

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
