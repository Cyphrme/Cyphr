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

impl PoolKey {
    /// Compute the thumbprint for this key.
    ///
    /// Per Coz spec: `tmb = H(canon({"alg": alg, "pub": pub}))`
    pub fn compute_tmb(&self) -> Result<coz::Thumbprint, Error> {
        use coz::base64ct::Encoding;

        let pub_bytes =
            coz::base64ct::Base64UrlUnpadded::decode_vec(&self.pub_key).map_err(|e| {
                Error::PoolValidation {
                    message: format!("key '{}': invalid base64url pub: {e}", self.name),
                }
            })?;

        coz::compute_thumbprint_for_alg(&self.alg, &pub_bytes).ok_or_else(|| {
            Error::PoolValidation {
                message: format!("key '{}': unsupported algorithm '{}'", self.name, self.alg),
            }
        })
    }

    /// Compute thumbprint as base64url string.
    pub fn compute_tmb_b64(&self) -> Result<String, Error> {
        use coz::base64ct::Encoding;
        let tmb = self.compute_tmb()?;
        Ok(coz::base64ct::Base64UrlUnpadded::encode_string(
            tmb.as_bytes(),
        ))
    }
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
    /// - Names are unique
    /// - Algorithm is supported
    /// - Thumbprint can be computed
    /// - (Future) Private key derives to public key
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Check for duplicate names
        let mut seen = std::collections::HashSet::new();
        for key in &self.pool.key {
            if !seen.insert(&key.name) {
                errors.push(format!("duplicate key name: {}", key.name));
            }
        }

        // Validate each key's thumbprint computation
        for key in &self.pool.key {
            if let Err(e) = key.compute_tmb() {
                errors.push(e.to_string());
            }
        }

        // TODO: Verify prv derives to pub when coz exposes public key derivation

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_load() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_vectors/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool.toml");
        assert_eq!(pool.pool.version, "0.1.0");
        assert!(pool.get("golden").is_some());
        assert!(pool.get("alice").is_some());
        assert!(pool.get("nonexistent").is_none());
    }

    #[test]
    fn test_pool_validate() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_vectors/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool.toml");

        // Validation should pass for supported keys, fail for unsupported
        let result = pool.validate();
        // RS256 (unsupported_key) should cause a validation error
        assert!(result.is_err(), "should fail with unsupported RS256 key");
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("unsupported_key")));
    }

    #[test]
    fn test_golden_key_thumbprint() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test_vectors/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool.toml");
        let golden = pool.get("golden").expect("golden key not found");

        // Expected thumbprint from pool.json reference
        let expected_tmb = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let computed_tmb = golden.compute_tmb_b64().expect("failed to compute tmb");

        assert_eq!(computed_tmb, expected_tmb, "golden key thumbprint mismatch");
    }
}
