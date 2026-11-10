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
    /// Numbered keys: derived on load, never stored in the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numbered: Option<NumberedKeys>,
}

/// Recipe for the numbered keys `#0 .. #<count-1>`.
///
/// Key `#n` is the Ed25519 key whose private half is `SHA-256(seed "/" n)`
/// (n in decimal). Ed25519 takes any 32 bytes as a private key, so the
/// derivation needs no rejection loop. This is test material derived from a
/// public seed: it protects nothing, and the seed is never a protocol hash
/// input. Changing `seed` changes every numbered vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumberedKeys {
    /// Public seed mixed into every derivation.
    pub seed: String,
    /// How many numbered keys exist.
    pub count: u32,
}

impl NumberedKeys {
    /// The pool key named `#<n>`.
    ///
    /// # Errors
    ///
    /// `PoolValidation` if the Ed25519 public half cannot be derived.
    pub fn key(&self, n: u32) -> Result<PoolKey, Error> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let prv = coz::HashAlg::Sha256.hash_bytes(format!("{}/{n}", self.seed).as_bytes());
        let pub_key =
            coz::Alg::Ed25519
                .derive_public_key(&prv)
                .ok_or_else(|| Error::PoolValidation {
                    message: format!("numbered key #{n}: Ed25519 derivation failed"),
                })?;
        Ok(PoolKey {
            name: format!("#{n}"),
            alg: "Ed25519".to_string(),
            pub_key: Base64UrlUnpadded::encode_string(&pub_key),
            prv: Some(Base64UrlUnpadded::encode_string(&prv)),
            tag: Some(format!("Numbered test key {n}")),
        })
    }
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

        if let Some(tmb) = coz::compute_thumbprint_for_alg(&self.alg, &pub_bytes) {
            Ok(tmb)
        } else {
            // Fallback for unsupported algorithms (e.g., RS256 for error testing)
            // so we can still generate test fixtures. The transaction will fail
            // with UnsupportedAlgorithm during replay.
            Ok(coz::Thumbprint::from_bytes(pub_bytes))
        }
    }

    /// This key as a [`cyphr::Key`] (its `alg`, `pub` and thumbprint).
    ///
    /// # Errors
    ///
    /// `PoolValidation` if `pub` is not base64url or the key is refused by
    /// the core (an algorithm it does not support).
    pub fn key(&self) -> Result<cyphr::Key, Error> {
        use coz::base64ct::Encoding;

        let pub_bytes =
            coz::base64ct::Base64UrlUnpadded::decode_vec(&self.pub_key).map_err(|e| {
                Error::PoolValidation {
                    message: format!("key '{}': invalid base64url pub: {e}", self.name),
                }
            })?;
        cyphr::Key::new(self.alg.clone(), self.compute_tmb()?, pub_bytes).map_err(|e| {
            Error::PoolValidation {
                message: format!("key '{}': {e}", self.name),
            }
        })
    }

    /// A software signer over this key's private half.
    ///
    /// # Errors
    ///
    /// `MissingPrivateKey` for a public-only key; `PoolValidation` if a
    /// half is not base64url.
    pub fn software_signer(&self) -> Result<cyphr::signer::SoftwareSigner, Error> {
        use coz::base64ct::Encoding;

        let decode = |what: &str, v: &str| {
            coz::base64ct::Base64UrlUnpadded::decode_vec(v).map_err(|e| Error::PoolValidation {
                message: format!("key '{}': invalid base64url {what}: {e}", self.name),
            })
        };
        let prv = self
            .prv
            .as_deref()
            .ok_or_else(|| Error::MissingPrivateKey {
                name: self.name.clone(),
            })?;
        Ok(cyphr::signer::SoftwareSigner::new(
            &self.alg,
            &decode("prv", prv)?,
            &decode("pub", &self.pub_key)?,
            &self.compute_tmb()?,
        ))
    }

    /// Compute thumbprint as base64url string.
    pub fn compute_tmb_b64(&self) -> Result<String, Error> {
        use coz::base64ct::Encoding;
        let tmb = self.compute_tmb()?;
        Ok(coz::base64ct::Base64UrlUnpadded::encode_string(
            tmb.as_bytes(),
        ))
    }

    /// Verify that a private key derives to the stated public key.
    ///
    /// Returns `Ok(true)` if the derived public key matches `self.pub_key`,
    /// `Ok(false)` if they don't match, or `Err` if derivation fails.
    pub fn verify_prv_derives_to_pub(&self, prv_b64: &str) -> Result<bool, Error> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let prv_bytes =
            Base64UrlUnpadded::decode_vec(prv_b64).map_err(|e| Error::PoolValidation {
                message: format!("key '{}': invalid base64url prv: {e}", self.name),
            })?;

        // Derive public key using Alg enum for type-safe dispatch
        let alg_enum = match coz::Alg::from_str(&self.alg) {
            Some(a) => a,
            None => {
                // Unsupported algorithm - skip prv validation
                return Ok(true);
            },
        };

        let derived_pub_bytes =
            alg_enum
                .derive_public_key(&prv_bytes)
                .ok_or_else(|| Error::PoolValidation {
                    message: format!(
                        "key '{}': failed to parse {} private key",
                        self.name, self.alg
                    ),
                })?;

        let derived_pub_b64 = Base64UrlUnpadded::encode_string(&derived_pub_bytes);

        Ok(derived_pub_b64 == self.pub_key)
    }
}

impl Pool {
    /// Load a pool from a TOML file, with its numbered keys derived and
    /// appended after the named ones.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut pool = Self::load_declared(path)?;
        if let Some(numbered) = pool.pool.numbered.clone() {
            for n in 0..numbered.count {
                pool.pool.key.push(numbered.key(n)?);
            }
        }
        Ok(pool)
    }

    /// Load a pool exactly as the file states it: named keys only. For
    /// tools that rewrite the file, which must not persist derived keys.
    pub fn load_declared(path: &Path) -> Result<Self, Error> {
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

        // Validate each key's algorithm is supported
        for key in &self.pool.key {
            if coz::Alg::from_str(&key.alg).is_none() {
                errors.push(format!(
                    "key '{}': unsupported algorithm: {}",
                    key.name, key.alg
                ));
            }
        }

        // Verify private key derives to stated public key for keys with prv
        for key in &self.pool.key {
            if let Some(ref prv) = key.prv {
                match key.verify_prv_derives_to_pub(prv) {
                    Ok(false) => {
                        errors.push(format!(
                            "key '{}': private key does not derive to stated public key",
                            key.name
                        ));
                    },
                    Err(e) => {
                        errors.push(format!("key '{}': prv validation error: {e}", key.name));
                    },
                    Ok(true) => {
                        // Valid
                    },
                }
            }
        }

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

    /// Backs: the key pool rejects an unsupported-algorithm key (RS256) instead of generating
    /// fixtures from it. Unit: build-time tooling with no end-to-end surface.
    #[test]
    fn test_pool_validate() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool.toml");

        // Validation should pass for supported keys, fail for unsupported
        let result = pool.validate();
        // RS256 (unsupported_key) should cause a validation error
        assert!(result.is_err(), "should fail with unsupported RS256 key");
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("unsupported_key")));
    }

    /// Backs: the golden key in the pool has the pinned thumbprint every golden vector depends on
    /// (SPEC 2.2 thumbprint); also proves the pool loads. Unit: pool is fixture tooling, not a
    /// protocol surface.
    #[test]
    fn test_golden_key_thumbprint() {
        let pool_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/keys/pool.toml");

        let pool = Pool::load(&pool_path).expect("failed to load pool.toml");
        let golden = pool.get("golden").expect("golden key not found");

        // Expected thumbprint from pool.json reference
        let expected_tmb = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
        let computed_tmb = golden.compute_tmb_b64().expect("failed to compute tmb");

        assert_eq!(computed_tmb, expected_tmb, "golden key thumbprint mismatch");
    }
}
