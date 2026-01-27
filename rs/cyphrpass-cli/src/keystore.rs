//! Keystore abstraction for private key storage.
//!
//! This module provides a trait for key storage backends and an MVP
//! plaintext JSON implementation.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Error type for keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading or writing keystore file.
    #[error("keystore I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error.
    #[error("keystore JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Key not found in keystore.
    #[error("key not found: {0}")]
    NotFound(String),

    /// Key already exists in keystore.
    #[error("key already exists: {0}")]
    AlreadyExists(String),

    /// Unknown algorithm.
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
}

/// A stored key entry with algorithm, public, and private key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKey {
    /// Algorithm identifier (ES256, ES384, ES512, Ed25519).
    pub alg: String,

    /// Public key bytes (base64url encoded in JSON).
    #[serde(with = "base64url_bytes")]
    pub pub_key: Vec<u8>,

    /// Private key bytes (base64url encoded in JSON).
    #[serde(with = "base64url_bytes")]
    pub prv_key: Vec<u8>,

    /// Optional human-readable tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// Keystore trait for private key storage.
///
/// Implementations may use files, OS keychains, HSMs, etc.
pub trait KeyStore {
    /// Store a key by its thumbprint.
    fn store(&mut self, tmb: &str, key: StoredKey) -> Result<(), Error>;

    /// Retrieve a key by its thumbprint.
    fn get(&self, tmb: &str) -> Result<&StoredKey, Error>;

    /// List all stored key thumbprints.
    fn list(&self) -> Vec<&str>;

    /// Persist changes to backing storage.
    fn save(&self) -> Result<(), Error>;
}

/// Plaintext JSON keystore (MVP implementation).
///
/// Stores keys in a JSON file on disk. **NOT SECURE** for production use.
/// Keys are stored in plaintext. Use only for development and testing.
pub struct JsonKeyStore {
    path: PathBuf,
    keys: HashMap<String, StoredKey>,
}

impl JsonKeyStore {
    /// Create or load a keystore from the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();

        let keys = if path.exists() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content)?
        } else {
            HashMap::new()
        };

        Ok(Self { path, keys })
    }

    /// Get the path to the keystore file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for JsonKeyStore {
    fn store(&mut self, tmb: &str, key: StoredKey) -> Result<(), Error> {
        if self.keys.contains_key(tmb) {
            return Err(Error::AlreadyExists(tmb.to_string()));
        }
        self.keys.insert(tmb.to_string(), key);
        Ok(())
    }

    fn get(&self, tmb: &str) -> Result<&StoredKey, Error> {
        self.keys
            .get(tmb)
            .ok_or_else(|| Error::NotFound(tmb.to_string()))
    }

    fn list(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    fn save(&self) -> Result<(), Error> {
        let content = serde_json::to_string_pretty(&self.keys)?;
        fs::write(&self.path, content)?;
        Ok(())
    }
}

/// Serde helper for base64url encoding/decoding of byte vectors.
mod base64url_bytes {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = Base64UrlUnpadded::encode_string(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Base64UrlUnpadded::decode_vec(&s).map_err(de::Error::custom)
    }
}
