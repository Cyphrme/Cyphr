//! Keystore abstraction for private key storage.
//!
//! This module provides a trait for key storage backends and an MVP
//! plaintext JSON implementation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

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

    /// The file states a format version this build does not read. No key
    /// was read from it.
    #[error("{file} version {found} is not the supported {supported}")]
    UnsupportedVersion {
        /// Which file was refused.
        file: &'static str,
        /// The version the file states.
        found: u64,
        /// The one version this build reads.
        supported: u64,
    },
}

/// The format version of the keystore: a flat map with a top-level `v`; a
/// file from before versions has none and is v1 (same layout), and is
/// stamped on its next save.
const FORMAT_VERSION: u64 = 1;

/// Read a versioned flat-map file, checking `v` before any entry is
/// interpreted.
fn read_versioned<T: serde::de::DeserializeOwned>(
    path: &Path,
    file: &'static str,
) -> Result<HashMap<String, T>, Error> {
    let mut doc: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(path)?)?;
    if let Some(v) = doc.remove("v") {
        let found = v.as_u64().ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
        })?;
        if found != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                file,
                found,
                supported: FORMAT_VERSION,
            });
        }
    }
    Ok(serde_json::from_value(serde_json::Value::Object(doc))?)
}

/// Serialize a flat map with the current `v`.
fn to_versioned<T: Serialize>(entries: &HashMap<String, T>) -> Result<String, Error> {
    let mut doc = serde_json::Map::new();
    for (key, entry) in entries {
        doc.insert(key.clone(), serde_json::to_value(entry)?);
    }
    doc.insert("v".to_string(), FORMAT_VERSION.into());
    Ok(serde_json::to_string_pretty(&doc)?)
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
            read_versioned(&path, "keystore")?
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
        let content = to_versioned(&self.keys)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredKey {
        StoredKey {
            alg: "Ed25519".into(),
            pub_key: vec![1; 32],
            prv_key: vec![2; 32],
            tag: None,
        }
    }

    /// Claim: the keystore file states its format
    /// version, and `open` refuses one it does not know as a typed
    /// `UnsupportedVersion`, before any key is read out of it. The current
    /// version still round-trips. Turns red on files written unstamped, or an
    /// `open` that ignores `v` (today an extra top-level field is mis-read
    /// as a key entry and fails as a bare JSON error). A unit test: the
    /// files are the unit under claim and no scenario reaches them cheaply.
    #[test]
    fn version_keystore_unknown_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut ks = JsonKeyStore::open(&path).unwrap();
        ks.store("tmb-1", stored()).unwrap();
        ks.save().unwrap();
        let reopened = JsonKeyStore::open(&path).expect("the current version reopens");
        reopened.get("tmb-1").expect("and still holds the key");

        let file = &path;
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert!(
            doc["v"].is_u64(),
            "{} must be stamped with a numeric `v`: {doc}",
            file.display()
        );
        for unknown in [0u64, 99] {
            doc["v"] = unknown.into();
            std::fs::write(file, serde_json::to_vec(&doc).unwrap()).unwrap();
            let refused = JsonKeyStore::open(&path).err();
            assert!(
                matches!(
                    refused,
                    Some(Error::UnsupportedVersion { found, .. }) if found == unknown
                ),
                "{} v={unknown} must be refused as UnsupportedVersion: {refused:?}",
                file.display()
            );
        }
    }
}
