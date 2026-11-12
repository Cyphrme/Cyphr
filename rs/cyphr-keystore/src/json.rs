//! The plaintext JSON software backend.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use serde::{Deserialize, Serialize};

use crate::{Error, KeyBackend, PublicKeyInfo};

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

/// A stored key entry: the on-disk record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    alg: String,

    #[serde(with = "base64url_bytes")]
    pub_key: Vec<u8>,

    #[serde(with = "base64url_bytes")]
    prv_key: Vec<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

impl StoredKey {
    fn info(&self, tmb: &str) -> PublicKeyInfo {
        PublicKeyInfo {
            alg: self.alg.clone(),
            pub_key: self.pub_key.clone(),
            tmb: tmb.to_string(),
            tag: self.tag.clone(),
        }
    }
}

/// Plaintext JSON keystore: the software [`KeyBackend`].
///
/// Stores keys in a JSON file on disk. **NOT SECURE** for production use.
/// Keys are stored in plaintext. Use only for development and testing. The
/// file format is the stable surface: existing key files keep working.
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

    fn save(&self) -> Result<(), Error> {
        fs::write(&self.path, to_versioned(&self.keys)?)?;
        Ok(())
    }

    fn entry(&self, tmb: &str) -> Result<&StoredKey, Error> {
        self.keys
            .get(tmb)
            .ok_or_else(|| Error::NotFound(tmb.to_string()))
    }
}

impl KeyBackend for JsonKeyStore {
    type Signer = SoftwareSigner;

    fn generate(&mut self, alg: &str, tag: Option<&str>) -> Result<PublicKeyInfo, Error> {
        let alg_enum =
            coz::Alg::from_str(alg).ok_or_else(|| Error::UnknownAlgorithm(alg.to_string()))?;
        let keypair = alg_enum.generate_keypair();
        let tmb = Base64UrlUnpadded::encode_string(keypair.thumbprint.as_bytes());
        if self.keys.contains_key(&tmb) {
            return Err(Error::AlreadyExists(tmb));
        }
        let stored = StoredKey {
            alg: alg.to_string(),
            pub_key: keypair.pub_bytes,
            prv_key: keypair.prv_bytes,
            tag: tag.map(String::from),
        };
        let info = stored.info(&tmb);
        self.keys.insert(tmb, stored);
        self.save()?;
        Ok(info)
    }

    fn list(&self) -> Result<Vec<PublicKeyInfo>, Error> {
        Ok(self.keys.iter().map(|(tmb, k)| k.info(tmb)).collect())
    }

    fn public(&self, tmb: &str) -> Result<PublicKeyInfo, Error> {
        Ok(self.entry(tmb)?.info(tmb))
    }

    fn remove(&mut self, tmb: &str) -> Result<(), Error> {
        self.keys
            .remove(tmb)
            .ok_or_else(|| Error::NotFound(tmb.to_string()))?;
        self.save()
    }

    fn signer(&self, tmb: &str) -> Result<SoftwareSigner, Error> {
        let k = self.entry(tmb)?;
        let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb)
            .map_err(|_| Error::InvalidThumbprint(tmb.to_string()))?;
        Ok(SoftwareSigner::new(
            &k.alg,
            &k.prv_key,
            &k.pub_key,
            &coz::Thumbprint::from_bytes(tmb_bytes),
        ))
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
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(bytes))
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

    /// Claim: the keystore file states its format version, and `open`
    /// refuses one it does not know as a typed `UnsupportedVersion`, before
    /// any key is read out of it. The current version still round-trips.
    /// Turns red on files written unstamped, or an `open` that ignores `v`
    /// (an extra top-level field is then mis-read as a key entry and fails
    /// as a bare JSON error). A unit test: the files are the unit under
    /// claim and no scenario reaches them cheaply.
    #[test]
    fn version_keystore_unknown_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut ks = JsonKeyStore::open(&path).unwrap();
        let tmb = ks.generate("Ed25519", None).unwrap().tmb;
        let reopened = JsonKeyStore::open(&path).expect("the current version reopens");
        reopened.public(&tmb).expect("and still holds the key");

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
