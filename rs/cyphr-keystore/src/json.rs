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
/// Stores keys in a JSON file on disk, created owner-only (0600 in a 0700
/// directory) and written atomically. **Unencrypted at rest** until Coz
/// encryption lands. The file format is the stable surface: existing key
/// files keep working.
pub struct JsonKeyStore {
    path: PathBuf,
    keys: HashMap<String, StoredKey>,
    tightened: Vec<Tightened>,
}

/// A permission change `open` made to bring the key file or its directory
/// down to owner-only access, so the caller can tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tightened {
    /// The file or directory changed.
    pub path: PathBuf,
    /// Its mode before, permission bits only.
    pub from: u32,
    /// Its mode now.
    pub to: u32,
}

/// Owner-only modes for the key directory and the key file.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Remove every group/other bit from an existing `path` that has any,
/// recording the change. Only bits are removed, never added, so a stricter
/// mode (0400) is left alone.
#[cfg(unix)]
fn tighten(path: &Path, limit: u32, out: &mut Vec<Tightened>) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let from = fs::metadata(path)?.permissions().mode() & 0o777;
    let to = from & limit;
    if to != from {
        fs::set_permissions(path, fs::Permissions::from_mode(to))?;
        out.push(Tightened {
            path: path.to_path_buf(),
            from,
            to,
        });
    }
    Ok(())
}

/// The directory holding `path`, or `None` when `path` is a bare file name:
/// that directory is the caller's working directory, which is not ours to
/// restrict.
fn key_dir(path: &Path) -> Option<&Path> {
    path.parent().filter(|d| !d.as_os_str().is_empty())
}

impl JsonKeyStore {
    /// Create or load a keystore from the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();

        let mut tightened = Vec::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            if let Some(dir) = key_dir(&path) {
                if dir.exists() {
                    tighten(dir, DIR_MODE, &mut tightened)?;
                } else {
                    fs::DirBuilder::new()
                        .recursive(true)
                        .mode(DIR_MODE)
                        .create(dir)?;
                }
            }
            if path.exists() {
                tighten(&path, FILE_MODE, &mut tightened)?;
            }
        }

        let keys = if path.exists() {
            read_versioned(&path, "keystore")?
        } else {
            HashMap::new()
        };

        Ok(Self {
            path,
            keys,
            tightened,
        })
    }

    /// Permission changes `open` made; empty when the store was already
    /// private.
    pub fn tightened(&self) -> &[Tightened] {
        &self.tightened
    }

    /// Write atomically: a temp file beside the target (same filesystem),
    /// created owner-only, fsynced, renamed over the target, then the
    /// directory fsynced so the rename itself is durable. A crash leaves
    /// the old file or the new one, never a torn one.
    fn save(&self) -> Result<(), Error> {
        use std::io::Write;
        let body = to_versioned(&self.keys)?;
        let dir = key_dir(&self.path).unwrap_or_else(|| Path::new("."));
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));

        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(FILE_MODE);
        }
        let written = (|| -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            fs::File::open(dir)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(written?)
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
