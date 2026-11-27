//! The plaintext JSON software backend.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, KeyBackend, PublicKeyInfo};

/// The format version of the keystore: a flat map with a top-level `v`; a
/// file from before versions has none and is v1 (same layout), and is
/// stamped on its next save.
const FORMAT_VERSION: u64 = 1;

/// The key file as the secret reader sees it: a flat map of thumbprint to
/// entry, with the version beside them. Entries are parsed straight into
/// [`StoredKey`], so a private key is never held as a `serde_json::Value`.
struct Entries(HashMap<String, StoredKey>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = Entries;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map of thumbprint to key entry")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Entries, A::Error> {
                let mut out = HashMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key == "v" {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    } else {
                        out.insert(key, map.next_value::<StoredKey>()?);
                    }
                }
                Ok(Entries(out))
            }
        }
        deserializer.deserialize_map(Visit)
    }
}

/// Read the key file with its secrets, checking `v` before any entry is
/// interpreted. The secrets live only as long as the returned map: callers
/// take what they need and let it drop, which wipes them. A missing file is
/// an empty map.
fn read_stored(path: &Path) -> Result<HashMap<String, StoredKey>, Error> {
    #[derive(Deserialize)]
    struct Version {
        v: Option<serde_json::Value>,
    }
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let text = Zeroizing::new(fs::read_to_string(path).map_err(io_at("reading", path))?);
    // First pass reads the version alone; every other field is skipped
    // without being kept.
    if let Some(v) = serde_json::from_str::<Version>(&text)?.v {
        let found = v.as_u64().ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
        })?;
        if found != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                file: "keystore",
                found,
                supported: FORMAT_VERSION,
            });
        }
    }
    Ok(serde_json::from_str::<Entries>(&text)?.0)
}

/// Serializes the entries and the current `v` as one flat map.
struct Versioned<'a>(&'a HashMap<String, StoredKey>);

impl Serialize for Versioned<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len() + 1))?;
        for (tmb, entry) in self.0 {
            map.serialize_entry(tmb, entry)?;
        }
        map.serialize_entry("v", &FORMAT_VERSION)?;
        map.end()
    }
}

/// The file's bytes, in a buffer that is wiped on drop. Sized up front so
/// it does not grow, and so leave an unwiped copy behind, in the usual case.
fn to_versioned(entries: &HashMap<String, StoredKey>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new(Vec::with_capacity(2048 * (entries.len() + 1)));
    serde_json::to_writer_pretty(&mut *buf, &Versioned(entries))?;
    Ok(buf)
}

/// A stored key entry: the on-disk record, secret included. It exists only
/// while a file is being read or written.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    alg: String,

    #[serde(with = "base64url_bytes")]
    pub_key: Vec<u8>,

    #[serde(with = "base64url_secret")]
    prv_key: Zeroizing<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

impl StoredKey {
    fn public(&self) -> PublicEntry {
        PublicEntry {
            alg: self.alg.clone(),
            pub_key: self.pub_key.clone(),
            tag: self.tag.clone(),
        }
    }
}

/// What the store keeps in memory of a key: everything but the secret.
struct PublicEntry {
    alg: String,
    pub_key: Vec<u8>,
    tag: Option<String>,
}

impl PublicEntry {
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
    /// Public data only: a private key is read from the file for the one
    /// operation that needs it and wiped when that operation ends.
    keys: HashMap<String, PublicEntry>,
    tightened: Vec<Tightened>,
    exposed_dir: Option<ExposedDir>,
}

/// A permission change `open` made to bring the key file down to
/// owner-only access, so the caller can tell the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tightened {
    /// The file changed.
    pub path: PathBuf,
    /// Its mode before, permission bits only.
    pub from: u32,
    /// Its mode now.
    pub to: u32,
}

/// An existing key directory that group or others can read or write. It is
/// reported, never changed: it may be the working directory or a shared
/// one such as `/tmp`, which is not ours to restrict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedDir {
    /// The directory.
    pub path: PathBuf,
    /// Its mode, permission bits only.
    pub mode: u32,
}

/// Owner-only modes for a key directory this code creates and for the key
/// file.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

fn io_at<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(std::io::Error) -> Error + 'a {
    move |source| Error::IoAt {
        op,
        path: path.to_path_buf(),
        source,
    }
}

/// The directory that holds `path`; `.` for a bare file name.
fn key_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn mode_of(path: &Path) -> Result<u32, Error> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)
        .map_err(io_at("reading permissions of", path))?
        .permissions()
        .mode()
        & 0o777)
}

impl JsonKeyStore {
    /// Load a keystore from the given path, or start an empty one. Never
    /// creates anything: the directory and file appear on the first write.
    /// An existing key file looser than 0600 is tightened (see
    /// [`Self::tightened`]); an existing directory open to group or others
    /// is reported (see [`Self::exposed_dir`]) and left as it is.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();

        let mut tightened = Vec::new();
        let mut exposed_dir = None;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = key_dir(&path);
            if dir.is_dir() {
                let mode = mode_of(dir)?;
                if mode & 0o077 != 0 {
                    exposed_dir = Some(ExposedDir {
                        path: dir.to_path_buf(),
                        mode,
                    });
                }
            }
            if path.exists() {
                let from = mode_of(&path)?;
                let to = from & FILE_MODE;
                if to != from {
                    fs::set_permissions(&path, fs::Permissions::from_mode(to))
                        .map_err(io_at("tightening permissions of", &path))?;
                    tightened.push(Tightened {
                        path: path.clone(),
                        from,
                        to,
                    });
                }
            }
        }

        let keys = read_stored(&path)?
            .into_iter()
            .map(|(tmb, stored)| (tmb, stored.public()))
            .collect();

        Ok(Self {
            path,
            keys,
            tightened,
            exposed_dir,
        })
    }

    /// Permission changes `open` made to the key file; empty when it was
    /// already private.
    pub fn tightened(&self) -> &[Tightened] {
        &self.tightened
    }

    /// The existing key directory, if group or others can reach it.
    pub fn exposed_dir(&self) -> Option<&ExposedDir> {
        self.exposed_dir.as_ref()
    }

    /// Write atomically: a temp file beside the target (same filesystem),
    /// created owner-only, fsynced, renamed over the target, then the
    /// directory fsynced so the rename itself is durable. A crash leaves
    /// the old file or the new one, never a torn one. A missing directory
    /// is created 0700; an existing target keeps its mode when that is
    /// stricter than 0600.
    fn save(&self, entries: &HashMap<String, StoredKey>) -> Result<(), Error> {
        use std::io::Write;
        let body = to_versioned(entries)?;
        let dir = key_dir(&self.path);
        #[cfg(unix)]
        if !dir.exists() {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(dir)
                .map_err(io_at("creating directory", dir))?;
        }
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
        // Not inside the cleanup scope: if `create_new` fails because the
        // name exists, that file is not ours to remove.
        let mut f = opts.open(&tmp).map_err(io_at("creating temp file", &tmp))?;
        let written = (|| -> Result<(), Error> {
            f.write_all(&body).map_err(io_at("writing", &tmp))?;
            #[cfg(unix)]
            if self.path.exists() {
                use std::os::unix::fs::PermissionsExt;
                let keep = mode_of(&self.path)? & FILE_MODE;
                f.set_permissions(fs::Permissions::from_mode(keep))
                    .map_err(io_at("setting permissions of", &tmp))?;
            }
            f.sync_all().map_err(io_at("syncing", &tmp))?;
            fs::rename(&tmp, &self.path).map_err(io_at("renaming over", &self.path))?;
            fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(io_at("syncing directory", dir))
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
    }

    fn entry(&self, tmb: &str) -> Result<&PublicEntry, Error> {
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
            prv_key: Zeroizing::new(keypair.prv_bytes),
            tag: tag.map(String::from),
        };
        let public = stored.public();
        // The file is rewritten whole, so every secret is read for the
        // write and wiped with the map once it is on disk.
        let mut entries = read_stored(&self.path)?;
        entries.insert(tmb.clone(), stored);
        self.save(&entries)?;
        let info = public.info(&tmb);
        self.keys.insert(tmb, public);
        Ok(info)
    }

    fn list(&self) -> Result<Vec<PublicKeyInfo>, Error> {
        Ok(self.keys.iter().map(|(tmb, k)| k.info(tmb)).collect())
    }

    fn public(&self, tmb: &str) -> Result<PublicKeyInfo, Error> {
        Ok(self.entry(tmb)?.info(tmb))
    }

    fn remove(&mut self, tmb: &str) -> Result<(), Error> {
        if !self.keys.contains_key(tmb) {
            return Err(Error::NotFound(tmb.to_string()));
        }
        let mut entries = read_stored(&self.path)?;
        entries.remove(tmb);
        self.save(&entries)?;
        self.keys.remove(tmb);
        Ok(())
    }

    fn signer(&self, tmb: &str) -> Result<SoftwareSigner, Error> {
        self.entry(tmb)?;
        let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb)
            .map_err(|_| Error::InvalidThumbprint(tmb.to_string()))?;
        // The secret is read now and dropped (wiped) on return; what the
        // signer holds is the caller's to keep for as short as it signs.
        let mut stored = read_stored(&self.path)?;
        let k = stored
            .remove(tmb)
            .ok_or_else(|| Error::NotFound(tmb.to_string()))?;
        Ok(SoftwareSigner::new(
            &k.alg,
            &k.prv_key,
            &k.pub_key,
            &coz::Thumbprint::from_bytes(tmb_bytes),
        ))
    }
}

/// Serde helper for a private key's bytes: base64url, held in a type that
/// wipes them when it drops, with the decoded text wiped too.
mod base64url_secret {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de};
    use zeroize::{Zeroize, Zeroizing};

    pub fn serialize<S>(bytes: &Zeroizing<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut text = Base64UrlUnpadded::encode_string(bytes);
        let out = serializer.serialize_str(&text);
        text.zeroize();
        out
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut text = String::deserialize(deserializer)?;
        let decoded = Base64UrlUnpadded::decode_vec(&text).map_err(de::Error::custom);
        text.zeroize();
        decoded.map(Zeroizing::new)
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
