//! Server authentication and signing identity.
//!
//! This module root holds the server's own signing key
//! ([`ServerIdentity`]) and is the home of bearer-token issuance, login
//! flows, and route protection (SPEC 17.4).
//!
//! The server holds one signing key, loaded from a file at startup, and
//! uses it to sign and verify its own Coz payloads (SPEC 17.4 bearer
//! token issuance signs with this key). Consumers hold a [`ServerIdentity`]
//! rather than raw key bytes, so the same abstraction can later be backed
//! by a full Cyphr principal without rewriting call sites.

pub mod login;
pub mod middleware;
pub mod policy;
pub mod principal;
pub mod token;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The category and position of a JSON fault, never serde's text: for a
/// wrong-typed field that text quotes the offending scalar, which in a
/// key file is key material and in a client body is an echo of attacker
/// input into logs and responses.
pub(crate) fn json_fault(e: &serde_json::Error) -> String {
    format!(
        "{:?} error at line {}, column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

/// Errors loading or using a server signing identity.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// I/O error reading the key file.
    #[error("signing key file: {0}")]
    Io(#[from] std::io::Error),

    /// The key file was not valid JSON in the expected shape.
    ///
    /// See [`json_fault`] for why serde's text is never echoed.
    #[error("signing key file is malformed ({})", json_fault(.0))]
    Malformed(#[from] serde_json::Error),

    /// The `alg` field named an algorithm coz does not recognize.
    #[error("signing key file names unknown algorithm: {0}")]
    UnknownAlgorithm(String),

    /// The private key bytes were rejected by coz for the named algorithm
    /// (wrong length or otherwise invalid).
    #[error("signing key file's private key is invalid for algorithm {0}")]
    InvalidPrivateKey(String),

    /// The stored public key does not match the public key derived from
    /// the stored private key -- the file has drifted or was hand-edited.
    #[error("signing key file's public key does not match its private key")]
    PublicKeyMismatch,

    /// The key file states a format version this build does not read. No
    /// key was loaded from it.
    #[error("signing key file version {found} is not the supported {supported}")]
    UnsupportedVersion { found: u64, supported: u32 },
}

/// The format version of the signing-key file and the server-principal
/// sidecar. A file with no `v` predates versions and is v1 (same layout).
pub(crate) const FILE_FORMAT_VERSION: u32 = 1;

/// The version a JSON document states: absent means v1.
///
/// # Errors
///
/// [`serde_json::Error`] when `v` is present but not an unsigned integer.
pub(crate) fn document_version(doc: &serde_json::Value) -> Result<u64, serde_json::Error> {
    match doc.get("v") {
        None => Ok(u64::from(FILE_FORMAT_VERSION)),
        Some(v) => v.as_u64().ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
        }),
    }
}

fn file_v1() -> u32 {
    FILE_FORMAT_VERSION
}

/// On-disk shape of a server signing key file: algorithm plus a raw
/// private/public keypair, base64url-encoded.
///
/// This is a server-local file format, not a shared dependency on
/// `cyphr-cli`'s keystore -- see `rs/cyphr-cli/src/keystore.rs` for the
/// (explicitly NOT SECURE) shape this was modeled after.
///
/// Deliberately does not derive `Debug`: it holds `prv_key` in the
/// clear, and the whole point of `ServerIdentity`'s own hand-written,
/// redacting `Debug` impl is that private key bytes never reach a
/// `{:?}`/`tracing` line anywhere in this module -- a derived `Debug`
/// on this type would silently reopen exactly that hole.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    /// Format version; absent in files from before versions (v1).
    #[serde(default = "file_v1")]
    v: u32,
    alg: String,
    #[serde(with = "base64url_bytes")]
    pub_key: Vec<u8>,
    #[serde(with = "base64url_secret")]
    prv_key: zeroize::Zeroizing<Vec<u8>>,
}

/// The server's own signing key.
///
/// Holds the private key material internally; callers reach it only
/// through [`ServerIdentity::sign`] and [`ServerIdentity::verify`], never
/// as raw bytes. The public key is not secret and is available via
/// [`ServerIdentity::pub_key`].
pub struct ServerIdentity {
    alg: coz::Alg,
    pub_bytes: Vec<u8>,
    prv_bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for ServerIdentity {
    /// Redacts private key material -- this type must never leak its
    /// signing key through a `{:?}`/`tracing` log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("alg", &self.alg.name())
            .field("pub_bytes", &self.pub_bytes)
            .field("prv_bytes", &"<redacted>")
            .finish()
    }
}

impl ServerIdentity {
    /// Load a signing identity from a key file at `path`.
    ///
    /// Fails clearly (never panics) on a missing file, malformed JSON, an
    /// unrecognized algorithm, an invalid private key, or a public key
    /// that does not match the private key.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let path = path.as_ref();
        warn_if_readable_by_others(path);
        // The file text holds the private key; it is wiped once parsed.
        let content = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let doc: serde_json::Value = serde_json::from_str(&content)?;
        let found = document_version(&doc)?;
        if found != u64::from(FILE_FORMAT_VERSION) {
            return Err(AuthError::UnsupportedVersion {
                found,
                supported: FILE_FORMAT_VERSION,
            });
        }
        let stamped = doc.get("v").is_some();
        let file: KeyFile = serde_json::from_value(doc)?;

        let alg = coz::Alg::from_str(&file.alg)
            .ok_or_else(|| AuthError::UnknownAlgorithm(file.alg.clone()))?;

        let derived_pub = alg
            .derive_public_key(&file.prv_key)
            .ok_or_else(|| AuthError::InvalidPrivateKey(file.alg.clone()))?;
        if derived_pub != file.pub_key {
            return Err(AuthError::PublicKeyMismatch);
        }

        // A file from before versions is v1: rewrite it stamped, so every
        // later read is of a versioned file.
        if !stamped {
            std::fs::write(path, serde_json::to_vec(&file)?)?;
        }

        Ok(Self {
            alg,
            pub_bytes: file.pub_key,
            prv_bytes: file.prv_key,
        })
    }

    /// The algorithm this identity signs and verifies with.
    pub fn alg(&self) -> coz::Alg {
        self.alg
    }

    /// The public key, safe to publish or embed in issued Coz payloads.
    pub fn pub_key(&self) -> &[u8] {
        &self.pub_bytes
    }

    /// The raw private key bytes, for constructing and finalizing the
    /// server's own chain cozies (see [`principal`]).
    ///
    /// Crate-private on purpose: this reopens no logging hole (the
    /// redacting `Debug` impl still governs every `{:?}` path), it only
    /// lets the sibling `principal` module sign genesis and rotation
    /// commits with the same key `sign`/`verify` already use.
    pub(crate) fn prv_key(&self) -> &[u8] {
        &self.prv_bytes
    }

    /// Sign a Coz `pay` payload with this identity's key.
    ///
    /// Returns `None` if coz rejects the payload or key (e.g. a key whose
    /// bytes coz can no longer parse for this algorithm).
    pub fn sign(&self, pay_json: &[u8]) -> Option<(Vec<u8>, coz::Cad)> {
        coz::sign_json(pay_json, self.alg.name(), &self.prv_bytes, &self.pub_bytes)
    }

    /// Verify a signature over `pay_json` against this identity's public
    /// key.
    pub fn verify(&self, pay_json: &[u8], sig: &[u8]) -> Option<bool> {
        coz::verify_json(pay_json, sig, self.alg.name(), &self.pub_bytes)
    }
}

/// The server signs login challenges with its own key.
impl cyphr_client::login::Issuer for ServerIdentity {
    fn alg(&self) -> &str {
        self.alg.name()
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_bytes
    }

    fn sign(&self, pay_bytes: &[u8]) -> Result<Vec<u8>, cyphr_client::login::IssuerError> {
        ServerIdentity::sign(self, pay_bytes)
            .map(|(sig, _)| sig)
            .ok_or_else(|| {
                cyphr_client::login::IssuerError("coz rejected the server's signing key".into())
            })
    }
}

/// The staging path for a key replacement: `<path>.next`, beside the key
/// file so the final rename never crosses a filesystem.
pub fn next_key_path(path: &Path) -> PathBuf {
    let mut next = path.as_os_str().to_owned();
    next.push(".next");
    PathBuf::from(next)
}

/// Durably write `kp` to `<path>.next` in the on-disk [`KeyFile`] format,
/// leaving the live key file untouched.
///
/// This is step one of a crash-safe key replacement (see [`principal`]): the
/// new key must be on stable storage before the chain commits to it, or a
/// crash after the commit could leave a chain whose active private key
/// exists nowhere. The file is fsynced before returning. It is created
/// owner-only (0600) whether or not a live key file exists: the staging
/// path is the one moment the private key is on disk under a name the
/// operator did not create, and the later rename carries that mode onto
/// the live file.
pub(crate) fn stage_key_file(path: &Path, kp: &coz::KeyPair) -> Result<(), AuthError> {
    use std::io::Write;

    let file = KeyFile {
        v: FILE_FORMAT_VERSION,
        alg: kp.alg.name().to_string(),
        pub_key: kp.pub_bytes.clone(),
        prv_key: zeroize::Zeroizing::new(kp.prv_bytes.clone()),
    };
    let next = next_key_path(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut out = options.open(&next)?;
    // `mode` applies only when the file is created; a `.next` left by a
    // torn run keeps its old mode, so narrow it explicitly too.
    #[cfg(unix)]
    out.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    out.write_all(&zeroize::Zeroizing::new(serde_json::to_vec(&file)?))?;
    out.sync_all()?;
    Ok(())
}

/// Atomically replace the key file with the staged `<path>.next`, then
/// fsync the directory so the rename itself survives a crash.
pub(crate) fn promote_staged_key(path: &Path) -> Result<(), AuthError> {
    std::fs::rename(next_key_path(path), path)?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Delete a staged `<path>.next` the chain does not vouch for, durably.
pub(crate) fn discard_staged_key(path: &Path) -> Result<(), AuthError> {
    std::fs::remove_file(next_key_path(path))?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Replace the file at `path` with `bytes` so a crash leaves either the old
/// contents or the new, never a torn file: write a sibling temp file, fsync
/// it, rename it over `path`, fsync the directory. A plain `fs::write`
/// truncates in place, so a crash mid-write leaves a file that parses as
/// nothing and a server that refuses to boot.
pub(crate) fn write_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut out = std::fs::File::create(&tmp)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    drop(out);
    std::fs::rename(&tmp, path)?;
    sync_parent_dir(path)
}

/// fsync the directory holding `path`, making a rename or unlink in it
/// durable (POSIX: the directory entry is data of the directory).
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Say so when other users can read the signing key file. The server does
/// not change the mode: it is the operator's file, and the keystore's own
/// check likewise only reports a directory it does not own.
#[cfg(unix)]
fn warn_if_readable_by_others(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:04o}"),
                "signing key file is accessible to other users; restrict it to its owner (0600)"
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_readable_by_others(_path: &Path) {}

/// Wall-clock server time in Unix seconds, shared by every auth surface
/// that needs "now" for expiry/window checks (login's timestamp window
/// and token expiry, and route-level bearer verification). A clock set
/// before the Unix epoch yields 0, which fails every window check closed
/// rather than panicking.
pub(crate) fn server_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serde helper for a private key's bytes: base64url, held in a type that
/// wipes them when it drops, with the decoded text wiped too.
mod base64url_secret {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
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
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
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

    /// Backs: `<key>.next` is created owner-only (0600) when no live key
    /// file exists to inherit a mode from, and a leftover wider `.next` is
    /// narrowed. Unit: rotation always reads the live key first, so no
    /// scenario reaches the no-live-file case; a torn earlier staging
    /// leaving a wide `.next` is likewise unschedulable end to end.
    #[cfg(unix)]
    #[test]
    fn stage_key_file_is_owner_only_without_a_live_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");
        let kp = coz::Alg::Ed25519.generate_keypair();
        let next = next_key_path(&path);
        std::fs::write(&next, b"torn").expect("leftover");
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o644)).expect("widen");
        stage_key_file(&path, &kp).expect("stage");
        let mode = std::fs::metadata(&next).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let fresh = dir.path().join("other.json");
        stage_key_file(&fresh, &kp).expect("stage fresh");
        let mode = std::fs::metadata(next_key_path(&fresh))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// Backs: a signing-key file whose public half does not match its private half is refused at
    /// startup (typed error). Unit: startup-only path; the lib test for a broken key path covers
    /// only the missing file.
    #[test]
    fn load_mismatched_pub_key_returns_typed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");
        let kp = coz::Alg::Ed25519.generate_keypair();
        let other_kp = coz::Alg::Ed25519.generate_keypair();
        let file = KeyFile {
            v: FILE_FORMAT_VERSION,
            alg: kp.alg.name().to_string(),
            pub_key: other_kp.pub_bytes, // mismatched on purpose
            prv_key: zeroize::Zeroizing::new(kp.prv_bytes),
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let result = ServerIdentity::load_from_path(&path);
        assert!(matches!(result, Err(AuthError::PublicKeyMismatch)));
    }

    /// Backs: a key file of the wrong shape is refused with an error that
    /// never echoes the offending value -- serde's own type-mismatch text
    /// quotes scalars (`invalid type: integer `N``), and this error reaches
    /// the server log and, via `EarlyExit`, test output.
    /// Backs the shared `json_fault` rule on the client-facing login path: a
    /// wrong-typed payload field is a typed refusal that does not echo it.
    #[test]
    fn malformed_login_payload_does_not_echo_values() {
        let request: cyphr_client::login::LoginRequest =
            serde_json::from_str(r#"{"pay":{"tmb":424242424242},"sig":"AAAA"}"#).expect("shape");
        let login = login::parse_login(&request, "cyphr.me").expect_err("tmb must be a string");
        assert!(matches!(login, login::LoginError::Malformed(_)));
        assert!(!login.to_string().contains("424242424242"), "{login}");
    }

    #[test]
    fn malformed_key_file_error_does_not_echo_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");
        std::fs::write(
            &path,
            br#"{"alg":"Ed25519","pub_key":"AAAA","prv_key":424242424242}"#,
        )
        .unwrap();
        let err =
            ServerIdentity::load_from_path(&path).expect_err("a numeric private key is refused");
        assert!(matches!(err, AuthError::Malformed(_)));
        assert!(
            !err.to_string().contains("424242424242"),
            "the refusal quotes the key file's value: {err}"
        );
    }

    /// Backs: a signing-key file that is not JSON, or names an unknown algorithm, is refused at
    /// startup with a typed error rather than a panic. Unit: startup-only path; the lib test for
    /// a broken key path covers only the missing file.
    #[test]
    fn load_malformed_and_unknown_algorithm_files_are_typed_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");

        std::fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            ServerIdentity::load_from_path(&path),
            Err(AuthError::Malformed(_))
        ));

        let kp = coz::Alg::Ed25519.generate_keypair();
        let file = KeyFile {
            v: FILE_FORMAT_VERSION,
            alg: "NotAnAlgorithm".to_string(),
            pub_key: kp.pub_bytes,
            prv_key: zeroize::Zeroizing::new(kp.prv_bytes),
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(
            ServerIdentity::load_from_path(&path),
            Err(AuthError::UnknownAlgorithm(_))
        ));
    }
}
