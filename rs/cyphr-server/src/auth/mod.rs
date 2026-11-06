//! Server authentication and signing identity.
//!
//! This module root holds the server's own signing key
//! ([`ServerIdentity`]) and is the home later campaign nodes extend with
//! bearer-token issuance, login flows, and route protection (SPEC.md
//! 17.4). This node only establishes the identity.
//!
//! The server holds one signing key, loaded from a file at startup, and
//! uses it to sign and verify its own Coz payloads (SPEC.md 17.4 bearer
//! token issuance signs with this key). Consumers hold a [`ServerIdentity`]
//! rather than raw key bytes, so a later campaign can back the same
//! abstraction with a full Cyphr principal without rewriting call sites.

pub mod login;
pub mod middleware;
pub mod principal;
pub mod token;

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Errors loading or using a server signing identity.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// I/O error reading the key file.
    #[error("signing key file: {0}")]
    Io(#[from] std::io::Error),

    /// The key file was not valid JSON in the expected shape.
    #[error("signing key file is malformed: {0}")]
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
    #[serde(with = "base64url_bytes")]
    prv_key: Vec<u8>,
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
    prv_bytes: Vec<u8>,
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
        let content = std::fs::read_to_string(path)?;
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

/// Write a keypair to a signing-key file in the on-disk [`KeyFile`] format
/// that [`ServerIdentity::load_from_path`] reads back.
///
/// Used by the server principal's key rotation to persist the freshly
/// activated key, so a later boot loads the new key rather than the retired
/// one (see [`principal`]).
pub(crate) fn write_key_file(path: &Path, kp: &coz::KeyPair) -> Result<(), AuthError> {
    let file = KeyFile {
        v: FILE_FORMAT_VERSION,
        alg: kp.alg.name().to_string(),
        pub_key: kp.pub_bytes.clone(),
        prv_key: kp.prv_bytes.clone(),
    };
    std::fs::write(path, serde_json::to_vec(&file)?)?;
    Ok(())
}

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
            prv_key: kp.prv_bytes,
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let result = ServerIdentity::load_from_path(&path);
        assert!(matches!(result, Err(AuthError::PublicKeyMismatch)));
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
            prv_key: kp.prv_bytes,
        };
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert!(matches!(
            ServerIdentity::load_from_path(&path),
            Err(AuthError::UnknownAlgorithm(_))
        ));
    }
}
