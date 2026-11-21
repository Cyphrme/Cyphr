//! The key backend seam: every key operation a client performs goes through
//! [`KeyBackend`], which generates keys inside the backend and signs with
//! them, and has no method that returns private-key bytes. Hardware,
//! encrypted and OS-keychain backends implement the same trait; the
//! plaintext [`JsonKeyStore`] is the software backend.

mod json;

use cyphr::signer::Signer;
pub use json::{ExposedDir, JsonKeyStore, Tightened};

/// What `key list` says about every key the [`JsonKeyStore`] holds: the
/// private key is in the file as plain bytes. No encryption exists yet, and
/// custody cannot be recorded.
pub const SOFTWARE_CUSTODY: &str = "software-held, unencrypted";

/// Error type for key backend operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading or writing keystore file.
    #[error("keystore I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A filesystem operation on a named path failed.
    #[error("keystore: {op} {path}: {source}")]
    IoAt {
        /// What was being done.
        op: &'static str,
        /// The file or directory involved.
        path: std::path::PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

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

    /// A thumbprint that is not base64url.
    #[error("invalid thumbprint {0}: not base64url")]
    InvalidThumbprint(String),

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

/// What a backend reports about a key it holds: everything but the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Coz algorithm name (`ES256`, `ES384`, `ES512`, `Ed25519`).
    pub alg: String,
    /// Public key bytes.
    pub pub_key: Vec<u8>,
    /// Thumbprint, base64url (the key's name in the backend).
    pub tmb: String,
    /// Optional human-readable tag.
    pub tag: Option<String>,
}

/// A place keys live. Private-key material is created inside the backend
/// and only ever used through the [`Signer`] it hands out; there is
/// deliberately no way to read it back or to import it through this trait.
///
/// Mutating operations are durable when they return.
pub trait KeyBackend {
    /// The signer this backend hands out.
    type Signer: Signer;

    /// Generate a key for `alg` inside the backend and persist it.
    fn generate(&mut self, alg: &str, tag: Option<&str>) -> Result<PublicKeyInfo, Error>;

    /// Every key the backend holds.
    fn list(&self) -> Result<Vec<PublicKeyInfo>, Error>;

    /// Public information for the key with thumbprint `tmb`.
    fn public(&self, tmb: &str) -> Result<PublicKeyInfo, Error>;

    /// Remove the key with thumbprint `tmb` and persist the removal.
    fn remove(&mut self, tmb: &str) -> Result<(), Error>;

    /// A signer for the key with thumbprint `tmb`.
    fn signer(&self, tmb: &str) -> Result<Self::Signer, Error>;
}
