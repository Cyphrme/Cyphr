//! The signing seam: commit finalization signs through a [`Signer`] that
//! never has to expose its key bytes, so non-exportable keys (hardware,
//! WebCrypto) can sign.
//!
//! # Contract
//!
//! - [`Signer::sign`] receives the Coz `cad` (the canonical hash of the pay) and returns the
//!   signature over it.
//! - The signer OWNS signature canonicality. For ECDSA algorithms it MUST return the low-S form
//!   (`coz` verification rejects high-S). Backends that return another encoding (PKCS#11 raw `r ||
//!   s` with arbitrary S, Secure Enclave DER) normalize before returning. The core never
//!   normalizes: it verifies the signature with `coz::verify_json` and rejects anything that does
//!   not verify as [`Error::InvalidSignature`](crate::Error), so one party owns the rule and a
//!   violation cannot be committed.
//! - Failure is a [`SignerError`], never an empty signature.
//! - The returned future is not required to be `Send` (WebCrypto futures are not).

use std::future::Future;
use std::task::{Context, Poll, Waker};

use coz::{Cad, Thumbprint};

/// A signing backend failed to produce a signature.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The backend reported failure (device unavailable, user denied, ...).
    #[error("signer backend failure: {0}")]
    Backend(String),
}

/// A key that signs Coz `cad` values without exposing private-key bytes.
pub trait Signer {
    /// Coz algorithm name of the key (e.g. `"ES256"`).
    fn alg(&self) -> &str;

    /// Public key bytes, in the form `coz::verify_json` accepts.
    fn pub_key(&self) -> &[u8];

    /// Thumbprint of the key.
    fn tmb(&self) -> &Thumbprint;

    /// Sign `cad`, returning the canonical (low-S) signature. See the module
    /// contract. Deliberately `-> impl Future` with no `Send` bound.
    fn sign(&self, cad: &Cad) -> impl Future<Output = Result<Vec<u8>, SignerError>>;
}

/// In-memory software [`Signer`] holding raw private-key bytes. Its future
/// completes on first poll, which [`SoftwareSigner::sign_now`] relies on.
pub struct SoftwareSigner {
    alg: String,
    prv: zeroize::Zeroizing<Vec<u8>>,
    pub_key: Vec<u8>,
    tmb: Thumbprint,
}

impl SoftwareSigner {
    /// Wrap key material. Validity of `prv` is checked at signing time.
    pub fn new(alg: &str, prv: &[u8], pub_key: &[u8], tmb: &Thumbprint) -> Self {
        Self {
            alg: alg.to_string(),
            prv: zeroize::Zeroizing::new(prv.to_vec()),
            pub_key: pub_key.to_vec(),
            tmb: tmb.clone(),
        }
    }

    fn sign_cad(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        use coz::{ES256, ES384, ES512, Ed25519, signing_key_from_bytes};
        let bad_key = || SignerError::Backend(format!("invalid {} private key", self.alg));
        let sig = match self.alg.as_str() {
            "ES256" => signing_key_from_bytes::<ES256>(&self.prv)
                .ok_or_else(bad_key)?
                .sign(cad.as_bytes()),
            "ES384" => signing_key_from_bytes::<ES384>(&self.prv)
                .ok_or_else(bad_key)?
                .sign(cad.as_bytes()),
            "ES512" => signing_key_from_bytes::<ES512>(&self.prv)
                .ok_or_else(bad_key)?
                .sign(cad.as_bytes()),
            "Ed25519" => signing_key_from_bytes::<Ed25519>(&self.prv)
                .ok_or_else(bad_key)?
                .sign(cad.as_bytes()),
            other => {
                return Err(SignerError::Backend(format!("unsupported alg {other}")));
            },
        };
        // coz signals internal signing failure with an empty signature.
        if sig.is_empty() {
            return Err(SignerError::Backend("signing produced no signature".into()));
        }
        Ok(sig)
    }

    /// Synchronous signing for callers with no executor. Exact because this
    /// signer never suspends.
    pub fn sign_now(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        let mut fut = std::pin::pin!(self.sign(cad));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(SignerError::Backend(
                "software signer unexpectedly suspended".into(),
            )),
        }
    }
}

impl Signer for SoftwareSigner {
    fn alg(&self) -> &str {
        &self.alg
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn tmb(&self) -> &Thumbprint {
        &self.tmb
    }

    async fn sign(&self, cad: &Cad) -> Result<Vec<u8>, SignerError> {
        self.sign_cad(cad)
    }
}
