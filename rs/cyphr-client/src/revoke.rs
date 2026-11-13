//! Verification of a naked revoke (SPEC 6.4): a `key/revoke` coz signed
//! outside any commit, by the key it names.
//!
//! The check reads nothing but the envelope. It discloses the public key,
//! requires that key to hash to the named `tmb` and to verify the coz's
//! own signature, so a revoke signed by any other key is refused: a peer
//! can serve a revoke but cannot forge one. The same rules gate the
//! server's `POST /revoke`.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

/// A naked revoke whose self-signature verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NakedRevoke {
    /// The revoked key.
    pub tmb: Thumbprint,
    /// The revocation time the coz declared. It decides nothing: a key's
    /// cutoff is the receiver's own clock when it accepts the revoke
    /// (SPEC 14.12).
    pub rvk: i64,
}

/// Why a served naked revoke was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevokeFailure {
    /// The envelope is not `{pay, sig, key: {alg, pub}}`.
    #[error("naked revoke is malformed: {0}")]
    Malformed(&'static str),
    /// The coz is not a `key/revoke`.
    #[error("coz typ `{0}` is not a key/revoke")]
    NotARevoke(String),
    /// `rvk` is absent or outside `1..=2^53-1`.
    #[error("rvk is not an integer in 1..=2^53-1")]
    BadRvk,
    /// The disclosed key does not hash to the revoked `tmb`, or its
    /// algorithm is unsupported.
    #[error("the disclosed key does not hash to the revoked thumbprint")]
    KeyMismatch,
    /// The signature does not verify against the disclosed key.
    #[error("the revoke signature does not verify")]
    BadSignature,
}

fn text<'a>(v: Option<&'a Value>, what: &'static str) -> Result<&'a str, RevokeFailure> {
    v.and_then(Value::as_str)
        .ok_or(RevokeFailure::Malformed(what))
}

/// Verify one served naked-revoke envelope.
///
/// # Errors
///
/// A [`RevokeFailure`] naming the first rule the envelope breaks.
pub fn verify_naked_revoke(envelope: &Value) -> Result<NakedRevoke, RevokeFailure> {
    let pay = envelope
        .get("pay")
        .ok_or(RevokeFailure::Malformed("no pay"))?;
    let sig = Base64UrlUnpadded::decode_vec(text(envelope.get("sig"), "no sig")?)
        .map_err(|_| RevokeFailure::Malformed("sig is not base64url"))?;
    let key = envelope
        .get("key")
        .ok_or(RevokeFailure::Malformed("no disclosed key"))?;
    let alg = text(key.get("alg"), "key has no alg")?;
    let public = Base64UrlUnpadded::decode_vec(text(key.get("pub"), "key has no pub")?)
        .map_err(|_| RevokeFailure::Malformed("pub is not base64url"))?;

    let typ = text(pay.get("typ"), "pay has no typ")?;
    if !cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::KEY_REVOKE) {
        return Err(RevokeFailure::NotARevoke(typ.to_owned()));
    }
    let rvk = pay
        .get("rvk")
        .and_then(Value::as_i64)
        .filter(|r| coz::is_valid_rvk(*r))
        .ok_or(RevokeFailure::BadRvk)?;
    let tmb = Base64UrlUnpadded::decode_vec(text(pay.get("tmb"), "pay names no tmb")?)
        .map(Thumbprint::from_bytes)
        .map_err(|_| RevokeFailure::Malformed("tmb is not base64url"))?;

    if coz::compute_thumbprint_for_alg(alg, &public).as_ref() != Some(&tmb) {
        return Err(RevokeFailure::KeyMismatch);
    }
    let pay_bytes = serde_json::to_vec(pay).map_err(|_| RevokeFailure::Malformed("pay"))?;
    if coz::verify_json(&pay_bytes, &sig, alg, &public) != Some(true) {
        return Err(RevokeFailure::BadSignature);
    }
    Ok(NakedRevoke { tmb, rvk })
}
