//! The one validity rule for a resync proof of possession (SPEC 13,
//! 15.8 item 2): a `resync/create` coz signed outside any commit, naming
//! the Principal Root of the tip the principal asserts.
//!
//! The coz is `{pay, sig}`. `pay.id` is the asserted tip's PR (a digest in
//! the coz's `alg`), `pay.tmb` the signer, `pay.now` required. The proof
//! mutates no root. Two steps, because the signer is a key of the
//! *asserted* state, which only a holder of that state can name:
//! [`parse_resync`] reads the envelope, and [`verify_resync`] checks the
//! signature against the key the holder finds at the tip. Every consumer
//! -- a storage engine, a verifier, a relying party -- calls these, so no
//! path accepts what another refuses.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use crate::key::Key;

/// A resync proof of possession's declared fields, before its signature is
/// checked against a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resync {
    /// The signing key.
    pub tmb: Thumbprint,
    /// The asserted tip's Principal Root.
    pub id: String,
    /// The time the signer declared. Required; no window is tested on
    /// receipt (a window would make the effect depend on when a holder
    /// hears of the proof), so it decides only the key-death gate.
    pub now: i64,
}

/// Why a resync proof was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResyncFailure {
    /// The envelope is not `{pay, sig}` with the fields a proof needs.
    #[error("resync proof is malformed: {0}")]
    Malformed(&'static str),
    /// The coz is not a `resync/create`.
    #[error("coz typ `{0}` is not a resync/create")]
    NotAResync(String),
    /// The key does not hash to the signer's thumbprint, or its algorithm
    /// is not the coz's.
    #[error("the key is not the proof's signer")]
    KeyMismatch,
    /// The signature does not verify against the key.
    #[error("the resync signature does not verify")]
    BadSignature,
}

fn text<'a>(v: Option<&'a Value>, what: &'static str) -> Result<&'a str, ResyncFailure> {
    v.and_then(Value::as_str)
        .ok_or(ResyncFailure::Malformed(what))
}

/// Read one resync envelope `{pay, sig}`.
///
/// # Errors
///
/// A [`ResyncFailure`] naming the first field it lacks.
pub fn parse_resync(envelope: &Value) -> Result<Resync, ResyncFailure> {
    let pay = envelope
        .get("pay")
        .ok_or(ResyncFailure::Malformed("no pay"))?;
    text(envelope.get("sig"), "no sig")?;
    let typ = text(pay.get("typ"), "pay has no typ")?;
    if !crate::parsed_coz::typ::has_suffix(typ, crate::parsed_coz::typ::RESYNC_CREATE) {
        return Err(ResyncFailure::NotAResync(typ.to_owned()));
    }
    let id = text(pay.get("id"), "pay names no id")?.to_owned();
    let now = pay
        .get("now")
        .and_then(Value::as_i64)
        .ok_or(ResyncFailure::Malformed("pay has no integer now"))?;
    let tmb = Base64UrlUnpadded::decode_vec(text(pay.get("tmb"), "pay names no tmb")?)
        .map(Thumbprint::from_bytes)
        .map_err(|_| ResyncFailure::Malformed("tmb is not base64url"))?;
    Ok(Resync { tmb, id, now })
}

/// Check `envelope`'s signature against `key`, the signer as the holder
/// finds it in the asserted state.
///
/// # Errors
///
/// A [`ResyncFailure`] naming the first rule the envelope breaks.
pub fn verify_resync(envelope: &Value, key: &Key) -> Result<Resync, ResyncFailure> {
    let resync = parse_resync(envelope)?;
    let pay = &envelope["pay"];
    if key.tmb() != &resync.tmb || pay.get("alg").and_then(Value::as_str) != Some(key.alg()) {
        return Err(ResyncFailure::KeyMismatch);
    }
    let sig = Base64UrlUnpadded::decode_vec(text(envelope.get("sig"), "no sig")?)
        .map_err(|_| ResyncFailure::Malformed("sig is not base64url"))?;
    let pay_bytes = serde_json::to_vec(pay).map_err(|_| ResyncFailure::Malformed("pay"))?;
    if coz::verify_json(&pay_bytes, &sig, key.alg(), key.pub_key()) != Some(true) {
        return Err(ResyncFailure::BadSignature);
    }
    Ok(resync)
}
