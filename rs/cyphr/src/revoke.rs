//! The one validity rule for a naked revoke (SPEC 6.4): a `key/revoke` coz
//! signed outside any commit, by the key it names.
//!
//! The check reads nothing but the envelope. It discloses the public key,
//! requires that key to hash to the named `tmb` and to verify the coz's
//! own signature, so a revoke signed by any other key is refused: a peer
//! can serve a revoke but cannot forge one.
//!
//! A naked revoke is valid iff it is Coz-valid: a `key/revoke` typ, `rvk`
//! an integer in `1..=2^53-1`, the payload within the Coz revoke size
//! limit, a self-signature. `now` is not required, and nothing about the
//! revoke's own time decides anything: the cutoff is the receiving node's
//! own receipt time (spec author on #203: "Coz valid revokes are always
//! accepted", "honor it from the witness's own receipt time"). Every
//! consumer -- the client's verifier, the server's `POST /revoke`,
//! gossip ingest and the storage engine's record -- calls this function,
//! so no path can accept what another refuses.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use crate::error::Error;
use crate::key::Key;
use crate::parsed_coz::verify_signed;

/// The instant a revoke takes a key out: the key is dead from here on
/// (SPEC 6.4). The one place the comparison is made, so no consumer
/// decides "revoked at `now`" or "which of two revokes stands" itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cutoff(pub i64);

impl Cutoff {
    /// Whether a statement dated `now` is stopped by this cutoff: always
    /// when it carries no date, otherwise from the cutoff on.
    #[must_use]
    pub fn stops(self, now: Option<i64>) -> bool {
        now.is_none_or(|n| n >= self.0)
    }

    /// Whether a period of a key's life that ends at `until` (`None`: still
    /// open) runs past this cutoff and so is cut short by it. A period
    /// ending exactly at the cutoff is not.
    #[must_use]
    pub fn runs_past(self, until: Option<i64>) -> bool {
        until.is_none_or(|u| u > self.0)
    }

    /// Where a period that began at `from` ends when this cutoff cuts it:
    /// at the cutoff, but no earlier than the period began.
    #[must_use]
    pub fn end_of_period_from(self, from: i64) -> i64 {
        self.0.max(from)
    }

    /// The cutoff that stands when two revokes of one key are known: the
    /// earlier, whichever arrived first.
    #[must_use]
    pub fn earliest(self, other: Cutoff) -> Cutoff {
        self.min(other)
    }
}

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
    /// The serialized payload exceeds the Coz revoke size limit.
    #[error("revoke payload is {size} bytes, over the {max}-byte limit")]
    TooLarge {
        /// The serialized payload size.
        size: usize,
        /// The limit ([`coz::RVK_MAX_SIZE`]).
        max: usize,
    },
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

/// Verify one naked-revoke envelope `{pay, sig, key: {alg, pub}}`.
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
    if !crate::parsed_coz::typ::has_suffix(typ, crate::parsed_coz::typ::KEY_REVOKE) {
        return Err(RevokeFailure::NotARevoke(typ.to_owned()));
    }
    let rvk = pay
        .get("rvk")
        .and_then(Value::as_i64)
        .filter(|r| coz::is_valid_rvk(*r))
        .ok_or(RevokeFailure::BadRvk)?;
    let pay_bytes = serde_json::to_vec(pay).map_err(|_| RevokeFailure::Malformed("pay"))?;
    // Parsed only to ask coz whether this payload is a revoke over the
    // limit; `coz` owns that rule, and the typ check above already
    // established it is one.
    let parsed: coz::Pay = serde_json::from_value(pay.clone())
        .map_err(|_| RevokeFailure::Malformed("pay is not a coz payload"))?;
    if coz::validate_revoke_size(&parsed, pay_bytes.len()).is_err() {
        return Err(RevokeFailure::TooLarge {
            size: pay_bytes.len(),
            max: coz::RVK_MAX_SIZE,
        });
    }
    let tmb = Base64UrlUnpadded::decode_vec(text(pay.get("tmb"), "pay names no tmb")?)
        .map(Thumbprint::from_bytes)
        .map_err(|_| RevokeFailure::Malformed("tmb is not base64url"))?;

    let key = Key::from_pub_key(alg, public).map_err(|_| RevokeFailure::KeyMismatch)?;
    verify_signed(&pay_bytes, &sig, &key)
        .map(drop)
        .map_err(|e| match e {
            // The fields `verify_signed` reads were checked above except
            // `alg`, so this is a pay with none (SPEC 2.3.1).
            Error::MalformedPayload => RevokeFailure::Malformed("pay has no alg"),
            Error::AlgMismatch | Error::UnknownKey | Error::UnsupportedAlgorithm(_) => {
                RevokeFailure::KeyMismatch
            },
            Error::InvalidSignature => RevokeFailure::BadSignature,
            // `verify_signed` returns no other variant; fail closed.
            _ => RevokeFailure::BadSignature,
        })?;
    Ok(NakedRevoke { tmb, rvk })
}
