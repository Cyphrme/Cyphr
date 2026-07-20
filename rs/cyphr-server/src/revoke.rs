//! Witness ingest of an uncommitted `key/revoke` coz -- a "naked revoke"
//! (SPEC.md §6.4).
//!
//! A naked revoke is a `key/revoke` coz signed *outside* any commit. A
//! witness accepts one, verifies it against the *named* principal's own
//! keys, and interprets it as either a self-signed revoke (the key revoked
//! itself -- proof of possession by its holder) or a third-party claim (an
//! outsider declaring the key compromised). This module is the pure
//! parse-and-verify half; [`crate::routes::revoke`] does the I/O (loading
//! the principal, recording the observation, responding).
//!
//! The design mirrors [`crate::auth::login`]'s split: extraction and
//! verification against the *claimed/named* principal only -- never a
//! global `tmb` index, which would reintroduce the key-sharing ambiguity
//! `auth::login` closes.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;

use crate::error::AppError;
use crate::observation::ObservationKind;

/// Request body for `POST /revoke`.
///
/// `principal_id` is the UNSIGNED target principal whose witness record is
/// annotated (mirrors [`crate::routes::PushRequest`]); `coz` is the signed
/// `key/revoke`. The target principal is named explicitly because the coz
/// itself names only a key (`tmb`), and a key may be shared across
/// principals (SPEC Appendix "Sharing Keys").
#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub principal_id: String,
    pub coz: RevokeCoz,
}

/// The signed naked-revoke coz: a `{pay, sig}` with an optional embedded
/// `key`.
#[derive(Debug, Deserialize)]
pub struct RevokeCoz {
    /// The signed payload, kept as the raw value so the exact bytes the
    /// signature covers are recoverable (`coz::verify_json`
    /// canonicalizes, so field order does not matter).
    pub pay: serde_json::Value,
    /// The detached signature, base64url.
    pub sig: String,
    /// A third party's own key, so a signature made by a key the named
    /// principal does not hold can still be verified -- the only
    /// self-describing way a witness can check such a signature. The exact
    /// third-party mechanism is spec-pending (forge issue #106).
    #[serde(default)]
    pub key: Option<EmbeddedKey>,
}

/// An outsider's key embedded in a third-party revoke coz.
#[derive(Debug, Deserialize)]
pub struct EmbeddedKey {
    pub alg: String,
    #[serde(rename = "pub")]
    pub pub_key: String,
}

/// A verified, interpreted naked revoke.
#[derive(Debug)]
pub struct NakedRevoke {
    /// Self-signed vs third-party -- decided by which key verified the
    /// signature.
    pub kind: ObservationKind,
    /// The revoked key's thumbprint (the coz's `tmb`).
    pub revoked_tmb: Thumbprint,
    /// The revocation timestamp the coz declared.
    pub rvk: i64,
}

/// Whether `typ` is a `key/revoke` under some authority segment, e.g.
/// `cyphr.me/cyphr/key/revoke`. Reuses the core `KEY_REVOKE` constant so
/// the accepted shape cannot drift from the protocol's.
fn is_revoke_typ(typ: &str) -> bool {
    matches!(
        typ.strip_suffix(cyphr::parsed_coz::typ::KEY_REVOKE),
        Some(authority) if authority.ends_with('/')
    )
}

/// Parse, validate, and verify a naked-revoke request against the *named*
/// `principal` (already loaded by the caller).
///
/// Verification order, each a distinct rejection:
/// 1. the payload parses and its `typ` is a `key/revoke`;
/// 2. `rvk` is a positive integer below 2^53-1 (`coz::is_valid_rvk`);
/// 3. the revoked `tmb` is a key *this* named principal holds;
/// 4. the signature verifies -- under the revoked key itself (self-signed)
///    or, failing that, under an embedded outsider key (third-party).
///
/// A malformed payload, bad `rvk`, wrong `typ`, or a `tmb` the principal
/// does not hold is a 400; a signature that verifies under no available
/// key is a 401.
pub fn interpret<S: eml::Storage>(
    request: &RevokeRequest,
    principal: &cyphr::Principal<S>,
) -> Result<NakedRevoke, AppError> {
    let pay_bytes = serde_json::to_vec(&request.coz.pay)
        .map_err(|e| AppError::bad_request(format!("revoke payload not serializable: {e}")))?;
    let pay: coz::Pay = serde_json::from_value(request.coz.pay.clone())
        .map_err(|e| AppError::bad_request(format!("malformed revoke payload: {e}")))?;

    let typ = pay.typ.as_deref().unwrap_or_default();
    if !is_revoke_typ(typ) {
        return Err(AppError::bad_request(format!(
            "coz typ `{typ}` is not a key/revoke"
        )));
    }

    let rvk = pay
        .rvk
        .ok_or_else(|| AppError::bad_request("revoke payload has no rvk"))?;
    if !coz::is_valid_rvk(rvk) {
        return Err(AppError::bad_request(format!(
            "rvk {rvk} is not a positive integer below 2^53-1"
        )));
    }

    let tmb = pay
        .tmb
        .clone()
        .ok_or_else(|| AppError::bad_request("revoke payload names no key (tmb)"))?;

    let sig = Base64UrlUnpadded::decode_vec(&request.coz.sig)
        .map_err(|e| AppError::bad_request(format!("revoke signature is not base64url: {e}")))?;

    // The revoked key must be one THIS named principal holds -- never a
    // global tmb index (preserves the key-sharing rule auth::login keeps).
    let key = principal
        .get_key(&tmb)
        .ok_or_else(|| AppError::bad_request("revoked key is not held by the named principal"))?;

    // Self-signed iff the signature verifies under the revoked key itself.
    if coz::verify_json(&pay_bytes, &sig, &key.alg, &key.pub_key) == Some(true) {
        return Ok(NakedRevoke {
            kind: ObservationKind::SelfRevoke,
            revoked_tmb: tmb,
            rvk,
        });
    }

    // Otherwise an outsider may be declaring the key compromised, proven by
    // a signature under a key embedded in the coz (spec-pending, #106).
    if let Some(embedded) = &request.coz.key {
        let pub_bytes = Base64UrlUnpadded::decode_vec(&embedded.pub_key).map_err(|e| {
            AppError::bad_request(format!("embedded key `pub` is not base64url: {e}"))
        })?;
        if coz::verify_json(&pay_bytes, &sig, &embedded.alg, &pub_bytes) == Some(true) {
            return Ok(NakedRevoke {
                kind: ObservationKind::ThirdParty,
                revoked_tmb: tmb,
                rvk,
            });
        }
    }

    Err(AppError::unauthorized("revoke signature does not verify"))
}
