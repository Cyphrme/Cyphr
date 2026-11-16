//! Witness ingest of an uncommitted `key/revoke` coz -- a "naked revoke"
//! (SPEC.md §6.4, confirmed model) under the **disclosed-key** model.
//!
//! A naked revoke is a `key/revoke` coz signed *outside* any commit. Under
//! the confirmed model a witness accepts one iff it is **self-signed**: the
//! key named by the coz's `tmb` signs its own revoke. The request DISCLOSES
//! that public key; verification recomputes `tmb = H(disclosed pub)` and checks
//! the signature against the SAME disclosed key. A revoke signed by any key
//! OTHER than the one it names fails the signature check, and a disclosed key
//! that does not hash to the named `tmb` fails the bind -- together they are the
//! self-signed-only rule, so there is no third-party path.
//!
//! Verification reads no server state: it depends only on the material the
//! client discloses, so a poisoned index entry (an attacker's pub stored under
//! a victim's `tmb`) cannot block the victim's own emergency revoke -- the
//! §6.4 availability property. Nor does it require the server to have seen
//! the key: a Level 1 principal signs nothing a peer could have seen (SPEC
//! 3.1, 5.1: no commit), yet its self-revoke must be recordable. The death
//! set is bounded instead by the operator's quota (`[limits] max_dead_keys`)
//! and the `/revoke` rate buckets. Past the quota, the revoke of a key some
//! stored principal holds is still recorded (the route checks presence only
//! then). Residual risk: while the set is full, the revoke of a Level 1 key
//! this server never saw is refused (`507`), so a flood of junk revokes can
//! deny that one case until the operator raises the quota.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;

use crate::error::AppError;

/// A naked-revoke request in the disclosed-key wire shape: the signed
/// `key/revoke` coz PLUS the public key it names. `key` is REQUIRED; it is
/// typed `Option` only so an absent key yields a controlled 400 through
/// [`AppError`] rather than an axum extractor rejection whose body is not the
/// `{"error": ..}` shape clients parse.
#[derive(Debug, Deserialize)]
pub struct NakedRevokeEnvelope {
    /// The `key/revoke` payload, as raw JSON (signed verbatim).
    pub pay: serde_json::Value,
    /// The detached signature over `pay` (base64url in JSON).
    #[serde(with = "coz::b64")]
    pub sig: Vec<u8>,
    /// The disclosed public key the revoke names. Absent => the request is
    /// rejected (a naked revoke must disclose its key).
    pub key: Option<DisclosedKey>,
}

/// The disclosed public key of a naked revoke, in the wire shape the rest of
/// the protocol uses (`{ "alg", "pub" }`, `pub` base64url).
#[derive(Debug, Deserialize)]
pub struct DisclosedKey {
    /// The key's algorithm (e.g. `ES256`).
    pub alg: String,
    /// The public key bytes (base64url in JSON, wire field `pub`).
    #[serde(rename = "pub", with = "coz::b64")]
    pub pub_key: Vec<u8>,
}

/// A verified naked revoke: its self-signature checked out against the
/// disclosed key, which hashes back to the named `tmb`.
#[derive(Debug)]
pub struct VerifiedRevoke {
    /// The revoked key's thumbprint (the coz's `tmb`), now dead globally.
    pub revoked_tmb: Thumbprint,
    /// The revocation timestamp the coz declared.
    pub rvk: i64,
    /// The full `{pay, sig, key}` envelope as verified -- self-contained,
    /// independently re-verifiable evidence to store in the death-set (needs no
    /// index to re-check).
    pub evidence: serde_json::Value,
}

/// Parse, validate, and verify a naked-revoke request against its DISCLOSED
/// key -- replay-free, self-signed-only, and reading no server state.
///
/// Verification order, each a distinct rejection:
/// 1. the body discloses a `key` (else 400 -- a naked revoke must disclose it);
/// 2. the payload parses and its `typ` is a `key/revoke`;
/// 3. `rvk` is a integer in 1..=2^53-1 (`coz::is_valid_rvk`); the timestamp value itself is NOT
///    checked, so a pre-signed `rvk`=1 is valid;
/// 4. the serialized payload is within `RVK_MAX_SIZE`;
/// 5. BIND: the disclosed key hashes back to the named `tmb` (`tmb = H(pub)`), welding the
///    disclosed key to the thumbprint before it is trusted;
/// 6. VERIFY: the signature verifies against the DISCLOSED key. A revoke signed by any key OTHER
///    than the one `tmb` names fails here -- the entire self-signed-only rule.
///
/// A missing key, malformed payload, bad `rvk`, wrong `typ`, or a disclosed
/// key that does not hash to its `tmb` is a 400; a signature that does not
/// verify is a 401.
pub async fn interpret(envelope: &NakedRevokeEnvelope) -> Result<VerifiedRevoke, AppError> {
    let key = envelope
        .key
        .as_ref()
        .ok_or_else(|| AppError::bad_request("naked revoke must disclose its public key"))?;

    let pay_bytes = serde_json::to_vec(&envelope.pay).map_err(|e| {
        AppError::bad_request(format!(
            "revoke payload not serializable ({})",
            crate::auth::json_fault(&e)
        ))
    })?;
    let pay: coz::Pay = serde_json::from_value(envelope.pay.clone()).map_err(|e| {
        AppError::bad_request(format!(
            "malformed revoke payload ({})",
            crate::auth::json_fault(&e)
        ))
    })?;

    let typ = pay.typ.as_deref().unwrap_or_default();
    if !cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::KEY_REVOKE) {
        // The typ is the sender's own text; it is not reflected back.
        return Err(AppError::bad_request("coz typ is not a key/revoke"));
    }

    let rvk = pay
        .rvk
        .ok_or_else(|| AppError::bad_request("revoke payload has no rvk"))?;
    if !coz::is_valid_rvk(rvk) {
        return Err(AppError::bad_request(format!(
            "rvk {rvk} is not an integer in 1..=2^53-1"
        )));
    }

    // Bound the revoke to the coz standard's `RVK_MAX_SIZE` (2048 bytes),
    // measured over the serialized payload. An oversized revoke is a
    // semantically valid payload the size limit alone rejects, so this is the
    // authoritative semantic check (never a parse or signature failure).
    coz::validate_revoke_size(&pay, pay_bytes.len())
        .map_err(|e| AppError::bad_request(e.to_string()))?;

    let tmb = pay
        .tmb
        .clone()
        .ok_or_else(|| AppError::bad_request("revoke payload names no key (tmb)"))?;

    // BIND: the disclosed key must hash back to the named `tmb` (`tmb = H(pub)`).
    // This weld is what keeps the revoke self-signed-only and forge-proof: to
    // kill `tmb` T an attacker must present a `pub` with `H(pub) = T`, a preimage
    // only T's holder has. Without this bind the signature check below would be
    // tautological -- any key could "revoke" any `tmb`.
    let recomputed = coz::compute_thumbprint_for_alg(&key.alg, &key.pub_key).ok_or_else(|| {
        AppError::bad_request(format!("revoke key algorithm `{}` is unsupported", key.alg))
    })?;
    if recomputed != tmb {
        return Err(AppError::bad_request(
            "disclosed key does not hash to the revoked thumbprint",
        ));
    }

    // VERIFY: the signature must verify against the DISCLOSED key -- a revoke
    // signed by any other key fails here (self-signed-only).
    if coz::verify_json(&pay_bytes, &envelope.sig, &key.alg, &key.pub_key) != Some(true) {
        return Err(AppError::unauthorized("revoke signature does not verify"));
    }

    // The full envelope is self-contained, independently re-verifiable evidence:
    // storing it lets any later reader re-check the death with no index.
    let evidence = serde_json::json!({
        "pay": envelope.pay,
        "sig": Base64UrlUnpadded::encode_string(&envelope.sig),
        "key": {
            "alg": key.alg,
            "pub": Base64UrlUnpadded::encode_string(&key.pub_key),
        },
    });

    Ok(VerifiedRevoke {
        revoked_tmb: tmb,
        rvk,
        evidence,
    })
}
