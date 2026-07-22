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
//! The global key index is a CACHE, never an authority: its CONTENT is never
//! dereferenced in this verification path. Its only remaining role is a
//! **presence fence** -- the named `tmb` must be a key the server has indexed --
//! which bounds the death-set to keys the server has seen (anti-spam) without
//! ever reading the indexed value. Because verification depends only on the
//! material the client discloses, a poisoned index entry (an attacker's pub
//! stored under a victim's `tmb`) cannot block the victim's own emergency
//! revoke -- the §6.4 availability property.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::index::Indexer;
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

/// Whether `typ` is a `key/revoke` under some authority segment, e.g.
/// `cyphr.me/cyphr/key/revoke`. Reuses the core `KEY_REVOKE` constant so the
/// accepted shape cannot drift from the protocol's.
fn is_revoke_typ(typ: &str) -> bool {
    matches!(
        typ.strip_suffix(cyphr::parsed_coz::typ::KEY_REVOKE),
        Some(authority) if authority.ends_with('/')
    )
}

/// Parse, validate, and verify a naked-revoke request against its DISCLOSED
/// key -- replay-free, self-signed-only, and independent of the index's
/// content.
///
/// Verification order, each a distinct rejection:
/// 1. the body discloses a `key` (else 400 -- a naked revoke must disclose it);
/// 2. the payload parses and its `typ` is a `key/revoke`;
/// 3. `rvk` is a positive integer below 2^53-1 (`coz::is_valid_rvk`); the timestamp value itself is
///    NOT checked, so a pre-signed `rvk`=1 is valid;
/// 4. the serialized payload is within `RVK_MAX_SIZE`;
/// 5. PRESENCE FENCE: the named `tmb` is a key the engine has indexed (`Some`) -- the indexed value's
///    CONTENT is never read; `None` (a key this server never saw) is a rejection that bounds the
///    death-set to seen keys;
/// 6. BIND: the disclosed key hashes back to the named `tmb` (`tmb = H(pub)`), welding the disclosed
///    key to the thumbprint before it is trusted;
/// 7. VERIFY: the signature verifies against the DISCLOSED key. A revoke signed by any key OTHER
///    than the one `tmb` names fails here -- the entire self-signed-only rule.
///
/// A missing key, malformed payload, bad `rvk`, wrong `typ`, an unknown `tmb`,
/// or a disclosed key that does not hash to its `tmb` is a 400; a signature that
/// does not verify is a 401; an index infrastructure failure is a 500.
pub async fn interpret<I: Indexer>(
    envelope: &NakedRevokeEnvelope,
    indexer: &I,
) -> Result<VerifiedRevoke, AppError> {
    let key = envelope
        .key
        .as_ref()
        .ok_or_else(|| AppError::bad_request("naked revoke must disclose its public key"))?;

    let pay_bytes = serde_json::to_vec(&envelope.pay)
        .map_err(|e| AppError::bad_request(format!("revoke payload not serializable: {e}")))?;
    let pay: coz::Pay = serde_json::from_value(envelope.pay.clone())
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
    let tmb_b64 = Base64UrlUnpadded::encode_string(tmb.as_bytes());

    // PRESENCE FENCE: the named `tmb` must be a key the engine has indexed. This
    // is the index's ONLY remaining role -- presence, never content. The
    // returned value is deliberately never read: verification below runs
    // entirely off the DISCLOSED key, so a poisoned index entry (an attacker's
    // pub under a victim's `tmb`) still passes this fence but cannot influence
    // the outcome. `None` bounds the death-set to keys the server has seen.
    let indexed = indexer.get_key(&tmb_b64).await.map_err(|e| {
        tracing::error!(error = %e, "naked-revoke presence-fence lookup failed");
        AppError::internal("key index lookup failed")
    })?;
    if indexed.is_none() {
        return Err(AppError::bad_request(
            "revoke names a key this server has not indexed",
        ));
    }

    // BIND: the disclosed key must hash back to the named `tmb` (`tmb = H(pub)`).
    // This weld is what keeps the revoke self-signed-only and forge-proof: to
    // kill `tmb` T an attacker must present a `pub` with `H(pub) = T`, a preimage
    // only T's holder has. Without this bind the signature check below would be
    // tautological -- any key could "revoke" any `tmb`.
    let recomputed =
        coz::compute_thumbprint_for_alg(&key.alg, &key.pub_key).ok_or_else(|| {
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
