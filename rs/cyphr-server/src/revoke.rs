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

/// Verify a naked-revoke request against its DISCLOSED key -- replay-free,
/// self-signed-only, and reading no server state.
///
/// The rule is core's ([`cyphr::revoke::verify_naked_revoke`]), the same
/// one the client's verifier and the engine apply; this adds only the
/// request's own requirement to disclose a key. A missing key, malformed
/// payload, bad `rvk`, oversize payload, wrong `typ`, or a disclosed key
/// that does not hash to its `tmb` is a 400; a signature that does not
/// verify is a 401.
pub async fn interpret(envelope: &NakedRevokeEnvelope) -> Result<VerifiedRevoke, AppError> {
    use cyphr::revoke::RevokeFailure;

    let key = envelope
        .key
        .as_ref()
        .ok_or_else(|| AppError::bad_request("naked revoke must disclose its public key"))?;

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

    // The refusal text is the sender's own material, never reflected back.
    let revoke = cyphr::revoke::verify_naked_revoke(&evidence).map_err(|e| match e {
        RevokeFailure::BadSignature => AppError::unauthorized("revoke signature does not verify"),
        other => AppError::bad_request(other.to_string()),
    })?;

    Ok(VerifiedRevoke {
        revoked_tmb: revoke.tmb,
        rvk: revoke.rvk,
        evidence,
    })
}

/// Record a verified naked revoke in both places the server keeps deaths,
/// in the one order every path uses: the engine first, then the
/// observation set every capability consults.
///
/// The engine's blob-store record is the truth (I1; it judges admission
/// and forks, and a rebuild re-verifies it), so the observation set is
/// written only once the engine holds the revoke: a revoke the engine
/// refuses reaches neither store, and a failure between the two writes
/// leaves the engine dead and the set not, a gap a repeat of the same
/// revoke closes (both writes are idempotent).
///
/// # Errors
///
/// The engine's refusal or storage fault, or the observation set's.
pub(crate) async fn record_everywhere(
    state: &crate::AppState,
    tmb: &Thumbprint,
    evidence: &serde_json::Value,
) -> Result<(), AppError> {
    // The key's cutoff is this node's own receipt time (#203).
    state
        .engine
        .record_revoke(evidence, crate::auth::server_now())
        .await
        .map_err(AppError::engine)?;
    // The ceiling was settled by the caller before the engine wrote
    // (`ObservationStore::has_room`), so this write is unbounded.
    state
        .observations
        .record_seen(tmb, evidence.clone())
        .await
        .map_err(AppError::observation)
}
