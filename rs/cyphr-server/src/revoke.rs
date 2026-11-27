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
/// `key/revoke` coz PLUS the public key it names, in `keys` (SPEC 4.6.1), an
/// array of exactly one. `keys` is REQUIRED; it is typed `Option` only so an
/// absent field yields a controlled 400 through
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
    /// rejected (a naked revoke must disclose its key); any count but one is
    /// refused by the core rule.
    pub keys: Option<Vec<DisclosedKey>>,
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
    /// The full `{pay, sig, keys}` envelope as verified -- self-contained,
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

    let keys = envelope
        .keys
        .as_ref()
        .ok_or_else(|| AppError::bad_request("naked revoke must disclose its public key"))?;

    // The full envelope is self-contained, independently re-verifiable evidence:
    // storing it lets any later reader re-check the death with no index.
    let evidence = serde_json::json!({
        "pay": envelope.pay,
        "sig": Base64UrlUnpadded::encode_string(&envelope.sig),
        "keys": keys
            .iter()
            .map(|key| serde_json::json!({
                "alg": key.alg,
                "pub": Base64UrlUnpadded::encode_string(&key.pub_key),
            }))
            .collect::<Vec<_>>(),
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

/// Record a verified naked revoke in the engine, the one store of deaths
/// every capability consults. `/revoke`, gossip and witness sync all come
/// through here, so every caller is bounded.
///
/// The engine's blob-store record is the truth (I1; it judges admission
/// and forks, and a rebuild re-verifies it).
///
/// The operator's ceiling (`[limits] max_dead_keys`) bounds the revokes of
/// keys no stored principal holds, for every caller: past it such a revoke
/// is refused (507) before anything is written, while the revoke of a held
/// key is still recorded (SPEC 6.4). A peer that names fresh thumbprints
/// can therefore grow the set no further than the ceiling plus the keys the
/// server really holds. Ceiling check and write run under one gate, so
/// concurrent revokes cannot overshoot it.
///
/// # Errors
///
/// The engine's refusal or storage fault, or the ceiling.
pub async fn record_everywhere(
    state: &crate::AppState,
    tmb: &Thumbprint,
    evidence: &serde_json::Value,
) -> Result<(), AppError> {
    use cyphr_storage::index::Indexer;

    let _one_revoke_at_a_time = state.revoke_gate.lock().await;
    let tmb_b64 = Base64UrlUnpadded::encode_string(tmb.as_bytes());

    // A death the engine already holds adds nothing to the set's size.
    if !state
        .engine
        .is_revoked(&tmb_b64)
        .await
        .map_err(AppError::engine)?
    {
        let ceiling = state.config.limits.max_dead_keys.get();
        let held_dead = state
            .engine
            .revoked_count()
            .await
            .map_err(AppError::engine)?;
        if u64::try_from(held_dead).unwrap_or(u64::MAX) >= ceiling {
            let held = state
                .engine
                .indexer()
                .get_key(&tmb_b64)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "naked-revoke presence lookup failed");
                    AppError::internal("key index lookup failed")
                })?
                .is_some();
            if !held {
                return Err(AppError::death_set_full(ceiling));
            }
        }
    }

    // The key's cutoff is this node's own receipt time (#203).
    state
        .engine
        .record_revoke(evidence, crate::auth::server_now())
        .await
        .map_err(AppError::engine)
}
