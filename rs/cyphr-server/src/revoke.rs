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

use crate::error::AppError;

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
/// The request is handed to core's [`cyphr::revoke::verify_naked_revoke`] as
/// received, so the one rule decides its shape (`keys` of exactly one key,
/// the singular `key` prohibited), its payload and its signature. A
/// malformed envelope, bad `rvk`, oversize payload, wrong `typ`, or a
/// disclosed key that does not hash to its `tmb` is a 400; a signature that
/// does not verify is a 401.
pub async fn interpret(envelope: &serde_json::Value) -> Result<VerifiedRevoke, AppError> {
    use cyphr::revoke::RevokeFailure;

    // The refusal text is the sender's own material, never reflected back.
    let revoke = cyphr::revoke::verify_naked_revoke(envelope).map_err(|e| match e {
        RevokeFailure::BadSignature => AppError::unauthorized("revoke signature does not verify"),
        other => AppError::bad_request(other.to_string()),
    })?;

    // The stored evidence is self-contained and re-verifiable by any later
    // reader with no index. Core has accepted exactly one key with a string
    // `alg` and `pub`; only those fields, and the signed pay and its sig,
    // are kept, so nothing else the sender added is stored.
    let key = &envelope["keys"][0];
    let evidence = serde_json::json!({
        "pay": envelope["pay"],
        "sig": envelope["sig"],
        "keys": [{"alg": key["alg"], "pub": key["pub"]}],
    });

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
