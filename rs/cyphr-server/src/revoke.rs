//! Witness ingest of an uncommitted `key/revoke` coz -- a "naked revoke"
//! (SPEC.md §6.4, confirmed model).
//!
//! A naked revoke is a `key/revoke` coz signed *outside* any commit. Under
//! the confirmed model a witness accepts one iff it is **self-signed**: the
//! key named by the coz's `tmb` signs its own revoke. Verification is O(1)
//! and replay-free -- resolve `tmb -> pubkey` through the engine's global key
//! index and check the one signature -- with no principal load and no chain
//! replay. A revoke signed by any key OTHER than the one it names fails the
//! signature check; that single check IS the self-signed-only rule, so there
//! is no third-party path.
//!
//! Resolving `tmb -> pubkey` here does NOT reintroduce the global `tmb` index
//! `auth::login` forbids: that rule bans inferring a *principal* from a `tmb`
//! during authentication. Here the lookup only recovers the public key to
//! verify a self-signature (`tmb = H(pubkey)` is a cryptographic binding --
//! one pubkey per `tmb`); no principal is inferred, and the result is an
//! additive refusal, never an auth grant.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::index::Indexer;

use crate::error::AppError;

/// A verified naked revoke: its self-signature checked out against the named
/// key's own indexed public key.
#[derive(Debug)]
pub struct VerifiedRevoke {
    /// The revoked key's thumbprint (the coz's `tmb`), now dead globally.
    pub revoked_tmb: Thumbprint,
    /// The revocation timestamp the coz declared.
    pub rvk: i64,
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

/// Parse, validate, and verify a naked-revoke coz against the engine's global
/// key index -- replay-free and self-signed-only.
///
/// Verification order, each a distinct rejection:
/// 1. the payload parses and its `typ` is a `key/revoke`;
/// 2. `rvk` is a positive integer below 2^53-1 (`coz::is_valid_rvk`); the timestamp value itself is
///    NOT checked, so a pre-signed `rvk`=1 is valid;
/// 3. the revoked `tmb` resolves to a public key the engine has indexed -- `None` (a key this
///    server never saw) is a rejection;
/// 4. the signature verifies against that public key. A revoke signed by any key OTHER than the one
///    `tmb` names fails here, since the signature will not verify against `tmb`'s public key -- the
///    entire self-signed-only rule.
///
/// A malformed payload, bad `rvk`, wrong `typ`, or an unknown `tmb` is a 400;
/// a signature that does not verify is a 401.
pub async fn interpret<I: Indexer>(
    coz: &coz::CozJson,
    indexer: &I,
) -> Result<VerifiedRevoke, AppError> {
    let pay_bytes = serde_json::to_vec(&coz.pay)
        .map_err(|e| AppError::bad_request(format!("revoke payload not serializable: {e}")))?;
    let pay: coz::Pay = serde_json::from_value(coz.pay.clone())
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
    let tmb_b64 = Base64UrlUnpadded::encode_string(tmb.as_bytes());

    // Resolve tmb -> pubkey through the engine's global key index (O(1), no
    // principal load). A tmb this server never indexed cannot be verified.
    let key = indexer
        .get_key(&tmb_b64)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "naked-revoke key-index lookup failed");
            AppError::internal("key index lookup failed")
        })?
        .ok_or_else(|| AppError::bad_request("revoke names a key this server has not indexed"))?;

    let pub_bytes = Base64UrlUnpadded::decode_vec(&key.public_key).map_err(|e| {
        tracing::error!(error = %e, "indexed public key is not base64url");
        AppError::internal("indexed public key is malformed")
    })?;

    // The signature must verify against the NAMED key's own public key: a
    // revoke signed by any other key fails here -- self-signed-only.
    if coz::verify_json(&pay_bytes, &coz.sig, &key.algorithm, &pub_bytes) != Some(true) {
        return Err(AppError::unauthorized("revoke signature does not verify"));
    }

    Ok(VerifiedRevoke {
        revoked_tmb: tmb,
        rvk,
    })
}
