//! Acceptance test suite for Node N1: Witness Registration Endpoint.
//!
//! Evaluates criteria N1.1 – N1.6:
//! - `register_list_revoke_roundtrip` (N1.1): Witness registration, listing, and revocation
//!   roundtrip.
//! - `third_party_cannot_register_for_principal` (N1.2): Adversarial check ensuring third parties
//!   cannot register witnesses for a principal.
//! - `unauthenticated_registration_refused` (N1.3): Unauthenticated or improperly signed
//!   registrations are refused.
//! - `responses_carry_freshness` (N1.4): Responses from registration endpoints carry required
//!   protocol freshness fields.
//! - `revocation_retains_record` (N1.5): Revocation/deletion of a witness retains historical
//!   records in append-only storage.
//! - `bound_refuses_rather_than_evicts` (N1.6): Enforcing capacity bounds by refusing new
//!   registrations rather than evicting existing ones.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tempfile::TempDir;
use test_fixtures::Pool;
use tower::ServiceExt;

mod common;

/// The witness registration endpoint URI.
const REGISTRATION_URI: &str = "/witness/register";

/// Audience string used in test configuration.
const AUDIENCE: &str = "cyphr.me";

/// Standard Unix timestamp reference.
const NOW: i64 = 1_700_000_000;

// ========================================================================
// Test Helpers
// ========================================================================

fn keyed_state_at(data_dir: &std::path::Path, key_path: &std::path::Path) -> Arc<AppState> {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };
    Arc::new(AppState::new(config).expect("open keyed AppState"))
}

fn fresh_keyed_state() -> (Arc<AppState>, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let state = keyed_state_at(&dir.path().join("data"), &key_path);
    (state, dir)
}

fn build_witness_register_coz(
    pool: &Pool,
    signer_name: &str,
    principal_id: &str,
    witness_pg: &str,
    verb: &str,
    now: i64,
) -> serde_json::Value {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let signer_tmb = signer.compute_tmb_b64().expect("signer tmb b64");

    let pay = serde_json::json!({
        "alg": signer.alg,
        "id": witness_pg,
        "now": now,
        "principal_id": principal_id,
        "tmb": signer_tmb,
        "typ": format!("cyphr.me/cyphr/witness/register/{verb}"),
    });

    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("valid signer prv base64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub base64");
    let pay_bytes = serde_json::to_vec(&pay).expect("pay serializes");

    let (sig_bytes, _cad) =
        coz::sign_json(&pay_bytes, &signer.alg, &prv, &pub_key).expect("signing supported");

    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig_bytes),
        "key": {
            "alg": signer.alg,
            "pub": signer.pub_key,
        }
    })
}

fn corrupt_signature(mut coz: serde_json::Value) -> serde_json::Value {
    if let Some(sig_str) = coz.get_mut("sig").and_then(|v| v.as_str()) {
        let mut bytes = Base64UrlUnpadded::decode_vec(sig_str).unwrap_or_default();
        if !bytes.is_empty() {
            bytes[0] ^= 0xff;
            coz["sig"] = serde_json::Value::String(Base64UrlUnpadded::encode_string(&bytes));
        }
    }
    coz
}

async fn post_witness_register(
    state: &Arc<AppState>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    common::post_json(
        build_router(state.clone()),
        REGISTRATION_URI,
        body.to_string(),
    )
    .await
}

async fn get_witness_list(
    state: &Arc<AppState>,
    principal_id: &str,
) -> (StatusCode, serde_json::Value) {
    let uri = format!("{REGISTRATION_URI}?pr={principal_id}");
    common::get_json(build_router(state.clone()), &uri).await
}

async fn delete_witness_register(
    state: &Arc<AppState>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(REGISTRATION_URI)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = build_router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

// ========================================================================
// Acceptance Criteria N1.1 – N1.6
// ========================================================================

/// N1.1: `register_list_revoke_roundtrip`
///
/// Registers a witness for a principal, verifies it appears in the witness listing,
/// and then revokes/deletes the registration, verifying it is no longer active.
#[tokio::test]
async fn register_list_revoke_roundtrip() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-roundtrip-principal";
    let witness_pg = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    // Step 1: Register witness via POST /witness/register
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "create", NOW);
    let (reg_status, reg_json) = post_witness_register(&state, reg_coz).await;
    assert_eq!(
        reg_status,
        StatusCode::CREATED,
        "witness registration create must succeed: {reg_json:?}"
    );

    // Step 2: List registered witnesses via GET /witness/register?pr=<pid>
    let (list_status, list_json) = get_witness_list(&state, pid).await;
    assert_eq!(
        list_status,
        StatusCode::OK,
        "witness registration listing must succeed: {list_json:?}"
    );
    let payload = common::envelope_payload(&list_json);
    let witnesses = payload["witnesses"]
        .as_array()
        .expect("witnesses array in payload");
    assert!(
        witnesses
            .iter()
            .any(|w| w.as_str() == Some(witness_pg) || w["id"].as_str() == Some(witness_pg)),
        "registered witness PG must be present in listing: {list_json:?}"
    );

    // Step 3: Revoke/delete witness registration via DELETE /witness/register
    let del_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "delete", NOW + 1);
    let (del_status, del_json) = delete_witness_register(&state, del_coz).await;
    assert_eq!(
        del_status,
        StatusCode::OK,
        "witness registration delete must succeed: {del_json:?}"
    );

    // Step 4: List registered witnesses again and verify witness is removed
    let (post_del_status, post_del_json) = get_witness_list(&state, pid).await;
    assert_eq!(
        post_del_status,
        StatusCode::OK,
        "witness registration listing after deletion must succeed: {post_del_json:?}"
    );
    let post_payload = common::envelope_payload(&post_del_json);
    let post_witnesses = post_payload["witnesses"]
        .as_array()
        .expect("witnesses array");
    assert!(
        !post_witnesses
            .iter()
            .any(|w| w.as_str() == Some(witness_pg) || w["id"].as_str() == Some(witness_pg)),
        "revoked witness must no longer be present in active listing: {post_del_json:?}"
    );
}

/// N1.2: `third_party_cannot_register_for_principal`
///
/// Adversarial check: an unauthorized third party (signer not active in principal's KR)
/// attempts to submit a witness registration for a principal, which MUST be refused.
#[tokio::test]
async fn third_party_cannot_register_for_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-third-party-target";
    let witness_pg = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    // Attacker 'alice' (not an authorized key for principal pid) attempts registration
    let attacker_coz = build_witness_register_coz(&pool, "alice", pid, witness_pg, "create", NOW);
    let (status, json) = post_witness_register(&state, attacker_coz).await;

    assert!(
        status.is_client_error(),
        "third-party registration attempt must be rejected with 4xx status, got {status}: {json:?}"
    );
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthorized third-party registration must return 401 Unauthorized: {json:?}"
    );

    // Verify witness list remains empty for principal pid
    let (list_status, list_json) = get_witness_list(&state, pid).await;
    if list_status.is_success() {
        let payload = common::envelope_payload(&list_json);
        let witnesses = payload["witnesses"].as_array();
        assert!(
            witnesses.map_or(true, |w| w.is_empty()),
            "no witnesses should be registered after third-party attempt: {list_json:?}"
        );
    }
}

/// N1.3: `unauthenticated_registration_refused`
///
/// Registration requests that are unauthenticated or carry invalid signatures MUST be refused.
#[tokio::test]
async fn unauthenticated_registration_refused() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-unauthed-principal";
    let witness_pg = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    // Case 1: Corrupted signature
    let valid_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "create", NOW);
    let corrupted_coz = corrupt_signature(valid_coz);
    let (status_corrupt, json_corrupt) = post_witness_register(&state, corrupted_coz).await;
    assert_eq!(
        status_corrupt,
        StatusCode::UNAUTHORIZED,
        "registration with corrupted signature must be rejected with 401 Unauthorized, got \
         {status_corrupt}: {json_corrupt:?}"
    );

    // Case 2: Completely unauthenticated / missing signature payload
    let raw_payload = serde_json::json!({
        "pay": {
            "alg": "ES256",
            "id": witness_pg,
            "now": NOW,
            "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
            "typ": "cyphr.me/cyphr/witness/register/create"
        }
    });
    let (status_no_sig, json_no_sig) = post_witness_register(&state, raw_payload).await;
    assert_eq!(
        status_no_sig,
        StatusCode::BAD_REQUEST,
        "unauthenticated registration missing signature must be rejected with 400 Bad Request, \
         got {status_no_sig}: {json_no_sig:?}"
    );
}

/// N1.4: `responses_carry_freshness`
///
/// Registration endpoint responses MUST carry protocol freshness indicators
/// (e.g. non-zero timestamp 'last_updated' or 'now', sequence count, or envelope freshness).
#[tokio::test]
async fn responses_carry_freshness() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-freshness-principal";
    let witness_pg = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    let reg_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "create", NOW);
    let (status, json) = post_witness_register(&state, reg_coz).await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "registration create must succeed: {json:?}"
    );

    let payload = common::envelope_payload(&json);
    let last_updated = payload
        .get("last_updated")
        .or_else(|| payload.get("now"))
        .and_then(|v| v.as_i64())
        .expect("response payload must carry a timestamp ('last_updated' or 'now')");

    assert!(
        last_updated > 0,
        "response timestamp must be a positive integer, got {last_updated}"
    );

    if let Some(now_val) = json.get("now").and_then(|v| v.as_i64()) {
        assert!(now_val > 0, "envelope 'now' timestamp must be positive");
    }
}

/// N1.5: `revocation_retains_record`
///
/// Revocation / deletion of a witness registration MUST retain historical records
/// in append-only storage and commit history rather than erasing state history.
#[tokio::test]
async fn revocation_retains_record() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-record-retention-principal";
    let witness_pg = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

    // Step 1: Register witness
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "create", NOW);
    let (reg_status, _) = post_witness_register(&state, reg_coz).await;
    assert_eq!(reg_status, StatusCode::CREATED);

    // Step 2: Delete/revoke witness
    let del_coz = build_witness_register_coz(&pool, "golden", pid, witness_pg, "delete", NOW + 5);
    let (del_status, _) = delete_witness_register(&state, del_coz).await;
    assert_eq!(del_status, StatusCode::OK);

    // Step 3: Retrieve patch / history for the principal
    let (patch_status, patch_json) =
        common::get_json(build_router(state.clone()), &format!("/patch?pr={pid}")).await;

    assert_eq!(
        patch_status,
        StatusCode::OK,
        "fetching patch history must succeed: {patch_json:?}"
    );

    let entries = patch_json["payload"]["entries"]
        .as_array()
        .or_else(|| patch_json["entries"].as_array())
        .expect("patch response must contain entries array");

    assert!(
        entries.len() >= 2,
        "patch history must retain all historical operations (expected >= 2 entries), got: \
         {entries:?}"
    );
}

/// N1.6: `bound_refuses_rather_than_evicts`
///
/// When the maximum bound of registered witnesses is reached for a principal,
/// subsequent registration attempts MUST be refused with an error rather than evicting
/// previously registered witnesses.
#[tokio::test]
async fn bound_refuses_rather_than_evicts() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-bound-principal";

    let max_bound = 10;
    let mut registered_pgs = Vec::new();

    for i in 0..max_bound {
        let witness_pg = format!("SHA-256:witness_pg_bound_{i:04}");
        let coz =
            build_witness_register_coz(&pool, "golden", pid, &witness_pg, "create", NOW + i as i64);
        let (status, json) = post_witness_register(&state, coz).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "registration #{i} within bound must succeed: {json:?}"
        );
        registered_pgs.push(witness_pg);
    }

    // Attempt to register 11th witness beyond capacity bound
    let overflow_pg = "SHA-256:witness_pg_overflow_9999";
    let overflow_coz = build_witness_register_coz(
        &pool,
        "golden",
        pid,
        overflow_pg,
        "create",
        NOW + max_bound as i64,
    );
    let (overflow_status, overflow_json) = post_witness_register(&state, overflow_coz).await;

    assert!(
        overflow_status.is_client_error(),
        "registration attempt beyond capacity bound must be refused with 4xx client error, got \
         {overflow_status}: {overflow_json:?}"
    );

    // Verify all originally registered witnesses remain active (none were evicted)
    let (list_status, list_json) = get_witness_list(&state, pid).await;
    assert_eq!(list_status, StatusCode::OK);
    let payload = common::envelope_payload(&list_json);
    let active_witnesses = payload["witnesses"]
        .as_array()
        .expect("active witnesses array");

    assert_eq!(
        active_witnesses.len(),
        max_bound,
        "active witness count must equal max_bound ({max_bound}), no eviction must occur: \
         {list_json:?}"
    );
    for pg in &registered_pgs {
        assert!(
            active_witnesses
                .iter()
                .any(|w| w.as_str() == Some(pg) || w["id"].as_str() == Some(pg)),
            "previously registered witness {pg} must still be active: {list_json:?}"
        );
    }
}
