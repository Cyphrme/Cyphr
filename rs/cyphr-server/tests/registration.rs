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
use proptest::prelude::*;
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
    // Direction A (S3): a non-resident principal's `principal_id` IS the
    // signer's own thumbprint. This fixture previously used an arbitrary
    // label and only registered because `witness_pg` below happened to
    // equal golden's own tmb -- the Direction-B bypass N0's
    // registration-authz rework closes. Corrected to genuine Direction A:
    // `pid` is golden's tmb AND `witness_pg` no longer coincides with it,
    // so this test exercises Direction A only, not Direction A confounded
    // with a residual Direction-B match.
    let golden_tmb = pool
        .get("golden")
        .expect("golden key")
        .compute_tmb_b64()
        .expect("golden tmb");
    let pid = golden_tmb.as_str();
    let witness_pg = "http://roundtrip-witness.example";

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
            witnesses.is_none_or(|w| w.is_empty()),
            "no witnesses should be registered after third-party attempt: {list_json:?}"
        );
    }
}

/// Adversarial check on `check_registration_authorization`
/// (`src/routes.rs:713-728`): the third-party guard for a not-yet-resident
/// principal only fires when `witness_id.strip_prefix("SHA-256:")` succeeds.
/// Real fanout targets are URLs (see `src/fanout.rs:118-124`), not
/// `SHA-256:`-prefixed thumbprints, so `strip_prefix` returns `None` and the
/// `else if` guard is skipped entirely -- an attacker-signed registration for
/// a victim principal that has no authorized keys and no tip yet would then
/// fall through to `Ok(())` unchecked. This mirrors N1.2 but with a
/// URL-shaped `witness_id` in place of a `SHA-256:` thumbprint, isolating the
/// `strip_prefix` branch as the interesting case.
#[tokio::test]
async fn third_party_cannot_register_url_witness_for_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-url-witness-target";
    let witness_url = "http://attacker.example";

    // Attacker 'alice' (not an authorized key for principal pid) attempts to
    // register a URL-shaped witness for a principal that has no tip and no
    // authorized keys yet.
    let attacker_coz = build_witness_register_coz(&pool, "alice", pid, witness_url, "create", NOW);
    let (status, json) = post_witness_register(&state, attacker_coz).await;

    assert!(
        status.is_client_error(),
        "third-party URL-witness registration attempt must be rejected with 4xx status, got \
         {status}: {json:?}"
    );
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthorized third-party URL-witness registration must return 401 Unauthorized: {json:?}"
    );

    // Verify witness list remains empty for principal pid
    let (list_status, list_json) = get_witness_list(&state, pid).await;
    if list_status.is_success() {
        let payload = common::envelope_payload(&list_json);
        let witnesses = payload["witnesses"].as_array();
        assert!(
            witnesses.is_none_or(|w| w.is_empty()),
            "no witnesses should be registered after third-party URL-witness attempt: \
             {list_json:?}"
        );
    }
}

/// Adversarial check on `check_registration_authorization`
/// (`src/routes.rs:723-724`): the third-party guard for a not-yet-resident
/// principal is gated on `target_tmb.len() == 43` in addition to the
/// `SHA-256:` prefix succeeding. A `SHA-256:`-prefixed `witness_id` whose
/// suffix is NOT exactly 43 base64url characters (a malformed or truncated
/// thumbprint) also falls through the `if` unchecked, the same as the
/// URL-shaped case in `third_party_cannot_register_url_witness_for_principal`
/// but isolating the length-guard condition instead of the prefix-strip
/// condition.
#[tokio::test]
async fn third_party_cannot_register_malformed_thumbprint_witness_for_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-malformed-thumbprint-target";
    // `SHA-256:` prefix present, but the suffix is far short of the 43
    // base64url characters a real thumbprint requires.
    let witness_malformed = "SHA-256:short-tmb";

    // Attacker 'alice' (not an authorized key for principal pid) attempts to
    // register a malformed-thumbprint witness for a principal that has no
    // tip and no authorized keys yet.
    let attacker_coz =
        build_witness_register_coz(&pool, "alice", pid, witness_malformed, "create", NOW);
    let (status, json) = post_witness_register(&state, attacker_coz).await;

    assert!(
        status.is_client_error(),
        "third-party malformed-thumbprint registration attempt must be rejected with 4xx status, \
         got {status}: {json:?}"
    );
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthorized third-party malformed-thumbprint registration must return 401 Unauthorized: \
         {json:?}"
    );

    // Verify witness list remains empty for principal pid
    let (list_status, list_json) = get_witness_list(&state, pid).await;
    if list_status.is_success() {
        let payload = common::envelope_payload(&list_json);
        let witnesses = payload["witnesses"].as_array();
        assert!(
            witnesses.is_none_or(|w| w.is_empty()),
            "no witnesses should be registered after third-party malformed-thumbprint attempt: \
             {list_json:?}"
        );
    }
}

/// Adversarial check on `check_registration_authorization`
/// (`src/routes.rs:681-726`): the guard is shared verbatim between
/// `POST /witness/register` (create) and `DELETE /witness/register`
/// (revoke), but every existing adversarial registration test in this file
/// exercises the `create` verb only. A third party exploiting the same
/// not-yet-resident-principal bypass (URL-shaped `witness_id`, see
/// `third_party_cannot_register_url_witness_for_principal`) against the
/// `delete` verb is entirely untested, even though `revoke_witness`
/// (`src/registration.rs:93-108`) unconditionally creates a state entry and
/// updates `last_updated` for ANY `principal_id`, authorized or not.
#[tokio::test]
async fn third_party_cannot_delete_url_witness_for_principal() {
    let (state, _dir) = fresh_keyed_state();
    let pool = common::load_pool();
    let pid = "n1-url-witness-delete-target";
    let witness_url = "http://attacker.example";

    // Attacker 'alice' (not an authorized key for principal pid) attempts to
    // delete/revoke a URL-shaped witness for a principal that has no tip and
    // no authorized keys yet -- there is nothing legitimately registered to
    // delete, but the authorization guard must still refuse the request
    // before reaching `revoke_witness`.
    let attacker_coz = build_witness_register_coz(&pool, "alice", pid, witness_url, "delete", NOW);
    let (status, json) = delete_witness_register(&state, attacker_coz).await;

    assert!(
        status.is_client_error(),
        "third-party URL-witness delete attempt must be rejected with 4xx status, got {status}: \
         {json:?}"
    );
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "unauthorized third-party URL-witness delete must return 401 Unauthorized: {json:?}"
    );
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
    // Direction A (S3): see `register_list_revoke_roundtrip` above -- this
    // fixture had the same accidental Direction-B dependency (`pid` AND
    // `witness_pg`), corrected the same way.
    let golden_tmb = pool
        .get("golden")
        .expect("golden key")
        .compute_tmb_b64()
        .expect("golden tmb");
    let pid = golden_tmb.as_str();
    let witness_pg = "http://freshness-witness.example";

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

    // Step 0: Bootstrap principal
    let push_body = common::build_genesis_push_body(&pool, pid, NOW - 10);
    let (push_status, _) = common::post_json(build_router(state.clone()), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

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
        !entries.is_empty(),
        "patch history must retain all historical operations, got: {entries:?}"
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
    // Direction A (S3): this fixture previously used an arbitrary
    // `principal_id` label and bootstrapped itself via registration #0's
    // Direction-B coincidence (a witness_id naming golden's own key), then
    // rode the resulting implicit `authorized_keys` seeding -- both closed
    // by N0's registration-authz rework -- to authorize #1..#9. Corrected
    // to genuine Direction A throughout: every registration is directly
    // authorized by `signer_tmb == principal_id`, so no seeding step (and
    // no special-cased witness #0) is needed.
    let golden_tmb = pool
        .get("golden")
        .expect("golden key")
        .compute_tmb_b64()
        .expect("golden tmb");
    let pid = golden_tmb.as_str();

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

// ========================================================================
// N0 — registration authorization: class-closing property tests
//
// The fix (S0/S3, head-ratified): self-registration is legitimate ONLY when
// `signer_tmb == principal_id` (Direction A). The guard's prior heuristic --
// treating a `witness_id` that names the signer's OWN key as authorization
// for ANY `principal_id` (Direction B: `witness_id == signer_tmb` or
// `witness_id.strip_prefix("SHA-256:") == Some(signer_tmb)`) -- is REMOVED.
// It conflated "this witness names my key" with "I may register for this
// principal," two unrelated propositions, and is the live bypass this node
// closes: an attacker registers `witness_id = "SHA-256:<their own key>"` for
// a principal they do not control; combined with the (also removed)
// implicit `authorized_keys` seeding, that single call seeds them into the
// victim principal's key list.
//
// `check_registration_authorization`'s caller-facing contract
// (`verify_witness_register_envelope`, src/routes.rs:590-673) takes
// `witness_id` as an opaque, wire-supplied `&str` with no shape validation
// at all -- so the invariant's domain is "any string," not "the three
// shapes someone once tried." The generator below is built from that
// domain, not from the guard's branches: an unweighted arbitrary-Unicode-
// string arm covers the whole space; the URL / `SHA-256:`-arbitrary-length /
// bare / empty arms raise sampling density over the historically interesting
// sub-regions and narrow nothing. The signer's-own-key arms (`bare` /
// `prefixed`, added below) are the one exception that must be explicit
// rather than density-boosted: the bypass shape is one exact 43-character
// base64 string, and no random-string strategy will land on it by chance
// with any practical probability, so without a dedicated arm this property
// could pass by simply never trying the shape that matters.
// ========================================================================

/// The signer key used throughout this module's properties. Computed once
/// per property invocation (the `in` clause of a `proptest!` parameter runs
/// once, before case generation begins, so an ordinary pool lookup here is
/// fine) so the generator can manufacture the Direction-B bypass shape
/// against the SAME key the property later signs with.
fn alice_tmb() -> String {
    common::load_pool()
        .get("alice")
        .expect("alice key in pool")
        .compute_tmb_b64()
        .expect("alice tmb b64")
}

/// The domain a `witness_id` can inhabit on the wire: an arbitrary string,
/// with explicit density on the historically interesting sub-regions
/// (including the Direction-B bypass shape -- `own_tmb`, bare and
/// `SHA-256:`-prefixed). See the module doc above for why the non-`.*` arms
/// are density boosters, not a restriction of the space.
fn witness_id_strategy(own_tmb: &str) -> impl Strategy<Value = String> {
    prop_oneof![
        2 => ".*",
        2 => "(http|https)://[a-zA-Z0-9.-]{1,40}(/[a-zA-Z0-9_-]{0,20}){0,3}",
        2 => "SHA-256:.{0,80}",
        1 => Just(String::new()),
        1 => "[a-zA-Z0-9_-]{1,64}",
        2 => Just(own_tmb.to_string()),
        2 => Just(format!("SHA-256:{own_tmb}")),
    ]
}

/// The domain a `principal_id` can inhabit: an arbitrary identifier string.
/// Residency is controlled by the test harness (a fresh state never receives
/// a genesis commit for it), independent of the string's shape.
fn principal_id_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[a-zA-Z0-9_-]{1,40}",
        1 => ".*",
    ]
}

fn verb_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("create"), Just("delete")]
}

/// Drive one registration attempt (create or delete) against a fresh,
/// never-resident `AppState` and return the resulting HTTP status.
async fn attempt_registration(
    pool: &Pool,
    principal_id: &str,
    witness_id: &str,
    verb: &str,
) -> (StatusCode, serde_json::Value) {
    let (state, _dir) = fresh_keyed_state();
    let coz = build_witness_register_coz(pool, "alice", principal_id, witness_id, verb, NOW);
    if verb == "create" {
        post_witness_register(&state, coz).await
    } else {
        delete_witness_register(&state, coz).await
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// N0.1: `registration_refuses_unbound_signer_property`
    ///
    /// For any signer key NOT bound to `principal_id` (`signer_tmb !=
    /// principal_id` -- Direction A, the only legitimate shape, is the sole
    /// exclusion), registration MUST be refused for ANY `witness_id` shape
    /// and EITHER verb -- INCLUDING `witness_id` that names the signer's own
    /// key (Direction B). Direction B is no longer excluded here: it is the
    /// live bypass, and asserting it refused is the entire point of this
    /// rework (S0/S3). This single generated property subsumes the three
    /// regression anchors (URL, malformed thumbprint, delete verb) plus the
    /// rest of the domain: bare tokens, empty strings, arbitrary Unicode,
    /// `SHA-256:`-prefixed strings of any length, and the signer's own
    /// thumbprint bare or prefixed.
    #[test]
    fn registration_refuses_unbound_signer_property(
        principal_id in principal_id_strategy(),
        witness_id in witness_id_strategy(&alice_tmb()),
        verb in verb_strategy(),
    ) {
        let pool = common::load_pool();
        let signer_tmb = pool
            .get("alice")
            .expect("alice key in pool")
            .compute_tmb_b64()
            .expect("alice tmb b64");

        // Direction A (signer == principal) is the only legitimate
        // self-registration (S3); it is N0.2's domain, not this property's.
        prop_assume!(principal_id != signer_tmb);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (status, json) =
            rt.block_on(attempt_registration(&pool, &principal_id, &witness_id, verb));

        prop_assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "unbound signer must be refused regardless of witness_id shape, including the \
             signer's-own-key Direction-B bypass shape: principal_id={:?}, witness_id={:?}, \
             verb={}, response={:?}",
            principal_id, witness_id, verb, json
        );
    }

    /// N0.2: `registration_permits_self_registration_property`
    ///
    /// The dual of N0.1: Direction A (`signer_tmb == principal_id`) remains
    /// permitted under generation, for ANY `witness_id` shape and EITHER
    /// verb. This is an INDEPENDENT test fn from N0.1, phrased to catch a
    /// regression that over-tightens the guard and starts refusing
    /// legitimate self-registration -- the same way N0.1 catches
    /// under-tightening.
    ///
    /// Direction B ("`witness_id` names the signer's own key" for a
    /// DIFFERENT `principal_id`) is deliberately NOT asserted permitted
    /// here -- that was the prior suite's defect (S0): it encoded the
    /// bypass as legitimate. Direction B now lives entirely in N0.1's
    /// refused domain.
    #[test]
    fn registration_permits_self_registration_property(
        witness_id in witness_id_strategy(&alice_tmb()),
        verb in verb_strategy(),
    ) {
        let pool = common::load_pool();
        let signer_tmb = pool
            .get("alice")
            .expect("alice key in pool")
            .compute_tmb_b64()
            .expect("alice tmb b64");
        let principal_id = signer_tmb.clone();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (status, json) =
            rt.block_on(attempt_registration(&pool, &principal_id, &witness_id, verb));

        let expected = if verb == "create" { StatusCode::CREATED } else { StatusCode::OK };
        prop_assert_eq!(
            status,
            expected,
            "legitimate Direction-A self-registration must be permitted: principal_id={:?}, \
             witness_id={:?}, verb={}, response={:?}",
            principal_id, witness_id, verb, json
        );
    }
}

/// N0.4: `grant_on_absence_is_refused`
///
/// A targeted, example-level companion to N0.1's generative claim, isolating
/// the two concrete conditions the guard's `else` branch (`routes.rs:713-
/// 735`) used to conflate:
///
/// - **Absence**: an unbound signer, an ordinary (non-coincidental) `witness_id`, against a
///   principal with no tip and no `authorized_keys` entry at all. Absence of authorization evidence
///   must never itself grant -- this already refuses on the unfixed guard (nothing in the current
///   code grants on absence alone once `has_authorized_keys` is false and no `witness_id` heuristic
///   matches).
/// - **Direction-B string-coincidence**: `witness_id` names the signer's own key, for a principal
///   the signer does not control. This is the live bypass and is RED here until the fix lands.
#[tokio::test]
async fn grant_on_absence_is_refused() {
    let pool = common::load_pool();
    let signer_tmb = pool
        .get("alice")
        .expect("alice key in pool")
        .compute_tmb_b64()
        .expect("alice tmb b64");

    for verb in ["create", "delete"] {
        let (status, json) =
            attempt_registration(&pool, "n0-absence-target", "http://attacker.example", verb).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "absent-authorization state must refuse (verb={verb}): {json:?}"
        );

        let (status, json) = attempt_registration(
            &pool,
            "n0-direction-b-target",
            &format!("SHA-256:{signer_tmb}"),
            verb,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "Direction-B string-coincidence must refuse (verb={verb}): {json:?}"
        );
    }
}

/// N0.5b: `principal_manages_own_witnesses`
///
/// Bootstrap preservation (S0 RULINGS, S3): the fix must not lock a
/// principal out of managing its own witness set before it is resident. A
/// principal (`signer_tmb == principal_id`, Direction A) registers AND
/// revokes its own witness for its non-resident principal, for both verbs,
/// and both MUST succeed -- Direction A is the one legitimate shape N0.1 and
/// N0.4 refuse around, so closing the bypass must not also close this.
#[tokio::test]
async fn principal_manages_own_witnesses() {
    let pool = common::load_pool();
    let (state, _dir) = fresh_keyed_state();
    let signer_tmb = pool
        .get("golden")
        .expect("golden key in pool")
        .compute_tmb_b64()
        .expect("golden tmb b64");
    let witness_pg = "http://self-managed.example";

    let reg_coz =
        build_witness_register_coz(&pool, "golden", &signer_tmb, witness_pg, "create", NOW);
    let (reg_status, reg_json) = post_witness_register(&state, reg_coz).await;
    assert_eq!(
        reg_status,
        StatusCode::CREATED,
        "principal must be able to register a witness for itself: {reg_json:?}"
    );

    let del_coz =
        build_witness_register_coz(&pool, "golden", &signer_tmb, witness_pg, "delete", NOW + 1);
    let (del_status, del_json) = delete_witness_register(&state, del_coz).await;
    assert_eq!(
        del_status,
        StatusCode::OK,
        "principal must be able to revoke its own witness: {del_json:?}"
    );
}
