//! Integration tests for attestation source correctness (issue #116, Node N0b).
//!
//! Asserts that every root the server signs — in tip receipts (`/tip`) and
//! commit receipts (`/push`) alike — is re-derived from the authoritative blob
//! store, never read from an index projection. If the index is stale or
//! corrupted, attestation must fail with a typed error rather than silently
//! signing cache content.

use std::sync::Arc;

use axum::http::StatusCode;
use cyphr_server::build_router;
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{IndexableCommit, Indexer};

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

const CORRUPT_PR: &str = "SHA-256:CORRUPTED_PR_9999999999999999999999999999999999999999";
const CORRUPT_SR: &str = "SHA-256:CORRUPTED_SR_9999999999999999999999999999999999999999";
const CORRUPT_AR: &str = "SHA-256:CORRUPTED_AR_9999999999999999999999999999999999999999";
const CORRUPT_CR: &str = "SHA-256:CORRUPTED_CR_9999999999999999999999999999999999999999";

/// Render a distinct, valid genesis-identifier string from a repeated
/// seed byte -- BARE b64ut, no algorithm tag (SPEC §2.2.3's DEFAULT
/// identifier form; tagging is `roots`/`commit_id`'s labeled exemption,
/// not the top-level `pr` this suite's `principal_id` fixtures become --
/// Amendment A2, `ND-typed-witness-domain.md`). Node ND's typed
/// `receipt::tip_report`/`commit_receipt` now refuse a malformed `pr`, so
/// this suite's principal identifiers, which used to be human-readable
/// placeholders, must genuinely parse.
fn digest(byte: u8) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(&[byte; 32])
}

/// Helper: Corrupt the indexer's tip state for `principal_id` by injecting a
/// fake IndexableCommit with sequence 99 and corrupted root strings.
async fn corrupt_indexer_tip(state: &Arc<cyphr_server::AppState>, principal_id: &str) {
    let dummy_hash = Blake3Hash::from_bytes([1u8; 32]);
    let corrupt_commit = IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec!["SHA-256:CORRUPTED_COMMIT_ID_999999999999999999999999".to_string()],
        sequence: 99,
        pre: None,
        prs: vec![CORRUPT_PR.to_string()],
        srs: vec![CORRUPT_SR.to_string()],
        ars: vec![CORRUPT_AR.to_string()],
        crs: vec![CORRUPT_CR.to_string()],
        blob_hashes: vec![dummy_hash],
        cozies: vec![],
        timestamp: 1_700_000_000,
        keys: vec![],
    };
    state
        .engine
        .indexer()
        .index_commit(&corrupt_commit)
        .await
        .expect("corrupt index_commit");
}

/// N0b.1 & N0b.5: Every signing path (both GET /tip and POST /push) re-derives its
/// roots from the blob store rather than using corrupted/stale index projections.
#[tokio::test]
async fn roots_derive_from_blobs() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let principal_id_digest = digest(0x01);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_000_000;

    // 1. Establish valid principal via genesis push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis push failed: {push_res:?}"
    );

    // 2. Corrupt indexer's tip record for principal_id.
    corrupt_indexer_tip(&state, principal_id).await;

    // Verify indexer get_tip indeed returns corrupted tip state.
    let index_tip = state
        .engine
        .indexer()
        .get_tip(principal_id)
        .await
        .unwrap()
        .expect("tip exists");
    assert_eq!(index_tip.pr, CORRUPT_PR);
    assert_eq!(index_tip.sr, CORRUPT_SR);
    assert_eq!(index_tip.ar, CORRUPT_AR);
    assert_eq!(index_tip.cr, CORRUPT_CR);

    // 3. GET /tip MUST NOT return a receipt signed over corrupted index values (all 4 root fields).
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;

    if tip_status == StatusCode::OK {
        // If it succeeded, its signed roots MUST NOT match any of the corrupted index roots!
        let coz_roots = &tip_body["statement"]["coz"]["pay"]["roots"];
        assert_ne!(
            coz_roots["pr"], CORRUPT_PR,
            "attestation MUST NOT sign corrupted index pr: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["sr"], CORRUPT_SR,
            "attestation MUST NOT sign corrupted index sr: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["ar"], CORRUPT_AR,
            "attestation MUST NOT sign corrupted index ar: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["cr"], CORRUPT_CR,
            "attestation MUST NOT sign corrupted index cr: {tip_body:?}"
        );
    } else {
        // Failing due to corrupted index is also valid behavior under N0b.2/N0b.3.
        assert!(
            tip_status.is_client_error() || tip_status.is_server_error(),
            "expected error status when index is corrupted, got: {tip_status}"
        );
    }

    // 4. POST /push under corrupted index MUST NOT return a commit receipt signed over corrupted
    //    index values.
    let push_principal_digest = digest(0x02);
    let push_principal = push_principal_digest.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt = build_genesis_push_body(&pool, push_principal, now);

    let (push_status, push_res) = post_json(app.clone(), "/push", push_body_corrupt).await;
    if push_status == StatusCode::CREATED {
        let coz_roots = &push_res["statement"]["coz"]["pay"]["roots"];
        assert_ne!(
            coz_roots["pr"], CORRUPT_PR,
            "push attestation MUST NOT sign corrupted index pr: {push_res:?}"
        );
        assert_ne!(
            coz_roots["sr"], CORRUPT_SR,
            "push attestation MUST NOT sign corrupted index sr: {push_res:?}"
        );
        assert_ne!(
            coz_roots["ar"], CORRUPT_AR,
            "push attestation MUST NOT sign corrupted index ar: {push_res:?}"
        );
        assert_ne!(
            coz_roots["cr"], CORRUPT_CR,
            "push attestation MUST NOT sign corrupted index cr: {push_res:?}"
        );
    } else {
        assert!(
            push_status.is_client_error() || push_status.is_server_error(),
            "expected error status for push when index is corrupted, got: {push_status}"
        );
    }
}

/// N0b.2 & N0b.5: With the index deliberately corrupted or stale, attestation
/// FAILS for both receipt kinds (/tip and /push) rather than signing cache content.
#[tokio::test]
async fn stale_index_fails_attestation() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let principal_id_digest = digest(0x03);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis push failed: {push_res:?}"
    );

    // 2. Corrupt indexer.
    corrupt_indexer_tip(&state, principal_id).await;

    // 3. GET /tip with stale/corrupted index MUST FAIL attestation.
    // Signing cache content is forbidden — it MUST NOT return 200 OK with a signed statement over
    // corrupted cache data.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    let is_signed_corrupt_tip = tip_status == StatusCode::OK
        && tip_body["statement"]["kind"] == "signed"
        && (tip_body["statement"]["coz"]["pay"]["roots"]["pr"] == CORRUPT_PR
            || tip_body["statement"]["coz"]["pay"]["roots"]["sr"] == CORRUPT_SR
            || tip_body["statement"]["coz"]["pay"]["roots"]["ar"] == CORRUPT_AR
            || tip_body["statement"]["coz"]["pay"]["roots"]["cr"] == CORRUPT_CR);
    assert!(
        !is_signed_corrupt_tip,
        "GET /tip attestation MUST FAIL when index is corrupted, but got 200 OK signing corrupted \
         cache: {tip_body:?}"
    );
    assert_ne!(
        tip_status,
        StatusCode::OK,
        "GET /tip MUST FAIL when index is corrupted/desynchronized"
    );

    // 4. POST /push with stale/corrupted index MUST FAIL attestation.
    let push_principal_digest = digest(0x04);
    let push_principal = push_principal_digest.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt = build_genesis_push_body(&pool, push_principal, now);
    let (push_status, push_body_res) = post_json(app.clone(), "/push", push_body_corrupt).await;

    let is_signed_corrupt_push = push_status == StatusCode::CREATED
        && push_body_res["statement"]["kind"] == "signed"
        && (push_body_res["statement"]["coz"]["pay"]["roots"]["pr"] == CORRUPT_PR
            || push_body_res["statement"]["coz"]["pay"]["roots"]["sr"] == CORRUPT_SR
            || push_body_res["statement"]["coz"]["pay"]["roots"]["ar"] == CORRUPT_AR
            || push_body_res["statement"]["coz"]["pay"]["roots"]["cr"] == CORRUPT_CR);
    assert!(
        !is_signed_corrupt_push,
        "POST /push attestation MUST FAIL when index is corrupted, but got 201 Created signing \
         corrupted cache: {push_body_res:?}"
    );
    assert!(
        push_status.is_client_error() || push_status.is_server_error(),
        "POST /push MUST FAIL when index is corrupted/desynchronized, got status: {push_status}"
    );
}

/// N0b.3 & N0b.5: The failure when index is corrupted is typed and its message
/// names what failed and why — no silent fallback to the index.
#[tokio::test]
async fn failure_is_typed_not_silent() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let principal_id_digest = digest(0x05);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis push failed: {push_res:?}"
    );

    // 2. Corrupt indexer.
    corrupt_indexer_tip(&state, principal_id).await;

    // 3. GET /tip with corrupted index.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;

    // Must return an error HTTP status (not 200 OK).
    assert!(
        tip_status.is_client_error() || tip_status.is_server_error(),
        "attestation failure must return an error status, got {tip_status} with body: {tip_body:?}"
    );

    // Body must be a typed AppError JSON object containing an explicit error message field ('error'
    // or 'message').
    assert!(
        tip_body.is_object(),
        "error response body must be a JSON object, got: {tip_body:?}"
    );
    let err_msg = tip_body["payload"]["error"]
        .as_str()
        .or_else(|| tip_body["payload"]["message"].as_str())
        .or_else(|| tip_body["error"].as_str())
        .or_else(|| tip_body["message"].as_str())
        .expect("response body must carry a typed error message field ('error' or 'message')");

    let lower_msg = err_msg.to_lowercase();
    assert!(
        lower_msg.contains("attestation")
            || lower_msg.contains("root")
            || lower_msg.contains("index"),
        "typed error message must explicitly name attestation, root, or index failure, got: \
         {err_msg:?}"
    );

    // 4. POST /push under corrupted index must also fail with a typed error message.
    let push_principal_digest = digest(0x06);
    let push_principal = push_principal_digest.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt = build_genesis_push_body(&pool, push_principal, now);
    let (push_status, push_res_body) = post_json(app.clone(), "/push", push_body_corrupt).await;

    assert!(
        push_status.is_client_error() || push_status.is_server_error(),
        "push attestation failure must return an error status, got {push_status} with body: \
         {push_res_body:?}"
    );
    assert!(
        push_res_body.is_object(),
        "push error response body must be a JSON object, got: {push_res_body:?}"
    );
    let push_err_msg = push_res_body["payload"]["error"]
        .as_str()
        .or_else(|| push_res_body["payload"]["message"].as_str())
        .or_else(|| push_res_body["error"].as_str())
        .or_else(|| push_res_body["message"].as_str())
        .expect("push response body must carry a typed error message field ('error' or 'message')");

    let push_lower_msg = push_err_msg.to_lowercase();
    assert!(
        push_lower_msg.contains("attestation")
            || push_lower_msg.contains("root")
            || push_lower_msg.contains("index"),
        "push typed error message must explicitly name attestation, root, or index failure, got: \
         {push_err_msg:?}"
    );
}
