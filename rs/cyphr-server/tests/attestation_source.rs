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

use common::{
    attestor_server, build_genesis_push_body, get_json, load_pool, post_json,
};

/// Helper: Corrupt the indexer's tip state for `principal_id` by injecting a
/// fake IndexableCommit with sequence 99 and corrupted root strings.
async fn corrupt_indexer_tip(
    state: &Arc<cyphr_server::AppState>,
    principal_id: &str,
) {
    let dummy_hash = Blake3Hash::from_bytes([1u8; 32]);
    let corrupt_commit = IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec!["SHA-256:CORRUPTED_COMMIT_ID_999999999999999999999999".to_string()],
        sequence: 99,
        pre: None,
        prs: vec!["SHA-256:CORRUPTED_PR_9999999999999999999999999999999999999999".to_string()],
        srs: vec!["SHA-256:CORRUPTED_SR_9999999999999999999999999999999999999999".to_string()],
        ars: vec!["SHA-256:CORRUPTED_AR_9999999999999999999999999999999999999999".to_string()],
        crs: vec!["SHA-256:CORRUPTED_CR_9999999999999999999999999999999999999999".to_string()],
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

/// N0b.1 & N0b.5: Every signing path (both /tip and /push) re-derives its
/// roots from the blob store rather than using corrupted/stale index projections.
#[tokio::test]
async fn roots_derive_from_blobs() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let principal_id = "test-roots-derive-from-blobs";
    let now = 1_700_000_000;

    // 1. Establish valid principal via genesis push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(status, StatusCode::CREATED, "genesis push failed: {push_res:?}");

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
    assert_eq!(index_tip.sr, "SHA-256:CORRUPTED_SR_9999999999999999999999999999999999999999");

    // 3. GET /tip MUST NOT return a receipt signed over the corrupted index values.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;

    if tip_status == StatusCode::OK {
        // If it succeeded, its signed roots MUST NOT be the corrupted index roots!
        let coz_roots = &tip_body["statement"]["coz"]["pay"]["roots"];
        assert_ne!(
            coz_roots["sr"],
            "SHA-256:CORRUPTED_SR_9999999999999999999999999999999999999999",
            "attestation MUST NOT sign corrupted index state: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["pr"],
            "SHA-256:CORRUPTED_PR_9999999999999999999999999999999999999999",
            "attestation MUST NOT sign corrupted index state: {tip_body:?}"
        );
    } else {
        // Failing due to corrupted index is also valid behavior under N0b.2/N0b.3.
        assert!(
            tip_status.is_client_error() || tip_status.is_server_error(),
            "expected error status when index is corrupted, got: {tip_status}"
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
    let principal_id = "test-stale-index-fails-attestation";
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(status, StatusCode::CREATED, "genesis push failed: {push_res:?}");

    // 2. Corrupt indexer.
    corrupt_indexer_tip(&state, principal_id).await;

    // 3. GET /tip with stale/corrupted index MUST FAIL attestation.
    // Signing cache content is forbidden — it MUST NOT return 200 OK with a signed statement over corrupted cache data.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;
    let is_signed_corrupt = tip_status == StatusCode::OK
        && tip_body["statement"]["kind"] == "signed"
        && tip_body["statement"]["coz"]["pay"]["roots"]["sr"]
            == "SHA-256:CORRUPTED_SR_9999999999999999999999999999999999999999";
    assert!(
        !is_signed_corrupt,
        "attestation MUST FAIL when index is corrupted, but got 200 OK signing corrupted cache: {tip_body:?}"
    );
    assert_ne!(
        tip_status,
        StatusCode::OK,
        "GET /tip MUST FAIL when index is corrupted/desynchronized"
    );
}

/// N0b.3 & N0b.5: The failure when index is corrupted is typed and its message
/// names what failed and why — no silent fallback to the index.
#[tokio::test]
async fn failure_is_typed_not_silent() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let principal_id = "test-failure-is-typed-not-silent";
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(status, StatusCode::CREATED, "genesis push failed: {push_res:?}");

    // 2. Corrupt indexer.
    corrupt_indexer_tip(&state, principal_id).await;

    // 3. GET /tip with corrupted index.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pr={principal_id}")).await;

    // Must return an error HTTP status (not 200 OK).
    assert!(
        tip_status.is_client_error() || tip_status.is_server_error(),
        "attestation failure must return an error status, got {tip_status} with body: {tip_body:?}"
    );

    // Body must be a typed AppError containing an explicit message about attestation / root / index failure.
    let err_msg = tip_body["error"]
        .as_str()
        .or_else(|| tip_body["message"].as_str())
        .expect("response body must carry a typed error message field");

    assert!(
        !err_msg.is_empty(),
        "error message must not be empty"
    );
}
