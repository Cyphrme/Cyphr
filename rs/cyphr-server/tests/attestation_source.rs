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
use cyphr_storage::index::{DeriveToken, IndexableCommit, Indexer, IndexerWrite};

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// A corrupt root per principal: the index refuses one digest naming two
/// principals, so the injected values must differ between them. Keyed on
/// the id's digest, so either spelling of the id names the same value.
fn corrupt_root(kind: &str, principal_id: &str) -> String {
    let digest = principal_id
        .strip_prefix("SHA-256:")
        .unwrap_or(principal_id);
    format!("SHA-256:CORRUPTED_{kind}_{digest}")
}
fn corrupt_pr(p: &str) -> String {
    corrupt_root("PR", p)
}
fn corrupt_sr(p: &str) -> String {
    corrupt_root("SR", p)
}
fn corrupt_ar(p: &str) -> String {
    corrupt_root("AR", p)
}
fn corrupt_cr(p: &str) -> String {
    corrupt_root("CR", p)
}

/// Helper: Corrupt the indexer's tip state for `principal_id` by injecting a
/// fake IndexableCommit with sequence 99 and corrupted root strings.
async fn corrupt_indexer_tip(state: &Arc<cyphr_server::AppState>, principal_id: &str) {
    // The index is keyed on the canonical (algorithm-labelled) spelling of a
    // principal id, which is how both principals here are named (their PG
    // is a SHA-256 PR).
    let bare = principal_id;
    let dummy_hash = Blake3Hash::from_bytes([1u8; 32]);
    let corrupt_commit = IndexableCommit {
        pg: Vec::new(),
        principal_id: principal_id.to_string(),
        commit_ids: vec![corrupt_root("COMMIT_ID", bare)],
        sequence: 99,
        pre: None,
        prs: vec![corrupt_pr(bare)],
        srs: vec![corrupt_sr(bare)],
        ars: vec![corrupt_ar(bare)],
        crs: vec![corrupt_cr(bare)],
        blob_hashes: vec![dummy_hash],
        cozies: vec![],
        timestamp: 1_700_000_000,
        keys: vec![],
    };
    state
        .engine
        .indexer()
        .index_commit(&corrupt_commit, &DeriveToken::for_conformance_tests())
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
    let principal_id = common::golden_principal_id(&pool).await;
    let principal_id = principal_id.as_str();
    let now = 1_700_000_000;

    // 1. Establish valid principal via genesis push.
    let push_body = build_genesis_push_body(&pool, principal_id, now).await;
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
    assert_eq!(index_tip.pr, corrupt_pr(principal_id));
    assert_eq!(index_tip.sr, Some(corrupt_sr(principal_id)));
    assert_eq!(index_tip.ar, Some(corrupt_ar(principal_id)));
    assert_eq!(index_tip.cr, corrupt_cr(principal_id));

    // 3. GET /tip MUST NOT return a receipt signed over corrupted index values (all 4 root fields).
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pg={principal_id}")).await;

    if tip_status == StatusCode::OK {
        // If it succeeded, its signed roots MUST NOT match any of the corrupted index roots!
        let coz_roots = &tip_body["statement"]["coz"]["pay"]["roots"];
        assert_ne!(
            coz_roots["pr"],
            corrupt_pr(principal_id),
            "attestation MUST NOT sign corrupted index pr: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["sr"],
            corrupt_sr(principal_id),
            "attestation MUST NOT sign corrupted index sr: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["ar"],
            corrupt_ar(principal_id),
            "attestation MUST NOT sign corrupted index ar: {tip_body:?}"
        );
        assert_ne!(
            coz_roots["cr"],
            corrupt_cr(principal_id),
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
    let push_principal = common::genesis_push_id(&pool, "alice", "key_a").await;
    let push_principal = push_principal.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt =
        common::build_genesis_push_body_with(&pool, "alice", "key_a", push_principal, now).await;

    let (push_status, push_res) = post_json(app.clone(), "/push", push_body_corrupt).await;
    if push_status == StatusCode::CREATED {
        let coz_roots = &push_res["statement"]["coz"]["pay"]["roots"];
        assert_ne!(
            coz_roots["pr"],
            corrupt_pr(push_principal),
            "push attestation MUST NOT sign corrupted index pr: {push_res:?}"
        );
        assert_ne!(
            coz_roots["sr"],
            corrupt_sr(push_principal),
            "push attestation MUST NOT sign corrupted index sr: {push_res:?}"
        );
        assert_ne!(
            coz_roots["ar"],
            corrupt_ar(push_principal),
            "push attestation MUST NOT sign corrupted index ar: {push_res:?}"
        );
        assert_ne!(
            coz_roots["cr"],
            corrupt_cr(push_principal),
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
    let principal_id = common::golden_principal_id(&pool).await;
    let principal_id = principal_id.as_str();
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now).await;
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
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pg={principal_id}")).await;
    let is_signed_corrupt_tip = tip_status == StatusCode::OK
        && tip_body["statement"]["kind"] == "signed"
        && (tip_body["statement"]["coz"]["pay"]["roots"]["pr"] == corrupt_pr(principal_id)
            || tip_body["statement"]["coz"]["pay"]["roots"]["sr"] == corrupt_sr(principal_id)
            || tip_body["statement"]["coz"]["pay"]["roots"]["ar"] == corrupt_ar(principal_id)
            || tip_body["statement"]["coz"]["pay"]["roots"]["cr"] == corrupt_cr(principal_id));
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
    let push_principal = common::genesis_push_id(&pool, "alice", "key_a").await;
    let push_principal = push_principal.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt =
        common::build_genesis_push_body_with(&pool, "alice", "key_a", push_principal, now).await;
    let (push_status, push_body_res) = post_json(app.clone(), "/push", push_body_corrupt).await;

    let is_signed_corrupt_push = push_status == StatusCode::CREATED
        && push_body_res["statement"]["kind"] == "signed"
        && (push_body_res["statement"]["coz"]["pay"]["roots"]["pr"] == corrupt_pr(push_principal)
            || push_body_res["statement"]["coz"]["pay"]["roots"]["sr"]
                == corrupt_sr(push_principal)
            || push_body_res["statement"]["coz"]["pay"]["roots"]["ar"]
                == corrupt_ar(push_principal)
            || push_body_res["statement"]["coz"]["pay"]["roots"]["cr"]
                == corrupt_cr(push_principal));
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
    let principal_id = common::golden_principal_id(&pool).await;
    let principal_id = principal_id.as_str();
    let now = 1_700_000_000;

    // 1. Initial valid push.
    let push_body = build_genesis_push_body(&pool, principal_id, now).await;
    let (status, push_res) = post_json(app.clone(), "/push", push_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis push failed: {push_res:?}"
    );

    // 2. Corrupt indexer.
    corrupt_indexer_tip(&state, principal_id).await;

    // 3. GET /tip with corrupted index.
    let (tip_status, tip_body) = get_json(app.clone(), &format!("/tip?pg={principal_id}")).await;

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
    let push_principal = common::genesis_push_id(&pool, "alice", "key_a").await;
    let push_principal = push_principal.as_str();
    corrupt_indexer_tip(&state, push_principal).await;
    let push_body_corrupt =
        common::build_genesis_push_body_with(&pool, "alice", "key_a", push_principal, now).await;
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
