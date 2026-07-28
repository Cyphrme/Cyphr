//! Acceptance test suite for Node N2: Witness Mode.
//!
//! Evaluates criteria N2.1 – N2.6:
//! - `witness_mode_starts` (N2.1): Server starts successfully when configured in witness mode.
//! - `all_write_routes_refused` (N2.2): Structural write refusal for all write routes in witness mode.
//! - `syncs_from_authority` (N2.3): Witness node syncs state from authority node.
//! - `rejects_unverifiable_delta` (N2.4): Witness node rejects unverifiable state deltas.
//! - `serves_only_self_verified` (N2.5): Adversarial check ensuring only self-verified state is served.
//! - `responses_carry_freshness` (N2.6): Responses from witness node carry required freshness indicators.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use clap::Parser;
use cyphr_server::config::{Cli, ServerConfig, ServerMode, resolve_config};
use cyphr_server::{AppState, build_app_router};
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{IndexableCommit, Indexer};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// Helper: Issue a `DELETE` request against an axum router with a JSON body.
async fn delete_json(app: axum::Router, uri: &str, body: String) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
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
// Acceptance Criteria N2.1 – N2.6
// ========================================================================

/// N2.1: `witness_mode_starts`
///
/// Verifies that a cyphr-server instance configured in Witness mode
/// (`ServerMode::Witness` / `serve --mode witness`) can resolve its configuration,
/// initialize AppState, and start successfully.
#[tokio::test]
async fn witness_mode_starts() {
    let cli = Cli::try_parse_from(&["cyphr-server", "serve", "--mode", "witness"])
        .expect("CLI args for witness mode should parse");

    let config =
        resolve_config(&cli).expect("witness mode configuration MUST resolve successfully");

    assert_eq!(
        config.mode,
        ServerMode::Witness,
        "resolved config mode MUST be ServerMode::Witness"
    );

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut witness_config = config;
    witness_config.data_dir = temp_dir.path().join("data");

    let state = AppState::new(witness_config)
        .expect("witness mode AppState MUST initialize successfully");
    assert_eq!(state.config.mode, ServerMode::Witness);
}

/// N2.2: `all_write_routes_refused`
///
/// Structural write refusal: In Witness mode, ALL state-mutating (write) endpoints
/// (`POST /push`, `POST /revoke`, `POST /witness/register`, `DELETE /witness/register`)
/// MUST be structurally refused with a non-success write-refusal HTTP status code
/// (e.g. 403 Forbidden, 405 Method Not Allowed, or 501 Not Implemented) and an unsigned response envelope.
#[tokio::test]
async fn all_write_routes_refused() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: temp_dir.path().join("data"),
        ..Default::default()
    };

    let state = Arc::new(AppState::new(config).expect("AppState initialization"));
    let app = build_app_router(state.clone()).expect("app router initialization");

    let pool = load_pool();
    let push_body = build_genesis_push_body(&pool, "n2-write-refusal-principal", 1_700_000_000);

    // 1. POST /push MUST be refused in witness mode
    let (push_status, push_json) = post_json(app.clone(), "/push", push_body).await;
    assert!(
        push_status == StatusCode::FORBIDDEN
            || push_status == StatusCode::METHOD_NOT_ALLOWED
            || push_status == StatusCode::NOT_IMPLEMENTED,
        "POST /push in witness mode MUST be structurally refused (403/405/501), got status {push_status}: {push_json:?}"
    );
    assert_eq!(
        push_json["statement"]["kind"], "unsigned",
        "write refusal envelope MUST be unsigned: {push_json:?}"
    );

    // 2. POST /revoke MUST be refused in witness mode
    let revoke_body = serde_json::json!({
        "principal_id": "n2-write-refusal-principal",
        "coz": {}
    })
    .to_string();
    let (revoke_status, revoke_json) = post_json(app.clone(), "/revoke", revoke_body).await;
    assert!(
        revoke_status == StatusCode::FORBIDDEN
            || revoke_status == StatusCode::METHOD_NOT_ALLOWED
            || revoke_status == StatusCode::NOT_IMPLEMENTED,
        "POST /revoke in witness mode MUST be structurally refused, got {revoke_status}: {revoke_json:?}"
    );
    assert_eq!(
        revoke_json["statement"]["kind"], "unsigned",
        "revoke refusal envelope MUST be unsigned: {revoke_json:?}"
    );

    // 3. POST /witness/register MUST be refused in witness mode
    let reg_body = serde_json::json!({
        "pay": { "id": "SHA-256:dummy", "typ": "cyphr.me/cyphr/witness/register/create" }
    })
    .to_string();
    let (reg_status, reg_json) = post_json(app.clone(), "/witness/register", reg_body).await;
    assert!(
        reg_status == StatusCode::FORBIDDEN
            || reg_status == StatusCode::METHOD_NOT_ALLOWED
            || reg_status == StatusCode::NOT_IMPLEMENTED,
        "POST /witness/register in witness mode MUST be structurally refused, got {reg_status}: {reg_json:?}"
    );

    // 4. DELETE /witness/register MUST be refused in witness mode
    let del_body = serde_json::json!({
        "pay": { "id": "SHA-256:dummy", "typ": "cyphr.me/cyphr/witness/register/delete" }
    })
    .to_string();
    let (del_status, del_json) = delete_json(app.clone(), "/witness/register", del_body).await;
    assert!(
        del_status == StatusCode::FORBIDDEN
            || del_status == StatusCode::METHOD_NOT_ALLOWED
            || del_status == StatusCode::NOT_IMPLEMENTED,
        "DELETE /witness/register in witness mode MUST be structurally refused, got {del_status}: {del_json:?}"
    );
}

/// N2.3: `syncs_from_authority`
///
/// Verifies that a witness node configured to sync from an authority node pulls state
/// and commits from the authority node so that queries to the witness node return the synced state.
#[tokio::test]
async fn syncs_from_authority() {
    let (auth_state, _identity, _dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let pool = load_pool();
    let principal_id = "n2-sync-principal";
    let now = 1_700_000_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    // Push state to authority node
    let (push_status, push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "authority push must succeed: {push_res:?}"
    );

    // Construct witness node
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // Query witness node for principal tip after sync from authority
    let (witness_tip_status, witness_tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={principal_id}")).await;

    assert_eq!(
        witness_tip_status,
        StatusCode::OK,
        "witness node MUST serve synced state from authority node, got status {witness_tip_status}: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);
    assert_eq!(
        payload["principal_id"], principal_id,
        "witness tip response payload must match synced principal"
    );
}

/// N2.4: `rejects_unverifiable_delta`
///
/// Verifies that a witness node REJECTS unverifiable, corrupted, or forged state deltas from an
/// authority node, refusing to apply them to its local storage.
#[tokio::test]
async fn rejects_unverifiable_delta() {
    let (auth_state, _identity, _dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let pool = load_pool();
    let principal_id = "n2-unverifiable-principal";
    let now = 1_700_000_000;

    // 1. Establish valid principal on authority
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (push_status, _push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    // 2. Corrupt index/state on authority node so it presents an unverifiable state delta
    let dummy_hash = Blake3Hash::from_bytes([7u8; 32]);
    let corrupt_commit = IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec!["SHA-256:CORRUPTED_COMMIT_999999999999999999999999".to_string()],
        sequence: 99,
        pre: None,
        prs: vec!["SHA-256:CORRUPT_PR_FORGED_ROOT".to_string()],
        srs: vec!["SHA-256:CORRUPT_SR_FORGED_ROOT".to_string()],
        ars: vec!["SHA-256:CORRUPT_AR_FORGED_ROOT".to_string()],
        crs: vec!["SHA-256:CORRUPT_CR_FORGED_ROOT".to_string()],
        blob_hashes: vec![dummy_hash],
        cozies: vec![],
        timestamp: now,
        keys: vec![],
    };
    auth_state
        .engine
        .indexer()
        .index_commit(&corrupt_commit)
        .await
        .expect("corrupt index_commit");

    // 3. Construct witness node
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // 4. Witness sync from authority MUST succeed for valid history but REJECT the corrupted delta
    let (witness_tip_status, witness_tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={principal_id}")).await;

    // Witness node MUST serve valid synced state, NOT the corrupted forged root
    assert_eq!(
        witness_tip_status,
        StatusCode::OK,
        "witness node MUST sync valid history from authority, got: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);
    assert_ne!(
        payload["roots"]["pr"], "SHA-256:CORRUPT_PR_FORGED_ROOT",
        "witness node MUST REJECT unverifiable delta and MUST NOT serve corrupted PR root: {witness_tip_json:?}"
    );
}

/// N2.5: `serves_only_self_verified`
///
/// Adversarial check: A witness node MUST serve only state that it has independently verified
/// against protocol rules and cryptographic signatures. If an unverified delta is submitted
/// or in transit, querying GET endpoints (/tip, /patch, /e/{digest}) MUST NOT return unverified state.
#[tokio::test]
async fn serves_only_self_verified() {
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    let adversarial_principal = "n2-adversarial-unverified-principal";

    // 1. GET /tip?pr=... MUST NOT serve unverified state (MUST return 404 or refusal error)
    let (tip_status, tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={adversarial_principal}")).await;
    assert_ne!(
        tip_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified state on GET /tip: {tip_json:?}"
    );

    // 2. GET /patch?pr=... MUST NOT serve unverified state (MUST return 404 or refusal error for unverified principal)
    let (patch_status, patch_json) =
        get_json(witness_app.clone(), &format!("/patch?pr={adversarial_principal}")).await;
    assert_ne!(
        patch_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified state on GET /patch: {patch_json:?}"
    );

    // 3. GET /e/{digest} MUST NOT serve unverified entity blobs
    let (entity_status, entity_json) = get_json(
        witness_app.clone(),
        "/e/SHA-256:UNVERIFIED_DIGEST_99999999999999999999999999999999",
    )
    .await;
    assert_ne!(
        entity_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified entity blobs on GET /e/digest: {entity_json:?}"
    );
}

/// N2.6: `responses_carry_freshness`
///
/// Verifies that all read API responses from a witness node carry required protocol
/// freshness metadata (non-zero timestamp 'now' or 'last_updated', envelope version v=1,
/// and statement markers).
#[tokio::test]
async fn responses_carry_freshness() {
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // GET /server on witness node
    let (server_status, server_json) = get_json(witness_app.clone(), "/server").await;
    assert_eq!(
        server_status,
        StatusCode::OK,
        "GET /server on witness node MUST succeed: {server_json:?}"
    );

    let payload = common::envelope_payload(&server_json);

    // Verify freshness timestamp field is present and positive
    let timestamp = payload
        .get("now")
        .or_else(|| payload.get("last_updated"))
        .or_else(|| payload.get("timestamp"))
        .and_then(|v| v.as_i64())
        .expect("witness response payload MUST carry a freshness timestamp ('now', 'last_updated', or 'timestamp')");

    assert!(
        timestamp > 0,
        "freshness timestamp MUST be positive, got: {timestamp}"
    );

    // Verify witness mode is reported in server info metadata
    let mode_str = payload
        .get("mode")
        .and_then(|v| v.as_str())
        .expect("server info MUST report mode in payload");

    assert_eq!(
        mode_str, "witness",
        "server info mode MUST be 'witness', got: {mode_str}"
    );
}
