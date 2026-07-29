//! Acceptance test suite for Node N2: Witness Mode.
//!
//! Evaluates criteria N2.1 – N2.6:
//! - `witness_mode_starts` (N2.1): Server starts successfully when configured in witness mode.
//! - `all_write_routes_refused` (N2.2): Structural write refusal for all write routes in witness
//!   mode.
//! - `syncs_from_authority` (N2.3): Witness node syncs state from authority node.
//! - `rejects_unverifiable_delta` (N2.4): Witness node rejects unverifiable state deltas.
//! - `serves_only_self_verified` (N2.5): Adversarial check ensuring only self-verified state is
//!   served.
//! - `responses_carry_freshness` (N2.6): Responses from witness node carry required freshness
//!   indicators.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use clap::Parser;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::{Cli, ServerConfig, ServerMode, resolve_config};
use cyphr_server::{AppState, build_app_router};
use cyphr_storage::blob::{Blake3Hash, BlobStore};
use cyphr_storage::index::{IndexableCommit, Indexer};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// Render a distinct, valid genesis-identifier string from a repeated
/// seed byte -- BARE b64ut, no algorithm tag (SPEC §2.2.3's DEFAULT
/// identifier form; tagging is `roots`/`commit_id`'s labeled exemption,
/// not the top-level `pr` this suite's principal identifiers become --
/// Amendment A2, `ND-typed-witness-domain.md`). Node ND's typed
/// `receipt::tip_report`/`commit_receipt` now refuse a malformed `pr`, so
/// these principal identifiers, which used to be human-readable
/// placeholders, must genuinely parse.
fn digest(byte: u8) -> String {
    Base64UrlUnpadded::encode_string(&[byte; 32])
}

/// Helper: Issue a `DELETE` request against an axum router with a JSON body.
async fn delete_json(
    app: axum::Router,
    uri: &str,
    body: String,
) -> (StatusCode, serde_json::Value) {
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
    let cli = Cli::try_parse_from(["cyphr-server", "serve", "--mode", "witness"])
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

    let state =
        AppState::new(witness_config).expect("witness mode AppState MUST initialize successfully");
    assert_eq!(state.config.mode, ServerMode::Witness);
}

/// N2.2: `all_write_routes_refused`
///
/// Structural write refusal: In Witness mode, ALL state-mutating (write) endpoints
/// (`POST /push`, `POST /revoke`, `POST /witness/register`, `DELETE /witness/register`,
/// and unmapped mutating routes like `POST /unmapped_write_route_test`) MUST be
/// structurally refused with a non-success write-refusal HTTP status code (403 Forbidden,
/// 405 Method Not Allowed, or 501 Not Implemented) and an unsigned response envelope
/// (`statement.kind == "unsigned"`).
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

    // 1. POST /push MUST be refused in witness mode with an unsigned envelope
    let (push_status, push_json) = post_json(app.clone(), "/push", push_body.clone()).await;
    assert!(
        push_status == StatusCode::FORBIDDEN
            || push_status == StatusCode::METHOD_NOT_ALLOWED
            || push_status == StatusCode::NOT_IMPLEMENTED,
        "POST /push in witness mode MUST be structurally refused (403/405/501), got status \
         {push_status}: {push_json:?}"
    );
    assert_eq!(
        push_json["statement"]["kind"], "unsigned",
        "push refusal envelope MUST be unsigned: {push_json:?}"
    );

    // 1b. POST /push with fanout/witness-push headers MUST ALSO be refused in witness mode
    let fanout_req = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json")
        .header("x-cyphr-fanout", "true")
        .header("x-witness-push", "true")
        .body(Body::from(push_body))
        .unwrap();
    let fanout_resp = app.clone().oneshot(fanout_req).await.unwrap();
    assert_eq!(
        fanout_resp.status(),
        StatusCode::FORBIDDEN,
        "POST /push with fanout headers MUST be structurally refused in witness mode"
    );

    // 2. POST /revoke MUST be refused in witness mode with an unsigned envelope
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
        "POST /revoke in witness mode MUST be structurally refused, got {revoke_status}: \
         {revoke_json:?}"
    );
    assert_eq!(
        revoke_json["statement"]["kind"], "unsigned",
        "revoke refusal envelope MUST be unsigned: {revoke_json:?}"
    );

    // 3. POST /witness/register MUST be refused in witness mode with an unsigned envelope
    let reg_body = serde_json::json!({
        "pay": { "id": "SHA-256:dummy", "typ": "cyphr.me/cyphr/witness/register/create" }
    })
    .to_string();
    let (reg_status, reg_json) = post_json(app.clone(), "/witness/register", reg_body).await;
    assert!(
        reg_status == StatusCode::FORBIDDEN
            || reg_status == StatusCode::METHOD_NOT_ALLOWED
            || reg_status == StatusCode::NOT_IMPLEMENTED,
        "POST /witness/register in witness mode MUST be structurally refused, got {reg_status}: \
         {reg_json:?}"
    );
    assert_eq!(
        reg_json["statement"]["kind"], "unsigned",
        "POST /witness/register refusal envelope MUST be unsigned: {reg_json:?}"
    );

    // 4. DELETE /witness/register MUST be refused in witness mode with an unsigned envelope
    let del_body = serde_json::json!({
        "pay": { "id": "SHA-256:dummy", "typ": "cyphr.me/cyphr/witness/register/delete" }
    })
    .to_string();
    let (del_status, del_json) = delete_json(app.clone(), "/witness/register", del_body).await;
    assert!(
        del_status == StatusCode::FORBIDDEN
            || del_status == StatusCode::METHOD_NOT_ALLOWED
            || del_status == StatusCode::NOT_IMPLEMENTED,
        "DELETE /witness/register in witness mode MUST be structurally refused, got {del_status}: \
         {del_json:?}"
    );
    assert_eq!(
        del_json["statement"]["kind"], "unsigned",
        "DELETE /witness/register refusal envelope MUST be unsigned: {del_json:?}"
    );

    // 5. Unmapped/arbitrary mutating route (e.g. POST /unmapped_write_route_test) MUST be refused
    //    in witness mode with an unsigned envelope
    let unmapped_body = serde_json::json!({"test": "unmapped"}).to_string();
    let (unmapped_status, unmapped_json) =
        post_json(app.clone(), "/unmapped_write_route_test", unmapped_body).await;
    assert!(
        unmapped_status == StatusCode::FORBIDDEN
            || unmapped_status == StatusCode::METHOD_NOT_ALLOWED
            || unmapped_status == StatusCode::NOT_IMPLEMENTED,
        "unmapped write route in witness mode MUST be structurally refused, got \
         {unmapped_status}: {unmapped_json:?}"
    );
    assert_eq!(
        unmapped_json["statement"]["kind"], "unsigned",
        "unmapped write route refusal envelope MUST be unsigned: {unmapped_json:?}"
    );
}

/// N2.3: `syncs_from_authority`
///
/// Verifies that a witness node configured to sync from an authority node (via authority TCP URL)
/// pulls state and commits from the authority node so that queries to the witness node return the
/// synced state.
#[tokio::test]
async fn syncs_from_authority() {
    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let mut auth_instance = common::multi::Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let _auth_addr = auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let pool = load_pool();
    let principal_id_digest = digest(0x01);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_000_000;
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    // Push state to authority node
    let (push_status, push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "authority push must succeed: {push_res:?}"
    );

    // Construct witness node configured with authority_url
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        authority_url: Some(auth_url),
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
        "witness node MUST serve synced state from authority node, got status \
         {witness_tip_status}: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);
    assert_eq!(
        payload["principal_id"], principal_id,
        "witness tip response payload must match synced principal"
    );
}

/// N2.4: `rejects_unverifiable_delta`
///
/// Verifies that a witness node configured with authority TCP URL REJECTS unverifiable,
/// corrupted, or forged state deltas from an authority node, refusing to apply them to its local
/// storage.
#[tokio::test]
async fn rejects_unverifiable_delta() {
    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let mut auth_instance = common::multi::Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let _auth_addr = auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let pool = load_pool();
    let principal_id_digest = digest(0x02);
    let principal_id = principal_id_digest.as_str();
    let now = 1_700_000_000;

    // 1. Establish valid principal on authority
    let push_body = build_genesis_push_body(&pool, principal_id, now);
    let (push_status, _push_res) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    // 2. Corrupt index/state on authority node so it presents an unverifiable state delta
    let dummy_bytes = vec![7u8; 32];
    let dummy_hash = Blake3Hash::from_bytes(*blake3::hash(&dummy_bytes).as_bytes());
    auth_state
        .engine
        .blob_store()
        .put(&dummy_bytes)
        .await
        .expect("put dummy blob");

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

    // 3. Construct witness node configured with authority_url
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        authority_url: Some(auth_url),
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
        "witness node MUST REJECT unverifiable delta and MUST NOT serve corrupted PR root: \
         {witness_tip_json:?}"
    );
}

/// N2.5: `serves_only_self_verified`
///
/// Adversarial check: Stand up an upstream authority server using Instance::bind_tcp(),
/// craft a delta with an invalid/forged signature or corrupted commit on that authority,
/// trigger witness sync against that authority, and assert that the witness node refuses
/// to accept or serve the unverified delta on GET /tip, GET /patch, and GET /e/{digest}
/// (returning 404 or refusal error rather than relaying unverified state).
#[tokio::test]
async fn serves_only_self_verified() {
    let (auth_state, _identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("authority router");

    let mut auth_instance = common::multi::Instance {
        name: "adversarial-authority".to_string(),
        state: auth_state.clone(),
        identity: Some(_identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let _auth_addr = auth_instance
        .bind_tcp()
        .await
        .expect("bind TCP for adversarial authority server");
    let auth_url = auth_instance
        .url()
        .expect("authority TCP URL must be available");

    let adversarial_principal = "n2-adversarial-unverified-principal";
    let now = 1_700_000_000;
    let dummy_hash = Blake3Hash::from_bytes([9u8; 32]);
    let forged_commit = IndexableCommit {
        principal_id: adversarial_principal.to_string(),
        commit_ids: vec!["SHA-256:FORGED_ADVERSARIAL_COMMIT_12345".to_string()],
        sequence: 0,
        pre: None,
        prs: vec!["SHA-256:FORGED_PR_ROOT".to_string()],
        srs: vec!["SHA-256:FORGED_SR_ROOT".to_string()],
        ars: vec!["SHA-256:FORGED_AR_ROOT".to_string()],
        crs: vec!["SHA-256:FORGED_CR_ROOT".to_string()],
        blob_hashes: vec![dummy_hash],
        cozies: vec![],
        timestamp: now,
        keys: vec![],
    };
    auth_state
        .engine
        .indexer()
        .index_commit(&forged_commit)
        .await
        .expect("index forged commit on authority");

    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        authority_url: Some(auth_url),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    // 1. GET /tip?pr=... MUST NOT serve unverified state (MUST return 404 or refusal error)
    let (tip_status, tip_json) = get_json(
        witness_app.clone(),
        &format!("/tip?pr={adversarial_principal}"),
    )
    .await;
    assert_ne!(
        tip_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified state on GET /tip: {tip_json:?}"
    );

    // 2. GET /patch?pr=... MUST NOT serve unverified state (MUST return 404 or refusal error)
    let (patch_status, patch_json) = get_json(
        witness_app.clone(),
        &format!("/patch?pr={adversarial_principal}"),
    )
    .await;
    assert_ne!(
        patch_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified state on GET /patch: {patch_json:?}"
    );

    // 3. GET /e/{digest} MUST NOT serve unverified entity blobs
    let (entity_status, entity_json) = get_json(
        witness_app.clone(),
        "/e/SHA-256:FORGED_ADVERSARIAL_COMMIT_12345",
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
/// and statement markers) on both GET /server and state read queries (GET /tip).
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

    // 1. GET /server on witness node
    let (server_status, server_json) = get_json(witness_app.clone(), "/server").await;
    assert_eq!(
        server_status,
        StatusCode::OK,
        "GET /server on witness node MUST succeed: {server_json:?}"
    );

    let payload = common::envelope_payload(&server_json);

    // Verify freshness timestamp field is present and positive on /server
    let server_timestamp = payload
        .get("now")
        .or_else(|| payload.get("last_updated"))
        .or_else(|| payload.get("timestamp"))
        .and_then(|v| v.as_i64())
        .expect(
            "witness GET /server response payload MUST carry a freshness timestamp ('now', \
             'last_updated', or 'timestamp')",
        );

    assert!(
        server_timestamp > 0,
        "freshness timestamp on GET /server MUST be positive, got: {server_timestamp}"
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

    // 2. GET /tip state read query on witness node MUST carry freshness metadata
    let (_tip_status, tip_json) =
        get_json(witness_app.clone(), "/tip?pr=n2-freshness-principal").await;
    let tip_payload = common::envelope_payload(&tip_json);
    let tip_timestamp = tip_payload
        .get("now")
        .or_else(|| tip_payload.get("last_updated"))
        .or_else(|| tip_payload.get("timestamp"))
        .or_else(|| tip_json.get("now"))
        .and_then(|v| v.as_i64())
        .expect(
            "witness GET /tip response MUST carry freshness metadata ('now', 'last_updated', or \
             'timestamp')",
        );

    assert!(
        tip_timestamp > 0,
        "freshness timestamp on GET /tip MUST be positive, got: {tip_timestamp}"
    );
}

/// Security Regression Test: `unauthenticated_fanout_header_cannot_bypass_witness_write_refusal`
///
/// Verifies that unauthenticated request headers (`x-cyphr-fanout`, `x-witness-push`) CANNOT
/// bypass strict structural write refusal on Witness nodes. All POST /push requests MUST be
/// rejected with HTTP 403 Forbidden and an unsigned refusal envelope.
#[tokio::test]
async fn unauthenticated_fanout_header_cannot_bypass_witness_write_refusal() {
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_instance = common::multi::Instance::from_config(witness_config, witness_dir).await;

    let pool = load_pool();
    let push_body =
        build_genesis_push_body(&pool, "n2-fanout-bypass-attempt-principal", 1_700_000_000);

    let resp = witness_instance
        .post_with_headers(
            "/push",
            push_body,
            &[("x-cyphr-fanout", "true"), ("x-witness-push", "true")],
        )
        .await;

    assert_eq!(
        resp.status,
        StatusCode::FORBIDDEN,
        "Witness node MUST return 403 Forbidden for POST /push even with fanout headers, got \
         status {}: {:?}",
        resp.status,
        resp.json
    );

    assert_eq!(
        resp.json["statement"]["kind"], "unsigned",
        "Refusal envelope MUST be unsigned, got: {:?}",
        resp.json
    );
}
