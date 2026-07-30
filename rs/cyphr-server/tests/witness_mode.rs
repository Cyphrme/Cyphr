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
use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::config::{AuthorityIdentity, Cli, ServerConfig, ServerMode, resolve_config};
use cyphr_server::{AppState, build_app_router, receipt};
use cyphr_storage::blob::{Blake3Hash, BlobStore};
use cyphr_storage::index::{IndexableCommit, Indexer};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// Render a distinct, valid genesis-identifier string from a repeated
/// seed byte -- BARE b64ut, no algorithm tag (SPEC §2.2.3's DEFAULT
/// identifier form; tagging is `roots`/`commit_id`'s labeled exemption,
/// not a principal's genesis identifier -- `docs/specs/receipts.md`).
/// `receipt::tip_report`/`commit_receipt` refuse a malformed `pr`, so
/// these principal identifiers must genuinely parse. Named
/// `principal_digest` (not `digest`) to stay distinct from the TAGGED
/// digest helper other test files use for `commit_id`/`roots` fixtures --
/// same shape, different wire form, never interchangeable.
fn principal_digest(byte: u8) -> String {
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
    let principal_id_digest = principal_digest(0x01);
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
    let principal_id_digest = principal_digest(0x02);
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

    // BIND THE CLAIM. `TipResponse` is FLAT: the served roots live at
    // payload.pr/sr/ar/cr, NOT under a `roots` object. The original assertion
    // indexed payload["roots"]["pr"], which is always `Null` (no such object),
    // so `assert_ne!(Null, "…")` held for every program state -- it could not
    // fail even against a witness that served the forged root verbatim. Index
    // the real fields.
    assert_ne!(
        payload["pr"], "SHA-256:CORRUPT_PR_FORGED_ROOT",
        "witness MUST NOT serve the forged PR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["sr"], "SHA-256:CORRUPT_SR_FORGED_ROOT",
        "witness MUST NOT serve the forged SR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["ar"], "SHA-256:CORRUPT_AR_FORGED_ROOT",
        "witness MUST NOT serve the forged AR root: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["cr"], "SHA-256:CORRUPT_CR_FORGED_ROOT",
        "witness MUST NOT serve the forged CR root: {witness_tip_json:?}"
    );

    // POSITIVE BINDING. A negative assertion alone still passes on an error
    // envelope or an unrelated shape. The witness's state must be EXACTLY the
    // legitimate genesis it verified: commit_count 1 (never the injected
    // sequence 99), and the served commit_id must not be the forged one.
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "witness must hold exactly the legitimate genesis (commit_count 1), never advance to the \
         injected sequence-99 delta: {witness_tip_json:?}"
    );
    assert_ne!(
        payload["commit_id"], "SHA-256:CORRUPTED_COMMIT_999999999999999999999999",
        "witness must serve the legitimate genesis commit, not the forged one: \
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

// ========================================================================
// N2 remediation: wedge elimination + authenticated channel + ingestion
// ========================================================================
//
// These acceptance tests drive deliverables 2, 4, and 5 of the sync-channel
// node. They are RED against the current code and GREEN once the honest
// outcome type, wedge fix, authenticated channel, and ingestion gate land.
//
// Design note -- why an on-path proxy / fixed mock, not two plain servers:
// the threats these tests bound are alterations of what the authority served
// (truncation, injection) and of what it signed (unsigned, mis-signed,
// non-canonical). A real attestor server serves only correct, fully-signed
// patches, so it cannot exhibit the shapes under test. The proxy reuses the
// authority's GENUINE signature and only deletes/injects entries (so the
// entry-binding check, not a broken signature, is what must catch it); the
// fixed mock serves a hand-crafted body a real server would never emit.
//
// Contract these tests pin (delegated shapes made concrete, honoring S3/S6):
//   * `ServerConfig::authority_identity: Option<AuthorityIdentity>` carries the expected
//     authority's alg + PUBLIC-KEY BYTES (not a bare thumbprint -- `coz::verify_json` needs key
//     material).
//   * When `authority_identity` is set, the witness MUST verify the patch envelope's signature
//     against it AND recompute the entry-commitment over the entries as received; an unsigned /
//     mis-signed / commitment-mismatch / non-canonical-report response is a `Failed` sync that
//     applies NOTHING.
//   * When it is UNSET, the legacy unauthenticated sync path is preserved (the existing
//     `syncs_from_authority` deployment shape): the wedge fix is orthogonal to the channel and
//     holds there.
//   * The authority's signed report rides the EXISTING envelope shape -- the signed coz at
//     `statement.coz`, exactly as `GET /tip` already returns `Envelope::signed(payload,
//     tip_report_coz)` (routes.rs). This is the one load-bearing assumption about the delegated
//     wrapping; it mirrors the established pattern rather than inventing a new one.

/// Append a single `key/create` commit (introducing `new_key_name`, signed by
/// `signer_name`) onto `principal`, and return the just-appended commit's wire
/// coz blobs with the new key embedded on its key-introducing cozy.
///
/// This is the per-commit core of `common::sign_key_create_commit`, lifted here
/// so TWO commits can be built on ONE principal (that helper takes the
/// principal by value and drops it, so it cannot chain a second commit; and
/// `common` is read-only for this node). Keeping one principal across both
/// commits is what makes the second genuinely chain -- `build_second_commit_
/// push_body` builds from a fresh principal and 409s with a state-root mismatch.
fn append_key_create(
    principal: &mut cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key_name: &str,
    now: i64,
) -> Vec<Vec<u8>> {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let new_key = pool.get(new_key_name).expect("new key in pool");

    let signer_tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");
    let new_tmb_b64 = new_key.compute_tmb_b64().expect("new key tmb");

    // Alphabetical field order matches `canonicalize_value`'s `sort_keys()`.
    let pay_value = serde_json::json!({
        "alg": signer.alg,
        "id": new_tmb_b64,
        "now": now,
        "tmb": signer_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_vec = serde_json::to_vec(&pay_value).unwrap();

    let signer_prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("valid signer prv base64");
    let signer_pub = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub");
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &signer.alg, &signer_prv, &signer_pub)
        .expect("signing supported for this algorithm");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).expect("czd for this algorithm");

    let new_cyphr_key = cyphr::Key {
        alg: new_key.alg.clone(),
        tmb: coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(&new_tmb_b64).expect("valid new key tmb base64"),
        ),
        pub_key: Base64UrlUnpadded::decode_vec(&new_key.pub_key).expect("valid new key pub base64"),
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_cyphr_key))
        .expect("key/create verifies against the current principal state");
    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_arrow(
            &signer.alg,
            &signer_prv,
            &signer_pub,
            &signer_tmb,
            now,
            "cyphr.me",
        )
        .expect("commit finalizes");

    let entries = cyphr_storage::export_commits(principal).expect("export commits");
    let new_commit = entries.last().expect("at least one commit after finalize");

    let mut key_idx = 0;
    new_commit
        .cozies
        .iter()
        .map(|v| {
            let mut coz = v.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < new_commit.keys.len() {
                let key = &new_commit.keys[key_idx];
                coz.as_object_mut().unwrap().insert(
                    "key".to_string(),
                    serde_json::json!({ "alg": key.alg, "pub": key.pub_key, "tmb": key.tmb }),
                );
                key_idx += 1;
            }
            serde_json::to_vec(&coz).expect("cozy serializes")
        })
        .collect()
}

/// Build genuine, CHAINING genesis + second-commit push bodies for one
/// principal: a `key/create` (key_a) genesis closed under the golden key, then
/// a second `key/create` (key_b) signed by golden onto the post-genesis state.
/// The two-entry patch the truncation test needs.
fn build_two_commit_push_bodies(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    now: i64,
) -> (String, String) {
    let golden = pool.get("golden").expect("golden key");
    let golden_key = cyphr::Key {
        alg: golden.alg.clone(),
        tmb: golden.compute_tmb().expect("golden tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("golden pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    let mut principal = cyphr::Principal::implicit(golden_key.clone()).expect("implicit genesis");

    // Commit 0 (genesis): introduce key_a, then embed the golden genesis key on
    // the closing cozy -- the wire contract `resolve_genesis` needs for a
    // never-before-seen principal (mirrors `build_genesis_push_body`).
    let mut c0 = append_key_create(&mut principal, pool, "golden", "key_a", now);
    let closing = c0.len() - 1;
    let mut closing_coz: serde_json::Value = serde_json::from_slice(&c0[closing]).unwrap();
    closing_coz.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": golden_key.alg,
            "pub": golden.pub_key,
            "tmb": Base64UrlUnpadded::encode_string(golden_key.tmb.as_bytes()),
        }),
    );
    c0[closing] = serde_json::to_vec(&closing_coz).unwrap();

    // Commit 1: introduce key_b, signed by the still-active golden key.
    let c1 = append_key_create(&mut principal, pool, "golden", "key_b", now + 1);

    let body = |blobs: &[Vec<u8>]| {
        serde_json::json!({
            "principal_id": principal_id,
            "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
        })
        .to_string()
    };
    (body(&c0), body(&c1))
}

/// A mutation applied to an upstream `/patch` JSON body by the proxy below.
type PatchMutation = Arc<dyn Fn(serde_json::Value) -> serde_json::Value + Send + Sync>;

/// Spawn a mock authority that serves a FIXED JSON body for `GET /patch`
/// (any query) over a real ephemeral TCP socket. Returns its base URL and the
/// task handle -- hold the handle for the test's lifetime (drop/abort stops
/// it). Serves hand-crafted patch responses a real server would never emit.
async fn spawn_fixed_authority(body: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock authority listener");
    let addr = listener.local_addr().expect("mock authority local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Spawn an on-path proxy in front of `upstream`: for each `GET /patch` it
/// forwards the request (preserving the query), then applies `mutate` to the
/// returned JSON body. Models an on-path party altering what the authority
/// served WITHOUT touching the authority's signature.
async fn spawn_patch_proxy(
    upstream: String,
    mutate: PatchMutation,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let mutate = mutate.clone();
            async move {
                let url = match raw.0 {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                axum::Json(mutate(body))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// A running attestor authority bound on TCP, holding `principal_id`.
/// Hold the whole struct: dropping it aborts the TCP task and removes the
/// backing store.
struct RunningAuthority {
    instance: common::multi::Instance,
    url: String,
}

impl RunningAuthority {
    fn identity(&self) -> AuthorityIdentity {
        let id = self
            .instance
            .identity
            .as_ref()
            .expect("attestor authority holds a signing identity");
        AuthorityIdentity {
            alg: id.alg().name().to_string(),
            pub_key: id.pub_key().to_vec(),
        }
    }
}

/// Stand up a real attestor authority on TCP and push a genuine genesis for
/// `principal_id` over HTTP.
async fn authority_with_genesis(principal_id: &str, now: i64) -> RunningAuthority {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state,
        identity: Some(identity),
        dir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind authority TCP");
    let url = instance.url().expect("authority TCP URL");

    let pool = load_pool();
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, principal_id, now),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "authority genesis push: {body:?}"
    );

    RunningAuthority { instance, url }
}

/// Stand up a real attestor authority on TCP holding a genuine TWO-commit
/// principal, pushed over HTTP (genesis + a chaining second commit). The
/// witness syncs HTTP-pushed principals; a fixture bootstrapped directly into
/// the engine does NOT round-trip through the witness's genesis auto-detection.
async fn authority_with_two_commits(principal_id: &str, now: i64) -> RunningAuthority {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state,
        identity: Some(identity),
        dir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind authority TCP");
    let url = instance.url().expect("authority TCP URL");

    let pool = load_pool();
    let (genesis_body, second_body) = build_two_commit_push_bodies(&pool, principal_id, now);
    let (s0, b0) = post_json(app.clone(), "/push", genesis_body).await;
    assert_eq!(s0, StatusCode::CREATED, "genesis push: {b0:?}");
    let (s1, b1) = post_json(app.clone(), "/push", second_body).await;
    assert_eq!(s1, StatusCode::CREATED, "second commit push: {b1:?}");

    RunningAuthority { instance, url }
}

/// Build a witness `AppState` + router pointed at `authority_url`, optionally
/// carrying an expected authority identity (the authenticated channel).
async fn witness_for(
    authority_url: &str,
    authority_identity: Option<AuthorityIdentity>,
) -> (Arc<AppState>, axum::Router) {
    let dir = tempfile::tempdir().expect("witness tempdir");
    let config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: dir.path().join("data"),
        authority_url: Some(authority_url.to_string()),
        authority_identity,
        ..Default::default()
    };
    // Leak the TempDir guard for the test's lifetime: the witness store must
    // outlive this function. Tests are short-lived processes.
    std::mem::forget(dir);
    let state = Arc::new(AppState::new(config).expect("witness AppState"));
    let app = build_app_router(state.clone()).expect("witness router");
    (state, app)
}

/// N2.1: a witness stalled by one malformed entry still applies a later good
/// entry -- no permanent wedge.
///
/// The sync audit's S4 wedge: an entry whose `blobs` array is empty aborts the
/// entire apply loop, and because nothing advanced, every later sync refetches
/// and re-aborts on the same entry -- a permanent, silent stall that also
/// blocks every GENUINE entry positioned after it. Here the malformed entry is
/// spliced BEFORE the genuine genesis, so under the current code the genesis
/// (the only real commit) never applies and the witness answers 404 forever.
/// A witness that gets past the bad entry applies the genesis and serves it.
///
/// Runs in the UNAUTHENTICATED sync mode (no expected identity): the wedge fix
/// is orthogonal to the authenticated channel and must hold on the legacy path.
#[tokio::test]
async fn sync_recovers_after_bad_entry() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x11);
    let authority = authority_with_genesis(&principal, now).await;

    let bad_pr = principal.clone();
    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(move |mut body: serde_json::Value| {
            let bad_entry = serde_json::json!({
                "commit_id": "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "sequence": 0,
                "pr": bad_pr,
                "blobs": [],
            });
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                entries.insert(0, bad_entry);
            }
            body
        }),
    )
    .await;

    let (_witness_state, witness_app) = witness_for(&proxy_url, None).await;

    // One /tip drives one sync attempt.
    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a malformed entry preceding the genesis must not permanently wedge the sync -- the \
         genuine genesis MUST still apply and be served: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], principal);
    assert!(
        payload["commit_count"].as_u64().unwrap_or(0) >= 1,
        "witness must have applied the genuine genesis past the bad entry: {json:?}"
    );
}

/// N2.1 (sibling): a witness stalled by one UNVERIFIABLE entry still applies
/// a later good entry -- the wedge's SECOND trigger site.
///
/// `sync_from_authority`'s per-entry loop wedges at two structurally
/// identical `break`s: blob-DECODE failure, and `submit_commit`
/// VERIFICATION failure (sync.rs -- the "rejected unverifiable delta"
/// arm). Both share the mechanism (nothing persists progress, `from_seq`
/// is recomputed fresh, the bad entry is refetched forever), but sharing a
/// mechanism is an argument, not evidence: a fix applied only to the
/// decode `break` leaves this second, equally real wedge open while
/// `sync_recovers_after_bad_entry` goes green. This sibling exercises the
/// second site with its own diagnostic.
///
/// The proxy clones the GENUINE genesis entry and corrupts one signature
/// inside its blobs: the entry stays well-formed (valid base64, valid coz
/// JSON -- it sails past the decode stage) but fails cryptographic
/// verification inside `submit_commit`. Spliced BEFORE the genuine
/// genesis, it wedges the loop at the verification `break` under the
/// current code, so the only real commit never applies.
///
/// Runs in the UNAUTHENTICATED sync mode (no expected identity), exactly
/// as the decode-site sibling: the wedge fix is orthogonal to the
/// authenticated channel and must hold on the legacy path.
#[tokio::test]
async fn sync_recovers_after_unverifiable_entry() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x12);
    let authority = authority_with_genesis(&principal, now).await;

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            let Some(entries) = body["payload"]["entries"].as_array_mut() else {
                return body;
            };
            let Some(genuine) = entries.first() else {
                return body;
            };

            // Corrupt the first blob's signature: decode the blob, flip the
            // sig's leading character to a DIFFERENT base64url character, and
            // re-encode. Everything about the entry still decodes and parses;
            // only the cryptographic check can reject it.
            let mut bad = genuine.clone();
            let blob_b64 = bad["blobs"][0]
                .as_str()
                .expect("genuine entry blob is a base64 string")
                .to_string();
            let blob =
                Base64UrlUnpadded::decode_vec(&blob_b64).expect("genuine entry blob decodes");
            let mut coz: serde_json::Value =
                serde_json::from_slice(&blob).expect("genuine entry blob is coz JSON");
            let mut sig = coz["sig"]
                .as_str()
                .expect("genuine coz carries a sig")
                .to_string();
            let flipped = if sig.starts_with('A') { "B" } else { "A" };
            sig.replace_range(0..1, flipped);
            coz["sig"] = sig.into();
            bad["blobs"][0] =
                Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).unwrap()).into();

            entries.insert(0, bad);
            body
        }),
    )
    .await;

    let (_witness_state, witness_app) = witness_for(&proxy_url, None).await;

    // One /tip drives one sync attempt.
    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a well-formed but UNVERIFIABLE entry preceding the genesis must not permanently wedge \
         the sync at the verification-failure break (the submit_commit arm, the wedge's second \
         trigger site) -- the genuine genesis MUST still apply and be served: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], principal);
    assert!(
        payload["commit_count"].as_u64().unwrap_or(0) >= 1,
        "witness must have applied the genuine genesis past the unverifiable entry: {json:?}"
    );
}

/// N2.4: a patch response NOT signed by the expected authority identity is
/// rejected -- no entry applied.
///
/// The witness expects a fresh identity the authority has never signed with,
/// so the authority's envelope -- unsigned today, or signed under the
/// authority's OWN key once the channel is authenticated -- cannot verify
/// against the expected key. An unverifiable channel must yield no applied
/// state, so `GET /tip` for the principal is NOT 200.
#[tokio::test]
async fn patch_envelope_authority_signature() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x14);
    let authority = authority_with_genesis(&principal, now).await;

    let expected = coz::Alg::Ed25519.generate_keypair();
    let wrong_identity = AuthorityIdentity {
        alg: expected.alg.name().to_string(),
        pub_key: expected.pub_bytes.clone(),
    };
    let (_witness_state, witness_app) = witness_for(&authority.url, Some(wrong_identity)).await;

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a patch response not signed by the EXPECTED authority identity must be rejected: the \
         witness must not apply or serve its entries: {json:?}"
    );
}

/// N2.4b: a patch whose entries were TRUNCATED after signing is rejected --
/// the post-apply reconciliation catches that local state falls short of
/// what the signed report attests.
///
/// The on-path proxy drops the trailing entry of a genuinely-signed,
/// two-commit patch. Every entry that remains is authentic and the
/// authority's signature still verifies -- so a channel that only checks
/// "is the signature valid?" accepts it and applies the short prefix
/// silently, as `Synced`.
///
/// REWORK NOTE (discrepancy surfaced, not silently resolved): the base IBC's
/// N2.4b text says "nothing applied." This node's council round (attack +
/// security + architect, converged) rejected pre-apply atomicity as the
/// mechanism -- see `architect-N2-round.md`'s "digest-over-all declination":
/// a genuine chain-verified PREFIX apply is explicitly ruled SOUND ("exactly
/// one reachable from an honest, shorter serving -- monotone, no integrity
/// loss"), and this node's own S3 forbids changing what a caller serves ("log
/// distinctly and proceed to serve as today"). Under that ratified design the
/// genuine sequence-0 entry legitimately applies and `/tip` legitimately
/// keeps serving it -- checking the NEXT `/tip` call's HTTP status is no
/// longer a valid proxy for "was the truncation caught." What must hold, and
/// is asserted directly below, is that the SYNC OUTCOME reports the
/// mismatch (never `Synced`) and that local state never silently advances
/// past the withheld commit.
#[tokio::test]
async fn patch_truncated_entries_rejected() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x1e);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                if entries.len() > 1 {
                    entries.pop();
                }
            }
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "a patch whose entries were truncated after signing must never report success, got \
         {outcome:?}"
    );

    // Local state may legitimately hold the sound genesis prefix (per the
    // ratified design), but must never have silently advanced to the
    // withheld second commit. Read the engine directly, not via a second
    // `/tip` round trip: the proxy's truncation is keyed on "does this
    // response hold more than one entry," so a SECOND sync attempt (with
    // `from` advanced past 0) would ask the real authority for only the
    // remaining entry, which the proxy then passes through untouched --
    // correctly resyncing on the next honest attempt, but not exercising
    // this test's property.
    let resulting = witness_state
        .engine
        .get_tip(&principal)
        .await
        .expect("local tip lookup");
    let commit_count = resulting.map(|t| t.commit_count);
    assert_eq!(
        commit_count,
        Some(1),
        "the witness must hold only the sound genesis prefix, never the withheld second commit: \
         {commit_count:?}"
    );
}

/// Sign a tip-report-shaped coz over `pay` with `identity`. The report rides
/// the wire as `{pay, sig}`; the signature is computed over the canonical `pay`
/// exactly as `coz::verify_json` re-canonicalizes it, so a validly-signed but
/// SEMANTICALLY malformed report (e.g. a non-canonical `pr`) still verifies --
/// isolating the parse gate from the signature gate.
fn sign_report(identity: &ServerIdentity, pay: serde_json::Value) -> coz::CozJson {
    let pay_bytes = serde_json::to_vec(&pay).expect("serialize report pay");
    let (sig, _cad) = identity
        .sign(&pay_bytes)
        .expect("authority signs report pay");
    coz::CozJson { pay, sig }
}

/// Stand up a real attestor, push a genesis for `principal`, and return its
/// genuine `/patch` entries array, its REAL signed `/tip` report (the
/// attestor's own `statement.coz`), and the signing identity (plus the store
/// guard to hold). The entries are authentic, so a witness with NO ingestion
/// gate would apply them -- which is exactly what the malformed-report test
/// must observe the gate PREVENT -- and the real report is the byte-genuine
/// claim set the accept-direction test derives its one-field-emptied fixture
/// from.
async fn genuine_entries_and_identity(
    principal: &str,
    now: i64,
) -> (
    serde_json::Value,
    coz::CozJson,
    Arc<ServerIdentity>,
    tempfile::TempDir,
) {
    let (state, identity, dir) = attestor_server().await;
    let app = build_app_router(state.clone()).expect("authority router");
    let pool = load_pool();
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, principal, now),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "genesis push: {body:?}");
    let (pstatus, patch) = get_json(app.clone(), &format!("/patch?pr={principal}&from=0")).await;
    assert_eq!(pstatus, StatusCode::OK, "authority /patch: {patch:?}");
    let entries = patch["payload"]["entries"].clone();
    assert!(
        entries.as_array().map(|e| !e.is_empty()).unwrap_or(false),
        "authority must serve at least the genesis entry: {patch:?}"
    );

    let (tstatus, tip) = get_json(app, &format!("/tip?pr={principal}")).await;
    assert_eq!(tstatus, StatusCode::OK, "authority /tip: {tip:?}");
    assert_eq!(
        tip["statement"]["kind"], "signed",
        "an attestor authority must sign its tip report: {tip:?}"
    );
    let report: coz::CozJson = serde_json::from_value(tip["statement"]["coz"].clone())
        .expect("authority tip statement.coz deserializes as a coz");

    (entries, report, identity, dir)
}

/// N2.8 (reject direction): a witness refuses to ingest a report that fails
/// `TipReport::parse`, even when it is validly signed by the expected authority.
///
/// This is the load-bearing half of the cross-node equivocation closure: ND
/// made `check_equivocation` compare TYPED values, but a report that cannot be
/// typed yields "no claim", observationally identical to the evasion. The
/// closure holds only if a malformed report never becomes a retained/applied
/// attestation in the first place -- and ingestion is this node's surface.
///
/// The mock serves GENUINE entries (a witness with no gate would apply them)
/// wrapped in `Envelope::signed` whose statement coz is a VALIDLY-SIGNED report
/// with a non-canonical `pr` (a JSON array -- `TipReport::parse`'s
/// `parse_genesis_id` rejects it; it is never unwrapped to an inner string).
/// The signature verifies (isolating the PARSE gate from the signature gate),
/// so a witness that stops at "signature valid" applies the entries. A witness
/// that parses the report before acting rejects it and applies nothing.
///
/// NB (a discrepancy surfaced): the IBC lists `sequence: "5"` as a malformed
/// example, but the merged `TipReport::parse` CANONICALIZES a decimal-string
/// sequence (`"5"` -> 5) -- it is accepted, not rejected. The genuinely
/// non-canonical shape used here is `pr: [..]`; a malformed sequence would be
/// `"5x"`/`""`/`true`, never `"5"`.
#[tokio::test]
async fn witness_rejects_malformed_report_at_ingestion() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x18);
    let (entries, _real_report, identity, _auth_dir) =
        genuine_entries_and_identity(&principal, now).await;

    let tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("authority thumbprint");
    let malformed_pay = serde_json::json!({
        "alg": identity.alg().name(),
        "now": now,
        "tmb": Base64UrlUnpadded::encode_string(tmb.as_bytes()),
        "typ": receipt::TIP_REPORT_TYP,
        // NON-CANONICAL: `pr` is a JSON array, not a bare b64ut genesis id.
        "pr": ["SHA-256:not-a-genesis-identifier"],
        "sequence": 0,
        "commit_id": TaggedDigest::new(HashAlg::Sha256, vec![0x18; 32]).unwrap().to_string(),
        "roots": {
            "pr": TaggedDigest::new(HashAlg::Sha256, vec![0x19; 32]).unwrap().to_string(),
            "sr": TaggedDigest::new(HashAlg::Sha256, vec![0x1a; 32]).unwrap().to_string(),
            "ar": TaggedDigest::new(HashAlg::Sha256, vec![0x1b; 32]).unwrap().to_string(),
            "cr": "",
        },
    });
    let report = sign_report(&identity, malformed_pay);

    // PIN that the violating shape is exactly what the invariant demands: the
    // report carries a VALID signature by the expected authority AND is
    // REJECTED by the gate's own parser. Together these isolate the PARSE gate
    // from the signature gate -- a rejection under test cannot be blamed on a
    // bad signature, and the report genuinely fails `TipReport::parse`.
    assert_eq!(
        coz::verify_json(
            &serde_json::to_vec(&report.pay).unwrap(),
            &report.sig,
            identity.alg().name(),
            identity.pub_key(),
        ),
        Some(true),
        "the malformed report MUST be validly signed by the expected authority"
    );
    assert!(
        receipt::TipReport::parse(&report).is_err(),
        "the report MUST fail TipReport::parse (the ingestion gate's own parser)"
    );

    let body = serde_json::json!({
        "v": 1,
        "payload": { "principal_id": principal, "entries": entries },
        "statement": { "kind": "signed", "coz": serde_json::to_value(&report).unwrap() },
    });
    let (mock_url, _mock) = spawn_fixed_authority(body).await;

    let expected = AuthorityIdentity {
        alg: identity.alg().name().to_string(),
        pub_key: identity.pub_key().to_vec(),
    };
    let (_witness_state, witness_app) = witness_for(&mock_url, Some(expected)).await;

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a validly-signed but NON-CANONICAL report must be refused at ingestion -- its (genuine) \
         entries must NOT be applied or served: {json:?}"
    );
}

/// N2.8 (accept direction): a report with NO commit root (`cr: ""`) --
/// validly signed by the expected authority, every OTHER claim byte-genuine
/// -- is ACCEPTED at ingestion, not over-rejected.
///
/// The other half of the two-sided property, built with the same rigor as
/// the reject-direction sibling: hand-construct the input, sign it for
/// real, and self-validate in-test that it genuinely has the property
/// under test before asserting the outcome.
///
/// WHY an empty `cr` is a legitimate wire value with real producers, not a
/// hypothetical: the engine reports "no commit root yet" as an empty
/// string for any principal whose EML log has no leaf (`DerivedRoots`
/// derivation in `cyphr-storage`'s engine), its reindex path indexes
/// legacy/synthetic implicit-genesis principals with `crs: Vec::new()`
/// ("No CR at genesis: PR = SR until the first real commit populates the
/// EML log"), and `receipt::sign_receipt`'s own construction-time
/// validation deliberately signs `cr: ""` through the same optional parse
/// `TipReport::parse` uses. A key-established principal with no commit
/// root is a spec-level state (`docs/specs/receipts.md`); an ingestion
/// gate rejecting its report re-creates, at this boundary, the exact
/// over-rejection availability defect already shipped three times in this
/// remediation.
///
/// FIXTURE HONESTY: no ordinary PUSH path on this Rust authority yields a
/// servable tip with an empty `cr` (`finalize_commit` writes CR on every
/// finalized commit), so a plain end-to-end sync cannot exercise this
/// value -- the prior version of this test claimed it did and did not
/// (its fixture's `cr` was a real digest). Instead the fixture takes the
/// authority's REAL signed tip report, empties exactly `roots.cr`, and
/// re-signs with the same identity: every mandatory claim (`pr`,
/// `sequence`, `commit_id`, `roots.pr/sr/ar`, `commit_count`) stays
/// byte-identical to what the true authority attests for these same
/// entries, so a correct fail-closed entry-binding has nothing to reject.
/// The `cr` claim alone flips from present to ABSENT -- the authority's
/// declared "no commit root yet", the one root the wire contract makes
/// optional. Only an implementation that treats that absence as malformed
/// (a parse weakened to reject `""`) or as a binding violation turns this
/// red -- and both of those ARE the defect this test exists to catch.
///
/// The in-test self-validations hold at baseline; the negative control
/// (red against a deliberately over-rejecting gate) cannot be exercised
/// until the gate exists, and is a lead-maintainer merge-gate review
/// obligation, exactly as N2.3's weakened-implementation control.
#[tokio::test]
async fn witness_accepts_genesis_report_at_ingestion() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x1c);
    let (entries, real_report, identity, _auth_dir) =
        genuine_entries_and_identity(&principal, now).await;

    // The true authority's report carries a REAL commit root for these
    // entries -- the fixture below genuinely flips a present claim to an
    // absent one, rather than restating what the authority already says.
    let parsed_real =
        receipt::TipReport::parse(&real_report).expect("the authority's own tip report parses");
    assert!(
        parsed_real.roots.cr.is_some(),
        "the authority's true tip must carry a commit root -- otherwise this fixture empties \
         nothing: {:?}",
        real_report.pay
    );

    // Empty exactly `roots.cr`; re-sign the otherwise byte-genuine claims
    // with the authority's real identity.
    let mut pay = real_report.pay.clone();
    pay["roots"]["cr"] = serde_json::Value::String(String::new());
    let report = sign_report(&identity, pay);

    // PIN the property under test, mirroring the reject-direction sibling:
    // the report is validly signed by the EXPECTED authority, and the
    // gate's own parser accepts it with the commit root typed as ABSENT.
    assert_eq!(
        coz::verify_json(
            &serde_json::to_vec(&report.pay).unwrap(),
            &report.sig,
            identity.alg().name(),
            identity.pub_key(),
        ),
        Some(true),
        "the empty-cr report MUST be validly signed by the expected authority"
    );
    let parsed = receipt::TipReport::parse(&report).expect(
        "an empty cr is 'no commit root yet', never malformed -- TipReport::parse MUST accept it",
    );
    assert!(
        parsed.roots.cr.is_none(),
        "the fixture MUST genuinely carry an empty commit root, typed as None: {:?}",
        report.pay
    );

    let body = serde_json::json!({
        "v": 1,
        "payload": { "principal_id": principal, "entries": entries },
        "statement": { "kind": "signed", "coz": serde_json::to_value(&report).unwrap() },
    });
    let (mock_url, _mock) = spawn_fixed_authority(body).await;

    let expected = AuthorityIdentity {
        alg: identity.alg().name().to_string(),
        pub_key: identity.pub_key().to_vec(),
    };
    let (_witness_state, witness_app) = witness_for(&mock_url, Some(expected)).await;

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a validly-signed report whose commit root is ABSENT (cr empty -- 'no commit root yet') \
         must be ACCEPTED at ingestion and its genuine entries applied and served, never \
         over-rejected: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], principal);
    assert!(
        payload["commit_count"].as_u64().unwrap_or(0) >= 1,
        "witness must have applied the accepted genesis: {json:?}"
    );
}

/// Authenticated-channel positive control: a witness configured with the
/// expected authority identity, syncing an UNTAMPERED real authority, must
/// accept and serve -- the end-to-end interop bind between serve-side
/// envelope signing and sync-side verification.
///
/// Every other authenticated-channel test rejects (unsigned, mis-signed,
/// truncated, malformed report) or drives a mock; a channel implementation
/// that over-rejects the REAL authority's genuine wire shape would leave
/// all of them green while breaking every actual deployment. This is the
/// whole-loop accept that forces the two sides to interoperate once
/// serve-side signing lands. (This fixture's tip report carries a real,
/// non-empty commit root -- the empty-`cr` accept case is
/// `witness_accepts_genesis_report_at_ingestion` above.)
#[tokio::test]
async fn authenticated_channel_accepts_genuine_authority() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x1d);
    let authority = authority_with_genesis(&principal, now).await;
    let authority_identity = authority.identity();

    let (_witness_state, witness_app) = witness_for(&authority.url, Some(authority_identity)).await;

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a witness holding the expected authority identity must accept an untampered genuine \
         authority's patch and serve the synced state: {json:?}"
    );
    let payload = common::envelope_payload(&json);
    assert_eq!(payload["principal_id"], principal);
    assert!(
        payload["commit_count"].as_u64().unwrap_or(0) >= 1,
        "witness must have applied the synced genesis: {json:?}"
    );
}

// ========================================================================
// N2 rework: post-apply reconciliation against the witness's OWN resulting
// state, and the cross-principal `pr` check
// ========================================================================
//
// The prior authenticated-channel gate compared the response's claimed
// `(sequence, commit_id)` against the SAME values the signed report carries
// in the clear -- a check any on-path reader can reproduce for free, since
// it never touches anything the witness itself verifies or produces. These
// tests derive from the attack/security/architect council round on this
// node (`.scratch/campaigns/server-witness-remediation/probes/N2-hacker.md`,
// `N2-security.md`, `architect-N2-round.md`): each pins one shape that
// defeated the old gate and must be caught by the new one.

/// Spawn an on-path proxy that rewrites the REQUEST query before forwarding,
/// leaving the authority's response byte-for-byte genuine. Models a party
/// that never touches what the authority serves, only what it is asked --
/// the shape no response-integrity check can ever see.
async fn spawn_query_rewriting_proxy(
    upstream: String,
    rewrite: Arc<dyn Fn(Option<String>) -> Option<String> + Send + Sync>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let rewrite = rewrite.clone();
            async move {
                let q = rewrite(raw.0);
                let url = match q {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                axum::Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Build a genuine genesis push body whose genesis key is `signer` (not
/// `golden`), so the resulting chain has a genuinely DIFFERENT principal
/// root from the golden-keyed fixtures every other test in this file uses --
/// required so the cross-principal test below cannot be dismissed as an
/// artifact of every fixture sharing one genesis key.
fn build_genesis_push_body_with(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    now: i64,
    signer: &str,
    new_key: &str,
) -> String {
    let g = pool.get(signer).expect("signer key in pool");
    let g_key = cyphr::Key {
        alg: g.alg.clone(),
        tmb: g.compute_tmb().expect("signer tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&g.pub_key).expect("signer pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };
    let mut principal = cyphr::Principal::implicit(g_key.clone()).expect("implicit genesis");
    let mut blobs = append_key_create(&mut principal, pool, signer, new_key, now);
    let closing = blobs.len() - 1;
    let mut closing_coz: serde_json::Value = serde_json::from_slice(&blobs[closing]).unwrap();
    closing_coz.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": g_key.alg,
            "pub": g.pub_key,
            "tmb": Base64UrlUnpadded::encode_string(g_key.tmb.as_bytes()),
        }),
    );
    blobs[closing] = serde_json::to_vec(&closing_coz).unwrap();
    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// N2 rework, fix 1: cross-principal state substitution is rejected before
/// any entry is applied.
///
/// An on-path proxy rewrites only the OUTBOUND request's `pr` from A to B;
/// the authority answers completely honestly for B. Every prior check
/// passes -- the signature verifies, the report parses, its claims are
/// internally consistent -- because the response genuinely is what it
/// claims to be, just an answer about a different principal. Principal A's
/// and B's genesis keys are genuinely distinct (`alice` vs `golden`), so
/// this is not a shared-fixture artifact: if the witness ever applied B's
/// blobs under A's identifier, A's `/tip` would come back 200 holding B's
/// chain.
#[tokio::test]
async fn cross_principal_substitution_rejected() {
    let now = 1_700_000_000;
    let principal_a = principal_digest(0x81);
    let principal_b = principal_digest(0x82);

    let authority = authority_with_two_commits(&principal_b, now).await;
    let authority_identity = authority.identity();
    let pool = load_pool();
    let (status, body) = post_json(
        authority.instance.router.clone(),
        "/push",
        build_genesis_push_body_with(&pool, &principal_a, now, "alice", "bob"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "principal A genesis push: {body:?}"
    );

    let b_for_rewrite = principal_b.clone();
    let (proxy_url, _proxy) = spawn_query_rewriting_proxy(
        authority.url.clone(),
        Arc::new(move |_q: Option<String>| Some(format!("pr={b_for_rewrite}&from=0"))),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal_a).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::PrincipalMismatch
            }
        ),
        "a genuine, validly-signed response for a DIFFERENT principal must be rejected as a \
         principal mismatch before any entry applies, got {outcome:?}"
    );

    // A's own state must be untouched -- never advanced to B's chain.
    let (status_a, json_a) = get_json(witness_app, &format!("/tip?pr={principal_a}")).await;
    if status_a == StatusCode::OK {
        let payload = common::envelope_payload(&json_a);
        assert_eq!(
            payload["commit_count"].as_u64(),
            Some(1),
            "principal A must hold only its own genesis (commit_count 1), never B's chain: \
             {json_a:?}"
        );
    }
}

/// N2 rework, fix 2 (part a): a decoy top entry that preserves its victim's
/// declared `(sequence, commit_id)` labels while swapping in junk `blobs` no
/// longer defeats the channel -- the witness's post-apply resulting state,
/// not any label carried on the wire, is what gets compared against the
/// signed attestation.
///
/// Run across three polls: the withholding must be caught EVERY time, never
/// silently accepted even once.
#[tokio::test]
async fn decoy_top_entry_withholding_rejected() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x7a);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            // Withhold sequence 1 on every response, leaving a decoy that
            // carries its genuine labels but junk blobs as the top entry.
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                for e in entries.iter_mut() {
                    if e["sequence"].as_u64() == Some(1) {
                        *e = serde_json::json!({
                            "commit_id": e["commit_id"].clone(),
                            "sequence": e["sequence"].clone(),
                            "pr": e["pr"].clone(),
                            "blobs": [Base64UrlUnpadded::encode_string(b"{}")],
                        });
                    }
                }
            }
            body
        }),
    )
    .await;

    let (witness_state, witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    for attempt in 0..3 {
        let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
        assert!(
            matches!(
                outcome,
                cyphr_server::sync::SyncOutcome::Failed {
                    reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
                }
            ),
            "attempt {attempt}: a label-preserving decoy top entry must be caught by the \
             post-apply reconciliation on EVERY poll, got {outcome:?}"
        );
    }

    let (status, json) = get_json(witness_app, &format!("/tip?pr={principal}")).await;
    let payload = common::envelope_payload(&json);
    assert_eq!(
        status,
        StatusCode::OK,
        "the genuine sequence-0 entry (never withheld) must still have applied: {json:?}"
    );
    assert_eq!(
        payload["commit_count"].as_u64(),
        Some(1),
        "the witness must never advance past the withheld commit, and must never report success \
         while short of it: {json:?}"
    );
}

/// N2 rework, fix 2 (part b): wholesale-emptying the `entries` array of a
/// genuine, genuinely-signed response no longer reads as `UpToDate`. The
/// signed report the witness just verified proves the authority is two
/// commits ahead; the post-apply comparison against the witness's own
/// (empty) resulting state must catch that the two disagree.
#[tokio::test]
async fn empty_entries_with_advanced_report_rejected() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x7b);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            body["payload"]["entries"] = serde_json::json!([]);
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "wholesale entry deletion against a report proving the authority is ahead must be \
         rejected, never read as UpToDate, got {outcome:?}"
    );
}

/// N2 rework, fix 2 (part c) -- the variant NO response-integrity mechanism
/// can ever catch: the on-path party never touches the response at all, only
/// the OUTBOUND request's `from`. The authority answers completely
/// honestly -- an empty entry set (nothing new past the huge `from`) plus its
/// genuine signature over its genuine current tip. Only comparing that
/// signed tip against the witness's own local state (never advanced) can
/// close this.
#[tokio::test]
async fn request_side_from_rewrite_withholding_rejected() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x7c);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_query_rewriting_proxy(
        authority.url.clone(),
        Arc::new(|q: Option<String>| {
            let q = q.unwrap_or_default();
            let pr = q
                .split('&')
                .find(|kv| kv.starts_with("pr="))
                .unwrap_or("")
                .to_string();
            Some(format!("{pr}&from=999999"))
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EntryCommitmentMismatch
            }
        ),
        "a request-side `from` rewrite must not withhold every entry behind a fully genuine \
         response, got {outcome:?}"
    );
}

/// N2 rework, fix 4 (architect): `Synced` carries a `rejected` count
/// alongside `applied`, so a caller can no longer mistake a sync where some
/// entries in the SAME response were individually rejected for a clean one.
///
/// The authority's genuine two-commit patch is followed by one extra
/// entry the witness cannot apply (its `blobs` array is absent). The two
/// genuine entries fully catch the witness up to what the signed report
/// attests (so the post-apply reconciliation passes and this is a real
/// `Synced`, not a `Failed`), while the trailing garbage entry is
/// individually rejected in the same pass.
#[tokio::test]
async fn synced_outcome_reports_rejected_count_alongside_applied() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x7f);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            if let Some(entries) = body["payload"]["entries"].as_array_mut() {
                entries.push(serde_json::json!({
                    "commit_id": "SHA-256:GARBAGE_TRAILING_ENTRY_NO_BLOBS_ARRAY",
                    "sequence": 2,
                    "pr": "",
                }));
            }
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    match outcome {
        cyphr_server::sync::SyncOutcome::Synced { applied, rejected } => {
            assert_eq!(applied, 2, "both genuine entries must have applied");
            assert_eq!(
                rejected, 1,
                "the trailing garbage entry must be counted as rejected, not silently absorbed \
                 into a clean-looking Synced"
            );
        },
        other => panic!("expected Synced {{ applied: 2, rejected: 1 }}, got {other:?}"),
    }
}

/// Spawn an on-path proxy that forwards the FIRST `/patch` request to
/// `upstream` untouched, caches that genuine response, and replays the SAME
/// cached response for every later request regardless of the query --
/// models an on-path party that holds one genuine response and rebroadcasts
/// it after the witness has moved past it, rather than forwarding a fresh
/// one.
async fn spawn_replay_proxy(upstream: String) -> (String, tokio::task::JoinHandle<()>) {
    let cache: Arc<tokio::sync::Mutex<Option<serde_json::Value>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let app = axum::Router::new().route(
        "/patch",
        axum::routing::get(move |raw: axum::extract::RawQuery| {
            let upstream = upstream.clone();
            let cache = cache.clone();
            async move {
                let mut cached = cache.lock().await;
                if let Some(body) = cached.clone() {
                    return axum::Json(body);
                }
                let url = match raw.0 {
                    Some(q) => format!("{upstream}/patch?{q}"),
                    None => format!("{upstream}/patch"),
                };
                let body: serde_json::Value = reqwest::Client::new()
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await
                    .expect("proxy upstream request")
                    .json()
                    .await
                    .expect("proxy upstream json decode");
                *cached = Some(body.clone());
                axum::Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy listener");
    let addr = listener.local_addr().expect("proxy local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// Diagnostic fix: a non-empty response every one of whose entries the
/// `seq < from_seq` guard skips -- because the witness already holds them,
/// exactly what a replayed-but-stale genuine response looks like once the
/// witness has since caught up further -- must not be reported as
/// `Failed { RejectedEntry }`. Nothing in such a response is rejected
/// (`rejected` stays 0); reporting a rejection would tell the operator every
/// entry failed verification when in fact none was even attempted.
///
/// The proxy forwards the witness's first request to a real two-commit
/// authority untouched and caches that genuine catch-up response (entries
/// for sequence 0 and 1, a signed report attesting the final tip), then
/// replays that identical cached response on every later request regardless
/// of the `from` it is asked for. The first sync legitimately applies both
/// entries; on the second sync both entries are now below the witness's
/// (advanced) `from_seq` and are skipped, not rejected, while the post-apply
/// check trivially agrees with local state because the replayed report
/// attests exactly the tip the witness already reached.
#[tokio::test]
async fn stale_replay_with_no_new_entries_reports_up_to_date_not_rejected() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x8a);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_replay_proxy(authority.url.clone()).await;
    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;

    let first = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            first,
            cyphr_server::sync::SyncOutcome::Synced {
                applied: 2,
                rejected: 0
            }
        ),
        "the first sync must genuinely catch the witness up to both commits: {first:?}"
    );

    let second = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    match second {
        cyphr_server::sync::SyncOutcome::UpToDate => {},
        cyphr_server::sync::SyncOutcome::Failed {
            reason: cyphr_server::sync::SyncFailure::RejectedEntry,
        } => panic!(
            "a stale-but-genuine response whose entries are all already applied must not be \
             reported as RejectedEntry -- nothing in it was rejected, both entries were merely \
             already held"
        ),
        other => panic!("expected UpToDate, got {other:?}"),
    }
}

/// GUARD (regression protection, already-correct behavior): a CONFIGURED
/// witness fails closed when the statement is stripped entirely -- the
/// `/patch` unsigned-on-signing-failure degradation (a liveness affordance
/// for an UNCONFIGURED witness) must never be usable to downgrade a
/// configured one's channel.
#[tokio::test]
async fn stripped_statement_fails_closed_when_configured() {
    let now = 1_700_000_000;
    let principal = principal_digest(0x7e);
    let authority = authority_with_two_commits(&principal, now).await;
    let authority_identity = authority.identity();

    let (proxy_url, _proxy) = spawn_patch_proxy(
        authority.url.clone(),
        Arc::new(|mut body: serde_json::Value| {
            body["statement"] = serde_json::json!({ "kind": "unsigned" });
            body
        }),
    )
    .await;

    let (witness_state, _witness_app) = witness_for(&proxy_url, Some(authority_identity)).await;
    let outcome = cyphr_server::sync::sync_from_authority(&witness_state, &principal).await;
    assert!(
        matches!(
            outcome,
            cyphr_server::sync::SyncOutcome::Failed {
                reason: cyphr_server::sync::SyncFailure::EnvelopeUnsignedOrMisSigned
            }
        ),
        "a configured witness must fail closed on a stripped statement, applying nothing, got \
         {outcome:?}"
    );
}
