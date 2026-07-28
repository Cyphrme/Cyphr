//! Acceptance test suite for Node N3: Push on Mutation (MSS).
//!
//! Evaluates criteria N3.1 – N3.6:
//! - `commit_reaches_registered_witness` (N3.1): Valid push on authority triggers fanout
//!   delivery to registered witness nodes.
//! - `unreachable_witness_does_not_fail_push` (N3.2): Unreachable witness node during push fanout
//!   does not cause authority push to fail.
//! - `unreachable_witness_does_not_delay_push` (N3.3): Fanout to an indefinitely blocking witness
//!   is non-blocking and does not delay authority push completion.
//! - `delivery_is_bounded_and_abandonment_visible` (N3.4): Fanout attempts are bounded and
//!   abandonment/failure is recorded in delivery status.
//! - `no_delivery_consistency_claim` (N3.5): Push response payload makes no structural delivery
//!   consistency claims (best-effort fanout).
//! - `delivered_state_is_still_verified` (N3.6): Witness independently verifies all pushed/delivered
//!   state deltas before applying them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::config::{ServerConfig, ServerMode};
use cyphr_server::{AppState, build_app_router};
use test_fixtures::Pool;

mod common;

use common::multi::Instance;
use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// Standard Unix timestamp reference for test cozies.
const NOW: i64 = 1_700_000_000;

/// Witness registration endpoint URI.
const REGISTRATION_URI: &str = "/witness/register";

/// Build a signed `witness/register/create` coz envelope registering `witness_url_or_id`.
fn build_witness_register_coz(
    pool: &Pool,
    signer_name: &str,
    principal_id: &str,
    witness_id: &str,
    verb: &str,
    now: i64,
) -> serde_json::Value {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let signer_tmb = signer.compute_tmb_b64().expect("signer tmb b64");

    let pay = serde_json::json!({
        "alg": signer.alg,
        "id": witness_id,
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

// ========================================================================
// Acceptance Criteria N3.1 – N3.6
// ========================================================================

/// N3.1: `commit_reaches_registered_witness`
///
/// Verifies that when a valid commit is submitted to an authority server via `POST /push`,
/// the authority node performs push fanout to registered witness nodes so that querying
/// the witness node (`GET /tip?pr=...`) returns the newly committed state.
#[tokio::test]
async fn commit_reaches_registered_witness() {
    // 1. Stand up authority server and bind TCP listener
    let (auth_state, identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("auth router");
    let mut auth_inst = Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_inst.bind_tcp().await.expect("bind TCP authority");

    // 2. Stand up witness server and bind TCP listener
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");
    let mut witness_inst = Instance {
        name: "witness".to_string(),
        state: witness_state.clone(),
        identity: None,
        dir: witness_dir,
        router: witness_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    let witness_addr = witness_inst.bind_tcp().await.expect("bind TCP witness");
    let witness_url = format!("http://{witness_addr}");

    // 3. Register witness_url for principal on authority server
    let pool = load_pool();
    let pid = "n3-fanout-principal";
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, &witness_url, "create", NOW);
    let (reg_status, reg_json) = post_json(auth_app.clone(), REGISTRATION_URI, reg_coz.to_string()).await;
    assert_eq!(reg_status, StatusCode::CREATED, "witness registration must succeed: {reg_json:?}");

    // 4. Push commit to authority server
    let push_body = build_genesis_push_body(&pool, pid, NOW + 10);
    let (push_status, push_json) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED, "push to authority must succeed: {push_json:?}");

    // Allow background fanout processing time if asynchronous
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Query witness server GET /tip?pr=<pid> to verify commit reached the witness
    let (witness_tip_status, witness_tip_json) =
        get_json(witness_app.clone(), &format!("/tip?pr={pid}")).await;

    assert_eq!(
        witness_tip_status,
        StatusCode::OK,
        "commit pushed to authority MUST reach registered witness and be queryable on GET /tip, got status {witness_tip_status}: {witness_tip_json:?}"
    );

    let payload = common::envelope_payload(&witness_tip_json);
    assert_eq!(
        payload["principal_id"], pid,
        "witness tip payload principal_id MUST match pushed principal"
    );
}

/// N3.2: `unreachable_witness_does_not_fail_push`
///
/// Verifies that when a registered witness is unreachable (e.g. offline endpoint),
/// submitting a commit to the authority node (`POST /push`) still succeeds with 201 Created.
#[tokio::test]
async fn unreachable_witness_does_not_fail_push() {
    let (auth_state, identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("auth router");
    let mut auth_inst = Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_inst.bind_tcp().await.expect("bind TCP authority");

    let pool = load_pool();
    let pid = "n3-unreachable-witness-principal";
    let unreachable_witness_url = "http://127.0.0.1:59999";

    // 1. Register unreachable witness URL for principal on authority server
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, unreachable_witness_url, "create", NOW);
    let (reg_status, reg_json) = post_json(auth_app.clone(), REGISTRATION_URI, reg_coz.to_string()).await;
    assert_eq!(reg_status, StatusCode::CREATED, "witness registration must succeed: {reg_json:?}");

    // 2. Push commit to authority server -- MUST succeed despite unreachable witness
    let push_body = build_genesis_push_body(&pool, pid, NOW + 10);
    let (push_status, push_json) = post_json(auth_app.clone(), "/push", push_body).await;

    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "POST /push MUST succeed with 201 Created even when a registered witness is unreachable, got {push_status}: {push_json:?}"
    );
}

/// N3.3: `unreachable_witness_does_not_delay_push`
///
/// Structurally proves that push fanout does not await fanout delivery by using an
/// indefinitely blocking TCP witness server and asserting `POST /push` completes rapidly.
#[tokio::test]
async fn unreachable_witness_does_not_delay_push() {
    // 1. Set up an indefinitely blocking TCP server
    let blocking_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind blocking listener");
    let blocking_addr = blocking_listener.local_addr().unwrap();
    let blocking_url = format!("http://{blocking_addr}");

    let _blocking_handle = tokio::spawn(async move {
        while let Ok((mut stream, _)) = blocking_listener.accept().await {
            // Keep connection open indefinitely without reading or responding
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // Loop reading to keep TCP socket active, but never reply
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    if n == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            });
        }
    });

    // 2. Stand up authority server
    let (auth_state, identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("auth router");
    let mut auth_inst = Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_inst.bind_tcp().await.expect("bind TCP authority");

    // 3. Register blocking witness URL on authority server
    let pool = load_pool();
    let pid = "n3-nonblocking-push-principal";
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, &blocking_url, "create", NOW);
    let (reg_status, reg_json) = post_json(auth_app.clone(), REGISTRATION_URI, reg_coz.to_string()).await;
    assert_eq!(reg_status, StatusCode::CREATED, "witness registration must succeed: {reg_json:?}");

    // 4. Time the POST /push execution
    let push_body = build_genesis_push_body(&pool, pid, NOW + 10);
    let start = Instant::now();
    let (push_status, push_json) = post_json(auth_app.clone(), "/push", push_body).await;
    let elapsed = start.elapsed();

    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "POST /push MUST succeed: {push_json:?}"
    );

    // 5. Assert push completes rapidly (well under 500ms) despite blocking witness TCP server
    assert!(
        elapsed < Duration::from_millis(500),
        "POST /push MUST NOT await witness fanout delivery (took {elapsed:?}, expected < 500ms)"
    );
}

/// N3.4: `delivery_is_bounded_and_abandonment_visible`
///
/// Verifies that fanout delivery attempts to an unreachable witness are bounded and
/// that delivery failure/abandonment is recorded and visible in registration/fanout status.
#[tokio::test]
async fn delivery_is_bounded_and_abandonment_visible() {
    let (auth_state, identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("auth router");
    let mut auth_inst = Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_inst.bind_tcp().await.expect("bind TCP authority");

    let pool = load_pool();
    let pid = "n3-bounded-delivery-principal";
    let unreachable_witness_url = "http://127.0.0.1:59998";

    // 1. Register unreachable witness
    let reg_coz = build_witness_register_coz(&pool, "golden", pid, unreachable_witness_url, "create", NOW);
    let (reg_status, _) = post_json(auth_app.clone(), REGISTRATION_URI, reg_coz.to_string()).await;
    assert_eq!(reg_status, StatusCode::CREATED);

    // 2. Push commit
    let push_body = build_genesis_push_body(&pool, pid, NOW + 10);
    let (push_status, _) = post_json(auth_app.clone(), "/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    // Wait for background fanout processing / retry attempts to finish
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Query witness registration listing / status to verify abandonment is recorded
    let (list_status, list_json) = get_json(auth_app.clone(), &format!("{REGISTRATION_URI}?pr={pid}")).await;
    assert_eq!(list_status, StatusCode::OK, "witness listing query must succeed: {list_json:?}");

    let payload = common::envelope_payload(&list_json);
    let deliveries = payload
        .get("deliveries")
        .or_else(|| payload.get("fanout_status"))
        .and_then(|v| v.as_array())
        .expect("payload MUST report fanout delivery status tracking for registered witnesses");

    assert!(
        !deliveries.is_empty(),
        "fanout delivery attempts MUST be recorded in registration status: {list_json:?}"
    );

    let unreachable_delivery = deliveries
        .iter()
        .find(|d| d["witness_id"].as_str() == Some(unreachable_witness_url) || d["url"].as_str() == Some(unreachable_witness_url))
        .expect("unreachable witness delivery entry MUST exist");

    let status_str = unreachable_delivery["status"]
        .as_str()
        .expect("delivery status string");

    assert!(
        status_str == "abandoned" || status_str == "failed" || status_str == "unreachable",
        "fanout delivery to unreachable witness MUST be recorded as abandoned/failed, got: {status_str}"
    );
}

/// N3.5: `no_delivery_consistency_claim`
///
/// Verifies that the authority push response (`POST /push`) makes no structural delivery
/// consistency claims (i.e. best-effort push fanout, no witness quorum requirements).
#[tokio::test]
async fn no_delivery_consistency_claim() {
    let (auth_state, identity, auth_dir) = attestor_server().await;
    let auth_app = build_app_router(auth_state.clone()).expect("auth router");
    let mut auth_inst = Instance {
        name: "authority".to_string(),
        state: auth_state.clone(),
        identity: Some(identity),
        dir: auth_dir,
        router: auth_app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    auth_inst.bind_tcp().await.expect("bind TCP authority");

    let pool = load_pool();
    let pid = "n3-no-consistency-claim-principal";

    // 1. Register 3 unreachable witnesses for principal
    for i in 0..3 {
        let url = format!("http://127.0.0.1:5998{i}");
        let reg_coz = build_witness_register_coz(&pool, "golden", pid, &url, "create", NOW + i);
        let (reg_status, _) = post_json(auth_app.clone(), REGISTRATION_URI, reg_coz.to_string()).await;
        assert_eq!(reg_status, StatusCode::CREATED);
    }

    // 2. Push commit to authority server
    let push_body = build_genesis_push_body(&pool, pid, NOW + 10);
    let (push_status, push_json) = post_json(auth_app.clone(), "/push", push_body).await;

    // 3. Push MUST still succeed with 201 Created
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "POST /push MUST succeed regardless of witness reachability: {push_json:?}"
    );

    // 4. Assert response payload contains NO witness delivery/quorum consistency claims
    let payload = &push_json["payload"];
    assert!(
        payload.get("witness_acks").is_none(),
        "push response MUST NOT claim witness acknowledgements: {push_json:?}"
    );
    assert!(
        payload.get("quorum_confirmed").is_none(),
        "push response MUST NOT claim witness quorum confirmation: {push_json:?}"
    );
}

/// N3.6: `delivered_state_is_still_verified`
///
/// Adversarial check: Verifies that if an invalid, unverified, or corrupted push payload
/// is delivered to a witness node (simulating adversarial delivery), the witness node
/// independently verifies signatures and state deltas and REJECTS the invalid payload.
#[tokio::test]
async fn delivered_state_is_still_verified() {
    // 1. Stand up witness node
    let witness_dir = tempfile::tempdir().expect("witness tempdir");
    let witness_config = ServerConfig {
        mode: ServerMode::Witness,
        data_dir: witness_dir.path().join("data"),
        ..Default::default()
    };
    let witness_state = Arc::new(AppState::new(witness_config).expect("witness AppState"));
    let witness_app = build_app_router(witness_state.clone()).expect("witness router");

    let pid = "n3-adversarial-delivery-principal";

    // 2. Attempt to deliver an unverified/invalid push payload directly to witness node
    let invalid_push_body = serde_json::json!({
        "principal_id": pid,
        "blobs": ["invalid_base64_blob_forged_payload"]
    })
    .to_string();

    let (push_status, push_json) = post_json(witness_app.clone(), "/push", invalid_push_body).await;

    // Witness node MUST refuse write/push in witness mode or reject unverified payload
    assert!(
        push_status.is_client_error() || push_status == StatusCode::FORBIDDEN || push_status == StatusCode::METHOD_NOT_ALLOWED,
        "witness node MUST reject invalid/unverified push delivery, got {push_status}: {push_json:?}"
    );

    // 3. Query witness GET /tip?pr=<pid> to ensure unverified state was NOT applied
    let (tip_status, tip_json) = get_json(witness_app.clone(), &format!("/tip?pr={pid}")).await;
    assert_ne!(
        tip_status,
        StatusCode::OK,
        "witness node MUST NOT serve unverified/corrupted state: {tip_json:?}"
    );
}
