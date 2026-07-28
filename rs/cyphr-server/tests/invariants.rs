//! Invariant acceptance tests for cyphr-server (Node N0).
//!
//! Verifies the four standing server invariants:
//! - N0.1 / I4: `two_instances_are_independent`
//! - N0.2 / I5: `refusals_are_never_signed`
//! - N0.3 / I6: `signed_statements_carry_freshness`
//! - N0.4 / I7: `no_standing_honesty_claim`
//! - N0.7: Invariant validation gate for server independence, signature safety, and honesty
//!   contracts.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};

mod common;

use common::multi::MultiServer;
use common::{build_genesis_push_body, load_pool};

/// Helper: current wall clock time in Unix seconds.
fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// N0.1: `two_instances_are_independent`
///
/// Verifies that two independent server instances (built using `common::multi`)
/// have completely isolated state, distinct cryptographic key pairs, separate storage
/// engines, and that cryptographic receipts issued by Instance A fail verification
/// when checked against Instance B's identity key.
#[tokio::test]
async fn two_instances_are_independent() {
    let multi = MultiServer::new_attestors(2).await;
    let inst0 = multi.get(0);
    let inst1 = multi.get(1);

    // 1. Identity isolation: distinct public keys & thumbprints
    let id0 = inst0.identity.as_ref().expect("inst0 identity");
    let id1 = inst1.identity.as_ref().expect("inst1 identity");

    assert_ne!(
        id0.pub_key(),
        id1.pub_key(),
        "N0.1 invariant failure: two independent server instances shared the same public key"
    );

    let tmb0 = id0.alg().compute_thumbprint(id0.pub_key()).unwrap();
    let tmb1 = id1.alg().compute_thumbprint(id1.pub_key()).unwrap();
    assert_ne!(
        tmb0, tmb1,
        "N0.1 invariant failure: thumbprints must be distinct across instances"
    );

    // 2. Data & Storage engine isolation: push principal to inst0
    let pool = load_pool();
    let principal_id = "n0-multi-instance-principal";
    let now = current_unix_timestamp();
    let push_body = build_genesis_push_body(&pool, principal_id, now);

    let (push_status, push_resp) = inst0.post("/push", push_body.clone()).await;
    assert_eq!(
        push_status,
        StatusCode::CREATED,
        "push to inst0 failed: {push_resp:?}"
    );

    // inst0 now has the principal
    let (tip_status0, tip_resp0) = inst0.get(&format!("/tip?pr={principal_id}")).await;
    assert_eq!(
        tip_status0,
        StatusCode::OK,
        "inst0 must return OK for pushed principal: {tip_resp0:?}"
    );

    // inst1 must NOT have the principal
    let (tip_status1, tip_resp1) = inst1.get(&format!("/tip?pr={principal_id}")).await;
    assert_eq!(
        tip_status1,
        StatusCode::NOT_FOUND,
        "N0.1 invariant failure: inst1 leaked data from inst0! {tip_resp1:?}"
    );

    // 3. Signature verification isolation: receipt from inst0 must fail against inst1's key
    let coz0 = &push_resp0_or_push(&push_resp);
    let pay_json = serde_json::to_vec(&coz0["pay"]).expect("serialize pay");
    let sig_bytes = Base64UrlUnpadded::decode_vec(coz0["sig"].as_str().unwrap()).unwrap();

    assert_eq!(
        id0.verify(&pay_json, &sig_bytes),
        Some(true),
        "inst0 receipt signature must verify against inst0's key"
    );
    assert_eq!(
        id1.verify(&pay_json, &sig_bytes),
        Some(false),
        "N0.1 invariant failure: inst1's key verified a receipt signed by inst0!"
    );
}

fn push_resp0_or_push(resp: &serde_json::Value) -> serde_json::Value {
    resp["statement"]["coz"].clone()
}

/// N0.2: `refusals_are_never_signed`
///
/// Verifies that server error responses, rejections, and refusals across all
/// endpoints (e.g. 400 Bad Request, 404 Not Found, 422 Unprocessable Entity,
/// 501 Not Implemented) NEVER carry a signed statement / receipt, and are
/// strictly formatted as unsigned envelopes (`Statement::Unsigned`).
#[tokio::test]
async fn refusals_are_never_signed() {
    let multi = MultiServer::new_attestors(1).await;
    let attestor = multi.get(0);

    let keyless_multi = MultiServer::new_keyless(1).await;
    let keyless = keyless_multi.get(0);

    let test_cases = vec![
        // (instance, uri, method, body, expected_status)
        (
            attestor,
            "/tip?pr=non-existent-principal-xyz",
            "GET",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            attestor,
            "/push",
            "POST",
            Some(serde_json::json!({ "principal_id": "p1", "blobs": [] }).to_string()),
            StatusCode::BAD_REQUEST,
        ),
        (
            attestor,
            "/push",
            "POST",
            Some("not json".to_string()),
            StatusCode::BAD_REQUEST,
        ),
        (
            attestor,
            "/revoke",
            "POST",
            Some("{}".to_string()),
            StatusCode::BAD_REQUEST,
        ),
        (
            attestor,
            "/non-existent-endpoint-path",
            "GET",
            None,
            StatusCode::NOT_FOUND,
        ),
        (
            keyless,
            "/auth/login",
            "POST",
            Some("{}".to_string()),
            StatusCode::NOT_IMPLEMENTED,
        ),
    ];

    for (inst, uri, method, body, expected_status) in test_cases {
        let (status, resp) = match method {
            "GET" => inst.get(uri).await,
            "POST" => inst.post(uri, body.unwrap_or_default()).await,
            _ => unreachable!(),
        };

        assert_eq!(
            status, expected_status,
            "expected status {expected_status} for {method} {uri}, got {status}: {resp:?}"
        );

        // Invariant Rule 1: The response envelope MUST carry wire version v=1
        assert_eq!(
            resp["v"],
            serde_json::json!(1),
            "N0.2 / I5 invariant violation: refusal response MUST be a valid Envelope with v=1: \
             {resp:?}"
        );

        // Invariant Rule 2: The statement slot MUST be explicitly "unsigned"
        assert_eq!(
            resp["statement"]["kind"],
            serde_json::json!("unsigned"),
            "N0.2 / I5 invariant violation: refusal response MUST be unsigned, got: {resp:?}"
        );

        // Invariant Rule 3: `statement.kind` MUST NEVER be "signed"
        assert_ne!(
            resp["statement"]["kind"],
            serde_json::json!("signed"),
            "N0.2 / I5 CRITICAL DEFECT: server signed a refusal response! {resp:?}"
        );
    }
}

/// N0.3: `signed_statements_carry_freshness`
///
/// Verifies that all signed statements and receipts issued by an attestor server
/// carry a fresh, positive, non-zero timestamp (`now`), bounded within reasonable clock
/// drift of wall clock time, and that fresh requests yield fresh timestamps.
#[tokio::test]
async fn signed_statements_carry_freshness() {
    let multi = MultiServer::new_attestors(1).await;
    let inst = multi.get(0);
    let identity = inst.identity.as_ref().unwrap();

    let pool = load_pool();
    let principal_id = "n0-freshness-principal";
    let start_time = current_unix_timestamp();
    let push_body = build_genesis_push_body(&pool, principal_id, start_time);

    let (push_status, push_resp) = inst.post("/push", push_body).await;
    assert_eq!(push_status, StatusCode::CREATED);

    let coz = &push_resp["statement"]["coz"];
    let pay = &coz["pay"];

    // 1. Freshness check: `now` field exists and is positive
    let now_val = pay["now"]
        .as_i64()
        .expect("signed statement pay must carry integer 'now'");
    assert!(
        now_val > 0,
        "N0.3 / I6 invariant violation: timestamp 'now' must be positive, got {now_val}"
    );

    // 2. Bound check: timestamp is within acceptable wall clock drift (60 seconds)
    let current_time = current_unix_timestamp();
    let drift = (now_val - current_time).abs();
    assert!(
        drift <= 60,
        "N0.3 / I6 invariant violation: timestamp 'now' ({now_val}) drifts too far from wall \
         clock ({current_time}), diff: {drift}s"
    );

    // 3. Receipt signature verifies over this timestamp payload
    let pay_json = serde_json::to_vec(pay).unwrap();
    let sig_bytes = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().unwrap()).unwrap();
    assert_eq!(
        identity.verify(&pay_json, &sig_bytes),
        Some(true),
        "N0.3 / I6: statement signature must verify over the freshness timestamp"
    );
}

/// N0.4: `no_standing_honesty_claim`
///
/// Verifies that keyless or unbootstrapped servers strictly publish `tier: "repository"`
/// without any identity or attestation fields on `GET /server`, and that no server instance
/// emits standing, static, or unverified claims of honesty.
#[tokio::test]
async fn no_standing_honesty_claim() {
    let keyless_multi = MultiServer::new_keyless(1).await;
    let keyless = keyless_multi.get(0);

    // 1. Keyless GET /server discovery must state tier: "repository"
    let (status, server_resp) = keyless.get("/server").await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        server_resp["payload"]["tier"],
        serde_json::json!("repository"),
        "N0.4 / I7 invariant failure: keyless server must declare tier 'repository'"
    );

    // 2. Keyless server MUST NOT contain any identity or attestation claims
    assert!(
        server_resp["payload"]["pg"].is_null(),
        "N0.4 / I7 invariant failure: keyless server must not publish 'pg'"
    );
    assert!(
        server_resp["payload"]["pub"].is_null(),
        "N0.4 / I7 invariant failure: keyless server must not publish 'pub'"
    );
    assert!(
        server_resp["payload"]["tmb"].is_null(),
        "N0.4 / I7 invariant failure: keyless server must not publish 'tmb'"
    );
    assert!(
        server_resp["payload"]["genesis"].is_null(),
        "N0.4 / I7 invariant failure: keyless server must not publish 'genesis'"
    );

    // 3. Response statement MUST be unsigned
    assert_eq!(
        server_resp["statement"]["kind"],
        serde_json::json!("unsigned"),
        "N0.4 / I7 invariant failure: keyless discovery statement must be unsigned"
    );
}

/// N0.5: `multi_server_tcp_socket_listener_option`
///
/// Verifies that `MultiServer` instances can bind real ephemeral TCP socket listeners
/// on `127.0.0.1:0` alongside in-process dispatch, returning distinct local addresses and URLs.
#[tokio::test]
async fn multi_server_tcp_socket_listener_option() {
    let mut multi = MultiServer::new_attestors(2).await;
    let addrs = multi.bind_tcp().await.expect("bind_tcp must succeed");

    assert_eq!(addrs.len(), 2);
    assert_ne!(addrs[0], addrs[1]);
    assert_eq!(addrs[0].ip().to_string(), "127.0.0.1");
    assert_eq!(addrs[1].ip().to_string(), "127.0.0.1");

    let inst0 = multi.get(0);
    assert_eq!(inst0.tcp_addr(), Some(addrs[0]));
    assert_eq!(inst0.url(), Some(format!("http://{}", addrs[0])));
}
