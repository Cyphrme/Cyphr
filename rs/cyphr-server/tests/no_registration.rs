//! Claim: the server is not an authority that pushes to registered
//! witnesses. `/witness/register` does not exist, and an accepted push
//! makes no outbound request, even to a peer that a (formerly valid)
//! signed registration named.

use std::time::Duration;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_app_router;
use test_fixtures::Pool;
use tokio::net::TcpListener;

mod common;

use common::{attestor_server, build_genesis_push_body, golden_principal_id, load_pool, post_json};

const NOW: i64 = 1_700_000_000;

/// A correctly signed registration envelope, so the only reason the route
/// can refuse it is that the route is gone.
fn signed_register_create(pool: &Pool, principal_id: &str, witness_url: &str) -> String {
    let signer = pool.get("golden").expect("golden key in pool");
    let pay = serde_json::json!({
        "alg": signer.alg,
        "id": witness_url,
        "now": NOW,
        "principal_id": principal_id,
        "tmb": signer.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/witness/register/create",
    });
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("prv")).expect("prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("pub b64");
    let (sig, _cad) = coz::sign_json(
        &serde_json::to_vec(&pay).unwrap(),
        &signer.alg,
        &prv,
        &pub_key,
    )
    .expect("signing supported");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": { "alg": signer.alg, "pub": signer.pub_key },
    })
    .to_string()
}

// @docket: arch-verifier-chooses-peers :: scripts/docket-run arch-verifier-chooses-peers
#[tokio::test]
async fn register_route_is_gone_and_push_never_dials_out() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_app_router(state).expect("router");

    // A would-be witness: any inbound connection is the fanout this node cuts.
    let peer = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_url = format!("http://{}", peer.local_addr().expect("peer addr"));

    let pool = load_pool();
    let pid = golden_principal_id(&pool).await;

    let (reg_status, _) = post_json(
        app.clone(),
        "/witness/register",
        signed_register_create(&pool, &pid, &peer_url),
    )
    .await;

    let (push_status, push_json) = post_json(
        app,
        "/push",
        build_genesis_push_body(&pool, &pid, NOW + 10).await,
    )
    .await;
    assert_eq!(push_status, StatusCode::CREATED, "push: {push_json:?}");

    let dialed = tokio::time::timeout(Duration::from_millis(500), peer.accept()).await;
    assert!(
        dialed.is_err(),
        "push dialed a peer: no outbound fanout may exist"
    );
    assert_eq!(
        reg_status,
        StatusCode::NOT_FOUND,
        "POST /witness/register must not be routed"
    );
}
