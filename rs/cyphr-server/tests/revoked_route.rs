//! `GET /revoked?tmbs=...` serves the naked revokes the peer holds, so a
//! verifier pulling from the peer can learn a key is dead (SPEC 6.4: a
//! revoke "does not mutate PR" and so cannot travel on the chain).

use axum::http::StatusCode;
use cyphr_server::build_app_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, post_json};

/// Claim: a naked revoke the peer accepted is served back, whole, to a
/// reader that asks for the key; what comes back verifies with the
/// client's own check (so the peer's word is not what makes it true); a
/// key the peer holds no revoke for is simply absent; an oversized ask is
/// refused rather than answered.
///
/// Turns red if: the route is absent; the served envelope is altered so the
/// client's verification fails; an unknown key is reported dead; or a
/// request naming 200 keys is answered.
/// End-to-end scenario: yes (POST /revoke, then the pull-side read and
/// verify).
#[tokio::test]
async fn revoked_serves_the_accepted_naked_revoke_verifiably() {
    let (state, _dir) = keyless_server();
    let app = build_app_router(state).expect("router");
    let golden: serde_json::Value = serde_json::from_str(include_str!("golden/naked_revoke_valid.json"))
        .expect("golden vector");
    let tmb = golden["pay"]["tmb"].as_str().expect("tmb").to_owned();

    let (status, body) = post_json(app.clone(), "/revoke", golden.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");

    let unknown = "A".repeat(43);
    let (status, body) = get_json(app.clone(), &format!("/revoked?tmbs={tmb},{unknown}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let served = envelope_payload(&body)["revoked"].as_array().expect("revoked list");
    assert_eq!(served.len(), 1, "only the key with a revoke is served");
    let revoke = cyphr_client::verify_naked_revoke(&served[0]).expect("verifies client-side");
    assert_eq!(revoke.tmb.to_b64(), tmb);
    assert_eq!(revoke.rvk, 1_700_000_000);

    let many = vec![unknown; 200].join(",");
    let (status, _) = get_json(app, &format!("/revoked?tmbs={many}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
