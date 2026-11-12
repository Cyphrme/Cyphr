//! A protocol refusal carries a machine-readable `kind` beside its message,
//! so a client tells one refusal from another without matching on text.
//!
//! The envelope's `error` stays the human message; `kind` is a stable
//! snake_case name, present for a refusal the caller can act on and absent
//! for a server fault.

use axum::http::StatusCode;
use cyphr_server::build_router;

mod common;

use common::{
    envelope_payload, genesis_pushed_principal, golden_principal_id, keyless_server, load_pool,
    post_json, sign_key_create_commit,
};

const NOW: i64 = 1_700_100_000;

/// Claim: a replayed genesis (422), a competing commit on a stale `pre`
/// (409) and a malformed body (400) each carry their own `kind`, so a
/// client separates a state mismatch from a reused coz without string
/// matching; the 409 and 422 refusals are two kinds, not one.
///
/// Turns red if: a refusal has no `kind`, two different refusals share one,
/// or the kind is only in the message text. End to end: yes (HTTP push over
/// a real store and replay).
#[tokio::test]
async fn protocol_refusals_name_their_kind() {
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;
    let genesis = common::build_genesis_push_body(&pool, &id, NOW).await;
    let adding = async |key: &str| {
        let principal = genesis_pushed_principal(&pool, "golden", "key_a", NOW).await;
        let blobs = sign_key_create_commit(principal, &pool, "golden", key, NOW + 1).await;
        common::push_body(&id, &blobs)
    };
    let (first, competing) = (adding("key_b").await, adding("carol").await);

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let kind_of =
        |reply: &serde_json::Value| envelope_payload(reply)["kind"].as_str().map(str::to_owned);

    let (status, reply) = post_json(app.clone(), "/push", genesis.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{reply:?}");
    assert_eq!(kind_of(&reply), None, "an accepted push names no refusal");
    let (status, reply) = post_json(app.clone(), "/push", first).await;
    assert_eq!(status, StatusCode::CREATED, "{reply:?}");

    let (status, replayed) = post_json(app.clone(), "/push", genesis).await;
    assert!(status.is_client_error(), "{replayed:?}");
    let (status, stale) = post_json(app.clone(), "/push", competing).await;
    assert_eq!(status, StatusCode::CONFLICT, "{stale:?}");
    let (status, malformed) = post_json(app, "/push", "garbage".into()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{malformed:?}");

    let kinds = [kind_of(&replayed), kind_of(&stale), kind_of(&malformed)];
    assert!(
        kinds.iter().all(Option::is_some),
        "every refusal names its kind: {kinds:?}"
    );
    assert_eq!(kinds[0].as_deref(), Some("coz_reuse"), "{replayed:?}");
    assert!(
        matches!(
            kinds[1].as_deref(),
            Some("state_mismatch" | "commit_mismatch")
        ),
        "a stale pre is a state or commit mismatch: {stale:?}"
    );
    assert_ne!(kinds[0], kinds[1], "a reused coz is not a stale pre");
}
