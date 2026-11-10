//! The algorithm table at the server boundary: an algorithm the
//! implementation does not support is refused with the core's typed kind,
//! never defaulted to SHA-256 and never dropped.

mod common;

use axum::http::StatusCode;
use common::{
    attestor_server, build_genesis_push_body, build_second_commit_push_body, golden_principal_id,
    load_pool, post_json,
};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::{StoredCoz, WireError};
use cyphr_server::build_router;
use cyphr_storage::{CommitEntry, Genesis, LoadError, load_principal_from_commits};

/// A server holding the standard genesis, the second commit's push body,
/// and that commit's `key/create` blob (which introduces `key_b`) as JSON,
/// ready to edit. The directory holds the server's data.
async fn server_and_key_create() -> (
    axum::Router,
    serde_json::Value,
    serde_json::Value,
    tempfile::TempDir,
) {
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;
    let (state, _identity, dir) = attestor_server().await;
    let app = build_router(state);
    let (status, _) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, 1_700_000_100).await,
    )
    .await;
    assert!(status.is_success(), "genesis push lands: {status}");
    let body: serde_json::Value = serde_json::from_str(
        &build_second_commit_push_body(&pool, &id, 1_700_000_100, 1_700_000_200).await,
    )
    .expect("push body");
    let blob = Base64UrlUnpadded::decode_vec(body["txs"][0][0].as_str().expect("blob"))
        .expect("base64url");
    let coz = serde_json::from_slice(&blob).expect("coz json");
    (app, body, coz, dir)
}

/// `body` with its first blob replaced by `coz`.
fn with_blob(mut body: serde_json::Value, coz: &serde_json::Value) -> String {
    body["txs"][0][0] =
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(coz).expect("json")).into();
    body.to_string()
}

/// Claim: a `key/create` introducing a key whose algorithm the
/// implementation does not support (`RS256`) is refused on push with the
/// core's `UnknownAlg` (SPEC 17: the algorithm is unknown or unsupported),
/// so no key of an algorithm outside the table enters a principal.
///
/// Turns red if: the key's algorithm is defaulted or dropped and the push
/// lands, or the refusal is a generic malformed blob instead of the kind.
/// End-to-end scenario: yes (HTTP push of a signed commit).
#[tokio::test]
async fn key_of_unsupported_alg_is_refused_on_push() {
    let (app, mut body, coz, _dir) = server_and_key_create().await;
    body["keys"][0]["alg"] = "RS256".into();

    let (status, reply) = post_json(app, "/push", with_blob(body, &coz)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{reply}");
    assert!(
        reply
            .to_string()
            .contains(&cyphr::Error::UnknownAlg.to_string()),
        "the push refusal names UnknownAlg: {reply}"
    );
}

/// Claim: a coz whose pay names an algorithm the implementation does not
/// support is refused with the core's `UnknownAlg` by the replay entry
/// point, on push (a 422 protocol refusal) and on import: one typed kind on
/// every path, as for any other core rule.
///
/// Turns red if: a path reports it by its own rule (a 400 malformed blob on
/// push, an untyped `UnsupportedAlgorithm` on import) or computes the coz
/// digest under a default algorithm.
/// End-to-end scenario: yes (the same coz through HTTP push, storage import
/// and core replay).
#[tokio::test]
async fn pay_of_unsupported_alg_is_unknown_alg_on_push_import_and_replay() {
    let (app, body, mut coz, _dir) = server_and_key_create().await;
    coz["pay"]["alg"] = "RS256".into();
    let blob = serde_json::to_vec(&coz).expect("json");

    assert!(
        matches!(
            StoredCoz::from_wire(&blob),
            Err(WireError::Protocol(cyphr::Error::UnknownAlg))
        ),
        "the replay entry point rules an unsupported alg UnknownAlg"
    );

    let (status, reply) = post_json(app, "/push", with_blob(body, &coz)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{reply}");
    assert!(
        reply
            .to_string()
            .contains(&cyphr::Error::UnknownAlg.to_string()),
        "the push refusal names UnknownAlg: {reply}"
    );

    let pool = load_pool();
    let golden = pool.get("golden").expect("golden key");
    let genesis = cyphr::Key::new(
        golden.alg.clone(),
        golden.compute_tmb().expect("tmb"),
        Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub"),
    )
    .expect("genesis key");
    let entry = CommitEntry {
        txs: vec![vec![coz]],
        commit_id: "SHA-256:c".into(),
        pr: "SHA-256:p".into(),
        ..CommitEntry::default()
    };
    let imported = load_principal_from_commits(Genesis::Implicit(genesis), &[entry]).await;
    assert!(
        matches!(imported, Err(LoadError::Protocol(cyphr::Error::UnknownAlg))),
        "import rules an unsupported alg UnknownAlg: {imported:?}"
    );
}
