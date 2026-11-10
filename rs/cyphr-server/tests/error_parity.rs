//! Error parity: one defective coz is refused with one core kind on every
//! path that reads stored or pushed cozies.

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

/// Claim: a coz whose pay has no `alg` is refused as the core's
/// `AlgMismatch` (SPEC: a coz names its algorithm; `verify_coz` rules an
/// absent `alg` a mismatch) by the replay entry point itself, and with that
/// same kind when the coz is pushed to the server (a 422 protocol refusal)
/// and when it is imported from stored commits.
///
/// Turns red if: any path judges the missing `alg` by its own rule (the
/// engine's `MalformedBlob`, import's `UnsupportedAlgorithm`, a wire-level
/// `MissingAlg`) instead of the replay entry point's core kind.
/// End-to-end scenario: yes (the same coz through HTTP push, storage import
/// and core replay).
#[tokio::test]
async fn missing_alg_is_alg_mismatch_on_push_import_and_replay() {
    let pool = load_pool();
    let id = golden_principal_id(&pool);
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let (status, _) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, 1_700_000_100),
    )
    .await;
    assert!(status.is_success(), "genesis push lands: {status}");

    // The second commit's key/create with its `alg` removed.
    let mut body: serde_json::Value = serde_json::from_str(&build_second_commit_push_body(
        &pool,
        &id,
        1_700_000_100,
        1_700_000_200,
    ))
    .expect("push body");
    let first =
        Base64UrlUnpadded::decode_vec(body["blobs"][0].as_str().expect("blob")).expect("base64url");
    let mut coz: serde_json::Value = serde_json::from_slice(&first).expect("coz json");
    coz["pay"].as_object_mut().expect("pay").remove("alg");
    let defective = serde_json::to_vec(&coz).expect("json");
    body["blobs"][0] = Base64UrlUnpadded::encode_string(&defective).into();

    // Replay: the entry point's own verdict.
    assert!(
        matches!(
            StoredCoz::from_wire(&defective),
            Err(WireError::Protocol(cyphr::Error::AlgMismatch))
        ),
        "the replay entry point rules a missing alg AlgMismatch"
    );

    // Push: a protocol refusal carrying that kind.
    let (status, reply) = post_json(app, "/push", body.to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{reply}");
    assert!(
        reply
            .to_string()
            .contains(&cyphr::Error::AlgMismatch.to_string()),
        "the push refusal names AlgMismatch: {reply}"
    );

    // Import: the same kind from stored commits.
    let golden = pool.get("golden").expect("golden key");
    let genesis = cyphr::Key::new(
        golden.alg.clone(),
        golden.compute_tmb().expect("tmb"),
        Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub"),
    )
    .expect("genesis key");
    let entry = CommitEntry::new(
        vec![coz],
        vec![],
        "SHA-256:c".into(),
        None,
        None,
        "SHA-256:p".into(),
    );
    let imported = load_principal_from_commits(Genesis::Implicit(genesis), &[entry]);
    assert!(
        matches!(
            imported,
            Err(LoadError::Protocol(cyphr::Error::AlgMismatch))
        ),
        "import rules a missing alg AlgMismatch: {imported:?}"
    );
}
