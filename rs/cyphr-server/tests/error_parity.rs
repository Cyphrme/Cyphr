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

/// The second commit's `key/create`, edited by `defect`, pushed to a server
/// holding the genesis and imported from stored commits. Returns the replay
/// entry point's parse of the edited coz, the push status and reply, and
/// the import result.
async fn refusals(
    defect: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> (
    Result<StoredCoz, WireError>,
    StatusCode,
    serde_json::Value,
    Result<cyphr::Principal, LoadError>,
) {
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let (status, _) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, 1_700_000_100).await,
    )
    .await;
    assert!(status.is_success(), "genesis push lands: {status}");

    let mut body: serde_json::Value = serde_json::from_str(
        &build_second_commit_push_body(&pool, &id, 1_700_000_100, 1_700_000_200).await,
    )
    .expect("push body");
    let first =
        Base64UrlUnpadded::decode_vec(body["blobs"][0].as_str().expect("blob")).expect("base64url");
    let mut coz: serde_json::Value = serde_json::from_slice(&first).expect("coz json");
    defect(coz["pay"].as_object_mut().expect("pay"));
    let defective = serde_json::to_vec(&coz).expect("json");
    body["blobs"][0] = Base64UrlUnpadded::encode_string(&defective).into();

    let replayed = StoredCoz::from_wire(&defective);
    let (status, reply) = post_json(app, "/push", body.to_string()).await;

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
    let imported = load_principal_from_commits(Genesis::Implicit(genesis), &[entry]).await;
    (replayed, status, reply, imported)
}

/// Claim: a coz whose pay has no `alg` is refused as the core's
/// `MalformedPayload` (SPEC 2.3.1: every coz has the field `alg`; a missing
/// required field is a malformed payload, not a mismatch with the key) by
/// the replay entry point itself, and with that same kind when the coz is
/// pushed to the server (a 422 protocol refusal) and when it is imported
/// from stored commits.
///
/// Turns red if: any path judges the missing `alg` by its own rule (the
/// engine's `MalformedBlob`, import's `UnsupportedAlgorithm`, a wire-level
/// `MissingAlg`) or as `AlgMismatch`, which is kept for a present `alg`
/// that differs from the signing key's.
/// End-to-end scenario: yes (the same coz through HTTP push, storage import
/// and core replay).
#[tokio::test]
async fn missing_alg_is_malformed_on_push_import_and_replay() {
    let (replayed, status, reply, imported) = refusals(|pay| {
        pay.remove("alg");
    })
    .await;

    assert!(
        matches!(
            replayed,
            Err(WireError::Protocol(cyphr::Error::MalformedPayload))
        ),
        "the replay entry point rules a missing alg MalformedPayload"
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{reply}");
    assert!(
        reply
            .to_string()
            .contains(&cyphr::Error::MalformedPayload.to_string()),
        "the push refusal names MalformedPayload: {reply}"
    );
    assert!(
        matches!(
            imported,
            Err(LoadError::Protocol(cyphr::Error::MalformedPayload))
        ),
        "import rules a missing alg MalformedPayload: {imported:?}"
    );
}

/// Claim: a coz whose pay names an `alg` other than its signing key's is
/// refused as `AlgMismatch` on push and on import (SPEC 2.3.1: `alg` is the
/// algorithm of the signing key), so the absent and the wrong `alg` stay
/// two kinds. The replay entry point accepts the coz: `ES384` is a known
/// algorithm, and only the signing key can show it is the wrong one.
///
/// Turns red if: the wrong `alg` is folded into `MalformedPayload` with
/// the absent one, or judged by another rule on either path.
/// End-to-end scenario: yes (HTTP push and storage import of one coz).
#[tokio::test]
async fn wrong_alg_is_alg_mismatch_on_push_and_import() {
    let (replayed, status, reply, imported) = refusals(|pay| {
        pay.insert("alg".into(), "ES384".into());
    })
    .await;

    assert!(replayed.is_ok(), "a known alg parses: {replayed:?}");
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{reply}");
    assert!(
        reply
            .to_string()
            .contains(&cyphr::Error::AlgMismatch.to_string()),
        "the push refusal names AlgMismatch: {reply}"
    );
    assert!(
        matches!(
            imported,
            Err(LoadError::Protocol(cyphr::Error::AlgMismatch))
        ),
        "import rules a wrong alg AlgMismatch: {imported:?}"
    );
}
