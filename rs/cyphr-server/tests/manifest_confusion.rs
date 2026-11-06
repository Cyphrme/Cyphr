//! Manifest confusion over `POST /push` (finding H1).
//!
//! Claim: bytes an untrusted client pushes can never be mistaken for the
//! engine's own commit manifest. `push` stores each blob raw, content
//! addressed, in the same blob store that holds the engine's
//! `CommitManifest` blobs. `rebuild_index_from_manifests` (run on every
//! `serve` start, `cyphr-server/src/lib.rs`) scans EVERY blob and treats
//! any that deserializes as `{kind, commit}` with the manifest `kind` as
//! authoritative. A coz envelope is `{pay, sig, key?}` and the signature
//! covers only `pay`, so an attacker can add top-level `kind` and `commit`
//! members to an otherwise valid, signed coz of their OWN principal
//! without disturbing the signature.
//!
//! Scenario (end to end): a victim principal pushes a genesis; an
//! attacker, a different principal, pushes a valid genesis whose closing
//! coz carries a forged manifest naming the VICTIM as `principal_id`; the
//! index is then rebuilt from the blob store (the server restart path).
//! The victim's tip must be exactly what it was.
//!
//! Defect that turns it red: any implementation that accepts a manifest
//! shaped blob from the wire as index input (today's behaviour). The
//! red test is `#[ignore = "RED(H1F)"]` and fails on its tip-equality
//! assertion, after the crafted push is accepted (201) and rebuilt.
//!
//! Lying implementations caught: a "fix" that makes rebuild skip every
//! manifest passes the red test vacuously, so the green companion
//! `rebuild_still_recovers_genuine_manifests` pins that a rebuild over
//! honest pushes still finds them (count > 0) and leaves tips intact.

use axum::http::StatusCode;
use cyphr_server::build_router;
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{IndexableCommit, IndexableCoz};

mod common;

use common::{
    build_genesis_push_body, build_genesis_push_body_with, envelope_payload, get_json,
    implicit_principal_id, keyless_server, load_pool, post_json,
};
use coz::base64ct::{Base64UrlUnpadded, Encoding};

const MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// A forged commit for `victim` that is not the victim's real next commit.
fn forged_commit(victim: &str) -> IndexableCommit {
    let hash = Blake3Hash::from_bytes([0xAB; 32]);
    IndexableCommit {
        pg: Vec::new(),
        principal_id: victim.to_string(),
        commit_ids: vec!["SHA-256:forged-commit".to_string()],
        sequence: 1,
        pre: None,
        prs: vec!["SHA-256:forged-pr".to_string()],
        srs: vec!["SHA-256:forged-sr".to_string()],
        ars: vec!["SHA-256:forged-ar".to_string()],
        crs: vec!["SHA-256:forged-cr".to_string()],
        blob_hashes: vec![hash],
        cozies: vec![IndexableCoz {
            blob_hash: hash,
            czd: "SHA-256:forged-czd".to_string(),
            typ: "cyphr.me/cyphr/key/create".to_string(),
            tmb: "forged".to_string(),
            alg: "Ed25519".to_string(),
            now: 1,
            payload: None,
        }],
        timestamp: 1,
        keys: Vec::new(),
    }
}

/// Re-encode the push body with `kind` and `commit` added to the closing
/// coz's top level (outside `pay`, so the signature still verifies).
fn with_forged_manifest(body: &str, victim: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(body).unwrap();
    let blobs = v["blobs"].as_array_mut().unwrap();
    let last = blobs.last_mut().unwrap();
    let mut coz: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(last.as_str().unwrap()).unwrap())
            .unwrap();
    let obj = coz.as_object_mut().unwrap();
    obj.insert("kind".into(), MANIFEST_KIND.into());
    obj.insert(
        "commit".into(),
        serde_json::to_value(forged_commit(victim)).unwrap(),
    );
    *last = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).unwrap()).into();
    v.to_string()
}

/// RED(H1F): a pushed coz carrying `kind`/`commit` rewrites the victim's
/// index entry on rebuild.
#[tokio::test]
#[ignore = "RED(H1F): rebuild_index_from_manifests trusts wire blobs shaped like a manifest"]
async fn pushed_coz_cannot_rewrite_victim_index_on_rebuild() {
    let pool = load_pool();
    let (state, _dir) = keyless_server();
    let app = build_router(state.clone());

    let victim = implicit_principal_id(&pool, "golden");
    let (s, b) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &victim, 1_700_000_000),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "victim genesis push: {b:?}");
    let before = state
        .engine
        .get_tip(&victim)
        .await
        .unwrap()
        .expect("victim has a tip");

    let attacker = implicit_principal_id(&pool, "alice");
    let honest = build_genesis_push_body_with(&pool, "alice", "carol", &attacker, 1_700_000_001);
    let crafted = with_forged_manifest(&honest, &before.principal_id);
    let (s, b) = post_json(app.clone(), "/push", crafted).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "setup: the crafted-but-validly-signed push is accepted today: {b:?}"
    );

    state.engine.rebuild_index_from_manifests().await.unwrap();

    let after = state.engine.get_tip(&victim).await.unwrap().unwrap();
    assert_eq!(
        after, before,
        "victim tip must be untouched by another principal's pushed coz"
    );
    let (s, tip) = get_json(app, &format!("/tip?pr={victim}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        envelope_payload(&tip)["commit_count"].as_u64(),
        Some(before.commit_count),
        "the victim's served commit_count must not grow"
    );
}

/// Green companion (end to end): a rebuild over honest pushes alone finds
/// the engine's own manifests and leaves every tip unchanged. Catches a
/// fix to the red test above that blinds the rebuild to all manifests
/// (count would be 0), and a rebuild that perturbs honest state.
#[tokio::test]
async fn rebuild_still_recovers_genuine_manifests() {
    let pool = load_pool();
    let (state, _dir) = keyless_server();
    let app = build_router(state.clone());

    let id = implicit_principal_id(&pool, "golden");
    let (s, b) = post_json(
        app,
        "/push",
        build_genesis_push_body(&pool, &id, 1_700_000_000),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");
    let before = state.engine.get_tip(&id).await.unwrap().unwrap();

    let found = state.engine.rebuild_index_from_manifests().await.unwrap();
    assert!(found >= 1, "rebuild must find the engine's own manifest");
    let after = state.engine.get_tip(&id).await.unwrap().unwrap();
    assert_eq!(after, before, "rebuild over honest state is a no-op");
}
