//! Explicit genesis carries a `key/create` for every genesis key (SPEC 5.1
//! step 1, 5.2, 5.3, 7.7 Example 1, zami be0663f): the genesis key adds
//! itself, then each further key, then `principal/create` and
//! `commit/create`. These scenarios run the producer (the core), the
//! server's push route, storage replay from blobs alone, and the server's
//! own principal end to end.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};

mod common;
use common::{get_json, keyless_server, post_json, write_signing_key};

const NOW: i64 = 1_700_000_000;

fn key_of(kp: &coz::KeyPair) -> cyphr::Key {
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    cyphr::Key::new(kp.alg.name().to_string(), tmb, kp.pub_bytes.clone()).expect("key")
}

fn signer_of(kp: &coz::KeyPair) -> cyphr::signer::SoftwareSigner {
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    cyphr::signer::SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb)
}

/// A `principal/create` signed by `kp` naming `id`, as a wire coz plus the
/// pieces `verify_and_apply` takes.
fn principal_create(kp: &coz::KeyPair, id: &str) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    let mut pay = serde_json::json!({
        "alg": kp.alg.name(), "id": id, "now": NOW, "tmb": tmb.to_b64(),
        "typ": "cyphr.me/cyphr/principal/create",
    });
    pay.as_object_mut().unwrap().sort_keys();
    let pay = serde_json::to_vec(&pay).unwrap();
    let (sig, cad) = coz::sign_json(&pay, kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes).unwrap();
    let czd = coz::czd_for_alg(&cad, &sig, kp.alg.name()).unwrap();
    (pay, sig, czd)
}

/// The genesis commit of `kps` (the first is the genesis key) as wire
/// blobs, and the PG it establishes.
fn genesis_bundle(kps: &[coz::KeyPair]) -> (String, Vec<Vec<u8>>) {
    let mut p = cyphr::Principal::explicit(kps.iter().map(key_of).collect()).expect("explicit");
    let pg = p.pr_tagged().expect("pr");
    let signer = signer_of(&kps[0]);
    let mut scope = p.begin_commit();
    let creates = scope
        .create_genesis_keys(&signer, NOW, "cyphr.me")
        .expect("genesis key/creates");
    let (pay, sig, czd) = principal_create(&kps[0], &pg);
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("principal/create after every key/create");
    let commit = scope
        .finalize_with_software(&signer, NOW, "cyphr.me")
        .expect("genesis commit");
    let cc = serde_json::to_vec(commit.commit_tx().0[0].raw()).unwrap();
    let mut blobs: Vec<Vec<u8>> = creates
        .iter()
        .map(|c| serde_json::to_vec(c).unwrap())
        .collect();
    blobs.push(
        serde_json::to_vec(&serde_json::json!({
            "pay": serde_json::from_slice::<serde_json::Value>(&pay).unwrap(),
            "sig": Base64UrlUnpadded::encode_string(&sig),
        }))
        .unwrap(),
    );
    blobs.push(cc);
    assert_eq!(
        p.pg().map(|pg| pg.0.tagged_first().unwrap().to_string()),
        Some(pg.clone())
    );
    (pg, blobs)
}

fn push_body(principal_id: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": principal_id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

fn typ_suffix(blob: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(blob).unwrap();
    let typ = v["pay"]["typ"].as_str().unwrap_or_default();
    typ.rsplit_once("cyphr/")
        .map(|(_, s)| s.to_owned())
        .unwrap_or_default()
}

/// Claim (SPEC 5.3, 7.7 Example 1): a two-key explicit genesis built by
/// `Principal::explicit` is key/create(genesis key), key/create(second
/// key), principal/create, commit/create; the server's push route accepts
/// it under its PG with both keys active, and a rebuild of the index from
/// blobs alone replays it to the same tip.
/// End-to-end: yes (core producer, HTTP push, storage replay).
/// Turns red on: a genesis without the key/creates, a server that cannot
/// read a multi-key genesis from its blobs (push refused), or a rebuild
/// that quarantines it.
#[tokio::test]
async fn multi_key_explicit_genesis_is_pushed_and_replayed_from_blobs() {
    let kps = [
        coz::Alg::ES256.generate_keypair(),
        coz::Alg::Ed25519.generate_keypair(),
    ];
    let (pg, blobs) = genesis_bundle(&kps);
    let typs: Vec<String> = blobs.iter().map(|b| typ_suffix(b)).collect();
    assert_eq!(
        typs,
        [
            "key/create",
            "key/create",
            "principal/create",
            "commit/create"
        ],
        "SPEC 5.3 genesis shape"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state.clone());
    let (status, body) = post_json(app.clone(), "/push", push_body(&pg, &blobs)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "multi-key genesis push: {body}"
    );

    let tip = state
        .engine
        .get_tip(&pg)
        .await
        .unwrap()
        .expect("stored under its PG");
    assert_eq!(tip.commit_count, 1);
    let replayed = state
        .engine
        .load_principal(
            &pg,
            cyphr_storage::Genesis::Explicit(kps.iter().map(key_of).collect()),
        )
        .await
        .expect("storage replays the genesis");
    assert_eq!(
        replayed.active_keys().count(),
        2,
        "both genesis keys active"
    );

    let report = state
        .engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(
        report.quarantined.is_empty(),
        "nothing quarantined: {:?}",
        report.quarantined
    );
    let after = state
        .engine
        .get_tip(&pg)
        .await
        .unwrap()
        .expect("tip after rebuild");
    assert_eq!(after.commit_count, tip.commit_count);
    let (status, _) = get_json(app, &format!("/tip?pr={pg}")).await;
    assert_eq!(status, StatusCode::OK, "served after rebuild");
}

/// Claim (SPEC 7.7 Example 1): genesis never creates a key implicitly, so
/// a `principal/create` while a genesis key lacks its `key/create` is
/// refused by the core, and a pushed genesis missing one is refused by the
/// server and stores nothing: the server reads the genesis keys from the
/// key/creates, so the uncreated key is no genesis key and the PG the
/// bundle claims is not the id its genesis derives.
/// End-to-end: yes (core producer, HTTP push).
/// Turns red on: a core or server that accepts a genesis whose key set is
/// not fully created (the pre-GEN0 behaviour).
#[tokio::test]
async fn genesis_omitting_a_key_create_is_refused() {
    let kps = [
        coz::Alg::ES256.generate_keypair(),
        coz::Alg::ES256.generate_keypair(),
    ];

    // Core: no key/create at all, the old two-coz genesis.
    let mut p = cyphr::Principal::explicit(kps.iter().map(key_of).collect()).unwrap();
    let pg = p.pr_tagged().unwrap();
    let (pay, sig, czd) = principal_create(&kps[0], &pg);
    let mut scope = p.begin_commit();
    let refused = scope.verify_and_apply(&pay, &sig, czd, None);
    assert!(
        matches!(refused, Err(cyphr::Error::UnknownKey)),
        "principal/create with uncreated genesis keys: {refused:?}"
    );

    // Server: the second key's key/create dropped from a valid bundle.
    let (pg, mut blobs) = genesis_bundle(&kps);
    blobs.remove(1);
    let (state, _dir) = keyless_server();
    let (status, body) =
        post_json(build_router(state.clone()), "/push", push_body(&pg, &blobs)).await;
    assert!(
        !status.is_success(),
        "a genesis missing a key/create is refused: {body}"
    );
    assert!(
        state.engine.get_tip(&pg).await.unwrap().is_none(),
        "nothing stored"
    );
}

/// Claim (SPEC 5.2, I1): the server's own principal is an explicit genesis
/// carrying key/create of its key, so a rebuild of the index from blobs
/// alone replays it (nothing quarantined, nothing skipped) and the server
/// signs on that chain afterwards (a key rotation commits).
/// End-to-end: yes (keyed boot, scratch rebuild, rotation).
/// Turns red on: a server genesis without the key/create (the replaying
/// rebuild cannot derive it and quarantines it), or a rebuild that leaves
/// the chain unloadable.
#[tokio::test]
async fn rebuild_replays_the_server_principal_and_the_server_signs_after() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = write_signing_key(dir.path());
    let config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key_path.clone()),
        ..Default::default()
    };
    let state = AppState::new(config).unwrap();
    let identity = state.identity.clone().unwrap();
    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap");

    let chain = state
        .engine
        .load_principal(
            sp.pg(),
            cyphr_storage::Genesis::Explicit(vec![sp.genesis_key().clone()]),
        )
        .await
        .expect("server chain");
    let genesis = chain.commits().next().expect("genesis commit");
    let typs: Vec<String> = genesis
        .iter_all_cozies()
        .map(|c| typ_suffix(&serde_json::to_vec(c.raw()).unwrap()))
        .collect();
    assert_eq!(typs, ["key/create", "principal/create", "commit/create"]);

    let report = state
        .engine
        .rebuild_index_from_scratch_with_report()
        .await
        .expect("rebuild");
    assert!(report.quarantined.is_empty(), "{:?}", report.quarantined);
    assert_eq!(
        report.indexed, 1,
        "the server's genesis commit is replayed and indexed"
    );

    sp.rotate(&state.engine, &coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("the server signs on its rebuilt chain");
    let tip = state.engine.get_tip(sp.pg()).await.unwrap().unwrap();
    assert_eq!(tip.commit_count, 2);
}
