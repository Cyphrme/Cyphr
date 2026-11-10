//! SPEC conformance (SC1), server tier. The map is
//! `docs/architecture/spec-conformance.md`; the core-tier scenarios live in
//! `rs/cyphr/tests/spec_conformance.rs`. This file holds the one row whose
//! requirement is only observable through the HTTP write path.
//!
//! Frozen- and deleted-principal pushes, and out-of-range `rvk` pushes, have
//! no server-tier test here on purpose: the only way to author such a commit
//! is the core builder, which will refuse to build it once the requirement is
//! enforced, so the scenario would silently stop exercising the server. The
//! core tier owns them (a hand-signed wire vector would go stale on every
//! corpus regeneration and pass for the wrong reason).

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    envelope_payload, genesis_pushed_principal, get_json, golden_principal_id, keyless_server,
    load_pool, post_json, sign_key_create_commit,
};

const NOW: i64 = 1_700_100_000;

/// A push of a second commit for the standard principal (`golden` with
/// `key_a`, its genesis pushed at `NOW`) that adds `new_key`, signed by
/// `golden`.
async fn second_commit_push_adding(
    pool: &test_fixtures::Pool,
    principal_id: &str,
    new_key: &str,
) -> String {
    let principal = genesis_pushed_principal(pool, "golden", "key_a", NOW).await;
    let blobs = sign_key_create_commit(principal, pool, "golden", new_key, NOW + 1).await;
    common::push_body(principal_id, &blobs)
}

async fn commit_count(app: &axum::Router, id: &str) -> u64 {
    let (status, env) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    assert_eq!(status, StatusCode::OK, "tip of {id}: {env:?}");
    envelope_payload(&env)["commit_count"]
        .as_u64()
        .expect("commit_count")
}

/// Backs SPEC 2.3.2: "Commits are never removed from the chain and implicit
/// forks are prohibited by the protocol." Scenario over HTTP: one principal
/// has its genesis commit and then a second commit (adds `key_b`) accepted;
/// a competing second commit (adds `carol`, signed by the same genesis key,
/// so it is fully authorized) is pushed on the same `pre` and must be
/// refused with 409, leaving the chain at two commits. Control: on a fresh
/// server the genesis then the competing commit alone are accepted, so the
/// refusal is the stale `pre`, not a malformed body. Turns red if the
/// server appends a commit on a `pre` the chain has moved past, or reports
/// success for it. End to end: yes (HTTP, store, replay).
// @docket: sc-l237 :: scripts/docket-run sc-l237
#[tokio::test]
async fn s2_3_2_push_on_a_stale_pre_is_refused_and_the_chain_stays_put() {
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;
    let genesis = common::build_genesis_push_body(&pool, &id, NOW).await;
    let first = second_commit_push_adding(&pool, &id, "key_b").await;
    let competing = second_commit_push_adding(&pool, &id, "carol").await;

    let (control_state, _control_dir) = keyless_server();
    let control = build_router(control_state);
    let (status, body) = post_json(control.clone(), "/push", genesis.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "control genesis: {body:?}");
    let (status, body) = post_json(control, "/push", competing.clone()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "control: the competing commit is valid on its own: {body:?}"
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (status, body) = post_json(app.clone(), "/push", genesis).await;
    assert_eq!(status, StatusCode::CREATED, "genesis commit: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", first).await;
    assert_eq!(status, StatusCode::CREATED, "second commit: {body:?}");
    assert_eq!(commit_count(&app, &id).await, 2);

    let (status, body) = post_json(app.clone(), "/push", competing).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a commit on a stale pre was not refused as a conflict: {body:?}"
    );
    assert_eq!(
        commit_count(&app, &id).await,
        2,
        "the refused fork commit landed in the chain"
    );
}

/// Backs SPEC 6 (line 944): the private component is "never transmitted".
/// Scenario over HTTP against an attestor (the keyed, bootstrapped server,
/// which holds a private signing key and signs what it serves): a genesis
/// push (the pool's `golden` adds `key_a`), then every read surface (`/server`,
/// `/tip`, `/patch` with its decoded blobs) and the push response, none of
/// which may contain the pool keys' or the server's own private bytes (read
/// from its key file) in base64url. A keyless server holds no private key
/// of its own and could not fail this. Turns red if any response carries a
/// private component. End to end: yes.
// @docket: sc-l944 :: scripts/docket-run sc-l944
#[tokio::test]
async fn s6_no_http_response_carries_private_key_material() {
    let pool = load_pool();
    let (state, _identity, dir) = common::attestor_server().await;
    let key_file: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("signing-key.json")).expect("server key file"),
    )
    .expect("key file is JSON");
    let mut needles: Vec<String> = vec![
        key_file["prv_key"]
            .as_str()
            .expect("server prv_key")
            .to_string(),
    ];
    for n in ["golden", "key_a"] {
        needles.push(
            pool.get(n)
                .expect("key in pool")
                .prv
                .clone()
                .expect("pool key has prv"),
        );
    }

    let app = build_router(state);
    let id = common::golden_principal_id(&pool).await;
    let (status, push) = post_json(
        app.clone(),
        "/push",
        common::build_genesis_push_body(&pool, &id, NOW).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{push:?}");
    assert_eq!(
        push["statement"]["kind"], "signed",
        "premise: the attestor signs"
    );
    let (_, server) = get_json(app.clone(), "/server").await;
    let (_, tip) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    let (status, patch) = get_json(app, &format!("/patch?pr={id}")).await;
    assert_eq!(status, StatusCode::OK);

    let mut surfaces = vec![
        push.to_string(),
        server.to_string(),
        tip.to_string(),
        patch.to_string(),
    ];
    for entry in patch["payload"]["entries"].as_array().expect("entries") {
        for blob in &common::wire_cozies(entry) {
            let raw = Base64UrlUnpadded::decode_vec(blob.as_str().expect("blob string"))
                .expect("blob base64url");
            surfaces.push(String::from_utf8_lossy(&raw).into_owned());
        }
    }
    assert!(surfaces.len() > 4, "premise: the patch carried blobs");
    for s in &surfaces {
        for n in &needles {
            assert!(
                !s.contains(n.as_str()),
                "a response carries a private component"
            );
        }
    }
}

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Backs SPEC 6 (line 944) for the storage wire forms: for any principal
    /// built from random keys of both algorithms, none of the exported
    /// commit entries (cozies and the key sidecars that travel with them)
    /// contains a private component in base64url or hex. Property test: the
    /// invariant is over all key sets. Lives in this crate because
    /// `cyphr-storage` depends on `cyphr`, so the core tier cannot import
    /// `export_commits`. Turns red if an exported form gains a private
    /// field.
    // @docket: sc-l944 :: scripts/docket-run sc-l944
    #[test]
    fn s6_exported_commits_carry_no_private_key_material(
        algs in proptest::collection::vec(any::<bool>(), 2..5),
    ) {
        block_on(async move {
        let gen_key = |ed: bool| {
            let k = if ed { coz::Alg::Ed25519 } else { coz::Alg::ES256 }.generate_keypair();
            let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
            (k, tmb)
        };
        let key_of = |k: &coz::KeyPair, tmb: &coz::Thumbprint| cyphr::Key::new(k.alg.name().to_string(), tmb.clone(), k.pub_bytes.clone()).expect("key binds its tmb");
        let keys: Vec<_> = algs.iter().map(|&ed| gen_key(ed)).collect();
        let (g, gtmb) = &keys[0];
        let mut p = cyphr::Principal::implicit(key_of(g, gtmb)).await.expect("genesis");
        let g_signer =
            cyphr::signer::SoftwareSigner::new(g.alg.name(), &g.prv_bytes, &g.pub_bytes, gtmb);
        p.commit_genesis(&g_signer, &[], 1_700_000_000, "cyphr.me").await.expect("genesis commit");
        for (i, (k, tmb)) in keys.iter().enumerate().skip(1) {
            let now = 1_700_000_000 + i64::try_from(i).expect("small");
            let pay = serde_json::json!({
                "alg": g.alg.name(), "id": Base64UrlUnpadded::encode_string(tmb.as_bytes()),
                "now": now, "tmb": Base64UrlUnpadded::encode_string(gtmb.as_bytes()),
                "typ": "cyphr.me/cyphr/key/create",
            });
            let bytes = serde_json::to_vec(&pay).expect("pay");
            let (sig, cad) = coz::sign_json(&bytes, g.alg.name(), &g.prv_bytes, &g.pub_bytes)
                .expect("sign");
            let czd = coz::czd_for_alg(&cad, &sig, g.alg.name()).expect("czd");
            let mut scope = p.begin_commit();
            scope.verify_and_apply(&bytes, &sig, czd, Some(key_of(k, tmb))).expect("apply");
            let signer =
                cyphr::signer::SoftwareSigner::new(g.alg.name(), &g.prv_bytes, &g.pub_bytes, gtmb);
            scope
                .finalize_with_software(
                    &signer,
                    now,
                    "cyphr.me",
                )
                .await.expect("finalize");
        }
        let exported = serde_json::to_string(&cyphr_storage::export_commits(&p).expect("export"))
            .expect("serialize");
        prop_assert!(exported.contains(&Base64UrlUnpadded::encode_string(keys[1].1.as_bytes())),
            "premise: sidecars are in the export");
        for (k, _) in &keys {
            let b64 = Base64UrlUnpadded::encode_string(&k.prv_bytes);
            let hex: String = k.prv_bytes.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert!(!exported.contains(&b64) && !exported.contains(&hex),
                "an exported commit carries a private component");
        }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

/// Backs SPEC 17.2 Option A step 1: "Service generates a 256-bit
/// cryptographic challenge (nonce)". Scenario: ten `/auth/challenge`
/// requests; every challenge decodes to 32 bytes and no two are equal.
/// Turns red if a challenge is shorter, longer, or repeats. Uniqueness over
/// ten draws is a smoke bound for a CSPRNG (a repeat has probability
/// 2^-250), not a randomness proof. End to end: yes.
// @docket: sc-l3054 :: scripts/docket-run sc-l3054
#[tokio::test]
async fn s17_2_challenge_is_256_bits_and_unique() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let config = cyphr_server::config::ServerConfig {
        data_dir: dir.path().to_path_buf(),
        signing_key_path: Some(key_path),
        audience: Some("cyphr.me".to_string()),
        ..Default::default()
    };
    let app = build_router(std::sync::Arc::new(
        cyphr_server::AppState::new(config).expect("open AppState"),
    ));
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..10 {
        let (status, env) = post_json(app.clone(), "/auth/challenge", String::new()).await;
        assert_eq!(status, StatusCode::OK, "{env:?}");
        let c = envelope_payload(&env)["challenge"]
            .as_str()
            .expect("challenge string");
        let bytes = Base64UrlUnpadded::decode_vec(c).expect("challenge is b64ut");
        assert_eq!(bytes.len(), 32, "challenge is not 256 bits");
        assert!(seen.insert(bytes), "a challenge repeated");
    }
}

/// Drive one proptest case's async body: `proptest!` bodies are
/// synchronous, so each case runs on its own current-thread runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}
