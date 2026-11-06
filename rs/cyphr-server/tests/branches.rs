//! `GET /branches?pr=<id>` lists every retained branch of a principal (G1).
//!
//! A commit that forks a stored principal is still refused as its tip
//! (409), but is retained as a verified non-tip branch; the route reports
//! each branch's tip, its `pre`, its sequence and whether it is the
//! canonical chain. There is no `/branches` route at the base, so the
//! tests that need it compile today and are `#[ignore]`d RED(G1); they
//! fail on their stated assertions when run with `--ignored`.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_server::build_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const NOW: i64 = 1_700_100_000;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        // Keys that are only ever created (never sign) may be public-only.
        prv: pk
            .prv
            .as_ref()
            .map(|p| Base64UrlUnpadded::decode_vec(p).expect("prv b64"))
            .unwrap_or_default(),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// `signer` creates `new` at `now` and finalizes the commit. Distinct
/// `new`/`now` give distinct commits at one position.
fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &signer.prv,
                &signer.pubb,
                &signer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

/// `principal/create` by `signer`, whose `id` is the current PR: establishes
/// the PG.
fn establish_pg(p: &mut cyphr::Principal, signer: &Kp, now: i64) {
    let pr = p.pr_tagged().expect("pr");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": pr, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &signer.prv,
                &signer.pubb,
                &signer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

/// Push body for commit `i` of `p` under `id`; commit 0 also embeds the
/// genesis key on its closing cozy, as the wire contract requires.
fn wire(p: &cyphr::Principal, i: usize, genesis: &Kp, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let entry = &entries[i];
    let mut key_idx = 0;
    let mut blobs: Vec<serde_json::Value> = entry
        .cozies
        .iter()
        .map(|c| {
            let mut c = c.clone();
            let typ = c["pay"]["typ"].as_str().unwrap_or("").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) && key_idx < entry.keys.len() {
                let k = &entry.keys[key_idx];
                c["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                key_idx += 1;
            }
            c
        })
        .collect();
    if i == 0 {
        let last = blobs.len() - 1;
        blobs[last]["key"] = serde_json::json!({
            "alg": genesis.alg,
            "pub": Base64UrlUnpadded::encode_string(&genesis.pubb),
            "tmb": genesis.tmb.to_b64(),
        });
    }
    serde_json::json!({
        "principal_id": id,
        "blobs": blobs
            .iter()
            .map(|b| Base64UrlUnpadded::encode_string(&serde_json::to_vec(b).expect("blob")))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A")
}

async fn tip_payload(app: axum::Router, id: &str) -> serde_json::Value {
    let (status, body) = get_json(app, &format!("/tip?pr={}", enc(id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let mut payload = envelope_payload(&body).clone();
    // `now` is the response's own clock, not principal state.
    payload.as_object_mut().expect("tip object").remove("now");
    payload
}

/// One principal with a PG, three PG hash variants (ES256, ES384, Ed25519
/// keys), and a fork at its last position: two rival commits that both
/// verify at the same `pre`.
struct Forked {
    id: String,
    genesis: Kp,
    /// The shared prefix, pushed first.
    shared: cyphr::Principal,
    /// The commit that is pushed first at the fork position, and its rival.
    canonical: cyphr::Principal,
    rival: cyphr::Principal,
    /// Every spelling the PG answers to, plus the genesis id.
    spellings: Vec<String>,
}

fn forked() -> Forked {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let mut shared = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    let id = common::golden_principal_id(&pool);
    create_key(&mut shared, &g, &kp(&pool, "diana_es384"), NOW);
    create_key(&mut shared, &g, &kp(&pool, "eve_ed25519"), NOW + 1);
    establish_pg(&mut shared, &g, NOW + 2);

    let mut spellings = vec![id.clone()];
    let mh = shared.pg().expect("PG established").as_multihash();
    for alg in mh.algorithms() {
        let tagged = mh.tagged(alg).expect("variant").to_string();
        spellings.push(tagged.split_once(':').expect("tagged").1.to_string());
        spellings.push(tagged);
    }

    let mut canonical = shared.clone();
    create_key(&mut canonical, &g, &kp(&pool, "key_a"), NOW + 3);
    let mut rival = shared.clone();
    create_key(&mut rival, &g, &kp(&pool, "key_b"), NOW + 4);
    Forked {
        id,
        genesis: g,
        shared,
        canonical,
        rival,
        spellings,
    }
}

async fn branches(app: axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_json(app, &format!("/branches?pr={}", enc(id))).await;
    let payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    (status, payload)
}

/// Backs a-red-route: a server holding a fork lists both branches, under
/// the genesis id and every PG spelling alike; and the push that forked it
/// is still refused (409) without moving the tip. Turns red (as it is
/// today) because `/branches` does not exist, or if the fork is dropped
/// (one branch listed), both or neither is canonical, or the listing
/// differs by spelling. End to end over `/push`, `/tip` and `/branches`:
/// yes.
#[tokio::test]
#[ignore = "RED(G1): no /branches route; a refused fork is not retained"]
async fn fork_is_listed_under_every_pg_spelling() {
    let f = forked();
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let n = cyphr_storage::export_commits(&f.shared)
        .expect("export")
        .len();
    for i in 0..n {
        let (status, body) =
            post_json(app.clone(), "/push", wire(&f.shared, i, &f.genesis, &f.id)).await;
        assert_eq!(status, StatusCode::CREATED, "shared commit {i}: {body:?}");
    }
    let (status, body) = post_json(
        app.clone(),
        "/push",
        wire(&f.canonical, n, &f.genesis, &f.id),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "canonical commit: {body:?}");
    let tip_before = tip_payload(app.clone(), &f.id).await;

    let (status, body) =
        post_json(app.clone(), "/push", wire(&f.rival, n, &f.genesis, &f.id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the fork must still be refused: {body:?}"
    );
    assert_eq!(
        tip_payload(app.clone(), &f.id).await,
        tip_before,
        "the fork moved the tip"
    );

    let pre_expected = f.shared.pr_tagged().expect("pr at the fork's parent");
    let mut seen = Vec::new();
    for spelling in &f.spellings {
        let (status, payload) = branches(app.clone(), spelling).await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {payload:?}");
        let list = payload["branches"].as_array().expect("branches array");
        let at_fork: Vec<_> = list.iter().filter(|b| b["sequence"] == n as u64).collect();
        assert_eq!(
            at_fork.len(),
            2,
            "{spelling}: both rivals listed: {payload:?}"
        );
        assert!(
            at_fork
                .iter()
                .all(|b| b["pre"] == pre_expected && b["tip"].is_string()),
            "{spelling}: pre is the shared parent: {payload:?}"
        );
        assert_ne!(
            at_fork[0]["tip"], at_fork[1]["tip"],
            "{spelling}: distinct tips"
        );
        assert_eq!(
            at_fork.iter().filter(|b| b["canonical"] == true).count(),
            1,
            "{spelling}: exactly one canonical: {payload:?}"
        );
        seen.push(payload);
    }
    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "the listing differs by spelling: {seen:?}"
    );
}

/// Backs a-red-route: a principal that was never forked lists exactly its
/// canonical chain (one canonical branch per position, none other), and an
/// unknown principal is 404, not an empty listing. The unknown-id 404 is
/// asserted only after the known principal answers 200, so the absent
/// route (also 404) cannot satisfy it. Turns red (as it is today) because
/// `/branches` does not exist. End to end: yes.
#[tokio::test]
#[ignore = "RED(G1): no /branches route"]
async fn unforked_principal_lists_only_its_chain_and_unknown_is_404() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let id = common::golden_principal_id(&pool);
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    create_key(&mut p, &g, &kp(&pool, "key_a"), NOW);
    create_key(&mut p, &g, &kp(&pool, "key_b"), NOW + 1);

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &g, &id)).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }

    let (status, payload) = branches(app.clone(), &id).await;
    assert_eq!(status, StatusCode::OK, "{payload:?}");
    let list = payload["branches"].as_array().expect("branches array");
    assert!(
        !list.is_empty(),
        "a stored principal has a canonical chain: {payload:?}"
    );
    assert!(
        list.iter().all(|b| b["canonical"] == true),
        "no fork was pushed, so no non-canonical branch exists: {payload:?}"
    );

    let unknown = common::implicit_principal_id(&pool, "key_a");
    let (status, body) = branches(app, &unknown).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body:?}");
}
