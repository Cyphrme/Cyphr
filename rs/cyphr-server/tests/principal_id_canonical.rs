//! One genesis-derived identity has one stored spelling (SPEC 3.1).
//!
//! A principal id may be written bare (`X`, an implicit genesis's tmb) or
//! algorithm-labelled (`SHA-256:X`). If the server keyed storage on whichever
//! spelling arrived, the same identity could be stored as two independent
//! principals: a fork refused under one spelling would be accepted under the
//! other, and a key the owner revoked under one spelling would keep signing
//! under the other. Both scenarios are end to end over `/push` and `/tip`.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::build_router;

mod common;

use common::{
    build_genesis_push_body_with, envelope_payload, get_json, keyless_server, load_pool, post_json,
};

const NOW: i64 = 1_700_100_000;

/// The two spellings of the golden implicit genesis's id: bare `X` and
/// labelled `SHA-256:X` (golden is an ES256 key).
fn spellings(pool: &test_fixtures::Pool) -> (String, String) {
    let bare = common::golden_principal_id(pool);
    let labelled = format!("SHA-256:{bare}");
    (bare, labelled)
}

async fn tip(app: axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_json(app, &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    let payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    (status, payload)
}

/// Backs: a divergent first commit is refused (409) under BOTH spellings of
/// an already-stored identity, and both spellings read the one chain. Turns
/// red if the alias keys a second, independent principal: the divergent
/// genesis is then accepted (201) under the labelled spelling. End to end:
/// yes.
#[tokio::test]
async fn alias_spelling_cannot_fork_a_stored_principal() {
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    let (bare, labelled) = spellings(&pool);

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_a", &bare, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");

    // Control: a divergent genesis (key_b instead of key_a) under the same
    // spelling is a fork and is refused.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_b", &bare, NOW),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "control: {body:?}");

    // The same divergent genesis under the other spelling is the same fork.
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body_with(&pool, "golden", "key_b", &labelled, NOW),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the labelled spelling stored a second, divergent principal: {body:?}"
    );

    let (_, by_bare) = tip(app.clone(), &bare).await;
    let (_, by_label) = tip(app, &labelled).await;
    assert_eq!(by_bare, by_label, "both spellings must read one chain");
}

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
        // key_b is only ever a sidecar here, so it may be public-only.
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

fn sign(k: &Kp, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&bytes, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (bytes, sig, czd)
}

/// One commit: apply `parts` (signed by `author`), finalize with `finalizer`.
fn commit_one(
    p: &mut cyphr::Principal,
    finalizer: &Kp,
    parts: (Vec<u8>, Vec<u8>, coz::Czd),
    sidecar: Option<cyphr::Key>,
    now: i64,
) {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &finalizer.alg,
                &finalizer.prv,
                &finalizer.pubb,
                &finalizer.tmb,
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

/// Backs: a key the owner self-revoked can neither commit nor rewind the
/// principal through the OTHER spelling of its id: both the owner's own
/// pre-revocation commit replayed and a fresh commit by the revoked key are
/// refused, and the tip does not move. Turns red if the alias keys a second
/// principal: the replay of the public genesis is accepted there and the
/// revoked key then commits (201). End to end: yes.
#[tokio::test]
async fn revoked_key_cannot_commit_through_the_alias_spelling() {
    let pool = load_pool();
    let (g, a, b) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "key_b"));
    let (bare, labelled) = spellings(&pool);
    let create = |signer: &Kp, id: &Kp, now: i64| {
        sign(
            signer,
            serde_json::json!({"alg": signer.alg, "id": id.tmb.to_b64(), "now": now,
                               "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        )
    };

    // Owner: genesis(golden) + key/create key_a; then golden self-revokes,
    // the commit finalized by key_a.
    let mut owner = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut owner, &g, create(&g, &a, NOW), Some(key_of(&a)), NOW);
    commit_one(
        &mut owner,
        &a,
        sign(
            &g,
            serde_json::json!({"alg": g.alg, "now": NOW + 10, "rvk": NOW + 10,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"}),
        ),
        None,
        NOW + 10,
    );

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&owner, i, &g, &bare)).await;
        assert_eq!(status, StatusCode::CREATED, "owner commit {i}: {body:?}");
    }
    let (_, before) = tip(app.clone(), &bare).await;

    // The attacker holds the revoked golden key and builds its own
    // continuation of the public genesis, adding key_b.
    let mut attacker = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut attacker,
        &g,
        create(&g, &a, NOW),
        Some(key_of(&a)),
        NOW,
    );
    commit_one(
        &mut attacker,
        &g,
        create(&g, &b, NOW + 20),
        Some(key_of(&b)),
        NOW + 20,
    );

    // Control: under the spelling the owner used, the revoked key is refused.
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &g, &bare)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "control: {body:?}"
    );

    // Replaying the owner's public first commit under the other spelling
    // must not open a second, pre-revocation copy of the principal.
    let (status, body) = post_json(app.clone(), "/push", wire(&owner, 0, &g, &labelled)).await;
    assert!(
        status.is_client_error(),
        "the public genesis was accepted afresh under the alias: {status} {body:?}"
    );
    let (status, body) = post_json(app.clone(), "/push", wire(&attacker, 1, &g, &labelled)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the revoked key committed through the alias spelling: {body:?}"
    );

    let (_, mut after) = tip(app, &bare).await;
    let mut before = before;
    // `now` is the response's own clock, not principal state.
    before.as_object_mut().expect("tip object").remove("now");
    after.as_object_mut().expect("tip object").remove("now");
    assert_eq!(before, after, "the alias push moved the principal");
}
