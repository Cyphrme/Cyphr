//! One key, two principals, each addressed by its own PG (SPEC be0663f 5.1
//! line 764: "A principal may reuse authentication components with an nonce
//! embedding for a unique PG"; 10.1, 10.2).
//!
//! Both principals are built on the same pool key, so without a nonce
//! their PG would be identical (the key's thumbprint). A KT-level
//! `nonce/create` in the genesis commit, before its `principal/create`
//! (SPEC 5.1), makes their Principal Roots differ, and `principal/create`
//! fixes each PG at that root. The server must then hold them as two
//! principals keyed by PG, never one keyed by the shared genesis key.

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
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("signing key has prv"))
            .expect("prv b64"),
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

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// `g`'s principal: the genesis commit (SPEC 5.1) is `g`'s self
/// `key/create`, a `nonce/create` at the KT root, then `principal/create`
/// at the resulting PR; commit 1 is `g` creating `next`.
fn principal_with_nonce(
    g: &Kp,
    next: &Kp,
    nonce: &[u8; 32],
) -> cyphr::error::Result<cyphr::Principal> {
    let mut p = cyphr::Principal::implicit(key_of(g))?;
    let mut scope = p.begin_commit();
    scope.create_genesis_keys(&signer_of(g), &[], NOW, "cyphr.me")?;
    let (pay, sig, czd) = sign(
        g,
        serde_json::json!({
            "alg": g.alg,
            "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(nonce)),
            "now": NOW, "tmb": g.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
        }),
    );
    scope.verify_and_apply(&pay, &sig, czd, None)?;
    scope.create_principal(&signer_of(g), NOW, "cyphr.me")?;
    scope.finalize_with_software(&signer_of(g), NOW, "cyphr.me")?;

    let (pay, sig, czd) = sign(
        g,
        serde_json::json!({"alg": g.alg, "id": next.tmb.to_b64(), "now": NOW + 1,
                           "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
    );
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, Some(key_of(next).with_first_seen(NOW + 1)))?;
    scope.finalize_with_software(&signer_of(g), NOW + 1, "cyphr.me")?;
    Ok(p)
}

fn pg_of(p: &cyphr::Principal) -> String {
    p.pg()
        .expect("principal/create establishes the PG")
        .as_multihash()
        .tagged_first()
        .expect("PG digest")
        .to_string()
}

/// Push body for commit `i` of `p` under `id`; every `key/create`
/// discloses the key it creates (SPEC 5.2 TX0).
fn wire(p: &cyphr::Principal, i: usize, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let mut blobs: Vec<serde_json::Value> = entries[i].cozies.clone();
    for c in &mut blobs {
        if !c["pay"]["typ"]
            .as_str()
            .is_some_and(|t| t.ends_with("cyphr/key/create"))
        {
            continue;
        }
        let key = entries[i]
            .keys
            .iter()
            .find(|k| c["pay"]["id"].as_str() == Some(k.tmb.as_str()))
            .expect("the commit carries every key it creates");
        c["key"] = serde_json::json!({"alg": key.alg, "pub": key.pub_key, "tmb": key.tmb});
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

/// The tip payload minus the response's own clock.
async fn tip(app: &axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) =
        get_json(app.clone(), &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    let mut payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    if let Some(o) = payload.as_object_mut() {
        o.remove("now");
    }
    (status, payload)
}

async fn push(app: &axum::Router, body: String, what: &str) {
    let (status, resp) = post_json(app.clone(), "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "{what}: {resp:?}");
}

/// Backs SPEC 5.1 (a nonce embedding yields a unique PG for reused
/// authentication components) end to end: one key creates two principals
/// that differ only in their KT nonce; the two PGs differ from each other
/// and from the key's thumbprint; each principal is pushed and stored under
/// its own PG (the nonce in its genesis commit is part of the PG),
/// interleaved with the other's pushes, and each push
/// leaves the other's tip byte-identical; each PG reads back its own
/// principal's Principal Root and commit count. Turns red if the nonce is not accepted (the
/// principals cannot be built), if the nonce does not change the PG (the
/// second principal collides with the first), if the server keys storage by
/// the shared genesis key so the second push is refused or merges into the
/// first (409 or a moved tip), or if a push under one PG touches the
/// other. End to end: yes.
#[tokio::test]
async fn two_principals_one_key_each_addressed_by_its_own_pg() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let next = kp(&pool, "key_a");
    let build = |nonce: &[u8; 32]| {
        principal_with_nonce(&g, &next, nonce)
            .unwrap_or_else(|e| panic!("nonce/create must apply in a genesis commit: {e:?}"))
    };
    let (a, b) = (build(&[0x11; 32]), build(&[0x22; 32]));
    let (pg_a, pg_b) = (pg_of(&a), pg_of(&b));
    assert_ne!(pg_a, pg_b, "different nonces must give different PGs");
    let (id_a, id_b) = (pg_a.clone(), pg_b.clone());
    // The PG of `golden`'s genesis without a nonce: its bare thumbprint.
    let genesis_id = common::implicit_principal_id(&pool, "golden");
    for pg in [&pg_a, &pg_b] {
        assert_ne!(pg, &format!("SHA-256:{genesis_id}"), "a PG is the bare key");
    }

    let (state, _dir) = keyless_server();
    let app = build_router(state);

    push(&app, wire(&a, 0, &id_a), "A commit 0").await;
    let a_after_0 = tip(&app, &pg_a).await;
    assert_eq!(a_after_0.0, StatusCode::OK);

    push(&app, wire(&b, 0, &id_b), "B commit 0").await;
    assert_eq!(tip(&app, &pg_a).await, a_after_0, "pushing B moved A's tip");
    let b_after_0 = tip(&app, &pg_b).await;
    assert_eq!(
        b_after_0.0,
        StatusCode::OK,
        "B is not addressable by its PG"
    );
    assert_ne!(a_after_0.1, b_after_0.1, "the two tips are the same record");

    push(&app, wire(&a, 1, &pg_a), "A commit 1").await;
    assert_eq!(
        tip(&app, &pg_b).await,
        b_after_0,
        "pushing A's second commit moved B's tip"
    );
    push(&app, wire(&b, 1, &pg_b), "B commit 1").await;

    for (p, pg) in [(&a, &pg_a), (&b, &pg_b)] {
        let (status, t) = tip(&app, pg).await;
        assert_eq!(status, StatusCode::OK, "{pg}: {t:?}");
        let bare = p
            .pr_tagged()
            .expect("pr")
            .split_once(':')
            .expect("tagged")
            .1
            .to_string();
        assert!(
            t["pr"].as_str().is_some_and(|s| s.contains(&bare)),
            "{pg} reads another principal's root: {t:?}"
        );
        assert_eq!(t["commit_count"], 2, "{pg}: {t:?}");
    }
}

/// Backs the identity rule from the equality side: the same key with the
/// SAME nonce is the same principal (same PG), so pushing it twice never
/// yields a second principal, and its second push cannot move or fork the
/// first one's tip. Every refusal is fine; a second principal, a moved
/// tip or a 5xx is not. Also pins N13's chain-position idempotency through
/// the PG key: the replay of position 0 is a no-op or a typed refusal,
/// never position 1. Turns red if the engine files the twin under another
/// key than the PG (a second chain, or a tip that advances), or if the
/// first push is refused (today: nonce kinds route as actions). A sibling
/// with a different nonce is the control that the two are told apart: it
/// is pushed in between and must leave the twin's tip alone. End to end:
/// yes.
#[tokio::test]
async fn identical_nonce_principal_pushed_twice_is_one_principal() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let next = kp(&pool, "key_a");
    let a = principal_with_nonce(&g, &next, &[0x33; 32]).expect("a");
    let sibling = principal_with_nonce(&g, &next, &[0x44; 32]).expect("sibling");
    let pg_a = pg_of(&a);
    assert_ne!(
        pg_a,
        pg_of(&sibling),
        "premise: the sibling is another principal"
    );
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    push(&app, wire(&a, 0, &pg_of(&a)), "A commit 0").await;
    let first = tip(&app, &pg_a).await;
    push(
        &app,
        wire(&sibling, 0, &pg_of(&sibling)),
        "sibling commit 0",
    )
    .await;
    let (status, resp) = post_json(app.clone(), "/push", wire(&a, 0, &pg_of(&a))).await;
    assert!(
        !status.is_server_error(),
        "replaying position 0 is a 5xx: {resp:?}"
    );
    let after = tip(&app, &pg_a).await;
    assert_eq!(after, first, "the replay or the sibling moved A's tip");
    assert_eq!(after.1["commit_count"], 1, "a second position appeared");
}
