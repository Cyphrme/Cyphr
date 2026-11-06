//! One key, two principals, each addressed by its own PG (SPEC be0663f 5.1
//! line 764: "A principal may reuse authentication components with an nonce
//! embedding for a unique PG"; 10.1, 10.2).
//!
//! Both principals start as an implicit genesis on the same pool key, so
//! their genesis-time identifier (the key's thumbprint) is identical. A
//! KT-level `nonce/create` in commit 0 makes their Principal Roots differ,
//! and `principal/create` in commit 1 fixes each PG at that root. The server
//! must then hold them as two principals keyed by PG, never one keyed by the
//! shared genesis key.

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

/// One finalized commit by `g` applying one signed coz.
fn commit_one(
    p: &mut cyphr::Principal,
    g: &Kp,
    parts: (Vec<u8>, Vec<u8>, coz::Czd),
    now: i64,
) -> cyphr::error::Result<()> {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, None)?;
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb),
            now,
            "cyphr.me",
        )
        .map(|_| ())
}

/// `g`'s principal: implicit genesis, commit 0 inserts `nonce` at the KT
/// root, commit 1 is `principal/create` at the resulting PR.
fn principal_with_nonce(g: &Kp, nonce: &[u8; 32]) -> cyphr::error::Result<cyphr::Principal> {
    let mut p = cyphr::Principal::implicit(key_of(g))?;
    commit_one(
        &mut p,
        g,
        sign(
            g,
            serde_json::json!({
                "alg": g.alg,
                "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(nonce)),
                "now": NOW, "tmb": g.tmb.to_b64(),
                "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
            }),
        ),
        NOW,
    )?;
    let pr = p.pr_tagged()?;
    commit_one(
        &mut p,
        g,
        sign(
            g,
            serde_json::json!({"alg": g.alg, "id": pr, "now": NOW + 1, "tmb": g.tmb.to_b64(),
                               "typ": "cyphr.me/cyphr/principal/create"}),
        ),
        NOW + 1,
    )?;
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

/// Push body for commit `i` of `p` under `id`; commit 0 also embeds the
/// genesis key on its closing cozy, as the wire contract requires.
fn wire(p: &cyphr::Principal, i: usize, genesis: &Kp, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let mut blobs: Vec<serde_json::Value> = entries[i].cozies.clone();
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
/// and from the key's thumbprint; each principal is pushable commit by commit
/// under its own PG, interleaved with the other's pushes, and each push
/// leaves the other's tip byte-identical; each PG reads back its own
/// principal's Principal Root and commit count. Turns red if the nonce is not accepted (the
/// principals cannot be built), if the nonce does not change the PG (the
/// second principal collides with the first), if the server keys storage by
/// the shared genesis key so the second push is refused or merges into the
/// first (409 or a moved tip), or if a push under one PG touches the
/// other. Red today: `nonce/create` is rejected as a malformed payload.
/// End to end: yes.
#[tokio::test]
#[ignore = "RED(NE1): one key cannot yet create two principals (nonces unimplemented)"]
async fn two_principals_one_key_each_addressed_by_its_own_pg() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let build = |nonce: &[u8; 32]| {
        principal_with_nonce(&g, nonce)
            .unwrap_or_else(|e| panic!("nonce/create must apply on an implicit genesis: {e:?}"))
    };
    let (a, b) = (build(&[0x11; 32]), build(&[0x22; 32]));
    let (pg_a, pg_b) = (pg_of(&a), pg_of(&b));
    assert_ne!(pg_a, pg_b, "different nonces must give different PGs");
    let genesis_id = common::golden_principal_id(&pool);
    for pg in [&pg_a, &pg_b] {
        assert_ne!(pg, &format!("SHA-256:{genesis_id}"), "a PG is the bare key");
    }

    let (state, _dir) = keyless_server();
    let app = build_router(state);

    push(&app, wire(&a, 0, &g, &pg_a), "A commit 0").await;
    let a_after_0 = tip(&app, &pg_a).await;
    assert_eq!(a_after_0.0, StatusCode::OK);

    push(&app, wire(&b, 0, &g, &pg_b), "B commit 0").await;
    assert_eq!(tip(&app, &pg_a).await, a_after_0, "pushing B moved A's tip");
    let b_after_0 = tip(&app, &pg_b).await;
    assert_eq!(
        b_after_0.0,
        StatusCode::OK,
        "B is not addressable by its PG"
    );
    assert_ne!(a_after_0.1, b_after_0.1, "the two tips are the same record");

    push(&app, wire(&a, 1, &g, &pg_a), "A commit 1").await;
    assert_eq!(
        tip(&app, &pg_b).await,
        b_after_0,
        "pushing A's second commit moved B's tip"
    );
    push(&app, wire(&b, 1, &g, &pg_b), "B commit 1").await;

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
