//! A naked revoke of a key the owner already removed from the chain
//! still reaches a holder that never heard it (SPEC 6.4, 13.7).
//!
//! A holder restored from a backup taken before the revoke holds the
//! chain in which the key is gone; the key is no longer active, but a
//! revoke of it is still news, so the revoke probe must ask about every
//! key the chain ever held.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::build_router;
use cyphr_server::gossip::{Gossip, Peer};

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_600_000;

/// One commit on `p` in which pool key `signer` deletes pool key `name`.
async fn key_delete_by(p: &mut cyphr::Principal, signer: &str, name: &str, now: i64) -> WireBundle {
    let pool = load_pool();
    let s = pool.get(signer).expect("signer");
    let target = pool.get(name).expect("pool key").key().expect("key");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": s.alg, "id": target.tmb().to_b64(), "now": now,
        "tmb": s.compute_tmb_b64().expect("tmb"), "typ": "cyphr.me/cyphr/key/delete"
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(s.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&s.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &s.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &s.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("applies");
    scope
        .finalize_with_software(&s.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle")
}

/// `name`'s self-signed naked revoke as of `rvk`: `{pay, sig, keys}`.
fn revoke_of(name: &str, rvk: i64) -> serde_json::Value {
    let pool = load_pool();
    let k = pool.get(name).expect("pool key");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": k.alg, "now": rvk, "rvk": rvk, "tmb": k.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(k.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&k.pub_key).expect("pub b64");
    let (sig, _) = coz::sign_json(&pay, &k.alg, &prv, &pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "keys": [{"alg": k.alg, "pub": k.pub_key}],
    })
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

async fn revoked_at(app: &axum::Router, tmb: &str) -> usize {
    let (status, body) = get_json(app.clone(), &format!("/revoked?tmbs={tmb}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["revoked"]
        .as_array()
        .expect("revoked")
        .len()
}

/// Backs the revoke probe's key set: P1 and P2 hold a chain in which the
/// owner added `carol` and then deleted her, so she is no longer active.
/// `carol` is then naked-revoked at P2 only (the holder restored from
/// before the revoke is P1). One round on P1 must hear it, before and
/// after P1 has gone idle on the principal.
///
/// Turns red if: the probe asks only about the chain's active keys, so
/// the revoke of a key the chain removed is never heard.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_keys_naked_revoke_is_still_heard() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut owner = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut owner, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let added = common::key_commit_by(&mut owner, "golden", "carol", T + 1).await;
    let removed = key_delete_by(&mut owner, "golden", "carol", T + 2).await;

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        for bundle in [&genesis, &added, &removed] {
            let body = common::push_body(&id, bundle);
            assert_eq!(
                post_json(app.clone(), "/push", body).await.0,
                StatusCode::CREATED
            );
        }
    }

    let url = serve(app2.clone()).await;
    let peers = [Peer::new(
        url.clone(),
        HttpConnector::with_client(p1.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    gossip.round(&p1, &peers).await;
    gossip.round(&p1, &peers).await;

    let carol = pool
        .get("carol")
        .expect("carol")
        .compute_tmb_b64()
        .expect("tmb");
    let (status, body) = post_json(
        app2.clone(),
        "/revoke",
        revoke_of("carol", T + 5).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
    assert_eq!(revoked_at(&app1, &carol).await, 0, "P1 starts ignorant");

    gossip.round(&p1, &peers).await;

    assert_eq!(
        revoked_at(&app1, &carol).await,
        1,
        "P1 heard the revoke of a key the chain removed"
    );
}
