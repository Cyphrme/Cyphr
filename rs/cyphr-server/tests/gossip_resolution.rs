//! Gossip carries a fork resolution across a partition (SPEC 15.8).
//!
//! Two peers each hold one side of a principal fork as canonical and the
//! other as a retained branch, so both are in Error. The phone resolves on
//! P1 with a commit extending its own branch. One gossip round on P2
//! against P1 must take that resolution: P2 pulls the head it lacks, with
//! P1's chain from the common ancestor, and submits it through the same
//! admission path a push takes.

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_500_000;

/// `golden` signs `fields` plus its own `alg` and `tmb`: (pay, sig, czd).
fn golden_signs(fields: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut fields = fields;
    fields["alg"] = g.alg.clone().into();
    fields["tmb"] = g.compute_tmb_b64().expect("tmb").into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&fields).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    (pay, sig, czd)
}

/// One commit on `p` of `typ` naming `id` (and `key`, for a key/create),
/// signed and finalized by `golden` at `now`; its bundle.
async fn commit(
    p: &mut cyphr::Principal,
    typ: &str,
    id: &str,
    key: Option<cyphr::Key>,
    now: i64,
) -> WireBundle {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let (pay, sig, czd) = golden_signs(serde_json::json!({"id": id, "now": now, "typ": typ}));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, key)
        .expect("applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle")
}

async fn key_commit(p: &mut cyphr::Principal, name: &str, now: i64) -> WireBundle {
    let key = load_pool().get(name).expect("pool key").key().expect("key");
    let tmb = key.tmb().to_b64();
    commit(p, "cyphr.me/cyphr/key/create", &tmb, Some(key), now).await
}

/// A data action then the `ds/create` including it, on `p`: the action's
/// wire coz and the commit's bundle (SPEC 4.8.2).
async fn data_commit(p: &mut cyphr::Principal, msg: &str, now: i64) -> (Vec<u8>, WireBundle) {
    let (pay, sig, czd) =
        golden_signs(serde_json::json!({"msg": msg, "now": now, "typ": "cyphr.me/comment/create"}));
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("records");
    let action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    let dr = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    let bundle = commit(p, "cyphr.me/cyphr/ds/create", &dr, None, now + 1).await;
    (action, bundle)
}

async fn push(app: &axum::Router, id: &str, bundle: &WireBundle) -> StatusCode {
    post_json(app.clone(), "/push", common::push_body(id, bundle))
        .await
        .0
}

async fn tip_pr(app: &axum::Router, id: &str) -> String {
    let (status, body) =
        get_json(app.clone(), &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["pr"]
        .as_str()
        .expect("pr")
        .to_owned()
}

/// Serve `state` on an ephemeral local port; its base URL.
async fn serve(state: &Arc<AppState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

/// Backs the gossip follow-up: P1 holds the phone's data branch B
/// canonical and the laptop's A retained; P2 the reverse. The phone
/// resolves on P1 with C extending B. One round of P2's gossip against P1
/// moves P2's tip to C, B's branch canonical, with A kept as a branch,
/// and P2 leaves Error as P1 did.
///
/// Turns red if: P2 does not take the resolution in one round (its tip
/// stays A and it stays in Error), or takes it as anything but a verified
/// commit. End to end over two servers on real sockets and one gossip
/// round: yes.
#[tokio::test(flavor = "multi_thread")]
async fn one_round_takes_a_peers_resolution() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut shared, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");

    let mut laptop = shared.fork().await.expect("fork");
    let a = key_commit(&mut laptop, "key_a", T + 1).await;
    let mut phone = shared.fork().await.expect("fork");
    let (action, mut b) = data_commit(&mut phone, "phone", T + 2).await;
    let mut resolved = phone.fork().await.expect("fork");
    let c = key_commit(&mut resolved, "carol", T + 4).await;

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
    }
    // P1: B canonical (its action pushed alone first), A retained.
    let (s, body) = post_json(
        app1.clone(),
        "/push",
        common::push_blobs(&id, std::slice::from_ref(&action)),
    )
    .await;
    assert!(s.is_success(), "B's action: {s} {body:?}");
    assert_eq!(push(&app1, &id, &b).await, StatusCode::CREATED, "B on P1");
    // A rival is refused as the tip (409, or 422 when its `now` is older
    // than the tip's) and kept as a branch: the Error below shows it.
    assert!(push(&app1, &id, &a).await.is_client_error(), "A kept");
    // P2: A canonical, B retained with its action inline.
    assert_eq!(push(&app2, &id, &a).await, StatusCode::CREATED, "A on P2");
    b.actions = vec![action];
    assert!(push(&app2, &id, &b).await.is_client_error(), "B kept");
    for p in [&p1, &p2] {
        assert!(p.engine.is_errored(&id).await.expect("verdict"), "a fork");
    }

    assert_eq!(push(&app1, &id, &c).await, StatusCode::CREATED, "C on P1");
    let want = resolved.pr_tagged().expect("pr");
    assert_eq!(tip_pr(&app1, &id).await, want);
    assert!(!p1.engine.is_errored(&id).await.expect("verdict"));

    let url = serve(&p1).await;
    let connector =
        HttpConnector::with_client(p2.http_client.clone(), &url, true).expect("connector");
    cyphr_server::gossip::round(&p2, &[(url, connector)]).await;

    assert_eq!(tip_pr(&app2, &id).await, want, "P2 took C in one round");
    assert!(
        !p2.engine.is_errored(&id).await.expect("verdict"),
        "P2 left Error"
    );
    let branches = p2.engine.list_branches(&id).await.expect("branches");
    assert_eq!(branches.len(), 2, "A is kept: {branches:?}");
}

/// One commit on `p` in which pool key `signer` creates pool key `name`,
/// finalized by `signer` at `now`; its bundle.
async fn key_commit_by(p: &mut cyphr::Principal, signer: &str, name: &str, now: i64) -> WireBundle {
    let pool = load_pool();
    let s = pool.get(signer).expect("signer");
    let key = pool.get(name).expect("pool key").key().expect("key");
    let mut pay = serde_json::json!({
        "alg": s.alg, "id": key.tmb().to_b64(), "now": now,
        "tmb": s.compute_tmb_b64().expect("tmb"), "typ": "cyphr.me/cyphr/key/create"
    });
    if let Some(obj) = pay.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(s.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&s.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &s.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &s.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key))
        .expect("applies");
    scope
        .finalize_with_software(&s.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle")
}

/// `eve`'s self-signed naked revoke (SPEC 6.4) as of `rvk`: `{pay, sig, key}`.
fn eve_revoke(rvk: i64) -> serde_json::Value {
    let pool = load_pool();
    let e = pool.get("eve_ed25519").expect("eve");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": e.alg, "now": rvk, "rvk": rvk, "tmb": e.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(e.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&e.pub_key).expect("pub b64");
    let (sig, _) = coz::sign_json(&pay, &e.alg, &prv, &pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": e.alg, "pub": e.pub_key},
    })
}

/// Backs the global key-death gate (SPEC 6.4) on the gossip path: P1
/// holds X canonical and knows `eve` is naked-revoked; P2 serves `eve`'s
/// rival R at X's position and B over it. One round of P1's gossip must
/// not promote R's line: X stays P1's tip and P1 stays Active. Pinned
/// twice, once with the revoke posted to P1 (its engine holds it) and
/// once with it recorded only as a death P1 saw (as gossip records one),
/// so both the participation rule and the shared dead-key gate are held.
/// Turns red if either round moves P1's tip.
#[tokio::test(flavor = "multi_thread")]
async fn gossip_never_promotes_a_dead_keys_rival() {
    for posted in [true, false] {
        let pool = load_pool();
        let g = pool.get("golden").expect("golden");
        let eve = pool.get("eve_ed25519").expect("eve");
        let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
            .await
            .expect("implicit");
        let genesis = test_fixtures::bundle::genesis_bundle(
            &mut shared,
            g,
            &[eve.key().expect("eve")],
            T,
        )
        .await
        .expect("genesis");
        let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
        let mut owner = shared.fork().await.expect("fork");
        let x = key_commit_by(&mut owner, "golden", "key_a", T + 1).await;
        let mut thief = shared.fork().await.expect("fork");
        let r = key_commit_by(&mut thief, "eve_ed25519", "key_b", T + 1).await;
        let b = key_commit_by(&mut thief, "eve_ed25519", "carol", T + 2).await;

        let (p1, _d1) = keyless_server();
        let (p2, _d2) = keyless_server();
        let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
        for app in [&app1, &app2] {
            assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
        }
        assert_eq!(push(&app1, &id, &x).await, StatusCode::CREATED, "X on P1");
        assert_eq!(push(&app2, &id, &r).await, StatusCode::CREATED, "R on P2");
        assert_eq!(push(&app2, &id, &b).await, StatusCode::CREATED, "B on P2");
        let revoke = eve_revoke(T + 5);
        if posted {
            let (status, body) = post_json(app1.clone(), "/revoke", revoke.to_string()).await;
            assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
        } else {
            let tmb = eve.key().expect("eve").tmb().clone();
            p1.observations
                .record_seen(&tmb, revoke)
                .await
                .expect("death recorded");
        }
        let want = owner.pr_tagged().expect("pr");

        let url = serve(&p2).await;
        let connector =
            HttpConnector::with_client(p1.http_client.clone(), &url, true).expect("connector");
        cyphr_server::gossip::round(&p1, &[(url, connector)]).await;

        assert_eq!(
            tip_pr(&app1, &id).await,
            want,
            "posted={posted}: P1 promoted a dead key's rival"
        );
        assert!(
            !p1.engine.is_errored(&id).await.expect("verdict"),
            "posted={posted}: a dead key's rival is evidence only"
        );
    }
}
