//! The gossip idle gate, end to end over two servers on real sockets.
//!
//! A peer that lists only heads this server holds has nothing to teach it,
//! so the round must not replay the principal's stored chain and must move
//! nothing past the heads and the revoke probe. A naked revoke moves no
//! head, so the probe is never gated: a revoke made while the pair is idle
//! still reaches the other server within a round.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use cyphr_client::HttpConnector;
use cyphr_server::gossip::{Gossip, Peer};
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_500_000;

/// `/metrics` series `name` of `state`.
fn series(state: &AppState, name: &str) -> u64 {
    state
        .metrics
        .render(0)
        .lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no series {name}"))
}

/// Serve `app` on an ephemeral port, recording the path of each request.
async fn serve_counting(app: axum::Router) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let app = app.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let log = Arc::clone(&log);
            async move {
                log.lock().expect("log").push(req.uri().path().to_owned());
                next.run(req).await
            }
        },
    ));
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
    (format!("http://{addr}"), seen)
}

async fn revoked_at(app: &axum::Router, tmb: &str) -> usize {
    let (status, body) = get_json(app.clone(), &format!("/revoked?tmbs={tmb}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["revoked"]
        .as_array()
        .expect("revoked")
        .len()
}

/// Backs the idle gate: P1 and P2 hold one principal at the
/// same tip. P1's engine keeps the principal's verified state from the
/// pushes, so a round opens its record over that state and replays
/// nothing, and three more rounds must replay nothing and ask P2 for
/// nothing but `/branches` and `/revoked`; every round, idle ones included,
/// is counted. A naked revoke of an active key posted to P2 while idle
/// reaches P1 in one round with nothing replayed (the probe is not gated),
/// and a commit pushed to P2 opens the gate: P1 takes it, and replays that
/// one commit, not the chain it already verified.
///
/// Turns red if: an idle round replays the chain (commits replayed grows),
/// or taking the new head replays more than the new commit,
/// fetches a patch or evidence, skips the revoke probe, or does not count
/// as a round; or the gate stays shut after P2 advances.
/// End to end over two servers on real sockets: yes.
#[tokio::test(flavor = "multi_thread")]
async fn an_idle_pair_replays_nothing_and_still_hears_revokes() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let eve = pool.get("eve_ed25519").expect("eve");
    let mut owner = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis =
        test_fixtures::bundle::genesis_bundle(&mut owner, g, &[eve.key().expect("eve")], T)
            .await
            .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let first = common::key_commit_by(&mut owner, "golden", "key_a", T + 1).await;

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        for bundle in [&genesis, &first] {
            let body = common::push_body(&id, bundle);
            assert_eq!(
                post_json(app.clone(), "/push", body).await.0,
                StatusCode::CREATED
            );
        }
    }

    let (url, seen) = serve_counting(app2.clone()).await;
    let peers = [Peer::new(
        url.clone(),
        HttpConnector::with_client(p1.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    let replayed = |s: &AppState| series(s, "cyphr_gossip_commits_replayed_total");
    let rounds = |s: &AppState| series(s, "cyphr_gossip_rounds_total");

    gossip.round(&p1, &peers).await;
    assert_eq!(replayed(&p1), 0, "the engine's kept state is the record");
    seen.lock().expect("log").clear();

    for _ in 0..3 {
        gossip.round(&p1, &peers).await;
    }
    assert_eq!(replayed(&p1), 0, "idle rounds replayed a chain");
    assert_eq!(rounds(&p1), 4, "every round counts, idle ones too");
    let asked = seen.lock().expect("log").clone();
    assert!(
        asked.iter().all(|p| p == "/branches" || p == "/revoked"),
        "an idle round asked for more than heads and revokes: {asked:?}"
    );
    assert_eq!(
        asked.iter().filter(|p| *p == "/revoked").count(),
        3,
        "{asked:?}"
    );

    // A revoke moves no head: the probe still runs when idle.
    let eve_tmb = eve.compute_tmb_b64().expect("tmb");
    let (status, body) = post_json(
        app2.clone(),
        "/revoke",
        common::eve_revoke(T + 5).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
    assert_eq!(revoked_at(&app1, &eve_tmb).await, 0, "P1 starts ignorant");
    gossip.round(&p1, &peers).await;
    assert_eq!(replayed(&p1), 0, "the probe needs no replay");
    assert_eq!(revoked_at(&app1, &eve_tmb).await, 1, "P1 heard the revoke");

    // A new head opens the gate.
    let second = common::key_commit_by(&mut owner, "golden", "carol", T + 9).await;
    let body = common::push_body(&id, &second);
    assert_eq!(
        post_json(app2.clone(), "/push", body).await.0,
        StatusCode::CREATED
    );
    gossip.round(&p1, &peers).await;
    // The revoke is no part of what P1's engine keeps its state against:
    // the round verifies the new commit and nothing else.
    assert_eq!(replayed(&p1), 1, "a revoke costs no replay");
    let want = owner.pr_tagged().expect("pr");
    let (_, tip) = get_json(app1.clone(), &format!("/tip?pg={}", id.replace(':', "%3A"))).await;
    assert_eq!(
        envelope_payload(&tip)["pr"],
        want.as_str(),
        "P1 took the head"
    );

    let third = common::key_commit_by(&mut owner, "golden", "bob", T + 12).await;
    let body = common::push_body(&id, &third);
    assert_eq!(
        post_json(app2.clone(), "/push", body).await.0,
        StatusCode::CREATED
    );
    gossip.round(&p1, &peers).await;
    assert_eq!(
        replayed(&p1),
        2,
        "a peer with a new head costs the one new commit, not the chain"
    );
}

/// `name`'s self-signed naked revoke (SPEC 6.4) as of `rvk`: `{pay, sig, keys}`.
fn revoke_of(name: &str, rvk: i64) -> serde_json::Value {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
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

/// Backs the memo's tip check: the remembered revoke-probe keys are valid
/// only at the tip they were read at. P1 and
/// P2 both take a key-add commit by direct push, so both tips move and
/// every peer head is held (the gate would say idle), then the NEW key is
/// naked-revoked at P2. One round on P1 must learn the new key from the
/// engine's kept state, which the push moved to the new tip with no replay,
/// and P1 must hear the revoke.
///
/// Turns red if: the memo is used at a tip it was not read at, so the
/// probe asks only about the old keys and the revoke of the new one is
/// never heard, or learning the new key replays commits the kept state
/// already covers. End to end over two
/// servers on real sockets: yes.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_added_while_idle_is_probed_for_revokes() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut owner = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut owner, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        let body = common::push_body(&id, &genesis);
        assert_eq!(
            post_json(app.clone(), "/push", body).await.0,
            StatusCode::CREATED
        );
    }
    let (url, _seen) = serve_counting(app2.clone()).await;
    let peers = [Peer::new(
        url.clone(),
        HttpConnector::with_client(p1.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    gossip.round(&p1, &peers).await;
    let replayed = series(&p1, "cyphr_gossip_commits_replayed_total");

    let added = common::key_commit_by(&mut owner, "golden", "carol", T + 1).await;
    for app in [&app1, &app2] {
        let body = common::push_body(&id, &added);
        assert_eq!(
            post_json(app.clone(), "/push", body).await.0,
            StatusCode::CREATED
        );
    }
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
        series(&p1, "cyphr_gossip_commits_replayed_total"),
        replayed,
        "the kept state already covers the added commit"
    );
    assert_eq!(
        revoked_at(&app1, &carol).await,
        1,
        "P1 heard the new key's revoke"
    );
}
