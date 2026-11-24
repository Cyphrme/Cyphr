//! Data actions travel by gossip (SPEC 4.8.1), end to end over two servers
//! on real sockets.
//!
//! An action-only bundle moves no head, so the idle gate does not open for
//! it (GitHub #211); it reaches a peer with the next commit, because a peer
//! serves every action bundle it holds with its patch. P2 gets an action
//! and then a commit; one gossip round on P1 must bring both, whether P1's
//! engine still keeps the principal's verified state (the round opens its
//! record over it and replays only the new commit) or was restarted and
//! keeps none (the round replays the stored chain once). A further round
//! must neither store an action twice nor replay a commit.
//!
//! Turns red if: P1 never holds the actions, holds one twice, or a round
//! replays commits the kept state already covers.

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::config::ServerConfig;
use cyphr_server::gossip::{Gossip, Peer};
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, load_pool, post_json};

const T: i64 = 1_700_500_000;

/// A data action signed by the pool's `golden` key.
fn action_blob(pool: &test_fixtures::Pool, msg: &str) -> Vec<u8> {
    let g = pool.get("golden").expect("golden");
    let mut pay = serde_json::json!({
        "alg": g.alg, "msg": msg, "now": T + 5,
        "tmb": g.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/comment/create",
    });
    pay.as_object_mut().expect("object").sort_keys();
    let pay = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub");
    let (sig, _) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz")
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

fn replayed(state: &AppState) -> u64 {
    state
        .metrics
        .render(0)
        .lines()
        .find_map(|l| {
            l.strip_prefix("cyphr_gossip_commits_replayed_total")?
                .trim()
                .parse()
                .ok()
        })
        .expect("series")
}

/// How many action bundles `app` serves for `id`.
async fn held_actions(app: &axum::Router, id: &str) -> usize {
    let (status, body) = get_json(
        app.clone(),
        &format!("/patch?pr={}", id.replace(':', "%3A")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["actions"]
        .as_array()
        .map_or(0, Vec::len)
}

#[tokio::test(flavor = "multi_thread")]
async fn data_actions_reach_this_server_with_the_next_commit_by_gossip() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut owner = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut owner, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let first = common::key_commit_by(&mut owner, "golden", "key_a", T + 1).await;

    let dir1 = tempfile::tempdir().expect("dir");
    let open = |dir: &std::path::Path| {
        Arc::new(
            AppState::new(ServerConfig {
                data_dir: dir.to_path_buf(),
                ..Default::default()
            })
            .expect("state"),
        )
    };
    let (p1, (p2, _d2)) = (open(dir1.path()), common::keyless_server());
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
    let url = serve(app2.clone()).await;
    let peers = |p: &Arc<AppState>| {
        [Peer::new(
            url.clone(),
            HttpConnector::with_client(p.http_client.clone(), &url, true).expect("connector"),
        )]
    };
    let push_to_p2 = |bundle: WireBundle| {
        let (app, id) = (app2.clone(), id.clone());
        async move {
            let (status, body) = post_json(app, "/push", common::push_body(&id, &bundle)).await;
            assert!(status.is_success(), "{status} {body:?}");
        }
    };
    let tip_of = |app: axum::Router, id: String| async move {
        let (_, tip) = get_json(app, &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
        envelope_payload(&tip)["pr"].clone()
    };

    push_to_p2(WireBundle::actions(vec![action_blob(&pool, "first note")])).await;
    let second = common::key_commit_by(&mut owner, "golden", "carol", T + 9).await;
    push_to_p2(second).await;
    assert_eq!(held_actions(&app1, &id).await, 0, "P1 starts without it");

    // P1's engine kept the principal's state from the pushes.
    let mut gossip = Gossip::default();
    gossip.round(&p1, &peers(&p1)).await;
    assert_eq!(
        tip_of(app1.clone(), id.clone()).await,
        tip_of(app2.clone(), id.clone()).await
    );
    assert_eq!(held_actions(&app1, &id).await, 1, "P1 took the action");
    assert_eq!(replayed(&p1), 1, "only the new commit is replayed");
    gossip.round(&p1, &peers(&p1)).await;
    assert_eq!(held_actions(&app1, &id).await, 1, "held once");
    assert_eq!(replayed(&p1), 1);

    // A restarted P1 keeps no state: its engine replays the stored chain
    // once for the next round, which verifies only the new commit, and the
    // action it lacks still comes.
    drop((gossip, app1));
    drop(p1);
    let p1 = open(dir1.path());
    let app1 = build_router(p1.clone());
    assert_eq!(held_actions(&app1, &id).await, 1, "the action survives");
    push_to_p2(WireBundle::actions(vec![action_blob(&pool, "second note")])).await;
    let third = common::key_commit_by(&mut owner, "golden", "bob", T + 12).await;
    push_to_p2(third).await;
    Gossip::default().round(&p1, &peers(&p1)).await;
    assert_eq!(
        tip_of(app1.clone(), id.clone()).await,
        tip_of(app2.clone(), id.clone()).await
    );
    assert_eq!(held_actions(&app1, &id).await, 2, "P1 took the second");
    assert_eq!(
        (replayed(&p1), p1.engine.commits_replayed()),
        (1, 3),
        "the round verified the new commit; the engine replayed its 3 stored commits once"
    );
}
