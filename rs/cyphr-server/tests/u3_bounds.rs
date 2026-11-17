//! U3 cost bounds of the served operations, pinned as counts (never time):
//! what a request replays, how many proof hashes it carries and how many
//! requests a gossip round makes must not grow with the length of the
//! principal's history. Each operation runs on a principal of 8 commits
//! and on one of 40. The timed counterpart is `cargo bench -p
//! cyphr-server --bench u3_server`.
//!
//! A test marked `#[ignore]` names a bound the server does not yet meet;
//! the change that meets it removes the ignore.

#[path = "../../cyphr-storage/benches/common/mod.rs"]
mod common;
#[path = "../benches/support/mod.rs"]
mod support;

use std::sync::atomic::Ordering::Relaxed;

use axum::http::StatusCode;
use common::Chain;
use cyphr_client::HttpConnector;
use cyphr_server::build_router;
use cyphr_server::gossip::Gossip;
use support::*;
use tokio::sync::OnceCell;

const SHORT: usize = 8;
const LONG: usize = 40;
const K: usize = 3;

#[derive(Debug)]
struct Obs {
    n: usize,
    write_replayed: u64,
    tip_replayed: u64,
    patch_replayed: u64,
    consistency_replayed: u64,
    consistency_hashes: usize,
    inclusion_replayed: u64,
    inclusion_hashes: usize,
    login_replayed: u64,
    session_replayed: u64,
    idle_requests: u64,
    idle_replayed: u64,
    idle_gossip_replayed: u64,
    pull_gossip_replayed: u64,
    pull_replayed: u64,
}

async fn observe(n: usize) -> Obs {
    let (a, _da) = attestor().await;
    let (b, _db) = keyless();
    let (app_a, app_b) = (build_router(a.clone()), build_router(b.clone()));
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let mut bundles = vec![chain.first()];
    while chain.commits < n {
        bundles.push(chain.next().await);
    }
    for bundle in &bundles {
        for app in [&app_a, &app_b] {
            let (st, ..) = call(app, "POST", "/push", push_body(&id, bundle)).await;
            assert_eq!(st, StatusCode::CREATED);
        }
    }

    let replayed = || a.engine.commits_replayed();
    let ok = |(st, _, body): (StatusCode, usize, Vec<u8>)| {
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")
    };
    // Hashes in a consistency proof: the boundary, the peak path and the
    // new peaks; in an inclusion proof: the path.
    let len = |v: &serde_json::Value| v.as_array().expect("array").len();
    let consistency_hashes = |v: &serde_json::Value| {
        let p = &v["payload"]["proof"];
        1 + len(&p["peak_path"]) + len(&p["new_peaks"])
    };
    let inclusion_hashes = |v: &serde_json::Value| len(&v["payload"]["proof"]["path"]);

    let before = replayed();
    let w = chain.next().await;
    let (st, ..) = call(&app_a, "POST", "/push", push_body(&id, &w)).await;
    assert_eq!(st, StatusCode::CREATED);
    call(&app_b, "POST", "/push", push_body(&id, &w)).await;
    let write_replayed = replayed() - before;
    let n = chain.commits;

    let before = replayed();
    let tip = ok(call(&app_a, "GET", &format!("/tip?pr={id}"), String::new()).await);
    let tip_replayed = replayed() - before;
    let commit_id = tip["payload"]["commit_id"].as_str().expect("commit_id");

    let before = replayed();
    ok(call(&app_a, "GET", &format!("/patch?pr={id}&from={commit_id}"), String::new()).await);
    let patch_replayed = replayed() - before;

    let before = replayed();
    let c = ok(call(&app_a, "GET", &format!("/consistency?pr={id}&from={}", n / 2), String::new()).await);
    let consistency_replayed = replayed() - before;
    let before = replayed();
    let i = ok(call(&app_a, "GET", &format!("/inclusion?pr={id}&index={}", n / 2), String::new()).await);
    let inclusion_replayed = replayed() - before;

    let before = replayed();
    let login = ok(call(&app_a, "POST", "/auth/login", login_body(&id)).await);
    let login_replayed = replayed() - before;
    let token = login["payload"]["token"].as_str().expect("token").to_owned();
    let before = replayed();
    ok(call(&app_a, "POST", "/auth/session", token).await);
    let session_replayed = replayed() - before;

    let (url, wire) = serve_counting(app_b.clone()).await;
    let peers = [(
        url.clone(),
        HttpConnector::with_client(a.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    gossip.round(&a, &peers).await;
    let gossiped = || series(&a, "cyphr_gossip_commits_replayed_total");
    let (r0, g0, q0) = (replayed(), gossiped(), wire.requests.load(Relaxed));
    gossip.round(&a, &peers).await;
    let idle_requests = wire.requests.load(Relaxed) - q0;
    let (idle_replayed, idle_gossip_replayed) = (replayed() - r0, gossiped() - g0);

    for _ in 0..K {
        let b2 = chain.next().await;
        call(&app_b, "POST", "/push", push_body(&id, &b2)).await;
    }
    let (r0, g0) = (replayed(), gossiped());
    gossip.round(&a, &peers).await;
    Obs {
        n,
        write_replayed,
        tip_replayed,
        patch_replayed,
        consistency_replayed,
        consistency_hashes: consistency_hashes(&c),
        inclusion_replayed,
        inclusion_hashes: inclusion_hashes(&i),
        login_replayed,
        session_replayed,
        idle_requests,
        idle_replayed,
        idle_gossip_replayed,
        pull_gossip_replayed: gossiped() - g0,
        pull_replayed: replayed() - r0,
    }
}

static OBS: OnceCell<[Obs; 2]> = OnceCell::const_new();

async fn obs() -> &'static [Obs; 2] {
    OBS.get_or_init(|| async { [observe(SHORT).await, observe(LONG).await] })
        .await
}

/// Bound: a write, a tip read, a patch from the tip, a consistency proof
/// and an inclusion proof each replay 0 commits, at any n.
#[tokio::test]
async fn writes_and_reads_replay_nothing() {
    for o in obs().await {
        let r = [
            o.write_replayed,
            o.tip_replayed,
            o.patch_replayed,
            o.consistency_replayed,
            o.inclusion_replayed,
        ];
        assert_eq!(r, [0; 5], "{o:?}");
    }
}

/// Bound: /consistency and /inclusion carry at most 2 ceil(log2 n) + 2
/// proof hashes (a path of at most log2 n steps, plus at most log2 n + 1
/// peaks).
#[tokio::test]
async fn proofs_carry_logarithmically_many_hashes() {
    for o in obs().await {
        let cap = 2 * (o.n as f64).log2().ceil() as usize + 2;
        assert!(o.consistency_hashes <= cap, "{o:?}");
        assert!(o.inclusion_hashes <= cap, "{o:?}");
    }
}

/// Bound: a login replays 0 commits, at any n.
#[tokio::test]
#[ignore = "bound not yet met: POST /auth/login replays the whole chain (load_principal)"]
async fn login_replays_nothing() {
    for o in obs().await {
        assert_eq!(o.login_replayed, 0, "{o:?}");
    }
}

/// Bound: presenting a bearer token (POST /auth/session) replays 0
/// commits, at any n.
#[tokio::test]
#[ignore = "bound not yet met: POST /auth/session replays the whole chain (check_session_key)"]
async fn token_check_replays_nothing() {
    for o in obs().await {
        assert_eq!(o.session_replayed, 0, "{o:?}");
    }
}

/// Bound: an idle gossip round makes the same number of requests whatever
/// n is (O(peers x principals)) and replays 0 commits.
#[tokio::test]
async fn idle_gossip_round_is_constant() {
    let o = obs().await;
    assert_eq!(o[0].idle_requests, o[1].idle_requests, "{o:?}");
    for o in o {
        assert_eq!((o.idle_replayed, o.idle_gossip_replayed), (0, 0), "{o:?}");
    }
}

/// Bound: pulling k new commits replays O(k) commits (at most k, none
/// beyond them) in the gossip record and 0 in the engine's cold path.
#[tokio::test]
async fn gossip_pull_replays_only_the_new_commits() {
    for o in obs().await {
        assert!(o.pull_gossip_replayed <= K as u64, "{o:?}");
        assert_eq!(o.pull_replayed, 0, "{o:?}");
    }
}
