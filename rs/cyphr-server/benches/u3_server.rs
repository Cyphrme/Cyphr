//! U3 server-level scaling bench: what each served operation costs as a
//! principal's history grows, beside its bound. Every request goes through
//! the real router (`oneshot`, in-process, so wall time is the server's
//! work plus serialization, no socket); gossip runs between two servers on
//! real sockets, with a counting layer on the peer for requests and bytes.
//!
//! Run: `cargo bench -p cyphr-server --bench u3_server` (see
//! `rs/bench-u3.sh` for the whole suite). `U3_NS=10,100` overrides the
//! history lengths.

#[path = "../../cyphr-storage/benches/common/mod.rs"]
mod common;
#[path = "support/mod.rs"]
mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

use axum::http::StatusCode;
use common::{Chain, bad_signature, median};
use cyphr_client::HttpConnector;
use cyphr_server::gossip::Gossip;
use cyphr_server::{AppState, build_router};
use support::*;

#[derive(Default, Clone, Copy)]
struct Cost {
    replayed: u64,
    gossip_replayed: u64,
    sigs: u64,
    requests: u64,
    kb: f64,
    ms: f64,
}

/// Counters before an operation; `end` is the cost since.
struct Mark<'a>(
    &'a AppState,
    Option<&'a Wire>,
    u64,
    u64,
    u64,
    u64,
    u64,
    Instant,
);

fn mark<'a>(s: &'a AppState, w: Option<&'a Wire>) -> Mark<'a> {
    Mark(
        s,
        w,
        s.engine.commits_replayed(),
        series(s, "cyphr_gossip_commits_replayed_total"),
        cyphr::probe::signatures_checked(),
        w.map_or(0, |w| w.requests.load(Relaxed)),
        w.map_or(0, |w| w.bytes.load(Relaxed)),
        Instant::now(),
    )
}

impl Mark<'_> {
    /// `served` is the response bytes of a request-shaped operation; a
    /// gossip operation reads its bytes and requests off the peer's wire.
    fn end(self, served: usize) -> Cost {
        let wire_bytes = self.1.map_or(0, |w| w.bytes.load(Relaxed)) - self.6;
        Cost {
            replayed: self.0.engine.commits_replayed() - self.2,
            gossip_replayed: series(self.0, "cyphr_gossip_commits_replayed_total") - self.3,
            sigs: cyphr::probe::signatures_checked() - self.4,
            requests: self.1.map_or(1, |w| w.requests.load(Relaxed) - self.5),
            kb: (served as u64 + wire_bytes) as f64 / 1024.0,
            ms: self.7.elapsed().as_secs_f64() * 1e3,
        }
    }
}

fn row(n: usize, op: &str, bound: &str, c: Cost) {
    println!(
        "| {n} | {op} | {bound} | {} | {} | {} | {} | {:.1} | {:.3} |",
        c.replayed, c.gossip_replayed, c.sigs, c.requests, c.kb, c.ms
    );
}

/// `f` timed `reps` times against `s`; median time, last counts.
async fn measure<F, Fut>(s: &AppState, w: Option<&Wire>, reps: usize, mut f: F) -> Cost
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = usize>,
{
    let (mut times, mut last) = (Vec::new(), Cost::default());
    for _ in 0..reps {
        let m = mark(s, w);
        let served = f().await;
        last = m.end(served);
        times.push(last.ms);
    }
    last.ms = median(times);
    last
}

/// `reps` gossip rounds of `a` against `peers`: median time, last counts.
async fn rounds(
    a: &Arc<AppState>,
    wire: &Wire,
    gossip: &mut Gossip,
    peers: &[(String, HttpConnector)],
    reps: usize,
) -> Cost {
    let (mut times, mut last) = (Vec::new(), Cost::default());
    for _ in 0..reps {
        let m = mark(a, Some(wire));
        gossip.round(a, peers).await;
        last = m.end(0);
        times.push(last.ms);
    }
    last.ms = median(times);
    last
}

async fn run(n: usize) {
    let (a, _da) = attestor().await;
    let (b, _db) = keyless();
    let (app_a, app_b) = (build_router(a.clone()), build_router(b.clone()));
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let t = Instant::now();
    let mut bundles = vec![chain.first()];
    while chain.commits < n {
        bundles.push(chain.next().await);
    }
    for bundle in &bundles {
        for app in [&app_a, &app_b] {
            let (st, _, body) = call(app, "POST", "/push", push_body(&id, bundle)).await;
            assert_eq!(
                st,
                StatusCode::CREATED,
                "{}",
                String::from_utf8_lossy(&body)
            );
        }
    }
    eprintln!("n={n}: history built in {:.1}s", t.elapsed().as_secs_f64());

    // write
    let next = chain.next().await;
    let body = push_body(&id, &next);
    let c = measure(&a, None, 1, || async {
        let (st, len, _) = call(&app_a, "POST", "/push", body.clone()).await;
        assert_eq!(st, StatusCode::CREATED);
        len + body.len()
    })
    .await;
    row(n, "write: POST /push", "replayed 0", c);
    call(&app_b, "POST", "/push", body).await;

    let n = chain.commits;
    let tip_uri = format!("/tip?pr={id}");
    let c = measure(&a, None, 5, || async {
        let (st, len, _) = call(&app_a, "GET", &tip_uri, String::new()).await;
        assert_eq!(st, StatusCode::OK);
        len
    })
    .await;
    row(n, "read: GET /tip", "replayed 0", c);

    let (_, _, tipbody) = call(&app_a, "GET", &tip_uri, String::new()).await;
    let tip: serde_json::Value = serde_json::from_slice(&tipbody).expect("tip json");
    let commit_id = tip["payload"]["commit_id"].as_str().expect("commit_id");
    let patch_uri = format!("/patch?pr={id}&from={commit_id}");
    let c = measure(&a, None, 5, || async {
        let (st, len, _) = call(&app_a, "GET", &patch_uri, String::new()).await;
        assert_eq!(st, StatusCode::OK);
        len
    })
    .await;
    row(n, "read: GET /patch from tip", "replayed 0", c);

    let c = measure(&a, None, 3, || async {
        let (st, len, _) = call(
            &app_a,
            "GET",
            &format!("/consistency?pr={id}&from={}", n / 2),
            String::new(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        len
    })
    .await;
    row(
        n,
        "GET /consistency (from n/2)",
        "O(log n) hashes, replayed 0",
        c,
    );
    let c = measure(&a, None, 3, || async {
        let (st, len, _) = call(
            &app_a,
            "GET",
            &format!("/inclusion?pr={id}&index={}", n / 2),
            String::new(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        len
    })
    .await;
    row(n, "GET /inclusion (n/2)", "O(log n) hashes, replayed 0", c);

    // auth
    let c = measure(&a, None, 3, || async {
        let (st, len, resp) = call(&app_a, "POST", "/auth/login", login_body(&id)).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
        len
    })
    .await;
    row(n, "auth: POST /auth/login", "replayed 0", c);
    let (_, _, resp) = call(&app_a, "POST", "/auth/login", login_body(&id)).await;
    let token = serde_json::from_slice::<serde_json::Value>(&resp).expect("json")["payload"]
        ["token"]
        .as_str()
        .expect("token")
        .to_owned();
    let c = measure(&a, None, 3, || async {
        let (st, len, _) = call(&app_a, "POST", "/auth/session", token.clone()).await;
        assert_eq!(st, StatusCode::OK);
        len
    })
    .await;
    row(n, "auth: POST /auth/session (token check)", "replayed 0", c);

    // refused junk
    let upcoming = chain.next().await;
    let bad = push_body(&id, &bad_signature(&upcoming));
    let c = measure(&a, None, 3, || async {
        let (st, len, _) = call(&app_a, "POST", "/push", bad.clone()).await;
        assert!(st.is_client_error(), "{st}");
        len + bad.len()
    })
    .await;
    row(
        n,
        "refused push, bad signature",
        "O(bundle), indep. of n",
        c,
    );
    let mut other = Chain::new("alice", "key_a", "key_b").await;
    let _ = other.next().await;
    let stranger = push_body(&id, &other.next().await);
    let c = measure(&a, None, 3, || async {
        let (st, len, _) = call(&app_a, "POST", "/push", stranger.clone()).await;
        assert!(st.is_client_error(), "{st}");
        len + stranger.len()
    })
    .await;
    row(n, "refused push, unknown key", "O(bundle), indep. of n", c);
    // Bring both servers level on `upcoming` so gossip starts idle.
    for app in [&app_a, &app_b] {
        let (st, ..) = call(app, "POST", "/push", push_body(&id, &upcoming)).await;
        assert_eq!(st, StatusCode::CREATED);
    }

    // gossip: A pulls from B
    let (url, wire) = serve_counting(app_b.clone()).await;
    let peers = [(
        url.clone(),
        HttpConnector::with_client(a.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    let c = rounds(&a, &wire, &mut gossip, &peers, 1).await;
    row(n, "gossip round, first (cold memo)", "replayed 0 (kept)", c);
    let c = rounds(&a, &wire, &mut gossip, &peers, 3).await;
    row(n, "gossip round, idle", "O(peers) requests, replayed 0", c);
    for k in [1usize, 10] {
        for _ in 0..k {
            let b2 = chain.next().await;
            let (st, ..) = call(&app_b, "POST", "/push", push_body(&id, &b2)).await;
            assert_eq!(st, StatusCode::CREATED);
        }
        let c = rounds(&a, &wire, &mut gossip, &peers, 1).await;
        row(n, &format!("gossip pull of k={k} new"), "O(k) replay", c);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let ns: Vec<usize> = std::env::var("U3_NS")
        .unwrap_or_else(|_| "10,100,1000".into())
        .split(',')
        .map(|s| s.trim().parse().expect("U3_NS is a list of counts"))
        .collect();
    println!(
        "| n | operation | bound | engine replayed | gossip replayed | data sigs | requests | KB \
         | ms |"
    );
    println!("|--:|---|---|--:|--:|--:|--:|--:|--:|");
    for n in ns {
        run(n).await;
    }
}
