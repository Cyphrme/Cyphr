//! Shared by the U3 server bench and its bound tests: an attestor server,
//! requests through the real router, a counting peer, a login body.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::common::Chain;

pub const AUDIENCE: &str = "cyphr.me";

/// An attestor server (keyed, bootstrapped, audience set): the shape the
/// production authority has.
pub async fn attestor() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    std::fs::write(
        &key,
        serde_json::json!({
            "alg": kp.alg.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
            "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
        })
        .to_string(),
    )
    .expect("key");
    let config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key.clone()),
        audience: Some(AUDIENCE.into()),
        ..Default::default()
    };
    let mut state = AppState::new(config).expect("state");
    // Counts are of the engine, not of the shadow check's own replays.
    state.engine.set_kept_shadow(false);
    let identity = state.identity.clone().expect("identity");
    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key, &state.config.data_dir)
        .await
        .expect("bootstrap");
    state.principal = Some(Arc::new(sp));
    (Arc::new(state), dir)
}

pub fn keyless() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = ServerConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    let mut state = AppState::new(config).expect("state");
    state.engine.set_kept_shadow(false);
    (Arc::new(state), dir)
}

pub fn push_body(id: &str, b: &WireBundle) -> String {
    let mut v = serde_json::to_value(b).expect("bundle");
    v["principal_id"] = id.into();
    v.to_string()
}

/// One request through the router: status and response size.
pub async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: String,
) -> (StatusCode, usize, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, bytes.len(), bytes.to_vec())
}

pub fn series(state: &AppState, name: &str) -> u64 {
    state
        .metrics
        .render(0)
        .lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no series {name}"))
}

/// Peer-side tally: requests, response bytes.
#[derive(Default)]
pub struct Wire {
    pub requests: AtomicU64,
    pub bytes: AtomicU64,
}

pub async fn serve_counting(app: Router) -> (String, Arc<Wire>) {
    let wire = Arc::new(Wire::default());
    let w = Arc::clone(&wire);
    let app = app.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let w = Arc::clone(&w);
            async move {
                w.requests.fetch_add(1, Relaxed);
                let (parts, body) = next.run(req).await.into_parts();
                let bytes = body.collect().await.expect("body").to_bytes();
                w.bytes.fetch_add(bytes.len() as u64, Relaxed);
                axum::response::Response::from_parts(parts, Body::from(bytes))
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
    (format!("http://{addr}"), wire)
}

pub fn login_body(id: &str) -> String {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool");
    let s = pool.get("golden").expect("golden");
    let prv = Base64UrlUnpadded::decode_vec(s.prv.as_ref().expect("prv")).expect("prv");
    let pubb = Base64UrlUnpadded::decode_vec(&s.pub_key).expect("pub");
    let mut pay = coz::Pay::new();
    pay.alg = Some(s.alg.clone());
    pay.now = Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64,
    );
    pay.tmb = Some(s.compute_tmb().expect("tmb"));
    pay.typ = Some(format!("{AUDIENCE}/user/login/request/create"));
    let bare = id.split_once(':').map_or(id, |(_, b)| b);
    pay.extra.insert("pg".into(), bare.into());
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &s.alg, &prv, &pubb).expect("sign");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).expect("pay"),
        sig,
    })
    .expect("login")
}

/// What a pull from a forked peer cost the holder, as the peer was asked.
pub struct ForkLocation {
    pub n: usize,
    pub height: usize,
    pub forked: bool,
    /// `/proof` asks (extension certificates).
    pub proof: usize,
    pub patch: usize,
    /// Commits the peer's `/patch` answers carried.
    pub fetched: usize,
    /// Timestamp checks the holder's pull made of what it replayed, from
    /// the record's clock (called once per signed message a replay checks).
    /// Counted per thread, so it is exact only on a current-thread
    /// runtime, and its unit is signed messages checked, not commits.
    pub client_checks: u64,
    /// The same count for building the holder's record from its `n`
    /// commits: one replay of the whole chain, so `build_checks / n` is a
    /// replay's cost per commit.
    pub build_checks: u64,
    /// Commits the holder asked its chain store for (a resumed holder
    /// only: the state is kept, the commits are stored); 0 otherwise.
    pub chain_reads: usize,
    pub ms: f64,
}

/// The chain a resumed holder's state covers, counting what is read of it.
struct Counted {
    entries: Vec<cyphr_client::PatchEntry>,
    reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl cyphr_client::ChainSource for Counted {
    fn first(
        &self,
        count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<cyphr_client::PatchEntry>, String>>
                + Send
                + '_,
        >,
    > {
        self.reads.fetch_add(count, Relaxed);
        Box::pin(async move { Ok(self.entries[..count].to_vec()) })
    }
}

thread_local! {
    static CLOCK_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The record's clock: far ahead of any chain, and counting its reads.
fn counting_clock() -> i64 {
    CLOCK_READS.with(|c| c.set(c.get() + 1));
    i64::MAX / 4
}

/// Counts what the holder asks the peer.
struct Asked {
    inner: cyphr_client::HttpConnector,
    asked: std::sync::Mutex<Vec<String>>,
    fetched: std::sync::Mutex<usize>,
}

impl cyphr_client::Connector for Asked {
    fn channel_binding(&self) -> Option<&cyphr_client::ChannelBinding> {
        self.inner.channel_binding()
    }

    async fn exchange(
        &self,
        request: &cyphr_client::Request,
    ) -> Result<Vec<u8>, cyphr_client::ConnectError> {
        self.asked
            .lock()
            .expect("asked")
            .push(request.target.clone());
        let body = self.inner.exchange(request).await?;
        if request.target.starts_with("/patch") {
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let n = json["payload"]["entries"].as_array().map_or(0, Vec::len);
            *self.fetched.lock().expect("fetched") += n;
        }
        Ok(body)
    }
}

/// A holder of `n` commits pulls from a peer that agrees with it up to
/// position `n / 2` and then goes its own way for the rest and one commit
/// more: where the logs part is found, and what it cost.
pub async fn fork_location(n: usize) -> ForkLocation {
    fork_location_at(n, n / 2, false, false).await
}

/// [`fork_location`] with the logs parting at position `at`, and the
/// holder either replayed from its commits or (`resumed`) started from its
/// verified state with the commits in a counted store.
///
/// With `rival_data` the peer's commit at `at` is a data commit
/// ([`Chain::next_data`]), which the holder verifies only once it has the
/// action the peer serves apart from it.
pub async fn fork_location_at(
    n: usize,
    at: usize,
    resumed: bool,
    rival_data: bool,
) -> ForkLocation {
    fork_locations(n, &[(at, rival_data)], resumed)
        .await
        .remove(0)
}

/// [`fork_location_at`] for each `(at, rival_data)` of `configs` on one
/// holder of `n` commits, built once (a chain's commits are the cost of
/// the measure, and the holder's are the same whatever the peer does).
pub async fn fork_locations(
    n: usize,
    configs: &[(usize, bool)],
    resumed: bool,
) -> Vec<ForkLocation> {
    let mut ats: Vec<usize> = configs.iter().map(|&(at, _)| at).collect();
    ats.sort_unstable();
    ats.dedup();
    let mut mine = Chain::new("golden", "key_a", "key_b").await;
    let mut snapshots = Vec::new();
    for at in ats {
        while mine.commits < at {
            mine.next().await;
        }
        snapshots.push((at, mine.fork().await));
    }
    while mine.commits < n {
        mine.next().await;
    }
    let mut out = Vec::new();
    for &(at, rival_data) in configs {
        let (_, snapshot) = snapshots.iter().find(|(a, _)| *a == at).expect("snapshot");
        let mut theirs = snapshot.fork().await;
        theirs.diverge("carol");
        if rival_data {
            theirs.next_data().await;
        }
        while theirs.commits <= n {
            theirs.next().await;
        }
        out.push(pull_fork(&mine, &theirs, at, resumed).await);
    }
    out
}

/// What the holder `mine` costs to pull from the peer `theirs`, which it
/// shares the first `height` commits with.
async fn pull_fork(mine: &Chain, theirs: &Chain, height: usize, resumed: bool) -> ForkLocation {
    let (peer, _dir) = keyless();
    let app = build_router(peer.clone());
    for i in 0..theirs.commits {
        if let Some(actions) = theirs.action_bundle(i) {
            let (st, ..) = call(&app, "POST", "/push", push_body(&theirs.id, &actions)).await;
            assert!(st.is_success(), "peer action push {i}: {st}");
        }
        let (st, ..) = call(
            &app,
            "POST",
            "/push",
            push_body(&theirs.id, &theirs.bundle(i)),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "peer push {i}");
    }
    let (url, _wire) = serve_counting(app).await;

    let key = {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
        let pool = test_fixtures::Pool::load(&path).expect("pool");
        pool.get("golden").expect("golden").key().expect("key")
    };
    let entries: Vec<cyphr_client::PatchEntry> = (0..mine.commits)
        .map(|i| cyphr_client::PatchEntry {
            sequence: i as u64,
            bundle: Ok(mine.bundle(i)),
        })
        .collect();
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let built_before = CLOCK_READS.with(std::cell::Cell::get);
    let mut record = cyphr_client::Record::from_entries(
        &mine.id,
        cyphr_client::Anchor::GenesisKey(key),
        counting_clock,
        &entries,
        &[],
    )
    .await
    .expect("record");
    let build_checks = CLOCK_READS.with(std::cell::Cell::get) - built_before;
    if resumed {
        let state = record
            .principal()
            .expect("held a chain")
            .fork()
            .await
            .expect("copy");
        let store = std::sync::Arc::new(Counted {
            entries: entries.clone(),
            reads: reads.clone(),
        });
        record =
            cyphr_client::Record::resume(&mine.id, state, counting_clock, store).expect("resumes");
    }

    let connector = Asked {
        inner: cyphr_client::HttpConnector::with_client(reqwest::Client::new(), &url, true)
            .expect("connector"),
        asked: Default::default(),
        fetched: Default::default(),
    };
    let checks_before = CLOCK_READS.with(std::cell::Cell::get);
    let t = std::time::Instant::now();
    let report = cyphr_client::pull(
        &mut record,
        &[cyphr_client::PullPeer {
            name: "peer",
            connector: &connector,
        }],
    )
    .await;
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let client_checks = CLOCK_READS.with(std::cell::Cell::get) - checks_before;
    let count = |route: &str| {
        connector
            .asked
            .lock()
            .expect("asked")
            .iter()
            .filter(|t| t.starts_with(route))
            .count()
    };
    ForkLocation {
        n: mine.commits,
        height,
        forked: report.forks.first().is_some_and(|f| f.height == height),
        proof: count("/proof"),
        patch: count("/patch"),
        fetched: *connector.fetched.lock().expect("fetched"),
        client_checks,
        build_checks,
        chain_reads: reads.load(Relaxed),
        ms,
    }
}
