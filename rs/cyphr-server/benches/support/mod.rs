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
use cyphr_server::AppState;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use http_body_util::BodyExt;
use tower::ServiceExt;

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
    (Arc::new(AppState::new(config).expect("state")), dir)
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
    pay.typ = Some(format!("{AUDIENCE}/cyphr/auth/login"));
    let bare = id.split_once(':').map_or(id, |(_, b)| b);
    pay.extra.insert("pr".into(), bare.into());
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &s.alg, &prv, &pubb).expect("sign");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).expect("pay"),
        sig,
    })
    .expect("login")
}
