//! Session binding (SO3): a session opened over the principal-authenticated
//! Noise transport is bound to that session's handshake hash, and a browser
//! edge session (plain HTTP, no channel) is bound to its key.
//!
//! Every test is an end-to-end scenario over a real TCP listener and a real
//! keyed server whose login audience is configured.
//!
//! Run: `cd rs && cargo test -p cyphr-server --test session_binding`

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::{Signer, SoftwareSigner};
use cyphr_client::transport::NoiseConnector;
use cyphr_client::{ChannelBinding, ConnectError, Connector, PeerChain, Request};
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::transport::serve_noise;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{
    build_genesis_push_body, get_json, golden_principal_id, load_pool, post_json,
    write_signing_key,
};

const AUDIENCE: &str = "cyphr.me";
const GOLDEN_KEY: &str = "golden";

/// The carrier over the in-process router, used only to follow the server
/// chain before the Noise session (the pin material is public).
struct RouterConnector(Router);

impl Connector for RouterConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let req = axum::http::Request::builder()
            .uri(&request.target)
            .body(axum::body::Body::empty())
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
        let Ok(resp) = self.0.clone().oneshot(req).await;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(ConnectError::NonSuccess(status.as_u16()));
        }
        Ok(bytes.to_vec())
    }
}

fn golden_signer() -> SoftwareSigner {
    let key = load_pool().get(GOLDEN_KEY).expect("key in pool").clone();
    SoftwareSigner::new(
        &key.alg,
        &Base64UrlUnpadded::decode_vec(key.prv.as_ref().expect("prv")).expect("prv b64"),
        &Base64UrlUnpadded::decode_vec(&key.pub_key).expect("pub b64"),
        &key.compute_tmb().expect("tmb"),
    )
}

/// A keyed, bootstrapped server that also serves logins for `AUDIENCE`,
/// with the `golden` principal pushed. Returns the state, the Noise
/// address, the principal id and the temp-dir guard.
async fn server() -> (Arc<AppState>, SocketAddr, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key_path.clone()),
        audience: Some(AUDIENCE.to_string()),
        ..Default::default()
    };
    let mut state = AppState::new(config).expect("open AppState");
    let identity = state.identity.clone().expect("keyed state has identity");
    let sp = ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
        .await
        .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(sp));
    let state = Arc::new(state);

    let app = build_router(state.clone());
    let pool = load_pool();
    let pr = golden_principal_id(&pool).await;
    let body = build_genesis_push_body(&pool, &pr, 1_700_000_000).await;
    let (status, resp) = post_json(app, "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp:?}");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let served = state.clone();
    tokio::spawn(async move {
        _ = serve_noise(listener, served).await;
    });
    (state, addr, pr, dir)
}

/// A fresh authenticated Noise session as the `golden` principal.
async fn session(state: &Arc<AppState>, addr: SocketAddr, pr: &str) -> NoiseConnector {
    let app = build_router(state.clone());
    let (_, discovery) = get_json(app.clone(), "/server").await;
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let b64 = |v: &serde_json::Value| Base64UrlUnpadded::decode_vec(v.as_str().expect("b64"));
    let genesis = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(b64(&g["tmb"]).expect("tmb")),
        b64(&g["pub"]).expect("pub"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let mut held = PeerChain::pin(d["pg"].as_str().expect("pg"), genesis).await;
    held.follow(&RouterConnector(app))
        .await
        .expect("follow the server chain");
    NoiseConnector::connect(addr, &mut held, &golden_signer(), pr)
        .await
        .expect("an authenticated session")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// The timestamp-flow login the `golden` key signs for `pr`.
fn login_body(pr: &str) -> String {
    let pool = load_pool();
    let key = pool.get(GOLDEN_KEY).expect("golden in pool");
    let prv = Base64UrlUnpadded::decode_vec(key.prv.as_ref().expect("prv")).expect("prv");
    let public = Base64UrlUnpadded::decode_vec(&key.pub_key).expect("pub");
    let mut pay = coz::Pay::new();
    pay.alg = Some(key.alg.clone());
    pay.now = Some(now());
    pay.tmb = Some(key.compute_tmb().expect("tmb"));
    pay.typ = Some(format!("{AUDIENCE}/cyphr/auth/login"));
    pay.extra.insert(
        "pr".to_string(),
        serde_json::Value::String(cyphr_storage::engine::bare_digest(pr).to_string()),
    );
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&bytes, &key.alg, &prv, &public).expect("sign");
    serde_json::to_string(&coz::CozJson {
        pay: serde_json::to_value(&pay).expect("pay value"),
        sig,
    })
    .expect("login json")
}

/// Send `request` over `conn` and read the status and JSON body; the
/// connector returns a non-success status as an error, so a refusal shows
/// as the status it carried.
async fn over_noise(conn: &NoiseConnector, request: Request) -> (u16, serde_json::Value) {
    match conn.exchange(&request).await {
        Ok(bytes) => (200, serde_json::from_slice(&bytes).expect("json")),
        Err(ConnectError::NonSuccess(status)) => (status, serde_json::Value::Null),
        Err(other) => panic!("transport failed: {other}"),
    }
}

fn token_of(login: &serde_json::Value) -> String {
    login["payload"]["token"]
        .as_str()
        .expect("login answers a token")
        .to_owned()
}

/// Claim: a stolen token is useless off the channel it was issued on. A
/// native client signs in over a Noise session; the token works on that
/// session, is refused with 401 on a second authenticated session of the
/// same principal and over plain HTTP, and the refusal does not end the
/// session on its own channel.
///
/// Turns red if: a token issued over Noise is accepted on a second Noise
/// session or over HTTP, or the refused presentation breaks the original.
/// End-to-end scenario: yes (real server, three channels, one principal).
#[tokio::test]
async fn token_is_refused_on_a_second_channel() {
    let (state, addr, pr, _dir) = server().await;
    let first = session(&state, addr, &pr).await;
    let (status, login) =
        over_noise(&first, Request::post("/auth/login", login_body(&pr).into_bytes())).await;
    assert_eq!(status, 200, "{login}");
    let token = token_of(&login);
    let present = || Request::post("/auth/session", token.clone().into_bytes());

    let (status, answer) = over_noise(&first, present()).await;
    assert_eq!(status, 200, "the issuing channel must accept: {answer}");
    assert_eq!(answer["payload"]["binding"], "noise-handshake-hash");

    let second = session(&state, addr, &pr).await;
    assert_ne!(
        first.channel_binding().expect("binding").as_bytes(),
        second.channel_binding().expect("binding").as_bytes(),
        "two sessions have two handshake hashes"
    );
    let (status, _) = over_noise(&second, present()).await;
    assert_eq!(status, 401, "a second Noise session must be refused");

    let (status, body) = post_json(
        build_router(state.clone()),
        "/auth/session",
        token.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, answer) = over_noise(&first, present()).await;
    assert_eq!(status, 200, "refusals must not end the session: {answer}");
}

/// Claim: a browser edge session has no channel to bind to, so it is bound
/// to its key. A login over plain HTTP mints a key-bound token that names
/// the key and is accepted wherever it arrives while that key stands;
/// nothing about it ties it to a connection.
///
/// Turns red if: an HTTP login's token is channel-bound (so refused on
/// Noise), or the binding it reports is not the key.
/// End-to-end scenario: yes (real server, HTTP and Noise).
#[tokio::test]
async fn browser_session_is_bound_to_its_key() {
    let (state, addr, pr, _dir) = server().await;
    let app = build_router(state.clone());
    let (status, login) = post_json(app.clone(), "/auth/login", login_body(&pr)).await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let token = token_of(&login);

    let (status, answer) = post_json(app, "/auth/session", token.clone()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["payload"]["binding"], "key");
    assert_eq!(
        answer["payload"]["key"],
        golden_signer().tmb().to_b64(),
        "the key the session is bound to"
    );

    let noise = session(&state, addr, &pr).await;
    let (status, answer) = over_noise(&noise, Request::post("/auth/session", token.into_bytes())).await;
    assert_eq!(status, 200, "a key-bound token has no channel: {answer}");
}
