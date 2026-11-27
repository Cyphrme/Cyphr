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
use cyphr_net::transport::NoiseConnector;
use cyphr_net::{ChannelBinding, ConnectError, Connector, PeerChain, Request};
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::transport::serve_noise;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{
    build_genesis_push_body, build_second_commit_push_body, get_json, golden_principal_id,
    load_pool, post_json, write_signing_key,
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
async fn server() -> (
    Arc<AppState>,
    SocketAddr,
    cyphr::PrincipalGenesis,
    tempfile::TempDir,
) {
    server_with(None).await
}

/// [`server`] with the configured session lifetime.
async fn server_with(
    session_ttl_secs: Option<i64>,
) -> (
    Arc<AppState>,
    SocketAddr,
    cyphr::PrincipalGenesis,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let config = ServerConfig {
        data_dir: dir.path().join("data"),
        signing_key_path: Some(key_path.clone()),
        audience: Some(AUDIENCE.to_string()),
        session_ttl_secs: session_ttl_secs.unwrap_or(ServerConfig::default().session_ttl_secs),
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
async fn session(
    state: &Arc<AppState>,
    addr: SocketAddr,
    pr: &cyphr::PrincipalGenesis,
) -> NoiseConnector {
    session_as(state, addr, pr, &golden_signer()).await
}

/// A fresh Level 1 principal (a key that is its own principal) and its
/// signer: whoever dials a server needs no account to authenticate.
fn fresh_level_one() -> (cyphr::PrincipalGenesis, SoftwareSigner) {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    let signer = SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb);
    let key = cyphr::Key::new(kp.alg.name().to_string(), tmb, kp.pub_bytes.clone())
        .expect("key binds its tmb");
    let id = cyphr_storage::engine::genesis_principal_id(&cyphr_storage::Genesis::Implicit(key))
        .expect("a Level 1 key derives an id");
    (id, signer)
}

async fn session_as(
    state: &Arc<AppState>,
    addr: SocketAddr,
    pr: &cyphr::PrincipalGenesis,
    signer: &SoftwareSigner,
) -> NoiseConnector {
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
    let mut held = PeerChain::pin(
        &d["pg"].as_str().expect("pg").parse().expect("labelled pg"),
        genesis,
    )
    .await;
    held.follow(&RouterConnector(app))
        .await
        .expect("follow the server chain");
    NoiseConnector::connect(addr, &mut held, signer, pr)
        .await
        .expect("an authenticated session")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// The timestamp-flow login the `golden` key signs for `pr`, committing to
/// the channel whose handshake hash is `h` when it is given (a native
/// client's login over Noise).
fn login_body(pr: &cyphr::PrincipalGenesis, h: Option<&[u8]>) -> String {
    login_body_with(pr, h, &[])
}

fn login_body_with(
    pr: &cyphr::PrincipalGenesis,
    h: Option<&[u8]>,
    extra: &[(&str, &str)],
) -> String {
    let pool = load_pool();
    let key = pool.get(GOLDEN_KEY).expect("golden in pool");
    let prv = Base64UrlUnpadded::decode_vec(key.prv.as_ref().expect("prv")).expect("prv");
    let public = Base64UrlUnpadded::decode_vec(&key.pub_key).expect("pub");
    let mut pay = coz::Pay::new();
    pay.alg = Some(key.alg.clone());
    pay.now = Some(now());
    pay.tmb = Some(key.compute_tmb().expect("tmb"));
    pay.typ = Some(format!("{AUDIENCE}/user/login/request/create"));
    pay.extra
        .insert("pg".to_string(), serde_json::Value::String(pr.to_string()));
    if let Some(h) = h {
        pay.extra.insert(
            "h".to_string(),
            serde_json::Value::String(Base64UrlUnpadded::encode_string(h)),
        );
    }
    for (name, value) in extra {
        pay.extra.insert(
            (*name).to_string(),
            serde_json::Value::String((*value).into()),
        );
    }
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

/// A native client's sign-in: a Noise session and the token its login,
/// which commits to that session's handshake hash, earned.
async fn native_login(
    state: &Arc<AppState>,
    addr: SocketAddr,
    pr: &cyphr::PrincipalGenesis,
) -> (NoiseConnector, String) {
    let conn = session(state, addr, pr).await;
    let h = conn.channel_binding().expect("binding").as_bytes().to_vec();
    let (status, login) = over_noise(
        &conn,
        Request::post("/auth/login", login_body(pr, Some(&h)).into_bytes()),
    )
    .await;
    assert_eq!(status, 200, "{login}");
    (conn, token_of(&login))
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
    let (first, token) = native_login(&state, addr, &pr).await;
    let present = || Request::post("/auth/session", token.clone().into_bytes());

    let (status, answer) = over_noise(&first, present()).await;
    assert_eq!(status, 200, "the issuing channel must accept: {answer}");
    assert_eq!(answer["payload"]["binding"], "noise-handshake-hash");

    let second = session(&state, addr, &pr).await;
    let (status, _) = over_noise(&second, present()).await;
    assert_eq!(status, 401, "a second Noise session must be refused");

    let (status, body) =
        post_json(build_router(state.clone()), "/auth/session", token.clone()).await;
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
    let (status, login) = post_json(app.clone(), "/auth/login", login_body(&pr, None)).await;
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
    let (status, answer) =
        over_noise(&noise, Request::post("/auth/session", token.into_bytes())).await;
    assert_eq!(status, 200, "a key-bound token has no channel: {answer}");
}

/// Claim: a login over Noise must come from the principal and key that
/// authenticated the session, or anyone with a Noise session could carry a
/// victim's signed login to the server on their own channel and walk away
/// with the victim's token bound to the attacker's channel.
///
/// Turns red if: a fresh Level 1 principal on its own session posting the
/// victim's signed login gets a token (200).
/// End-to-end scenario: yes (real server, attacker and victim identities).
#[tokio::test]
async fn login_over_noise_must_come_from_the_session_peer() {
    let (state, addr, pr, _dir) = server().await;
    let (attacker_pr, attacker) = fresh_level_one();
    let conn = session_as(&state, addr, &attacker_pr, &attacker).await;
    let h = conn.channel_binding().expect("binding").as_bytes().to_vec();
    let (status, _) = over_noise(
        &conn,
        Request::post("/auth/login", login_body(&pr, Some(&h)).into_bytes()),
    )
    .await;
    assert_eq!(status, 401, "the victim's login on the attacker's session");
}

/// Claim: a login commits to its channel (SPEC 17.2 login over Noise): over
/// Noise the client signs the handshake hash into the login and the server
/// binds the token only when it equals the session's; a login carrying a
/// hash is refused over HTTP and a login without one is refused over Noise,
/// so neither can be downgraded to the other.
///
/// Turns red if: a victim's Noise login reposted over HTTP or on a second
/// Noise session mints a token, a login without a hash is accepted over
/// Noise, or one carrying a hash is accepted over HTTP.
/// End-to-end scenario: yes (real server, three channels).
#[tokio::test]
async fn login_commits_to_its_channel() {
    let (state, addr, pr, _dir) = server().await;
    let app = build_router(state.clone());
    let victim = session(&state, addr, &pr).await;
    let h = victim
        .channel_binding()
        .expect("binding")
        .as_bytes()
        .to_vec();
    let body = login_body(&pr, Some(&h));
    let (status, _) = over_noise(
        &victim,
        Request::post("/auth/login", body.clone().into_bytes()),
    )
    .await;
    assert_eq!(status, 200, "the login on its own channel");

    let (status, _) = post_json(app.clone(), "/auth/login", body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the same login over HTTP");
    let second = session(&state, addr, &pr).await;
    let (status, _) = over_noise(&second, Request::post("/auth/login", body.into_bytes())).await;
    assert_eq!(status, 401, "the same login on a second session");

    let (status, _) = over_noise(
        &second,
        Request::post("/auth/login", login_body(&pr, None).into_bytes()),
    )
    .await;
    assert_eq!(status, 401, "no hash over Noise is a downgrade");
}

/// Claim: over Noise a push carries its session's token in the body (the
/// transport has no headers), and a token is good only on its own session.
///
/// Turns red if: another session's token is accepted on a push, or the
/// session's own token is not.
/// End-to-end scenario: yes (real server, two sessions, a real second commit).
#[tokio::test]
async fn push_over_noise_takes_the_sessions_own_token() {
    let (state, addr, pr, _dir) = server().await;
    let (mine, my_token) = native_login(&state, addr, &pr).await;
    let (_theirs, their_token) = native_login(&state, addr, &pr).await;
    let pool = load_pool();
    let base = build_second_commit_push_body(&pool, &pr, 1_700_000_000, 1_700_000_100).await;
    let push = |token: &str| {
        let mut body: serde_json::Value = serde_json::from_str(&base).expect("push body");
        body["token"] = token.into();
        Request::post("/push", body.to_string().into_bytes())
    };
    let (status, _) = over_noise(&mine, push(&their_token)).await;
    assert_eq!(status, 401, "another session's token");
    let (status, answer) = over_noise(&mine, push(&my_token)).await;
    assert_eq!(status, 200, "the session's own token: {answer}");
}

/// Claim (binding rules): the binding cannot be supplied by the client and
/// the session is short and configured. A `cb` smuggled into the signed
/// login does not bind the token (admission reads it only from the
/// server-signed token); the response names the binding that applied; the
/// lifetime is the configured one; presenting a token never extends it.
///
/// Turns red if: a client-supplied `cb` changes the binding, the response
/// omits the binding or the lifetime, the lifetime is not the configured
/// one, or a presentation moves it.
/// End-to-end scenario: yes (real server over HTTP).
#[tokio::test]
async fn rules_binding_is_server_signed_and_lifetime_configured() {
    let (state, _addr, pr, _dir) = server_with(Some(120)).await;
    let app = build_router(state.clone());
    let smuggled = login_body_with(&pr, None, &[("cb", "AAAA")]);
    let (status, login) = post_json(app.clone(), "/auth/login", smuggled).await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let token = token_of(&login);

    let (_, first) = post_json(app.clone(), "/auth/session", token.clone()).await;
    assert_eq!(first["payload"]["binding"], "key", "{first}");
    let exp = first["payload"]["exp"].as_i64().expect("exp");
    let issued = now();
    assert!(
        (issued + 118..=issued + 120).contains(&exp),
        "exp {exp} is not the configured 120s from now {issued}"
    );
    let (_, again) = post_json(app, "/auth/session", token).await;
    assert_eq!(
        again["payload"]["exp"], first["payload"]["exp"],
        "no sliding refresh"
    );
}
