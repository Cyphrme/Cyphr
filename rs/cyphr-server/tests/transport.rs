//! Principal-authenticated transport, server side (TR1 reds).
//!
//! The design under test: a Noise NN handshake with ephemeral keys only,
//! then each side signs the handshake hash with its Cyphr key in SIGMA-I
//! order (responder first). There is no non-Cyphr long-term key, and the
//! client's key here comes from the test through the `Signer` interface;
//! nothing stores a private key.
//!
//! Every test is an end-to-end scenario over a real TCP listener and a real
//! keyed server.
//!
//! Run: `cd rs && cargo test -p cyphr-server --test transport`
//!
//! APIs assumed (the implement brief provides them):
//! - `cyphr_client::transport::{NoiseConnector, TransportError}`; `NoiseConnector::connect(addr,
//!   &mut PeerChain, &impl Signer, &str)` is async; `peer()` gives `AuthenticatedPeer { pg, tmb,
//!   verified_at, anchor }`.
//! - `cyphr_server::transport::serve_noise(listener, Arc<AppState>)`, and
//!   `serve_noise_with(listener, state, router)`, which is `serve_noise` with the dispatch router
//!   supplied by the caller (the test-only hook that lets a peer serve envelope `v=99`).
//! - The responder signs its statement through `AppState::attestor_signer`, the one accessor every
//!   server signature goes through.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::{Signer, SoftwareSigner};
use cyphr_client::transport::{
    Channel, NoiseConnector, Role, TransportError, assemble_statement, decode_ack, statement_pay,
};
use cyphr_client::{
    BindingKind, BindingPolicy, ChannelBinding, ConnectError, Connector, PatchFailure,
    PatchRequest, PeerChain, Request, fetch_patch,
};
use cyphr_server::transport::{AuthenticatedPeer, ServeError, serve_noise, serve_noise_with};
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, golden_principal_id, keyless_server,
    load_pool, post_json,
};

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

/// The pin material `/server` publishes: the server PG and genesis key.
async fn discover(app: &Router) -> (String, cyphr::Key) {
    let (_, discovery) = get_json(app.clone(), "/server").await;
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let key = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb b64"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub b64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    (d["pg"].as_str().expect("pg").to_string(), key)
}

/// Pin the server and follow its chain over the in-process router.
async fn pinned_and_followed(app: &Router) -> (PeerChain, String, cyphr::Key) {
    let (pg, genesis) = discover(app).await;
    let mut held = PeerChain::pin(&pg, genesis.clone()).await;
    held.follow(&RouterConnector(app.clone()))
        .await
        .expect("follow the server chain");
    (held, pg, genesis)
}

/// Push the `golden` principal (the client's own principal) to the server.
async fn push_client_principal(app: &Router) -> String {
    let pool = load_pool();
    let pr = golden_principal_id(&pool).await;
    let body = build_genesis_push_body(&pool, &pr, 1_700_000_000).await;
    let (status, resp) = post_json(app.clone(), "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    pr
}

/// A pool key behind the `Signer` interface. No key is stored anywhere.
fn pool_signer(name: &str) -> SoftwareSigner {
    let pool = load_pool();
    let key = pool.get(name).expect("key in pool");
    SoftwareSigner::new(
        &key.alg,
        &Base64UrlUnpadded::decode_vec(key.prv.as_ref().expect("prv")).expect("prv b64"),
        &Base64UrlUnpadded::decode_vec(&key.pub_key).expect("pub b64"),
        &key.compute_tmb().expect("tmb"),
    )
}

/// The test-supplied Level 1 client key: the pool's `golden` key.
fn golden_signer() -> SoftwareSigner {
    pool_signer("golden")
}

/// Extend `principal` with a commit in which `signer_name` revokes itself
/// (SPEC's self-revoke shape), returning the commit's wire blobs. Mirrors
/// the helper `tests/login.rs` keeps for the same purpose; the two suites
/// do not share a module.
async fn self_revoke_commit_blobs(
    mut principal: cyphr::Principal<impl cyphr::eml::Storage>,
    signer_name: &str,
    at: i64,
) -> Vec<Vec<u8>> {
    let pool = load_pool();
    let key = pool.get(signer_name).expect("key in pool");
    let tmb = key.compute_tmb_b64().expect("tmb");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": key.alg,
        "now": at,
        "rvk": at,
        "tmb": tmb,
        "typ": "cyphr.me/cyphr/key/revoke",
    }))
    .expect("pay json");
    let prv = Base64UrlUnpadded::decode_vec(key.prv.as_ref().expect("prv")).expect("prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&key.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &key.alg, &prv, &pub_key).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &key.alg).expect("czd");

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("the self-revoke verifies against the principal");
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&key.alg, &prv, &pub_key, &key.compute_tmb().expect("tmb")),
            at,
            "cyphr.me",
        )
        .await
        .expect("the commit finalizes");
    let entries = cyphr_storage::export_commits(&principal).expect("export the commit");
    entries
        .last()
        .expect("a commit after finalize")
        .cozies
        .iter()
        .map(|c| serde_json::to_vec(c).expect("cozy serializes"))
        .collect()
}

async fn listen() -> (tokio::net::TcpListener, SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    (listener, addr)
}

async fn start_noise(state: Arc<AppState>) -> SocketAddr {
    let (listener, addr) = listen().await;
    tokio::spawn(async move {
        _ = serve_noise(listener, state).await;
    });
    addr
}

/// Claim: two Cyphr principals authenticate one Noise session. A client
/// holding a pinned, followed server chain and a test-supplied Level 1 key
/// completes NN plus both signed handshake-hash statements against a real
/// keyed server; the binding is the Noise handshake hash and is fresh per
/// session; `peer()` names the server PG, the signing tmb, the held tip the
/// statement was verified against, and the anchor; a request through the
/// connector returns what HTTP returns.
///
/// Turns red if: a session is accepted without both verified statements
/// (the request would then succeed in the refusal tests below), the binding
/// is not the handshake hash kind or repeats across sessions, or `peer()`
/// reports a PG, tmb or tip other than the one the client verified.
/// End-to-end scenario: yes. The binding's equality on both sides is
/// checked indirectly: the server accepts the client statement only over
/// its own `h`, so a request that succeeds proves both ends hold the same
/// value; a server-side accessor would be a test-only seam this brief does
/// not define.
#[tokio::test]
async fn two_principals_authenticate_one_noise_session() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, pg, genesis) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;
    let signer = golden_signer();

    let first = NoiseConnector::connect(addr, &mut held, &signer, &own_principal)
        .await
        .expect("both statements verify");
    let binding = first.channel_binding().expect("a Noise session binds");
    assert_eq!(binding.kind(), BindingKind::NoiseHandshakeHash);
    assert!(
        binding.as_bytes().len() >= 32,
        "a handshake hash, not a stub"
    );

    let peer = first.peer();
    assert_eq!(peer.pg, pg, "peer() names the pinned server PG");
    assert_eq!(&peer.tmb, genesis.tmb(), "peer() names the signing tmb");
    assert_eq!(
        peer.verified_at,
        held.held_tip().expect("held tip"),
        "peer() names the held tip the statement was verified against"
    );
    let _anchor = &peer.anchor;

    let over_noise = first
        .exchange(&Request::get("/server"))
        .await
        .expect("a request through the authenticated session");
    let (_, over_http) = get_json(app.clone(), "/server").await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&over_noise).expect("json body"),
        over_http,
        "the transport returns the HTTP body"
    );

    let second = NoiseConnector::connect(addr, &mut held, &signer, &own_principal)
        .await
        .expect("a second session");
    assert_ne!(
        first.channel_binding().map(ChannelBinding::as_bytes),
        second.channel_binding().map(ChannelBinding::as_bytes),
        "a handshake hash is unique to one session"
    );
}

/// Claim: the server verifies the initiator statement against the
/// principal's chain and never serves a session whose initiator did not
/// prove a key that chain holds. Here the client names the pushed principal
/// but signs with a key the chain does not hold.
///
/// A control session with the principal's real key must succeed first, so a
/// transport that refuses everything cannot pass.
///
/// Turns red if: the control session fails, or the server accepts an
/// initiator statement by a key outside the named principal's chain (the
/// request would return a body). End-to-end scenario: yes.
#[tokio::test]
async fn initiator_key_outside_the_principal_chain_is_refused() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    let control = NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("the principal's own key opens a session");
    control
        .exchange(&Request::get("/server"))
        .await
        .expect("the control session is served");

    let stranger = coz::Alg::Ed25519.generate_keypair();
    let tmb = stranger
        .alg
        .compute_thumbprint(&stranger.pub_bytes)
        .expect("tmb");
    let signer = SoftwareSigner::new(
        stranger.alg.name(),
        &stranger.prv_bytes,
        &stranger.pub_bytes,
        &tmb,
    );

    // The server may refuse before or after the client's connect returns;
    // either way no response body may come back.
    let outcome = match NoiseConnector::connect(addr, &mut held, &signer, &own_principal).await {
        Err(_) => Err(()),
        Ok(conn) => conn
            .exchange(&Request::get("/server"))
            .await
            .map_err(|_| ()),
    };
    assert!(outcome.is_err(), "a stranger key must not get a session");
}

/// Claim: the server verifies the initiator's SIGNATURE, not just that the
/// key it names is in the chain. A client that claims the principal's real
/// thumbprint but signs with a key of its own is refused.
///
/// The control with the real key must be served first, so a transport that
/// refuses everything cannot pass.
///
/// Turns red if: the claimed thumbprint alone, without a verifying
/// signature, opens a session. End-to-end scenario: yes.
#[tokio::test]
async fn initiator_claiming_a_chain_key_without_its_signature_is_refused() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("the principal's own key opens a session")
        .exchange(&Request::get("/server"))
        .await
        .expect("the control session is served");

    let pool = load_pool();
    let golden = pool.get("golden").expect("golden in pool");
    let thief = coz::Alg::Ed25519.generate_keypair();
    let forged = SoftwareSigner::new(
        thief.alg.name(),
        &thief.prv_bytes,
        &thief.pub_bytes,
        &golden.compute_tmb().expect("golden tmb"),
    );
    let outcome = match NoiseConnector::connect(addr, &mut held, &forged, &own_principal).await {
        Err(_) => Err(()),
        Ok(conn) => conn
            .exchange(&Request::get("/server"))
            .await
            .map_err(|_| ()),
    };
    assert!(
        outcome.is_err(),
        "a claimed key without its signature must not get a session"
    );
}

/// Claim: the server refuses an initiator key its chain has revoked, even
/// though the key is still present in the chain and its signature verifies.
/// `key_a` is pushed with the principal, then self-revokes in a second
/// commit; the principal's other key, `golden`, stays active.
///
/// The control with `golden` must be served first, so a transport that
/// refuses everything cannot pass.
///
/// Turns red if: a revoked key's valid signature opens a session.
/// End-to-end scenario: yes (push, revoke commit, handshake).
#[tokio::test]
async fn initiator_key_revoked_in_the_chain_is_refused() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;

    let genesis = state
        .engine
        .resolve_genesis(&own_principal, &[])
        .await
        .expect("resolve genesis");
    let principal = state
        .engine
        .load_principal(&own_principal, genesis)
        .await
        .expect("load the pushed principal");
    let blobs = self_revoke_commit_blobs(principal, "key_a", 1_700_000_100).await;
    let slices: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    state
        .engine
        .submit_commit(&own_principal, None, &slices)
        .await
        .expect("submit the revoke commit");

    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("the active key opens a session")
        .exchange(&Request::get("/server"))
        .await
        .expect("the control session is served");

    let outcome =
        match NoiseConnector::connect(addr, &mut held, &pool_signer("key_a"), &own_principal).await
        {
            Err(_) => Err(()),
            Ok(conn) => conn
                .exchange(&Request::get("/server"))
                .await
                .map_err(|_| ()),
        };
    assert!(outcome.is_err(), "a revoked key must not get a session");
}

/// Claim: a responder statement signed by a key the client's held chain no
/// longer holds active is refused, typed. The server's signing key is
/// rotated and its stale backend keeps signing statements with the retired
/// key; the client, holding the post-rotation chain, refuses.
///
/// Turns red if: the client accepts a retired key's statement (lookup among
/// every key the chain ever held) or reports another failure.
/// End-to-end scenario: yes (rotation, pin, follow, handshake).
#[tokio::test]
async fn responder_signing_with_a_retired_key_is_refused() {
    let (state, retired, _dir) = attestor_server().await;
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("sole owner of the state"));
    state
        .rotate_signing_key(&coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("rotate the signing key");
    let state = Arc::new(state.with_receipt_signer(retired));
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    let refused = NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .err()
        .expect("a retired key's statement must not open a session");
    assert!(
        matches!(refused, TransportError::KeyNotActive { .. }),
        "typed refusal expected: {refused:?}"
    );
}

/// Claim: every format a client reads back carries a checked version, over
/// the transport too (N13). A peer serving envelope `v=99` inside an
/// authenticated Noise session makes the client fail closed with the typed
/// `UnsupportedVersion`, handing back nothing to apply.
///
/// Turns red if: the transport decodes a `v=99` envelope as if it were v1,
/// or flattens the refusal to a message or another variant.
/// End-to-end scenario: yes (a hostile peer, over a real authenticated
/// session).
#[tokio::test]
async fn version_unknown_envelope_over_the_transport_fails_closed() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, pg, _) = pinned_and_followed(&app).await;

    let hostile = Router::new().fallback(|| async {
        axum::Json(serde_json::json!({
            "v": 99,
            "payload": { "entries": [] },
            "statement": { "kind": "unsigned" },
        }))
    });
    let (listener, addr) = listen().await;
    tokio::spawn(async move {
        _ = serve_noise_with(listener, state, hostile).await;
    });

    let conn = NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("the session itself authenticates");
    let refused = fetch_patch(
        &conn,
        &PatchRequest {
            principal_id: &pg,
            anchor: None,
        },
        BindingPolicy::Required(BindingKind::NoiseHandshakeHash),
        None,
    )
    .await
    .expect_err("a v=99 envelope must be refused");
    assert!(
        matches!(refused, PatchFailure::UnsupportedVersion { found: 99, .. }),
        "typed UnsupportedVersion expected: {refused:?}"
    );
}

/// Claim: a keyless server refuses to start the transport listener, typed,
/// and keeps serving HTTP. It holds no Cyphr key to prove itself with, and
/// the transport authenticates the server as a principal.
///
/// Turns red if: the listener starts on a keyless state, or the refusal is
/// anything but `ServeError::Keyless`, or the refusal costs the HTTP
/// router. End-to-end scenario: no. A scenario over the process (next
/// test) covers the `serve` wiring; this one pins the typed error, which a
/// process cannot show.
#[tokio::test]
async fn keyless_server_refuses_the_transport_listener() {
    let (state, _dir) = keyless_server();
    let (listener, _) = listen().await;
    let refused = serve_noise(listener, state.clone())
        .await
        .expect_err("a keyless state must not serve the transport");
    assert!(matches!(refused, ServeError::Keyless), "{refused:?}");

    let (status, _) = get_json(build_router(state), "/server").await;
    assert_eq!(status, StatusCode::OK, "HTTP keeps serving");
}

/// Claim: the `serve` entry point wires the transport the same way: a
/// keyed process with `transport_listen` set announces the listener and
/// authenticates a client over it; the same process, keyless, announces no
/// listener and keeps answering HTTP.
///
/// The keyed run is the positive control, so a server that never starts
/// the transport cannot pass the keyless run vacuously.
///
/// Turns red if: the keyed process does not serve the transport, the
/// keyless process starts one, or either stops serving HTTP. End-to-end
/// scenario: yes (the shipped binary over loopback).
#[tokio::test(flavor = "multi_thread")]
async fn serve_starts_the_transport_only_for_a_keyed_server() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    struct Proc {
        child: std::process::Child,
        http: SocketAddr,
        transport: Option<SocketAddr>,
        _dir: tempfile::TempDir,
    }
    impl Drop for Proc {
        fn drop(&mut self) {
            _ = self.child.kill();
            _ = self.child.wait();
        }
    }

    fn start(keyed: bool) -> Proc {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cyphr-server"));
        cmd.args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--transport-listen",
            "127.0.0.1:0",
        ])
        .arg("--data-dir")
        .arg(dir.path().join("data"));
        if keyed {
            cmd.arg("--signing-key-path")
                .arg(common::write_signing_key(dir.path()));
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cyphr-server");
        let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
        let mut addr_after = |prefix: &str| {
            let line = lines.next()?.ok()?;
            line.strip_prefix(prefix)?.trim().parse::<SocketAddr>().ok()
        };
        let http = addr_after("listening on ").expect("the HTTP address line");
        // The transport line follows the HTTP line when there is one; a
        // keyless process prints nothing more, so wait a grace period.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(lines.next().and_then(Result::ok)).ok();
        });
        let transport = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .ok()
            .flatten()
            .and_then(|l| {
                l.strip_prefix("transport listening on ")?
                    .trim()
                    .parse()
                    .ok()
            });
        Proc {
            child,
            http,
            transport,
            _dir: dir,
        }
    }

    let keyed = start(true);
    let transport = keyed
        .transport
        .expect("a keyed server announces the transport");
    let http = reqwest::Client::new();
    let discovery: serde_json::Value = http
        .get(format!("http://{}/server", keyed.http))
        .send()
        .await
        .expect("GET /server")
        .json()
        .await
        .expect("json");
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let genesis = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let mut held = PeerChain::pin(d["pg"].as_str().expect("pg"), genesis).await;
    let pool = load_pool();
    let pr = golden_principal_id(&pool).await;
    let pushed = http
        .post(format!("http://{}/push", keyed.http))
        .header("content-type", "application/json")
        .body(build_genesis_push_body(&pool, &pr, 1_700_000_000).await)
        .send()
        .await
        .expect("push the client principal");
    assert_eq!(pushed.status(), StatusCode::CREATED);
    // The server never acknowledges the initiator statement, so a served
    // request is what shows both ends authenticated.
    let conn = NoiseConnector::connect(transport, &mut held, &golden_signer(), &pr)
        .await
        .expect("the responder statement verifies");
    conn.exchange(&Request::get("/server"))
        .await
        .expect("the keyed process serves the authenticated client");

    let keyless = start(false);
    assert_eq!(
        keyless.transport, None,
        "a keyless server starts no transport"
    );
    let status = http
        .get(format!("http://{}/server", keyless.http))
        .send()
        .await
        .expect("keyless HTTP")
        .status();
    assert!(status.is_success(), "a keyless server keeps serving HTTP");
}

// ---- Level 1 initiators, the responder ack, naked revoke ----------------

/// A hand-rolled initiator, so a test controls exactly what the statement
/// claims and what sidecar it carries. The responder's own statement is
/// read and not judged: these tests are about the server's verdict.
struct Claim<'a> {
    /// The key that signs.
    signer: &'a coz::KeyPair,
    /// The thumbprint and principal the pay claims.
    tmb: &'a coz::Thumbprint,
    pr: &'a str,
    /// The `key` sidecar: algorithm, public key, claimed thumbprint.
    sidecar: Option<(&'a str, &'a [u8], &'a coz::Thumbprint)>,
}

async fn initiate_with(addr: SocketAddr, claim: Claim<'_>) -> Result<(), TransportError> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let mut channel = Channel::initiate(stream).await?;
    let h = channel.handshake_hash().to_vec();
    channel.recv_one().await?;
    let alg = claim.signer.alg.name();
    let pay = statement_pay(alg, claim.tmb, claim.pr, Role::Initiator, &h, 1_700_000_000)?;
    let (sig, _) =
        coz::sign_json(&pay, alg, &claim.signer.prv_bytes, &claim.signer.pub_bytes).expect("sign");
    channel
        .send_one(&assemble_statement(&pay, &sig, claim.sidecar)?)
        .await?;
    decode_ack(&channel.recv_one().await?)
}

fn fresh_key() -> (coz::KeyPair, coz::Thumbprint) {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    (kp, tmb)
}

fn refused(outcome: Result<(), TransportError>, why: &str) {
    assert!(
        matches!(outcome, Err(TransportError::Refused { .. })),
        "{why}: expected a typed refusal at the ack, got {outcome:?}"
    );
}

/// Claim: a Level 1 principal (no stored chain; its id is its key's
/// thumbprint) authenticates with a self-certifying key sidecar. A
/// connector with a fresh key, nothing pushed, opens a served session; and
/// the three ways to forge that claim are each refused with a reason: a
/// sidecar whose thumbprint is not its key's, a sidecar that is not the key
/// the statement names, and a thumbprint that is not the claimed principal.
///
/// Turns red if: an unstored principal is refused with an honest sidecar,
/// or any forged claim is accepted. End-to-end scenario: yes.
#[tokio::test]
async fn level_one_initiator_authenticates_by_its_sidecar_and_forgeries_are_refused() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    // Positive: through the shipped connector, which always sends the sidecar.
    let (kp, tmb) = fresh_key();
    let signer = SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb);
    let conn = NoiseConnector::connect(addr, &mut held, &signer, &tmb.to_b64())
        .await
        .expect("a Level 1 principal authenticates by its sidecar");
    conn.exchange(&Request::get("/server"))
        .await
        .expect("the Level 1 session is served");

    // The honest claim by hand is accepted, so each forgery below differs
    // from it in exactly one respect.
    let honest = Claim {
        signer: &kp,
        tmb: &tmb,
        pr: &tmb.to_b64(),
        sidecar: Some((kp.alg.name(), &kp.pub_bytes, &tmb)),
    };
    initiate_with(addr, honest)
        .await
        .expect("the control claim");

    // The sidecar's thumbprint is not the thumbprint of its key. Statement,
    // sidecar and principal all agree on the false thumbprint.
    let false_tmb = coz::Thumbprint::from_bytes(vec![9; 32]);
    let lying = Claim {
        signer: &kp,
        tmb: &false_tmb,
        pr: &false_tmb.to_b64(),
        sidecar: Some((kp.alg.name(), &kp.pub_bytes, &false_tmb)),
    };
    refused(
        initiate_with(addr, lying).await,
        "a thumbprint that is not the key's",
    );

    // The statement is honest but the sidecar declares a thumbprint that is
    // not its key's: the sidecar is refused on its own, not just because it
    // disagrees with the statement.
    let mislabelled = Claim {
        signer: &kp,
        tmb: &tmb,
        pr: &tmb.to_b64(),
        sidecar: Some((kp.alg.name(), &kp.pub_bytes, &false_tmb)),
    };
    refused(
        initiate_with(addr, mislabelled).await,
        "a sidecar mislabelled with another thumbprint",
    );

    // The sidecar is another key's: its own thumbprint is honest, but the
    // statement names a different one.
    let (other, other_tmb) = fresh_key();
    let swapped = Claim {
        signer: &kp,
        tmb: &tmb,
        pr: &tmb.to_b64(),
        sidecar: Some((other.alg.name(), &other.pub_bytes, &other_tmb)),
    };
    refused(
        initiate_with(addr, swapped).await,
        "a sidecar that is not the statement's key",
    );

    // Honest key and sidecar, but the claimed principal is not its
    // thumbprint: a Level 1 key may only speak for itself.
    let borrowed = Claim {
        signer: &kp,
        tmb: &tmb,
        pr: &other_tmb.to_b64(),
        sidecar: Some((kp.alg.name(), &kp.pub_bytes, &tmb)),
    };
    refused(
        initiate_with(addr, borrowed).await,
        "a principal that is not the key's thumbprint",
    );

    // No sidecar and no stored chain: nothing to verify against.
    let bare = Claim {
        signer: &kp,
        tmb: &tmb,
        pr: &tmb.to_b64(),
        sidecar: None,
    };
    refused(initiate_with(addr, bare).await, "no chain and no sidecar");
}

/// Claim: the responder tells the initiator its verdict, so a refused
/// initiator fails at `connect` with the reason, not on its first request.
///
/// Turns red if: `connect` returns Ok for a session the server refused, or
/// the refusal arrives untyped. End-to-end scenario: yes.
#[tokio::test]
async fn a_refused_initiator_fails_at_connect_with_its_reason() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    let (kp, tmb) = fresh_key();
    let stranger = SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb);
    let err = NoiseConnector::connect(addr, &mut held, &stranger, &own_principal)
        .await
        .err()
        .expect("a stranger key must fail at connect");
    assert!(
        matches!(&err, TransportError::Refused { reason } if !reason.is_empty()),
        "{err:?}"
    );
}

/// Claim: an initiator whose key was naked-revoked (SPEC 6.4, invisible to
/// the chain) is refused, while the principal's other key still opens a
/// session. `key_a` works first, so the refusal is the revoke's doing.
///
/// Turns red if: the death set is not consulted for the initiator key.
/// End-to-end scenario: yes (push, naked revoke over HTTP, handshake).
#[tokio::test]
async fn a_naked_revoked_initiator_key_is_refused() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    NoiseConnector::connect(addr, &mut held, &pool_signer("key_a"), &own_principal)
        .await
        .expect("key_a opens a session before the revoke");

    let pool = load_pool();
    let key_a = pool.get("key_a").expect("key_a");
    let prv = Base64UrlUnpadded::decode_vec(key_a.prv.as_ref().expect("prv")).expect("prv");
    let pub_key = Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("pub");
    let pay = serde_json::json!({
        "alg": key_a.alg,
        "now": 1_700_000_000,
        "rvk": 1_700_000_000,
        "tmb": key_a.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let (sig, _) = coz::sign_json(
        &serde_json::to_vec(&pay).expect("pay"),
        &key_a.alg,
        &prv,
        &pub_key,
    )
    .expect("sign");
    let body = serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": { "alg": key_a.alg, "pub": key_a.pub_key },
    });
    let (status, resp) = post_json(app.clone(), "/revoke", body.to_string()).await;
    assert!(
        status.is_success(),
        "naked revoke accepted: {status} {resp:?}"
    );

    let err = NoiseConnector::connect(addr, &mut held, &pool_signer("key_a"), &own_principal)
        .await
        .err()
        .expect("a naked-revoked key must be refused");
    assert!(matches!(err, TransportError::Refused { .. }), "{err:?}");
    NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("the principal's other key still opens a session");
}

/// A naked revoke (SPEC 6.4) of `kp`'s key, self-signed, disclosing `disclosed`.
fn naked_revoke_body(kp: &coz::KeyPair, tmb: &coz::Thumbprint, disclosed: &coz::KeyPair) -> String {
    let pay = serde_json::json!({
        "alg": kp.alg.name(),
        "now": 1_700_000_000,
        "rvk": 1_700_000_000,
        "tmb": tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let (sig, _) = coz::sign_json(
        &serde_json::to_vec(&pay).expect("pay"),
        kp.alg.name(),
        &kp.prv_bytes,
        &kp.pub_bytes,
    )
    .expect("sign");
    serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {
            "alg": disclosed.alg.name(),
            "pub": Base64UrlUnpadded::encode_string(&disclosed.pub_bytes),
        },
    })
    .to_string()
}

/// Claim (SPEC 3.1 "Self-revoke results in permanent lockout", 6.4: a naked
/// revoke is a self-signed declaration made outside any commit): the key of
/// a Level 1 principal that never pushed anything, so no peer has seen it,
/// can still be naked-revoked: the server records the revoke, and the key
/// is then refused when it opens a session as its own principal. A revoke
/// whose disclosed key does not thumbprint to the `tmb` it names is
/// refused and kills nothing.
///
/// Turns red if: the revoke route requires the key to be known to the
/// server (a presence fence), so a never-pushed key cannot be revoked; or
/// a revoke binding a key to another key's thumbprint is accepted.
/// End-to-end scenario: yes (Level 1 handshake, naked revoke over HTTP,
/// handshake refused).
#[tokio::test]
async fn a_never_pushed_level_one_key_can_be_naked_revoked() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    let (kp, tmb) = fresh_key();
    let signer = SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb);
    NoiseConnector::connect(addr, &mut held, &signer, &tmb.to_b64())
        .await
        .expect("control: the Level 1 key opens a session before the revoke");

    // A forgery: the revoke names the victim's thumbprint but discloses
    // another key. It is refused and the victim stays alive.
    let (other, _) = fresh_key();
    let (status, resp) =
        post_json(app.clone(), "/revoke", naked_revoke_body(&kp, &tmb, &other)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a disclosed key that does not thumbprint to tmb: {resp:?}"
    );
    NoiseConnector::connect(addr, &mut held, &signer, &tmb.to_b64())
        .await
        .expect("the refused forgery revoked nothing");

    let (status, resp) = post_json(app.clone(), "/revoke", naked_revoke_body(&kp, &tmb, &kp)).await;
    assert!(
        status.is_success(),
        "a never-pushed key's own revoke is accepted: {status} {resp:?}"
    );
    let err = NoiseConnector::connect(addr, &mut held, &signer, &tmb.to_b64())
        .await
        .err()
        .expect("the naked-revoked Level 1 key is locked out");
    assert!(
        matches!(&err, TransportError::Refused { reason } if reason.contains("revoked")),
        "{err:?}"
    );
}

// ---- the transport carries the HTTP fences -------------------------------

/// A keyed, bootstrapped server whose configuration `tweak` adjusts before
/// the principal is established.
async fn attestor_with(
    tweak: impl FnOnce(&mut cyphr_server::config::ServerConfig),
) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = common::write_signing_key(dir.path());
    let mut state = common::keyed_appstate(&dir.path().join("data"), &key_path);
    tweak(&mut state.config);
    let identity = state.identity.clone().expect("keyed state has identity");
    let principal = cyphr_server::auth::principal::ServerPrincipal::bootstrap(
        &state.engine,
        identity,
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(principal));
    (Arc::new(state), dir)
}

/// A Level 1 session: a fresh key is its own principal, so it needs no
/// registration and costs nothing to mint.
async fn level_one_session(addr: SocketAddr, held: &mut PeerChain) -> NoiseConnector {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    let signer = SoftwareSigner::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes, &tmb);
    NoiseConnector::connect(addr, held, &signer, &tmb.to_b64())
        .await
        .expect("a Level 1 session")
}

/// Claim: the transport serves the same fenced router HTTP does, so it
/// cannot be used to get around a limit. With `max_body_bytes = 64`, a 4 KiB
/// push is refused `413` over the transport, exactly as over HTTP, and the
/// session stays usable.
///
/// Turns red if: `serve_noise` dispatches to a router without the body
/// limit (the push then reaches its handler and answers 400, 401 or 422).
/// End-to-end scenario: yes.
#[tokio::test]
async fn the_transport_carries_the_body_limit() {
    let (state, _dir) = attestor_with(|c| c.limits.max_body_bytes = 64).await;
    let app = build_router(state.clone());
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;
    let conn = level_one_session(addr, &mut held).await;

    let big = Request::post("/push", vec![b'x'; 4096]);
    let refused = conn.exchange(&big).await;
    assert!(
        matches!(refused, Err(ConnectError::NonSuccess(413))),
        "{refused:?}"
    );
    conn.exchange(&Request::get("/server"))
        .await
        .expect("the session survives a refused request");
}

// ---- bounds on what a peer that costs nothing can hold --------------------
//
// A Level 1 key is its own principal, so any peer authenticates for free:
// the transport must bound what an unauthenticated or throwaway peer can
// hold. Source addresses on 127.0.0.0/8 stand in for distinct clients.

/// Connect to `addr` from the loopback address `from`.
async fn try_connect_from(from: &str, addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(from.parse().expect("ip"), 0))?;
    socket.connect(addr).await
}

async fn connect_from(from: &str, addr: SocketAddr) -> tokio::net::TcpStream {
    try_connect_from(from, addr).await.expect("connect")
}

/// Whether the server has closed `sock`: a read says end of file or an
/// error, where an open silent socket would say it would block.
fn closed_by_peer(sock: &tokio::net::TcpStream) -> bool {
    !matches!(sock.try_read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

/// Claim: one address cannot hold the transport. 300 silent connections
/// from one address leave an honest client from another address served
/// within seconds, and all but a small per-address allowance of the
/// attacker's connections are closed by the server.
///
/// Turns red if: the session slots are a shared pool one address can fill
/// (the honest connect then times out), or one address may hold more than
/// its allowance. End-to-end scenario: yes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_cannot_hold_every_session_slot() {
    let (state, _dir) = attestor_with(|_| {}).await;
    let app = build_router(state.clone());
    let (mut held, ..) = pinned_and_followed(&app).await;
    let addr = start_noise(state).await;

    let mut attacker = Vec::new();
    for _ in 0..300 {
        attacker.push(connect_from("127.0.0.2", addr).await);
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let honest = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        level_one_session(addr, &mut held),
    )
    .await
    .expect("an honest client must connect while one address floods");
    honest
        .exchange(&Request::get("/server"))
        .await
        .expect("and be served");

    let open = attacker.iter().filter(|s| !closed_by_peer(s)).count();
    assert!(
        open <= 16,
        "{open} of the attacker's connections stayed open"
    );
}

/// Claim: the whole pre-authentication exchange shares one deadline. A
/// client that delays its handshake and then stalls its statement is cut off
/// about 10 s after it connected, not 10 s per step.
///
/// Turns red if: each step restarts the clock (the client is held for the
/// sum, near 18 s here). End-to-end scenario: yes.
#[tokio::test]
async fn the_pre_auth_exchange_shares_one_deadline() {
    let (state, _dir) = attestor_with(|_| {}).await;
    let addr = start_noise(state).await;

    let started = std::time::Instant::now();
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    let mut channel = Channel::initiate(stream).await.expect("a late handshake");
    channel.recv_one().await.expect("the responder statement");
    // Stalled: the initiator statement never comes.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(20), channel.recv_one())
        .await
        .expect("the server must give up");
    assert!(
        closed.is_err(),
        "the server sent something to a stalled client"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(13),
        "held for {:?}",
        started.elapsed()
    );
}

/// An authenticated Level 1 session driven by hand, so a test controls
/// every byte after the ack.
async fn raw_session(addr: SocketAddr) -> Channel<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    raw_session_over(stream).await
}

async fn raw_session_over<S>(stream: S) -> Channel<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (kp, tmb) = fresh_key();
    let mut channel = Channel::initiate(stream).await.expect("handshake");
    let h = channel.handshake_hash().to_vec();
    channel.recv_one().await.expect("the responder statement");
    let alg = kp.alg.name();
    let pay =
        statement_pay(alg, &tmb, &tmb.to_b64(), Role::Initiator, &h, 1_700_000_000).expect("pay");
    let (sig, _) = coz::sign_json(&pay, alg, &kp.prv_bytes, &kp.pub_bytes).expect("sign");
    let sidecar = Some((alg, kp.pub_bytes.as_slice(), &tmb));
    channel
        .send_one(&assemble_statement(&pay, &sig, sidecar).expect("statement"))
        .await
        .expect("send");
    decode_ack(&channel.recv_one().await.expect("ack")).expect("accepted");
    channel
}

/// Claim: a message is refused by its declared length, before it is
/// buffered. A session that announces a 16 MiB message (the router's body
/// limit is 2 MiB) and sends only its first chunk is closed within seconds.
///
/// Turns red if: the server waits for the rest (up to the idle timeout)
/// while holding what it has read. End-to-end scenario: yes.
#[tokio::test]
async fn an_oversize_message_is_refused_by_its_declared_length() {
    let (state, _dir) = attestor_with(|_| {}).await;
    let addr = start_noise(state).await;
    let mut channel = raw_session(addr).await;

    let mut first = (16u32 * 1024 * 1024).to_be_bytes().to_vec();
    first.extend(vec![0u8; 65519 - 4]);
    channel.send_one(&first).await.expect("the first chunk");
    let closed = tokio::time::timeout(std::time::Duration::from_secs(3), channel.recv_one())
        .await
        .expect("the server must close, not wait for the rest");
    assert!(closed.is_err(), "the server answered an oversize message");
}

/// Claim: a write that cannot complete is cut off. A client with a tiny
/// receive buffer asks for a 12 MiB response and never reads; after the
/// write deadline the server drops the session, so the client's later read
/// ends in an error, not in the whole response.
///
/// Turns red if: the server's write waits forever on a peer that does not
/// read (the late read then receives all 12 MiB). End-to-end scenario: yes.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_never_reads_is_cut_off() {
    let (state, _dir) = attestor_with(|_| {}).await;
    let huge = Router::new().fallback(|| async { vec![b'x'; 12 * 1024 * 1024] });
    let (listener, addr) = listen().await;
    tokio::spawn(async move {
        _ = serve_noise_with(listener, state, huge).await;
    });

    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).expect("socket");
    socket
        .set_recv_buffer_size(4096)
        .expect("small receive buffer");
    socket.connect(&addr.into()).expect("connect");
    socket.set_nonblocking(true).expect("nonblocking");
    let stream = tokio::net::TcpStream::from_std(socket.into()).expect("tokio stream");
    let mut channel = raw_session_over(stream).await;

    let request = cyphr_client::transport::encode_request(&Request::get("/")).expect("request");
    channel.send_message(&request).await.expect("ask");
    tokio::time::sleep(std::time::Duration::from_secs(14)).await;
    let late = channel
        .recv_message(cyphr_client::transport::MAX_MESSAGE)
        .await;
    assert!(
        late.is_err(),
        "the server waited out a peer that never read"
    );
}

/// Claim: the transport listener survives accept failures. With the
/// process limited to a few dozen file descriptors, connections from many
/// addresses exhaust them and `accept` fails; once the flood is gone the
/// listener still accepts and authenticates a client.
///
/// Turns red if: an accept error ends the listener (the honest connect is
/// then refused). End-to-end scenario: yes (the shipped binary, `ulimit`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_listener_survives_running_out_of_descriptors() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().expect("tempdir");
    let key = common::write_signing_key(dir.path());
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("ulimit -n 96; exec \"$0\" \"$@\"")
        .arg(env!("CARGO_BIN_EXE_cyphr-server"))
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--transport-listen",
            "127.0.0.1:0",
        ])
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .arg("--signing-key-path")
        .arg(&key)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cyphr-server");
    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            _ = self.0.kill();
            _ = self.0.wait();
        }
    }
    let stdout = child.stdout.take().expect("piped");
    let guard = Kill(child);
    let mut lines = BufReader::new(stdout).lines();
    let mut addr_of = |prefix: &str| -> SocketAddr {
        lines
            .next()
            .expect("a line")
            .expect("readable")
            .strip_prefix(prefix)
            .expect("the expected announcement")
            .trim()
            .parse()
            .expect("an address")
    };
    let http_addr = addr_of("listening on ");
    let transport = addr_of("transport listening on ");

    // 40 addresses x 3 connections, each under the per-address allowance.
    let mut flood = Vec::new();
    for host in 10..50 {
        for _ in 0..3 {
            // Once the server is out of descriptors a connect may stall or
            // fail; either is the point of the flood.
            if let Ok(Ok(s)) = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                try_connect_from(&format!("127.0.0.{host}"), transport),
            )
            .await
            {
                flood.push(s);
            }
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    drop(flood);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let http = reqwest::Client::new();
    let discovery: serde_json::Value = http
        .get(format!("http://{http_addr}/server"))
        .send()
        .await
        .expect("GET /server")
        .json()
        .await
        .expect("json");
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let genesis = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let mut held = PeerChain::pin(d["pg"].as_str().expect("pg"), genesis).await;
    level_one_session(transport, &mut held).await;
    drop(guard);
}

// ---- identity reaches routes ---------------------------------------------

/// Claim: a route can see who the transport authenticated. Every request
/// routed over the transport carries an `AuthenticatedPeer` extension naming
/// the initiator's principal, its signing key and the session's handshake
/// hash; the same router reached over HTTP sees none.
///
/// Turns red if: the extension is missing over the transport, names another
/// principal, key or session, or is present on an HTTP request.
/// End-to-end scenario: yes (probe route, real session, real HTTP request).
#[tokio::test]
async fn routes_see_the_authenticated_peer_only_over_the_transport() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state.clone());
    let own_principal = push_client_principal(&app).await;
    let (mut held, ..) = pinned_and_followed(&app).await;

    let probe = Router::new().fallback(|request: axum::extract::Request| async move {
        match request.extensions().get::<AuthenticatedPeer>() {
            Some(peer) => axum::Json(serde_json::json!({
                "present": true,
                "pg": peer.pg,
                "tmb": peer.tmb.to_b64(),
                "h": Base64UrlUnpadded::encode_string(&peer.handshake_hash),
            })),
            None => axum::Json(serde_json::json!({ "present": false })),
        }
    });
    let (listener, addr) = listen().await;
    let served = state.clone();
    let carried = probe.clone();
    tokio::spawn(async move {
        _ = serve_noise_with(listener, served, carried).await;
    });

    let conn = NoiseConnector::connect(addr, &mut held, &golden_signer(), &own_principal)
        .await
        .expect("an authenticated session");
    let over_noise: serde_json::Value = serde_json::from_slice(
        &conn
            .exchange(&Request::get("/probe"))
            .await
            .expect("served"),
    )
    .expect("json");
    let binding = conn.channel_binding().expect("a binding");
    assert_eq!(over_noise["present"], true, "{over_noise}");
    // The peer is named in its default wire spelling, the bare digest
    // (SPEC 2.2.3); the pushed id is the engine's labelled PG.
    assert_eq!(
        over_noise["pg"],
        cyphr_storage::engine::bare_digest(&own_principal)
    );
    assert_eq!(
        over_noise["tmb"],
        golden_signer().tmb().to_b64(),
        "the signing key"
    );
    assert_eq!(
        over_noise["h"],
        Base64UrlUnpadded::encode_string(binding.as_bytes()),
        "this session's handshake hash"
    );

    let (_, over_http) = get_json(probe, "/probe").await;
    assert_eq!(over_http["present"], false, "{over_http}");
}
