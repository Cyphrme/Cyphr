//! Principal-authenticated transport, server side (TR1 reds).
//!
//! The design under test: a Noise NN handshake with ephemeral keys only,
//! then each side signs the handshake hash with its Cyphr key in SIGMA-I
//! order (responder first). There is no non-Cyphr long-term key, and the
//! client's key here comes from the test through the `Signer` interface;
//! nothing stores a private key.
//!
//! Every test is an end-to-end scenario over a real TCP listener and a real
//! keyed server. The whole file is gated behind `cfg(red_tr1)` because it
//! names APIs the implementation does not have yet; under the cfg the
//! binary fails to compile on the base (its red), without it the binary is
//! empty and the workspace stays green.
//!
//! Run: `cd rs && RUSTFLAGS="--cfg red_tr1" cargo test -p cyphr-server \
//! --test transport`
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

#![allow(unexpected_cfgs)]
#![cfg(red_tr1)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr_client::transport::{NoiseConnector, TransportError};
use cyphr_client::{
    BindingKind, BindingPolicy, ChannelBinding, ConnectError, Connector, PatchFailure,
    PatchRequest, PeerChain, Request, fetch_patch,
};
use cyphr_server::transport::{serve_noise, serve_noise_with};
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, golden_principal_id, load_pool, post_json,
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
    let mut held = PeerChain::pin(&pg, genesis.clone());
    held.follow(&RouterConnector(app.clone()))
        .await
        .expect("follow the server chain");
    (held, pg, genesis)
}

/// Push the `golden` principal (the client's own principal) to the server.
async fn push_client_principal(app: &Router) -> String {
    let pool = load_pool();
    let pr = golden_principal_id(&pool);
    let body = build_genesis_push_body(&pool, &pr, 1_700_000_000);
    let (status, resp) = post_json(app.clone(), "/push", body).await;
    assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    pr
}

/// The test-supplied Level 1 client key: the pool's `golden` key behind the
/// `Signer` interface. No key is stored anywhere.
fn golden_signer() -> SoftwareSigner {
    let pool = load_pool();
    let golden = pool.get("golden").expect("golden in pool");
    SoftwareSigner::new(
        &golden.alg,
        &Base64UrlUnpadded::decode_vec(golden.prv.as_ref().expect("golden prv")).expect("prv b64"),
        &Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub b64"),
        &golden.compute_tmb().expect("golden tmb"),
    )
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
        matches!(
            refused,
            TransportError::Revoked { .. } | TransportError::KeyNotActive { .. }
        ),
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
    .err()
    .expect("a v=99 envelope must be refused");
    assert!(
        matches!(refused, PatchFailure::UnsupportedVersion { found: 99, .. }),
        "typed UnsupportedVersion expected: {refused:?}"
    );
}
