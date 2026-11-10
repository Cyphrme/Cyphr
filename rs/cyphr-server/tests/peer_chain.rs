//! End-to-end peer-chain following against a real server: a client pins the
//! server's PG and genesis key from `/server`, follows `/patch`, verifies
//! signed `/tip` and `/view` against the keys active in that chain, and
//! follows once when the server rotates its signing key.
//!
//! Rotation goes through `AppState::rotate_signing_key`; no key
//! storage is involved.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{ChannelBinding, ConnectError, Connector, PeerChain, PeerFailure, Request};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::{AppState, build_router};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{
    build_genesis_push_body, build_second_commit_push_body, get_json, golden_principal_id,
    keyed_appstate, load_pool, post_json, write_signing_key,
};

/// The carrier over the in-process router, counting `/patch` fetches.
struct RouterConnector {
    app: Router,
    patches: AtomicUsize,
}

impl RouterConnector {
    fn new(app: Router) -> Self {
        Self {
            app,
            patches: AtomicUsize::new(0),
        }
    }

    fn patches(&self) -> usize {
        self.patches.load(Ordering::SeqCst)
    }
}

impl Connector for RouterConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        if request.target.starts_with("/patch") {
            self.patches.fetch_add(1, Ordering::SeqCst);
        }
        let req = axum::http::Request::builder()
            .uri(&request.target)
            .body(axum::body::Body::empty())
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
        // The router's error type is `Infallible`: no failure to map.
        let Ok(resp) = self.app.clone().oneshot(req).await;
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

/// Push bodies for two successive commits of the standard principal: its
/// genesis commit (`golden` creates itself and `key_a`, SPEC 5.1), then a
/// `key/create` of `key_b` signed by `golden` on that genesis state.
async fn two_commit_bodies(pool: &test_fixtures::Pool, pr: &str) -> (String, String) {
    let genesis_now = 1_700_000_000;
    let first = build_genesis_push_body(pool, pr, genesis_now).await;
    let second = build_second_commit_push_body(pool, pr, genesis_now, 1_700_000_100).await;
    (first, second)
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

/// A bootstrapped attestor that has pushed `golden`'s commits, not yet
/// routed: the caller builds routers so it can rotate between them.
async fn attestor_state() -> (
    Arc<AppState>,
    Arc<ServerIdentity>,
    tempfile::TempDir,
    String,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");
    let sp = ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(sp));
    let pool = load_pool();
    let pr = golden_principal_id(&pool).await;
    (Arc::new(state), identity, dir, pr)
}

async fn push_golden(app: &Router, pr: &str) {
    let pool = load_pool();
    let (first, second) = two_commit_bodies(&pool, pr).await;
    for body in [first, second] {
        let (status, resp) = post_json(app.clone(), "/push", body).await;
        assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    }
}

/// The digest bytes of a principal id, which may carry an algorithm label
/// (`SHA-256:<b64ut>`, as the PG does) or be a bare digest.
fn pr_thumbprint(pr: &str) -> coz::Thumbprint {
    let digest = pr.rsplit_once(':').map_or(pr, |(_, d)| d);
    coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(digest).expect("pr b64"))
}

/// Claim: a client pins the server by PG and genesis key from `/server`,
/// follows its chain, and verifies a signed `/tip`; when the server rotates
/// its signing key, a tip signed by the NEW key is refused by the stale
/// held chain, accepted by `verify_tip_following` after following exactly
/// once, and accepted by plain `verify_tip` thereafter.
///
/// Turns red if: the pin or follow fails against a real `/patch`; a tip by
/// an unheld key is accepted without following; following fetches more
/// than once; or the followed chain does not carry the rotated-in key.
/// End-to-end scenario: yes (pin, follow, rotation, re-follow).
#[tokio::test]
async fn client_follows_the_server_chain_across_a_key_rotation() {
    let (state, _identity, _dir, pr) = attestor_state().await;
    let app = build_router(state.clone());
    push_golden(&app, &pr).await;

    let (pg, genesis_key) = discover(&app).await;
    let mut held = PeerChain::pin(&pg, genesis_key).await;
    held.follow(&RouterConnector::new(app.clone()))
        .await
        .expect("follow the server chain");
    let (status, tip) = get_json(app.clone(), &format!("/tip?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");
    let report = held
        .verify_tip(&tip, &pr)
        .expect("a tip signed by the genesis key verifies");
    assert_eq!(report.sequence, 1);

    // Rotate: the router holds an Arc of the state, so drop it first.
    drop(app);
    let mut state = Arc::try_unwrap(state)
        .unwrap_or_else(|_| panic!("no router or connector may outlive the pre-rotation phase"));
    state
        .rotate_signing_key(&coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("rotate the signing key");
    let app = build_router(Arc::new(state));

    let (status, tip) = get_json(app.clone(), &format!("/tip?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");
    assert!(
        matches!(
            held.verify_tip(&tip, &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "the stale held chain does not know the rotated-in key"
    );

    let carrier = RouterConnector::new(app);
    held.verify_tip_following(&carrier, &tip, &pr)
        .await
        .expect("following once admits the rotated-in key");
    assert_eq!(carrier.patches(), 1, "follow once, not repeatedly");
    assert!(
        held.verify_tip(&tip, &pr).is_ok(),
        "the followed chain now holds the key"
    );
}

/// Claim: a statement signed by a key the server has rotated away from is
/// refused as `KeyNotActive` by a client holding the current chain, for a
/// tip and for a view, even after following, and never loops.
///
/// Turns red if: the retired key is accepted (lookup among every key the
/// chain ever held instead of the active ones); the refusal is another
/// failure; or the client fetches `/patch` more than once.
/// End-to-end scenario: yes (rotation, stale-backend signer, pin, follow).
#[tokio::test]
async fn statement_signed_by_the_retired_key_is_refused() {
    let (state, retired, _dir, pr) = attestor_state().await;
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("sole owner of the state"));
    state
        .rotate_signing_key(&coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("rotate the signing key");
    // The stale-backend seam: attestations keep signing with the old key.
    let state = state.with_receipt_signer(retired);
    let app = build_router(Arc::new(state));
    push_golden(&app, &pr).await;

    let (pg, genesis_key) = discover(&app).await;
    let mut held = PeerChain::pin(&pg, genesis_key).await;
    let carrier = RouterConnector::new(app.clone());

    let (_, tip) = get_json(app.clone(), &format!("/tip?pr={pr}")).await;
    assert_eq!(
        tip["statement"]["kind"],
        serde_json::json!("signed"),
        "{tip:?}"
    );
    let refused = held.verify_tip_following(&carrier, &tip, &pr).await;
    assert!(
        matches!(refused, Err(PeerFailure::KeyNotActive { .. })),
        "a retired key's tip must be refused: {refused:?}"
    );
    assert!(carrier.patches() <= 1, "at most one follow, no loop");

    let (status, view) = get_json(app, &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{view:?}");
    let coz: coz::CozJson =
        serde_json::from_value(view["statement"]["coz"].clone()).expect("view coz");
    let refused = held.verify_view(&coz, &pr_thumbprint(&pr));
    assert!(
        matches!(refused, Err(PeerFailure::KeyNotActive { .. })),
        "a retired key's view must be refused: {refused:?}"
    );
}

/// Claim: a pin whose PG is not the server's own (here, another principal's
/// id paired with the server's genuine genesis key) is refused as
/// `PinMismatch` when followed against the real server.
///
/// Turns red if: the pin is accepted and the client adopts a chain that its
/// genesis key does not root.
/// End-to-end scenario: yes (real discovery, real `/patch`).
#[tokio::test]
async fn pin_naming_another_server_pg_is_refused() {
    let (state, _identity, _dir, pr) = attestor_state().await;
    let app = build_router(state);
    push_golden(&app, &pr).await;

    let (pg, genesis_key) = discover(&app).await;
    assert_ne!(pg, pr, "the golden principal is not the server's own");
    let mut held = PeerChain::pin(&pr, genesis_key).await;
    let refused = held.follow(&RouterConnector::new(app)).await;
    assert!(
        matches!(refused, Err(PeerFailure::PinMismatch { .. })),
        "{refused:?}"
    );
}

/// Claim (snapshot trust): keys are judged against the held chain snapshot.
/// After the server rotates away from a key, a tip still signed by that key
/// is accepted until the caller follows, and refused as `KeyNotActive`
/// once it has. The caller owns re-follow policy; the verifier does not
/// guess.
///
/// Turns red if: `verify_tip` consults anything newer than the held chain
/// (accepting nothing stale), or `follow` does not carry the retirement
/// into the held chain.
/// End-to-end scenario: yes (pin, follow, rotation, stale signer, re-follow).
#[tokio::test]
async fn retired_key_is_accepted_until_the_caller_follows_again() {
    let (state, retired, _dir, pr) = attestor_state().await;
    let app = build_router(state.clone());
    push_golden(&app, &pr).await;
    let (pg, genesis_key) = discover(&app).await;
    let mut held = PeerChain::pin(&pg, genesis_key).await;
    held.follow(&RouterConnector::new(app.clone()))
        .await
        .expect("follow before the rotation");

    drop(app);
    let mut state = Arc::try_unwrap(state)
        .unwrap_or_else(|_| panic!("no router or connector may outlive the pre-rotation phase"));
    state
        .rotate_signing_key(&coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("rotate the signing key");
    // The stale-backend seam: attestations keep signing with the old key.
    let app = build_router(Arc::new(state.with_receipt_signer(retired)));
    let (status, tip) = get_json(app.clone(), &format!("/tip?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");

    assert!(
        held.verify_tip(&tip, &pr).is_ok(),
        "the snapshot still holds the retired key until the caller follows"
    );
    held.follow(&RouterConnector::new(app))
        .await
        .expect("follow after the rotation");
    assert!(
        matches!(
            held.verify_tip(&tip, &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "after following, the retired key is refused"
    );
}
