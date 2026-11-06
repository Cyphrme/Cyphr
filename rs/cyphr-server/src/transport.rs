//! The server end of the principal-authenticated Noise transport
//! (`cyphr_client::transport`): the responder, and the same router served
//! over it.
//!
//! A session authenticates both ends as Cyphr principals before a single
//! request is read. The server speaks first: its statement, signed over the
//! handshake hash through [`AppState::attestor_signer`] (the one accessor
//! every server signature goes through), proves it is the principal the
//! client pinned. The client answers only after verifying that, and its
//! statement is judged against the chain the server stores for the
//! principal it names, with the same gates a login passes: the key is
//! active in that chain, the principal is Active, and the key is not in
//! the naked-revoke death set. A session whose initiator fails any gate is
//! closed before it is served.
//!
//! The carrier adds no authority of its own: an authenticated session is
//! dispatched through the same router HTTP uses, so every route keeps its
//! own checks.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use cyphr_client::Method;
use cyphr_client::transport::{
    BindStatement, Channel, HANDSHAKE_TIMEOUT, MAX_MESSAGE, Role, TransportError,
    assemble_statement, decode_request, encode_ack, encode_response, statement_cad, statement_pay,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tower::ServiceExt;

use crate::{AppState, build_app_router};

/// Sessions served at once, across all addresses.
const MAX_SESSIONS: usize = 256;

/// Sessions one source address may hold at once. A Level 1 key is its own
/// principal, so a peer authenticates for free and the address is the only
/// scarce thing it has; without this one address could fill every slot.
const MAX_SESSIONS_PER_IP: usize = 16;

/// How long an authenticated session may sit without a request before the
/// server closes it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// The session slots: a global pool and a per-address allowance, taken at
/// accept time, before any handshake work, and returned when the session
/// ends. A connection that finds no slot is dropped at once.
struct Slots {
    total: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// A held slot; dropping it frees both halves.
struct Slot {
    _total: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Slots {
    fn new() -> Self {
        Self {
            total: Arc::new(Semaphore::new(MAX_SESSIONS)),
            per_ip: Arc::default(),
        }
    }

    fn admit(&self, ip: IpAddr) -> Option<Slot> {
        let total = self.total.clone().try_acquire_owned().ok()?;
        // A poisoned lock only means another session panicked mid-update of a
        // plain counter map; the counts stay usable.
        let mut held = self.per_ip.lock().unwrap_or_else(|p| p.into_inner());
        let n = held.entry(ip).or_insert(0);
        if *n >= MAX_SESSIONS_PER_IP {
            return None;
        }
        *n += 1;
        Some(Slot {
            _total: total,
            per_ip: self.per_ip.clone(),
            ip,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.per_ip.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = held.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.ip);
            }
        }
    }
}

/// Why the transport listener did not run.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The server has no attestor capability (no signing identity and
    /// principal), so it has no Cyphr key to prove itself with. The
    /// transport authenticates the server as a principal; without one it
    /// refuses to listen rather than serve an unauthenticated session.
    #[error("the transport needs a keyed server: no signing identity and principal")]
    Keyless,
    /// Binding or accepting on the socket failed.
    #[error("transport listener: {0}")]
    Io(#[from] std::io::Error),
    /// The application router (admission, fences) could not be built.
    #[error("application router: {0}")]
    Router(String),
}

/// Why one session ended without being served.
#[derive(Debug, thiserror::Error)]
enum SessionError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("responder statement: {0}")]
    Sign(String),
    #[error("initiator refused: {0}")]
    Initiator(&'static str),
    #[error("initiator lookup: {0}")]
    Lookup(String),
}

impl SessionError {
    /// What the initiator is told. A lookup failure is the server's own
    /// trouble and says nothing about the stored state.
    fn reason(&self) -> String {
        match self {
            Self::Lookup(_) => "the server could not look up the principal".into(),
            other => other.to_string(),
        }
    }
}

/// Serve the full application router over Noise on `listener`, running
/// until the listener fails. The router is [`build_app_router`]: the same
/// admission gate, rate limits and body limit HTTP has, so the transport
/// cannot be used to get around one.
///
/// # Errors
///
/// [`ServeError::Keyless`] before anything is accepted when the server has
/// no attestor capability; [`ServeError::Router`] when the application
/// router cannot be built; [`ServeError::Io`] when accepting fails.
pub async fn serve_noise(listener: TcpListener, state: Arc<AppState>) -> Result<(), ServeError> {
    require_attestor(&state)?;
    let router = build_app_router(state.clone()).map_err(|e| ServeError::Router(e.to_string()))?;
    serve_noise_with(listener, state, router).await
}

/// [`serve_noise`] with the dispatch router supplied by the caller. The
/// caller owns what the router enforces: pass [`build_app_router`]'s to
/// keep the HTTP fences; a test passes a hostile one to play a bad peer.
///
/// # Errors
///
/// As [`serve_noise`].
pub async fn serve_noise_with(
    listener: TcpListener,
    state: Arc<AppState>,
    router: Router,
) -> Result<(), ServeError> {
    require_attestor(&state)?;
    let slots = Slots::new();
    loop {
        let (stream, peer) = listener.accept().await?;
        let Some(slot) = slots.admit(peer.ip()) else {
            tracing::debug!(%peer, "transport at capacity for this address; dropped");
            continue;
        };
        let (state, router) = (state.clone(), router.clone());
        tokio::spawn(async move {
            match session(stream, peer, &state, router).await {
                Ok(()) => tracing::debug!(%peer, "transport session closed"),
                Err(err) => tracing::warn!(%peer, %err, "transport session ended"),
            }
            drop(slot);
        });
    }
}

/// Bind `addr` and serve `router` over Noise in the background, returning
/// the bound address and the listener task.
///
/// # Errors
///
/// [`ServeError::Keyless`] (checked before binding) or [`ServeError::Io`].
pub async fn spawn_noise(
    addr: &str,
    state: Arc<AppState>,
    router: Router,
) -> Result<(SocketAddr, JoinHandle<()>), ServeError> {
    require_attestor(&state)?;
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        if let Err(err) = serve_noise_with(listener, state, router).await {
            tracing::error!(%err, "transport listener stopped");
        }
    });
    Ok((local, handle))
}

fn require_attestor(state: &AppState) -> Result<(), ServeError> {
    state.attestor_signer().map(drop).ok_or(ServeError::Keyless)
}

async fn session(
    stream: TcpStream,
    peer: SocketAddr,
    state: &AppState,
    router: Router,
) -> Result<(), SessionError> {
    let mut channel = Channel::respond(stream).await?;
    let h = channel.handshake_hash().to_vec();

    let statement = responder_statement(state, &h).await?;
    channel.send_one(&statement).await?;

    let incoming = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.recv_one())
        .await
        .map_err(|_| TransportError::Timeout)??;
    // The verdict goes back before anything else, so a refused initiator
    // learns it at `connect` and a served one knows it was accepted.
    match authorize_initiator(state, &incoming, &h).await {
        Ok(()) => channel.send_one(&encode_ack(Ok(()))).await?,
        Err(refusal) => {
            channel
                .send_one(&encode_ack(Err(&refusal.reason())))
                .await?;
            return Err(refusal);
        },
    }

    loop {
        let message = match tokio::time::timeout(IDLE_TIMEOUT, channel.recv_message()).await {
            Err(_) => return Ok(()),
            Ok(Err(TransportError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            },
            Ok(message) => message?,
        };
        let (status, body) = match decode_request(&message) {
            Ok(request) => dispatch(&router, peer, request).await,
            Err(_) => (400, b"malformed request".to_vec()),
        };
        channel
            .send_message(&encode_response(status, &body))
            .await?;
    }
}

/// The server's own statement: signed through the attestor backend, naming
/// the server principal and the key that signs.
async fn responder_statement(state: &AppState, h: &[u8]) -> Result<Vec<u8>, SessionError> {
    let sign_err = |why: &str| SessionError::Sign(why.to_string());
    let (principal, _) = state
        .attestor()
        .ok_or_else(|| sign_err("the server lost its attestor capability"))?;
    let signer = state
        .attestor_signer()
        .ok_or_else(|| sign_err("the server lost its attestor capability"))?;
    let (alg, pub_key) = (signer.alg(), signer.pub_key());
    let tmb = coz::compute_thumbprint_for_alg(alg, pub_key)
        .ok_or_else(|| sign_err("no thumbprint for the signing key"))?;
    let now = crate::auth::server_now();
    let pay = statement_pay(alg, &tmb, principal.pg(), Role::Responder, h, now)?;
    let cad = statement_cad(alg, &pay)?;
    let sig = signer
        .sign(&cad)
        .await
        .map_err(|e| SessionError::Sign(e.to_string()))?;
    // A backend that signs badly would hand every client a refusal; catch
    // it here, where the cause is named.
    if coz::verify_json(&pay, &sig, alg, pub_key) != Some(true) {
        return Err(sign_err(
            "the signature does not verify under the signing key",
        ));
    }
    Ok(assemble_statement(&pay, &sig, None)?)
}

/// Judge the initiator's statement: bound to this session and role, and
/// signed by a key that is active in the stored chain of the principal it
/// names.
async fn authorize_initiator(
    state: &AppState,
    incoming: &[u8],
    h: &[u8],
) -> Result<(), SessionError> {
    let statement = BindStatement::parse(incoming)?;
    statement.expect(Role::Initiator, h)?;

    let pr = statement.pr();
    let lookup = |e: cyphr_storage::engine::EngineError| SessionError::Lookup(e.to_string());
    let stored = state.engine.get_tip(pr).await.map_err(lookup)?.is_some();
    if stored {
        // A stored principal is judged by its chain alone; any sidecar the
        // statement carries is ignored, so it cannot widen who may speak.
        let genesis = state
            .engine
            .resolve_genesis(pr, &[])
            .await
            .map_err(lookup)?;
        let principal = state
            .engine
            .load_principal(pr, genesis)
            .await
            .map_err(lookup)?;
        // `get_key` also returns revoked keys, so activity is its own check.
        let key = principal
            .get_key(statement.tmb())
            .ok_or(SessionError::Initiator("the key is not the principal's"))?;
        statement.verify(key)?;
        if !principal.is_key_active(statement.tmb()) {
            return Err(SessionError::Initiator("the key is not active"));
        }
        if principal.lifecycle_state() != cyphr::lifecycle::LifecycleState::Active {
            return Err(SessionError::Initiator("the principal is not active"));
        }
    } else {
        // No chain: only a Level 1 principal, whose id is its key's
        // thumbprint, can prove itself, by the key it brings.
        let key = statement.sidecar_key()?.ok_or(SessionError::Initiator(
            "no stored chain for the principal and no key sidecar",
        ))?;
        if key.tmb() != statement.tmb() {
            return Err(SessionError::Initiator(
                "the sidecar key is not the key the statement names",
            ));
        }
        if pr != key.tmb().to_b64() {
            return Err(SessionError::Initiator(
                "an unstored principal must be its key's thumbprint",
            ));
        }
        statement.verify(&key)?;
    }
    // Naked revoke (SPEC 6.4) is global by thumbprint and invisible to the chain.
    if state
        .observations
        .is_dead(statement.tmb())
        .await
        .map_err(|e| SessionError::Lookup(e.to_string()))?
    {
        return Err(SessionError::Initiator("the key was naked-revoked"));
    }
    Ok(())
}

/// Run one decoded request through `router` and return the status and body
/// of its answer.
async fn dispatch(
    router: &Router,
    peer: SocketAddr,
    request: cyphr_client::Request,
) -> (u16, Vec<u8>) {
    let method = match request.method {
        Method::Get => axum::http::Method::GET,
        Method::Post => axum::http::Method::POST,
    };
    let built = axum::http::Request::builder()
        .method(method)
        .uri(&request.target)
        .header("accept", "application/json")
        .header("content-type", "application/json")
        .body(Body::from(request.body));
    let mut http = match built {
        Ok(http) => http,
        Err(_) => return (400, b"malformed request target".to_vec()),
    };
    // The per-IP fence keys on the peer the kernel reports.
    http.extensions_mut().insert(ConnectInfo(peer));
    let Ok(response) = router.clone().oneshot(http).await;
    let status = response.status().as_u16();
    match axum::body::to_bytes(response.into_body(), MAX_MESSAGE - 2).await {
        Ok(bytes) => (status, bytes.to_vec()),
        Err(_) => (500, b"response too large".to_vec()),
    }
}
