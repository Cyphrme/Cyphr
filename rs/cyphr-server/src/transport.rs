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
    BindStatement, Channel, MAX_MESSAGE, Role, TransportError, assemble_statement, decode_request,
    encode_ack, encode_response, statement_cad, statement_pay,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tower::ServiceExt;

use crate::{AppState, build_app_router};

/// Sessions served at once, across all addresses.
const MAX_SESSIONS: usize = 256;

/// Sessions one source may hold at once. A Level 1 key is its own
/// principal, so a peer authenticates for free and the address is the only
/// scarce thing it has; without this one source could fill every slot. A
/// source is a full IPv4 address or an IPv6 /64 (see [`bucket`]).
const MAX_SESSIONS_PER_IP: usize = 16;

/// How long an authenticated session may sit without a request before the
/// server closes it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Who the transport authenticated, attached to every request it routes as
/// a request extension. HTTP requests carry none, so a route that finds one
/// knows the request arrived over an authenticated Noise session and which
/// principal and key proved themselves on it. No route requires it yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// The initiator's principal: the stored principal's canonical id, or
    /// for a Level 1 principal the thumbprint that is its id.
    pub pg: String,
    /// The key that signed the initiator's statement.
    pub tmb: coz::Thumbprint,
    /// The Noise handshake hash of this session: the binding the statement
    /// was signed over.
    pub handshake_hash: Vec<u8>,
}

/// The unit the per-source cap counts. An IPv6 /64 is one end site, one
/// subscriber (RFC 6177), who can source an address per connection, so it
/// is bucketed by its /64 prefix. IPv4 keeps the full address: a /24 would
/// merge unrelated hosts behind one provider's block (and one NAT already
/// shares an address), and no test here supports the wider bucket.
fn bucket(ip: IpAddr) -> IpAddr {
    // A dual-stack listener reports an IPv4 client as `::ffff:a.b.c.d`;
    // key it as the IPv4 address it is, or all of them share one /64.
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => v4,
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !u128::from(u64::MAX);
            IpAddr::V6(prefix.into())
        },
    }
}

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
        let ip = bucket(ip);
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

/// Pause after a failed `accept` before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long writing one response may take before the session is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
/// router cannot be built. A failed `accept` is logged and retried, never
/// returned.
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
        // Running out of descriptors or a connection aborted before accept
        // is the peers' doing or the machine's, not a reason to stop
        // listening; back off briefly so a persistent failure cannot spin.
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "transport accept failed; retrying");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            },
        };
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

/// The whole pre-authentication exchange, handshake through the ack, must
/// finish within this, measured from accept. One budget, not one per step,
/// so a peer cannot stretch its stay by stalling each step just short of
/// its own limit.
const PREAUTH_DEADLINE: Duration = Duration::from_secs(10);

async fn session(
    stream: TcpStream,
    peer: SocketAddr,
    state: &AppState,
    router: Router,
) -> Result<(), SessionError> {
    let (mut channel, identity) =
        tokio::time::timeout(PREAUTH_DEADLINE, authenticate(stream, state))
            .await
            .map_err(|_| TransportError::Timeout)??;
    // A request carries its body plus a target of at most 64 KiB; anything
    // declared larger would be refused by the body limit anyway.
    let max_request = usize::try_from(state.config.limits.max_body_bytes.get())
        .unwrap_or(usize::MAX)
        .saturating_add(64 * 1024);
    serve_requests(&mut channel, peer, &identity, &router, max_request).await
}

/// Handshake, both statements and the ack: everything before a request.
async fn authenticate(
    stream: TcpStream,
    state: &AppState,
) -> Result<(Channel<TcpStream>, AuthenticatedPeer), SessionError> {
    let mut channel = Channel::respond(stream).await?;
    let h = channel.handshake_hash().to_vec();

    let statement = responder_statement(state, &h).await?;
    channel.send_one(&statement).await?;

    let incoming = channel.recv_one().await?;
    // The verdict goes back before anything else, so a refused initiator
    // learns it at `connect` and a served one knows it was accepted.
    let identity = match authorize_initiator(state, &incoming, &h).await {
        Ok(identity) => {
            channel.send_one(&encode_ack(Ok(()))).await?;
            identity
        },
        Err(refusal) => {
            channel
                .send_one(&encode_ack(Err(&refusal.reason())))
                .await?;
            return Err(refusal);
        },
    };
    Ok((channel, identity))
}

/// Serve requests on an authenticated channel until it closes or idles out.
async fn serve_requests(
    channel: &mut Channel<TcpStream>,
    peer: SocketAddr,
    identity: &AuthenticatedPeer,
    router: &Router,
    max_request: usize,
) -> Result<(), SessionError> {
    loop {
        let message =
            match tokio::time::timeout(IDLE_TIMEOUT, channel.recv_message(max_request)).await {
                Err(_) => return Ok(()),
                Ok(Err(TransportError::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                },
                Ok(message) => message?,
            };
        let (status, body) = match decode_request(&message) {
            Ok(request) => dispatch(router, peer, identity, request).await,
            Err(_) => (400, b"malformed request".to_vec()),
        };
        // A peer that stops reading must not hold the session, and the
        // buffer behind this write, for the idle timeout or longer.
        tokio::time::timeout(
            WRITE_TIMEOUT,
            channel.send_message(&encode_response(status, &body)),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
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
) -> Result<AuthenticatedPeer, SessionError> {
    let statement = BindStatement::parse(incoming)?;
    statement.expect(Role::Initiator, h)?;

    let pr = statement.pr();
    let lookup = |e: cyphr_storage::engine::EngineError| SessionError::Lookup(e.to_string());
    let stored = state.engine.get_tip(pr).await.map_err(lookup)?.is_some();
    // The principal's one spelling, so a route keys on it whatever the
    // statement called it (a stored id may be tagged or bare).
    let pg = if stored {
        let canonical = state
            .engine
            .canonical_principal_id(pr)
            .await
            .map_err(lookup)?;
        cyphr_storage::engine::bare_digest(&canonical).to_string()
    } else {
        pr.to_string()
    };
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
    Ok(AuthenticatedPeer {
        pg,
        tmb: statement.tmb().clone(),
        handshake_hash: h.to_vec(),
    })
}

/// Run one decoded request through `router` and return the status and body
/// of its answer.
async fn dispatch(
    router: &Router,
    peer: SocketAddr,
    identity: &AuthenticatedPeer,
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
    // What the session authenticated, for routes that care who is asking.
    http.extensions_mut().insert(identity.clone());
    let Ok(response) = router.clone().oneshot(http).await;
    let status = response.status().as_u16();
    match axum::body::to_bytes(response.into_body(), MAX_MESSAGE - 2).await {
        Ok(bytes) => (status, bytes.to_vec()),
        Err(_) => (500, b"response too large".to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Claim: the per-address session cap counts an IPv6 /64 as one source
    /// (RFC 6177: a /64 is one end site), while distinct /64s and distinct
    /// IPv4 addresses keep separate allowances. Red if admit keys on the
    /// exact address: 16 addresses of one /64 would then each get a fresh
    /// allowance and a 17th session would be admitted.
    ///
    /// Why a unit test: an end-to-end test cannot bind this many distinct
    /// source addresses (a client socket gets the loopback address or one
    /// host address), so only `admit` can be driven with chosen peers.
    #[test]
    fn ipv6_sessions_share_a_64_allowance_and_ipv4_does_not() {
        let slots = Slots::new();
        let v6 =
            |net: u16, host: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, net, 0, 0, 0, host));

        // Fill one /64 with one session from each of 16 different addresses.
        let held: Vec<_> = (0..MAX_SESSIONS_PER_IP as u16)
            .map(|h| slots.admit(v6(1, h)).expect("within the /64 allowance"))
            .collect();
        assert!(
            slots.admit(v6(1, 999)).is_none(),
            "a 17th address of the same /64 is refused"
        );
        assert!(
            slots.admit(v6(2, 0)).is_some(),
            "another /64 is still admitted"
        );

        // IPv4 stays per full address: a neighbouring address is separate.
        let v4 = |d: u8| IpAddr::V4(Ipv4Addr::new(192, 0, 2, d));
        let _a: Vec<_> = (0..MAX_SESSIONS_PER_IP)
            .map(|_| slots.admit(v4(1)).expect("within the IPv4 allowance"))
            .collect();
        assert!(slots.admit(v4(1)).is_none());
        assert!(slots.admit(v4(2)).is_some());

        // A dual-stack `[::]` listener reports IPv4 clients as mapped
        // `::ffff:a.b.c.d`; they must key as plain IPv4, not share the
        // ::/64 bucket their common prefix would put them in.
        let mapped = |d: u8| IpAddr::V6(Ipv4Addr::new(198, 51, 100, d).to_ipv6_mapped());
        let _m: Vec<_> = (0..MAX_SESSIONS_PER_IP)
            .map(|_| slots.admit(mapped(1)).expect("within the mapped allowance"))
            .collect();
        assert!(slots.admit(mapped(1)).is_none());
        assert!(
            slots.admit(mapped(2)).is_some(),
            "a different mapped IPv4 client has its own allowance"
        );
        assert!(
            slots
                .admit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
                .is_none(),
            "a mapped address and its plain IPv4 form are one client"
        );

        // Releasing the /64's sessions frees its bucket.
        drop(held);
        assert!(slots.admit(v6(1, 999)).is_some());
    }
}
