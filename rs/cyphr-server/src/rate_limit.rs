//! Server-side resource FENCES (orthogonal to the protocol).
//!
//! Three refuse-only fences, keyed on transport facts (request rate, request
//! size) and one storage fact (per-principal commit count), composed only in
//! [`crate::serve`] -- never in `build_router`, which stays the standing strip
//! test and never sees a limiter. They only ever REFUSE service (`429` rate /
//! `413` size / `402` quota); they never admit, validate, or mutate protocol
//! state.
//!
//! Orthogonality is compiler-checked: this module imports NO `cyphr::*` or
//! `coz::*` protocol type. The one storage fact a fence needs -- a principal's
//! commit count -- crosses the boundary as a `u64` through the [`CountProbe`]
//! closure defined in `serve()`, exactly as admission's residency probe does,
//! so no engine type enters here.
//!
//! ## The fences
//!
//! - **Rate** (via the `governor` token-bucket engine): a per-peer-IP bucket, a per-operation
//!   bucket (reads / push / login / revoke, each keyed on peer IP), and a per-principal bucket on
//!   the write path (keyed on the peeked `principal_id`, so it bounds writes even when no bearer
//!   auth is configured). Independent buckets: a flood of one never drains another.
//! - **Size**: a body past `max_body_bytes` is refused `413` before handler work -- both on the
//!   declared `Content-Length` and on the bytes actually buffered for the write path (so a chunked
//!   over-cap push cannot slip the header check).
//! - **Count quota**: a principal already at or over `count_quota` commits is refused a further
//!   commit with a distinct `402`, via the [`CountProbe`].
//!
//! ## Bounded state (no self-DoS)
//!
//! Every keyed limiter map is swept on a traffic-driven cadence (see
//! [`Fences::maybe_sweep`]): `governor`'s `retain_recent` drops keys whose
//! buckets are fully replenished -- indistinguishable from absent -- so the
//! maps track only ACTIVE clients, never every client ever seen. The maps
//! cannot grow without bound, so the fences cannot become a memory self-DoS.

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::header::CONTENT_LENGTH;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use serde::Deserialize;
use tower::{Layer, Service};

use crate::config::{LimitsConfig, RateBucket};

/// A commit-count probe: given a principal id, resolve how many commits it
/// currently has. The sole storage fact the quota fence reads, reduced to a
/// `u64` so no protocol type crosses into this module. A probe failure
/// resolves to `0` (under any quota) -- an index blip never fabricates a quota
/// refusal of legitimate traffic; the fence only ever refuses on a *known*
/// over-cap count.
pub type CountProbe = Arc<dyn Fn(String) -> BoxFuture<'static, u64> + Send + Sync>;

/// A keyed `governor` limiter over key `K`, backed by the default (DashMap)
/// keyed state store and default clock.
type KeyedLimiter<K> = RateLimiter<K, DefaultKeyedStateStore<K>, DefaultClock>;

/// Sweep the limiter maps once every this many requests (see
/// [`Fences::maybe_sweep`]). Amortizes the bounded-state maintenance across
/// traffic without a background timer.
const SWEEP_INTERVAL: u64 = 512;

// ========================================================================
// The fences
// ========================================================================

/// The resource decision state, shared behind an `Arc` across all cloned
/// service instances.
struct Fences {
    /// Per-peer-IP bucket, over every request.
    per_ip: KeyedLimiter<IpAddr>,
    /// Per-operation buckets, each keyed on peer IP.
    read: KeyedLimiter<IpAddr>,
    push: KeyedLimiter<IpAddr>,
    login: KeyedLimiter<IpAddr>,
    revoke: KeyedLimiter<IpAddr>,
    /// Per-principal write-path bucket, keyed on the peeked `principal_id`.
    per_principal: KeyedLimiter<String>,
    /// Maximum accepted request body in bytes.
    max_body_bytes: u64,
    /// Per-principal hard commit-count cap.
    count_quota: u64,
    /// Request counter driving the amortized bounded-state sweep.
    sweeps: AtomicU64,
}

impl Fences {
    fn from_config(limits: &LimitsConfig) -> Self {
        Self {
            per_ip: RateLimiter::keyed(quota(limits.per_ip)),
            read: RateLimiter::keyed(quota(limits.read)),
            push: RateLimiter::keyed(quota(limits.push)),
            login: RateLimiter::keyed(quota(limits.login)),
            revoke: RateLimiter::keyed(quota(limits.revoke)),
            per_principal: RateLimiter::keyed(quota(limits.per_principal)),
            max_body_bytes: limits.max_body_bytes,
            count_quota: limits.count_quota,
            sweeps: AtomicU64::new(0),
        }
    }

    /// The per-operation limiter for `op`, or `None` for an unclassified route
    /// (still covered by the per-IP fence).
    fn op_limiter(&self, op: Op) -> Option<&KeyedLimiter<IpAddr>> {
        match op {
            Op::Read => Some(&self.read),
            Op::Push => Some(&self.push),
            Op::Login => Some(&self.login),
            Op::Revoke => Some(&self.revoke),
            Op::Other => None,
        }
    }

    /// Amortized bounded-state maintenance: every [`SWEEP_INTERVAL`] requests,
    /// drop keys whose buckets are fully replenished (indistinguishable from
    /// absent) so each map tracks only ACTIVE clients. This is what makes the
    /// key maps -- and thus the fences' memory -- bounded rather than a
    /// self-DoS.
    fn maybe_sweep(&self) {
        if self.sweeps.fetch_add(1, Ordering::Relaxed) % SWEEP_INTERVAL == 0 {
            self.per_ip.retain_recent();
            self.read.retain_recent();
            self.push.retain_recent();
            self.login.retain_recent();
            self.revoke.retain_recent();
            self.per_principal.retain_recent();
        }
    }
}

/// Translate a configured `{ per_second, burst }` bucket into a `governor`
/// quota: one cell replenished every `1s / per_second`, up to `burst` capacity.
/// Both fields are clamped to at least 1 so a misconfigured `0` becomes the
/// tightest live bucket rather than a panic.
fn quota(bucket: RateBucket) -> Quota {
    let per_second = bucket.per_second.max(1);
    let burst = NonZeroU32::new(bucket.burst.max(1)).expect("burst clamped to >= 1");
    let period = Duration::from_secs(1) / per_second;
    Quota::with_period(period)
        .unwrap_or_else(|| {
            // `period` is only zero for an absurd `per_second`; fall back to
            // the finest non-zero replenishment rather than refusing to build.
            Quota::with_period(Duration::from_nanos(1)).expect("1ns period is non-zero")
        })
        .allow_burst(burst)
}

/// The operation class of a request, selecting its per-operation bucket.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Read,
    Push,
    Login,
    Revoke,
    Other,
}

/// Classify a request by method and path into its operation bucket. `/revoke`
/// is deliberately ordinary -- no exemption from rate limiting.
fn classify(method: &Method, path: &str) -> Op {
    match (method, path) {
        (&Method::POST, "/push") => Op::Push,
        (&Method::POST, "/revoke") => Op::Revoke,
        (&Method::POST, "/auth/challenge") | (&Method::POST, "/auth/login") => Op::Login,
        (&Method::GET, _) => Op::Read,
        _ => Op::Other,
    }
}

/// The peer IP for per-IP keying, read from the `ConnectInfo` extension that
/// `serve()` wires via `into_make_service_with_connect_info`. Absent it (which
/// the wiring makes unreachable in `serve()`), all requests fall into one
/// sentinel bucket -- the safe, still-bounding direction.
fn peer_ip(req: &Request) -> IpAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// The declared body length from `Content-Length`, if the header is present
/// and a valid `u64`. A chunked body without the header is bounded instead by
/// the buffering cap on the write path.
fn declared_len(req: &Request) -> Option<u64> {
    req.headers()
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}

// ========================================================================
// The fence decision
// ========================================================================

/// Apply the fences to `req`, delegating to `inner` on a pass. Any tripped
/// fence short-circuits to its refusal; nothing else is mutated.
async fn handle<S>(
    fences: Arc<Fences>,
    count_probe: CountProbe,
    req: Request,
    inner: &mut S,
) -> Response
where
    S: Service<Request, Response = Response, Error = Infallible>,
    S::Future: Send,
{
    fences.maybe_sweep();

    // (1) Size cap on the declared length -- refuse before any keying or
    // buffering when the client announces an over-cap body.
    if let Some(len) = declared_len(&req) {
        if len > fences.max_body_bytes {
            return too_large(fences.max_body_bytes);
        }
    }

    // (2) Per-IP fence over every request.
    let ip = peer_ip(&req);
    if fences.per_ip.check_key(&ip).is_err() {
        return rate_limited();
    }

    // (3) Per-operation fence (keyed on peer IP within the operation).
    let op = classify(req.method(), req.uri().path());
    if let Some(limiter) = fences.op_limiter(op) {
        if limiter.check_key(&ip).is_err() {
            return rate_limited();
        }
    }

    // (4) Write path: buffer the body (enforcing the size cap on the actual
    // bytes), peek the principal, then apply the per-principal rate fence and
    // the hard count quota.
    if op == Op::Push {
        let (parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, fences.max_body_bytes as usize).await {
            Ok(bytes) => bytes,
            Err(_) => return too_large(fences.max_body_bytes),
        };
        let principal_id = peek_principal_id(&bytes);
        let req = Request::from_parts(parts, Body::from(bytes));

        // Absent/unparseable `principal_id`: nothing to key or count. The
        // handler's own parse rejects it and no state is created.
        let Some(id) = principal_id else {
            return call_inner(inner, req).await;
        };

        if fences.per_principal.check_key(&id).is_err() {
            return rate_limited();
        }

        let count = (count_probe)(id).await;
        if count >= fences.count_quota {
            return quota_exceeded(fences.count_quota);
        }

        return call_inner(inner, req).await;
    }

    call_inner(inner, req).await
}

/// Drive the inner service. Its error is `Infallible`, so the match is total.
async fn call_inner<S>(inner: &mut S, req: Request) -> Response
where
    S: Service<Request, Response = Response, Error = Infallible>,
    S::Future: Send,
{
    match inner.call(req).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// A rate-limit refusal: `429` with a machine-readable body.
fn rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({ "error": "rate limit exceeded" })),
    )
        .into_response()
}

/// A size-cap refusal: `413` naming the byte limit.
fn too_large(limit: u64) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({
            "error": "request body too large",
            "limit_bytes": limit,
        })),
    )
        .into_response()
}

/// A count-quota refusal: a distinct `402` (deliberately neither the `429` of a
/// rate fence nor the `403` of admission) naming the commit limit, so a client
/// can tell a resource-quota refusal from a rate throttle or an admission deny.
fn quota_exceeded(limit: u64) -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(serde_json::json!({
            "error": "per-principal commit quota exhausted",
            "limit_commits": limit,
        })),
    )
        .into_response()
}

/// One-field peek at the wire push shape, mirroring the handler's serde
/// discipline so the fence and the handler agree on a parseable `principal_id`.
/// Duplicated (not imported) from admission to keep this module free of any
/// cross-fence coupling.
#[derive(Deserialize)]
struct PrincipalIdPeek {
    principal_id: String,
}

fn peek_principal_id(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<PrincipalIdPeek>(bytes)
        .ok()
        .map(|peek| peek.principal_id)
}

// ========================================================================
// tower plumbing
// ========================================================================

/// Build the rate/size/quota fence layer for `limits`, reading commit counts
/// through `count_probe`. Always returns a layer: unlike admission's `Open`,
/// the fences always apply -- a bare server gets the conservative defaults.
pub fn layer(limits: &LimitsConfig, count_probe: CountProbe) -> RateLimitLayer {
    RateLimitLayer {
        fences: Arc::new(Fences::from_config(limits)),
        count_probe,
    }
}

/// The rate/size/quota tower layer. Cheap to clone (shares the [`Fences`]).
#[derive(Clone)]
pub struct RateLimitLayer {
    fences: Arc<Fences>,
    count_probe: CountProbe,
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            fences: self.fences.clone(),
            count_probe: self.count_probe.clone(),
        }
    }
}

/// The rate/size/quota tower service wrapping the inner router service.
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    fences: Arc<Fences>,
    count_probe: CountProbe,
}

impl<S> Service<Request> for RateLimitService<S>
where
    S: Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;
    type Response = Response;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let fences = self.fences.clone();
        let count_probe = self.count_probe.clone();
        // Readiness was checked on `self.inner`; move that ready clone into the
        // future and leave a fresh (not-yet-ready) clone behind.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(async move { Ok(handle(fences, count_probe, req, &mut inner).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tight bucket trips within its burst; a fresh key starts full.
    #[test]
    fn tight_quota_trips_within_burst() {
        let limiter: KeyedLimiter<IpAddr> = RateLimiter::keyed(quota(RateBucket {
            per_second: 1,
            burst: 2,
        }));
        let ip = IpAddr::from([127, 0, 0, 1]);
        assert!(limiter.check_key(&ip).is_ok(), "first cell within burst");
        assert!(limiter.check_key(&ip).is_ok(), "second cell within burst");
        assert!(
            limiter.check_key(&ip).is_err(),
            "third immediate cell exceeds a burst of 2"
        );

        // A distinct key is an independent bucket.
        let other = IpAddr::from([127, 0, 0, 2]);
        assert!(
            limiter.check_key(&other).is_ok(),
            "a distinct key must not share the tripped bucket"
        );
    }

    /// A generous bucket never trips under a modest burst.
    #[test]
    fn generous_quota_admits_a_burst() {
        let limiter: KeyedLimiter<IpAddr> = RateLimiter::keyed(quota(RateBucket {
            per_second: 100_000,
            burst: 100_000,
        }));
        let ip = IpAddr::from([127, 0, 0, 1]);
        for _ in 0..1000 {
            assert!(
                limiter.check_key(&ip).is_ok(),
                "generous bucket must not trip"
            );
        }
    }

    #[test]
    fn classify_maps_routes_to_operations() {
        assert!(classify(&Method::POST, "/push") == Op::Push);
        assert!(classify(&Method::POST, "/revoke") == Op::Revoke);
        assert!(classify(&Method::POST, "/auth/login") == Op::Login);
        assert!(classify(&Method::GET, "/tip") == Op::Read);
        assert!(classify(&Method::GET, "/e/abc") == Op::Read);
        assert!(classify(&Method::PUT, "/whatever") == Op::Other);
    }

    #[test]
    fn peek_reads_principal_id() {
        let body = br#"{"principal_id":"abc","blobs":[]}"#;
        assert_eq!(peek_principal_id(body).as_deref(), Some("abc"));
        assert!(peek_principal_id(b"not json").is_none());
    }

    /// F2 bounded-state (WHITE-BOX). RED (uncompilable) today, GREEN after F2
    /// gives every keyed limiter map a hard max-entry ceiling. The merged fence
    /// bounds its maps only with governor's `retain_recent` -- a TIME sweep that
    /// drops fully-replenished buckets, NOT a size cap. A distributed or
    /// IPv6-rotation flood of distinct, never-replenished keys therefore grows
    /// the per-IP and per-operation maps without bound: a memory self-DoS the
    /// module doc today wrongly calls impossible. This pins the invariant a size
    /// ceiling must hold -- after inserting more than `KEY_CEILING` distinct
    /// keys and running the bounded-state maintenance, the map retains at most
    /// `KEY_CEILING` entries (oldest evicted).
    ///
    /// `KEY_CEILING` and the eviction path are the implementation's to add (AC3
    /// greps for the ceiling constant + eviction), so this test does not compile
    /// against today's code -- that non-compilation IS its red signal, not a
    /// harness fault. It pins the size-bound contract; the exact accessor and
    /// eviction mechanism are the implementation's, and this test moves in
    /// lockstep with what the impl-worker builds within the node.
    #[test]
    fn keyed_limiter_map_is_bounded_by_key_ceiling() {
        use std::net::Ipv6Addr;

        let fences = Fences::from_config(&LimitsConfig::default());

        // Flood the per-IP map with distinct, never-seen keys -- the exact
        // vector `retain_recent` cannot bound (none of these buckets ever
        // replenishes within the loop, so a time sweep keeps them all).
        for i in 0..(KEY_CEILING as u128 + 1_000) {
            let ip = IpAddr::V6(Ipv6Addr::from(i));
            let _ = fences.per_ip.check_key(&ip);
            fences.maybe_sweep();
        }

        assert!(
            fences.per_ip.len() <= KEY_CEILING,
            "the per-IP limiter map must stay within KEY_CEILING ({}) entries under a flood of \
             distinct keys, got {}",
            KEY_CEILING,
            fences.per_ip.len(),
        );
    }
}
