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
//! - **Rate** (via the `governor` token-bucket engine): a per-peer-IP bucket and a per-operation
//!   bucket (reads / push / login / revoke, each keyed on peer IP). Independent buckets: a flood of
//!   one never drains another. There is deliberately no per-principal RATE bucket: keying a rate
//!   fence on the `principal_id` peeked from a raw, unverified `/push` body would let an
//!   unauthenticated attacker throttle a victim merely by naming its principal in a garbage flood.
//!   The write path is bounded instead by the per-IP fence (keyed on the real, un-nameable TCP
//!   peer) and the count quota below (which reads durable, uninflatable commit-count state).
//! - **Size**: a body past `max_body_bytes` is refused `413` before handler work -- both on the
//!   declared `Content-Length` and on the bytes actually buffered for the write path (so a chunked
//!   over-cap push cannot slip the header check). Every OTHER route is capped the same way by a
//!   `serve()`-composed body-limit layer (see [`crate::serve`]), so `max_body_bytes` is the single
//!   authoritative body cap across every route. `/push` under an active (non-`Open`) admission
//!   policy is ADDITIONALLY buffered by admission itself (to peek `principal_id` before this fence
//!   ever runs), but that buffer is bounded by the SAME configured `max_body_bytes` value (see
//!   [`crate::admission::layer`]), never a separate constant.
//! - **Count quota**: a principal already at or over `count_quota` commits is refused a further
//!   commit with a distinct `402`, via the [`CountProbe`]. The check reads `commit_count` before
//!   the handler's own increment, so concurrent same-principal pushes can overshoot the cap by up
//!   to the in-flight burst -- a bounded soft overshoot; strict atomic enforcement belongs to the
//!   storage engine, not this fence.
//!
//! ## Bounded state (no self-DoS)
//!
//! Every keyed limiter map is bounded two ways: a traffic-driven TIME sweep (see
//! [`Fences::maybe_sweep`]) that runs `governor`'s `retain_recent` to drop keys whose buckets are
//! fully replenished -- indistinguishable from absent -- and a hard SIZE ceiling ([`KEY_CEILING`])
//! enforced in the same sweep. The time sweep alone does not bound the map: a distributed or
//! IPv6-rotation flood of distinct, never-replenished keys never looks stale, so it grows the map
//! without bound. `governor` exposes no per-key removal (only the global
//! `retain_recent`/`len`/`is_empty`), so once a map still exceeds `KEY_CEILING` after the time
//! sweep, [`BoundedLimiter`] resets it to fresh rather than leaving it to grow further.
//!
//! That reset is an accepted, attacker-triggerable LOOSENING, not a free backstop: an adversary
//! who can present more than `KEY_CEILING` distinct *real, routable* peer addresses (e.g. a routed
//! IPv6 allocation) can deliberately drive a map over the ceiling to force a reset, which clears
//! EVERY bucket in that map -- including a concurrently-throttled abuser's. This is accepted, not
//! overlooked, for four reasons. First, the precondition is an adversary who by construction
//! already defeats per-IP rate limiting at that scale; per-IP throttling exists to stop the cheap
//! single-/few-address griefer, for whom the map never approaches `KEY_CEILING` and the reset never
//! fires. Second, the reset only ever loosens -- every bucket, legitimate or not, gets a fresh
//! allowance -- so it can never manufacture a spurious refusal against honest traffic. Third, it is
//! strictly better on this same distributed-flood vector than the unbounded-memory exhaustion it
//! replaces. Fourth, the durable per-principal count quota (see "The fences" above) -- the real
//! bound on write volume -- is untouched by the reset. Finer, per-key eviction would close this gap
//! but requires replacing `governor` (which exposes no per-key removal); that is follow-up work,
//! not done here.

use std::convert::Infallible;
use std::future::Future;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
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

/// Hard per-limiter entry ceiling (see the module doc's "Bounded state"
/// section). Generous enough that no legitimate deployment's active-client
/// count ever approaches it, tight enough that a flood of distinct keys
/// cannot grow a limiter map past a bounded, predictable footprint.
const KEY_CEILING: usize = 100_000;

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

/// A [`KeyedLimiter`] wrapped with a hard SIZE ceiling ([`KEY_CEILING`]), on
/// top of `governor`'s own TIME-based `retain_recent` sweep (see the module
/// doc's "Bounded state" section for why the time sweep alone is
/// insufficient). `governor` exposes no way to remove a single key from a
/// keyed state store -- only the global `retain_recent` / `len` / `is_empty`
/// trio -- so the only `&self`-compatible way to bound the map's size is to
/// replace the whole inner limiter once it is still oversized after the time
/// sweep. The inner limiter lives behind a `RwLock` so [`Fences::maybe_sweep`]
/// (called from many concurrent request-handling tasks, all holding only a
/// shared `&Fences`) can perform that replacement without `&mut self`.
struct BoundedLimiter<K: Hash + Eq + Clone> {
    inner: RwLock<KeyedLimiter<K>>,
    quota: Quota,
}

impl<K: Hash + Eq + Clone> BoundedLimiter<K> {
    fn new(quota: Quota) -> Self {
        Self {
            inner: RwLock::new(RateLimiter::keyed(quota)),
            quota,
        }
    }

    /// Check one cell for `key`. `Err` means the bucket is exhausted; the
    /// caller only distinguishes success from failure, so the specific
    /// `governor` outcome type stays internal to this wrapper.
    fn check_key(&self, key: &K) -> Result<(), ()> {
        self.inner
            .read()
            .expect("limiter lock poisoned")
            .check_key(key)
            .map_err(|_| ())
    }

    /// Drop keys whose buckets are fully replenished (the TIME sweep).
    fn retain_recent(&self) {
        self.inner
            .read()
            .expect("limiter lock poisoned")
            .retain_recent();
    }

    /// The current live-key count.
    fn len(&self) -> usize {
        self.inner.read().expect("limiter lock poisoned").len()
    }

    /// The SIZE-ceiling backstop: if the map still exceeds [`KEY_CEILING`]
    /// after [`retain_recent`](Self::retain_recent), reset it to a fresh
    /// limiter of the same quota. Re-checks under the write lock (a second
    /// caller may have already reset the map between the read-locked
    /// over-ceiling check and acquiring the write lock), so a benign race
    /// never resets twice in a row for one overshoot.
    fn evict_if_over_ceiling(&self) {
        if self.len() > KEY_CEILING {
            let mut guard = self.inner.write().expect("limiter lock poisoned");
            if guard.len() > KEY_CEILING {
                *guard = RateLimiter::keyed(self.quota);
            }
        }
    }
}

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
    per_ip: BoundedLimiter<IpAddr>,
    /// Per-operation buckets, each keyed on peer IP.
    read: BoundedLimiter<IpAddr>,
    push: BoundedLimiter<IpAddr>,
    login: BoundedLimiter<IpAddr>,
    revoke: BoundedLimiter<IpAddr>,
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
            per_ip: BoundedLimiter::new(quota(limits.per_ip)),
            read: BoundedLimiter::new(quota(limits.read)),
            push: BoundedLimiter::new(quota(limits.push)),
            login: BoundedLimiter::new(quota(limits.login)),
            revoke: BoundedLimiter::new(quota(limits.revoke)),
            max_body_bytes: limits.max_body_bytes,
            count_quota: limits.count_quota,
            sweeps: AtomicU64::new(0),
        }
    }

    /// The per-operation limiter for `op`, or `None` for an unclassified route
    /// (still covered by the per-IP fence).
    fn op_limiter(&self, op: Op) -> Option<&BoundedLimiter<IpAddr>> {
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
    /// absent), then reset any map still over [`KEY_CEILING`]. This is what
    /// makes the key maps -- and thus the fences' memory -- bounded rather
    /// than a self-DoS, against both an idle-client backlog (the time sweep)
    /// and a flood of distinct, never-replenished keys (the size ceiling).
    fn maybe_sweep(&self) {
        if self.sweeps.fetch_add(1, Ordering::Relaxed) % SWEEP_INTERVAL == 0 {
            for limiter in [
                &self.per_ip,
                &self.read,
                &self.push,
                &self.login,
                &self.revoke,
            ] {
                limiter.retain_recent();
                limiter.evict_if_over_ceiling();
            }
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
    // bytes), peek the principal, then apply the hard count quota. No
    // per-principal RATE fence here -- see the module doc's "The fences"
    // section for why keying a rate bucket on the peeked, unverified
    // `principal_id` would be attacker-nameable.
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

        // This reads `commit_count` BEFORE the handler's own increment (the
        // commit that follows this check is what would push the count over),
        // so N concurrent same-principal pushes can each observe the
        // pre-increment count and all pass, overshooting `count_quota` by up
        // to that burst -- a bounded soft overshoot, not an unbounded one.
        // Closing it exactly (an atomic check-and-increment) is a
        // storage-engine concern: it needs a transactional read-then-write
        // over `commit_count`, which this fence -- reduced to a stateless
        // `u64` probe by design (see the module doc) -- cannot provide.
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

    /// WHITE-BOX bounded-state invariant: every keyed limiter map carries a
    /// hard max-entry ceiling (`KEY_CEILING`), not just `governor`'s
    /// `retain_recent` TIME sweep (which drops fully-replenished buckets but
    /// never bounds a flood of distinct, never-replenished keys -- e.g. a
    /// distributed or IPv6-rotation attack). After inserting more than
    /// `KEY_CEILING` distinct keys and running the bounded-state maintenance,
    /// the map must retain at most `KEY_CEILING` entries (see
    /// [`BoundedLimiter::evict_if_over_ceiling`]).
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
