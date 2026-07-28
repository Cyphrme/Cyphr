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
//! Each keyed limiter is a `moka` size-bounded concurrent cache
//! (`moka::sync::Cache`) of one per-key `governor` DIRECT rate limiter per
//! resident key, capped at [`KEY_CEILING`] entries. Eviction is continuous:
//! every insert past the cap evicts the single COLDEST (least-recently/least-
//! frequently used) entry, so the map never needs an external sweep to stay
//! bounded -- unlike a bulk-only store (`governor`'s own keyed state store
//! exposes no per-key removal, only a global `retain_recent`/`len`), which
//! could only bound itself by periodically resetting the WHOLE map.
//!
//! Coldest-key eviction is consequence-free, not merely accepted: a re-
//! entering evicted key simply gets a fresh full bucket on its next request --
//! the same LOOSENING a whole-map reset produced, but now scoped to the one
//! key that was actually cold, never to a key still being hammered. A HOT
//! key -- one recently and repeatedly checked, as an abuser's key is by
//! definition -- accrues a high recency/frequency signal and is therefore
//! never the coldest resident entry, so it SURVIVES a flood of `> KEY_CEILING`
//! distinct cold keys that would previously have forced a whole-map reset and
//! cleared it too. Eviction still only ever loosens (a fresh bucket for
//! whichever key was evicted), never manufactures a spurious refusal against
//! any other key.

use std::convert::Infallible;
use std::future::Future;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::header::CONTENT_LENGTH;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::future::BoxFuture;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use moka::sync::Cache;
use serde::Deserialize;
use tower::{Layer, Service};

use crate::config::{LimitsConfig, RateBucket};
use crate::envelope::Envelope;

/// Hard per-limiter entry ceiling: the `moka` cache capacity backing each
/// [`BoundedLimiter`] (see the module doc's "Bounded state" section).
/// Generous enough that no legitimate deployment's active-client count ever
/// approaches it, tight enough that a flood of distinct keys cannot grow a
/// limiter's resident set past a bounded, predictable footprint.
const KEY_CEILING: usize = 100_000;

/// A commit-count probe: given a principal id, resolve how many commits it
/// currently has. The sole storage fact the quota fence reads, reduced to a
/// `u64` so no protocol type crosses into this module. A probe failure
/// resolves to `0` (under any quota) -- an index blip never fabricates a quota
/// refusal of legitimate traffic; the fence only ever refuses on a *known*
/// over-cap count.
pub type CountProbe = Arc<dyn Fn(String) -> BoxFuture<'static, u64> + Send + Sync>;

/// A single-key `governor` DIRECT (un-keyed) rate limiter -- the per-key cell
/// [`BoundedLimiter`] stores one of per resident key.
type DirectLimiter = DefaultDirectRateLimiter;

/// A size-bounded store of per-key `governor` DIRECT rate limiters, capped at
/// [`KEY_CEILING`] resident keys (see the module doc's "Bounded state"
/// section). Backed by `moka::sync::Cache`: a concurrent, lock-free hot path
/// with continuous, per-insert eviction of the single coldest entry once at
/// capacity -- unlike a plain `RwLock<LruCache>`, which would serialize
/// `check_key` on one global lock (LRU recency mutates on every read).
struct BoundedLimiter<K: Hash + Eq + Clone + Send + Sync + 'static> {
    cache: Cache<K, Arc<DirectLimiter>>,
    quota: Quota,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> BoundedLimiter<K> {
    fn new(quota: Quota) -> Self {
        Self {
            cache: Cache::builder().max_capacity(KEY_CEILING as u64).build(),
            quota,
        }
    }

    /// Check one cell for `key`, creating a fresh per-key direct limiter on
    /// first sight (get-or-insert, atomic under concurrent same-key
    /// callers -- `moka::sync::Cache::get_with` runs the init closure at
    /// most once per key even under a concurrent stampede). Insertion past
    /// [`KEY_CEILING`] evicts the coldest resident key; that eviction never
    /// touches `key`'s own bucket. `Err` means the bucket is exhausted; the
    /// caller only distinguishes success from failure, so the specific
    /// `governor` outcome type stays internal to this wrapper.
    fn check_key(&self, key: &K) -> Result<(), ()> {
        let limiter = self
            .cache
            .get_with(key.clone(), || Arc::new(RateLimiter::direct(self.quota)));
        limiter.check().map(|_| ()).map_err(|_| ())
    }

    /// The current resident-key count. Forces `moka`'s internal housekeeping
    /// to run first: `entry_count` alone is an eventually-consistent
    /// estimate (see `moka::sync::Cache::entry_count`'s own documentation)
    /// that can lag behind concurrent inserts and evictions. Test-only: no
    /// production call site needs the resident count.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.cache.run_pending_tasks();
        self.cache.entry_count() as usize
    }
}

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
}

/// Translate a configured `{ per_second, burst }` bucket into a `governor`
/// quota: one cell replenished every `1s / per_second`, up to `burst` capacity.
/// Both fields are clamped to at least 1 so a misconfigured `0` becomes the
/// tightest live bucket rather than a panic. Deliberately a silent LOOSENING,
/// unlike `max_body_bytes == 0` / `count_quota == 0` (rejected loudly at
/// startup -- see `config::resolve_config`): a clamped-tightest bucket still
/// serves traffic, just very strictly, so it never bricks writes and is
/// clamped rather than refused.
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
        Json(Envelope::unsigned(
            serde_json::json!({ "error": "rate limit exceeded" }),
        )),
    )
        .into_response()
}

/// A size-cap refusal: `413` naming the byte limit.
fn too_large(limit: u64) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(Envelope::unsigned(serde_json::json!({
            "error": "request body too large",
            "limit_bytes": limit,
        }))),
    )
        .into_response()
}

/// A count-quota refusal: a distinct `402` (deliberately neither the `429` of a
/// rate fence nor the `403` of admission) naming the commit limit, so a client
/// can tell a resource-quota refusal from a rate throttle or an admission deny.
fn quota_exceeded(limit: u64) -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        Json(Envelope::unsigned(serde_json::json!({
            "error": "per-principal commit quota exhausted",
            "limit_commits": limit,
        }))),
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
    use governor::clock::DefaultClock;
    use governor::state::keyed::DefaultKeyedStateStore;

    use super::*;

    /// A keyed `governor` limiter over key `K`, backed by the default
    /// (DashMap) keyed state store and default clock. Exercises `governor`'s
    /// own keyed bucket behavior directly, in isolation from
    /// [`BoundedLimiter`]'s `moka`-backed store.
    type KeyedLimiter<K> = RateLimiter<K, DefaultKeyedStateStore<K>, DefaultClock>;

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

    /// WHITE-BOX bounded-state invariant: every keyed limiter carries a hard
    /// max-entry ceiling (`KEY_CEILING`) enforced continuously by `moka` on
    /// every insert, not just an amortized sweep -- so even a flood of
    /// distinct, never-repeated keys (e.g. a distributed or IPv6-rotation
    /// attack, which no time-based staleness check alone can bound) never
    /// grows the map past `KEY_CEILING` resident entries.
    #[test]
    fn keyed_limiter_map_is_bounded_by_key_ceiling() {
        use std::net::Ipv6Addr;

        let fences = Fences::from_config(&LimitsConfig::default());

        // Flood the per-IP map with distinct, never-seen keys. `moka` evicts
        // the coldest resident key inline on each insert past capacity --
        // no external sweep to drive.
        for i in 0..(KEY_CEILING as u128 + 1_000) {
            let ip = IpAddr::V6(Ipv6Addr::from(i));
            let _ = fences.per_ip.check_key(&ip);
        }

        assert!(
            fences.per_ip.len() <= KEY_CEILING,
            "the per-IP limiter map must stay within KEY_CEILING ({}) entries under a flood of \
             distinct keys, got {}",
            KEY_CEILING,
            fences.per_ip.len(),
        );
    }

    /// A HOT key's accumulated throttle must SURVIVE a flood of distinct
    /// COLD keys. The prior whole-map ceiling reset (see git history) wiped
    /// EVERY bucket -- including a currently-throttled hot key -- once the
    /// map was still over `KEY_CEILING` after a time sweep, so an attacker
    /// who floods `> KEY_CEILING` distinct cold keys could force a reset
    /// that freed a concurrently-hammered hot key. Per-key eviction closes
    /// that gap: `moka` evicts only the single coldest resident entry on
    /// each insert past capacity, so a key that stays recently- and
    /// repeatedly-touched is never the eviction victim. This test drives
    /// the exact per-request path production runs (`check_key`, which
    /// resolves and evicts inline) directly on a `BoundedLimiter`.
    #[test]
    fn hot_key_throttle_survives_cold_key_flood() {
        use std::net::Ipv6Addr;

        // Exhaustible quota so H trips fast. The periodic "keep H warm"
        // touches below run ~399 times over the flood -- far more than
        // HOT_BURST -- so they would just as readily re-exhaust a bucket
        // that eviction had reset to fresh. Burst size buys no protection
        // against that; the assertion holds only because per-key eviction
        // keeps H recently-touched and therefore never the eviction victim,
        // so its exhausted bucket is the one that survives, never a reset one.
        const HOT_BURST: u32 = 64;
        let lim = BoundedLimiter::new(quota(RateBucket {
            per_second: 1,
            burst: HOT_BURST,
        }));
        let hot = IpAddr::from([10, 0, 0, 1]);

        // 1. Exhaust H's bucket; confirm it is now throttled (guard
        // assertion -- proves the premise before the flood).
        for _ in 0..HOT_BURST {
            let _ = lim.check_key(&hot);
        }
        assert!(
            lim.check_key(&hot).is_err(),
            "baseline: H must be throttled after exhausting its burst"
        );

        // 2. Flood > KEY_CEILING distinct cold IPv6 keys, interleaving
        // periodic touches of H (models an attacker hammering H while
        // flooding fillers, so H stays recently-used). `moka` evicts the
        // coldest resident key inline on each `check_key` insert past
        // capacity -- the exact per-request path production runs, no
        // external sweep to drive.
        let flood = KEY_CEILING as u128 + 2_000;
        for i in 0..flood {
            let cold = IpAddr::V6(Ipv6Addr::from(
                0xfd00_0000_0000_0000_0000_0000_0000_0000u128 + i,
            ));
            let _ = lim.check_key(&cold);
            if i % 256 == 0 {
                let _ = lim.check_key(&hot); // keep H warm
            }
        }

        // 3. Before per-key eviction, a whole-map reset would have cleared H
        // along with the cold keys, so `check_key(&hot)` would come back
        // `Ok`. With per-key eviction, H was never the coldest/least-
        // recently-used key, so it is never the eviction victim and stays
        // throttled.
        assert!(
            lim.check_key(&hot).is_err(),
            "H must STAY throttled across a cold-key flood -- a per-key store must not reset the \
             hot key when evicting cold keys"
        );

        // The entry ceiling bounds memory: the live map size stays at or
        // below the cap.
        assert!(
            lim.len() <= KEY_CEILING,
            "map stays size-bounded under the flood, got {}",
            lim.len()
        );

        // Eviction only ever loosens: a fresh, never-before-seen key is
        // admitted, never spuriously refused.
        let fresh = IpAddr::from([10, 0, 0, 2]);
        assert!(
            lim.check_key(&fresh).is_ok(),
            "eviction never manufactures a spurious refusal against fresh traffic"
        );
    }
}
