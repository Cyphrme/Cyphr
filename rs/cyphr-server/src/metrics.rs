//! Operability surface: request/refusal/push counters (`GET /metrics`) and
//! the storage liveness probe behind `GET /healthz`.
//!
//! Counters follow the Prometheus text exposition format
//! (<https://prometheus.io/docs/instrumenting/exposition_formats/>) and its
//! `_total` counter naming convention. Every series is a fixed atomic
//! slot: the label set is a closed enum derived from the response status,
//! never from the URI, a principal id, a key, or any request content, so
//! neither a leak nor unbounded series growth is representable.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

/// Closed set of refusal kinds, one series each. Derived from the response
/// status only, so a client cannot mint new series.
#[derive(Clone, Copy)]
enum RefusalKind {
    BadRequest,
    Denied,
    NotFound,
    Conflict,
    TooLarge,
    Unprocessable,
    RateLimited,
    ServerError,
}

impl RefusalKind {
    const ALL: [Self; 8] = [
        Self::BadRequest,
        Self::Denied,
        Self::NotFound,
        Self::Conflict,
        Self::TooLarge,
        Self::Unprocessable,
        Self::RateLimited,
        Self::ServerError,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TooLarge => "too_large",
            Self::Unprocessable => "unprocessable",
            Self::RateLimited => "rate_limited",
            Self::ServerError => "server_error",
        }
    }

    /// `None` for a non-refusal (1xx-3xx, 2xx). Any other 4xx folds into
    /// `BadRequest` so the set stays closed.
    fn of(status: StatusCode) -> Option<Self> {
        match status.as_u16() {
            401 | 403 => Some(Self::Denied),
            404 => Some(Self::NotFound),
            409 => Some(Self::Conflict),
            413 => Some(Self::TooLarge),
            422 => Some(Self::Unprocessable),
            429 => Some(Self::RateLimited),
            400..=499 => Some(Self::BadRequest),
            500..=599 => Some(Self::ServerError),
            _ => None,
        }
    }
}

/// Process-lifetime counters. Relaxed atomics: each counter is independent
/// and monotone, and a scrape needs no cross-counter ordering.
#[derive(Default)]
pub struct Metrics {
    requests: AtomicU64,
    pushes_accepted: AtomicU64,
    refusals: [AtomicU64; RefusalKind::ALL.len()],
}

impl Metrics {
    fn record(&self, method: &Method, path: &str, status: StatusCode) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if status.is_success() && method == Method::POST && path == "/push" {
            self.pushes_accepted.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(kind) = RefusalKind::of(status) {
            self.refusals[kind as usize].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render the Prometheus text exposition.
    pub fn render(&self) -> String {
        let mut out = String::new();
        // `write!` into a `String` is infallible; the results are discarded.
        let _ = writeln!(
            out,
            "# HELP cyphr_requests_total Requests answered.\n# TYPE cyphr_requests_total \
             counter\ncyphr_requests_total {}",
            self.requests.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP cyphr_pushes_accepted_total Pushes answered 2xx.\n# TYPE \
             cyphr_pushes_accepted_total counter\ncyphr_pushes_accepted_total {}",
            self.pushes_accepted.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP cyphr_refusals_total Requests answered 4xx/5xx, by kind.\n# TYPE \
             cyphr_refusals_total counter"
        );
        for kind in RefusalKind::ALL {
            let _ = writeln!(
                out,
                "cyphr_refusals_total{{kind=\"{}\"}} {}",
                kind.label(),
                self.refusals[kind as usize].load(Ordering::Relaxed)
            );
        }
        out
    }
}

/// Outermost middleware: counts every response, including those produced
/// by the admission and rate-limit layers inside it.
pub async fn count(
    State(state): State<std::sync::Arc<crate::AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    state.metrics.record(&method, &path, resp.status());
    resp
}

/// Single-flight storage write probe for `/healthz`.
///
/// Reads cannot detect a destroyed store (open descriptors keep answering),
/// and neither can an insert into an already-open keyspace (it lands in the
/// unlinked journal), so liveness is two writes that must both succeed: one
/// fixed key in a dedicated `healthz` keyspace (catches a poisoned or
/// failing engine), and one fixed-name, fixed-content sentinel file in the
/// record directory, synced (catches a vanished, read-only, or full
/// directory). Keys, values and file name are constants, so the probe is
/// idempotent, bounded to a few bytes, and touches no blob, commit, or
/// principal data.
///
/// Cost control for an unauthenticated caller: probes never run
/// concurrently. A caller that arrives while one is in flight adopts that
/// probe's result instead of issuing its own, so write rate is bounded by
/// one disk sync at a time regardless of request rate (the per-IP fence
/// still applies on top). No TTL cache: a stale "healthy" is exactly the
/// defect the probe exists to avoid.
pub struct HealthProbe {
    db: fjall::Database,
    keyspace: fjall::Keyspace,
    sentinel: std::path::PathBuf,
    gate: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    last_ok: AtomicBool,
}

impl HealthProbe {
    /// Open the sentinel keyspace on the record database.
    pub fn open(db: fjall::Database, record_dir: &std::path::Path) -> Result<Self, fjall::Error> {
        let keyspace = db.keyspace("healthz", fjall::KeyspaceCreateOptions::default)?;
        Ok(Self {
            db,
            keyspace,
            sentinel: record_dir.join("healthz.probe"),
            gate: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            last_ok: AtomicBool::new(true),
        })
    }

    /// Whether the record store accepted a durable write just now (or
    /// within the in-flight probe this call coalesced into).
    pub async fn storage_writable(&self) -> bool {
        let seen = self.generation.load(Ordering::Acquire);
        let _turn = self.gate.lock().await;
        if self.generation.load(Ordering::Acquire) != seen {
            return self.last_ok.load(Ordering::Acquire);
        }
        let (db, keyspace, sentinel) = (
            self.db.clone(),
            self.keyspace.clone(),
            self.sentinel.clone(),
        );
        let ok = tokio::task::spawn_blocking(move || {
            keyspace.insert("probe", "1").is_ok()
                && db.persist(fjall::PersistMode::SyncAll).is_ok()
                && std::fs::write(&sentinel, b"1").is_ok()
        })
        .await
        .unwrap_or(false);
        self.last_ok.store(ok, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        ok
    }
}
