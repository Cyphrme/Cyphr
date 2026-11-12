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

    /// Render the Prometheus text exposition. `eml_append_failures` is the
    /// storage engine's own count of commits whose log append failed after
    /// the commit was stored; the engine owns it, so it is passed in.
    pub fn render(&self, eml_append_failures: u64) -> String {
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
        let _ = writeln!(
            out,
            "# HELP cyphr_eml_append_failures_total Commits stored whose commit-log append failed \
             (repaired by the next load).\n# TYPE cyphr_eml_append_failures_total \
             counter\ncyphr_eml_append_failures_total {eml_append_failures}"
        );
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

/// Why a health probe failed: which step, and the underlying cause. Logged
/// server-side only; the HTTP response stays generic.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// The sentinel file could not be written.
    #[error("writing sentinel {path}: {source}")]
    Sentinel {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// The blocking probe task did not complete.
    #[error("probe task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

type ProbeFn = dyn Fn() -> Result<(), ProbeError> + Send + Sync;

/// Single-flight storage write probe for `/healthz`.
///
/// Reads cannot detect a destroyed store (open descriptors keep answering),
/// and neither can an insert into an already-open database (it lands in the
/// unlinked journal), so liveness is a write into the record directory
/// itself: one fixed-name, fixed-content sentinel file. It fails when the
/// directory has vanished or is not writable. It is not fsynced, so it does
/// not claim to detect a full disk or a failing device; those surface on
/// the real write path. The name and content are constants, so the probe
/// is idempotent, one byte, and touches no blob, commit, or principal
/// data.
///
/// Cost control for an unauthenticated caller: probes never run
/// concurrently. A caller that arrives while one is in flight adopts that
/// probe's result instead of issuing its own, so write rate is bounded by
/// one tiny write at a time regardless of request rate (the per-IP fence
/// applies on top). No TTL cache: a stale "healthy" is exactly the defect
/// the probe exists to avoid.
pub struct HealthProbe {
    run: std::sync::Arc<ProbeFn>,
    gate: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    last_ok: AtomicBool,
}

impl HealthProbe {
    /// A probe that writes `<record_dir>/healthz.probe`.
    pub fn new(record_dir: &std::path::Path) -> Self {
        let sentinel = record_dir.join("healthz.probe");
        Self::with_probe(move || {
            std::fs::write(&sentinel, b"1").map_err(|source| ProbeError::Sentinel {
                path: sentinel.clone(),
                source,
            })
        })
    }

    fn with_probe(run: impl Fn() -> Result<(), ProbeError> + Send + Sync + 'static) -> Self {
        Self {
            run: std::sync::Arc::new(run),
            gate: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            last_ok: AtomicBool::new(true),
        }
    }

    /// Whether the record directory accepted a write just now (or within
    /// the in-flight probe this call coalesced into). Failure causes are
    /// logged here with the step that failed.
    pub async fn storage_writable(&self) -> bool {
        let seen = self.generation.load(Ordering::Acquire);
        let _turn = self.gate.lock().await;
        if self.generation.load(Ordering::Acquire) != seen {
            return self.last_ok.load(Ordering::Acquire);
        }
        let run = self.run.clone();
        let outcome = match tokio::task::spawn_blocking(move || run()).await {
            Ok(result) => result,
            Err(join) => Err(ProbeError::from(join)),
        };
        if let Err(err) = &outcome {
            tracing::error!(error = %err, "healthz probe failed");
        }
        let ok = outcome.is_ok();
        self.last_ok.store(ok, Ordering::Release);
        self.generation.fetch_add(1, Ordering::AcqRel);
        ok
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Claim: concurrent `/healthz` callers coalesce into few probes and
    /// never overlap, which is the unauthenticated-caller write bound.
    /// Turns red if coalescing is removed (every caller probes) or the
    /// gate is removed (probes overlap). A unit test because the router
    /// cannot count probes. 16 callers vs a 50ms probe.
    #[tokio::test]
    async fn concurrent_callers_coalesce_and_never_overlap() {
        let runs = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let probe = Arc::new(HealthProbe::with_probe({
            let (runs, in_flight, max) = (runs.clone(), in_flight.clone(), max_in_flight.clone());
            move || {
                runs.fetch_add(1, Ordering::SeqCst);
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(50));
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        }));

        let calls = (0..16).map(|_| {
            let probe = probe.clone();
            tokio::spawn(async move { probe.storage_writable().await })
        });
        for ok in futures::future::join_all(calls).await {
            assert!(ok.expect("caller task"), "healthy probe answers true");
        }

        assert_eq!(max_in_flight.load(Ordering::SeqCst), 1, "probes overlapped");
        assert!(
            runs.load(Ordering::SeqCst) <= 2,
            "16 concurrent callers ran {} probes; coalescing is broken",
            runs.load(Ordering::SeqCst)
        );
    }
}
