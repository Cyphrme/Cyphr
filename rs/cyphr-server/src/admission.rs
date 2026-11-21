//! Server-side admission FENCE (orthogonal to the protocol).
//!
//! Admission gates the single unauthenticated resource-acquisition event --
//! a brand-new principal taking up residency via `POST /push` -- and nothing
//! else. It is a tower layer composed only in [`crate::serve`], never in
//! `build_router`, so the protocol handlers never learn admission exists: the
//! strip test (delete this layer, a correct self-bootstrapping server remains)
//! holds by construction.
//!
//! Orthogonality is compiler-checked: this module imports NO `cyphr::*` or
//! `coz::*` protocol type. The one protocol fact it needs -- does a principal
//! already have a resident tip -- crosses the boundary as a `bool` through the
//! [`ResidentProbe`] closure defined in `serve()`, so the storage engine type
//! never enters here. The layer can only *refuse* service (fail-open on
//! ambiguity); it has no path that admits, validates, or mutates protocol
//! state.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::Json;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use futures::future::BoxFuture;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower::{Layer, Service};

use crate::config::AdmissionConfig;
use crate::envelope::Envelope;
use crate::observation::{
    DurabilityLost, STORE_FORMAT_VERSION, StampError, SyncLatch, check_store_version,
};

/// Header carrying the opaque, out-of-band invite token.
const INVITE_HEADER: &str = "x-cyphr-invite";

/// Spent-set marker for a reserved (in-flight) token hash.
const STATE_RESERVED: &[u8] = b"R";
/// Spent-set marker for a consumed (observed-2xx) token hash.
const STATE_CONSUMED: &[u8] = b"C";

/// A residency probe: given a principal id, resolve whether it already has a
/// resident tip. The sole protocol fact admission reads, reduced to a `bool`
/// so no protocol type crosses into this module.
pub type ResidentProbe = Arc<dyn Fn(String) -> BoxFuture<'static, bool> + Send + Sync>;

/// Failures constructing or operating the admission fence.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// The deployment invite-tokens file could not be read.
    #[error("reading invite tokens file {path}: {source}")]
    TokensRead {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The deployment invite-tokens file could not be written (admin command).
    #[error("writing invite tokens file {path}: {source}")]
    TokensWrite {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A line in the tokens file is not a 64-hex-char sha256 hash.
    #[error("invite tokens file {path} line {line}: expected 64 hex chars (a sha256 token hash)")]
    TokensParse { path: PathBuf, line: usize },

    /// The spent-set fjall store failed.
    #[error("admission store backend: {0}")]
    Backend(String),

    /// A `spawn_blocking` store task failed to join.
    #[error("admission store task join: {0}")]
    Join(String),

    /// A sync of the spent set failed; it refuses every write until restart.
    #[error("admission store durability lost: {0}")]
    DurabilityLost(String),

    /// The spent-set store records a format version this build does not
    /// read. Nothing was read from it: a mis-decoded spent set would let a
    /// consumed single-use token be spent again.
    #[error("spent set format version {found} is not the supported {supported}")]
    UnsupportedVersion { found: u64, supported: u32 },
}

impl From<DurabilityLost> for AdmissionError {
    fn from(e: DurabilityLost) -> Self {
        Self::DurabilityLost(e.0)
    }
}

impl From<StampError> for AdmissionError {
    fn from(e: StampError) -> Self {
        match e {
            StampError::Backend(m) => Self::Backend(m),
            StampError::NotANumber(t) => {
                Self::Backend(format!("recorded format version is not a number: {t:?}"))
            },
            StampError::Unsupported { found } => Self::UnsupportedVersion {
                found,
                supported: STORE_FORMAT_VERSION,
            },
        }
    }
}

fn backend(e: fjall::Error) -> AdmissionError {
    AdmissionError::Backend(e.to_string())
}

/// Build the admission layer for `config`, or `Ok(None)` for `Open` (the
/// layer is *absent*, not an always-pass middleware).
///
/// `resident` is the residency probe captured from `serve()`'s state.
/// `max_body_bytes` is the deployer's configured `[limits] max_body_bytes` --
/// the same single authoritative body cap enforced on every other route --
/// so a genesis push is bounded by the deployer's own knob, never a private
/// admission constant.
///
/// `record_dir` is the `record/` subtree (ADR-0002 Decision 1), not the bare
/// data directory: the spent-set is told state the server cannot recover if
/// lost, so it lives beside `blobs/`, `observations/`, and
/// `server-principal.json` under `record/`, never beside the disposable
/// `index/`.
pub fn layer(
    config: &AdmissionConfig,
    record_dir: &Path,
    resident: ResidentProbe,
    max_body_bytes: usize,
    health: &crate::metrics::HealthProbe,
) -> Result<Option<AdmissionLayer>, AdmissionError> {
    let policy = match config {
        AdmissionConfig::Open => return Ok(None),
        AdmissionConfig::Invite { tokens_path } => {
            let hashes = load_token_hashes(tokens_path)?;
            let spent = SpentSet::open(&record_dir.join("admission"))?;
            health.watch(spent.latch.clone());
            Policy::Invite { hashes, spent }
        },
    };
    let gate = Gate {
        resident,
        policy,
        max_body_bytes,
    };
    Ok(Some(AdmissionLayer {
        gate: Arc::new(gate),
    }))
}

/// Generate `count` fresh invite tokens, append their `sha256` hashes to
/// `tokens_path` (creating it if absent), and return the plaintext tokens for
/// the deployer to distribute. The plaintext is never persisted server-side.
pub fn issue_tokens(tokens_path: &Path, count: usize) -> Result<Vec<String>, AdmissionError> {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut plaintexts = Vec::with_capacity(count);
    let mut lines = String::new();
    for _ in 0..count {
        let mut raw = [0u8; 24];
        rng.fill_bytes(&mut raw);
        let token = hex_encode(&raw);
        let hash = sha256(token.as_bytes());
        writeln!(lines, "{}", hex_encode(&hash)).expect("writing to a String cannot fail");
        plaintexts.push(token);
    }

    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(tokens_path)
        .map_err(|source| AdmissionError::TokensWrite {
            path: tokens_path.to_path_buf(),
            source,
        })?;
    file.write_all(lines.as_bytes())
        .map_err(|source| AdmissionError::TokensWrite {
            path: tokens_path.to_path_buf(),
            source,
        })?;
    Ok(plaintexts)
}

// ========================================================================
// The fence gate
// ========================================================================

/// The admission decision state, shared behind an `Arc` across all cloned
/// service instances.
struct Gate {
    /// Residency probe (a resident principal bypasses admission).
    resident: ResidentProbe,
    /// The active policy and its per-policy state.
    policy: Policy,
    /// The deployer's configured `[limits] max_body_bytes` -- the single
    /// authoritative body cap, enforced here exactly as on every other route.
    max_body_bytes: usize,
}

/// The active admission policy. `Open` installs no layer, so it never reaches
/// here; only the enforcing policies carry runtime state.
enum Policy {
    /// Single-use invite tokens over a durable spent-set.
    Invite {
        /// `sha256(token)` for every deployment-issued token.
        hashes: Vec<[u8; 32]>,
        /// Durable single-use spent-set.
        spent: SpentSet,
    },
}

impl Gate {
    /// Apply the fence to `req`, delegating to `inner` on a pass.
    async fn handle<S>(&self, req: Request, inner: &mut S) -> Response
    where
        S: Service<Request, Response = Response, Error = Infallible>,
        S::Future: Send,
    {
        // (1) Only a new-principal genesis push is gated.
        if req.method() != Method::POST || req.uri().path() != "/push" {
            return call_inner(inner, req).await;
        }

        // (2) Buffer the body to peek `principal_id`, then restore it. Bound
        // by the deployer's configured `max_body_bytes`, not a private
        // constant -- the handler's own body limit enforces the same cap, so
        // this never refuses a body the rest of the stack would accept.
        let (parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, self.max_body_bytes).await {
            Ok(bytes) => bytes,
            Err(_) => return refuse(StatusCode::PAYLOAD_TOO_LARGE, "push body too large"),
        };
        let principal_id = peek_principal_id(&bytes);
        let req = Request::from_parts(parts, Body::from(bytes));

        // Absent/unparseable `principal_id`: nothing to gate. Fail open -- the
        // handler's own full parse rejects it and no state is created.
        let Some(id) = principal_id else {
            return call_inner(inner, req).await;
        };

        // (3) An already-resident principal is bound to its chain by the
        // protocol; admission never fires for it.
        if (self.resident)(id).await {
            return call_inner(inner, req).await;
        }

        // (4) A new principal -- apply the active policy.
        match &self.policy {
            Policy::Invite { hashes, spent } => admit_invite(hashes, spent, req, inner).await,
        }
    }
}

/// Whether `hash` matches any deployment token hash, in constant time
/// (data-independent over the secret: every entry is compared, no early exit,
/// no length branch).
fn is_known(hashes: &[[u8; 32]], hash: &[u8; 32]) -> bool {
    let mut found = subtle::Choice::from(0u8);
    for known in hashes {
        found |= hash.as_slice().ct_eq(known.as_slice());
    }
    bool::from(found)
}

/// Invite policy for a new principal: a valid, unspent token admits; anything
/// else is a 403 naming the policy. Reserve on admit, consume on an observed
/// 2xx, refund on a non-2xx.
async fn admit_invite<S>(
    hashes: &[[u8; 32]],
    spent: &SpentSet,
    req: Request,
    inner: &mut S,
) -> Response
where
    S: Service<Request, Response = Response, Error = Infallible>,
    S::Future: Send,
{
    let token = req
        .headers()
        .get(INVITE_HEADER)
        .and_then(|value| value.to_str().ok());
    let Some(token) = token else {
        return denied_invite();
    };
    let hash = sha256(token.as_bytes());
    if !is_known(hashes, &hash) {
        return denied_invite();
    }

    match spent.reserve(hash).await {
        Ok(true) => {},
        // Already reserved or consumed: single-use is spent.
        Ok(false) => return denied_invite(),
        // A store failure must never admit; refuse honestly (infra fault,
        // not a missing invite).
        Err(e) => {
            tracing::error!(error = %e, "admission spent-set reserve failed");
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "admission store unavailable",
            );
        },
    }

    let response = call_inner(inner, req).await;
    if response.status().is_success() {
        if let Err(e) = spent.consume(hash).await {
            // The token is already durably reserved, so it stays spent;
            // only the audit refinement to `consumed` was lost.
            tracing::error!(error = %e, "admission spent-set consume failed");
        }
    } else if let Err(e) = spent.refund(hash).await {
        // Refund failed: the token stays reserved (stranded spent). Safe
        // direction -- it can never be double-spent, only lost.
        tracing::error!(error = %e, "admission spent-set refund failed");
    }
    response
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

/// An invite-policy denial: 403 (never 401 -- this is not an authentication
/// failure) whose JSON body names the policy.
fn denied_invite() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(Envelope::unsigned(serde_json::json!({
            "error": "admission required",
            "policy": "invite",
        }))),
    )
        .into_response()
}

/// A non-denial refusal on a transport/infrastructure fact.
fn refuse(status: StatusCode, error: &str) -> Response {
    (
        status,
        Json(Envelope::unsigned(serde_json::json!({ "error": error }))),
    )
        .into_response()
}

/// One-field peek at the wire `PushRequest` shape, using the same serde
/// discipline as the handler so the layer and the handler agree on what a
/// parseable `principal_id` is.
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

/// The admission tower layer. Cheap to clone (shares the [`Gate`]).
#[derive(Clone)]
pub struct AdmissionLayer {
    gate: Arc<Gate>,
}

impl<S> Layer<S> for AdmissionLayer {
    type Service = AdmissionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AdmissionService {
            inner,
            gate: self.gate.clone(),
        }
    }
}

/// The admission tower service wrapping the inner router service.
#[derive(Clone)]
pub struct AdmissionService<S> {
    inner: S,
    gate: Arc<Gate>,
}

impl<S> Service<Request> for AdmissionService<S>
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
        let gate = self.gate.clone();
        // Readiness was checked on `self.inner`; move that ready clone into the
        // future and leave a fresh (not-yet-ready) clone behind.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        Box::pin(async move { Ok(gate.handle(req, &mut inner).await) })
    }
}

// ========================================================================
// Durable single-use spent-set
// ========================================================================

/// A durable set of spent (reserved or consumed) token hashes, backed by a
/// dedicated fjall database beside the blob store and index (own failure
/// domain; a reindex cannot touch it). Keyed by `sha256(token)`.
struct SpentSet {
    db: Database,
    tokens: Keyspace,
    /// Serializes the reserve check-and-set so concurrent double-submits of
    /// one token cannot both reserve it.
    reserve_lock: Arc<Mutex<()>>,
    /// Closes the store to writes after a failed sync.
    latch: Arc<SyncLatch>,
}

impl SpentSet {
    fn open(path: &Path) -> Result<Self, AdmissionError> {
        let db = Database::builder(path).open().map_err(backend)?;
        check_store_version(&db)?;
        let tokens = db
            .keyspace("admission", KeyspaceCreateOptions::default)
            .map_err(backend)?;
        Ok(Self {
            db,
            tokens,
            reserve_lock: Arc::new(Mutex::new(())),
            latch: Arc::default(),
        })
    }

    /// Atomically reserve `hash`: `Ok(true)` if newly reserved, `Ok(false)` if
    /// already reserved or consumed (single-use is spent). The insert is
    /// fsynced so a reservation survives a crash (stranding the token spent --
    /// the documented, not-defended failure mode).
    async fn reserve(&self, hash: [u8; 32]) -> Result<bool, AdmissionError> {
        let tokens = self.tokens.clone();
        let db = self.db.clone();
        let lock = self.reserve_lock.clone();
        let latch = self.latch.clone();
        tokio::task::spawn_blocking(move || {
            // The mutex guards no data, only mutual exclusion of the
            // contains/insert pair below, which leaves the store consistent
            // at every step: a panicked prior holder poisons the lock
            // without invalidating anything, so recover the guard.
            let _guard = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            latch.writable()?;
            if tokens.contains_key(hash).map_err(backend)? {
                return Ok(false);
            }
            tokens.insert(hash, STATE_RESERVED).map_err(backend)?;
            latch.sync(|| db.persist(PersistMode::SyncAll))?;
            Ok(true)
        })
        .await
        .map_err(|e| AdmissionError::Join(e.to_string()))?
    }

    /// Refine a reserved hash to consumed on an observed 2xx.
    async fn consume(&self, hash: [u8; 32]) -> Result<(), AdmissionError> {
        let tokens = self.tokens.clone();
        let db = self.db.clone();
        let latch = self.latch.clone();
        tokio::task::spawn_blocking(move || {
            latch.writable()?;
            tokens.insert(hash, STATE_CONSUMED).map_err(backend)?;
            latch.sync(|| db.persist(PersistMode::SyncAll))?;
            Ok(())
        })
        .await
        .map_err(|e| AdmissionError::Join(e.to_string()))?
    }

    /// Release a reservation on a non-2xx so the token remains usable (a
    /// protocol-rejected genesis does not burn an invite).
    ///
    /// Deliberately NOT fsynced: unlike reserve/consume, the refund carries no
    /// durability barrier. A refund lost to a crash only strands a token spent
    /// -- the already-documented safe failure direction (single-use is never
    /// violated, only under-counted). Fsyncing here would instead let one valid
    /// token drive unbounded durable syncs on the refund path (a rejected push
    /// costs a reserve fsync plus a refund fsync), so the barrier is pure
    /// amplification with no integrity gain.
    async fn refund(&self, hash: [u8; 32]) -> Result<(), AdmissionError> {
        let tokens = self.tokens.clone();
        let latch = self.latch.clone();
        tokio::task::spawn_blocking(move || {
            latch.writable()?;
            tokens.remove(hash).map_err(backend)
        })
        .await
        .map_err(|e| AdmissionError::Join(e.to_string()))?
    }
}

// ========================================================================
// Hashing and hex (no protocol-crate dependency)
// ========================================================================

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse a deployment tokens file: one `sha256(token)` hex hash per non-blank
/// line. A malformed line is a startup error (a broken tokens file must fail
/// loudly, never silently admit or deny).
fn load_token_hashes(path: &Path) -> Result<Vec<[u8; 32]>, AdmissionError> {
    let text = std::fs::read_to_string(path).map_err(|source| AdmissionError::TokensRead {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hashes = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let hash = hex_decode_32(line).ok_or(AdmissionError::TokensParse {
            path: path.to_path_buf(),
            line: index + 1,
        })?;
        hashes.push(hash);
    }
    Ok(hashes)
}
