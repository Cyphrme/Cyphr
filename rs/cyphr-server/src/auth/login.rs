//! Login flows (SPEC.md §17.2) and their one shared, centralized payload
//! schema.
//!
//! Two flows issue a bearer token on success: challenge-response (Option
//! A) and timestamp-based (Option B). Both sign the same login payload
//! shape and differ only in their replay defense -- a single-use nonce
//! versus a bounded timestamp window.
//!
//! # Both ends are named in the signature (ruling R6)
//!
//! SPEC 17.2's examples name neither the *audience* (which service the
//! signer believes they are authenticating to) nor the *claimed
//! principal*. Both omissions are exploitable:
//!
//! - **Audience.** Without it, a malicious service M can relay a login a user signed for M to a
//!   victim service S and collect a token for the user at S -- the adversary-in-the-middle relay
//!   WebAuthn closes by binding the origin inside the signed `clientData`. Here the audience is the
//!   authority segment of the login `typ` (SPEC 7.3), asserted by the client based on where it
//!   believes it is connecting and verified by the server against its own configured identity. It
//!   is never taken from an unsigned transport detail the counterparty controls.
//! - **Principal.** SPEC permits one key across many principals (Appendix "Sharing Keys"), so a
//!   `tmb`-only lookup is ambiguous by construction. The signer names the principal it claims; the
//!   server verifies the `tmb` is an active key of *that* principal, never inferring the principal
//!   from the `tmb`.
//!
//! These interim field choices are pending the spec author's review, so
//! this module is the single place they live (ruling R6a): field names
//! are constants and one [`parse_login`] does all extraction and
//! validation, making a later rename a one-module edit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::State;
use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::engine::{EngineError, bare_digest};
use rand::RngCore;
use serde::Serialize;

use super::{ServerIdentity, server_now};
use crate::AppState;
use crate::config::MAX_SESSION_TTL_SECS;
use crate::envelope::Envelope;
use crate::error::AppError;

/// Login-payload field names. The one home for the interim R6 binding
/// fields (ruling R6a) -- neither handler reads these strings directly.
pub mod field {
    /// The claimed principal: its genesis identifier / current PR as a
    /// tagged digest. Doubles as the storage id the server loads.
    pub const PR: &str = "pr";
    /// The service-issued 256-bit nonce (challenge-response flow only).
    pub const CHALLENGE: &str = "challenge";
    /// The Noise handshake hash (b64ut) of the session the login is sent
    /// over, signed by the client so the login names its channel. Distinct
    /// from the token's server-signed `cb`: a client never supplies that.
    pub const CHANNEL: &str = "h";
}

/// Suffix every login `typ` must end with; the text before it is the
/// audience (the SPEC 7.3 authority segment). A login `typ` is thus
/// `<audience>/cyphr/auth/login`.
pub const LOGIN_TYP_SUFFIX: &str = "/cyphr/auth/login";

/// Acceptance half-window, in seconds, for the timestamp-based flow
/// (SPEC 17.2 Option B example: ±60s). A `now` further than this from
/// server time is rejected.
pub const TIMESTAMP_WINDOW_SECS: i64 = 60;

/// How long an issued challenge remains usable.
pub const CHALLENGE_TTL_SECS: i64 = 120;

/// Challenge nonce length: 256 bits (SPEC 17.2 / 17.3).
pub const CHALLENGE_BYTES: usize = 32;

/// Why a login was rejected. Each variant is a distinct, testable
/// failure -- an audience or principal mismatch is never conflated with a
/// generic malformed-payload error.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The request body was not valid JSON in the expected Coz shape.
    #[error("login payload is not valid JSON in the expected shape ({})", super::json_fault(.0))]
    Malformed(#[from] serde_json::Error),

    /// A required field was absent from the signed payload.
    #[error("login payload is missing required field `{0}`")]
    MissingField(&'static str),

    /// `typ` is absent or is not a login request (`.../cyphr/auth/login`).
    #[error("login payload `typ` is not a login request")]
    NotALogin,

    /// A login-shaped `typ` whose authority segment (the audience) is
    /// empty -- the signer named no audience at all.
    #[error("login payload names no audience")]
    AudienceMissing,

    /// The named audience is not this server's own identity -- possibly a
    /// login relayed from the service the user actually intended.
    #[error("login audience does not name this server")]
    AudienceMismatch,

    /// The signature did not verify against the claimed key's public key.
    #[error("login signature is invalid")]
    InvalidSignature,

    /// The signing `tmb` is not an active key of the *claimed* principal
    /// (unknown to it, or revoked) -- even if it is active in some other
    /// principal that shares the key.
    #[error("signing key is not an active key of the claimed principal")]
    KeyNotActive,

    /// The claimed principal is not in an Active lifecycle state (it is
    /// Frozen, Deleted, Dead, ...).
    #[error("claimed principal is not in an active lifecycle state")]
    PrincipalNotActive,

    /// The signing key is naked-revoked (SPEC §6.4): recorded dead in the
    /// global death-set and refused at login even though it is still active
    /// on-chain, since the key's own holder declared it compromised out of
    /// band.
    #[error("signing key was naked-revoked")]
    KeyNakedRevoked,

    /// The timestamp-based `now` is outside the acceptance window.
    #[error("login timestamp is outside the acceptance window")]
    TimestampOutOfWindow,

    /// The challenge is unknown, already used, or expired.
    #[error("login challenge is unknown, already used, or expired")]
    ChallengeInvalid,

    /// The login does not commit to the channel it arrived on: over Noise
    /// it must carry the session's handshake hash and over HTTP none, and
    /// it must be signed by the session's own principal and key.
    #[error("login does not match the channel it arrived on: {0}")]
    ChannelMismatch(&'static str),
}

/// A parsed, audience-verified login payload. Field extraction and the
/// audience check are already done; the signature, key-activity, and
/// lifecycle checks are [`authorize_login`]'s job.
#[derive(Debug)]
pub struct ParsedLogin {
    /// The signing key's thumbprint.
    pub tmb: Thumbprint,
    /// The signing algorithm named in the payload.
    pub alg: String,
    /// The client's asserted timestamp.
    pub now: i64,
    /// The claimed principal (storage id).
    pub pr: String,
    /// The challenge nonce, present iff this is the challenge-response
    /// flow.
    pub challenge: Option<String>,
    /// The handshake hash the login commits to, present iff the client
    /// signed it into the login (a login sent over Noise).
    pub channel: Option<Vec<u8>>,
    /// The exact payload bytes the signature is over.
    pub pay_bytes: Vec<u8>,
    /// The detached signature.
    pub sig: Vec<u8>,
}

/// Parse and validate a login envelope's payload against `server_audience`
/// -- the single owner of the login-payload schema (ruling R6a). Both
/// flows call through here; neither extracts fields itself.
///
/// This performs the checks that need only the payload and the server's
/// own identity: shape, audience binding, and presence of required
/// fields. It deliberately does *not* verify the signature or touch the
/// principal -- those need the loaded principal's keyring and are
/// [`authorize_login`]'s responsibility.
pub fn parse_login(
    coz_json: coz::CozJson,
    server_audience: &str,
) -> Result<ParsedLogin, LoginError> {
    let pay_bytes = serde_json::to_vec(&coz_json.pay)?;
    let sig = coz_json.sig;
    let pay: coz::Pay = serde_json::from_value(coz_json.pay)?;

    let typ = pay.typ.as_deref().ok_or(LoginError::NotALogin)?;
    let audience = typ
        .strip_suffix(LOGIN_TYP_SUFFIX)
        .ok_or(LoginError::NotALogin)?;
    if audience.is_empty() {
        return Err(LoginError::AudienceMissing);
    }
    if audience != server_audience {
        return Err(LoginError::AudienceMismatch);
    }

    let tmb = pay.tmb.clone().ok_or(LoginError::MissingField("tmb"))?;
    let alg = pay.alg.clone().ok_or(LoginError::MissingField("alg"))?;
    let now = pay.now.ok_or(LoginError::MissingField("now"))?;
    let pr = pay
        .extra
        .get(field::PR)
        .and_then(serde_json::Value::as_str)
        .ok_or(LoginError::MissingField(field::PR))?
        .to_string();
    let challenge = pay
        .extra
        .get(field::CHALLENGE)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let channel = pay
        .extra
        .get(field::CHANNEL)
        .map(|v| {
            v.as_str()
                .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                .ok_or(LoginError::ChannelMismatch("`h` is not base64url"))
        })
        .transpose()?;

    Ok(ParsedLogin {
        tmb,
        alg,
        now,
        pr,
        challenge,
        channel,
        pay_bytes,
        sig,
    })
}

/// Verify a parsed login against the *claimed* principal: the signing key
/// belongs to and is active in that principal, its signature verifies,
/// and the principal is Active.
///
/// `principal` is the one named by `login.pr`, already loaded by the
/// caller. The key is looked up in *this* principal only -- never a
/// global `tmb` index -- which is what closes the key-sharing ambiguity.
pub fn authorize_login<S: eml::Storage>(
    login: &ParsedLogin,
    principal: &cyphr::Principal<S>,
) -> Result<(), LoginError> {
    // The key must be one this claimed principal knows. `get_key` returns
    // active or revoked keys; an unknown key (active only in some *other*
    // principal that shares it) is not found here and is rejected.
    let key = principal
        .get_key(&login.tmb)
        .ok_or(LoginError::KeyNotActive)?;

    // Proof of possession: the signature must verify against that key.
    if coz::verify_json(&login.pay_bytes, &login.sig, key.alg(), key.pub_key()) != Some(true) {
        return Err(LoginError::InvalidSignature);
    }

    // A present-but-revoked key proves possession but is no longer active.
    if !principal.is_key_active(&login.tmb) {
        return Err(LoginError::KeyNotActive);
    }

    // Only an Active principal may log in (reject Frozen/Deleted/Dead/...).
    if principal.lifecycle_state() != cyphr::lifecycle::LifecycleState::Active {
        return Err(LoginError::PrincipalNotActive);
    }

    Ok(())
}

/// Whether a client timestamp is within `window_secs` of server time, in
/// either direction (SPEC 17.2 Option B). `client_now` is attacker-controlled
/// (the raw `now` field of a signed-but-unverified-at-call-time payload), so
/// the distance is computed with `abs_diff` rather than a subtract-then-abs,
/// which would overflow on an i64::MIN/MAX client value.
///
/// `window_secs` must be non-negative: `as u64` on a negative value wraps to
/// a huge magnitude and fail-*opens* (accepts any client_now) instead of the
/// fail-closed behavior a negative window implies. The only caller today
/// passes the positive constant `TIMESTAMP_WINDOW_SECS`, but this is `pub`,
/// so the precondition is asserted rather than left as an implicit contract.
pub fn within_window(client_now: i64, server_now: i64, window_secs: i64) -> bool {
    debug_assert!(
        window_secs >= 0,
        "within_window: window_secs must be non-negative"
    );
    server_now.abs_diff(client_now) <= window_secs as u64
}

/// In-memory single-use challenge store for the challenge-response flow.
///
/// A challenge is a 256-bit nonce mapped to its expiry. Consumption
/// removes it, so a replay of a consumed nonce finds nothing; an expired
/// nonce is rejected even if still present. There is no revocation story
/// beyond expiry (ruling R8's spirit): the store is per-process and
/// disposable.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    entries: Mutex<HashMap<String, i64>>,
}

impl ChallengeStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new single-use challenge expiring [`CHALLENGE_TTL_SECS`]
    /// after `now`. Opportunistically drops already-expired entries so the
    /// map does not grow without bound.
    pub fn issue(&self, now: i64) -> String {
        let mut buf = [0u8; CHALLENGE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        let challenge = Base64UrlUnpadded::encode_string(&buf);

        let mut entries = self.lock();
        entries.retain(|_, &mut exp| exp > now);
        entries.insert(challenge.clone(), now + CHALLENGE_TTL_SECS);
        challenge
    }

    /// Consume a challenge: valid exactly once, and only before it
    /// expires. Any subsequent or expired presentation is
    /// [`LoginError::ChallengeInvalid`].
    pub fn consume(&self, challenge: &str, now: i64) -> Result<(), LoginError> {
        let mut entries = self.lock();
        match entries.remove(challenge) {
            Some(exp) if exp > now => Ok(()),
            _ => Err(LoginError::ChallengeInvalid),
        }
    }

    /// Lock the map, recovering rather than propagating a poisoned lock:
    /// the map holds only nonces and expiries, so a panic mid-mutation
    /// leaves nothing unsafe to read, and a challenge store that panics
    /// every request after one unrelated panic is worse than one that
    /// keeps working.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ========================================================================
// HTTP handlers
// ========================================================================

/// Response for `POST /auth/challenge`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// A single-use 256-bit nonce (b64ut) to sign in the
    /// challenge-response flow.
    pub challenge: String,
}

/// Response for a successful `POST /auth/login`.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// The issued bearer token (an opaque signed Coz string).
    pub token: String,
}

/// A login rejection is authentication failure (401); only a genuinely
/// malformed request body is a 400. Every distinct [`LoginError`] keeps
/// its own message so the specific reason is still observable, without
/// conflating an audience or principal mismatch with a parse error.
impl From<LoginError> for AppError {
    fn from(err: LoginError) -> Self {
        match err {
            LoginError::Malformed(_) => AppError::bad_request(err.to_string()),
            _ => AppError::unauthorized(err.to_string()),
        }
    }
}

/// Permissions a successful login grants. There is no permissions model
/// in v1 (route-level enforcement is a later concern), so a login
/// authorizes the principal for the baseline read/write surface; a real
/// policy will refine this.
fn default_login_perms() -> Vec<String> {
    vec!["read".to_string(), "write".to_string()]
}

/// The explicit, honest rejection a keyless server (no configured signing
/// identity) gives both login and challenge -- the SAME condition, the
/// SAME error, never `AppError::internal`. A keyless server cannot
/// issue a bearer token, so login is a declared capability absence, not
/// a fault; a challenge nobody can ever redeem would be a silent trap,
/// so challenge shares the same rejection rather than issuing one. The
/// message points a rejected client at `GET /server`
/// (`docs/specs/server-identity.md`), where the server's declared
/// capability tier ("repository" here) actually lives.
fn keyless_identity_rejection() -> AppError {
    AppError::not_implemented(
        "this server runs without a signing identity; login is not offered -- see GET /server for \
         the declared capability tier",
    )
}

/// The explicit refusal a server with a signing key but no configured
/// audience gives: it cannot verify any login's audience binding, so no
/// login can succeed. Same shape as [`keyless_identity_rejection`] -- a
/// declared capability absence, not a fault.
fn audienceless_rejection() -> AppError {
    AppError::not_implemented(
        "this server has no configured audience; login is not offered -- see GET /server for the \
         declared capability tier",
    )
}

/// What a server must hold before it can complete any login: a signing
/// identity to issue the token and an audience to bind logins against.
/// Both `challenge` and `login` gate on this one function, so the server
/// never issues a nonce that a login cannot redeem.
fn login_capability(state: &AppState) -> Result<(&ServerIdentity, &str), AppError> {
    let identity = state
        .identity
        .as_deref()
        .ok_or_else(keyless_identity_rejection)?;
    let audience = state
        .config
        .audience
        .as_deref()
        .ok_or_else(audienceless_rejection)?;
    Ok((identity, audience))
}

/// Map a principal-load failure: an unknown principal is an
/// authentication failure (401, and indistinguishable from a
/// wrong-audience or inactive rejection, so principal existence is not an
/// oracle), while a genuine storage fault surfaces as 500.
fn map_load_error(err: EngineError) -> AppError {
    match err {
        EngineError::NotFound(_) => AppError::unauthorized("login: unknown principal"),
        other => AppError::engine(other),
    }
}

/// `POST /auth/challenge` — issue a single-use challenge for the
/// challenge-response flow (SPEC 17.2 Option A).
///
/// A server that cannot complete a login (no signing identity, or no
/// audience) never issues a challenge at all: a nonce that can never be
/// redeemed by a login that can never succeed is a silent trap, not a
/// service worth offering, so this fails the same honest way `login`
/// does rather than succeeding here and only failing later.
pub async fn challenge(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Envelope<ChallengeResponse>>, AppError> {
    login_capability(&state)?;
    let challenge = state.challenges.issue(server_now());
    Ok(Json(Envelope::unsigned(ChallengeResponse { challenge })))
}

/// `POST /auth/login` — verify a signed login payload (either flow) and
/// issue a bearer token (SPEC 17.2).
///
/// One handler serves both flows: they share the whole pipeline (schema
/// parse, audience binding, principal load, key-activity and lifecycle
/// gate, token issuance) and diverge only at the replay check, selected
/// by whether the payload carries a challenge.
pub async fn login(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<crate::transport::AuthenticatedPeer>>,
    body: String,
) -> Result<Json<Envelope<LoginResponse>>, AppError> {
    let (identity, audience) = login_capability(&state)?;

    let coz_json: coz::CozJson = serde_json::from_str(&body).map_err(|e| {
        AppError::bad_request(format!(
            "failed to parse login body as JSON ({})",
            super::json_fault(&e)
        ))
    })?;

    // One schema parse + audience binding for both flows (ruling R6a).
    let parsed = parse_login(coz_json, audience)?;

    // Read the *claimed* principal and gate on it: key active in it, and
    // it is Active. The verified state at its tip, from the same engine
    // entry the write path uses.
    let principal = state
        .engine
        .at_tip(&parsed.pr)
        .await
        .map_err(map_load_error)?
        .ok_or_else(|| AppError::unauthorized("login: unknown principal"))?;
    authorize_login(&parsed, &principal)?;
    // A fork leaves the lifecycle base state Active (SPEC 11.1: Errored is
    // orthogonal), so `authorize_login` cannot see it; the engine's verdict
    // can (SPEC 17.2: reject Errored).
    if state
        .engine
        .is_errored(&parsed.pr)
        .await
        .map_err(map_load_error)?
    {
        return Err(LoginError::PrincipalNotActive.into());
    }
    let canonical_id = state
        .engine
        .canonical_principal_id(&parsed.pr)
        .await
        .map_err(map_load_error)?;

    // The login must name the channel it arrived on (no downgrade either
    // way) and, over Noise, come from the principal and key that
    // authenticated the session: otherwise a signed login could be carried
    // to the server on someone else's channel and earn a token bound to it.
    let channel = match (peer.as_ref(), &parsed.channel) {
        (None, None) => None,
        (Some(p), Some(h)) => {
            if *h != p.0.handshake_hash {
                return Err(LoginError::ChannelMismatch("`h` is not this session's hash").into());
            }
            if p.0.tmb != parsed.tmb || bare_digest(&p.0.pg) != bare_digest(&canonical_id) {
                return Err(LoginError::ChannelMismatch(
                    "the session's principal and key did not sign this login",
                )
                .into());
            }
            Some(h.as_slice())
        },
        (Some(_), None) => {
            return Err(LoginError::ChannelMismatch("a login over Noise must sign `h`").into());
        },
        (None, Some(_)) => {
            return Err(LoginError::ChannelMismatch("a login over HTTP must not sign `h`").into());
        },
    };

    // Naked-revoke gate (SPEC §6.4): a key its own holder self-revoked out of
    // band is refused here even though `authorize_login` found it still active
    // on-chain -- the death-set, not the chain, carries that fact. Death is
    // global by thumbprint, so the check names only the key, never a principal.
    if state
        .observations
        .is_dead(&parsed.tmb)
        .await
        .map_err(AppError::observation)?
    {
        return Err(LoginError::KeyNakedRevoked.into());
    }

    // Replay defense: the two flows diverge only here.
    let now = server_now();
    match &parsed.challenge {
        Some(challenge) => state.challenges.consume(challenge, now)?,
        None => {
            if !within_window(parsed.now, now, TIMESTAMP_WINDOW_SECS) {
                return Err(LoginError::TimestampOutOfWindow.into());
            }
        },
    }

    // The subject is the principal's one canonical id, never the spelling
    // the client typed: a relying party keys accounts on this, and two
    // spellings of one identity must not yield two accounts.
    let subject = bare_digest(&canonical_id).to_string();
    let token = identity
        .issue_login_token(
            subject,
            &parsed.tmb,
            default_login_perms(),
            now,
            state.config.session_ttl_secs.clamp(1, MAX_SESSION_TTL_SECS),
            // Bound to the channel the login committed to; over HTTP (a
            // browser edge) there is none, and the session is bound to the
            // key alone. `channel` is the session's own hash, checked above.
            channel,
        )
        .ok_or_else(|| AppError::internal("failed to issue bearer token"))?;

    Ok(Json(Envelope::unsigned(LoginResponse { token })))
}

/// Response for `POST /auth/session`: what a live session stands for.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    /// The session's principal.
    pub pr: String,
    /// The key that opened the session, which it stands or falls with.
    pub key: String,
    /// `noise-handshake-hash` for a session bound to the Noise channel that
    /// issued it, `key` for a browser edge session bound to its key alone.
    pub binding: &'static str,
    /// When the session ends (Unix seconds). Fixed at login: presenting the
    /// token never extends it.
    pub exp: i64,
}

/// `POST /auth/session` — present a bearer token (the request body) and
/// learn whether its session still stands.
///
/// The token must verify, the channel it arrives on must be the one it was
/// issued on (a token minted over Noise is refused over any other
/// session, and over HTTP), and the key that opened it must still be
/// active in the principal's chain. This is the one route that presents a
/// token as its whole input, since the transport carries no headers.
pub async fn session(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<crate::transport::AuthenticatedPeer>>,
    body: String,
) -> Result<Json<Envelope<SessionResponse>>, AppError> {
    let (identity, _) = login_capability(&state)?;
    let claims = identity
        .verify_token(body.trim(), server_now())
        .map_err(|e| AppError::unauthorized(format!("bearer token rejected: {e}")))?;
    super::middleware::check_channel(
        &claims,
        peer.as_ref().map(|p| p.0.handshake_hash.as_slice()),
    )?;
    super::middleware::check_session_key(&state.engine, &state.observations, &claims).await?;
    let key = claims
        .login_tmb
        .clone()
        .ok_or_else(|| AppError::unauthorized("bearer token names no login key"))?;
    let binding = if claims.channel.is_some() {
        "noise-handshake-hash"
    } else {
        "key"
    };
    Ok(Json(Envelope::unsigned(SessionResponse {
        pr: claims.pr,
        key,
        binding,
        exp: claims.exp,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- within_window ---

    proptest::proptest! {
        /// Backs: SPEC 17.2 timestamp window. For any signed `now` pair (extremes
        /// included, so an attacker-chosen `now` can never overflow) the window
        /// is exactly `|client - server| <= window`, computed here in i128.
        /// Property: e2e cannot place `now` on the one-second boundary or at
        /// `i64::MIN`.
        #[test]
        fn window_is_exactly_the_absolute_difference(
            client in proptest::prelude::any::<i64>(),
            server in proptest::prelude::any::<i64>(),
            window in 0i64..=i64::MAX,
        ) {
            let diff = (i128::from(server) - i128::from(client)).abs();
            proptest::prop_assert_eq!(
                within_window(client, server, window),
                diff <= i128::from(window)
            );
        }

        /// The edge the generator rarely lands on: one second either side of
        /// the production window.
        #[test]
        fn window_edges_at_the_production_constant(server in -1_000_000i64..1_000_000) {
            let w = TIMESTAMP_WINDOW_SECS;
            proptest::prop_assert!(within_window(server - w, server, w));
            proptest::prop_assert!(within_window(server + w, server, w));
            proptest::prop_assert!(!within_window(server - w - 1, server, w));
            proptest::prop_assert!(!within_window(server + w + 1, server, w));
        }
    }

    // --- ChallengeStore ---

    /// Backs: SPEC 17.2 challenge freshness - an expired challenge cannot be redeemed.
    /// Unit: e2e cannot advance the store clock.
    #[test]
    fn challenge_expires() {
        let store = ChallengeStore::new();
        let c = store.issue(1000);
        // now is past the TTL.
        let result = store.consume(&c, 1000 + CHALLENGE_TTL_SECS + 1);
        assert!(
            matches!(result, Err(LoginError::ChallengeInvalid)),
            "an expired challenge must be rejected, got: {result:?}"
        );
    }
}
