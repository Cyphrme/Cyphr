//! Login flows (SPEC.md §17.2) and their one shared, centralized payload
//! schema.
//!
//! Two flows issue a bearer token on success: challenge-response (Option
//! A) and timestamp-based (Option B). Both sign the same login payload
//! shape and differ only in their replay defense -- a single-use signed
//! challenge versus a bounded timestamp window.
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
//! The wire contract (typs, claim names, build, parse, challenge) lives in
//! `cyphr_client::login`, shared with the user's device and a relying
//! party. This module adds what only the server decides: the audience it
//! accepts, the principal's key and lifecycle checks, and the token it
//! issues.

use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::State;
use cyphr_client::login::{self, LoginRequest, ParsedRequest, SpentChallenges, VerifiedRequest};
use cyphr_storage::engine::{EngineError, bare_digest};
use serde::Serialize;

use super::{ServerIdentity, server_now};
use crate::AppState;
use crate::config::MAX_SESSION_TTL_SECS;
use crate::envelope::Envelope;
use crate::error::AppError;

impl From<login::VerifyError> for LoginError {
    fn from(err: login::VerifyError) -> Self {
        match err {
            login::VerifyError::MissingField(name) => Self::MissingField(name),
            login::VerifyError::NotALogin => Self::NotALogin,
            login::VerifyError::AudienceMissing => Self::AudienceMissing,
            login::VerifyError::ChannelMalformed => Self::ChannelMismatch("`h` is not base64url"),
            login::VerifyError::ChallengeInvalid => Self::ChallengeInvalid,
            login::VerifyError::InvalidSignature => Self::InvalidSignature,
        }
    }
}

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

    /// `typ` is absent or is not a login request
    /// (`<audience>/user/login/request/create`).
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

/// Parse a login request against `server_audience`: the contract's
/// extraction and shape checks ([`login::parse_request`]) plus the one thing
/// only the server knows, that the audience is itself.
///
/// This deliberately does *not* verify the signature or touch the
/// principal -- those need the loaded principal's keyring and are
/// [`authorize_login`]'s responsibility.
pub fn parse_login(
    request: &LoginRequest,
    server_audience: &str,
) -> Result<ParsedRequest, LoginError> {
    // A wrong-typed standard claim is a malformed body (400), not a missing
    // field (401), whatever its value; the error never echoes the value.
    serde_json::from_value::<coz::Pay>(request.coz.pay.clone())?;
    let parsed = login::parse_request(request)?;
    if parsed.audience != server_audience {
        return Err(LoginError::AudienceMismatch);
    }
    Ok(parsed)
}

/// Verify a parsed login against the *claimed* principal: the signing key
/// belongs to and is active in that principal, its signature verifies,
/// and the principal is Active.
///
/// `principal` is the one named by `login.pg`, already loaded by the
/// caller. The key is looked up in *this* principal only -- never a
/// global `tmb` index -- which is what closes the key-sharing ambiguity.
pub fn authorize_login<S: eml::Storage>(
    login: ParsedRequest,
    principal: &cyphr::Principal<S>,
) -> Result<VerifiedRequest, LoginError> {
    // The key must be one this claimed principal knows. `get_key` returns
    // active or revoked keys; an unknown key (active only in some *other*
    // principal that shares it) is not found here and is rejected.
    let key = principal
        .get_key(&login.tmb)
        .ok_or(LoginError::KeyNotActive)?;

    // Proof of possession: the signature must verify against that key.
    let login = login.verify(key.alg(), key.pub_key())?;

    // A present-but-revoked key proves possession but is no longer active.
    if !principal.is_key_active(&login.tmb) {
        return Err(LoginError::KeyNotActive);
    }

    // Only an Active principal may log in (reject Frozen/Deleted/Dead/...).
    if principal.lifecycle_state() != cyphr::lifecycle::LifecycleState::Active {
        return Err(LoginError::PrincipalNotActive);
    }

    Ok(login)
}

/// In-memory store of redeemed challenges for the challenge-response flow.
///
/// A challenge is a Coz the server signed, so it needs no issuance record:
/// only the nonces already redeemed are kept, each until its challenge
/// could no longer verify. The store is per-process and disposable.
#[derive(Debug, Default)]
pub struct ChallengeStore {
    spent: Mutex<SpentChallenges>,
}

impl ChallengeStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Redeem the challenge `request` returns: the server's own signed
    /// challenge for this audience, unexpired, matching the request's
    /// nonce, and not redeemed before.
    pub fn redeem(
        &self,
        identity: &ServerIdentity,
        request: &VerifiedRequest,
        now: i64,
    ) -> Result<(), LoginError> {
        // The set holds only nonces and expiries, so a panic mid-mutation
        // leaves nothing unsafe to read; a store that panics every request
        // after one unrelated panic is worse than one that keeps working.
        let mut spent = self
            .spent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(login::redeem_challenge(identity, request, &mut spent, now)?)
    }
}

// ========================================================================
// HTTP handlers
// ========================================================================

/// Response for `POST /auth/challenge`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// A Coz the server signed over a single-use 256-bit nonce. The signer
    /// returns it, whole, inside the login it signs.
    pub challenge: coz::CozJson,
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
    let (identity, audience) = login_capability(&state)?;
    let challenge = login::issue_challenge(identity, audience, server_now())
        .map_err(|e| AppError::internal(e.to_string()))?;
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

    let request: LoginRequest = serde_json::from_str(&body).map_err(|e| {
        AppError::bad_request(format!(
            "failed to parse login body as JSON ({})",
            super::json_fault(&e)
        ))
    })?;

    // One schema parse + audience binding for both flows (ruling R6a).
    let parsed = parse_login(&request, audience)?;

    // Read the *claimed* principal and gate on it: key active in it, and
    // it is Active. The verified state at its tip, from the same engine
    // entry the write path uses.
    let principal = state
        .engine
        .at_tip(&parsed.pg)
        .await
        .map_err(map_load_error)?
        .ok_or_else(|| AppError::unauthorized("login: unknown principal"))?;
    let parsed = authorize_login(parsed, &principal)?;
    // A fork leaves the lifecycle base state Active (SPEC 11.1: Errored is
    // orthogonal), so `authorize_login` cannot see it; the engine's verdict
    // can (SPEC 17.2: reject Errored).
    if state
        .engine
        .is_errored(&parsed.pg)
        .await
        .map_err(map_load_error)?
    {
        return Err(LoginError::PrincipalNotActive.into());
    }
    let canonical_id = state
        .engine
        .canonical_principal_id(&parsed.pg)
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
        .engine
        .is_revoked(&parsed.tmb.to_b64())
        .await
        .map_err(AppError::engine)?
    {
        return Err(LoginError::KeyNakedRevoked.into());
    }

    // Replay defense: the two flows diverge only here.
    let now = server_now();
    if parsed.nonce.is_some() || parsed.challenge.is_some() {
        state.challenges.redeem(identity, &parsed, now)?;
    } else if !parsed.in_window(now) {
        return Err(LoginError::TimestampOutOfWindow.into());
    }

    // The subject is the principal's one canonical id, never the spelling
    // the client typed: a relying party keys accounts on this, and two
    // spellings of one identity must not yield two accounts.
    let subject = bare_digest(&canonical_id).to_string();
    let perms = state.login_policy.perms(&subject, &parsed.tmb);
    let token = identity
        .issue_login_token(
            subject,
            &parsed.tmb,
            perms,
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
    pub pg: String,
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
    login_capability(&state)?;
    let claims = super::middleware::authenticate(
        &state,
        body.trim(),
        peer.as_ref().map(|p| p.0.handshake_hash.as_slice()),
    )
    .await?;
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
        pg: claims.pg,
        key,
        binding,
        exp: claims.exp,
    })))
}
