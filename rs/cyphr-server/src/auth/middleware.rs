//! Reusable bearer-token admission logic for HTTP routes (SPEC.md 17.4):
//! [`authenticate`] and [`require`] for a route that needs a token or a
//! permission.
//!
//! This module wraps [`auth::token::verify_token`](crate::auth::token) for
//! use at a route: [`check_push_admission`] is `/push`'s specific
//! OPTIONAL admission knob (ARCHITECT RULING R7): no token is always
//! fine, a *presented* token must verify and must name the principal
//! being pushed to.
//!
//! A token's signature and `exp` prove only that the server once issued
//! it. The admission check therefore also re-checks the key that logged in
//! against the principal's current chain ([`check_session_key`], #162):
//! a session lives only while the key that opened it is active.

use axum::http::HeaderMap;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::engine::{EngineError, bare_digest};

use super::token::Claims;
use super::{ServerIdentity, server_now};
use crate::AppState;
use crate::error::AppError;

/// The concrete engine type the server runs on.
type Engine = cyphr_storage::engine::StorageEngine<
    cyphr_blob_fjall::FjallBlobStore,
    cyphr_index_fjall::FjallIndexer,
    cyphr_blob_fjall::storage_fjall::FjallStorage,
>;

/// Why a verified token's session is refused against the principal chain.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The token's principal has no stored chain, so no key can be checked.
    #[error("bearer token's principal is unknown")]
    UnknownPrincipal,

    /// Reading the principal from storage failed.
    #[error("loading the session's principal: {0}")]
    Storage(EngineError),

    /// The token carries no [`LOGIN_KEY_FIELD`](super::token::LOGIN_KEY_FIELD): it was not minted
    /// by a login, so no key vouches for it. Fails closed.
    #[error("bearer token names no login key")]
    NoLoginKey,

    /// The token's login key is not a well-formed thumbprint.
    #[error("bearer token's login key is malformed")]
    MalformedLoginKey,

    /// The login key is not in the principal's chain (never was, or was
    /// deleted from it).
    #[error("the key that opened this session is not an active key of the principal")]
    KeyNotActive,

    /// The login key is still on record but revoked.
    #[error("the key that opened this session was revoked")]
    Revoked,

    /// The token was issued over one Noise session and arrived on another
    /// channel, or on none: a stolen token is useless off its channel.
    #[error("bearer token is bound to the channel that issued it, not this one")]
    ChannelMismatch,

    /// The principal is not in an Active lifecycle state.
    #[error("the session's principal is not in an active lifecycle state")]
    PrincipalNotActive,
}

impl From<SessionError> for AppError {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::Storage(e) => AppError::engine(e),
            other => AppError::unauthorized(format!("bearer token rejected: {other}")),
        }
    }
}

/// Extract the bearer token string from an `Authorization: Bearer <token>`
/// header, if present. `None` covers both a missing header and one that
/// isn't the `Bearer` scheme.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Refuse a channel-bound token presented anywhere but the channel that
/// issued it. `channel` is the handshake hash of the Noise session the
/// request arrived on, `None` over plain HTTP. A token with no channel
/// claim is key-bound and passes here.
pub fn check_channel(claims: &Claims, channel: Option<&[u8]>) -> Result<(), SessionError> {
    match claims.channel.as_deref() {
        Some(bound) if channel != Some(bound) => Err(SessionError::ChannelMismatch),
        _ => Ok(()),
    }
}

/// Re-check, against `engine`'s current view of the token's principal and
/// the naked-revoke death-set, that the key which logged in is still
/// active (#162).
///
/// The principal is read at its tip from the engine
/// (`StorageEngine::at_tip`), serialized with its writes, so the answer is
/// as current as the server's own view -- not a claim about other views of
/// the principal -- and costs no replay while the engine keeps its state.
pub async fn check_session_key(engine: &Engine, claims: &Claims) -> Result<(), SessionError> {
    let load_error = |e: EngineError| match e {
        EngineError::NotFound(_) => SessionError::UnknownPrincipal,
        other => SessionError::Storage(other),
    };
    let principal = engine
        .at_tip(&claims.pg)
        .await
        .map_err(load_error)?
        .ok_or(SessionError::UnknownPrincipal)?;

    let login_tmb = claims
        .login_tmb
        .as_deref()
        .ok_or(SessionError::NoLoginKey)?;
    let login_tmb = Base64UrlUnpadded::decode_vec(login_tmb)
        .map(coz::Thumbprint::from_bytes)
        .map_err(|_| SessionError::MalformedLoginKey)?;

    if principal.get_key(&login_tmb).is_none() {
        return Err(SessionError::KeyNotActive);
    }
    if !principal.is_key_active(&login_tmb) {
        return Err(SessionError::Revoked);
    }
    // A naked revoke (SPEC 6.4) kills the key globally without touching the
    // chain, so the chain alone still calls it active; login refuses such a
    // key and so must the session it opened.
    if engine
        .is_revoked(&login_tmb.to_b64())
        .await
        .map_err(SessionError::Storage)?
    {
        return Err(SessionError::Revoked);
    }
    if principal.lifecycle_state() != cyphr::lifecycle::LifecycleState::Active {
        return Err(SessionError::PrincipalNotActive);
    }
    Ok(())
}

/// The claims of `token`, once every check a session owes has passed: the
/// signature and `exp`, the channel it arrived on, and the login key still
/// being active in the principal's chain ([`check_session_key`]).
pub async fn authenticate(
    state: &AppState,
    token: &str,
    channel: Option<&[u8]>,
) -> Result<Claims, AppError> {
    let identity = state.identity.as_deref().ok_or_else(|| {
        AppError::not_implemented(
            "this server runs without a signing identity; it issues and accepts no bearer tokens",
        )
    })?;
    let claims = identity
        .verify_token(token, server_now())
        .map_err(|e| AppError::unauthorized(format!("bearer token rejected: {e}")))?;
    check_channel(&claims, channel)?;
    check_session_key(&state.engine, &claims).await?;
    Ok(claims)
}

/// A route's requirement of a request: an `Authorization: Bearer` token
/// that authenticates ([`authenticate`]) and carries the permission `perm`.
///
/// The service that defines the route chooses `perm` and the policy that
/// grants it ([`LoginPolicy`](super::policy::LoginPolicy)); this checks
/// only that the signed claims name it.
///
/// # Errors
///
/// 401 for an absent or refused token, 403 for a valid token without
/// `perm`.
pub async fn require(
    state: &AppState,
    headers: &HeaderMap,
    channel: Option<&[u8]>,
    perm: &str,
) -> Result<Claims, AppError> {
    let token = bearer_token(headers)
        .ok_or_else(|| AppError::unauthorized("this route requires a bearer token"))?;
    let claims = authenticate(state, token, channel).await?;
    if !claims.perms.iter().any(|p| p == perm) {
        return Err(AppError::forbidden(format!(
            "bearer token does not carry the `{perm}` permission"
        )));
    }
    Ok(claims)
}

/// `/push`'s admission knob (ARCHITECT RULING R7): a bearer token is
/// never required -- the pushed commit bundle's own signatures are the
/// real authorization -- but if one IS presented it must verify, its
/// `pg` claim must name the same principal as `target_principal` (compared
/// in canonical form, so either id spelling matches), and the key that
/// logged in must still be active in that principal (#162).
///
/// If the server holds no signing identity at all, no token this server
/// ever issued could exist, so the check is skipped entirely (mirrors
/// the no-token case) rather than rejecting on a config detail unrelated
/// to the pushed payload's own validity.
pub async fn check_push_admission(
    token: Option<&str>,
    identity: Option<&ServerIdentity>,
    engine: &Engine,
    target_principal: &str,
    now: i64,
    channel: Option<&[u8]>,
) -> Result<(), AppError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    let Some(token) = token else {
        return Ok(());
    };
    let claims = match identity.verify_token(token, now) {
        Ok(claims) => claims,
        Err(e) => {
            return Err(AppError::unauthorized(format!(
                "bearer token rejected: {e}"
            )));
        },
    };
    // The token subject is the canonical bare digest; compare like with
    // like, whichever spelling the push named.
    let canonical = engine
        .canonical_principal_id(target_principal)
        .await
        .map_err(AppError::engine)?;
    if claims.pg != bare_digest(&canonical) {
        return Err(AppError::unauthorized(
            "bearer token does not authorize this principal",
        ));
    }
    check_channel(&claims, channel)?;
    match check_session_key(engine, &claims).await {
        // A push naming a principal with no stored chain is its genesis:
        // no session can exist yet, and the optional knob (R7) leaves the
        // bundle's own signatures as the authorization.
        Ok(()) | Err(SessionError::UnknownPrincipal) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;

    /// A fresh, randomly generated signing identity for unit tests --
    /// mirrors `auth::token`'s own test helper.
    fn test_identity() -> ServerIdentity {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");
        let kp = coz::Alg::Ed25519.generate_keypair();
        let file = serde_json::json!({
            "alg": kp.alg.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
            "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
        });
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
        // Keep the tempdir alive long enough for load_from_path to read it;
        // the loaded identity holds its key material in memory afterward.
        drop(dir);
        identity
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    const PR: &str = "test-principal";

    // --- bearer_token ---

    // --- check_push_admission (paths decided before any
    // chain lookup; the chain re-check and the subject match are covered
    // end to end in tests/route_protection.rs, which has real principals) ---

    /// The state and the directory backing it; hold the guard for the
    /// test's lifetime.
    fn test_engine() -> (crate::AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::config::ServerConfig {
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        let state = crate::AppState::new(config).expect("open AppState");
        (state, dir)
    }

    /// Backs: a push carrying a garbage bearer token is refused rather than treated as tokenless.
    /// Unit: the e2e suite presents only well-formed tokens.
    #[tokio::test]
    async fn check_push_admission_rejects_invalid_token() {
        let identity = test_identity();
        let (state, _dir) = test_engine();
        let headers = headers_with_bearer("garbage");
        assert!(
            check_push_admission(
                bearer_token(&headers),
                Some(&identity),
                &state.engine,
                PR,
                1_100,
                None
            )
            .await
            .is_err()
        );
    }
}
