//! Reusable bearer-token admission logic for HTTP routes (SPEC.md 17.4).
//!
//! This module wraps [`auth::token::verify_token`](crate::auth::token) for
//! use at any route: [`require_bearer`] for a route that must reject
//! every request with no valid token, and [`check_push_admission`] for
//! `/push`'s specific OPTIONAL admission knob (ARCHITECT RULING R7): no
//! token is always fine, a *presented* token must verify and must name
//! the principal being pushed to.
//!
//! A token's signature and `exp` prove only that the server once issued
//! it. Both entry points therefore also re-check the key that logged in
//! against the principal's current chain ([`check_session_key`], #162):
//! a session lives only while the key that opened it is active.

use axum::http::HeaderMap;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::engine::{EngineError, bare_digest};

use super::ServerIdentity;
use super::token::{Claims, TokenError};
use crate::error::AppError;
use crate::observation::{ObservationError, ObservationStore};

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

    /// Reading the naked-revoke death-set failed.
    #[error("reading the naked-revoke record: {0}")]
    Observation(ObservationError),

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

    /// The principal is not in an Active lifecycle state.
    #[error("the session's principal is not in an active lifecycle state")]
    PrincipalNotActive,
}

impl From<SessionError> for AppError {
    fn from(err: SessionError) -> Self {
        match err {
            SessionError::Storage(e) => AppError::engine(e),
            SessionError::Observation(e) => AppError::observation(e),
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

/// Verify a request's bearer token against `identity`, if one is present.
///
/// Returns `Ok(None)` when no `Authorization` header carries a bearer
/// token -- the caller decides whether that is acceptable (an optional
/// admission knob) or a rejection (mandatory auth). Returns
/// `Ok(Some(claims))` for a genuine, unexpired token issued by
/// `identity`. Returns `Err` for a token that IS present but fails
/// verification -- a present-and-invalid token is never treated the same
/// as an absent one. This checks the token only; the chain re-check is
/// [`check_session_key`].
pub fn verify_bearer_if_present(
    headers: &HeaderMap,
    identity: &ServerIdentity,
    now: i64,
) -> Result<Option<Claims>, TokenError> {
    bearer_token(headers)
        .map(|token| identity.verify_token(token, now))
        .transpose()
}

/// Re-check, against `engine`'s current view of the token's principal and
/// the naked-revoke death-set, that the key which logged in is still
/// active (#162).
///
/// The principal is replayed from storage on each call (replay-cost
/// caching is deferred, root U3), so the answer is as current as the
/// server's own view -- not a claim about other views of the principal.
pub async fn check_session_key(
    engine: &Engine,
    observations: &ObservationStore,
    claims: &Claims,
) -> Result<(), SessionError> {
    let load_error = |e: EngineError| match e {
        EngineError::NotFound(_) => SessionError::UnknownPrincipal,
        other => SessionError::Storage(other),
    };
    let genesis = engine
        .resolve_genesis(&claims.pr, &[])
        .await
        .map_err(load_error)?;
    let principal = engine
        .load_principal(&claims.pr, genesis)
        .await
        .map_err(load_error)?;

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
    if observations
        .is_dead(&login_tmb)
        .await
        .map_err(SessionError::Observation)?
    {
        return Err(SessionError::Revoked);
    }
    if principal.lifecycle_state() != cyphr::lifecycle::LifecycleState::Active {
        return Err(SessionError::PrincipalNotActive);
    }
    Ok(())
}

/// Require a valid bearer token: reject a missing, malformed, or invalid
/// token alike, and one whose login key has left the chain. Real,
/// independently-tested infrastructure for a future route that needs
/// mandatory bearer auth -- no current route in this campaign uses it (R7
/// keeps `/push` optional and the witness-read routes public), so nothing
/// calls this yet.
pub async fn require_bearer(
    headers: &HeaderMap,
    identity: &ServerIdentity,
    engine: &Engine,
    observations: &ObservationStore,
    now: i64,
) -> Result<Claims, AppError> {
    match verify_bearer_if_present(headers, identity, now) {
        Ok(Some(claims)) => {
            check_session_key(engine, observations, &claims).await?;
            Ok(claims)
        },
        Ok(None) => Err(AppError::unauthorized("missing bearer token")),
        Err(e) => Err(AppError::unauthorized(format!(
            "bearer token rejected: {e}"
        ))),
    }
}

/// `/push`'s admission knob (ARCHITECT RULING R7): a bearer token is
/// never required -- the pushed commit bundle's own signatures are the
/// real authorization -- but if one IS presented it must verify, its
/// `pr` claim must name the same principal as `target_principal` (compared
/// in canonical form, so either id spelling matches), and the key that
/// logged in must still be active in that principal (#162).
///
/// If the server holds no signing identity at all, no token this server
/// ever issued could exist, so the check is skipped entirely (mirrors
/// the no-token case) rather than rejecting on a config detail unrelated
/// to the pushed payload's own validity.
pub async fn check_push_admission(
    headers: &HeaderMap,
    identity: Option<&ServerIdentity>,
    engine: &Engine,
    observations: &ObservationStore,
    target_principal: &str,
    now: i64,
) -> Result<(), AppError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    let claims = match verify_bearer_if_present(headers, identity, now) {
        Ok(None) => return Ok(()),
        Ok(Some(claims)) => claims,
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
    if claims.pr != bare_digest(&canonical) {
        return Err(AppError::unauthorized(
            "bearer token does not authorize this principal",
        ));
    }
    match check_session_key(engine, observations, &claims).await {
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

    #[test]
    fn bearer_token_extracts_from_authorization_header() {
        let headers = headers_with_bearer("abc.def");
        assert_eq!(bearer_token(&headers), Some("abc.def"));
    }

    #[test]
    fn bearer_token_none_when_absent() {
        let headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn bearer_token_none_when_not_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    // --- verify_bearer_if_present ---

    #[test]
    fn verify_bearer_if_present_ok_none_when_absent() {
        let identity = test_identity();
        let headers = HeaderMap::new();
        let result = verify_bearer_if_present(&headers, &identity, 1_100);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn verify_bearer_if_present_ok_some_for_valid_token() {
        let identity = test_identity();
        let token = identity
            .issue_unbound_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        let result = verify_bearer_if_present(&headers, &identity, 1_100);
        let claims = result
            .expect("valid token verifies")
            .expect("token present");
        assert_eq!(claims.pr, PR);
    }

    #[test]
    fn verify_bearer_if_present_err_for_invalid_token() {
        let identity = test_identity();
        let headers = headers_with_bearer("not-a-real-token");
        let result = verify_bearer_if_present(&headers, &identity, 1_100);
        assert!(
            matches!(result, Err(TokenError::Malformed(_))),
            "got: {result:?}"
        );
    }

    // --- require_bearer / check_push_admission (paths decided before any
    // chain lookup; the chain re-check and the subject match are covered
    // end to end in tests/route_protection.rs, which has real principals) ---

    fn test_engine() -> crate::AppState {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = crate::config::ServerConfig {
            data_dir: dir.path().join("data"),
            ..Default::default()
        };
        // The state outlives this helper; the directory must too.
        std::mem::forget(dir);
        crate::AppState::new(config).expect("open AppState")
    }

    #[tokio::test]
    async fn require_bearer_rejects_missing_token() {
        let identity = test_identity();
        let state = test_engine();
        let result = require_bearer(
            &HeaderMap::new(),
            &identity,
            &state.engine,
            &state.observations,
            1_100,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn require_bearer_rejects_invalid_token() {
        let identity = test_identity();
        let state = test_engine();
        let headers = headers_with_bearer("garbage");
        assert!(
            require_bearer(
                &headers,
                &identity,
                &state.engine,
                &state.observations,
                1_100
            )
            .await
            .is_err()
        );
    }

    /// A validly signed, unexpired token that names no login key (not
    /// minted by a login) is refused. Here its principal is also unknown;
    /// the no-login-key arm for a stored principal is pinned end to end by
    /// `token_key_absent_or_missing_is_refused_at_push`.
    #[tokio::test]
    async fn require_bearer_rejects_token_without_login_key() {
        let identity = test_identity();
        let state = test_engine();
        let token = identity
            .issue_unbound_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        let result = require_bearer(
            &headers,
            &identity,
            &state.engine,
            &state.observations,
            1_100,
        )
        .await;
        assert!(result.is_err(), "a token with no login key must be refused");
    }

    #[tokio::test]
    async fn check_push_admission_allows_no_token() {
        let identity = test_identity();
        let state = test_engine();
        assert!(
            check_push_admission(
                &HeaderMap::new(),
                Some(&identity),
                &state.engine,
                &state.observations,
                PR,
                1_100
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn check_push_admission_rejects_invalid_token() {
        let identity = test_identity();
        let state = test_engine();
        let headers = headers_with_bearer("garbage");
        assert!(
            check_push_admission(
                &headers,
                Some(&identity),
                &state.engine,
                &state.observations,
                PR,
                1_100
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn check_push_admission_allows_when_no_identity_configured() {
        // A token is presented but the server holds no signing identity at
        // all -- no such token could ever have been genuinely issued by
        // this server, so the check is skipped rather than rejecting on a
        // config detail unrelated to the pushed payload's own validity.
        let state = test_engine();
        let headers = headers_with_bearer("anything");
        assert!(
            check_push_admission(
                &headers,
                None,
                &state.engine,
                &state.observations,
                PR,
                1_100
            )
            .await
            .is_ok()
        );
    }
}
