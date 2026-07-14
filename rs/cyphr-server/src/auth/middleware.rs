//! Reusable bearer-token admission logic for HTTP routes (SPEC.md 17.4).
//!
//! This module wraps [`auth::token::verify_token`](crate::auth::token) for
//! use at any route: [`require_bearer`] for a route that must reject
//! every request with no valid token, and [`check_push_admission`] for
//! `/push`'s specific OPTIONAL admission knob (ARCHITECT RULING R7): no
//! token is always fine, a *presented* token must verify and must name
//! the principal being pushed to. Every check here extracts the header
//! and calls
//! [`ServerIdentity::verify_token`] -- none of it re-parses or
//! re-verifies a token's signature itself.

use axum::http::HeaderMap;

use super::ServerIdentity;
use super::token::{Claims, TokenError};
use crate::error::AppError;

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
/// as an absent one.
pub fn verify_bearer_if_present(
    headers: &HeaderMap,
    identity: &ServerIdentity,
    now: i64,
) -> Result<Option<Claims>, TokenError> {
    bearer_token(headers)
        .map(|token| identity.verify_token(token, now))
        .transpose()
}

/// Require a valid bearer token: reject a missing, malformed, or invalid
/// token alike. Real, independently-tested infrastructure for a future
/// route that needs mandatory bearer auth -- no current route in this
/// campaign uses it (R7 keeps `/push` optional and the witness-read
/// routes public), so nothing calls this yet.
pub fn require_bearer(
    headers: &HeaderMap,
    identity: &ServerIdentity,
    now: i64,
) -> Result<Claims, AppError> {
    match verify_bearer_if_present(headers, identity, now) {
        Ok(Some(claims)) => Ok(claims),
        Ok(None) => Err(AppError::unauthorized("missing bearer token")),
        Err(e) => Err(AppError::unauthorized(format!("bearer token rejected: {e}"))),
    }
}

/// `/push`'s admission knob (ARCHITECT RULING R7): a bearer token is
/// never required -- the pushed commit bundle's own signatures are the
/// real authorization -- but if one IS presented it must verify and its
/// `pr` claim must match `target_principal`, so a valid token for one
/// principal cannot be replayed to push under another's identity.
///
/// If the server holds no signing identity at all, no token this server
/// ever issued could exist, so the check is skipped entirely (mirrors
/// the no-token case) rather than rejecting on a config detail unrelated
/// to the pushed payload's own validity.
pub fn check_push_admission(
    headers: &HeaderMap,
    identity: Option<&ServerIdentity>,
    target_principal: &str,
    now: i64,
) -> Result<(), AppError> {
    let Some(identity) = identity else {
        return Ok(());
    };

    match verify_bearer_if_present(headers, identity, now) {
        Ok(None) => Ok(()),
        Ok(Some(claims)) if claims.pr == target_principal => Ok(()),
        Ok(Some(_)) => Err(AppError::unauthorized(
            "bearer token does not authorize this principal",
        )),
        Err(e) => Err(AppError::unauthorized(format!("bearer token rejected: {e}"))),
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
            .issue_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        let result = verify_bearer_if_present(&headers, &identity, 1_100);
        let claims = result.expect("valid token verifies").expect("token present");
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

    // --- require_bearer ---

    #[test]
    fn require_bearer_rejects_missing_token() {
        let identity = test_identity();
        let headers = HeaderMap::new();
        assert!(require_bearer(&headers, &identity, 1_100).is_err());
    }

    #[test]
    fn require_bearer_accepts_valid_token() {
        let identity = test_identity();
        let token = identity
            .issue_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        let claims = require_bearer(&headers, &identity, 1_100).expect("valid token accepted");
        assert_eq!(claims.pr, PR);
    }

    #[test]
    fn require_bearer_rejects_invalid_token() {
        let identity = test_identity();
        let headers = headers_with_bearer("garbage");
        assert!(require_bearer(&headers, &identity, 1_100).is_err());
    }

    // --- check_push_admission ---

    #[test]
    fn check_push_admission_allows_no_token() {
        let identity = test_identity();
        let headers = HeaderMap::new();
        assert!(check_push_admission(&headers, Some(&identity), PR, 1_100).is_ok());
    }

    #[test]
    fn check_push_admission_allows_matching_token() {
        let identity = test_identity();
        let token = identity
            .issue_token(PR, vec!["write".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        assert!(check_push_admission(&headers, Some(&identity), PR, 1_100).is_ok());
    }

    #[test]
    fn check_push_admission_rejects_mismatched_token() {
        let identity = test_identity();
        let token = identity
            .issue_token("other-principal", vec!["write".to_string()], 1_000, 300)
            .expect("issue token");
        let headers = headers_with_bearer(&token);
        assert!(check_push_admission(&headers, Some(&identity), PR, 1_100).is_err());
    }

    #[test]
    fn check_push_admission_rejects_invalid_token() {
        let identity = test_identity();
        let headers = headers_with_bearer("garbage");
        assert!(check_push_admission(&headers, Some(&identity), PR, 1_100).is_err());
    }

    #[test]
    fn check_push_admission_allows_when_no_identity_configured() {
        // A token is presented but the server holds no signing identity at
        // all -- no such token could ever have been genuinely issued by
        // this server, so the check is skipped rather than rejecting on a
        // config detail unrelated to the pushed payload's own validity.
        let headers = headers_with_bearer("anything");
        assert!(check_push_admission(&headers, None, PR, 1_100).is_ok());
    }
}
