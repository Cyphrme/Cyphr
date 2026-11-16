//! Bearer-token issuance and verification (SPEC.md 17.4).
//!
//! A bearer token is a signed Coz message *from the service*: the server
//! signs the claims with its own [`ServerIdentity`], and a holder presents
//! the resulting opaque string on subsequent requests instead of re-signing
//! each one. `issue_login_token` is called from the login flow (`auth::login`);
//! `verify_token` is called from `auth::middleware`'s bearer-verification
//! helpers, wired into `/push`'s optional admission knob.
//!
//! There is no revocation list (ruling R8), but a session is bound to the
//! key that opened it: a login token carries that key's thumbprint in
//! [`LOGIN_KEY_FIELD`], and route protection refuses the token once the key
//! is no longer active in the server's current view of the principal
//! (`auth::middleware`). `exp` still caps a session on top of that.
//!
//! A login over the principal-authenticated Noise transport commits to its
//! channel: the client signs the session's handshake hash `h` into the
//! login, the server accepts it only from the session's own principal and
//! key and only when `h` equals that session's hash, and then signs the
//! hash into the token ([`CHANNEL_FIELD`]) so the token is good only on
//! that channel (Noise section 11.2: the handshake hash is the channel
//! binding). A login over plain HTTP, a browser edge, carries no `h` and
//! gets a token with no channel claim: that session is bound to its key
//! alone. Neither login can be presented as the other. Admission reads the
//! channel only from this server-signed token, never from the request.
//!
//! # Bearer residual
//!
//! A token is still a bearer credential. A channel-bound token is useless
//! off its channel, but whoever controls that channel (the client's own
//! endpoint, or a process that reads its memory) can use it until `exp`; a
//! key-bound (browser) token has no channel at all and works for anyone who
//! holds it until `exp` or until its key leaves the chain. Binding narrows
//! theft, it does not make a token proof of possession. The lifetime is
//! therefore short and configured (`session_ttl_secs`, at most an hour),
//! and a session is never extended: only a new login, which proves
//! possession of the key again, mints a new token. A timestamp-flow login
//! can be replayed inside its window; the challenge flow is single-use.
//! That residual is why Authenticated Atomic Actions (AAA), each signed
//! individually by the key, are preferred over a bearer token for
//! sensitive operations.
//! The binding is a signed claim rather than a server-side session table,
//! so it survives a restart and adds no state.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;

use super::ServerIdentity;

/// Default token lifetime: 15 minutes.
///
/// SPEC.md 17.4 names no specific duration. Short enough that R8's
/// no-revocation stance is a reasonable trade, long enough to avoid
/// re-authenticating on every request.
pub const DEFAULT_TTL_SECS: i64 = 15 * 60;

/// The `typ` every bearer token this server issues is stamped with, and
/// the only `typ` [`ServerIdentity::verify_token`] accepts.
///
/// A bearer token is just a Coz message the server signed; without a
/// fixed, checked `typ` any *other* message the server key ever signs
/// (a future signed notice, a different protocol message) whose payload
/// happens to carry `pr`/`exp`/`perms`/`tmb` would verify as a bearer
/// token. Stamping issuance and checking verification against this one
/// constant makes the two symmetric, so a token's kind is bound into
/// the signature, not merely assumed by the reader.
pub const BEARER_TOKEN_TYP: &str = "cyphr-server/auth/token";

/// The signed claim naming the thumbprint (b64ut) of the principal key
/// that logged in. The server signs it, so a holder cannot rebind a
/// session to a different key; route protection re-checks that key
/// against the principal chain on every request (#162). Absent on a
/// token not minted by a login, which route protection refuses.
pub const LOGIN_KEY_FIELD: &str = "ltmb";

/// The signed claim holding the handshake hash (b64ut) of the Noise
/// session that issued the token. Present only on a token minted over the
/// transport; route protection refuses such a token on any other channel.
pub const CHANNEL_FIELD: &str = "cb";

/// Claims extracted from a verified bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The principal's genesis identifier.
    pub pr: String,
    /// Permissions the token authorizes.
    pub perms: Vec<String>,
    /// Unix expiry timestamp.
    pub exp: i64,
    /// The issuing key's thumbprint (b64ut), SPEC.md 17.4 / ruling R8.
    pub tmb: String,
    /// The thumbprint (b64ut) of the principal key that logged in
    /// ([`LOGIN_KEY_FIELD`]); `None` for a token not minted by a login.
    pub login_tmb: Option<String>,
    /// The handshake hash of the Noise session that issued the token
    /// ([`CHANNEL_FIELD`]); `None` for a key-bound (browser edge) token.
    pub channel: Option<Vec<u8>>,
}

/// Errors verifying a bearer token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The token was not valid JSON in the expected Coz shape.
    #[error("bearer token is not valid JSON ({})", super::json_fault(.0))]
    Malformed(#[from] serde_json::Error),

    /// The payload verified but is missing a required claim.
    #[error("bearer token payload is missing required claim `{0}`")]
    MissingClaim(&'static str),

    /// The signature did not verify against this identity's key.
    #[error("bearer token signature is invalid")]
    InvalidSignature,

    /// The payload verified against this identity's key but its `typ` is
    /// not [`BEARER_TOKEN_TYP`] -- some other message the server signed,
    /// presented as a bearer token (closes F22).
    #[error("message is not a bearer token: wrong `typ`")]
    TypMismatch,

    /// The token's `exp` claim is at or before the reference time.
    #[error("bearer token has expired")]
    Expired,
}

impl ServerIdentity {
    /// Issue the bearer token a successful login mints: `pr`, authorizing
    /// `perms`, expiring `ttl_secs` after `now`, plus the thumbprint of the
    /// key that logged in. That thumbprint is signed into the token so
    /// route protection can end the session when the key leaves the chain
    /// or dies (#162).
    ///
    /// The token is always stamped with [`BEARER_TOKEN_TYP`]; the caller
    /// cannot mint a token under any other `typ`, which is the issuance
    /// half of the F22 binding (verification checks the same constant).
    ///
    /// `channel` is the handshake hash of the Noise session the login
    /// arrived on, or `None` for a login with no channel (a browser edge),
    /// whose token is bound to the key alone.
    ///
    /// Returns `None` if coz rejects the payload or this identity's key
    /// (mirrors [`ServerIdentity::sign`]).
    pub fn issue_login_token(
        &self,
        pr: impl Into<String>,
        login_tmb: &coz::Thumbprint,
        perms: Vec<String>,
        now: i64,
        ttl_secs: i64,
        channel: Option<&[u8]>,
    ) -> Option<String> {
        self.issue(pr.into(), Some(login_tmb), perms, now, ttl_secs, channel)
    }

    /// A login-shaped token under a fixed login key, for unit tests that
    /// only need some verifiable token.
    #[cfg(test)]
    pub(crate) fn issue_test_token(
        &self,
        pr: impl Into<String>,
        perms: Vec<String>,
        now: i64,
        ttl_secs: i64,
    ) -> Option<String> {
        let tmb = coz::Alg::Ed25519.compute_thumbprint(&[7u8; 32])?;
        self.issue_login_token(pr, &tmb, perms, now, ttl_secs, None)
    }

    /// A validly signed token that names no login key -- what no login
    /// mints -- to exercise route protection's fail-closed arm.
    #[cfg(test)]
    pub(crate) fn issue_unbound_token(
        &self,
        pr: impl Into<String>,
        perms: Vec<String>,
        now: i64,
        ttl_secs: i64,
    ) -> Option<String> {
        self.issue(pr.into(), None, perms, now, ttl_secs, None)
    }

    fn issue(
        &self,
        pr: String,
        login_tmb: Option<&coz::Thumbprint>,
        perms: Vec<String>,
        now: i64,
        ttl_secs: i64,
        channel: Option<&[u8]>,
    ) -> Option<String> {
        let tmb = self.alg().compute_thumbprint(self.pub_key())?;

        let mut pay = coz::Pay::new();
        pay.alg = Some(self.alg().name().to_string());
        pay.now = Some(now);
        pay.tmb = Some(tmb);
        pay.typ = Some(BEARER_TOKEN_TYP.to_string());
        pay.extra.insert("pr".to_string(), Value::String(pr));
        pay.extra
            .insert("exp".to_string(), Value::from(now + ttl_secs));
        pay.extra.insert("perms".to_string(), Value::from(perms));
        if let Some(login_tmb) = login_tmb {
            pay.extra.insert(
                LOGIN_KEY_FIELD.to_string(),
                Value::String(login_tmb.to_b64()),
            );
        }

        if let Some(channel) = channel {
            pay.extra.insert(
                CHANNEL_FIELD.to_string(),
                Value::String(Base64UrlUnpadded::encode_string(channel)),
            );
        }

        let pay_json = serde_json::to_vec(&pay).ok()?;
        let (sig, _cad) = self.sign(&pay_json)?;
        let pay_value = serde_json::to_value(&pay).ok()?;

        serde_json::to_string(&coz::CozJson {
            pay: pay_value,
            sig,
        })
        .ok()
    }

    /// Verify a bearer token issued by this identity.
    ///
    /// Rejects a malformed token, a signature that does not verify against
    /// this identity's key (including a genuine token from a foreign
    /// service, or any tampering with the signed claims), a validly-signed
    /// message whose `typ` is not [`BEARER_TOKEN_TYP`] (so a different
    /// message the server signed cannot pose as a token -- F22), and a
    /// token whose `exp` is at or before `now`.
    pub fn verify_token(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        let coz_json: coz::CozJson = serde_json::from_str(token)?;
        let pay_json = serde_json::to_vec(&coz_json.pay)?;

        if self.verify(&pay_json, &coz_json.sig) != Some(true) {
            return Err(TokenError::InvalidSignature);
        }

        let pay: coz::Pay = serde_json::from_value(coz_json.pay)?;

        // Bind the message kind into verification: the signature above
        // only proves *this server* signed *these bytes*, not that it
        // signed them *as a bearer token* (F22).
        if pay.typ.as_deref() != Some(BEARER_TOKEN_TYP) {
            return Err(TokenError::TypMismatch);
        }

        let claims = claims_from_pay(&pay)?;

        if claims.exp <= now {
            return Err(TokenError::Expired);
        }

        Ok(claims)
    }
}

/// Extract [`Claims`] from a verified payload's fields.
fn claims_from_pay(pay: &coz::Pay) -> Result<Claims, TokenError> {
    let tmb = pay
        .tmb
        .as_ref()
        .ok_or(TokenError::MissingClaim("tmb"))?
        .to_b64();

    let pr = pay
        .extra
        .get("pr")
        .and_then(Value::as_str)
        .ok_or(TokenError::MissingClaim("pr"))?
        .to_string();

    let exp = pay
        .extra
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(TokenError::MissingClaim("exp"))?;

    let perms = pay
        .extra
        .get("perms")
        .and_then(Value::as_array)
        .ok_or(TokenError::MissingClaim("perms"))?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()
        .ok_or(TokenError::MissingClaim("perms"))?;

    let login_tmb = pay
        .extra
        .get(LOGIN_KEY_FIELD)
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or(TokenError::MissingClaim(LOGIN_KEY_FIELD))
        })
        .transpose()?;

    let channel = pay
        .extra
        .get(CHANNEL_FIELD)
        .map(|v| {
            v.as_str()
                .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                .ok_or(TokenError::MissingClaim(CHANNEL_FIELD))
        })
        .transpose()?;

    Ok(Claims {
        pr,
        perms,
        exp,
        tmb,
        login_tmb,
        channel,
    })
}

#[cfg(test)]
mod tests {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;

    /// Write a signing key file for a fixed (deterministic) Ed25519
    /// keypair, for golden-vector coverage.
    fn write_fixed_key_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");

        let prv_key = [0x11u8; 32];
        let pub_key = coz::Alg::Ed25519
            .derive_public_key(&prv_key)
            .expect("derive public key from fixed seed");

        let file = serde_json::json!({
            "alg": coz::Alg::Ed25519.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&pub_key),
            "prv_key": Base64UrlUnpadded::encode_string(&prv_key),
        });
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        (dir, path)
    }

    /// Write a signing key file for a fresh, randomly generated keypair.
    fn write_random_key_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("signing-key.json");

        let kp = coz::Alg::Ed25519.generate_keypair();
        let file = serde_json::json!({
            "alg": kp.alg.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
            "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
        });
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        (dir, path)
    }

    const PR: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    /// Backs: bearer-token claims are signature-bound; a rewritten claim is refused.
    /// Unit: e2e cannot rewrite a token minted by the server.
    #[test]
    fn verify_rejects_tampered_claims() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_test_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");

        // Flip a claim without re-signing: "read" -> "admin".
        let tampered = token.replace("read", "admin");
        assert_ne!(
            tampered, token,
            "test setup: replacement must actually change the token"
        );

        let result = identity.verify_token(&tampered, 1_100);
        assert!(
            matches!(result, Err(TokenError::InvalidSignature)),
            "tampered claims must fail signature verification, got: {result:?}"
        );
    }

    /// Backs: bearer tokens expire.
    /// Unit: e2e cannot advance the server clock past `exp`.
    #[test]
    fn verify_rejects_expired_token() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_test_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");

        // now == exp: expiry is inclusive of the boundary instant.
        let result = identity.verify_token(&token, 1_300);
        assert!(
            matches!(result, Err(TokenError::Expired)),
            "a token at/after its exp must be rejected, got: {result:?}"
        );
    }

    /// Backs the shared `json_fault` rule on the bearer path: a wrong-typed
    /// token field is a typed refusal that does not echo the value.
    #[test]
    fn malformed_token_does_not_echo_values() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
        let err = identity
            .verify_token(r#"{"pay":{},"sig":424242424242}"#, 0)
            .expect_err("a numeric sig is malformed");
        assert!(matches!(err, TokenError::Malformed(_)));
        assert!(!err.to_string().contains("424242424242"), "{err}");
    }

    /// Byte-exact golden vector: a fixed key, fixed claims, and fixed
    /// timestamps must always produce this exact wire-format string. A
    /// silent change to field order, encoding, or the signing/canon
    /// pipeline breaks this test loudly instead of drifting unnoticed.
    #[test]
    fn issued_token_matches_golden_vector() {
        let (_dir, path) = write_fixed_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_test_token(
                PR,
                vec!["read".to_string(), "write".to_string()],
                1_700_000_000,
                900,
            )
            .expect("issue token");

        const GOLDEN: &str = concat!(
            r#"{"pay":{"alg":"Ed25519","now":1700000000,"#,
            r#""tmb":"aaMiqIXTeW8wfSkKY_ME3BDBAfz5t-qPLabapQ1TQfNzUFPOEp4_4KTGYRUHVbe18MOVsXusLb0qAWmmoV3Yvw","#,
            r#""typ":"cyphr-server/auth/token","pr":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","#,
            r#""exp":1700000900,"perms":["read","write"],"#,
            r#""ltmb":"OzD0J6wdMqmN0aWu42RcWFRp1DzYJeQW8KYvXdrsLOrNV8Pva_ZpjrNtvsdqWsFL_zpZUDutAiTu4W5OdIL44A"},"#,
            r#""sig":"rdOfTv9Wm11gKJ9YT6tbj1wNs1cB8aF_yQKPjahwc3iEccPcsZF8wjJf9cJb04LHkAqhZ8BD3kYuWJi5HjaVAQ"}"#,
        );

        assert_eq!(token, GOLDEN);

        // The golden vector must itself verify, so a future accidental
        // signature-only bit-flip in the constant above is also caught.
        let claims = identity
            .verify_token(&token, 1_700_000_000)
            .expect("golden-vector token must verify");
        assert_eq!(claims.pr, PR);
    }

    /// Backs: the login key rides in the signed token (#162). The claim
    /// round-trips, a plain token carries none, and rewriting it breaks the
    /// signature, so a holder cannot rebind a session to another key.
    #[test]
    fn login_token_signs_in_the_login_key() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
        let login_tmb = coz::Alg::Ed25519
            .compute_thumbprint(&coz::Alg::Ed25519.generate_keypair().pub_bytes)
            .expect("thumbprint");

        let token = identity
            .issue_login_token(PR, &login_tmb, vec!["read".to_string()], 1_000, 300, None)
            .expect("issue login token");
        let claims = identity.verify_token(&token, 1_100).expect("verifies");
        assert_eq!(claims.login_tmb, Some(login_tmb.to_b64()));

        let plain = identity
            .issue_unbound_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue plain token");
        assert_eq!(
            identity.verify_token(&plain, 1_100).unwrap().login_tmb,
            None
        );

        let rebound = token.replace(&login_tmb.to_b64(), &"A".repeat(login_tmb.to_b64().len()));
        assert!(matches!(
            identity.verify_token(&rebound, 1_100),
            Err(TokenError::InvalidSignature)
        ));
    }
}
