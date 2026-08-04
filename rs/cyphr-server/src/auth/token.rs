//! Bearer-token issuance and verification (SPEC.md 17.4).
//!
//! A bearer token is a signed Coz message *from the service*: the server
//! signs the claims with its own [`ServerIdentity`], and a holder presents
//! the resulting opaque string on subsequent requests instead of re-signing
//! each one. `issue_token` is called from the login flow (`auth::login`);
//! `verify_token` is called from `auth::middleware`'s bearer-verification
//! helpers, wired into `/push`'s optional admission knob.
//!
//! There is no revocation list in v1 (ruling R8): a short `exp` is the sole
//! invalidation mechanism, and the token carries the issuing key's `tmb` so
//! a future key-rotation story has a verification-time anchor to check
//! against.

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
}

/// Errors verifying a bearer token.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The token was not valid JSON in the expected Coz shape.
    #[error("bearer token is not valid JSON: {0}")]
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
    /// Issue a bearer token for `pr`, authorizing `perms`, expiring
    /// `ttl_secs` after `now`.
    ///
    /// The token is always stamped with [`BEARER_TOKEN_TYP`]; the caller
    /// cannot mint a token under any other `typ`, which is the issuance
    /// half of the F22 binding (verification checks the same constant).
    ///
    /// Returns `None` if coz rejects the payload or this identity's key
    /// (mirrors [`ServerIdentity::sign`]).
    pub fn issue_token(
        &self,
        pr: impl Into<String>,
        perms: Vec<String>,
        now: i64,
        ttl_secs: i64,
    ) -> Option<String> {
        let tmb = self.alg().compute_thumbprint(self.pub_key())?;

        let mut pay = coz::Pay::new();
        pay.alg = Some(self.alg().name().to_string());
        pay.now = Some(now);
        pay.tmb = Some(tmb);
        pay.typ = Some(BEARER_TOKEN_TYP.to_string());
        pay.extra.insert("pr".to_string(), Value::String(pr.into()));
        pay.extra
            .insert("exp".to_string(), Value::from(now + ttl_secs));
        pay.extra.insert("perms".to_string(), Value::from(perms));

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

    Ok(Claims {
        pr,
        perms,
        exp,
        tmb,
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

    /// Forge a Coz message signed by `identity` carrying an arbitrary
    /// `typ` but otherwise-valid bearer-token claims. Used to exercise
    /// F22: a message the server genuinely signed, presented as a bearer
    /// token, must still be rejected when its `typ` is not
    /// [`BEARER_TOKEN_TYP`].
    fn forge_signed_message(identity: &ServerIdentity, typ: &str, now: i64, exp: i64) -> String {
        let tmb = identity
            .alg()
            .compute_thumbprint(identity.pub_key())
            .expect("thumbprint");

        let mut pay = coz::Pay::new();
        pay.alg = Some(identity.alg().name().to_string());
        pay.now = Some(now);
        pay.tmb = Some(tmb);
        pay.typ = Some(typ.to_string());
        pay.extra.insert("pr".to_string(), Value::String(PR.into()));
        pay.extra.insert("exp".to_string(), Value::from(exp));
        pay.extra
            .insert("perms".to_string(), Value::from(vec!["read".to_string()]));

        let pay_json = serde_json::to_vec(&pay).expect("serialize pay");
        let (sig, _cad) = identity.sign(&pay_json).expect("sign");
        let pay_value = serde_json::to_value(&pay).expect("pay to value");
        serde_json::to_string(&coz::CozJson {
            pay: pay_value,
            sig,
        })
        .expect("serialize coz")
    }

    #[test]
    fn issue_then_verify_genuine_unexpired_token_succeeds() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_token(
                PR,
                vec!["read".to_string(), "write".to_string()],
                1_000,
                300,
            )
            .expect("issue token");

        let claims = identity
            .verify_token(&token, 1_100)
            .expect("verify unexpired token");

        assert_eq!(claims.pr, PR);
        assert_eq!(claims.perms, vec!["read".to_string(), "write".to_string()]);
        assert_eq!(claims.exp, 1_300);
        assert_eq!(
            claims.tmb,
            identity
                .alg()
                .compute_thumbprint(identity.pub_key())
                .unwrap()
                .to_b64()
        );
    }

    #[test]
    fn verify_rejects_tampered_claims() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_token(PR, vec!["read".to_string()], 1_000, 300)
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

    #[test]
    fn verify_rejects_foreign_signer() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let (_foreign_dir, foreign_path) = write_random_key_file();
        let foreign = ServerIdentity::load_from_path(&foreign_path).expect("load foreign key");

        let token = foreign
            .issue_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token from foreign identity");

        let result = identity.verify_token(&token, 1_100);
        assert!(
            matches!(result, Err(TokenError::InvalidSignature)),
            "a token issued by a foreign key must not verify against a different identity, got: \
             {result:?}"
        );
    }

    #[test]
    fn verify_rejects_expired_token() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_token(PR, vec!["read".to_string()], 1_000, 300)
            .expect("issue token");

        // now == exp: expiry is inclusive of the boundary instant.
        let result = identity.verify_token(&token, 1_300);
        assert!(
            matches!(result, Err(TokenError::Expired)),
            "a token at/after its exp must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn verify_rejects_malformed_token() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let result = identity.verify_token("not json", 1_000);
        assert!(
            matches!(result, Err(TokenError::Malformed(_))),
            "malformed JSON must be rejected with a typed error, got: {result:?}"
        );
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
            .issue_token(
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
            r#""exp":1700000900,"perms":["read","write"]},"#,
            r#""sig":"a7Gqw1C2Pd8XgBS-HYdzPfinLtAKZl2AlDeEWWpcNLrIoyNBm-_icERvy4SlNMQOJCzLw5w5A0w08t5dl8aYCg"}"#,
        );

        assert_eq!(token, GOLDEN);

        // The golden vector must itself verify, so a future accidental
        // signature-only bit-flip in the constant above is also caught.
        let claims = identity
            .verify_token(&token, 1_700_000_000)
            .expect("golden-vector token must verify");
        assert_eq!(claims.pr, PR);
    }

    /// F22: a message the server genuinely signed, with valid
    /// `pr`/`exp`/`perms`/`tmb` claims and an unexpired `exp`, but whose
    /// `typ` is not [`BEARER_TOKEN_TYP`], must be rejected -- otherwise
    /// any other message the server key ever signs could be replayed as a
    /// bearer token. The signature here is real (same identity), so only
    /// the `typ` binding stands between it and acceptance.
    // docket: signon-token-kind-binding :: cargo test --manifest-path rs/Cargo.toml --lib
    #[test]
    fn verify_rejects_valid_signature_with_wrong_typ() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let forged = forge_signed_message(&identity, "cyphr-server/auth/not-a-token", 1_000, 1_300);

        // Sanity: the forgery IS a genuine signature by this identity --
        // it is the `typ` binding, not the signature, that must reject it.
        let coz_json: coz::CozJson = serde_json::from_str(&forged).expect("forged parses");
        let pay_json = serde_json::to_vec(&coz_json.pay).expect("pay bytes");
        assert_eq!(
            identity.verify(&pay_json, &coz_json.sig),
            Some(true),
            "test setup: the forged message must carry a genuine signature by this identity"
        );

        let result = identity.verify_token(&forged, 1_100);
        assert!(
            matches!(result, Err(TokenError::TypMismatch)),
            "a validly-signed, unexpired message whose typ is not the bearer typ must be rejected \
             as TypMismatch, got: {result:?}"
        );
    }
}
