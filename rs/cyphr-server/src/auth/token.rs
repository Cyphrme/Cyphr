//! Bearer-token issuance and verification (SPEC.md 17.4).
//!
//! A bearer token is a signed Coz message *from the service*: the server
//! signs the claims with its own [`ServerIdentity`], and a holder presents
//! the resulting opaque string on subsequent requests instead of re-signing
//! each one. This module only builds the issue/verify primitive -- it is not
//! wired to any login flow or HTTP route yet.
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

    /// The token's `exp` claim is at or before the reference time.
    #[error("bearer token has expired")]
    Expired,
}

impl ServerIdentity {
    /// Issue a bearer token for `pr`, authorizing `perms`, expiring
    /// `ttl_secs` after `now`.
    ///
    /// Returns `None` if coz rejects the payload or this identity's key
    /// (mirrors [`ServerIdentity::sign`]).
    pub fn issue_token(
        &self,
        typ: impl Into<String>,
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
        pay.typ = Some(typ.into());
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
    /// service, or any tampering with the signed claims), and a token whose
    /// `exp` is at or before `now`.
    pub fn verify_token(&self, token: &str, now: i64) -> Result<Claims, TokenError> {
        let coz_json: coz::CozJson = serde_json::from_str(token)?;
        let pay_json = serde_json::to_vec(&coz_json.pay)?;

        if self.verify(&pay_json, &coz_json.sig) != Some(true) {
            return Err(TokenError::InvalidSignature);
        }

        let pay: coz::Pay = serde_json::from_value(coz_json.pay)?;
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

    const TYP: &str = "cyphr-server/auth/token";
    const PR: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    #[test]
    fn issue_then_verify_genuine_unexpired_token_succeeds() {
        let (_dir, path) = write_random_key_file();
        let identity = ServerIdentity::load_from_path(&path).expect("load signing key");

        let token = identity
            .issue_token(
                TYP,
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
            .issue_token(TYP, PR, vec!["read".to_string()], 1_000, 300)
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
            .issue_token(TYP, PR, vec!["read".to_string()], 1_000, 300)
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
            .issue_token(TYP, PR, vec!["read".to_string()], 1_000, 300)
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
                TYP,
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
}
