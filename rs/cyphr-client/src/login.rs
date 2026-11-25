//! The login contract (SPEC 17.2), defined once for every party that signs
//! a login or checks one: the user's device, a Cyphr server, and a
//! separated relying party.
//!
//! It follows the spec author's login design (`login/README.md` and
//! `login/login.go` on the `zami` branch): the user signs a login request,
//! the service verifies it and signs a bearer token. The challenge is
//! optional there; when one is used it is a Coz the service signed, and the
//! request carries it back beside its own signature so the service need
//! only recognise its own signature. Four `typ` names are recommended:
//! `.../challenge/create`, `.../request/create`, `.../bearer/create` (the
//! token) and `.../bearer/delete` (sign-out, which is the client dropping
//! its token; nothing issues it, so no constant is kept for it).
//!
//! # What is bound
//!
//! - **Audience.** The authority segment of the request and challenge `typ` is the service the
//!   signer believes it is signing in to. A service accepts only its own name there, so a login
//!   signed for one service cannot be relayed to another.
//! - **Principal.** SPEC permits one key across many principals, so a `tmb` alone is ambiguous. The
//!   request names the principal as `pg`, and the service looks the key up in that principal only.
//! - **Single use.** A challenge is redeemed once: [`SpentChallenges`] remembers a used nonce until
//!   the challenge could no longer verify.
//!
//! Correlation is not hidden: a principal's `pg` and `tmb` are the same at
//! every service it signs in to.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::{CozJson, Thumbprint};
use cyphr::signer::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Suffix of a login request `typ`; the text before it is the audience.
pub const REQUEST_TYP_SUFFIX: &str = "/user/login/request/create";

/// Suffix of a challenge `typ`; the text before it is the audience.
pub const CHALLENGE_TYP_SUFFIX: &str = "/user/login/challenge/create";

/// The `typ` of the bearer token a service signs after a login.
pub const BEARER_TYP: &str = "cyphr.me/user/login/bearer/create";

/// Acceptance half-window, in seconds, for a request that carries no
/// challenge (SPEC 17.2 Option B: +-60s).
pub const TIMESTAMP_WINDOW_SECS: i64 = 60;

/// How long an issued challenge stays redeemable.
pub const CHALLENGE_TTL_SECS: i64 = 120;

/// Default lifetime of a signed-in session, in seconds: 15 minutes.
///
/// SPEC 17.4 names no duration. A bearer token is good for whoever holds
/// it until it ends, so a session is short and never extended; one that
/// wants longer signs in again. A server's `session_ttl_secs` and a relying
/// party's [`session_ttl`](crate::RpConfig::session_ttl) both read as this.
pub const DEFAULT_SESSION_TTL_SECS: i64 = 15 * 60;

/// Challenge nonce length: 256 bits (SPEC 17.2).
pub const CHALLENGE_BYTES: usize = 32;

/// Names of the claims a login carries beyond `alg`, `now`, `tmb`, `typ`.
pub mod field {
    /// The claimed principal's genesis, in a request.
    pub const PG: &str = "pg";
    /// The challenge nonce, in a request (the challenge Coz carries it as
    /// [`NONCE`]).
    pub const CHALLENGE: &str = "challenge";
    /// The nonce, in a challenge.
    pub const NONCE: &str = "nonce";
    /// The Noise handshake hash (b64ut) of the channel a login is sent
    /// over, signed so the login names its channel.
    pub const CHANNEL: &str = "h";
}

/// Why a login or challenge was refused when checked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// A required claim is absent or not the type the contract needs.
    #[error("login is missing required claim `{0}`")]
    MissingField(&'static str),
    /// `typ` is absent or not a login request.
    #[error("login `typ` is not a login request")]
    NotALogin,
    /// A login-shaped `typ` whose authority segment is empty.
    #[error("login names no audience")]
    AudienceMissing,
    /// The channel claim is not base64url.
    #[error("login claim `h` is not base64url")]
    ChannelMalformed,
    /// The challenge is absent where one is needed, is not this issuer's,
    /// is for another audience, is expired, does not match the request's
    /// nonce, or was already redeemed.
    #[error("login challenge is unknown, used, or expired")]
    ChallengeInvalid,
    /// The request's signature did not verify under the key it names.
    #[error("login signature is invalid")]
    InvalidSignature,
}

/// Why a login request or challenge could not be signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The pay does not serialize or canonicalize.
    #[error("login pay cannot be canonicalized: {0}")]
    Canonicalize(String),
    /// The challenge to answer carries no nonce.
    #[error("the challenge to answer carries no nonce")]
    ChallengeHasNoNonce,
    /// The user's signer failed.
    #[error("the signer failed: {0}")]
    Signer(String),
    /// The issuer's key cannot sign.
    #[error(transparent)]
    Issuer(#[from] IssuerError),
}

/// An [`Issuer`] failed to produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the issuer key cannot sign: {0}")]
pub struct IssuerError(pub String);

/// A login request on the wire: the signed Coz and, in the challenge flow,
/// the challenge the service signed, returned to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    /// The signed request: `{pay, sig}`.
    #[serde(flatten)]
    pub coz: CozJson,
    /// The service's signed challenge, present iff the request answers one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<CozJson>,
}

/// A request's claims, extracted and shape-checked. The signature is not
/// yet verified: that needs the key, which only the caller can look up.
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// The signing key's thumbprint.
    pub tmb: Thumbprint,
    /// The signing algorithm named in the payload.
    pub alg: String,
    /// The signer's timestamp.
    pub now: i64,
    /// The service the signer names (the `typ`'s authority segment).
    pub audience: String,
    /// The claimed principal's genesis, as the signer spelled it.
    pub pg: String,
    /// The challenge nonce the request answers, if any.
    pub nonce: Option<String>,
    /// The channel hash the request commits to, if any.
    pub channel: Option<Vec<u8>>,
    /// The exact payload bytes the signature is over.
    pub pay_bytes: Vec<u8>,
    /// The signature.
    pub sig: Vec<u8>,
    /// The service's challenge, returned.
    pub challenge: Option<CozJson>,
}

impl ParsedRequest {
    /// Check the signature under the key the caller looked up for
    /// [`tmb`](Self::tmb) (`alg`, `pub_key`).
    ///
    /// # Errors
    ///
    /// [`VerifyError::InvalidSignature`] when it does not verify.
    pub fn verify(self, alg: &str, pub_key: &[u8]) -> Result<VerifiedRequest, VerifyError> {
        if alg == self.alg
            && coz::verify_json(&self.pay_bytes, &self.sig, alg, pub_key) == Some(true)
        {
            Ok(VerifiedRequest(self))
        } else {
            Err(VerifyError::InvalidSignature)
        }
    }

    /// Whether the request's `now` is within the window of `server_now`
    /// ([`within_window`]).
    #[must_use]
    pub fn in_window(&self, server_now: i64) -> bool {
        within_window(self.now, server_now)
    }
}

/// Whether `client_now` is within [`TIMESTAMP_WINDOW_SECS`] of `server_now`,
/// in either direction. The client's value is attacker-chosen, so the
/// distance is `abs_diff`, which cannot overflow where a subtract-then-abs
/// would at `i64::MIN`.
#[must_use]
pub fn within_window(client_now: i64, server_now: i64) -> bool {
    server_now.abs_diff(client_now) <= TIMESTAMP_WINDOW_SECS.unsigned_abs()
}

/// A request whose signature verified under the key its signer named: the
/// only thing [`redeem_challenge`] accepts, so a challenge cannot be spent
/// by a login that was never checked.
#[derive(Debug, Clone)]
pub struct VerifiedRequest(ParsedRequest);

impl std::ops::Deref for VerifiedRequest {
    type Target = ParsedRequest;

    fn deref(&self) -> &ParsedRequest {
        &self.0
    }
}

fn str_claim<'a>(pay: &'a Value, name: &'static str) -> Result<&'a str, VerifyError> {
    pay.get(name)
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField(name))
}

/// Extract and shape-check a request's claims.
///
/// # Errors
///
/// The [`VerifyError`] naming the first claim that is absent or malformed.
pub fn parse_request(request: &LoginRequest) -> Result<ParsedRequest, VerifyError> {
    let pay = &request.coz.pay;
    let pay_bytes = serde_json::to_vec(pay).map_err(|_| VerifyError::MissingField("pay"))?;
    let typ = pay
        .get("typ")
        .and_then(Value::as_str)
        .ok_or(VerifyError::NotALogin)?;
    let audience = typ
        .strip_suffix(REQUEST_TYP_SUFFIX)
        .ok_or(VerifyError::NotALogin)?;
    if audience.is_empty() {
        return Err(VerifyError::AudienceMissing);
    }
    let tmb = Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(str_claim(pay, "tmb")?)
            .map_err(|_| VerifyError::MissingField("tmb"))?,
    );
    let now = pay
        .get("now")
        .and_then(Value::as_i64)
        .ok_or(VerifyError::MissingField("now"))?;
    let channel = pay
        .get(field::CHANNEL)
        .map(|v| {
            v.as_str()
                .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                .ok_or(VerifyError::ChannelMalformed)
        })
        .transpose()?;
    Ok(ParsedRequest {
        tmb,
        alg: str_claim(pay, "alg")?.to_owned(),
        now,
        audience: audience.to_owned(),
        pg: str_claim(pay, field::PG)?.to_owned(),
        nonce: pay
            .get(field::CHALLENGE)
            .and_then(Value::as_str)
            .map(str::to_owned),
        channel,
        pay_bytes,
        sig: request.coz.sig.clone(),
        challenge: request.challenge.clone(),
    })
}

/// Build and sign a login request as `signer`, for the service `audience`,
/// naming the principal `pg`. `challenge` selects the challenge flow;
/// `channel` is the handshake hash to commit to over Noise.
///
/// # Errors
///
/// [`SignError`] if the pay cannot be canonicalized or the signer fails.
pub async fn sign_request<S: Signer>(
    signer: &S,
    audience: &str,
    pg: &str,
    now: i64,
    challenge: Option<&CozJson>,
    channel: Option<&[u8]>,
) -> Result<LoginRequest, SignError> {
    let mut pay = Map::new();
    pay.insert("alg".into(), signer.alg().into());
    pay.insert("now".into(), now.into());
    pay.insert(field::PG.into(), pg.into());
    pay.insert("tmb".into(), signer.tmb().to_b64().into());
    pay.insert(
        "typ".into(),
        format!("{audience}{REQUEST_TYP_SUFFIX}").into(),
    );
    if let Some(challenge) = challenge {
        let nonce = challenge_nonce(challenge).map_err(|_| SignError::ChallengeHasNoNonce)?;
        pay.insert(field::CHALLENGE.into(), nonce.into());
    }
    if let Some(h) = channel {
        pay.insert(
            field::CHANNEL.into(),
            Base64UrlUnpadded::encode_string(h).into(),
        );
    }
    pay.sort_keys();
    let pay = Value::Object(pay);
    let pay_bytes = serde_json::to_vec(&pay).map_err(|e| SignError::Canonicalize(e.to_string()))?;
    let cad = coz::canonical_hash_for_alg(&pay_bytes, signer.alg(), None).ok_or_else(|| {
        SignError::Canonicalize(format!("no canonical hash for {}", signer.alg()))
    })?;
    let sig = signer
        .sign(&cad)
        .await
        .map_err(|e| SignError::Signer(e.to_string()))?;
    Ok(LoginRequest {
        coz: CozJson { pay, sig },
        challenge: challenge.cloned(),
    })
}

fn challenge_nonce(challenge: &CozJson) -> Result<String, VerifyError> {
    str_claim(&challenge.pay, field::NONCE).map(str::to_owned)
}

/// A key a service signs challenges with, supplied by the integrating
/// site. The library holds no key of its own.
pub trait Issuer: Send + Sync + std::fmt::Debug {
    /// Coz algorithm name of the key.
    fn alg(&self) -> &str;
    /// Public key bytes, as `coz::verify_json` takes them.
    fn pub_key(&self) -> &[u8];
    /// Sign `pay_bytes` as `coz::sign_json` does.
    ///
    /// # Errors
    ///
    /// [`IssuerError`] naming why the key could not sign.
    fn sign(&self, pay_bytes: &[u8]) -> Result<Vec<u8>, IssuerError>;
}

/// An [`Issuer`] over raw key bytes the caller supplies.
pub struct SoftwareIssuer {
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
}

impl SoftwareIssuer {
    /// Wrap key material the caller holds. Validity is checked when a
    /// challenge is signed.
    #[must_use]
    pub fn new(alg: &str, prv: &[u8], pub_key: &[u8]) -> Self {
        Self {
            alg: alg.to_owned(),
            prv: prv.to_vec(),
            pub_key: pub_key.to_vec(),
        }
    }
}

impl std::fmt::Debug for SoftwareIssuer {
    /// Redacts the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareIssuer")
            .field("alg", &self.alg)
            .field("prv", &"<redacted>")
            .finish()
    }
}

impl Issuer for SoftwareIssuer {
    fn alg(&self) -> &str {
        &self.alg
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn sign(&self, pay_bytes: &[u8]) -> Result<Vec<u8>, IssuerError> {
        coz::sign_json(pay_bytes, &self.alg, &self.prv, &self.pub_key)
            .map(|(sig, _)| sig)
            .ok_or_else(|| IssuerError(format!("{} rejected the key material", self.alg)))
    }
}

/// Issue a challenge for `audience`: a Coz the issuer signs over a fresh
/// 256-bit nonce.
///
/// # Errors
///
/// [`SignError`] if the issuer's key has no thumbprint or cannot sign.
pub fn issue_challenge(
    issuer: &dyn Issuer,
    audience: &str,
    now: i64,
) -> Result<CozJson, SignError> {
    let tmb = coz::compute_thumbprint_for_alg(issuer.alg(), issuer.pub_key())
        .ok_or_else(|| IssuerError("the key has no thumbprint".into()))?;
    let mut nonce = [0u8; CHALLENGE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut pay = Map::new();
    pay.insert("alg".into(), issuer.alg().into());
    pay.insert("now".into(), now.into());
    pay.insert(
        field::NONCE.into(),
        Base64UrlUnpadded::encode_string(&nonce).into(),
    );
    pay.insert("tmb".into(), tmb.to_b64().into());
    pay.insert(
        "typ".into(),
        format!("{audience}{CHALLENGE_TYP_SUFFIX}").into(),
    );
    pay.sort_keys();
    let pay = Value::Object(pay);
    let pay_bytes = serde_json::to_vec(&pay).map_err(|e| SignError::Canonicalize(e.to_string()))?;
    let sig = issuer.sign(&pay_bytes)?;
    Ok(CozJson { pay, sig })
}

/// Check that `challenge` is one `issuer` signed for `audience`, still
/// within [`CHALLENGE_TTL_SECS`] of `now`, and return its nonce and the
/// time it stops verifying.
///
/// # Errors
///
/// [`VerifyError::ChallengeInvalid`] for anything else.
pub fn verify_challenge(
    issuer: &dyn Issuer,
    audience: &str,
    challenge: &CozJson,
    now: i64,
) -> Result<(String, i64), VerifyError> {
    let pay = &challenge.pay;
    let typ_ok = pay.get("typ").and_then(Value::as_str)
        == Some(format!("{audience}{CHALLENGE_TYP_SUFFIX}").as_str());
    let issued = pay.get("now").and_then(Value::as_i64);
    let pay_bytes = serde_json::to_vec(pay).map_err(|_| VerifyError::ChallengeInvalid)?;
    let signed =
        coz::verify_json(&pay_bytes, &challenge.sig, issuer.alg(), issuer.pub_key()) == Some(true);
    let (Some(issued), true, true) = (issued, typ_ok, signed) else {
        return Err(VerifyError::ChallengeInvalid);
    };
    let nonce = challenge_nonce(challenge).map_err(|_| VerifyError::ChallengeInvalid)?;
    let expires = issued.saturating_add(CHALLENGE_TTL_SECS);
    // A challenge from the future would outlive its TTL, so it is refused.
    if issued > now || expires <= now {
        return Err(VerifyError::ChallengeInvalid);
    }
    Ok((nonce, expires))
}

/// Redeem the challenge a request returns: it must verify as the issuer's
/// ([`verify_challenge`]), carry the nonce the request signed, and not have
/// been redeemed before.
///
/// # Verification order
///
/// The one order every party follows: verify the request's signature
/// ([`ParsedRequest::verify`]) first, then redeem. Redeeming spends the
/// challenge, so a login with a junk signature must never reach it; taking a
/// [`VerifiedRequest`] makes the order the only one that compiles. Whatever
/// else a party checks (key activity, lifecycle, channel) it checks before
/// calling this, so the spend is the last step that can refuse.
///
/// # Errors
///
/// [`VerifyError::ChallengeInvalid`] when any of those fails.
pub fn redeem_challenge(
    issuer: &dyn Issuer,
    request: &VerifiedRequest,
    spent: &mut SpentChallenges,
    now: i64,
) -> Result<(), VerifyError> {
    let challenge = request
        .challenge
        .as_ref()
        .ok_or(VerifyError::ChallengeInvalid)?;
    let (nonce, expires) = verify_challenge(issuer, &request.audience, challenge, now)?;
    if request.nonce.as_deref() != Some(nonce.as_str()) {
        return Err(VerifyError::ChallengeInvalid);
    }
    spent.spend(&nonce, expires, now)
}

/// Nonces already redeemed, each kept until its challenge can no longer
/// verify, so a used challenge is refused for as long as it would
/// otherwise pass and the set is bounded by the issue rate over the TTL.
#[derive(Debug, Default)]
pub struct SpentChallenges {
    until: BTreeMap<String, i64>,
}

impl SpentChallenges {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` as redeemed until `expires`.
    ///
    /// # Errors
    ///
    /// [`VerifyError::ChallengeInvalid`] if it was already redeemed.
    pub fn spend(&mut self, nonce: &str, expires: i64, now: i64) -> Result<(), VerifyError> {
        self.until.retain(|_, until| *until > now);
        if self.until.contains_key(nonce) {
            return Err(VerifyError::ChallengeInvalid);
        }
        self.until.insert(nonce.to_owned(), expires);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// A `SoftwareIssuer` over a fresh key.
    fn issuer() -> SoftwareIssuer {
        let kp = coz::Alg::Ed25519.generate_keypair();
        SoftwareIssuer::new(kp.alg.name(), &kp.prv_bytes, &kp.pub_bytes)
    }

    proptest! {
        /// Backs: SPEC 17.2 timestamp window. For any pair of signed
        /// timestamps, extremes included, the window is exactly
        /// `|client - server| <= TIMESTAMP_WINDOW_SECS`, computed here in
        /// i128, so an attacker-chosen `now` can never overflow it.
        #[test]
        fn window_is_exactly_the_absolute_difference(
            client in any::<i64>(),
            server in any::<i64>(),
        ) {
            let diff = (i128::from(server) - i128::from(client)).abs();
            prop_assert_eq!(
                within_window(client, server),
                diff <= i128::from(TIMESTAMP_WINDOW_SECS)
            );
        }

        /// Backs: SPEC 17.2 challenge freshness. A challenge verifies
        /// exactly while `issued <= now < issued + TTL`: not before it was
        /// issued, not at or after its expiry.
        #[test]
        fn a_challenge_verifies_exactly_within_its_ttl(
            issued in 0i64..1_000_000,
            now in -1_000i64..1_002_000,
        ) {
            let issuer = issuer();
            let challenge = issue_challenge(&issuer, "svc.example", issued).expect("issues");
            let verdict = verify_challenge(&issuer, "svc.example", &challenge, now);
            prop_assert_eq!(
                verdict.is_ok(),
                issued <= now && now < issued + CHALLENGE_TTL_SECS
            );
        }
    }
}
