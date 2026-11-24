//! Signed server receipts: commit-acceptance and tip attestations
//! (`docs/specs/receipts.md`).
//!
//! A receipt is a Coz message the server signs through a
//! [`ReceiptSigner`] -- the one attest path for every server signature
//! (commit receipts and tip reports). The signer is a seam:
//! it wraps the server's [`ServerIdentity`] today and any non-exportable
//! key later, without this module learning key bytes. Each kind gets its
//! own `typ` so no signature can be replayed across purposes, the same
//! replay-across-purposes closure bearer tokens
//! ([`ServerIdentity::issue_login_token`](super::auth::token)) apply.
//!
//! Issuance is stateless (decision D2, `docs/specs/receipts.md`): nothing
//! here persists a receipt or a received-at time. The recipient holds the
//! trust object; the server signs and forgets.

use std::future::Future;
use std::pin::Pin;

use cyphr::HashAlg;
use cyphr::fork::Contest;
use cyphr::signer::{SignerError, SoftwareSigner};
use cyphr::state::TaggedDigest;
// The canonical report parse lives in the client crate; `check_equivocation`
// consumes it, and this re-export keeps `receipt::TipReport` one type, not two.
pub use cyphr_client::{COMMIT_RECEIPT_TYP, HELD_REPORT_TYP, TIP_REPORT_TYP, TipReport};
use serde_json::Value;

use crate::auth::ServerIdentity;

/// A signing backend for server statements: the server-side counterpart of
/// [`cyphr::signer::Signer`], object-safe and `Send` so it can sit behind
/// an `Arc<dyn ReceiptSigner>` in shared state (the core trait's future is
/// deliberately not `Send`, for WebCrypto, so it cannot be used as-is).
///
/// The signer owns signature canonicality, as in the core contract: the
/// receipt constructor verifies what it returns and refuses a signature
/// that does not verify.
pub trait ReceiptSigner: Send + Sync {
    /// Coz algorithm name of the key.
    fn alg(&self) -> &str;

    /// Public key bytes, in the form `coz::verify_json` accepts.
    fn pub_key(&self) -> &[u8];

    /// Sign the Coz `cad`, returning the signature or why the backend
    /// could not.
    fn sign<'a>(
        &'a self,
        cad: &'a coz::Cad,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SignerError>> + Send + 'a>>;
}

impl ReceiptSigner for ServerIdentity {
    fn alg(&self) -> &str {
        ServerIdentity::alg(self).name()
    }

    fn pub_key(&self) -> &[u8] {
        ServerIdentity::pub_key(self)
    }

    fn sign<'a>(
        &'a self,
        cad: &'a coz::Cad,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SignerError>> + Send + 'a>> {
        Box::pin(async move {
            let tmb = ServerIdentity::alg(self)
                .compute_thumbprint(ServerIdentity::pub_key(self))
                .ok_or_else(|| SignerError::Backend("identity thumbprint unavailable".into()))?;
            let software = SoftwareSigner::new(
                ServerIdentity::alg(self).name(),
                self.prv_key(),
                ServerIdentity::pub_key(self),
                &tmb,
            );
            // An in-memory key never suspends, so the synchronous path is
            // exact and spares a non-`Send` future crossing this boundary.
            software.sign_now(cad)
        })
    }
}

/// Why a statement was not signed. Server-side only: an unsigned answer
/// carries no reason on the wire, because an unauthenticated statement is
/// not something a client can act on; the reason goes to the log.
#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    /// A field to be attested is not a canonical identifier or digest.
    #[error("{field}: {source}")]
    Field {
        field: &'static str,
        source: cyphr::error::Error,
    },
    /// The signer's algorithm or key does not yield a thumbprint.
    #[error("signer key is unusable: {0}")]
    Key(&'static str),
    /// The payload did not serialize or canonicalize.
    #[error("statement payload could not be composed: {0}")]
    Compose(String),
    /// The signing backend failed, or returned a signature that does not
    /// verify.
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
}

/// The post-commit roots a receipt attests, exactly as the tip payload
/// carries them (`docs/specs/http-envelope.md` `[envelope-r-cr]`).
///
/// Nested under the `roots` claim so its `pr` (the post-commit Principal
/// Root) never collides with the receipt's top-level `pr` claim (the
/// attested principal's genesis identifier) -- the two are different
/// facts that happen to share a SPEC field name.
///
/// `sr`, `ar` and `cr` are `Option<String>`. A principal that is
/// key-established but has not yet finalized a data commit has no commit
/// root (#147); a Dead principal (SPEC 11) has no AR, and no SR unless it
/// holds data (SPEC 3.7). The absence is typed here rather than signaled by
/// an empty-string sentinel: `None` serializes to JSON `null` on the wire
/// ([`Roots::to_value`]), never `""`. `pr` is always present once a
/// principal exists, so it stays a mandatory `String`.
#[derive(Debug, Clone)]
pub struct Roots {
    pub pr: String,
    pub sr: Option<String>,
    pub ar: Option<String>,
    pub cr: Option<String>,
}

impl Roots {
    fn to_value(&self) -> Value {
        serde_json::json!({
            "pr": self.pr,
            "sr": self.sr,
            "ar": self.ar,
            "cr": self.cr,
        })
    }
}

/// Compose and sign a commit-acceptance receipt for `/push`'s statement
/// slot.
///
/// `pr` is the attested principal's genesis identifier; `sequence` is the
/// accepted commit's 0-indexed position (the post-state tip's
/// `commit_count - 1`); `roots` is the post-state roots exactly as the
/// tip payload carries them.
///
/// # Errors
///
/// [`ReceiptError`]: a malformed field, an unusable key, or a signer
/// failure.
pub async fn commit_receipt(
    signer: &dyn ReceiptSigner,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
) -> Result<coz::CozJson, ReceiptError> {
    let (pr, commit_id) = (pr.into(), commit_id.into());
    validate(&pr, &commit_id, roots)?;
    sign_statement(
        signer,
        now,
        COMMIT_RECEIPT_TYP,
        [
            ("pr", Value::String(pr)),
            ("sequence", Value::from(sequence)),
            ("commit_id", Value::String(commit_id)),
            ("roots", roots.to_value()),
        ],
    )
    .await
}

/// Compose and sign a tip report for `/tip`'s statement slot.
///
/// As [`commit_receipt`], plus the tip payload's `commit_count` and
/// `last_updated`, since a tip report attests the whole principal's
/// current state, not just the one commit that produced it.
///
/// # Errors
///
/// As [`commit_receipt`].
#[allow(clippy::too_many_arguments)]
pub async fn tip_report(
    signer: &dyn ReceiptSigner,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
    commit_count: u64,
    last_updated: i64,
) -> Result<coz::CozJson, ReceiptError> {
    let (pr, commit_id) = (pr.into(), commit_id.into());
    validate(&pr, &commit_id, roots)?;
    sign_statement(
        signer,
        now,
        TIP_REPORT_TYP,
        [
            ("pr", Value::String(pr)),
            ("sequence", Value::from(sequence)),
            ("commit_id", Value::String(commit_id)),
            ("roots", roots.to_value()),
            ("commit_count", Value::from(commit_count)),
            ("last_updated", Value::from(last_updated)),
        ],
    )
    .await
}

/// One head a held statement names, as the engine reports it.
#[derive(Debug, Clone)]
pub struct HeldClaim {
    pub commit_id: String,
    pub sequence: u64,
    pub held_since: Option<i64>,
}

/// Compose and sign the statement `/tip` carries while the principal is in
/// Error (SPEC 15.5): the fork point and each head with the time this
/// server first stored it (SPEC 13.6 "first_seen"). It claims nothing
/// canonical: no `roots`, no `commit_id`, no `sequence`, because in Error
/// no commit is the principal's tip.
///
/// # Errors
///
/// As [`commit_receipt`].
pub async fn held_report(
    signer: &dyn ReceiptSigner,
    now: i64,
    pr: impl Into<String>,
    fork_height: u64,
    fork_pre: Option<&str>,
    heads: &[HeldClaim],
) -> Result<coz::CozJson, ReceiptError> {
    let pr = pr.into();
    parse_genesis_id_str(&pr)
        .map(drop)
        .map_err(|source| ReceiptError::Field {
            field: "pr",
            source,
        })?;
    let digest = |field: &'static str, s: &str| {
        s.parse::<TaggedDigest>()
            .map(drop)
            .map_err(|source| ReceiptError::Field { field, source })
    };
    if let Some(pre) = fork_pre {
        digest("fork_point.pre", pre)?;
    }
    for head in heads {
        digest("heads.commit_id", &head.commit_id)?;
    }
    sign_statement(
        signer,
        now,
        HELD_REPORT_TYP,
        [
            ("pr", Value::String(pr)),
            (
                "fork_point",
                serde_json::json!({"height": fork_height, "pre": fork_pre}),
            ),
            (
                "heads",
                Value::Array(
                    heads
                        .iter()
                        .map(|h| {
                            serde_json::json!({
                                "commit_id": h.commit_id,
                                "sequence": h.sequence,
                                "held_since": h.held_since,
                            })
                        })
                        .collect(),
                ),
            ),
        ],
    )
    .await
}

/// Refuse to sign a malformed value: every identifier/digest-bearing field
/// is parsed (and discarded) at construction, not just at the wire
/// boundary, so a value that is not valid never reaches a signature.
///
/// `pr` is the attested principal's GENESIS IDENTIFIER, not a tagged
/// digest: SPEC §2.2.3's DEFAULT identifier form is bare canonical b64ut --
/// tagging is the labeled exemption `commit_id`/`roots` use, not this
/// field. At Level 1/2 a principal's genesis identifier IS its raw
/// thumbprint via implicit promotion, so requiring a tag here would reject
/// every Level 1/2 principal's receipt.
fn validate(pr: &str, commit_id: &str, roots: &Roots) -> Result<(), ReceiptError> {
    fn digest(field: &'static str, s: &str) -> Result<(), ReceiptError> {
        s.parse::<TaggedDigest>()
            .map(drop)
            .map_err(|source| ReceiptError::Field { field, source })
    }
    parse_genesis_id_str(pr)
        .map(drop)
        .map_err(|source| ReceiptError::Field {
            field: "pr",
            source,
        })?;
    digest("commit_id", commit_id)?;
    digest("roots.pr", &roots.pr)?;
    // `sr`, `ar` and `cr` may legitimately be absent (a Dead principal has
    // no AR; a principal that has not finalized a commit has no CR, #147).
    // A present value still must parse as a `TaggedDigest`.
    for (field, root) in [
        ("roots.sr", &roots.sr),
        ("roots.ar", &roots.ar),
        ("roots.cr", &roots.cr),
    ] {
        if let Some(root) = root {
            digest(field, root)?;
        }
    }
    Ok(())
}

/// The one signing path: stamp `alg`/`now`/`tmb`/`typ`, add the kind's
/// claims, sign the payload's `cad` through `signer`, and refuse a
/// signature that does not verify under the signer's own key.
async fn sign_statement<const N: usize>(
    signer: &dyn ReceiptSigner,
    now: i64,
    typ: &str,
    claims: [(&str, Value); N],
) -> Result<coz::CozJson, ReceiptError> {
    let (alg, pub_key) = (signer.alg(), signer.pub_key());
    let tmb = coz::compute_thumbprint_for_alg(alg, pub_key).ok_or(ReceiptError::Key(
        "no thumbprint for this algorithm and key",
    ))?;

    let mut pay = coz::Pay::new();
    pay.alg = Some(alg.to_string());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(typ.to_string());
    for (name, value) in claims {
        pay.extra.insert(name.to_string(), value);
    }

    let pay_json = serde_json::to_vec(&pay).map_err(|e| ReceiptError::Compose(e.to_string()))?;
    let cad = coz::canonical_hash_for_alg(&pay_json, alg, None)
        .ok_or(ReceiptError::Key("algorithm cannot hash a payload"))?;
    let sig = signer.sign(&cad).await?;
    if coz::verify_json(&pay_json, &sig, alg, pub_key) != Some(true) {
        return Err(SignerError::Backend(
            "signature does not verify under the signer's key".into(),
        )
        .into());
    }
    let pay = serde_json::to_value(&pay).map_err(|e| ReceiptError::Compose(e.to_string()))?;
    Ok(coz::CozJson { pay, sig })
}

/// Decode a bare b64ut genesis-identifier string into `coz::Thumbprint`.
///
/// Uses the SAME strict canonical decoder `TaggedDigest::from_str` uses
/// (`Base64UrlUnpadded::decode_vec`, which rejects padding, the standard
/// alphabet, whitespace/case variants, and any non-canonical encoding of
/// the same bytes) -- this is load-bearing: a looser check would let two
/// spellings of one identifier compare unequal, reopening the
/// equivocation door this canonical decode exists to close. A tagged
/// `ALG:...` string also fails here, since `:` is outside the b64url
/// alphabet -- tagging is `commit_id`/`roots`'s exemption, not `pr`'s.
///
/// `pub(crate)`: also `routes::push`'s pre-commit canonicality check
/// (#168) -- refusing a non-canonical `principal_id` before
/// `submit_commit` runs, rather than discovering the same refusal only
/// after the write already landed, when this function later refuses to
/// sign the receipt.
///
/// Length is checked against the codebase's supported digest lengths
/// (32/48/64 -- SHA-256/384/512 via [`TaggedDigest::expected_len`]), NOT
/// against the receipt's own `alg`: a receipt's `alg` is the WITNESS
/// SERVER's signing algorithm, independent of the attested principal's
/// genesis-key algorithm, so binding `pr`'s length to it would reject
/// every principal whose algorithm differs from the witness's.
pub(crate) fn parse_genesis_id_str(s: &str) -> Result<coz::Thumbprint, cyphr::error::Error> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let bytes = Base64UrlUnpadded::decode_vec(s)
        .map_err(|_| cyphr::error::Error::MalformedDigest("invalid base64"))?;
    let supported_len = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
        .iter()
        .any(|&alg| bytes.len() == TaggedDigest::expected_len(alg));
    if !supported_len {
        return Err(cyphr::error::Error::MalformedDigest(
            "not a supported digest length (32/48/64 bytes)",
        ));
    }
    Ok(coz::Thumbprint::from_bytes(bytes))
}

/// The outcome of checking two signed tip reports for equivocation
/// (`docs/specs/receipts.md`'s equivocation section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationVerdict {
    /// Both reports carry a valid signature under their own
    /// caller-supplied key, share `pr` and `sequence`, and differ in
    /// `commit_id` or `roots` -- proven equivocation.
    Proven,
    /// One or both cozies are not stamped `typ == TIP_REPORT_TYP`.
    WrongTyp,
    /// One or both signatures fail to verify under the caller-supplied
    /// key.
    InvalidSignature,
    /// The two reports attest different principals (`pr`).
    DifferentPrincipal,
    /// The two reports attest different sequence positions.
    DifferentSequence,
    /// The two reports are claim-identical -- not a conflict.
    IdenticalClaims,
    /// The pair differs at one position and one of its commits was
    /// abandoned: the earlier report names a commit on a branch the fork
    /// rule over what the witness holds has since passed over, because a
    /// valid resolution (a `resync/create` proof, or a commit extending the
    /// other branch) settled the fork (SPEC 15.8: "the abandoned branch's
    /// transactions become permanently invalid"). A server that follows the
    /// fork rule signs both reports, so this is not equivocation.
    Resolved,
    /// One or both reports fail to canonicalize via [`TipReport::parse`] --
    /// a validly-signed report whose claims cannot be typed.
    ///
    /// This variant is DISTINCT from every other one in this enum, but no
    /// production code calls [`check_equivocation`] today, so nothing
    /// reads it as distinct from an honest non-conflict. A future
    /// consumer must read `Malformed` separately from a genuine
    /// non-conflict, and ingestion must refuse a report failing
    /// `TipReport::parse` before it is retained as a claim; otherwise an
    /// attacker who makes one report fail to parse gets the same "no
    /// equivocation" outcome as an honest pair.
    Malformed,
}

/// Check whether two signed tip reports constitute proven equivocation.
///
/// Pure: a function over the two raw coz values plus caller-supplied key
/// material and the forks a witness holds (`forks`, plain core values) --
/// no engine, no `AppState`, no I/O, no clock, so a
/// verifier anywhere can run it on retained bytes. `a_pub_key` verifies
/// `a`'s signature and `b_pub_key` verifies `b`'s -- they may be
/// identical (the degenerate same-key case) or different (a
/// cross-key-rotation pair), since the server's identity is its chain,
/// not any single key.
///
/// The caller MUST have already established that both keys are active
/// keys of the SAME server principal's chain at each receipt's `now`
/// (`docs/specs/receipts.md`'s offline verification procedure) -- this
/// helper never resolves or chain-checks keys itself, which is what
/// keeps it pure while still covering the cross-rotation case.
///
/// The pinned predicate, checked in order: (1) both pays carry `typ ==
/// TIP_REPORT_TYP`; (2) each signature verifies under its own
/// caller-supplied key; (3) both reports canonicalize into a [`TipReport`]
/// -- a report that does not is diagnosed [`EquivocationVerdict::Malformed`],
/// a verdict this function's own return type keeps distinct from every
/// other outcome (no production code calls this function today); (4) both
/// claim the same typed `pr` and the same typed `sequence`; (5) they differ
/// in typed `commit_id` or in any typed `roots` field -- compared by
/// canonical value, so representation never causes a miss or a false alarm;
/// (6) the report signed first does not name a commit the fork rule has
/// passed over (`forks`, the [`Contest`]s of the fork rule over the commits
/// and resync proofs a witness holds for the principal): a fork a valid
/// resolution settled is no longer a fork, and a server that followed the
/// rule signed both ([`EquivocationVerdict::Resolved`]).
/// Anything else is a diagnosed non-equivocation.
pub fn check_equivocation(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
    forks: &[Contest],
) -> EquivocationVerdict {
    let tip_typ = Value::String(TIP_REPORT_TYP.to_string());
    if a.pay["typ"] != tip_typ || b.pay["typ"] != tip_typ {
        return EquivocationVerdict::WrongTyp;
    }

    if !receipt_signature_verifies(a, a_pub_key) || !receipt_signature_verifies(b, b_pub_key) {
        return EquivocationVerdict::InvalidSignature;
    }

    let (Ok(a_report), Ok(b_report)) = (TipReport::parse(a), TipReport::parse(b)) else {
        return EquivocationVerdict::Malformed;
    };

    if a_report.pr != b_report.pr {
        return EquivocationVerdict::DifferentPrincipal;
    }
    if a_report.sequence != b_report.sequence {
        return EquivocationVerdict::DifferentSequence;
    }
    if a_report.commit_id == b_report.commit_id && a_report.roots == b_report.roots {
        return EquivocationVerdict::IdenticalClaims;
    }

    // The pair differs. A fork resolved under the server explains it if the
    // report signed first names a commit the resolution passed over; a
    // report signed after it names the commit the fork rule follows.
    let (earlier, later) = (a.pay["now"].as_i64(), b.pay["now"].as_i64());
    let superseded = match (earlier, later) {
        (Some(x), Some(y)) if x < y => Some(&a_report),
        (Some(x), Some(y)) if y < x => Some(&b_report),
        _ => None,
    };
    if let Some(report) = superseded
        && abandoned(forks, &report.commit_id.to_string())
    {
        return EquivocationVerdict::Resolved;
    }

    EquivocationVerdict::Proven
}

/// Whether the fork rule's walk over what a witness holds passed over
/// `commit_id`: it is a commit the walk skipped at a resolved contest, or a
/// tip of a branch it skipped ([`Contest::abandoned`]). A commit between
/// the two is not listed, so a report of one is read as unexplained.
fn abandoned(forks: &[Contest], commit_id: &str) -> bool {
    forks.iter().any(|contest| {
        contest
            .abandoned
            .iter()
            .any(|(head, tips)| head == commit_id || tips.iter().any(|t| t == commit_id))
    })
}

/// Verify one receipt cozy's signature against a caller-supplied key,
/// using only the `alg` the pay itself claims -- plain `coz::verify_json`,
/// no bespoke crypto.
///
/// `pub(crate)`: also the signature-verification primitive for the witness
/// sync authenticated channel (`crate::sync`'s `/patch` envelope check,
/// K10) -- the same "verify under a caller-supplied key" shape
/// [`check_equivocation`] needs, so sync reuses it rather than re-deriving
/// `coz::verify_json` plumbing.
pub(crate) fn receipt_signature_verifies(coz: &coz::CozJson, pub_key: &[u8]) -> bool {
    let Some(alg) = coz.pay["alg"].as_str() else {
        return false;
    };
    let Ok(pay_json) = serde_json::to_vec(&coz.pay) else {
        return false;
    };
    coz::verify_json(&pay_json, &coz.sig, alg, pub_key) == Some(true)
}
