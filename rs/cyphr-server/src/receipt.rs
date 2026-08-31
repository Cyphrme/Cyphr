//! Signed server receipts: commit-acceptance and tip attestations
//! (`docs/specs/receipts.md`).
//!
//! A receipt is a Coz message the server signs with its own
//! [`ServerIdentity`], exactly the compose-and-sign pattern
//! [`ServerIdentity::issue_token`](super::auth::token) uses for bearer
//! tokens: `coz::Pay::new()`, a dedicated `typ` constant, extra claims,
//! serde to bytes, `identity.sign`, `coz::CozJson{pay, sig}`. Each kind
//! gets its own `typ` so no signature can be replayed across purposes,
//! the same replay-across-purposes closure bearer tokens already apply.
//!
//! Issuance is stateless (decision D2, `docs/specs/receipts.md`): nothing
//! here persists a receipt or a received-at time. The recipient holds the
//! trust object; the server signs and forgets.

use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use serde_json::Value;

use crate::auth::ServerIdentity;

/// The `typ` a signed commit-acceptance receipt (the `/push` statement
/// slot) is stamped with.
pub const COMMIT_RECEIPT_TYP: &str = "cyphr-server/receipt/commit";

/// The `typ` a signed tip report (the `/tip` statement slot) is stamped
/// with.
pub const TIP_REPORT_TYP: &str = "cyphr-server/receipt/tip";

/// The post-commit roots a receipt attests, exactly as the tip payload
/// carries them (`docs/specs/http-envelope.md` `[envelope-r-cr]`).
///
/// Nested under the `roots` claim so its `pr` (the post-commit Principal
/// Root) never collides with the receipt's top-level `pr` claim (the
/// attested principal's genesis identifier) -- the two are different
/// facts that happen to share a SPEC field name.
///
/// `cr` alone is `Option<String>` (#147): a principal that is
/// key-established but has not yet finalized a data commit has no commit
/// root, and that absence is typed here rather than signaled by handing
/// `sign_receipt` the empty-string sentinel storage used to hand it --
/// `None` serializes to JSON `null` on the wire ([`Roots::to_value`]),
/// never `""`. `pr`/`sr`/`ar` are always present once a principal exists,
/// so they stay mandatory `String`s.
#[derive(Debug, Clone)]
pub struct Roots {
    pub pr: String,
    pub sr: String,
    pub ar: String,
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
/// tip payload carries them. Returns `None` if coz rejects the payload or
/// this identity's key (mirrors [`ServerIdentity::sign`]).
pub fn commit_receipt(
    identity: &ServerIdentity,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
) -> Option<coz::CozJson> {
    sign_receipt(
        identity,
        now,
        COMMIT_RECEIPT_TYP,
        pr,
        sequence,
        commit_id,
        roots,
        None,
    )
}

/// Compose and sign a tip report for `/tip`'s statement slot.
///
/// As [`commit_receipt`], plus the tip payload's `commit_count` and
/// `last_updated`, since a tip report attests the whole principal's
/// current state, not just the one commit that produced it.
#[allow(clippy::too_many_arguments)]
pub fn tip_report(
    identity: &ServerIdentity,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
    commit_count: u64,
    last_updated: i64,
) -> Option<coz::CozJson> {
    sign_receipt(
        identity,
        now,
        TIP_REPORT_TYP,
        pr,
        sequence,
        commit_id,
        roots,
        Some((commit_count, last_updated)),
    )
}

/// Shared composition core for both receipt kinds: everything but `typ`
/// and the tip-only extra claims is identical, so the two public
/// constructors differ only in what they pass here.
#[allow(clippy::too_many_arguments)]
fn sign_receipt(
    identity: &ServerIdentity,
    now: i64,
    typ: &str,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
    tip_extra: Option<(u64, i64)>,
) -> Option<coz::CozJson> {
    let pr = pr.into();
    let commit_id = commit_id.into();

    // Refuse to sign a malformed value into a receipt: validate every
    // identifier/digest-bearing field at construction, not just at the
    // wire boundary. Parsing (and discarding) each one before composing
    // the payload means a value that isn't valid never reaches the
    // signature -- `?` on `.ok()` returns `None` on the first failure,
    // matching this function's existing "compose failed" contract.
    //
    // `pr` is the attested principal's GENESIS IDENTIFIER, not a tagged
    // digest: SPEC §2.2.3's DEFAULT identifier form is bare canonical
    // b64ut -- tagging is the labeled exemption `commit_id`/`roots` use,
    // not this field. At Level 1/2 a principal's genesis identifier IS
    // its raw thumbprint via implicit promotion, so requiring a tag here
    // would reject every Level 1/2 principal's receipt.
    let _: coz::Thumbprint = parse_genesis_id_str(&pr).ok()?;
    commit_id.parse::<TaggedDigest>().ok()?;
    roots.pr.parse::<TaggedDigest>().ok()?;
    roots.sr.parse::<TaggedDigest>().ok()?;
    roots.ar.parse::<TaggedDigest>().ok()?;
    // `cr` alone may legitimately be absent (#147): a principal that is
    // key-established but has not finalized a data commit has no commit
    // root yet. `None` needs no validation; `Some` still must parse as a
    // `TaggedDigest`, exactly as `pr`/`sr`/`ar` above.
    if let Some(cr) = &roots.cr {
        cr.parse::<TaggedDigest>().ok()?;
    }

    let tmb = identity.alg().compute_thumbprint(identity.pub_key())?;

    let mut pay = coz::Pay::new();
    pay.alg = Some(identity.alg().name().to_string());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(typ.to_string());
    pay.extra.insert("pr".to_string(), Value::String(pr));
    pay.extra
        .insert("sequence".to_string(), Value::from(sequence));
    pay.extra
        .insert("commit_id".to_string(), Value::String(commit_id));
    pay.extra.insert("roots".to_string(), roots.to_value());
    if let Some((commit_count, last_updated)) = tip_extra {
        pay.extra
            .insert("commit_count".to_string(), Value::from(commit_count));
        pay.extra
            .insert("last_updated".to_string(), Value::from(last_updated));
    }

    let pay_json = serde_json::to_vec(&pay).ok()?;
    let (sig, _cad) = identity.sign(&pay_json)?;
    let pay_value = serde_json::to_value(&pay).ok()?;

    Some(coz::CozJson {
        pay: pay_value,
        sig,
    })
}

/// The post-commit roots a tip report attests, parsed into the typed
/// domain: the same four fields [`Roots`] carries on the wire, but each
/// one validated into a [`TaggedDigest`] rather than trusted as a bare
/// `String`.
///
/// `cr` alone is `Option`: a principal that is key-established but has not
/// yet finalized a data commit has no commit root, and a signed receipt
/// carries that absence as wire `null` (#147) -- typed here as `None`
/// rather than rejected as malformed. `pr`/`sr`/`ar` are always present
/// once a principal exists, so they stay mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipReportRoots {
    pub pr: TaggedDigest,
    pub sr: TaggedDigest,
    pub ar: TaggedDigest,
    pub cr: Option<TaggedDigest>,
}

/// A signed tip report's claims, canonically parsed: the typed
/// counterpart to the raw `pr`/`sequence`/`commit_id`/`roots` JSON
/// [`check_equivocation`] used to compare directly, as raw `Value`s. This
/// is the ONLY path a report's claims take into that comparison --
/// non-canonical input is rejected here (the boundary-side property),
/// never downstream, and everything that parses is compared by this typed
/// value alone (the passing-through property).
///
/// `pr` is `coz::Thumbprint`, not `TaggedDigest`: it is the attested
/// principal's GENESIS IDENTIFIER, SPEC §2.2.3's DEFAULT (untagged)
/// identifier form -- at Level 1/2 that identifier IS the principal's raw
/// key thumbprint via implicit promotion
/// (`docs/specs/principal-lifecycle.md`), so `coz::Thumbprint` is the
/// existing type reused here rather than a hand-rolled wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipReport {
    pub pr: coz::Thumbprint,
    pub sequence: u64,
    pub commit_id: TaggedDigest,
    pub roots: TipReportRoots,
}

/// Why a signed report's `pay` failed to canonicalize into a [`TipReport`].
///
/// Every variant is a REJECT-LOUD outcome: a validly-signed report that
/// produces one of these must never be silently compared or dropped by
/// its caller -- see `EquivocationVerdict::Malformed` at the one
/// comparison this type feeds today.
#[derive(Debug, thiserror::Error)]
pub enum TipReportParseError {
    /// `pr` is not a JSON string, or the string does not decode as a bare
    /// canonical b64ut genesis identifier: an array, a number, or `null`
    /// is not an identifier encoding at all -- never unwrapped to recover
    /// one; a tagged `ALG:...` string also fails, since tagging is
    /// `commit_id`/`roots`'s labeled exemption, not `pr`'s.
    #[error("pr: {0}")]
    Pr(cyphr::error::Error),
    /// `commit_id` -- same disposition as `pr`.
    #[error("commit_id: {0}")]
    CommitId(cyphr::error::Error),
    /// `sequence` is neither a JSON number nor the JSON string of a `u64`'s
    /// decimal digits (the one field that CANONICALIZES across those two
    /// representations; anything else -- `"5x"`, `"5.0"`, `""`, a bool, an
    /// array -- is malformed, never coerced).
    #[error("sequence is not a canonical non-negative integer: {0}")]
    Sequence(Value),
    /// `roots.<field>` -- same disposition as `pr`/`commit_id`.
    #[error("roots.{field}: {source}")]
    Roots {
        field: &'static str,
        source: cyphr::error::Error,
    },
}

impl TipReport {
    /// Parse a signed report's `pay` into the typed domain -- the
    /// canonical parse, and the single boundary through which a report's
    /// claims enter typed comparison.
    pub fn parse(coz: &coz::CozJson) -> Result<Self, TipReportParseError> {
        let pr = parse_genesis_id(&coz.pay["pr"]).map_err(TipReportParseError::Pr)?;
        let commit_id =
            parse_digest_field(&coz.pay["commit_id"]).map_err(TipReportParseError::CommitId)?;
        let sequence = parse_sequence(&coz.pay["sequence"])?;
        let roots = TipReportRoots {
            pr: parse_digest_field(&coz.pay["roots"]["pr"]).map_err(|source| {
                TipReportParseError::Roots {
                    field: "pr",
                    source,
                }
            })?,
            sr: parse_digest_field(&coz.pay["roots"]["sr"]).map_err(|source| {
                TipReportParseError::Roots {
                    field: "sr",
                    source,
                }
            })?,
            ar: parse_digest_field(&coz.pay["roots"]["ar"]).map_err(|source| {
                TipReportParseError::Roots {
                    field: "ar",
                    source,
                }
            })?,
            cr: parse_optional_digest_field(&coz.pay["roots"]["cr"]).map_err(|source| {
                TipReportParseError::Roots {
                    field: "cr",
                    source,
                }
            })?,
        };
        Ok(Self {
            pr,
            sequence,
            commit_id,
            roots,
        })
    }
}

/// Parse a JSON value as a digest field: it MUST be a JSON string -- an
/// array, a number, or `null` is not a digest encoding at all, and is
/// never unwrapped down to an inner string -- and that string must parse
/// as a [`TaggedDigest`]. Used for `commit_id` and each `roots.<field>` --
/// NOT `pr`, see [`parse_genesis_id`].
fn parse_digest_field(value: &Value) -> Result<TaggedDigest, cyphr::error::Error> {
    value
        .as_str()
        .ok_or(cyphr::error::Error::MalformedDigest(
            "not a JSON string -- digests are never arrays, numbers, or null",
        ))
        .and_then(|s| s.parse())
}

/// Parse a `roots.cr`-shaped JSON value: unlike every other digest field,
/// JSON `null` is not rejected here -- it is the wire encoding for "no
/// commit root yet" (#147: a principal that is key-established but has
/// not finalized a data commit) -- and parses to `None`. Any other value
/// must still be a JSON string that parses as a [`TaggedDigest`], exactly
/// as [`parse_digest_field`]; the empty string this function used to
/// special-case is no longer accepted -- #147 retires that sentinel in
/// favor of the type, so `""` is now malformed like any other non-digest
/// string.
fn parse_optional_digest_field(value: &Value) -> Result<Option<TaggedDigest>, cyphr::error::Error> {
    if value.is_null() {
        return Ok(None);
    }
    parse_digest_field(value).map(Some)
}

/// Parse a JSON value as a genesis identifier -- `pr`'s disposition: the
/// same reject-loud shape discipline as [`parse_digest_field`] (a JSON
/// string only; an array, a number, or `null` is never an identifier
/// encoding), but the string itself decodes as BARE canonical b64ut, not
/// `ALG:b64ut` -- SPEC §2.2.3's DEFAULT identifier form. See
/// [`parse_genesis_id_str`] for the decode itself.
fn parse_genesis_id(value: &Value) -> Result<coz::Thumbprint, cyphr::error::Error> {
    value
        .as_str()
        .ok_or(cyphr::error::Error::MalformedDigest(
            "not a JSON string -- a genesis identifier is never an array, number, or null",
        ))
        .and_then(parse_genesis_id_str)
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

/// Parse a JSON value as a `sequence`: a JSON number canonicalizes
/// directly; a JSON string canonicalizes if and only if it is exactly the
/// decimal digits of a `u64`. Any other JSON shape, or a string that
/// isn't a clean integer, is malformed.
fn parse_sequence(value: &Value) -> Result<u64, TipReportParseError> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| TipReportParseError::Sequence(value.clone())),
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|_| TipReportParseError::Sequence(value.clone())),
        _ => Err(TipReportParseError::Sequence(value.clone())),
    }
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
    /// One or both reports fail to canonicalize via [`TipReport::parse`] --
    /// a validly-signed report whose claims cannot be typed.
    ///
    /// This variant is DISTINCT from every other one in this enum -- but
    /// distinctness in the type is not the same as distinctness in
    /// practice: NO current consumer treats it differently from an honest
    /// non-conflict. `consistency.rs`'s three call sites each compare
    /// `verdict == Proven`, so `Malformed` folds in with `WrongTyp`,
    /// `InvalidSignature`, `DifferentPrincipal`, `DifferentSequence`, and
    /// `IdenticalClaims` alike -- an attacker who makes one report fail to
    /// parse gets the same "no equivocation" outcome as an honest
    /// non-conflicting pair, today. Closing that gap needs two things
    /// neither of which lives in this function: a consumer that reads
    /// `Malformed` as distinct from a genuine non-conflict, and an
    /// ingestion gate that refuses a report failing `TipReport::parse`
    /// before it is ever retained as a claim (so a malformed report cannot
    /// relocate the evasion instead of being closed by it). Until both
    /// land, this variant exists but is not yet load-bearing anywhere.
    Malformed,
}

/// Check whether two signed tip reports constitute proven equivocation.
///
/// Pure: a function over the two raw coz values plus caller-supplied key
/// material only -- no engine, no `AppState`, no I/O, no clock, so a
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
/// other outcome, though no current caller reads it that way (see
/// `Malformed`'s doc: `consistency.rs` folds it in with every other
/// non-conflict); (4) both claim the same typed `pr` and the same typed
/// `sequence`; (5) they differ in typed `commit_id` or in any typed
/// `roots` field -- compared by canonical value, so representation never
/// causes a miss or a false alarm. Anything else is a diagnosed
/// non-equivocation.
pub fn check_equivocation(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
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

    EquivocationVerdict::Proven
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
