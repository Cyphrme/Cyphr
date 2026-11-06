//! A signed server statement's claims, canonically parsed: the tip report
//! and the peer view statement.
//!
//! This is the canonical parse a verifier applies to a signed statement's
//! `pay` before acting on any claim in it: non-canonical input is rejected
//! here, never downstream.

use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use serde::Deserialize as _;
use serde_json::Value;

use crate::patch::Statement;

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
/// counterpart to the raw `pr`/`sequence`/`commit_id`/`roots` JSON.
/// Non-canonical input is rejected here (the boundary-side property),
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
/// Length is checked against the codebase's supported digest lengths
/// (32/48/64 -- SHA-256/384/512 via [`TaggedDigest::expected_len`]), NOT
/// against the receipt's own `alg`: a receipt's `alg` is the WITNESS
/// SERVER's signing algorithm, independent of the attested principal's
/// genesis-key algorithm, so binding `pr`'s length to it would reject
/// every principal whose algorithm differs from the witness's.
fn parse_genesis_id_str(s: &str) -> Result<coz::Thumbprint, cyphr::error::Error> {
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

/// The `typ` a signed view statement is stamped with. Its own `typ`, so no
/// receipt, tip report or bearer token can be replayed as a view (and the
/// reverse): the kind is bound into the signature.
pub const VIEW_STATEMENT_TYP: &str = "cyphr-server/view";

/// A peer's signed view statement, canonically parsed: "I hold principal
/// `pr` at this tree size and index" (GOSSIP.md section 3).
///
/// The field layout follows the C2SP checkpoint shape
/// (<https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md>): an origin
/// (`pr`), a tree size, and the root the size commits to (`commit_id` and
/// `roots`). `index` is the position of the newest commit, the leaf the
/// statement is anchored at; it is always `tree_size - 1`, and the parse
/// refuses a statement where it is not, so the two cannot be signed apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewStatement {
    pub pr: coz::Thumbprint,
    pub tree_size: u64,
    pub index: u64,
    pub commit_id: TaggedDigest,
    pub roots: TipReportRoots,
}

/// Why a view statement's `pay` failed to canonicalize.
#[derive(Debug, thiserror::Error)]
pub enum ViewStatementParseError {
    /// `pr` is not a bare canonical genesis identifier.
    #[error("pr: {0}")]
    Pr(cyphr::error::Error),
    /// `commit_id` is not a tagged digest.
    #[error("commit_id: {0}")]
    CommitId(cyphr::error::Error),
    /// `tree_size` is not a non-negative integer JSON number.
    #[error("tree_size is not a canonical non-negative integer: {0}")]
    TreeSize(Value),
    /// `index` is not a non-negative integer JSON number.
    #[error("index is not a canonical non-negative integer: {0}")]
    Index(Value),
    /// `index` is not `tree_size - 1` (an empty tree has no index).
    #[error("index {index} is not tree_size {tree_size} minus one")]
    Inconsistent { tree_size: u64, index: u64 },
    /// `roots.<field>` is not a digest.
    #[error("roots.{field}: {source}")]
    Roots {
        field: &'static str,
        source: cyphr::error::Error,
    },
}

impl ViewStatement {
    /// Parse a view statement's `pay`. Never panics on any input (fuzzed:
    /// `fuzz_view_statement`).
    pub fn parse(coz: &coz::CozJson) -> Result<Self, ViewStatementParseError> {
        let pay = &coz.pay;
        let pr = parse_genesis_id(&pay["pr"]).map_err(ViewStatementParseError::Pr)?;
        let commit_id =
            parse_digest_field(&pay["commit_id"]).map_err(ViewStatementParseError::CommitId)?;
        let tree_size = pay["tree_size"]
            .as_u64()
            .ok_or_else(|| ViewStatementParseError::TreeSize(pay["tree_size"].clone()))?;
        let index = pay["index"]
            .as_u64()
            .ok_or_else(|| ViewStatementParseError::Index(pay["index"].clone()))?;
        if tree_size.checked_sub(1) != Some(index) {
            return Err(ViewStatementParseError::Inconsistent { tree_size, index });
        }
        let digest = |field: &'static str| {
            parse_digest_field(&pay["roots"][field])
                .map_err(|source| ViewStatementParseError::Roots { field, source })
        };
        let roots = TipReportRoots {
            pr: digest("pr")?,
            sr: digest("sr")?,
            ar: digest("ar")?,
            cr: parse_optional_digest_field(&pay["roots"]["cr"]).map_err(|source| {
                ViewStatementParseError::Roots {
                    field: "cr",
                    source,
                }
            })?,
        };
        Ok(Self {
            pr,
            tree_size,
            index,
            commit_id,
            roots,
        })
    }
}

/// Why a peer's view statement was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum ViewFailure {
    /// The envelope's statement slot is unsigned or not a statement.
    #[error("the response carries no signed statement")]
    Unsigned,
    /// The signed `typ` is not [`VIEW_STATEMENT_TYP`].
    #[error("the signed statement is not a view statement")]
    WrongTyp,
    /// The statement's `tmb` is absent or not a thumbprint.
    #[error("the statement names no usable signing key")]
    NoKey,
    /// The signing key is not active in the peer chain the caller holds.
    #[error("the signing key is not active in the peer chain")]
    KeyNotActive,
    /// The signature does not verify under the chain's key.
    #[error("the statement's signature does not verify")]
    BadSignature,
    /// The signed claims do not canonicalize.
    #[error("the statement is malformed: {0}")]
    Malformed(#[from] ViewStatementParseError),
    /// The statement attests a different principal than the one asked about.
    #[error("the statement attests a different principal")]
    PrincipalMismatch,
}

/// Verify a peer's view statement against the peer principal chain the
/// caller holds, never against the server's own say-so.
///
/// `envelope` is the `GET /view` response body; `chain` is the peer's own
/// principal, replayed locally; `pr` is the principal the view is asked
/// about. The statement is accepted only if its signing key (`pay.tmb`) is
/// ACTIVE in `chain` and the signature verifies under that chain's key
/// bytes, so a statement signed by a key the chain does not hold fails even
/// when its own signature is valid. Because the whole `pay` is signed, a
/// forged tree size or index fails the signature.
///
/// # Errors
///
/// A [`ViewFailure`] naming the first check that refused.
pub fn verify_view_statement<S: cyphr::eml::Storage>(
    envelope: &Value,
    chain: &cyphr::Principal<S>,
    pr: &str,
) -> Result<ViewStatement, ViewFailure> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let statement = envelope
        .get("statement")
        .and_then(|s| Statement::deserialize(s).ok());
    let Some(Statement::Signed(coz)) = statement else {
        return Err(ViewFailure::Unsigned);
    };
    if coz.pay["typ"].as_str() != Some(VIEW_STATEMENT_TYP) {
        return Err(ViewFailure::WrongTyp);
    }
    let tmb = coz.pay["tmb"]
        .as_str()
        .and_then(|t| Base64UrlUnpadded::decode_vec(t).ok())
        .map(coz::Thumbprint::from_bytes)
        .ok_or(ViewFailure::NoKey)?;
    // Looked up among ACTIVE keys only: `get_key` also returns revoked ones,
    // and a key the chain has retired must not vouch for a current view.
    let key = chain
        .active_keys()
        .find(|k| k.tmb() == &tmb)
        .ok_or(ViewFailure::KeyNotActive)?;
    if coz.pay["alg"].as_str() != Some(key.alg())
        || !signature_verifies(&coz, key.alg(), key.pub_key())
    {
        return Err(ViewFailure::BadSignature);
    }
    let view = ViewStatement::parse(&coz)?;
    if view.pr.to_string() != pr.split_once(':').map_or(pr, |(_, digest)| digest) {
        return Err(ViewFailure::PrincipalMismatch);
    }
    Ok(view)
}

fn signature_verifies(coz: &coz::CozJson, alg: &str, pub_key: &[u8]) -> bool {
    let Ok(pay_json) = serde_json::to_vec(&coz.pay) else {
        return false;
    };
    coz::verify_json(&pay_json, &coz.sig, alg, pub_key) == Some(true)
}
