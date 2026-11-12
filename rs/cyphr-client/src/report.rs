//! A signed server statement's claims, canonically parsed: the tip report.
//!
//! This is the canonical parse a verifier applies to a signed statement's
//! `pay` before acting on any claim in it: non-canonical input is rejected
//! here, never downstream.

use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use serde_json::Value;

/// The post-commit roots a tip report attests, parsed into the typed
/// domain: the same four fields [`Roots`] carries on the wire, but each
/// one validated into a [`TaggedDigest`] rather than trusted as a bare
/// `String`.
///
/// `sr`, `ar` and `cr` are `Option`. A principal that is key-established
/// but has not yet finalized a data commit has no commit root (#147); a
/// Dead principal (SPEC 11) has no AR, and no SR unless it holds data
/// (SPEC 3.7). A signed receipt carries each absence as wire `null`, typed
/// here as `None` rather than rejected as malformed; a field missing from
/// the claim is still malformed. `pr` is always present once a principal
/// exists, so it stays mandatory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipReportRoots {
    pub pr: TaggedDigest,
    pub sr: Option<TaggedDigest>,
    pub ar: Option<TaggedDigest>,
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
            sr: parse_nullable_root(&coz.pay["roots"], "sr").map_err(|source| {
                TipReportParseError::Roots {
                    field: "sr",
                    source,
                }
            })?,
            ar: parse_nullable_root(&coz.pay["roots"], "ar").map_err(|source| {
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
/// A root that may be `null` but must be present: a field missing from the
/// `roots` claim is malformed, not an absent root (`Value` indexing would
/// otherwise read a missing key as `null`).
fn parse_nullable_root(
    roots: &Value,
    field: &str,
) -> Result<Option<TaggedDigest>, cyphr::error::Error> {
    match roots.get(field) {
        Some(value) => parse_optional_digest_field(value),
        None => parse_digest_field(&Value::Null).map(Some),
    }
}

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
