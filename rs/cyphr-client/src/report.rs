//! A signed tip report's claims, canonically parsed.

use cyphr::state::TaggedDigest;
use serde_json::Value;

/// The post-commit roots a tip report attests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipReportRoots {
    pub pr: TaggedDigest,
    pub sr: TaggedDigest,
    pub ar: TaggedDigest,
    pub cr: Option<TaggedDigest>,
}

/// A signed tip report's claims, canonically parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TipReport {
    pub pr: coz::Thumbprint,
    pub sequence: u64,
    pub commit_id: TaggedDigest,
    pub roots: TipReportRoots,
}

/// Why a signed report's `pay` failed to canonicalize.
#[derive(Debug, thiserror::Error)]
pub enum TipReportParseError {
    #[error("pr: {0}")]
    Pr(cyphr::error::Error),
    #[error("commit_id: {0}")]
    CommitId(cyphr::error::Error),
    #[error("sequence is not a canonical non-negative integer: {0}")]
    Sequence(Value),
    #[error("roots.{field}: {source}")]
    Roots {
        field: &'static str,
        source: cyphr::error::Error,
    },
}

impl TipReport {
    /// Parse a signed report's `pay`.
    pub fn parse(_coz: &coz::CozJson) -> Result<Self, TipReportParseError> {
        Err(TipReportParseError::Sequence(Value::Null))
    }
}
