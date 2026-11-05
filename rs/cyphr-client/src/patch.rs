//! Fetching and verifying one `/patch` response.

use serde_json::Value;

use crate::connector::{BindingError, BindingPolicy, ChannelBinding, ConnectError, Connector};
use crate::report::TipReport;

/// The authority key a signed statement must verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKey {
    pub alg: String,
    pub pub_key: Vec<u8>,
}

/// One `/patch` request.
#[derive(Debug, Clone, Copy)]
pub struct PatchRequest<'a> {
    pub principal_id: &'a str,
    pub anchor: Option<&'a str>,
}

/// Why one patch entry cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryDefect {
    NoBlobsArray,
    BadBlobEncoding,
    EmptyBlobs,
}

/// One decoded patch entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    pub sequence: u64,
    pub blobs: Result<Vec<Vec<u8>>, EntryDefect>,
}

/// A patch response that passed every carrier-independent check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPatch {
    pub entries: Vec<PatchEntry>,
    pub report: Option<TipReport>,
    pub binding: Option<ChannelBinding>,
}

/// Why a patch response was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatchFailure {
    #[error(transparent)]
    Binding(#[from] BindingError),
    #[error("upstream unreachable: {0}")]
    Unreachable(String),
    #[error("upstream status {0}")]
    NonSuccess(u16),
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    #[error("statement unsigned or not signed by the expected authority")]
    EnvelopeUnsignedOrMisSigned,
    #[error("signed report does not canonicalize")]
    MalformedReport,
    #[error("signed report attests a different principal")]
    PrincipalMismatch,
}

impl From<ConnectError> for PatchFailure {
    fn from(err: ConnectError) -> Self {
        match err {
            ConnectError::Unreachable(m) => Self::Unreachable(m),
            ConnectError::NonSuccess(s) => Self::NonSuccess(s),
        }
    }
}

/// Fetch one patch over `connector` and verify it.
pub async fn fetch_patch<C: Connector>(
    _connector: &C,
    _request: &PatchRequest<'_>,
    _policy: BindingPolicy,
    _expected: Option<&AuthorityKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    Err(PatchFailure::Unreachable("not implemented".into()))
}

/// Decode and authenticate one patch response body.
pub fn verify_patch_body(
    _body: &[u8],
    _principal_id: &str,
    _expected: Option<&AuthorityKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    Err(PatchFailure::MalformedResponse("not implemented".into()))
}

/// Verify the signed statement of one patch response.
pub fn verify_authenticated_envelope(
    _body: &Value,
    _expected: &AuthorityKey,
    _principal_id: &str,
) -> Result<TipReport, PatchFailure> {
    Err(PatchFailure::MalformedReport)
}
