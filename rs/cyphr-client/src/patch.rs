//! Fetching and verifying one `/patch` response.
//!
//! Everything here is pure computation over bytes the [`Connector`]
//! returned: the same body verifies identically whatever carried it.
//!
//! When an [`AuthorityKey`] is supplied, the response's signed statement
//! must verify against it, canonicalize via [`TipReport::parse`], and
//! attest to the principal actually requested -- see
//! [`verify_authenticated_envelope`]. A genuine, validly-signed report for
//! a *different* principal (an on-path party rewrote only the outbound
//! query) is refused before any entry reaches the caller.
//!
//! Binding the report to the entries is NOT decided here. A signature over
//! `pay` says nothing about the separate plaintext `entries` array, so no
//! comparison of the wire body against itself is sound; the caller
//! compares the report against the state its own verifying store produced
//! after applying the entries.

use std::fmt::Write as _;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connector::{
    BindingError, BindingPolicy, ChannelBinding, ConnectError, Connector, Request,
};
use crate::report::TipReport;

/// The response envelope wire version this client reads
/// (`docs/specs/http-envelope.md`).
pub(crate) const ENVELOPE_VERSION: u64 = 1;

/// The authority key a signed statement must verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKey {
    /// The authority's signature algorithm (e.g. `Ed25519`).
    pub alg: String,
    /// The authority's public key bytes.
    pub pub_key: Vec<u8>,
}

/// One `/patch` request.
#[derive(Debug, Clone, Copy)]
pub struct PatchRequest<'a> {
    /// The principal to sync.
    pub principal_id: &'a str,
    /// The resync anchor: the caller's current tip PR digest, absent when
    /// it holds nothing yet and wants a full resync from genesis.
    pub anchor: Option<&'a str>,
}

impl PatchRequest<'_> {
    /// The request target (`/patch?pr=...[&from=...]`) carried to the
    /// peer. Both values are percent-encoded so a value containing
    /// `&`/`=`/`#` cannot inject extra query parameters into the outbound
    /// request; the encoding must not depend on any other guard.
    #[must_use]
    pub fn target(&self) -> String {
        let pr = percent_encode_query_value(self.principal_id);
        match self.anchor {
            Some(anchor) => format!("/patch?pr={pr}&from={}", percent_encode_query_value(anchor)),
            None => format!("/patch?pr={pr}"),
        }
    }
}

/// Why one patch entry cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryDefect {
    /// The entry carries no `txs` array, or an action bundle no `blobs`
    /// array.
    NoBlobsArray,
    /// A blob is not a base64url string, or the entry is not a bundle of
    /// the SPEC 4.6.2 shape.
    BadBlobEncoding,
    /// The entry decodes to no coz.
    EmptyBlobs,
}

/// One decoded patch entry. A defective entry is reported, not dropped, so
/// the caller can count it as rejected without it blocking later entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    /// The entry's declared sequence (`0` when absent). Advisory only.
    pub sequence: u64,
    /// The decoded bundle, or why it cannot be applied.
    pub bundle: Result<WireBundle, EntryDefect>,
}

/// One decoded action-only bundle (SPEC 4.8.1): data actions, not
/// chained, each authorized by the key active at its own `now` (SPEC 6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionBundle {
    /// The decoded action blobs, or why they cannot be applied.
    pub blobs: Result<Vec<Vec<u8>>, EntryDefect>,
}

/// One step of replaying a patch.
pub(crate) enum Step<'a> {
    /// An action-only bundle.
    Actions(&'a ActionBundle),
    /// The commit at this absolute chain position.
    Commit(usize, &'a PatchEntry),
}

/// The order to replay `entries` (the commits from position `held`) and
/// `actions` in: every commit, then every action bundle. An action holds no
/// chain position; the core judges it by the key history the commits
/// build, at the action's own `now`, so it is recorded once they are all
/// in.
pub(crate) fn replay_order<'a>(
    held: usize,
    entries: &'a [PatchEntry],
    actions: &'a [ActionBundle],
) -> Vec<Step<'a>> {
    entries
        .iter()
        .enumerate()
        .map(|(offset, entry)| Step::Commit(held + offset, entry))
        .chain(actions.iter().map(Step::Actions))
        .collect()
}

/// A patch response that passed every carrier-independent check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPatch {
    /// The entries, in wire order, still to be applied by the caller.
    pub entries: Vec<PatchEntry>,
    /// The action-only bundles, in wire order; empty from a peer that
    /// serves none.
    pub actions: Vec<ActionBundle>,
    /// The authenticated tip report; `Some` exactly when an
    /// [`AuthorityKey`] was supplied.
    pub report: Option<TipReport>,
    /// The carrier's channel binding, passed through for the caller.
    pub binding: Option<ChannelBinding>,
}

/// Why a patch response was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatchFailure {
    /// The carrier fell short of the required channel binding; nothing
    /// was sent.
    #[error(transparent)]
    Binding(#[from] BindingError),
    /// The peer could not be reached.
    #[error("upstream unreachable: {0}")]
    Unreachable(String),
    /// The peer answered with a non-success status.
    #[error("upstream answered with status {0}")]
    NonSuccess(u16),
    /// The body did not decode as the expected patch JSON shape.
    #[error("malformed response: {0}")]
    MalformedResponse(String),
    /// An authority key was supplied, but the response carried no signed
    /// statement or its signature does not verify against that key.
    #[error("statement unsigned or not signed by the expected authority")]
    EnvelopeUnsignedOrMisSigned,
    /// The statement is validly signed but does not canonicalize via
    /// [`TipReport::parse`]. A malformed report must never become a
    /// retained attestation (it would read as "no claim" in a typed
    /// comparison, opening an equivocation-evasion path).
    #[error("signed report does not canonicalize")]
    MalformedReport,
    /// The signed report attests a different principal than requested.
    #[error("signed report attests a different principal")]
    PrincipalMismatch,
    /// The response envelope states a wire version this client does not
    /// read; nothing was decoded or applied.
    #[error("response envelope version {found} is not the supported {supported}")]
    UnsupportedVersion {
        /// The version the peer stated.
        found: u64,
        /// The one version this client reads.
        supported: u64,
    },
}

impl From<ConnectError> for PatchFailure {
    fn from(err: ConnectError) -> Self {
        match err {
            ConnectError::NonSuccess(s) | ConnectError::Refused { status: s, .. } => {
                Self::NonSuccess(s)
            },
            // A cap or scheme refusal means no answer was taken from the
            // peer: reads as unreachable, with the carrier's reason kept.
            ConnectError::Unreachable(m) => Self::Unreachable(m),
            other @ (ConnectError::TooLarge { .. } | ConnectError::CleartextRefused { .. }) => {
                Self::Unreachable(other.to_string())
            },
        }
    }
}

/// Fetch one patch over `connector` and verify it.
///
/// `policy` is enforced before the request leaves the client, so a carrier
/// that cannot supply the required binding never sees the request.
///
/// # Errors
///
/// A [`PatchFailure`] for a binding shortfall, a carrier failure, or any
/// failure of [`verify_patch_body`].
pub async fn fetch_patch<C: Connector>(
    connector: &C,
    request: &PatchRequest<'_>,
    policy: BindingPolicy,
    expected: Option<&AuthorityKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    if let BindingPolicy::Required(required) = policy {
        match connector.channel_binding() {
            None => return Err(BindingError::Missing { required }.into()),
            Some(found) if found.kind() != required => {
                return Err(BindingError::WrongKind {
                    required,
                    found: found.kind(),
                }
                .into());
            },
            Some(_) => {},
        }
    }

    let body = connector.exchange(&Request::get(request.target())).await?;
    let mut verified = verify_patch_body(&body, request.principal_id, expected)?;
    verified.binding = connector.channel_binding().cloned();
    Ok(verified)
}

/// Decode and authenticate one patch response body. Pure: no I/O, and the
/// public untrusted-input entry point the fuzz target drives.
///
/// # Errors
///
/// [`PatchFailure::MalformedResponse`] when the body is not a patch;
/// otherwise the failures of [`verify_authenticated_envelope`] when
/// `expected` is supplied. The envelope is checked strictly before any
/// entry is decoded, so a refusal hands the caller nothing to apply.
pub fn verify_patch_body(
    body: &[u8],
    principal_id: &str,
    expected: Option<&AuthorityKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    let body: Value = serde_json::from_slice(body)
        .map_err(|err| PatchFailure::MalformedResponse(err.to_string()))?;

    // Version first, before any payload is interpreted: a future envelope
    // may reshape everything below.
    let found = body.get("v").and_then(Value::as_u64).ok_or_else(|| {
        PatchFailure::MalformedResponse("v missing or not an integer".to_string())
    })?;
    if found != ENVELOPE_VERSION {
        return Err(PatchFailure::UnsupportedVersion {
            found,
            supported: ENVELOPE_VERSION,
        });
    }

    let entries = body
        .get("payload")
        .and_then(|p| p.get("entries"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            PatchFailure::MalformedResponse("payload.entries missing or not an array".to_string())
        })?;

    let report = expected
        .map(|key| verify_authenticated_envelope(&body, key, principal_id))
        .transpose()?;

    Ok(VerifiedPatch {
        entries: entries.iter().map(decode_entry).collect(),
        actions: body
            .get("payload")
            .and_then(|p| p.get("actions"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|a| ActionBundle {
                blobs: decode_blobs(a),
            })
            .collect(),
        report,
        binding: None,
    })
}

fn decode_entry(entry: &Value) -> PatchEntry {
    let sequence = entry.get("sequence").and_then(Value::as_u64).unwrap_or(0);
    PatchEntry {
        sequence,
        bundle: decode_bundle(entry),
    }
}

/// An entry's bundle: `txs` (SPEC 4.6.2), `keys` and `actions`.
fn decode_bundle(entry: &Value) -> Result<WireBundle, EntryDefect> {
    if !entry.get("txs").is_some_and(Value::is_array) {
        return Err(EntryDefect::NoBlobsArray);
    }
    let bundle = WireBundle::deserialize(entry).map_err(|_| EntryDefect::BadBlobEncoding)?;
    if bundle.is_empty() {
        return Err(EntryDefect::EmptyBlobs);
    }
    Ok(bundle)
}

fn decode_blobs(entry: &Value) -> Result<Vec<Vec<u8>>, EntryDefect> {
    let blobs = entry
        .get("blobs")
        .and_then(Value::as_array)
        .ok_or(EntryDefect::NoBlobsArray)?;
    let decoded = blobs
        .iter()
        .map(|b| {
            b.as_str()
                .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                .ok_or(EntryDefect::BadBlobEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if decoded.is_empty() {
        return Err(EntryDefect::EmptyBlobs);
    }
    Ok(decoded)
}

/// The server statement slot, discriminated by `kind` so trust is decided
/// by the tag, never by probing for a signature. The signed form nests a
/// pristine coz (`{pay, sig}`) under `coz`, byte identical to a standalone
/// coz so a verifier can lift it out unchanged.
///
/// This is the one definition of the slot: the server serializes it and
/// every client reads it (`docs/specs/http-envelope.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "coz", rename_all = "lowercase")]
pub enum Statement {
    /// No server attestation -- an affirmative marker, not an absence.
    Unsigned,
    /// A server-signed coz (`{pay, sig}`) over the response.
    Signed(coz::CozJson),
}

/// Verify the signed statement of one patch response: it must be a
/// signature by `expected`, it must canonicalize via [`TipReport::parse`],
/// and it must attest to `principal_id` -- the principal actually being
/// synced, not merely SOME principal the authority happens to hold.
///
/// The principal check is load-bearing, not defense in depth: a storage
/// engine derives a new principal's genesis from whatever blobs are
/// submitted under `principal_id` and never compares it against the
/// identifier itself, so an on-path party who rewrites only the outbound
/// query's `pr` gets back a fully genuine, genuinely-signed response for a
/// *different* principal. This is the only place that can stop it.
///
/// # Errors
///
/// [`PatchFailure::EnvelopeUnsignedOrMisSigned`],
/// [`PatchFailure::MalformedReport`] or [`PatchFailure::PrincipalMismatch`].
pub fn verify_authenticated_envelope(
    body: &Value,
    expected: &AuthorityKey,
    principal_id: &str,
) -> Result<TipReport, PatchFailure> {
    let statement: Option<Statement> = body
        .get("statement")
        .and_then(|s| Statement::deserialize(s).ok());

    let Some(Statement::Signed(coz)) = statement else {
        return Err(PatchFailure::EnvelopeUnsignedOrMisSigned);
    };

    if coz.pay["alg"].as_str() != Some(expected.alg.as_str())
        || !signature_verifies(&coz, &expected.pub_key)
    {
        return Err(PatchFailure::EnvelopeUnsignedOrMisSigned);
    }

    let report = TipReport::parse(&coz).map_err(|_| PatchFailure::MalformedReport)?;

    // `report.pr` (a bare b64ut genesis identifier, SPEC section 2.2.3's
    // default form) and the bare form of `principal_id` share one wire
    // form: a direct string comparison, no re-encoding.
    if report.pr.to_string() != bare_digest(principal_id) {
        return Err(PatchFailure::PrincipalMismatch);
    }

    Ok(report)
}

fn signature_verifies(coz: &coz::CozJson, pub_key: &[u8]) -> bool {
    let Some(alg) = coz.pay["alg"].as_str() else {
        return false;
    };
    let Ok(pay_json) = serde_json::to_vec(&coz.pay) else {
        return false;
    };
    coz::verify_json(&pay_json, &coz.sig, alg, pub_key) == Some(true)
}

/// The digest part of a labelled id (`ALG:digest`); an unlabelled id is
/// returned as is.
fn bare_digest(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, digest)| digest)
}

/// Percent-encode `value` for use as one query-string component, escaping
/// every byte outside RFC 3986's `unreserved` set (`ALPHA` / `DIGIT` / `-` /
/// `.` / `_` / `~`) as `%XX`.
pub(crate) fn percent_encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            },
            _ => {
                // Writing to a `String` is infallible; the `Result` is
                // `fmt::Write`'s signature, not a reachable error.
                let _ = write!(out, "%{byte:02X}");
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backs: a patch query value cannot inject an extra parameter or fragment
    /// (`&`, `=`, `#` are escaped; unreserved bytes pass through).
    /// Unit: a pure encoder whose byte table no scenario reaches more cheaply.
    #[test]
    fn percent_encode_query_value_escapes_injection_and_keeps_unreserved() {
        assert_eq!(percent_encode_query_value("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode_query_value(""), "");
        assert_eq!(percent_encode_query_value("a&b=c#d"), "a%26b%3Dc%23d");
    }

    fn patch_body(v: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "v": v,
            "payload": {"entries": []},
            "statement": {"kind": "unsigned"},
        }))
        .unwrap()
    }

    /// Claim: a client fails closed on a response envelope version it does
    /// not know: the typed `UnsupportedVersion`, with nothing handed back to apply, even
    /// when no authority key is supplied. A known version still decodes.
    /// Turns red on a reader that ignores `v` (the S10 hostile peer). A unit
    /// test: the pure entry point the fuzz target drives; the networked form
    /// is `s10_hostile`, gated on transport.
    #[test]
    fn version_patch_envelope_unknown_is_refused() {
        verify_patch_body(&patch_body(1), "pid", None).expect("v1 decodes");
        for unknown in [0u64, 99] {
            let refused = verify_patch_body(&patch_body(unknown), "pid", None).err();
            assert!(
                matches!(
                    refused,
                    Some(PatchFailure::UnsupportedVersion { found, .. }) if found == unknown
                ),
                "envelope v={unknown} must be refused as UnsupportedVersion: {refused:?}"
            );
        }
    }
}
