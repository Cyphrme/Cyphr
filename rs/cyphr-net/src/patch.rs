//! Fetching and verifying one `/patch` response.
//!
//! Everything here is pure computation over bytes the [`Connector`]
//! returned: the same body verifies identically whatever carried it.
//!
//! When an [`PeerKey`] is supplied, the response's signed statement
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
use cyphr::PrincipalGenesis;
use cyphr::replay::WireBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::connector::{
    BindingError, BindingPolicy, ChannelBinding, ConnectError, Connector, Request,
};
use crate::report::{HeldReport, ReportedForkPoint, TipReport};

/// The response envelope wire version this client reads
/// (`docs/specs/http-envelope.md`).
pub(crate) const ENVELOPE_VERSION: u64 = 1;

/// The key of a peer's server principal a signed statement must verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKey {
    /// The key's signature algorithm (e.g. `Ed25519`).
    pub alg: String,
    /// The key's public key bytes.
    pub pub_key: Vec<u8>,
}

/// One `/patch` request.
#[derive(Debug, Clone, Copy)]
pub struct PatchRequest<'a> {
    /// The principal to sync.
    pub principal_id: &'a PrincipalGenesis,
    /// The resync anchor: the caller's current tip PR digest, absent when
    /// it holds nothing yet and wants a full resync from genesis.
    pub anchor: Option<&'a str>,
}

impl PatchRequest<'_> {
    /// The request target (`/patch?pg=...[&from=...]`) carried to the
    /// peer. Both values are percent-encoded so a value containing
    /// `&`/`=`/`#` cannot inject extra query parameters into the outbound
    /// request; the encoding must not depend on any other guard.
    #[must_use]
    pub fn target(&self) -> String {
        let pr = percent_encode_query_value(&self.principal_id.to_string());
        match self.anchor {
            Some(anchor) => format!("/patch?pg={pr}&from={}", percent_encode_query_value(anchor)),
            None => format!("/patch?pg={pr}"),
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
    /// The entries, in wire order, still to be applied by the caller: the
    /// chain the peer serves. While the peer is in Error (SPEC 15.5) it
    /// serves the common chain and then each branch; this is the
    /// common chain followed by the branch the peer marks canonical, so a
    /// consumer reads one chain exactly as it would an Active peer's, and
    /// [`fork`](Self::fork) holds every branch.
    pub entries: Vec<PatchEntry>,
    /// The fork point and each branch, present exactly when the peer
    /// reports Error.
    pub fork: Option<ForkPatch>,
    /// The action-only bundles, in wire order; empty from a peer that
    /// serves none.
    pub actions: Vec<ActionBundle>,
    /// The authenticated tip report; `Some` exactly when an
    /// [`PeerKey`] was supplied.
    pub report: Option<TipReport>,
    /// The authenticated held statement; `Some` exactly when an
    /// [`PeerKey`] was supplied and the peer is in Error, where it
    /// attests the heads instead of a tip.
    pub held: Option<HeldReport>,
    /// The carrier's channel binding, passed through for the caller.
    pub binding: Option<ChannelBinding>,
}

/// Whether a patch body is an Error peer's (it names its branches).
fn entries_fork_marker(body: &Value) -> bool {
    body.get("payload")
        .is_some_and(|p| p.get("branches").is_some())
}

/// An Error peer's patch beyond the common chain (SPEC 15.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkPatch {
    /// Where the branches part.
    pub fork_point: ReportedForkPoint,
    /// Each branch, from the fork point to its head.
    pub branches: Vec<BranchPatch>,
}

/// One branch of a [`ForkPatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPatch {
    /// The branch's head commit id, as the peer states it.
    pub head: String,
    /// Whether the peer marks this the chain its index serves, the one
    /// `/evidence` items are stated against.
    pub canonical: bool,
    /// The branch's commits, lowest first.
    pub entries: Vec<PatchEntry>,
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
    expected: Option<&PeerKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    check_binding(connector, policy)?;
    let body = connector.exchange(&Request::get(request.target())).await?;
    let mut verified = verify_patch_body(&body, request.principal_id, expected)?;
    verified.binding = connector.channel_binding().cloned();
    Ok(verified)
}

/// [`fetch_patch`] for a peer whose signing key is not known up front but
/// is held in a chain: the statement's signer is read first and `keys`
/// resolves it (a key active in the peer's server principal). A signer
/// `keys` does not know is [`PatchFailure::EnvelopeUnsignedOrMisSigned`],
/// as an unsigned envelope is, and nothing is decoded.
///
/// # Errors
///
/// As [`fetch_patch`].
pub async fn fetch_patch_keyed<C: Connector>(
    connector: &C,
    request: &PatchRequest<'_>,
    policy: BindingPolicy,
    keys: impl Fn(&coz::Thumbprint) -> Option<PeerKey>,
) -> Result<VerifiedPatch, PatchFailure> {
    check_binding(connector, policy)?;
    let body = connector.exchange(&Request::get(request.target())).await?;
    let key = statement_signer(&body)
        .and_then(|tmb| keys(&tmb))
        .ok_or(PatchFailure::EnvelopeUnsignedOrMisSigned)?;
    let mut verified = verify_patch_body(&body, request.principal_id, Some(&key))?;
    verified.binding = connector.channel_binding().cloned();
    Ok(verified)
}

/// A peer's `GET /tip` answer for `principal_id`, as its raw body bytes: the
/// signed tip report a verifier checks with [`verify_authenticated_envelope`]
/// once it holds the signer's key ([`statement_signer`] names it).
///
/// # Errors
///
/// [`PatchFailure::NonSuccess`] with 404 for a principal the peer does not
/// hold; any other carrier failure.
pub async fn fetch_tip_body<C: Connector>(
    connector: &C,
    principal_id: &PrincipalGenesis,
) -> Result<Vec<u8>, PatchFailure> {
    let target = format!(
        "/tip?pg={}",
        percent_encode_query_value(&principal_id.to_string())
    );
    Ok(connector.exchange(&Request::get(target)).await?)
}

/// The thumbprint a response's signed statement names as its signer: read
/// before any signature is checked, only to choose the key to check it
/// against.
#[must_use]
pub fn statement_signer(body: &[u8]) -> Option<coz::Thumbprint> {
    let body: Value = serde_json::from_slice(body).ok()?;
    let Some(Statement::Signed(coz)) = body
        .get("statement")
        .and_then(|s| Statement::deserialize(s).ok())
    else {
        return None;
    };
    cyphr::parsed_coz::CozHeader::parse(&coz.pay)
        .ok()
        .map(|header| header.tmb)
}

/// Refuse before the request leaves when the carrier cannot supply the
/// binding `policy` requires.
fn check_binding<C: Connector>(connector: &C, policy: BindingPolicy) -> Result<(), PatchFailure> {
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
    Ok(())
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
    principal_id: &PrincipalGenesis,
    expected: Option<&PeerKey>,
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

    let in_error = entries_fork_marker(&body);
    let (report, held) = match expected {
        None => (None, None),
        Some(key) if in_error => (None, Some(verify_held_envelope(&body, key, principal_id)?)),
        Some(key) => (
            Some(verify_authenticated_envelope(&body, key, principal_id)?),
            None,
        ),
    };

    let mut entries: Vec<PatchEntry> = entries.iter().map(decode_entry).collect();
    let fork = decode_fork(body.get("payload"))?;
    if let Some(fork) = &fork {
        let canonical = fork.branches.iter().find(|b| b.canonical).ok_or_else(|| {
            PatchFailure::MalformedResponse("an Error patch marks no canonical branch".into())
        })?;
        entries.extend(canonical.entries.iter().cloned());
    }

    Ok(VerifiedPatch {
        entries,
        fork,
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
        held,
        binding: None,
    })
}

/// The `fork_point` and `branches` of an Error patch; `None` when the
/// payload names neither (an Active peer).
fn decode_fork(payload: Option<&Value>) -> Result<Option<ForkPatch>, PatchFailure> {
    let Some(payload) = payload.filter(|p| p.get("branches").is_some()) else {
        return Ok(None);
    };
    let malformed = |what: String| PatchFailure::MalformedResponse(what);
    let (fork_point, _) = crate::report::parse_fork_point(payload)
        .map_err(|e| malformed(format!("fork_point: {e}")))?;
    let branches = payload["branches"]
        .as_array()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| malformed("branches is not a non-empty array".into()))?
        .iter()
        .map(|b| {
            Ok(BranchPatch {
                head: b["head"]
                    .as_str()
                    .ok_or_else(|| malformed("a branch has no head".into()))?
                    .to_owned(),
                canonical: b["canonical"].as_bool().unwrap_or(false),
                entries: b["entries"]
                    .as_array()
                    .ok_or_else(|| malformed("a branch has no entries".into()))?
                    .iter()
                    .map(decode_entry)
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, PatchFailure>>()?;
    Ok(Some(ForkPatch {
        fork_point,
        branches,
    }))
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
    expected: &PeerKey,
    principal_id: &PrincipalGenesis,
) -> Result<TipReport, PatchFailure> {
    let coz = signed_by(body, expected)?;
    let report = TipReport::parse(&coz).map_err(|_| PatchFailure::MalformedReport)?;

    // `report.pg` is the labelled id the statement attests: it must be
    // the principal asked about.
    if report.pg != *principal_id {
        return Err(PatchFailure::PrincipalMismatch);
    }

    Ok(report)
}

/// Verify the signed `held` statement of a `/tip` answer given while the
/// principal is in Error: a signature by `expected`, a canonical parse
/// ([`HeldReport::parse`]) and the principal actually asked about. The
/// statement names heads the server held and since when; it names no tip.
///
/// # Errors
///
/// As [`verify_authenticated_envelope`]; [`PatchFailure::MalformedReport`]
/// also for a statement that is not a held report.
pub fn verify_held_envelope(
    body: &Value,
    expected: &PeerKey,
    principal_id: &PrincipalGenesis,
) -> Result<HeldReport, PatchFailure> {
    let coz = signed_by(body, expected)?;
    let report = HeldReport::parse(&coz).map_err(|_| PatchFailure::MalformedReport)?;
    if report.pg != *principal_id {
        return Err(PatchFailure::PrincipalMismatch);
    }
    Ok(report)
}

/// The envelope's signed statement, once its signature verifies under
/// `expected`.
fn signed_by(body: &Value, expected: &PeerKey) -> Result<coz::CozJson, PatchFailure> {
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
    Ok(coz)
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

    fn pid() -> PrincipalGenesis {
        PrincipalGenesis::from_digest(cyphr::HashAlg::Sha256, vec![1; 32]).expect("valid id")
    }

    /// Claim: a client fails closed on a response envelope version it does
    /// not know: the typed `UnsupportedVersion`, with nothing handed back to apply, even
    /// when no authority key is supplied. A known version still decodes.
    /// Turns red on a reader that ignores `v` (the S10 hostile peer). A unit
    /// test: the pure entry point the fuzz target drives; the networked form
    /// is `s10_hostile`, gated on transport.
    #[test]
    fn version_patch_envelope_unknown_is_refused() {
        verify_patch_body(&patch_body(1), &pid(), None).expect("v1 decodes");
        for unknown in [0u64, 99] {
            let refused = verify_patch_body(&patch_body(unknown), &pid(), None).err();
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
