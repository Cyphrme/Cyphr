//! Carrier-independent Cyphr sync client.
//!
//! The crate has two layers. The **verify core** (everything but the
//! `http` and `transport` modules) performs no I/O and names no async runtime: it decodes
//! and authenticates a `/patch` response body and hands back entries a
//! caller can apply. The **transports** (feature-gated) carry request and
//! response bytes behind the [`Connector`] trait, so sync does not depend
//! on the carrier; the Noise [`transport`] (feature `noise`) is one more
//! `Connector`.

mod connector;
mod embedded;
pub mod evidence;
mod exchange;
mod extension;
mod patch;
mod peer;
mod relying_party;
mod report;
mod revoke;
mod sync;

pub use embedded::{FollowReport, GossipTips, PeerPull};
pub use exchange::{Bundle, BundleActions, BundleChain, BundleConnector, BundleError};
pub use extension::{
    Extension, ExtensionFailure, confirm_extension, verify_extension, verify_extension_at,
};
pub use relying_party::{
    LOGIN_TYP_SUFFIX, Refusal, RelyingParty, RpConfig, Session, SessionBinding, Trust,
    UnmetCurrency,
};
pub use revoke::{NakedRevoke, RevokeFailure, verify_naked_revoke};
pub use sync::{
    Anchor, ChainSource, DEFAULT_PATCH_CAP, ForkFinding, MAX_RESYNCS, PeerHeads, PeerOutcome,
    PeerStanding, PullPeer, PullReport, Record, RecordTip, RevokedKey, branch_bundles,
    fetch_resyncs, fetch_revoked, opener_of, peer_heads, pull, verified_revokes,
};

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "noise")]
pub mod transport;

pub use connector::{
    BindingError, BindingKind, BindingPolicy, ChannelBinding, ConnectError, Connector, Method,
    Request,
};
#[cfg(feature = "http")]
pub use http::{HttpConnector, HttpOptions, MAX_RESPONSE_BYTES};
pub use patch::{
    ActionBundle, AuthorityKey, BranchPatch, EntryDefect, ForkPatch, PatchEntry, PatchFailure,
    PatchRequest, Statement, VerifiedPatch, fetch_patch, verify_authenticated_envelope,
    verify_held_envelope, verify_patch_body,
};
pub use peer::{HeldTip, PeerChain, PeerFailure, PeerLimits};
pub use report::{
    COMMIT_RECEIPT_TYP, ForkPoint, HELD_REPORT_TYP, HeldHead, HeldReport, HeldReportParseError,
    TIP_REPORT_TYP, TipAnswer, TipReport, TipReportParseError, TipReportRoots,
};
