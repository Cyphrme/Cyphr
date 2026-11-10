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
pub mod evidence;
mod patch;
mod peer;
mod report;

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
    ActionBundle, AuthorityKey, EntryDefect, PatchEntry, PatchFailure, PatchRequest, Statement,
    VerifiedPatch, fetch_patch, verify_authenticated_envelope, verify_patch_body,
};
pub use peer::{HeldTip, PeerChain, PeerFailure};
pub use report::{
    TipReport, TipReportParseError, TipReportRoots, VIEW_STATEMENT_TYP, ViewFailure, ViewStatement,
    ViewStatementParseError, verify_view, verify_view_statement,
};
