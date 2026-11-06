//! Carrier-independent Cyphr sync client.
//!
//! The crate has two layers. The **verify core** (everything but the
//! `http` module) performs no I/O and names no async runtime: it decodes
//! and authenticates a `/patch` response body and hands back entries a
//! caller can apply. The **transports** (feature-gated) carry request and
//! response bytes behind the [`Connector`] trait, so sync does not depend
//! on the carrier; a Noise transport plugs in as one more `Connector`.

mod connector;
mod patch;
mod report;

#[cfg(feature = "http")]
mod http;

pub use connector::{
    BindingError, BindingKind, BindingPolicy, ChannelBinding, ConnectError, Connector, Method,
    Request,
};
#[cfg(feature = "http")]
pub use http::HttpConnector;
pub use patch::{
    AuthorityKey, EntryDefect, PatchEntry, PatchFailure, PatchRequest, VerifiedPatch, fetch_patch,
    verify_authenticated_envelope, verify_patch_body,
};
pub use report::{TipReport, TipReportParseError, TipReportRoots};
