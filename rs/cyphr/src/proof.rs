//! Pinned roots and certificates: membership and extension across hash
//! algorithm epochs (frame NETSIM-FIX, E10).
//!
//! **THIS MODULE IS A STUB.** It declares the E10 surface the acceptance
//! tests (`tests/stitch.rs`) are written against; every function that
//! needs logic is `unimplemented!()`. The pre-E10 implementation lives in
//! [`legacy`] (to reuse, then delete); it still hashes the arrow sorted
//! and is broken against the ordered arrow.
//!
//! A [`Root`] is what a holder pins: the Principal Root at a size. An
//! [`Anchor`] says which roots the verifier trusts. A [`Certificate`] is
//! time-free plain data a prover builds and a verifier checks against an
//! anchor: every proof is `PR` -(open)-> `CR` -(hop)*-> terminal, where a
//! hop is an EML step within one family followed by a stitch (the Principal
//! Tree opening at `s - 1`) into the arrow's family. The Principal Tree
//! opening is carried at each end.
//!
//! # Wire form (the tests tamper through it; the implementer may reshape
//! # it and then adapts the tests' accessors in one place)
//!
//! JSON, every byte string base64url without padding, every family named
//! by its Coz name:
//!
//! ```text
//! certificate := {
//!   "top":  { "pt_cells": [bytes] },    // PR at the head size -> CR
//!   "base": { "pt_cells": [bytes] },    // extension only: PR at `from` -> CR
//!   "stitches": [ stitch ],
//!   "terminal": path | consistency
//! }
//! stitch   := { "alg", "leaf": path, "opening": {
//!   "tr_map", "tr_path": [step], "coz",
//!   "pre_variants": [[alg, bytes]],     // the variants of PR_{s-1} the arrow binds
//!   "fwd": [alg, bytes] | null,         // the forward State Root, as the arrow takes it
//!   "pt_cells": [bytes] } }
//! path        := { "alg", "index", "size", "steps": [step] }
//! step        := { "position", "siblings": [bytes] }
//! consistency := { "alg", "boundary_hash", "peak_path": [step],
//!                  "new_peaks": [bytes], "split_index" }
//! ```
//!
//! The arrow is `H_G(pre || fwd? || TMR)` in SPEC 4.2 order. TMR is
//! recomputed from the opened TR, never carried; `pre` and `fwd` widths
//! come from their declared families, never from lengths.

use serde::{Deserialize, Serialize};

use crate::{Principal, PrincipalRoot, PrincipalState, TransactionRoot};

#[doc(hidden)]
pub mod legacy;

/// Why a proof is refused. Each variant names the check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// An EML path does not reach the root it is checked against.
    #[error("log path does not reach the root")]
    Path,
    /// The closing coz, TR path or arrow components do not bind the opened
    /// commit: the arrow does not recompute.
    #[error("commit opening does not bind the arrow")]
    Arrow,
    /// A Principal Tree opening does not fold to the Principal Root it must
    /// (the anchor's pin at the top, the arrow's `pre` at a stitch).
    #[error("principal tree opening does not fold to the principal root")]
    PtCell,
    /// A root of the family the walk needs is absent.
    #[error("no root for the requested family")]
    Family,
    /// The consistency proof does not connect the roots.
    #[error("the head does not extend the trusted root")]
    NotAnExtension,
    /// The certificate does not match the claim (size, index, transaction,
    /// head) or is not the wire shape.
    #[error("certificate does not match the claim: {0}")]
    Mismatch(String),
    /// The prover cannot build the certificate.
    #[error("no certificate: {0}")]
    Unprovable(String),
    /// The log's store failed while the certificate was built.
    #[error("store: {0}")]
    Storage(String),
}

/// The Principal Root at a size: what a holder pins and what `GET /head`
/// reports. PR-level: it is a function of the commit history, equal for
/// every party holding it. Plain data; it confers trust only through an
/// [`Anchor`] constructor.
///
/// Wire: `{"size": n, "pr": {"SHA-256": "<base64url>", ...}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// Commits the root covers.
    pub size: u64,
    /// The Principal Root after the last of them, one variant per family
    /// active then.
    pub pr: PrincipalRoot,
}

impl Serialize for Root {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        unimplemented!("stub: Root::serialize")
    }
}

impl<'de> Deserialize<'de> for Root {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        unimplemented!("stub: Root::deserialize")
    }
}

#[allow(dead_code)]
enum Pins<'a> {
    Chain(&'a PrincipalState),
    Pin(Root),
}

/// Which roots a verifier trusts. Nothing in this crate turns a peer's
/// answer into an anchor: [`Anchor::of_chain`] pins every size of a chain
/// the holder verified, [`Anchor::pin`] pins the one root the caller
/// chose (SPEC 13.2).
///
/// An anchor cannot be built by hand:
///
/// ```compile_fail,E0423
/// use cyphr::proof::*;
/// fn forge(root: Root) -> Anchor<'static> {
///     Anchor(root)
/// }
/// ```
pub struct Anchor<'a>(#[allow(dead_code)] Pins<'a>);

impl<'a> Anchor<'a> {
    /// STUB. Trust every size of `state`'s chain. O(1), copies nothing.
    #[must_use]
    pub fn of_chain(_state: &'a PrincipalState) -> Self {
        unimplemented!("stub: Anchor::of_chain")
    }

    /// STUB. Trust one root: the caller's own choice of anchor.
    #[must_use]
    pub fn pin(_root: Root) -> Anchor<'static> {
        unimplemented!("stub: Anchor::pin")
    }
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Step {
    position: usize,
    siblings: Vec<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Path {
    alg: String,
    index: u64,
    size: u64,
    steps: Vec<Step>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Opening {
    tr_map: String,
    tr_path: Vec<Step>,
    coz: String,
    pre_variants: Vec<(String, String)>,
    fwd: Option<(String, String)>,
    pt_cells: Vec<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Stitch {
    alg: String,
    leaf: Path,
    opening: Opening,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Ends {
    pt_cells: Vec<String>,
}

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
struct Consistency {
    alg: String,
    boundary_hash: String,
    peak_path: Vec<Step>,
    new_peaks: Vec<String>,
    split_index: usize,
}

#[allow(dead_code)]
#[derive(Serialize)]
#[serde(untagged)]
enum Terminal {
    Path(Path),
    Consistency(Consistency),
}

#[allow(dead_code)]
#[derive(Serialize)]
struct Wire {
    top: Ends,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<Ends>,
    stitches: Vec<Stitch>,
    terminal: Terminal,
}

/// Opaque proof material: built by `prove_*`, parsed by a bounded
/// `Deserialize` that refuses oversized fields (F4), mis-framed Principal
/// Tree cells (F1) and implausible lengths before any hashing. It carries
/// no trust: only [`verify_membership`] and [`verify_extension`] against
/// an [`Anchor`] judge it.
///
/// A certificate cannot be built by hand:
///
/// ```compile_fail,E0423
/// use cyphr::proof::*;
/// fn forge() -> Certificate {
///     Certificate(todo!())
/// }
/// ```
#[derive(Serialize)]
pub struct Certificate(#[allow(dead_code)] Wire);

impl<'de> Deserialize<'de> for Certificate {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        unimplemented!("stub: Certificate::deserialize (bounded)")
    }
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Certificate(..)")
    }
}

/// STUB. Check that `tr` is the transaction root of commit `index` in the
/// log of `size` commits the anchor pins. The walk follows the signer's
/// family from the Principal Root the anchor pins at `size`.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_membership(
    _anchor: &Anchor<'_>,
    _certificate: &Certificate,
    _size: u64,
    _index: u64,
    _tr: &TransactionRoot,
) -> Result<(), ProofError> {
    unimplemented!("stub: verify_membership")
}

/// STUB. Check that `head` (a peer's claim, plain data) extends the log of
/// `from` commits the anchor pins. A verdict only: it returns no root and
/// grants no trust, so nothing the peer added is vouched for.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_extension(
    _anchor: &Anchor<'_>,
    _certificate: &Certificate,
    _from: u64,
    _head: &Root,
) -> Result<(), ProofError> {
    unimplemented!("stub: verify_extension")
}

impl<S: eml::Storage> Principal<S> {
    /// STUB. The principal's root at `size` commits (the Principal Root of
    /// commit `size - 1`); `None` for 0 or a size past the log.
    #[must_use]
    pub fn root_at(&self, _size: u64) -> Option<Root> {
        unimplemented!("stub: Principal::root_at")
    }

    /// STUB. The certificate that commit `index` is in the log of `size`
    /// commits.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for an index or size the log lacks.
    pub async fn prove_membership(
        &self,
        _index: u64,
        _size: u64,
    ) -> Result<Certificate, ProofError> {
        unimplemented!("stub: Principal::prove_membership")
    }

    /// STUB. The certificate that the log of `to` commits extends the log
    /// of `from`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for sizes the log has not passed.
    pub async fn prove_extension(&self, _from: u64, _to: u64) -> Result<Certificate, ProofError> {
        unimplemented!("stub: Principal::prove_extension")
    }
}
