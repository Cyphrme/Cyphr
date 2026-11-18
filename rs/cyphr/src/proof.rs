//! Pinned roots and certificates: membership and extension across hash
//! algorithm epochs.
//!
//! A [`Root`] is what a holder pins: the Principal Root at a size. An
//! [`Anchor`] says which roots the verifier trusts. A [`Certificate`] is
//! time-free plain data a prover builds and a verifier checks against an
//! anchor: every proof is `PR` -(open)-> `CR` -(hop)*-> terminal, where a
//! hop is an EML step within one family followed by a stitch (the Principal
//! Tree opening at `s - 1`) into the arrow's family. The Principal Tree
//! opening is carried at each end.
//!
//! # Wire form
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
//!   "tr_map", "coz",
//!   "tr_path": [step],                  // one per mutation transaction: its czds as siblings, position 0
//!   "fwd_variants": [[alg, bytes]],     // the forward State Root's variants, empty when absent
//!   "pt_cells": [bytes] } }             // SR, CR, nonces of PR_{s-1}: every family's variant
//! path        := { "alg", "index", "size", "steps": [step] }
//! step        := { "position", "siblings": [bytes] }
//! consistency := { "alg", "boundary_hash", "peak_path": [step],
//!                  "new_peaks": [bytes], "split_index" }
//! ```
//!
//! The arrow is `H_G(pre || fwd? || TMR)` in SPEC 4.2 order. TMR is
//! recomputed from the czds the opening carries (the same czds the leaf's
//! transaction root is made of), never carried; `pre` is derived from the
//! Principal Tree cells (each family's variant folds to `PR_{s-1}`'s), not
//! carried either. Every variant on the wire (the cells', `fwd_variants`)
//! has the width of its declared family, checked at parse.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{PrincipalRoot, PrincipalState, TransactionRoot};

mod prove;
mod verify;
mod wire;

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

#[derive(Serialize, Deserialize)]
struct RawRoot {
    size: u64,
    pr: std::collections::BTreeMap<String, wire::Capped<64>>,
}

impl Serialize for Root {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        RawRoot {
            size: self.size,
            pr: self
                .pr
                .0
                .variants()
                .iter()
                .map(|(a, d)| (a.to_string(), wire::Capped(d.to_vec())))
                .collect(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Root {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawRoot::deserialize(d)?;
        let variants = raw
            .pr
            .into_iter()
            .map(|(name, digest)| {
                let alg = crate::state::hash_alg_named(&name)
                    .map_err(|_| serde::de::Error::custom(format!("unknown family {name:?}")))?;
                Ok((alg, digest.0.into_boxed_slice()))
            })
            .collect::<Result<_, D::Error>>()?;
        let pr = crate::multihash::MultihashDigest::new(variants)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(Self {
            size: raw.size,
            pr: PrincipalRoot(pr),
        })
    }
}

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
pub struct Anchor<'a>(Pins<'a>);

impl<'a> Anchor<'a> {
    /// Trust every size of `state`'s chain. O(1), copies nothing.
    #[must_use]
    pub fn of_chain(state: &'a PrincipalState) -> Self {
        Self(Pins::Chain(state))
    }

    /// Trust one root, the caller's own choice of anchor. Pin only a root
    /// trusted by other means (SPEC 13.2): a root a peer reports, or the
    /// head a certificate was made for, is the peer's word and nothing
    /// more, and a certificate checked against such a pin proves only that
    /// the peer is consistent with itself.
    #[must_use]
    pub fn pin(root: Root) -> Anchor<'static> {
        Anchor(Pins::Pin(root))
    }

    /// The Principal Root this anchor pins at `size` commits.
    fn pr_at(&self, size: u64) -> Option<&PrincipalRoot> {
        match &self.0 {
            Pins::Chain(state) => state
                .commit_at(usize::try_from(size.checked_sub(1)?).ok()?)
                .map(crate::Commit::pr),
            Pins::Pin(root) => (root.size == size).then_some(&root.pr),
        }
    }

    /// The family roots of the Commit Root at `from` commits. A holder of
    /// the chain reads them from its own cells; a pin has only the root, so
    /// the certificate's `base` opening is folded to it.
    fn old_roots(&self, from: u64, base: &wire::Cells) -> Result<verify::Roots, ProofError> {
        match &self.0 {
            Pins::Chain(state) => {
                let own = usize::try_from(from.checked_sub(1).ok_or(ProofError::PtCell)?)
                    .ok()
                    .and_then(|i| state.commit_at(i))
                    .ok_or_else(|| {
                        ProofError::Mismatch(format!("the anchor pins no root at size {from}"))
                    })?;
                let cells =
                    wire::Cells::parse(own.pt_cells().to_vec()).map_err(ProofError::Mismatch)?;
                verify::cr_roots(&cells, &cells.families)
            },
            Pins::Pin(root) if root.size == from => verify::open_pinned(base, &root.pr),
            Pins::Pin(_) => Err(ProofError::Mismatch(format!(
                "the anchor pins no root at size {from}"
            ))),
        }
    }

    /// The transaction root of commit `index`, when the anchor holds the
    /// chain.
    fn tr_at(&self, index: u64) -> Option<&TransactionRoot> {
        match &self.0 {
            Pins::Chain(state) => state
                .commit_at(usize::try_from(index).ok()?)
                .map(crate::Commit::tr),
            Pins::Pin(_) => None,
        }
    }
}

/// Opaque proof material: built by `prove_*`, parsed by a bounded
/// `Deserialize` that refuses oversized fields, mis-framed Principal
/// Tree cells and implausible lengths before any hashing. It carries
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
pub struct Certificate(wire::Cert);

impl Serialize for Certificate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        wire::RawCert::from(&self.0).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Certificate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = wire::RawCert::deserialize(d)?;
        wire::Cert::try_from(raw)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Certificate(..)")
    }
}

/// Check that `tr` is the transaction root of commit `index` in the log of
/// `size` commits the anchor pins. The walk follows the signer's family
/// from the Principal Root the anchor pins at `size`.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_membership(
    anchor: &Anchor<'_>,
    certificate: &Certificate,
    size: u64,
    index: u64,
    tr: &TransactionRoot,
) -> Result<(), ProofError> {
    verify::membership(anchor, certificate, size, index, tr)
}

/// Check that `head` (a peer's claim, plain data) extends the log of
/// `from` commits the anchor pins.
///
/// `Ok` is a verdict that steers and does not vouch: it returns no root and
/// grants no trust, so nothing the peer added past `from` is believed. A
/// caller may act on it to decide what to fetch, never to accept the head;
/// the commits themselves, replayed and signature-checked, are what make a
/// head trusted. Pin (see [`Anchor::pin`]) only a root trusted by other
/// means.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_extension(
    anchor: &Anchor<'_>,
    certificate: &Certificate,
    from: u64,
    head: &Root,
) -> Result<(), ProofError> {
    verify::extension(anchor, certificate, from, head)
}
