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
//! # What a thin client can and cannot establish
//!
//! A client that pins one [`Root`] (by other means: a root it was given
//! out of band, or one it replayed) can check, with [`verify`], that a
//! commit is in the log that root commits to ([`Claim::Member`], given the
//! commit itself), that a longer head extends it ([`Claim::Extends`]), and
//! that a key is in its key set ([`Claim::Key`]). A server serves the
//! certificates (`GET /proof`) and the head (`GET /tip`'s `root`); a
//! holder of a principal builds them with [`Principal::prove`](crate::Principal::prove)
//! and reads roots with [`Principal::root_at`](crate::Principal::root_at).
//!
//! It cannot establish that its pinned root is the principal's *current*
//! one: a certificate is time-free, and a server may serve a log that is
//! older than the principal's real state. Freshness needs a witness, a
//! party the client trusts to say what the latest root is; it is not
//! something a certificate can show. Nor does a verified extension advance
//! the pin: an `Ok` from an `Extends` claim steers what to fetch and does
//! not vouch for what the peer added.
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
//!   "txs": [[bytes]],                   // each mutation transaction's czds, in order
//!   "fwd_variants": [[alg, bytes]],     // the forward State Root's variants, empty when absent
//!   "pt_cells": [bytes] } }             // SR, CR, nonces of PR_{s-1}: every family's variant
//! path        := { "alg", "index", "size", "steps": [step] }
//! step        := { "position", "siblings": [bytes] }
//! consistency := { "alg", "boundary_hash", "peak_path": [step],
//!                  "new_peaks": [bytes], "split_index" }
//!
//! key certificate := {
//!   "top": { "pt_cells": [bytes] },     // PR at the size -> SR (cell 0)
//!   "key": { "alg", "hops": [path] }    // key leaf in KT (root KR); KR in the
//!                                       // AR node; AR in the SR node (SR is the
//!                                       // cell's variant); empty steps where
//!                                       // a single child is promoted
//! }
//! ```
//!
//! A certificate of one kind is refused as malformed by the verifier of
//! another: a key certificate has no `stitches` or `terminal`, a
//! membership or extension certificate no `key`.
//!
//! The arrow is `H_G(pre || fwd? || TMR)` in SPEC 4.2 order. TMR is
//! recomputed from the czds the opening carries (the same czds the leaf's
//! transaction root is made of), never carried; `pre` is derived from the
//! Principal Tree cells (each family's variant folds to `PR_{s-1}`'s), not
//! carried either. Every variant on the wire (the cells', `fwd_variants`)
//! has the width of its declared family, checked at parse.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::replay::WireBundle;
use crate::{PrincipalRoot, PrincipalState, TransactionRoot};

mod prove;
mod verify;
mod wire;

/// The checks that fail inside the prover and the verifier, finer than the
/// kinds a caller acts on ([`ProofError`], [`ProveError`]). Not part of the
/// stable surface: tests read it through `cause()` (feature `test-utils`),
/// and no message text is contract.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Cause {
    /// An EML path does not reach the root it is checked against.
    #[error("log path does not reach the root")]
    Path,
    /// The closing coz, TR path or arrow components do not bind the opened
    /// commit: the arrow does not recompute.
    #[error("commit opening does not bind the arrow")]
    Arrow,
    /// A Principal Tree opening does not fold to the Principal Root it must.
    #[error("principal tree opening does not fold to the principal root")]
    PtCell,
    /// A root of the family the walk needs is absent.
    #[error("no root for the requested family")]
    Family,
    /// The consistency proof does not connect the roots.
    #[error("the head does not extend the trusted root")]
    NotAnExtension,
    /// The certificate states something other than the claim (a size, an
    /// index, a transaction root).
    #[error("certificate does not match the claim: {0}")]
    Mismatch(String),
    /// The asked index, size or anchor do not fit.
    #[error("{0}")]
    Asked(String),
    /// Bounds or framing.
    #[error("{0}")]
    Framing(String),
    /// The prover cannot build the certificate for what was asked.
    #[error("no certificate: {0}")]
    Unprovable(String),
    /// The key asked about is not in the key set at the size asked.
    #[error("no such key: {0}")]
    NoKey(String),
    /// The log's last commit left no State Root, so there is nothing to open.
    #[error("no state root: {0}")]
    NoStateRoot(String),
    /// The log's store failed while the certificate was built.
    #[error("store: {0}")]
    Storage(String),
}

/// Why a claim is not accepted, in the ways a caller acts on. Each carries
/// the check that failed; read it with `cause()` under `test-utils`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// The question does not fit what is pinned: a size the anchor does not
    /// pin, an index at or past the size. Nothing is accused; ask again.
    #[error("the question does not fit: {0}")]
    Question(Cause),
    /// A well-formed certificate that does not verify: a possible forgery.
    #[error("refuted: {0}")]
    Refuted(Cause),
    /// Not a certificate of the claim's kind, or out of bounds or framing:
    /// refused before any hashing.
    #[error("malformed: {0}")]
    Malformed(Cause),
    /// An `Extends` claim whose consistency check fails: the head does not
    /// extend the pinned log, the shape of a fork. Only `Extends` gives it.
    #[error("diverged: {0}")]
    Diverged(Cause),
}

impl ProofError {
    /// The check that failed.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
    pub fn cause(&self) -> &Cause {
        match self {
            Self::Question(c) | Self::Refuted(c) | Self::Malformed(c) | Self::Diverged(c) => c,
        }
    }
}

impl From<Cause> for ProofError {
    fn from(c: Cause) -> Self {
        match c {
            Cause::Path | Cause::Arrow | Cause::PtCell | Cause::Family | Cause::Mismatch(_) => {
                Self::Refuted(c)
            },
            Cause::NotAnExtension => Self::Diverged(c),
            Cause::Asked(_)
            | Cause::Unprovable(_)
            | Cause::NoKey(_)
            | Cause::NoStateRoot(_)
            | Cause::Storage(_) => Self::Question(c),
            Cause::Framing(_) => Self::Malformed(c),
        }
    }
}

/// Why a certificate cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProveError {
    /// The claim asks for what the log does not hold: an index or size past
    /// it, a key not in the key set at that size.
    #[error("the claim does not fit the log: {0}")]
    Question(Cause),
    /// The log cannot answer now: a store failure, or a last commit that
    /// left no State Root.
    #[error("unavailable: {0}")]
    Unavailable(Cause),
}

impl ProveError {
    /// The check that failed.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
    pub fn cause(&self) -> &Cause {
        match self {
            Self::Question(c) | Self::Unavailable(c) => c,
        }
    }
}

impl From<Cause> for ProveError {
    fn from(c: Cause) -> Self {
        match c {
            Cause::NoStateRoot(_) | Cause::Storage(_) => Self::Unavailable(c),
            other => Self::Question(other),
        }
    }
}

/// The Principal Root at a size: what a holder pins and what `GET /tip` reports
/// as `root`. PR-level: it is a function of the commit history, equal for
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
    fn old_roots(&self, from: u64, base: &wire::Cells) -> Result<verify::Roots, Cause> {
        match &self.0 {
            Pins::Chain(state) => {
                let own = usize::try_from(from.checked_sub(1).ok_or(Cause::PtCell)?)
                    .ok()
                    .and_then(|i| state.commit_at(i))
                    .ok_or_else(|| {
                        Cause::Asked(format!("the anchor pins no root at size {from}"))
                    })?;
                let cells = wire::Cells::parse(own.pt_cells().to_vec()).map_err(Cause::Framing)?;
                verify::cr_roots(&cells, &cells.families)
            },
            Pins::Pin(root) if root.size == from => verify::open_pinned(base, &root.pr),
            Pins::Pin(_) => Err(Cause::Asked(format!(
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
/// no trust: only [`verify`] against
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

/// What a certificate is asked to show, at a `size` the anchor pins.
#[derive(Clone, Debug)]
pub enum Claim {
    /// The commit `commit` is at `index` of the log of `size` commits. The
    /// commit is as a server serves it (its bundle); the transaction root is
    /// computed from its cozies, never passed in, and a prover reads `index`
    /// only. A holder builds it with `WireBundle::of_commit`. The claim binds
    /// the czds of the commit's cozies and how they are grouped, and nothing
    /// else: the bundle's data `actions` and `keys` are not under the
    /// transaction root, so verifying shows that these cozies, so grouped,
    /// are commit `index`, not what the bundle carries beside them.
    Member {
        /// Position of the commit.
        index: u64,
        /// The commit itself.
        commit: WireBundle,
    },
    /// The log of `size` commits, whose Principal Root is `head`, extends
    /// the log of `from` commits the anchor pins. `Ok` is a verdict that
    /// steers and does not vouch: nothing the peer added past `from` is
    /// believed, and the commits, replayed and signature-checked, are what
    /// make a head trusted.
    Extends {
        /// The pinned size extended from.
        from: u64,
        /// The claimed head's Principal Root, at `size`.
        head: PrincipalRoot,
    },
    /// The key with this thumbprint is in the key set (KR) at `size`: the
    /// Principal Tree opening to SR, then AR, KR and the key's leaf. It
    /// answers membership in KR only; frozen, deleted and errored are not
    /// checked.
    Key {
        /// The key's thumbprint.
        tmb: coz::Thumbprint,
    },
}

/// Check `claim` at `size` against `certificate`, relative to `anchor`.
///
/// # Errors
///
/// [`ProofError::Question`] for a size the anchor does not pin or an index
/// at or past it; [`ProofError::Refuted`] for a certificate that does not
/// verify; [`ProofError::Malformed`] for a certificate of another kind or
/// out of bounds; [`ProofError::Diverged`] for an `Extends` claim whose
/// consistency check fails.
pub fn verify(
    anchor: &Anchor<'_>,
    certificate: &Certificate,
    size: u64,
    claim: &Claim,
) -> Result<(), ProofError> {
    match claim {
        Claim::Member { index, commit } => {
            verify::membership(anchor, certificate, size, *index, commit)
        },
        Claim::Extends { from, head } => {
            let head = Root {
                size,
                pr: head.clone(),
            };
            verify::extension(anchor, certificate, *from, &head)
        },
        Claim::Key { tmb } => verify::key(anchor, certificate, size, tmb),
    }
    .map_err(Into::into)
}
