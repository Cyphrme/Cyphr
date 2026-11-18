//! Tip-anchored membership and extension proofs across hash-algorithm
//! epochs (the "stitch").
//!
//! Within one hash family's epoch a proof is an ordinary EML inclusion or
//! consistency proof. At an epoch boundary a [`Stitch`] opens one commit's
//! leaf through its TR path, the closing coz and the arrow preimage to
//! `PR_{s-1}`, then through the Principal Tree cells to `CR_{s-1}`.
//!
//! `PR[X]` binds `CR[X]` alone (each family's hasher reads only its own
//! variant of a cell), so a stitch authenticates only the families the
//! arrow's `pre` binds: the signer's, or by Cyphr's component conversion
//! rule the one variant or all of them.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use eml::Hasher as _;
use serde::{Deserialize, Serialize};

use crate::commit_root::{MaltHasher, hash_alg_to_u64, u64_to_hash_alg};
use crate::replay::StoredCoz;
use crate::state::{TaggedCzd, TaggedDigest, hash_concat_bytes, hash_sorted_concat_bytes};
use crate::{HashAlg, Principal, TransactionRoot};

/// Run `$body` with the type alias `$f` naming the family of `$alg`.
macro_rules! with_family {
    ($alg:expr, $f:ident => $body:expr) => {
        match $alg {
            HashAlg::Sha256 => {
                type $f = Sha256;
                $body
            },
            HashAlg::Sha384 => {
                type $f = Sha384;
                $body
            },
            HashAlg::Sha512 => {
                type $f = Sha512;
                $body
            },
        }
    };
}

mod sealed {
    pub trait Sealed {}
}

/// Wrapping a family's proof parts as the `Any*` enums; for the prover,
/// where the family is a concrete type.
trait Wrap: HashFamily {
    fn wrap_stitch(stitch: Stitch<Self>) -> AnyStitch
    where
        Self: Sized;
    fn wrap_path(path: LogPath<Self>) -> AnyPath
    where
        Self: Sized;
    fn wrap_consistency(c: Consistency<Self>) -> AnyConsistency
    where
        Self: Sized;
}

/// A hash family a log is built under. Sealed: the set is closed.
pub trait HashFamily: sealed::Sealed + 'static {
    /// The algorithm.
    const ALG: HashAlg;
    /// The digest width in bytes.
    const LEN: usize;
}

/// SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256 {}
/// SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha384 {}
/// SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha512 {}

macro_rules! family {
    ($t:ident, $alg:ident, $len:expr) => {
        impl sealed::Sealed for $t {}

        impl Wrap for $t {
            fn wrap_stitch(stitch: Stitch<Self>) -> AnyStitch {
                AnyStitch::$t(stitch)
            }

            fn wrap_path(path: LogPath<Self>) -> AnyPath {
                AnyPath::$t(path)
            }

            fn wrap_consistency(c: Consistency<Self>) -> AnyConsistency {
                AnyConsistency::$t(c)
            }
        }

        impl HashFamily for $t {
            const ALG: HashAlg = HashAlg::$alg;
            const LEN: usize = $len;
        }
    };
}
family!(Sha256, Sha256, 32);
family!(Sha384, Sha384, 48);
family!(Sha512, Sha512, 64);

/// Why a proof is refused. Each variant names the check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// A digest is not the width of its family.
    #[error("digest of {got} bytes is not a {want}-byte family digest")]
    Width {
        /// Bytes the family needs.
        want: usize,
        /// Bytes given.
        got: usize,
    },
    /// An EML path does not reach the root it is checked against: a
    /// foreign head, a forged tree, or a path under a family with a null at
    /// that position.
    #[error("log path does not reach the root")]
    Path,
    /// The closing coz, TR path, or arrow preimage does not bind the
    /// opened commit: the preimage does not hash to the coz's arrow, or the
    /// coz's czd is not under the opened TR.
    #[error("commit opening does not bind the arrow")]
    Arrow,
    /// A Principal Tree cell does not fold to the `PR` the arrow binds.
    #[error("principal tree cell does not fold to the principal root")]
    PtCell,
    /// The root has no variant for the requested family.
    #[error("no root for the requested family")]
    Family,
    /// The consistency proof does not connect the trusted root to the
    /// claimed one.
    #[error("the claimed log does not extend the trusted one")]
    NotAnExtension,
    /// The proof does not match the claimed size, index, or transaction.
    #[error("proof does not match the claim: {0}")]
    Mismatch(String),
    /// The prover cannot build the proof.
    #[error("no proof: {0}")]
    Unprovable(String),
    /// The log's store failed while the proof was built.
    #[error("store: {0}")]
    Storage(String),
}

/// A digest of family `H`: width checked at construction; equal only
/// within `H`.
///
/// Digests of different families cannot be compared:
///
/// ```compile_fail,E0308
/// use cyphr::proof::*;
/// fn same(a: Digest<Sha256>, b: Digest<Sha512>) -> bool {
///     a == b
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest<H: HashFamily>(Box<[u8]>, PhantomData<H>);

impl<H: HashFamily> Digest<H> {
    /// A digest from bytes, [`ProofError::Width`] if not `H::LEN`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Width`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() == H::LEN {
            Ok(Self(bytes.into(), PhantomData))
        } else {
            Err(ProofError::Width {
                want: H::LEN,
                got: bytes.len(),
            })
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One family's member root: a size and a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyRoot<H: HashFamily> {
    /// Leaves covered.
    pub size: u64,
    /// The root.
    pub digest: Digest<H>,
}

/// One family's root of any family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyFamilyRoot {
    /// SHA-256.
    Sha256(FamilyRoot<Sha256>),
    /// SHA-384.
    Sha384(FamilyRoot<Sha384>),
    /// SHA-512.
    Sha512(FamilyRoot<Sha512>),
}

/// A whole Commit Root as a Principal Tree cell holds it: a root for
/// every family active at its size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullCr {
    /// Commits covered.
    pub size: u64,
    /// One root per active family.
    pub variants: Vec<AnyFamilyRoot>,
}

mod trust {
    pub trait Sealed {}
}

/// How a root came to be believed. Sealed.
pub trait Trust: trust::Sealed + 'static {}
/// A root the holder verified or minted from its own verified state.
#[derive(Debug)]
pub enum Trusted {}
/// A root a peer stated, not yet extended-from or anchored.
#[derive(Debug)]
pub enum Claimed {}
impl trust::Sealed for Trusted {}
impl trust::Sealed for Claimed {}
impl Trust for Trusted {}
impl Trust for Claimed {}

/// A root `T` at trust level `M`. The field is private and the only
/// `Trusted` constructors read the holder's own state; the extension
/// verifier is the only `Claimed` -> `Trusted` path.
///
/// Control: the public flow compiles, and builds a digest first (red
/// until [`Digest::from_bytes`] exists).
///
/// ```
/// use cyphr::proof::*;
/// let d = Digest::<Sha512>::from_bytes(&[0; 64]).unwrap();
/// let claim = Rooted::<Claimed, FamilyRoot<Sha512>>::claim(FamilyRoot { size: 2, digest: d });
/// # let _ = claim;
/// ```
///
/// A claim is not a trusted root:
///
/// ```compile_fail,E0308
/// use cyphr::proof::*;
/// fn forge(c: Rooted<Claimed, FamilyRoot<Sha512>>) -> Rooted<Trusted, FamilyRoot<Sha512>> {
///     c
/// }
/// ```
///
/// Nor can one be built by hand, its field being private:
///
/// ```compile_fail,E0423
/// use cyphr::proof::*;
/// fn forge(r: FamilyRoot<Sha512>) -> Rooted<Trusted, FamilyRoot<Sha512>> {
///     Rooted(r, std::marker::PhantomData)
/// }
/// ```
///
/// A claimed root cannot anchor a membership proof:
///
/// ```compile_fail,E0277
/// use cyphr::proof::*;
/// fn anchor(
///     claimed: &Rooted<Claimed, AnyFamilyRoot>,
///     proof: &MembershipProof,
///     tr: &cyphr::TransactionRoot,
/// ) {
///     let _ = verify_membership(claimed, proof, tr);
/// }
/// ```
///
/// Only the holder's own `FullCr` has per-family accessors; a single
/// family's root has no `family::<H>()`:
///
/// ```compile_fail,E0599
/// use cyphr::proof::*;
/// fn pick(r: &Rooted<Trusted, AnyFamilyRoot>) {
///     let _ = r.family::<Sha256>();
/// }
/// ```
///
/// A peer's whole Commit Root is never one claim (its variants are not
/// bound to each other), so there is no way to claim one:
///
/// ```compile_fail,E0599
/// use cyphr::proof::*;
/// fn claim(cr: FullCr) {
///     let _ = Rooted::<Claimed, FullCr>::claim(cr);
/// }
/// ```
#[derive(Debug)]
pub struct Rooted<M: Trust, T>(T, PhantomData<M>);

impl<M: Trust, T> Rooted<M, T> {
    /// The root inside.
    #[must_use]
    pub fn get(&self) -> &T {
        &self.0
    }
}

impl AnyFamilyRoot {
    /// A root of `alg`'s family over `size` leaves.
    ///
    /// # Errors
    ///
    /// [`ProofError::Width`] if `bytes` is not the family's digest width.
    pub fn new(alg: HashAlg, size: u64, bytes: &[u8]) -> Result<Self, ProofError> {
        let digest = bytes;
        Ok(match alg {
            HashAlg::Sha256 => Self::Sha256(FamilyRoot {
                size,
                digest: Digest::from_bytes(digest)?,
            }),
            HashAlg::Sha384 => Self::Sha384(FamilyRoot {
                size,
                digest: Digest::from_bytes(digest)?,
            }),
            HashAlg::Sha512 => Self::Sha512(FamilyRoot {
                size,
                digest: Digest::from_bytes(digest)?,
            }),
        })
    }

    /// The digest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Sha256(r) => r.digest.as_bytes(),
            Self::Sha384(r) => r.digest.as_bytes(),
            Self::Sha512(r) => r.digest.as_bytes(),
        }
    }

    /// The leaves covered.
    #[must_use]
    pub fn size(&self) -> u64 {
        match self {
            Self::Sha256(r) => r.size,
            Self::Sha384(r) => r.size,
            Self::Sha512(r) => r.size,
        }
    }

    /// This root as family `H`'s, `None` for another family.
    fn to_family<H: HashFamily>(&self) -> Option<FamilyRoot<H>> {
        if self.alg() != H::ALG {
            return None;
        }
        Some(FamilyRoot {
            size: self.size(),
            digest: Digest::from_bytes(self.bytes()).ok()?,
        })
    }

    /// The hash algorithm of the family.
    #[must_use]
    pub fn alg(&self) -> HashAlg {
        match self {
            Self::Sha256(_) => HashAlg::Sha256,
            Self::Sha384(_) => HashAlg::Sha384,
            Self::Sha512(_) => HashAlg::Sha512,
        }
    }
}

/// Whether some epoch of `epochs` contains leaf `i`.
fn covers(epochs: &[(u64, u64)], i: u64) -> bool {
    epochs.iter().any(|&(a, e)| a <= i && i < e)
}

impl Rooted<Trusted, FullCr> {
    /// The holder's own whole Commit Root at its tip.
    #[must_use]
    pub fn of_principal<S: eml::Storage>(p: &Principal<S>) -> Option<Self> {
        let size = p.commit_count() as u64;
        let variants = p
            .cr()?
            .as_multihash()
            .variants()
            .iter()
            .map(|(&alg, d)| AnyFamilyRoot::new(alg, size, d))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        Some(Rooted(FullCr { size, variants }, PhantomData))
    }

    /// The holder's own whole Commit Root as it stood at `size`, read
    /// from the commit that made it (each commit keeps its own), so it
    /// costs O(1) whatever the log's store holds.
    pub async fn at_size<S: eml::Storage>(p: &Principal<S>, size: u64) -> Option<Self> {
        let commit = p.commit_at(usize::try_from(size.checked_sub(1)?).ok()?)?;
        let variants = commit
            .cr()
            .as_multihash()
            .variants()
            .iter()
            .map(|(&alg, d)| AnyFamilyRoot::new(alg, size, d))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        Some(Rooted(FullCr { size, variants }, PhantomData))
    }

    /// The member root of family `H`, `None` if `H` is not in this Commit
    /// Root.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn family_impl<H: HashFamily>(&self) -> Option<Rooted<Trusted, FamilyRoot<H>>> {
        self.0
            .variants
            .iter()
            .find_map(AnyFamilyRoot::to_family)
            .map(|r| Rooted(r, PhantomData))
    }

    /// Test support for [`Self::family_impl`].
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    #[must_use]
    pub fn family<H: HashFamily>(&self) -> Option<Rooted<Trusted, FamilyRoot<H>>> {
        self.family_impl()
    }
}

impl<H: HashFamily> Rooted<Claimed, FamilyRoot<H>> {
    /// Wrap a stated root as a claim.
    #[must_use]
    pub fn claim(root: FamilyRoot<H>) -> Self {
        Rooted(root, PhantomData)
    }
}

impl Rooted<Claimed, AnyFamilyRoot> {
    /// Wrap a peer's stated head, in the one family it states, as a claim.
    #[must_use]
    pub fn claim(root: AnyFamilyRoot) -> Self {
        Rooted(root, PhantomData)
    }
}

/// An EML path for leaf `index` in family `H`'s tree of `size` leaves.
#[derive(Clone, Debug)]
pub struct LogPath<H: HashFamily> {
    /// Leaf position.
    pub index: u64,
    /// Tree size the path is for.
    pub size: u64,
    /// The sibling steps.
    pub steps: Vec<eml::ProofStep>,
    /// Family marker.
    pub family: PhantomData<H>,
}

/// An EML consistency proof between two sizes of family `H`'s tree.
#[derive(Clone, Debug)]
pub struct Consistency<H: HashFamily> {
    /// The proof.
    pub proof: eml::ConsistencyProof,
    /// Family marker.
    pub family: PhantomData<H>,
}

/// One commit opened from its leaf down to `CR_{s-1}`: constant size per
/// stitch (a TR path, one coz, an arrow preimage, the variants of `pre`,
/// the Principal Tree cells).
#[derive(Clone, Debug)]
pub struct CommitOpening {
    /// The serialized TR map that is the commit's log leaf.
    pub tr_map: Vec<u8>,
    /// Path from `TR_s[F]` to the closing coz's czd.
    pub tr_path: Vec<eml::ProofStep>,
    /// The closing coz (the last coz of the commit, the one carrying the
    /// arrow), in the wire blob form `WireBundle::cozies` yields: names
    /// the arrow's algorithm.
    pub coz: Vec<u8>,
    /// The arrow's other components: the mutation root under the arrow's
    /// algorithm, then the forward State Root when the commit leaves one,
    /// as the conversion rule gives it (a single-variant root keeps its
    /// own family's width). `pre` is derived from [`Self::pre_variants`].
    pub arrow_preimage: Vec<u8>,
    /// The variants of `PR_{s-1}` the arrow's `pre` binds, per Cyphr's
    /// component conversion rule: just the signer family's when `PR` has it
    /// (case 1) and the one variant when `PR` has exactly one (case 2),
    /// every variant, supplied whole, when it has several and none is the
    /// arrow's (case 3, checked by recomputing the hash of their sorted
    /// concatenation). The verifier derives the case from the supplied
    /// variants; the prover does not choose it.
    pub pre_variants: Vec<(HashAlg, Vec<u8>)>,
    /// The Principal Tree's cells (SR, CR, nonce) as serialized.
    pub pt_cells: Vec<Vec<u8>>,
}

/// A stitch: leaf `s` in family `F`'s tree, and the commit's opening.
#[derive(Clone, Debug)]
pub struct Stitch<F: HashFamily> {
    /// Leaf `s` in `F`'s tree at the anchor's size.
    pub leaf: LogPath<F>,
    /// The commit opened down to `CR_{s-1}`.
    pub opening: CommitOpening,
}

/// A vector with at least one element: a stitch always lands in some
/// family.
#[derive(Debug)]
pub(crate) struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    fn new(items: Vec<T>) -> Option<Self> {
        (!items.is_empty()).then_some(Self(items))
    }
}

/// The `pre` component the arrow `g` binds, from the supplied variants of
/// `PR_{s-1}` (see [`CommitOpening::pre_variants`]).
fn pre_component(g: HashAlg, variants: &[(HashAlg, Vec<u8>)]) -> Result<Vec<u8>, ProofError> {
    for (i, (alg, bytes)) in variants.iter().enumerate() {
        if bytes.len() != TaggedDigest::expected_len(*alg)
            || variants[..i].iter().any(|(a, _)| a == alg)
        {
            return Err(ProofError::Arrow);
        }
    }
    if let Some((_, bytes)) = variants.iter().find(|(alg, _)| *alg == g) {
        // Case 1 binds this variant alone: any other supplied variant
        // would be read as authenticated without being bound.
        return if variants.len() == 1 {
            Ok(bytes.clone())
        } else {
            Err(ProofError::Arrow)
        };
    }
    match variants {
        [] => Err(ProofError::Arrow),
        [(_, bytes)] => Ok(bytes.clone()),
        _ => {
            let all: Vec<&[u8]> = variants.iter().map(|(_, b)| b.as_slice()).collect();
            Ok(hash_sorted_concat_bytes(g, &all))
        },
    }
}

impl<M: Trust, F: HashFamily> Rooted<M, FamilyRoot<F>> {
    /// Cross an epoch boundary: verify leaf `s` under this root, open its
    /// arrow, where `G` is the arrow's family read from the coz, and read
    /// what `pre` binds through the component conversion rule: one
    /// `PR_{s-1}` variant (cases 1 and 2) or all of them (case 3). Each
    /// opens through its own PT to `CR_{s-1}[X]` (`PR[X]` binds `CR[X]`
    /// alone), and the roots are returned at the same trust level.
    ///
    /// # Errors
    ///
    /// [`ProofError::Path`], [`ProofError::Arrow`], [`ProofError::PtCell`].
    pub(crate) fn stitch(
        &self,
        s: &Stitch<F>,
    ) -> Result<NonEmpty<Rooted<M, AnyFamilyRoot>>, ProofError> {
        let n = self.0.size;
        let (leaf, o) = (&s.leaf, &s.opening);
        if leaf.size != n {
            return Err(ProofError::Mismatch(format!(
                "stitch path is for size {}, the root has {n}",
                leaf.size
            )));
        }
        if leaf.index == 0 || leaf.index >= n {
            return Err(ProofError::Mismatch(format!(
                "no stitch at index {} of {n}",
                leaf.index
            )));
        }
        let hasher = MaltHasher::new(F::ALG);
        let leaf_digest = hasher.leaf(&o.tr_map);
        let path = eml::InclusionProof {
            path: leaf.steps.clone(),
        };
        if !crate::commit_root::verify_inclusion(
            &hasher,
            &leaf_digest,
            leaf.index,
            n,
            &path,
            self.0.digest.as_bytes(),
        ) {
            return Err(ProofError::Path);
        }

        let coz = StoredCoz::from_wire(&o.coz).map_err(|_| ProofError::Arrow)?;
        let arrow: TaggedDigest = coz
            .pay()
            .get("arrow")
            .and_then(serde_json::Value::as_str)
            .and_then(|a| a.parse().ok())
            .ok_or(ProofError::Arrow)?;
        let czd = TaggedCzd::new(coz.czd(), coz.hash_alg()).convert_to(F::ALG);
        let tr = match o.tr_path.as_slice() {
            [] => czd,
            [step]
                if step.position == step.siblings.len()
                    && !step.siblings.is_empty()
                    && step.siblings.iter().all(|x| x.len() == F::LEN) =>
            {
                let mut parts: Vec<&[u8]> = step.siblings.iter().map(Vec::as_slice).collect();
                parts.push(&czd);
                hash_concat_bytes(F::ALG, &parts)
            },
            _ => return Err(ProofError::Arrow),
        };
        if tr != leaf_digest {
            return Err(ProofError::Arrow);
        }

        let g = arrow.alg();
        let len = TaggedDigest::expected_len(g);
        // The mutation root is under `g`; the forward State Root may carry
        // only another family, which the conversion rule passes through at
        // its own width.
        let (tmr, fwd) = o
            .arrow_preimage
            .split_at_checked(len)
            .ok_or(ProofError::Arrow)?;
        if !(fwd.is_empty()
            || crate::state::HASH_ALGS
                .iter()
                .any(|&a| TaggedDigest::expected_len(a) == fwd.len()))
        {
            return Err(ProofError::Arrow);
        }
        let pre = pre_component(g, &o.pre_variants)?;
        let mut components: Vec<&[u8]> = vec![&pre, tmr];
        if !fwd.is_empty() {
            components.push(fwd);
        }
        if hash_sorted_concat_bytes(g, &components) != arrow.as_bytes() {
            return Err(ProofError::Arrow);
        }

        if o.pt_cells.len() < 2 {
            return Err(ProofError::PtCell);
        }
        for (x, bound) in &o.pre_variants {
            let folded = crate::principal_tree::fold_cells(*x, &o.pt_cells)
                .map_err(|_| ProofError::PtCell)?;
            if folded != *bound {
                return Err(ProofError::PtCell);
            }
        }
        let cr: BTreeMap<u64, Box<[u8]>> =
            serde_json::from_slice(&o.pt_cells[1]).map_err(|_| ProofError::PtCell)?;
        let mut roots = Vec::with_capacity(o.pre_variants.len());
        for (x, _) in &o.pre_variants {
            let digest = cr.get(&hash_alg_to_u64(*x)).ok_or(ProofError::PtCell)?;
            roots.push(Rooted(
                AnyFamilyRoot::new(*x, leaf.index, digest)?,
                PhantomData,
            ));
        }
        NonEmpty::new(roots).ok_or(ProofError::Arrow)
    }
}

/// What a membership proof established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The position proven.
    pub index: u64,
}

/// A value only verification makes.
#[derive(Debug)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// What was verified.
    #[must_use]
    pub fn get(&self) -> &T {
        &self.0
    }
}

/// Terminal step of a membership proof, internal to [`verify_membership`]:
/// `tr` is the leaf at `path.index` under `root`.
///
/// # Errors
///
/// [`ProofError::Mismatch`] if the path is for another size, or `tr` is
/// not the leaf the path proves at that index under the root.
pub(crate) fn verify_terminal<H: HashFamily>(
    root: &Rooted<Trusted, FamilyRoot<H>>,
    path: &LogPath<H>,
    tr: &TransactionRoot,
) -> Result<Verified<Membership>, ProofError> {
    if path.size != root.0.size {
        return Err(ProofError::Mismatch(format!(
            "path is for size {}, the root has {}",
            path.size, root.0.size
        )));
    }
    let leaf = tr.get(H::ALG).ok_or_else(|| {
        ProofError::Mismatch("the transaction root has no variant in the path's family".into())
    })?;
    let proof = eml::InclusionProof {
        path: path.steps.clone(),
    };
    if !crate::commit_root::verify_inclusion(
        &MaltHasher::new(H::ALG),
        leaf,
        path.index,
        path.size,
        &proof,
        root.0.digest.as_bytes(),
    ) {
        return Err(ProofError::Mismatch(format!(
            "the transaction root is not the leaf at index {}",
            path.index
        )));
    }
    Ok(Verified(Membership { index: path.index }))
}

/// The only `Claimed` -> `Trusted` path: `new` extends `old` by `c`.
///
/// # Errors
///
/// [`ProofError::NotAnExtension`].
pub(crate) fn upgrade<H: HashFamily>(
    old: &Rooted<Trusted, FamilyRoot<H>>,
    new: Rooted<Claimed, FamilyRoot<H>>,
    c: &Consistency<H>,
) -> Result<Rooted<Trusted, FamilyRoot<H>>, ProofError> {
    let (o, n) = (&old.0, &new.0);
    let holds = match o.size.cmp(&n.size) {
        std::cmp::Ordering::Greater => false,
        // Same size: the log is the same exactly when the roots are.
        std::cmp::Ordering::Equal => o.digest.as_bytes() == n.digest.as_bytes(),
        std::cmp::Ordering::Less => crate::commit_root::verify_consistency(
            &MaltHasher::new(H::ALG),
            o.size,
            n.size,
            &c.proof,
            o.digest.as_bytes(),
            n.digest.as_bytes(),
        ),
    };
    if holds {
        Ok(Rooted(
            FamilyRoot {
                size: n.size,
                digest: Digest::from_bytes(n.digest.as_bytes())?,
            },
            PhantomData,
        ))
    } else {
        Err(ProofError::NotAnExtension)
    }
}

/// A stitch of any family.
#[derive(Clone, Debug)]
pub enum AnyStitch {
    /// Leaf in a SHA-256 tree.
    Sha256(Stitch<Sha256>),
    /// Leaf in a SHA-384 tree.
    Sha384(Stitch<Sha384>),
    /// Leaf in a SHA-512 tree.
    Sha512(Stitch<Sha512>),
}

/// A path of any family.
#[derive(Clone, Debug)]
pub enum AnyPath {
    /// SHA-256.
    Sha256(LogPath<Sha256>),
    /// SHA-384.
    Sha384(LogPath<Sha384>),
    /// SHA-512.
    Sha512(LogPath<Sha512>),
}

/// A consistency proof of any family.
#[derive(Clone, Debug)]
pub enum AnyConsistency {
    /// SHA-256.
    Sha256(Consistency<Sha256>),
    /// SHA-384.
    Sha384(Consistency<Sha384>),
    /// SHA-512.
    Sha512(Consistency<Sha512>),
}

/// Tip-anchored proof that a commit is the log's leaf at `index`: one
/// stitch per epoch boundary crossed, then a terminal path.
#[derive(Clone, Debug)]
pub struct MembershipProof {
    /// The stitches, from the tip toward `index`.
    pub stitches: Vec<AnyStitch>,
    /// The terminal path to leaf `index`.
    pub terminal: AnyPath,
}

/// Tip-anchored proof that a claimed head extends an older trusted one:
/// stitches down to a family active at the old size, then a consistency
/// proof in that family.
#[derive(Clone, Debug)]
pub struct ExtensionProof {
    /// The stitches, from the claimed head toward the old size.
    pub stitches: Vec<AnyStitch>,
    /// The terminal consistency proof.
    pub terminal: AnyConsistency,
}

mod anchor {
    use super::AnyFamilyRoot;

    pub trait Sealed {
        /// The family roots the holder trusts.
        fn roots(&self) -> Vec<AnyFamilyRoot>;
    }
}

/// A trusted root a membership proof can start from: the holder's own
/// whole Commit Root, or a head upgraded by [`verify_extension`] in one
/// family. Sealed.
pub trait Anchor: anchor::Sealed {}
impl anchor::Sealed for Rooted<Trusted, FullCr> {
    fn roots(&self) -> Vec<AnyFamilyRoot> {
        self.0.variants.clone()
    }
}
impl anchor::Sealed for Rooted<Trusted, AnyFamilyRoot> {
    fn roots(&self) -> Vec<AnyFamilyRoot> {
        vec![self.0.clone()]
    }
}
impl Anchor for Rooted<Trusted, FullCr> {}
impl Anchor for Rooted<Trusted, AnyFamilyRoot> {}

/// The root of family `H` among `roots`.
fn pick<M: Trust, H: HashFamily>(
    roots: &[Rooted<M, AnyFamilyRoot>],
) -> Result<Rooted<M, FamilyRoot<H>>, ProofError> {
    roots
        .iter()
        .find_map(|r| r.0.to_family::<H>())
        .map(|r| Rooted(r, PhantomData))
        .ok_or(ProofError::Family)
}

/// Cross every stitch from `roots`, each in the family it names.
fn walk<M: Trust>(
    mut roots: Vec<Rooted<M, AnyFamilyRoot>>,
    stitches: &[AnyStitch],
) -> Result<Vec<Rooted<M, AnyFamilyRoot>>, ProofError> {
    for stitch in stitches {
        let next = match stitch {
            AnyStitch::Sha256(s) => pick::<M, Sha256>(&roots)?.stitch(s)?,
            AnyStitch::Sha384(s) => pick::<M, Sha384>(&roots)?.stitch(s)?,
            AnyStitch::Sha512(s) => pick::<M, Sha512>(&roots)?.stitch(s)?,
        };
        roots = next.0;
    }
    Ok(roots)
}

/// The one entry point for a membership proof: `proof` is plain data,
/// `anchor` a trusted root (any [`Anchor`]). The walk follows the
/// signer's family from the anchor's own, so one family suffices. Walks
/// every stitch from the anchor, then the terminal path, checking `tr` is
/// the leaf proven.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_membership(
    anchor: &impl Anchor,
    proof: &MembershipProof,
    tr: &TransactionRoot,
) -> Result<Verified<Membership>, ProofError> {
    let roots = anchor
        .roots()
        .into_iter()
        .map(|r| Rooted::<Trusted, _>(r, PhantomData))
        .collect();
    let roots = walk(roots, &proof.stitches)?;
    match &proof.terminal {
        AnyPath::Sha256(p) => verify_terminal(&pick::<Trusted, Sha256>(&roots)?, p, tr),
        AnyPath::Sha384(p) => verify_terminal(&pick::<Trusted, Sha384>(&roots)?, p, tr),
        AnyPath::Sha512(p) => verify_terminal(&pick::<Trusted, Sha512>(&roots)?, p, tr),
    }
}

/// The one entry point for an extension proof: upgrades `head`, a claim in
/// one family, to trusted in that family only, and only if it extends the
/// trusted `old`.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_extension(
    old: &Rooted<Trusted, FullCr>,
    head: Rooted<Claimed, AnyFamilyRoot>,
    proof: &ExtensionProof,
) -> Result<Rooted<Trusted, AnyFamilyRoot>, ProofError> {
    let claimed = head.0.clone();
    let roots = walk(vec![head], &proof.stitches)?;
    match &proof.terminal {
        AnyConsistency::Sha256(c) => {
            upgrade(&old_in::<Sha256>(old)?, pick::<Claimed, Sha256>(&roots)?, c)?;
        },
        AnyConsistency::Sha384(c) => {
            upgrade(&old_in::<Sha384>(old)?, pick::<Claimed, Sha384>(&roots)?, c)?;
        },
        AnyConsistency::Sha512(c) => {
            upgrade(&old_in::<Sha512>(old)?, pick::<Claimed, Sha512>(&roots)?, c)?;
        },
    }
    Ok(Rooted(claimed, PhantomData))
}

fn old_in<H: HashFamily>(
    old: &Rooted<Trusted, FullCr>,
) -> Result<Rooted<Trusted, FamilyRoot<H>>, ProofError> {
    old.family_impl().ok_or(ProofError::Family)
}

/// One hop of a prover's plan: the stitch at leaf `s` in `family`'s tree of
/// `size` leaves.
struct Hop {
    family: HashAlg,
    s: u64,
    size: u64,
}

impl<S: eml::Storage> Principal<S> {
    /// The epochs of `alg`: `[start, end)` leaf ranges, `end` open as
    /// `u64::MAX`.
    fn epochs_of(&self, alg: HashAlg) -> Vec<(u64, u64)> {
        let id = hash_alg_to_u64(alg);
        self.commit_trees()
            .epochs()
            .into_iter()
            .find_map(|(i, e)| (i == id).then_some(e))
            .unwrap_or_default()
    }

    /// The start of `alg`'s epoch containing leaf `i`.
    fn epoch_start(&self, alg: HashAlg, i: u64) -> Option<u64> {
        self.epochs_of(alg)
            .into_iter()
            .find_map(|(a, e)| (a <= i && i < e).then_some(a))
    }

    /// The family a proof starts in: the principal's own, the one a head
    /// is claimed in.
    fn proof_family(&self) -> Result<HashAlg, ProofError> {
        let last = (self.commit_count() as u64)
            .checked_sub(1)
            .ok_or_else(|| ProofError::Unprovable("the log is empty".into()))?;
        let own = self.hash_alg();
        if self.epoch_start(own, last).is_some() {
            return Ok(own);
        }
        self.commit_trees()
            .epochs()
            .into_iter()
            .filter_map(|(id, _)| u64_to_hash_alg(id).ok())
            .find(|&alg| self.epoch_start(alg, last).is_some())
            .ok_or_else(|| ProofError::Unprovable("no family is active at the tip".into()))
    }

    /// The families a stitch at commit `s` yields: what `pre` binds.
    fn yields(&self, s: u64) -> Result<Vec<HashAlg>, ProofError> {
        let unprovable = |what: &str| ProofError::Unprovable(format!("commit {s}: {what}"));
        let at = |i: u64| {
            usize::try_from(i)
                .ok()
                .and_then(|i| self.commit_at(i))
                .ok_or_else(|| unprovable("not held"))
        };
        let g = at(s)?
            .commit_tx()
            .0
            .last()
            .and_then(|z| z.arrow())
            .and_then(|a| a.algorithms().next())
            .ok_or_else(|| unprovable("no closing coz"))?;
        let pre = &at(s - 1)?.pr().0;
        Ok(if pre.contains(g) {
            vec![g]
        } else {
            pre.algorithms().collect()
        })
    }

    /// The hops from the tip, in `start`'s family, to a family that was
    /// active at leaf `p` (for a membership proof; `one_epoch` asks for one
    /// epoch from `p` through the end, for a consistency proof, which does
    /// not cross a gap); and that family and size.
    fn plan(
        &self,
        start: HashAlg,
        p: u64,
        one_epoch: bool,
    ) -> Result<(Vec<Hop>, HashAlg, u64), ProofError> {
        let mut hops = Vec::new();
        let (mut family, mut size) = (start, self.commit_count() as u64);
        loop {
            let a = self.epoch_start(family, size - 1).ok_or_else(|| {
                ProofError::Unprovable(format!("{family} is not active at leaf {}", size - 1))
            })?;
            let reaches = if one_epoch {
                a <= p
            } else {
                self.epoch_start(family, p).is_some()
            };
            if reaches {
                return Ok((hops, family, size));
            }
            // Stitch at the start of the family's epoch: the farthest back
            // it can go (the E5 walk rule), read from the epoch timeline
            // without looking at any commit but the one stitched. It lands
            // in what commit `a`'s arrow binds; take the family that
            // reaches back furthest.
            let s = a;
            let mut best: Option<(u64, HashAlg)> = None;
            for g in self.yields(s)? {
                let start = self.epoch_start(g, s - 1).ok_or_else(|| {
                    ProofError::Unprovable(format!("{g} is not active at leaf {}", s - 1))
                })?;
                if best.is_none_or(|(b, _)| start < b) {
                    best = Some((start, g));
                }
            }
            let (_, next) =
                best.ok_or_else(|| ProofError::Unprovable(format!("commit {s} binds no family")))?;
            hops.push(Hop { family, s, size });
            family = next;
            size = s;
        }
    }

    async fn stitch_for(&self, hop: &Hop) -> Result<AnyStitch, ProofError> {
        let opening = self.opening_at(hop.s, hop.family).await?;
        with_family!(hop.family, F => {
            let leaf = self.log_path_impl::<F>(hop.s, hop.size).await?;
            Ok(F::wrap_stitch(Stitch { leaf, opening }))
        })
    }

    /// Commit `s` opened for a stitch under `f`'s tree: its closing coz,
    /// the arrow's components, and the Principal Tree cells of `PR_{s-1}`.
    /// Each part is checked against what the verifier will check.
    async fn opening_at(&self, s: u64, f: HashAlg) -> Result<CommitOpening, ProofError> {
        let unprovable = |what: &str| ProofError::Unprovable(format!("commit {s}: {what}"));
        let idx = usize::try_from(s).map_err(|_| unprovable("index out of range"))?;
        let commit = self.commit_at(idx).ok_or_else(|| unprovable("not held"))?;
        let prev = idx
            .checked_sub(1)
            .and_then(|i| self.commit_at(i))
            .ok_or_else(|| unprovable("has no predecessor"))?;
        let tr_map = self
            .commit_trees()
            .get_leaf(s)
            .await
            .map_err(|e| ProofError::Storage(e.to_string()))?;

        let (commit_tx, mutations) = commit
            .transactions()
            .split_last()
            .ok_or_else(|| unprovable("no transactions"))?;
        let [closing] = commit_tx.0.as_slice() else {
            // Admission refuses every commit transaction of several cozies
            // (issue #217), so this is unreachable today; if admission
            // changes, the opening needs a step through that transaction.
            return Err(unprovable("its commit transaction has several cozies"));
        };
        let arrow = closing.arrow().ok_or_else(|| unprovable("no arrow"))?;
        let g = arrow
            .algorithms()
            .next()
            .ok_or_else(|| unprovable("empty arrow"))?;
        let coz =
            serde_json::to_vec(closing.raw()).map_err(|_| unprovable("unserializable coz"))?;

        let ids = |alg: HashAlg| -> Result<Vec<crate::MultihashDigest>, ProofError> {
            mutations
                .iter()
                .map(|t| t.id(&[alg]))
                .collect::<Option<_>>()
                .ok_or_else(|| unprovable("a transaction has no id"))
        };
        let siblings = ids(f)?
            .iter()
            .map(|d| d.get(f).map(<[u8]>::to_vec))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| unprovable("a transaction id lacks the family"))?;
        let tr_path = if siblings.is_empty() {
            Vec::new()
        } else {
            vec![eml::ProofStep {
                position: siblings.len(),
                siblings,
            }]
        };

        let pre_md = &prev.pr().0;
        let to_err = |e: crate::error::Error| unprovable(&e.to_string());
        let pre = pre_md.arrow_component_bytes(g).map_err(to_err)?;
        let tx_ids = ids(g)?;
        let refs: Vec<&crate::MultihashDigest> = tx_ids.iter().collect();
        let tmr = crate::transaction_root::compute_tmr(&refs, &[g])
            .ok_or_else(|| unprovable("no mutation root"))?;
        let tmr = tmr.0.arrow_component_bytes(g).map_err(to_err)?;
        let fwd = commit
            .sr()
            .map(|sr| sr.0.arrow_component_bytes(g))
            .transpose()
            .map_err(to_err)?;
        let mut components: Vec<&[u8]> = vec![&pre, &tmr];
        components.extend(fwd.as_deref());
        if arrow.get(g) != Some(hash_sorted_concat_bytes(g, &components).as_slice()) {
            return Err(unprovable("the arrow does not recompute"));
        }
        let arrow_preimage = components[1..].concat();

        let pre_variants: Vec<(HashAlg, Vec<u8>)> = match pre_md.get(g) {
            Some(b) => vec![(g, b.to_vec())],
            None => pre_md
                .variants()
                .iter()
                .map(|(&a, b)| (a, b.to_vec()))
                .collect(),
        };

        let sr = prev
            .sr()
            .ok_or_else(|| unprovable("no state root before"))?;
        let mut cells = vec![
            crate::principal_tree::PrincipalTree::serialize(&sr.0).map_err(to_err)?,
            crate::principal_tree::PrincipalTree::serialize(prev.cr().as_multihash())
                .map_err(to_err)?,
        ];
        cells.extend_from_slice(prev.nonce_cells());
        for (x, bound) in &pre_variants {
            let folded = crate::principal_tree::fold_cells(*x, &cells).map_err(to_err)?;
            if &folded != bound {
                return Err(unprovable("the principal tree cells do not fold to PR"));
            }
        }
        Ok(CommitOpening {
            tr_map,
            tr_path,
            coz,
            arrow_preimage,
            pre_variants,
            pt_cells: cells,
        })
    }

    /// EML path for leaf `index` in family `H`'s tree of `size`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`], [`ProofError::Storage`].
    #[allow(dead_code)]
    pub(crate) async fn log_path_impl<H: HashFamily>(
        &self,
        index: u64,
        size: u64,
    ) -> Result<LogPath<H>, ProofError> {
        // The tree needs a root at `size` (active at its last leaf) and the
        // leaf; a closed stretch between them is null leaves, which a path
        // carries.
        let epochs = self.epochs_of(H::ALG);
        let covered = index < size
            && size <= self.commit_count() as u64
            && covers(&epochs, index)
            && covers(&epochs, size - 1);
        if !covered {
            return Err(ProofError::Unprovable(format!(
                "{} has no tree holding leaf {index} at size {size}",
                H::ALG
            )));
        }
        let proof = self
            .commit_trees()
            .inclusion_proof_at(hash_alg_to_u64(H::ALG), index, size)
            .await
            .map_err(|e| ProofError::Storage(e.to_string()))?
            .ok_or_else(|| {
                ProofError::Unprovable(format!("no path for leaf {index} at size {size}"))
            })?;
        Ok(LogPath {
            index,
            size,
            steps: proof.path,
            family: PhantomData,
        })
    }

    /// Test support for the prover's `log_path_impl`.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn log_path<H: HashFamily>(
        &self,
        index: u64,
        size: u64,
    ) -> Result<LogPath<H>, ProofError> {
        self.log_path_impl::<H>(index, size).await
    }

    /// Consistency of family `H`'s tree from `from` to `to`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`], [`ProofError::Storage`].
    #[allow(dead_code)]
    pub(crate) async fn family_consistency_impl<H: HashFamily>(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Consistency<H>, ProofError> {
        let covered = 1 <= from
            && from <= to
            && to <= self.commit_count() as u64
            && self
                .epochs_of(H::ALG)
                .iter()
                .any(|&(a, e)| a < from && to <= e);
        if !covered {
            return Err(ProofError::Unprovable(format!(
                "{} has no one tree from size {from} to {to}",
                H::ALG
            )));
        }
        // Equal sizes are checked by comparing roots; there is no proof.
        let proof = if from == to {
            eml::ConsistencyProof {
                boundary_hash: Vec::new(),
                peak_path: Vec::new(),
                new_peaks: Vec::new(),
                split_index: 0,
            }
        } else {
            self.commit_trees()
                .consistency_proof_between(hash_alg_to_u64(H::ALG), from, to)
                .await
                .map_err(|e| ProofError::Storage(e.to_string()))?
                .ok_or_else(|| {
                    ProofError::Unprovable(format!("no consistency from {from} to {to}"))
                })?
        };
        Ok(Consistency {
            proof,
            family: PhantomData,
        })
    }

    /// Test support for the prover's `family_consistency_impl`.
    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn family_consistency<H: HashFamily>(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Consistency<H>, ProofError> {
        self.family_consistency_impl::<H>(from, to).await
    }

    /// The tip-anchored membership proof for the commit at `index`: no
    /// algorithm choice; every held commit is provable. It starts in the
    /// principal's own family, so any anchor holding that family can walk
    /// it.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for an index past the log;
    /// [`ProofError::Storage`] when the store fails.
    pub async fn prove_membership(&self, index: u64) -> Result<MembershipProof, ProofError> {
        if index >= self.commit_count() as u64 {
            return Err(ProofError::Unprovable(format!(
                "index {index} is past the {} commits held",
                self.commit_count()
            )));
        }
        let (hops, family, size) = self.plan(self.proof_family()?, index, false)?;
        let mut stitches = Vec::with_capacity(hops.len());
        for hop in &hops {
            stitches.push(self.stitch_for(hop).await?);
        }
        let terminal = with_family!(family, F => {
            F::wrap_path(self.log_path_impl::<F>(index, size).await?)
        });
        Ok(MembershipProof { stitches, terminal })
    }

    /// The extension proof from the log as of `from` commits to the
    /// current tip, in the principal's own family (the head's).
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for a `from` the log has not passed;
    /// [`ProofError::Storage`] when the store fails.
    pub async fn prove_extension(&self, from: u64) -> Result<ExtensionProof, ProofError> {
        if from == 0 || from > self.commit_count() as u64 {
            return Err(ProofError::Unprovable(format!(
                "{from} is not a size of the {}-commit log",
                self.commit_count()
            )));
        }
        let (hops, family, size) = self.plan(self.proof_family()?, from - 1, true)?;
        let mut stitches = Vec::with_capacity(hops.len());
        for hop in &hops {
            stitches.push(self.stitch_for(hop).await?);
        }
        let terminal = with_family!(family, F => {
            F::wrap_consistency(self.family_consistency_impl::<F>(from, size).await?)
        });
        Ok(ExtensionProof { stitches, terminal })
    }

    /// The principal's head in the family its proofs start in: what a peer
    /// claims for an [`ExtensionProof`] to be checked against.
    #[must_use]
    pub fn head_root(&self) -> Option<AnyFamilyRoot> {
        Rooted::<Trusted, FullCr>::of_principal(self)?
            .0
            .variants
            .into_iter()
            .find(|v| v.alg() == self.hash_alg())
    }
}

// ---- wire form ----
//
// JSON, every byte string base64url without padding, every family named by
// its Coz name (`SHA-256`). The `Any*` enums carry the family in an `alg`
// field; parsing refuses a family the core does not know.

use coz::base64ct::{Base64UrlUnpadded, Encoding};

#[derive(Serialize, Deserialize)]
struct WireStep {
    position: usize,
    siblings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct WirePath {
    index: u64,
    size: u64,
    steps: Vec<WireStep>,
}

#[derive(Serialize, Deserialize)]
struct WireOpening {
    tr_map: String,
    tr_path: Vec<WireStep>,
    coz: String,
    arrow_preimage: String,
    pre_variants: Vec<(String, String)>,
    pt_cells: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct WireStitch {
    alg: String,
    leaf: WirePath,
    opening: WireOpening,
}

#[derive(Serialize, Deserialize)]
struct WireTerminalPath {
    alg: String,
    #[serde(flatten)]
    path: WirePath,
}

#[derive(Serialize, Deserialize)]
struct WireTerminalConsistency {
    alg: String,
    boundary_hash: String,
    peak_path: Vec<WireStep>,
    new_peaks: Vec<String>,
    split_index: usize,
}

#[derive(Serialize, Deserialize)]
struct WireMembership {
    stitches: Vec<WireStitch>,
    terminal: WireTerminalPath,
}

#[derive(Serialize, Deserialize)]
struct WireExtension {
    stitches: Vec<WireStitch>,
    terminal: WireTerminalConsistency,
}

fn enc(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

/// Most levels a path climbs, peaks a frontier holds, stitches a proof
/// crosses, and the like: what a log of `u64` size can need, so a payload
/// past them is refused at the parse, before any hashing.
const MAX_STEPS: usize = 64;
const MAX_SIBLINGS: usize = 256;
const MAX_PEAKS: usize = 64;
const MAX_STITCHES: usize = 64;
const MAX_CELLS: usize = 258;
const MAX_PRE: usize = 3;

fn bounded<T>(items: &[T], max: usize, what: &str) -> Result<(), ProofError> {
    if items.len() > max {
        return Err(ProofError::Mismatch(format!("too many {what}")));
    }
    Ok(())
}

fn dec(s: &str) -> Result<Vec<u8>, ProofError> {
    Base64UrlUnpadded::decode_vec(s)
        .map_err(|_| ProofError::Mismatch("a byte string is not base64url".into()))
}

fn wire_steps(steps: &[eml::ProofStep]) -> Vec<WireStep> {
    steps
        .iter()
        .map(|s| WireStep {
            position: s.position,
            siblings: s.siblings.iter().map(|x| enc(x)).collect(),
        })
        .collect()
}

/// The steps of a path under a family of digest width `width`.
fn steps_of(wire: &[WireStep], width: usize) -> Result<Vec<eml::ProofStep>, ProofError> {
    bounded(wire, MAX_STEPS, "path steps")?;
    wire.iter()
        .map(|s| {
            bounded(&s.siblings, MAX_SIBLINGS, "siblings")?;
            Ok(eml::ProofStep {
                position: s.position,
                siblings: s
                    .siblings
                    .iter()
                    .map(|x| hash_of(x, width))
                    .collect::<Result<_, _>>()?,
            })
        })
        .collect()
}

/// A digest of exactly `width` bytes.
fn hash_of(s: &str, width: usize) -> Result<Vec<u8>, ProofError> {
    let bytes = dec(s)?;
    if bytes.len() != width {
        return Err(ProofError::Width {
            want: width,
            got: bytes.len(),
        });
    }
    Ok(bytes)
}

fn wire_path<H: HashFamily>(p: &LogPath<H>) -> WirePath {
    WirePath {
        index: p.index,
        size: p.size,
        steps: wire_steps(&p.steps),
    }
}

fn path_of<H: HashFamily>(w: &WirePath) -> Result<LogPath<H>, ProofError> {
    Ok(LogPath {
        index: w.index,
        size: w.size,
        steps: steps_of(&w.steps, H::LEN)?,
        family: PhantomData,
    })
}

fn wire_stitch<H: HashFamily>(s: &Stitch<H>) -> WireStitch {
    let o = &s.opening;
    WireStitch {
        alg: H::ALG.to_string(),
        leaf: wire_path(&s.leaf),
        opening: WireOpening {
            tr_map: enc(&o.tr_map),
            tr_path: wire_steps(&o.tr_path),
            coz: enc(&o.coz),
            arrow_preimage: enc(&o.arrow_preimage),
            pre_variants: o
                .pre_variants
                .iter()
                .map(|(a, b)| (a.to_string(), enc(b)))
                .collect(),
            pt_cells: o.pt_cells.iter().map(|c| enc(c)).collect(),
        },
    }
}

fn alg_of(name: &str) -> Result<HashAlg, ProofError> {
    crate::state::hash_alg_named(name)
        .map_err(|_| ProofError::Mismatch(format!("unknown hash family {name:?}")))
}

fn stitch_of<H: HashFamily>(w: &WireStitch) -> Result<Stitch<H>, ProofError> {
    let o = &w.opening;
    bounded(&o.pre_variants, MAX_PRE, "pre variants")?;
    bounded(&o.pt_cells, MAX_CELLS, "principal tree cells")?;
    Ok(Stitch {
        leaf: path_of(&w.leaf)?,
        opening: CommitOpening {
            tr_map: dec(&o.tr_map)?,
            tr_path: steps_of(&o.tr_path, H::LEN)?,
            coz: dec(&o.coz)?,
            arrow_preimage: dec(&o.arrow_preimage)?,
            pre_variants: o
                .pre_variants
                .iter()
                .map(|(a, b)| Ok((alg_of(a)?, dec(b)?)))
                .collect::<Result<_, ProofError>>()?,
            pt_cells: o
                .pt_cells
                .iter()
                .map(|c| dec(c))
                .collect::<Result<_, _>>()?,
        },
    })
}

fn wire_any_stitch(s: &AnyStitch) -> WireStitch {
    match s {
        AnyStitch::Sha256(s) => wire_stitch(s),
        AnyStitch::Sha384(s) => wire_stitch(s),
        AnyStitch::Sha512(s) => wire_stitch(s),
    }
}

fn any_stitch_of(w: &WireStitch) -> Result<AnyStitch, ProofError> {
    Ok(match alg_of(&w.alg)? {
        HashAlg::Sha256 => AnyStitch::Sha256(stitch_of(w)?),
        HashAlg::Sha384 => AnyStitch::Sha384(stitch_of(w)?),
        HashAlg::Sha512 => AnyStitch::Sha512(stitch_of(w)?),
    })
}

impl MembershipProof {
    fn to_wire(&self) -> WireMembership {
        let (alg, path) = match &self.terminal {
            AnyPath::Sha256(p) => (Sha256::ALG, wire_path(p)),
            AnyPath::Sha384(p) => (Sha384::ALG, wire_path(p)),
            AnyPath::Sha512(p) => (Sha512::ALG, wire_path(p)),
        };
        WireMembership {
            stitches: self.stitches.iter().map(wire_any_stitch).collect(),
            terminal: WireTerminalPath {
                alg: alg.to_string(),
                path,
            },
        }
    }

    /// Bytes on the wire of the proof, for cost comparison.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        // A struct of strings and integers always serializes; zero would
        // only ever mean the impossible failure.
        serde_json::to_vec(&self.to_wire()).map_or(0, |v| v.len())
    }

    /// Parse the `/inclusion` payload.
    ///
    /// # Errors
    ///
    /// [`ProofError::Mismatch`] for a payload that is not the wire shape.
    pub fn from_payload(payload: &serde_json::Value) -> Result<Self, ProofError> {
        let w: WireMembership = serde_json::from_value(payload.clone())
            .map_err(|e| ProofError::Mismatch(format!("not a membership proof: {e}")))?;
        bounded(&w.stitches, MAX_STITCHES, "stitches")?;
        let terminal = match alg_of(&w.terminal.alg)? {
            HashAlg::Sha256 => AnyPath::Sha256(path_of(&w.terminal.path)?),
            HashAlg::Sha384 => AnyPath::Sha384(path_of(&w.terminal.path)?),
            HashAlg::Sha512 => AnyPath::Sha512(path_of(&w.terminal.path)?),
        };
        Ok(Self {
            stitches: w
                .stitches
                .iter()
                .map(any_stitch_of)
                .collect::<Result<_, _>>()?,
            terminal,
        })
    }
}

impl Serialize for MembershipProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire().serialize(serializer)
    }
}

fn wire_consistency<H: HashFamily>(c: &Consistency<H>) -> WireTerminalConsistency {
    WireTerminalConsistency {
        alg: H::ALG.to_string(),
        boundary_hash: enc(&c.proof.boundary_hash),
        peak_path: wire_steps(&c.proof.peak_path),
        new_peaks: c.proof.new_peaks.iter().map(|p| enc(p)).collect(),
        split_index: c.proof.split_index,
    }
}

fn consistency_of<H: HashFamily>(
    w: &WireTerminalConsistency,
) -> Result<Consistency<H>, ProofError> {
    bounded(&w.new_peaks, MAX_PEAKS, "peaks")?;
    // The split names one of the peaks, except in the proofless same-size
    // case, which has none.
    let proofless = w.new_peaks.is_empty() && w.split_index == 0;
    if w.split_index >= w.new_peaks.len() && !proofless {
        return Err(ProofError::Mismatch("split outside the peaks".into()));
    }
    Ok(Consistency {
        proof: eml::ConsistencyProof {
            boundary_hash: if proofless && w.boundary_hash.is_empty() {
                Vec::new()
            } else {
                hash_of(&w.boundary_hash, H::LEN)?
            },
            peak_path: steps_of(&w.peak_path, H::LEN)?,
            new_peaks: w
                .new_peaks
                .iter()
                .map(|p| hash_of(p, H::LEN))
                .collect::<Result<_, _>>()?,
            split_index: w.split_index,
        },
        family: PhantomData,
    })
}

impl ExtensionProof {
    fn to_wire(&self) -> WireExtension {
        WireExtension {
            stitches: self.stitches.iter().map(wire_any_stitch).collect(),
            terminal: match &self.terminal {
                AnyConsistency::Sha256(c) => wire_consistency(c),
                AnyConsistency::Sha384(c) => wire_consistency(c),
                AnyConsistency::Sha512(c) => wire_consistency(c),
            },
        }
    }

    /// Bytes on the wire of the proof, for cost comparison.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        // See `MembershipProof::encoded_len`.
        serde_json::to_vec(&self.to_wire()).map_or(0, |v| v.len())
    }

    /// Parse the `/consistency` payload.
    ///
    /// # Errors
    ///
    /// [`ProofError::Mismatch`] for a payload that is not the wire shape.
    pub fn from_payload(payload: &serde_json::Value) -> Result<Self, ProofError> {
        let w: WireExtension = serde_json::from_value(payload.clone())
            .map_err(|e| ProofError::Mismatch(format!("not an extension proof: {e}")))?;
        bounded(&w.stitches, MAX_STITCHES, "stitches")?;
        let terminal = match alg_of(&w.terminal.alg)? {
            HashAlg::Sha256 => AnyConsistency::Sha256(consistency_of(&w.terminal)?),
            HashAlg::Sha384 => AnyConsistency::Sha384(consistency_of(&w.terminal)?),
            HashAlg::Sha512 => AnyConsistency::Sha512(consistency_of(&w.terminal)?),
        };
        Ok(Self {
            stitches: w
                .stitches
                .iter()
                .map(any_stitch_of)
                .collect::<Result<_, _>>()?,
            terminal,
        })
    }
}

impl Serialize for ExtensionProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_wire().serialize(serializer)
    }
}
