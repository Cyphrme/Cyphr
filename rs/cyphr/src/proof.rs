//! Tip-anchored membership and extension proofs across hash-algorithm
//! epochs (the "stitch").
//!
//! **THIS MODULE IS A STUB.** It declares the types and signatures the
//! acceptance tests (`tests/stitch.rs`) are written against; every
//! function body is `unimplemented!()`. The implementation walk replaces
//! the bodies and may reshape private fields, but not the public
//! signatures the tests use without flagging it.
//!
//! Within one hash family's epoch a proof is an ordinary EML inclusion or
//! consistency proof. At an epoch boundary a [`Stitch`] opens one commit's
//! leaf through its TR path, the closing coz and the arrow preimage to
//! `PR_{s-1}`, then through the Principal Tree cells to the full
//! `CR_{s-1}`, which carries a root for every family active at `s-1`.

use std::marker::PhantomData;

use crate::{HashAlg, Principal, TransactionRoot};

mod sealed {
    pub trait Sealed {}
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
    /// STUB. A digest from bytes, [`ProofError::Width`] if not `H::LEN`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Width`].
    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, ProofError> {
        unimplemented!("stub: Digest::from_bytes")
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
/// `Trusted` constructors read the holder's own state; [`upgrade`] is the
/// only `Claimed` -> `Trusted` path.
///
/// Control: the typed flow compiles, and builds a digest first (red until
/// [`Digest::from_bytes`] exists).
///
/// ```
/// use cyphr::proof::*;
/// let d = Digest::<Sha512>::from_bytes(&[0; 64]).unwrap();
/// let new = Rooted::<Claimed, FamilyRoot<Sha512>>::claim(FamilyRoot { size: 2, digest: d });
/// fn extend(
///     old: &Rooted<Trusted, FamilyRoot<Sha512>>,
///     new: Rooted<Claimed, FamilyRoot<Sha512>>,
///     c: &Consistency<Sha512>,
/// ) -> Rooted<Trusted, FamilyRoot<Sha512>> {
///     upgrade(old, new, c).unwrap()
/// }
/// # let _ = (new, extend);
/// ```
///
/// A claim is not a trusted root without `upgrade`:
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
/// A stitch of one family does not open a root of another:
///
/// ```compile_fail,E0308
/// use cyphr::proof::*;
/// fn mix(r: &Rooted<Trusted, FamilyRoot<Sha512>>, s: &Stitch<Sha256>) {
///     let _ = r.stitch(s);
/// }
/// ```
#[derive(Debug)]
pub struct Rooted<M: Trust, T>(T, PhantomData<M>);

impl<M: Trust, T> Rooted<M, T> {
    /// STUB. The root inside.
    #[must_use]
    pub fn get(&self) -> &T {
        unimplemented!("stub: Rooted::get")
    }
}

impl Rooted<Trusted, FullCr> {
    /// STUB. The holder's own whole Commit Root at its tip.
    #[must_use]
    pub fn of_principal<S: eml::Storage>(_p: &Principal<S>) -> Option<Self> {
        unimplemented!("stub: Rooted::<Trusted, FullCr>::of_principal")
    }

    /// STUB. The holder's own whole Commit Root as it stood at `size`.
    pub async fn at_size<S: eml::Storage>(_p: &Principal<S>, _size: u64) -> Option<Self> {
        unimplemented!("stub: Rooted::<Trusted, FullCr>::at_size")
    }
}

impl<H: HashFamily> Rooted<Claimed, FamilyRoot<H>> {
    /// STUB. Wrap a stated root as a claim.
    #[must_use]
    pub fn claim(_root: FamilyRoot<H>) -> Self {
        unimplemented!("stub: Rooted::<Claimed, FamilyRoot>::claim")
    }
}

impl Rooted<Claimed, FullCr> {
    /// STUB. Wrap a stated whole Commit Root as a claim.
    #[must_use]
    pub fn claim(_cr: FullCr) -> Self {
        unimplemented!("stub: Rooted::<Claimed, FullCr>::claim")
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
/// stitch (a TR path, one coz, an arrow preimage, three PT cells).
#[derive(Clone, Debug)]
pub struct CommitOpening {
    /// The serialized TR map that is the commit's log leaf.
    pub tr_map: Vec<u8>,
    /// Path from `TR_s[F]` to the closing coz's czd.
    pub tr_path: Vec<eml::ProofStep>,
    /// The closing coz (pay and sig): names the arrow's algorithm.
    pub coz: Vec<u8>,
    /// The arrow preimage: `pre`, `fwd`, TMR under the coz's algorithm.
    pub arrow_preimage: Vec<u8>,
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

impl<M: Trust, F: HashFamily> Rooted<M, FamilyRoot<F>> {
    /// STUB. Cross an epoch boundary: verify leaf `s` under this root,
    /// open it to `CR_{s-1}`, return that whole Commit Root at the same
    /// trust level. The arrow's family is read from the coz.
    ///
    /// # Errors
    ///
    /// [`ProofError::Path`], [`ProofError::Arrow`], [`ProofError::PtCell`].
    pub fn stitch(&self, _s: &Stitch<F>) -> Result<Rooted<M, FullCr>, ProofError> {
        unimplemented!("stub: Rooted::stitch")
    }
}

impl<M: Trust> Rooted<M, FullCr> {
    /// STUB. The member root of family `H`, `None` if `H` is not in this
    /// Commit Root.
    #[must_use]
    pub fn family<H: HashFamily>(&self) -> Option<Rooted<M, FamilyRoot<H>>> {
        unimplemented!("stub: Rooted::family")
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

/// STUB. Terminal step of a membership proof, internal to
/// [`verify_membership`]: `tr` is the leaf at `path.index` under `root`.
///
/// # Errors
///
/// [`ProofError::Path`] if the leaf does not reach the root;
/// [`ProofError::Mismatch`] if `tr` is not the leaf's content.
pub fn verify_terminal<H: HashFamily>(
    _root: &Rooted<Trusted, FamilyRoot<H>>,
    _path: &LogPath<H>,
    _tr: &TransactionRoot,
) -> Result<Verified<Membership>, ProofError> {
    unimplemented!("stub: verify_terminal")
}

/// STUB. The only `Claimed` -> `Trusted` path: `new` extends `old` by `c`.
///
/// # Errors
///
/// [`ProofError::NotAnExtension`].
pub fn upgrade<H: HashFamily>(
    _old: &Rooted<Trusted, FamilyRoot<H>>,
    _new: Rooted<Claimed, FamilyRoot<H>>,
    _c: &Consistency<H>,
) -> Result<Rooted<Trusted, FamilyRoot<H>>, ProofError> {
    unimplemented!("stub: upgrade")
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

impl MembershipProof {
    /// STUB. Bytes on the wire of the proof, for cost comparison.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        unimplemented!("stub: MembershipProof::encoded_len")
    }

    /// STUB. Parse the `/inclusion` payload.
    ///
    /// # Errors
    ///
    /// [`ProofError::Mismatch`] for a payload that is not the wire shape.
    pub fn from_payload(_payload: &serde_json::Value) -> Result<Self, ProofError> {
        unimplemented!("stub: MembershipProof::from_payload")
    }
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

impl ExtensionProof {
    /// STUB. Bytes on the wire of the proof, for cost comparison.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        unimplemented!("stub: ExtensionProof::encoded_len")
    }
}

/// STUB. The one entry point for a membership proof: `proof` is plain
/// data, `anchor` the holder's trusted tip. Walks every stitch from the
/// tip, then the terminal path, checking `tr` is the leaf proven.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_membership(
    _anchor: &Rooted<Trusted, FullCr>,
    _proof: &MembershipProof,
    _tr: &TransactionRoot,
) -> Result<Verified<Membership>, ProofError> {
    unimplemented!("stub: verify_membership")
}

/// STUB. The one entry point for an extension proof: upgrades `head` to
/// trusted only if it extends the trusted `old`.
///
/// # Errors
///
/// The [`ProofError`] of the first failing step.
pub fn verify_extension(
    _old: &Rooted<Trusted, FullCr>,
    _head: Rooted<Claimed, FullCr>,
    _proof: &ExtensionProof,
) -> Result<Rooted<Trusted, FullCr>, ProofError> {
    unimplemented!("stub: verify_extension")
}

impl<S: eml::Storage> Principal<S> {
    /// STUB. EML path for leaf `index` in family `H`'s tree of `size`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`].
    pub async fn log_path<H: HashFamily>(
        &self,
        _index: u64,
        _size: u64,
    ) -> Result<LogPath<H>, ProofError> {
        unimplemented!("stub: Principal::log_path")
    }

    /// STUB. Consistency of family `H`'s tree from `from` to `to`.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`].
    pub async fn family_consistency<H: HashFamily>(
        &self,
        _from: u64,
        _to: u64,
    ) -> Result<Consistency<H>, ProofError> {
        unimplemented!("stub: Principal::family_consistency")
    }

    /// STUB. The tip-anchored membership proof for the commit at `index`:
    /// no algorithm choice; every held commit is provable.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for an index past the log.
    pub async fn prove_membership(&self, _index: u64) -> Result<MembershipProof, ProofError> {
        unimplemented!("stub: Principal::prove_membership")
    }

    /// STUB. The extension proof from the log as of `from` commits to the
    /// current tip.
    ///
    /// # Errors
    ///
    /// [`ProofError::Unprovable`] for a `from` the log has not passed.
    pub async fn prove_extension(&self, _from: u64) -> Result<ExtensionProof, ProofError> {
        unimplemented!("stub: Principal::prove_extension")
    }
}
