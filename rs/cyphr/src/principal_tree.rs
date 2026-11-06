//! Principal Tree (PT): the `polydigest::EpochTree` backing the Principal Root.
//!
//! Cell 0 = State Root (SR), cell 1 = Commit Root (CR). The Principal Root
//! (PR) is a per-algorithm [`MultihashDigest`] whose variants are
//! `EpochTree::root(alg_id)` — the tree's native per-algorithm member root —
//! **never** `combined_root()`, which folds every registered algorithm's
//! member root together and would violate per-algorithm isolation.
//!
//! At genesis (cell 1 absent), the tree holds a single leaf, so `root(alg_id)`
//! is that leaf's digest verbatim (the spine's structural singleton
//! promotion — see `cmt::shape::build`). Because [`MaltHasher`]'s `leaf()` is
//! an identity extraction (raw bytes, unhashed), this makes PR byte-identical
//! to SR at genesis with no special-case branching anywhere in this module.

use std::collections::BTreeMap;

use crate::commit_root::{CommitRoot, MaltHasher, hash_alg_to_u64};
use crate::error::{Error, Result};
use crate::multihash::MultihashDigest;
use crate::state::{HashAlg, PrincipalRoot, StateDigest, StateRoot};

/// The proof-spine arity while only SR and CR sit in the tree.
const ARITY: u64 = 2;

/// The arity once PR-level nonces follow SR and CR: one flat fold of up to
/// 256 children, which for the two defined cells is the same bytes as
/// [`ARITY`] (SPEC §3.7.1).
const NONCE_ARITY: u64 = 256;

/// Cell index of the State Root.
const SR_CELL: u64 = 0;

/// Cell index of the Commit Root.
const CR_CELL: u64 = 1;

/// Construct a fresh, empty `EpochTree` at the fixed arity-2 spine shape
/// every `PrincipalTree` (and its clones) uses.
fn new_inner(arity: u64) -> polydigest::EpochTree {
    polydigest::EpochTree::new(polydigest::CmtConfig { arity })
        .expect("arity is a fixed constant within the spine's 2..=256 range")
}

/// The Principal Tree: an `EpochTree` with cell 0 = SR, cell 1 = CR, then
/// any PR-level nonces in ascending byte order. With no nonce it is k=2.
///
/// `inner` is derived: every setter rewrites the held cell contents and
/// rebuilds it, because a nonce's cell index depends on whether CR is set.
#[derive(Debug)]
pub struct PrincipalTree {
    inner: polydigest::EpochTree,
    /// Algorithms currently registered in `inner`, in registration order.
    algs: Vec<HashAlg>,
    /// Cell 0 payload.
    sr: Option<Vec<u8>>,
    /// Cell 1 payload.
    cr: Option<Vec<u8>>,
    /// PR-level nonces, raw and sorted; payloads depend on `algs`.
    nonces: Vec<Vec<u8>>,
}

impl PrincipalTree {
    /// Create an empty principal tree with no algorithms registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: new_inner(ARITY),
            algs: Vec::new(),
            sr: None,
            cr: None,
            nonces: Vec::new(),
        }
    }

    /// Register `alg` if it is not already registered.
    fn ensure_algorithm(&mut self, alg: HashAlg) {
        if !self.algs.contains(&alg) {
            self.algs.push(alg);
        }
    }

    /// Rebuild `inner` from the held cells: SR, CR if set, then the nonces,
    /// registering every algorithm in `algs`.
    ///
    /// # Error mapping
    ///
    /// Like `crate::semantic_tree`'s `register_algs`, this wraps
    /// `EpochTree`/`Cmt` — pure in-memory, no `Storage`-generic backend.
    /// The mapped failure (`DuplicateAlgorithm`, `IndexGap`) is a
    /// dense-tree invariant violation, not I/O; `Error::Storage` is still
    /// the best-available existing variant for it, distinct from
    /// `crate::principal`'s `CommitTrees`-backed sites, which are genuine
    /// `eml::Storage` backend failures.
    fn rebuild(&mut self) -> Result<()> {
        let arity = if self.nonces.is_empty() {
            ARITY
        } else {
            NONCE_ARITY
        };
        self.inner = self.build_inner(arity)?;
        Ok(())
    }

    /// The held cells folded at `arity`. Separate from [`Self::rebuild`] so
    /// a test can fold the same cells at both arities.
    fn build_inner(&self, arity: u64) -> Result<polydigest::EpochTree> {
        let mut inner = new_inner(arity);
        for &alg in &self.algs {
            inner
                .register_algorithm(hash_alg_to_u64(alg), Box::new(MaltHasher::new(alg)))
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        let mut payloads: Vec<Vec<u8>> = self.sr.iter().chain(&self.cr).cloned().collect();
        for nonce in &self.nonces {
            payloads.push(crate::semantic_tree::serialize_converted(
                nonce, &self.algs,
            )?);
        }
        for (index, payload) in payloads.into_iter().enumerate() {
            inner
                .set(index as u64, payload, Vec::new())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(inner)
    }

    /// Serialize a multihash's variants into the shared cell-payload idiom
    /// (a `BTreeMap<alg_id, digest>` JSON blob), the same idiom the Commit
    /// Tree's leaves already use — each algorithm's hasher extracts its own
    /// variant at leaf time.
    fn serialize(md: &MultihashDigest) -> Result<Vec<u8>> {
        let mut mapped = BTreeMap::new();
        for (&alg, digest) in md.variants() {
            mapped.insert(hash_alg_to_u64(alg), digest.clone());
        }
        serde_json::to_vec(&mapped).map_err(|_| Error::MalformedPayload)
    }

    /// Write the State Root into cell 0, registering any newly active
    /// algorithms first. Does not touch cell 1 (CR).
    pub fn set_sr(&mut self, sr: &StateRoot, algs: &[HashAlg]) -> Result<()> {
        for &alg in algs {
            self.ensure_algorithm(alg);
        }
        self.sr = Some(Self::serialize(sr.as_multihash())?);
        self.rebuild()
    }

    /// Remove the State Root: a principal with no keys and no data has none
    /// (SPEC 3.7: an empty component is omitted), and the tree, being
    /// dense, then promotes the Commit Root to cell 0 and PR is CR.
    pub fn clear_sr(&mut self, algs: &[HashAlg]) -> Result<()> {
        for &alg in algs {
            self.ensure_algorithm(alg);
        }
        self.sr = None;
        self.rebuild()
    }

    /// Write the Commit Root, registering any newly active algorithms
    /// first. It is cell 1 after an SR, or cell 0 when SR is absent.
    pub fn set_cr(&mut self, cr: &CommitRoot, algs: &[HashAlg]) -> Result<()> {
        for &alg in algs {
            self.ensure_algorithm(alg);
        }
        self.cr = Some(Self::serialize(cr.as_multihash())?);
        self.rebuild()
    }

    /// Replace the PR-level nonces, registering any newly active
    /// algorithms first. They sit after SR and CR (SPEC §3.7.1), so a
    /// nonce moves from cell 1 to cell 2 when CR first appears.
    pub(crate) fn set_nonces(&mut self, nonces: &[&[u8]], algs: &[HashAlg]) -> Result<()> {
        for &alg in algs {
            self.ensure_algorithm(alg);
        }
        let mut sorted: Vec<Vec<u8>> = nonces.iter().map(|n| n.to_vec()).collect();
        sorted.sort();
        self.nonces = sorted;
        self.rebuild()
    }

    /// Generate a self-contained inclusion proof for the Commit Root, cell 1,
    /// under `alg_id` — the hop-2 witness of the two-step transaction
    /// inclusion verification (see
    /// [`Principal::verify_transaction_inclusion`](crate::principal::Principal::verify_transaction_inclusion)):
    /// "CR is included in PR."
    ///
    /// Returns `None` if `alg_id` is unregistered or cell 1 has not yet been
    /// set (no commits exist yet — a genesis principal has no CR to prove).
    #[must_use]
    pub fn cr_inclusion_proof(&self, alg_id: u64) -> Option<polydigest::LeafProof> {
        // Without CR, cell 1 may hold a nonce: it must not be proven as CR.
        self.cr.as_ref()?;
        let cell = if self.sr.is_some() { CR_CELL } else { SR_CELL };
        self.inner.leaf_proof(alg_id, cell)
    }

    /// Generate a self-contained inclusion proof for the State Root, cell 0,
    /// under `alg_id` — the final hop of the key-membership chain (see
    /// [`Principal::verify_key_inclusion`](crate::principal::Principal::verify_key_inclusion)):
    /// "SR is included in PR." The cell-0 sibling of
    /// [`Self::cr_inclusion_proof`]; together the two cover every cell PT
    /// has, still not a general "prove any cell" facility beyond those two.
    ///
    /// Returns `None` if `alg_id` is unregistered or cell 0 has not yet been
    /// set (no SR exists yet).
    #[must_use]
    pub fn sr_inclusion_proof(&self, alg_id: u64) -> Option<polydigest::LeafProof> {
        self.sr.as_ref()?;
        self.inner.leaf_proof(alg_id, SR_CELL)
    }

    /// Assemble the Principal Root from the tree's current per-algorithm
    /// member roots: `PR.variants[alg] = EpochTree::root(alg_id)`.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if `algs` is empty or the tree has no root
    /// yet for one of the requested algorithms (cell 0 not yet set).
    pub fn pr(&self, algs: &[HashAlg]) -> Result<PrincipalRoot> {
        let mut variants = BTreeMap::new();
        for &alg in algs {
            let alg_id = hash_alg_to_u64(alg);
            let root = self.inner.root(alg_id).ok_or(Error::EmptyMultihash)?;
            variants.insert(alg, root.into_boxed_slice());
        }
        Ok(PrincipalRoot(MultihashDigest::new(variants)?))
    }
}

impl Default for PrincipalTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Deep clone: reconstructs a fresh, independent `EpochTree` with the same
/// registered algorithms and cell contents, rather than sharing state.
///
/// Deliberately **not** an `Arc<Mutex<...>>` sharing pattern (unlike
/// [`crate::commit_root::CloneableLog`], the Commit Tree's wrapper): SR is
/// rewritten on every principal mutation, including mutations `CommitScope`
/// applies to its `projected` clone before `finalize()`. A shared PT would
/// leak an abandoned scope's writes into the live principal; deep-cloning on
/// every `Principal::clone()` preserves the isolation `CommitScope` depends
/// on. This is cheap regardless: the tree holds SR, CR and a few nonces.
impl Clone for PrincipalTree {
    fn clone(&self) -> Self {
        let mut tree = Self {
            inner: new_inner(ARITY),
            algs: self.algs.clone(),
            sr: self.sr.clone(),
            cr: self.cr.clone(),
            nonces: self.nonces.clone(),
        };
        tree.rebuild()
            .expect("rebuilding an already-valid tree from its own cells cannot fail");
        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multihash::MultihashDigest;

    fn sr(bytes: &[u8]) -> StateRoot {
        StateRoot(MultihashDigest::from_single(HashAlg::Sha256, bytes.to_vec()).unwrap())
    }

    fn cr(bytes: &[u8]) -> CommitRoot {
        CommitRoot(MultihashDigest::from_single(HashAlg::Sha256, bytes.to_vec()).unwrap())
    }

    fn nonce_values(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut v = vec![0xEE; 32];
                v[..2].copy_from_slice(&(i as u16).to_be_bytes());
                v
            })
            .collect()
    }

    /// PR (Sha256) over SR, CR and `n` nonces, optionally without CR.
    fn pr_root(with_cr: bool, n: usize) -> Vec<u8> {
        let algs = [HashAlg::Sha256];
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr(&[0xAA; 32]), &algs).unwrap();
        if with_cr {
            pt.set_cr(&cr(&[0xBB; 32]), &algs).unwrap();
        }
        let nv = nonce_values(n);
        let nr: Vec<&[u8]> = nv.iter().map(Vec::as_slice).collect();
        pt.set_nonces(&nr, &algs)
            .unwrap_or_else(|e| panic!("PR of SR, CR={with_cr} + {n} nonces refused: {e:?}"));
        pt.pr(&algs).unwrap().get(HashAlg::Sha256).unwrap().to_vec()
    }

    /// FNV-1a over the concatenation of `parts`: a dependency-free,
    /// version-stable fingerprint of many roots at once.
    fn fingerprint(parts: &[Vec<u8>]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in parts.iter().flatten() {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
        h
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Nonce counts the golden pins sample: every count to 20, every ninth,
    /// and the approach to the boundary (SR, CR and 254 nonces fill 256).
    fn pinned_counts() -> impl Iterator<Item = usize> {
        (0..=254usize).filter(|n| *n <= 20 || n % 9 == 0 || *n >= 248)
    }

    const PIN_PR_254: &str = "6a7e81d8836f5667f1a33fcdec4f8c484666510748746aa43794a00f83347b96";
    const PIN_PR_NO_CR_254: &str =
        "afc251fd7384169223e1a3a6e0efc4c434f36a31f20abd765afcaec10f8f2681";
    const PIN_FP_PR: u64 = 11_276_060_262_666_140_975;
    const PIN_FP_PR_NO_CR: u64 = 17_233_225_874_401_855_600;

    /// Backs "no root for 256 items or fewer changes" (AR1, SPEC 4) at PR.
    /// Golden characterization, green on the pre-AR1 tree: roots captured
    /// before the cap was lifted, as a fingerprint over a fixed sample of
    /// nonce counts (see `pinned_counts`) with CR, and with SR alone, plus
    /// the full-fold roots in hex. Turns red if lifting the cap changes any
    /// root at or below 256 items (a re-leveled fold, a changed cell order,
    /// a prefixed fold below the boundary). Unit level: 256 cells by signed
    /// scenario is not cheap.
    #[test]
    fn arity_pr_roots_up_to_256_items_are_pinned() {
        let with_cr: Vec<_> = pinned_counts().map(|n| pr_root(true, n)).collect();
        let no_cr: Vec<_> = pinned_counts().map(|n| pr_root(false, n)).collect();
        assert_eq!(hex(with_cr.last().unwrap()), PIN_PR_254);
        assert_eq!(hex(no_cr.last().unwrap()), PIN_PR_NO_CR_254);
        assert_eq!(fingerprint(&with_cr), PIN_FP_PR, "PR with CR");
        assert_eq!(fingerprint(&no_cr), PIN_FP_PR_NO_CR, "PR without CR");
    }

    /// Backs SPEC 4 ("Merkle tree primitive must support n-arity") at PR with
    /// SR and CR counted: 255, 300 and 1000 nonces build; every size gives a
    /// distinct root that differs from the 254-nonce (full-fold) root; the
    /// root does not depend on nonce input order; and replacing the nonces
    /// with a smaller set, or with none, restores the earlier root (removal
    /// is the real incremental path here: `set_nonces` rebuilds in place).
    /// Turns red if the cap stays, items past the fold are dropped, the
    /// growth scheme depends on input order, or a shrink keeps cells from the
    /// larger tree. Unit level, as above.
    #[test]
    fn arity_pr_builds_beyond_256_and_removal_restores_the_root() {
        let algs = [HashAlg::Sha256];
        let base = pr_root(true, 254);
        let mut seen = vec![base.clone()];
        for n in [255, 300, 1000] {
            let r = pr_root(true, n);
            assert!(!seen.contains(&r), "SR, CR + {n} nonces collided");
            seen.push(r);
        }

        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr(&[0xAA; 32]), &algs).unwrap();
        pt.set_cr(&cr(&[0xBB; 32]), &algs).unwrap();
        let small = nonce_values(10);
        let small: Vec<&[u8]> = small.iter().map(Vec::as_slice).collect();
        pt.set_nonces(&small, &algs).unwrap();
        let before = pt.pr(&algs).unwrap();

        let big = nonce_values(1000);
        let mut fwd: Vec<&[u8]> = big.iter().map(Vec::as_slice).collect();
        pt.set_nonces(&fwd, &algs).unwrap();
        let grown = pt.pr(&algs).unwrap();
        fwd.reverse();
        pt.set_nonces(&fwd, &algs).unwrap();
        assert_eq!(pt.pr(&algs).unwrap(), grown, "root depends on input order");

        pt.set_nonces(&small, &algs).unwrap();
        assert_eq!(pt.pr(&algs).unwrap(), before, "removal did not restore");
        pt.set_nonces(&[], &algs).unwrap();
        assert_eq!(
            pt.pr(&algs).unwrap().get(HashAlg::Sha256).unwrap(),
            pr_root(true, 0).as_slice(),
            "removing every nonce did not restore the nonce-free root"
        );
    }

    /// Backs the claim in [`NONCE_ARITY`] that a flat k=256 fold over just
    /// SR and CR is the same bytes as the k=2 fold. That equality is what
    /// lets a PR with nonces keep SR and CR in their slots without changing
    /// any nonce-free PR. Property over random SR, CR and algorithm sets
    /// (each digest at its algorithm's width). Turns red if either fold
    /// changes its rule for two cells (a reordered or prefixed fold).
    /// Unit level: with no nonce the code stays on k=2, so no signed
    /// scenario reaches the k=256 fold over two cells. AR1 may retire this
    /// with the arity change.
    mod fold_equivalence {
        use proptest::prelude::*;

        use super::*;

        fn digest(alg: HashAlg, seed: &[u8]) -> Vec<u8> {
            let len = crate::state::TaggedDigest::expected_len(alg);
            seed.iter().copied().cycle().take(len).collect()
        }

        fn multihash(algs: &[HashAlg], seed: &[u8]) -> MultihashDigest {
            let variants = algs
                .iter()
                .map(|&a| (a, digest(a, seed).into_boxed_slice()))
                .collect();
            MultihashDigest::new(variants).unwrap()
        }

        proptest! {
            #[test]
            fn k2_and_k256_folds_of_sr_and_cr_agree(
                sr_seed in proptest::collection::vec(any::<u8>(), 1..8),
                cr_seed in proptest::collection::vec(any::<u8>(), 1..8),
                algs in proptest::sample::subsequence(
                    vec![HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512], 1..=3),
            ) {
                let mut pt = PrincipalTree::new();
                pt.set_sr(&StateRoot(multihash(&algs, &sr_seed)), &algs).unwrap();
                pt.set_cr(&CommitRoot(multihash(&algs, &cr_seed)), &algs).unwrap();
                let k2 = pt.build_inner(ARITY).unwrap();
                let k256 = pt.build_inner(NONCE_ARITY).unwrap();
                for alg in algs {
                    let id = hash_alg_to_u64(alg);
                    prop_assert_eq!(k2.root(id), k256.root(id), "{:?}", alg);
                }
            }
        }
    }

    #[test]
    fn genesis_pr_equals_sr_verbatim() {
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr(&[0xAA; 32]), &[HashAlg::Sha256]).unwrap();

        let pr = pt.pr(&[HashAlg::Sha256]).unwrap();
        assert_eq!(pr.get(HashAlg::Sha256).unwrap(), &[0xAA; 32]);
    }

    #[test]
    fn post_commit_pr_changes_from_genesis() {
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr(&[0xAA; 32]), &[HashAlg::Sha256]).unwrap();
        let genesis_pr = pt.pr(&[HashAlg::Sha256]).unwrap();

        pt.set_cr(&cr(&[0xBB; 32]), &[HashAlg::Sha256]).unwrap();
        let post_commit_pr = pt.pr(&[HashAlg::Sha256]).unwrap();

        assert_ne!(
            genesis_pr.get(HashAlg::Sha256),
            post_commit_pr.get(HashAlg::Sha256)
        );
    }

    /// The CR-cell inclusion witness (hop 2's prerequisite) is absent at
    /// genesis (cell 1 unset) and present, and verifiable, once CR is set.
    #[test]
    fn cr_inclusion_proof_absent_at_genesis_present_after_commit() {
        let alg_id = hash_alg_to_u64(HashAlg::Sha256);
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr(&[0xAA; 32]), &[HashAlg::Sha256]).unwrap();
        assert!(
            pt.cr_inclusion_proof(alg_id).is_none(),
            "cell 1 (CR) is unset at genesis"
        );

        pt.set_cr(&cr(&[0xBB; 32]), &[HashAlg::Sha256]).unwrap();
        let proof = pt
            .cr_inclusion_proof(alg_id)
            .expect("cell 1 is set after set_cr");
        assert_eq!(proof.index, CR_CELL);
        assert_eq!(proof.tree_size, 2);
        assert_eq!(proof.arity, ARITY);

        let root = pt.pr(&[HashAlg::Sha256]).unwrap();
        let hasher = MaltHasher::new(HashAlg::Sha256);
        let sk =
            polydigest::rebalanced_skeleton(proof.tree_size, proof.arity, proof.index).unwrap();
        assert!(proof.verify(&hasher, &sk, root.get(HashAlg::Sha256).unwrap()));
    }

    /// Proves the mechanism `CommitScope` isolation depends on: mutating a
    /// clone never touches the source tree's materialized roots.
    #[test]
    fn clone_is_independent_of_source() {
        let mut original = PrincipalTree::new();
        original
            .set_sr(&sr(&[0x01; 32]), &[HashAlg::Sha256])
            .unwrap();
        let original_pr_before = original.pr(&[HashAlg::Sha256]).unwrap();

        let mut cloned = original.clone();
        cloned.set_sr(&sr(&[0x02; 32]), &[HashAlg::Sha256]).unwrap();
        cloned.set_cr(&cr(&[0x03; 32]), &[HashAlg::Sha256]).unwrap();

        let original_pr_after = original.pr(&[HashAlg::Sha256]).unwrap();
        assert_eq!(
            original_pr_before.get(HashAlg::Sha256),
            original_pr_after.get(HashAlg::Sha256),
            "mutating the clone must not change the source tree's root"
        );
        assert_eq!(
            original_pr_after.get(HashAlg::Sha256).unwrap(),
            &[0x01; 32],
            "source must still promote its own genesis SR verbatim"
        );
    }
}
