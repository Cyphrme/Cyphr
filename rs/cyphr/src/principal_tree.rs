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

/// The proof-spine arity: cell 0 (SR) and cell 1 (CR), no more.
const ARITY: u64 = 2;

/// Cell index of the State Root.
const SR_CELL: u64 = 0;

/// Cell index of the Commit Root.
const CR_CELL: u64 = 1;

/// The Principal Tree: a k=2 `EpochTree` with cell 0 = SR, cell 1 = CR.
#[derive(Debug)]
pub struct PrincipalTree {
    inner: eml::EpochTree,
    /// Algorithms currently registered in `inner`, in registration order.
    algs: Vec<HashAlg>,
}

impl PrincipalTree {
    /// Create an empty principal tree with no algorithms registered.
    #[must_use]
    pub fn new() -> Self {
        let inner = eml::EpochTree::new(eml::CmtConfig { arity: ARITY })
            .expect("arity 2 is within the spine's 2..=256 range");
        Self {
            inner,
            algs: Vec::new(),
        }
    }

    /// Register `alg` if it is not already registered.
    fn ensure_algorithm(&mut self, alg: HashAlg) -> Result<()> {
        if self.algs.contains(&alg) {
            return Ok(());
        }
        let alg_id = hash_alg_to_u64(alg);
        self.inner
            .register_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        self.algs.push(alg);
        Ok(())
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
            self.ensure_algorithm(alg)?;
        }
        let payload = Self::serialize(sr.as_multihash())?;
        self.inner
            .set(SR_CELL, payload, Vec::new())
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))
    }

    /// Write the Commit Root into cell 1, registering any newly active
    /// algorithms first. Cell 0 (SR) must already be set.
    pub fn set_cr(&mut self, cr: &CommitRoot, algs: &[HashAlg]) -> Result<()> {
        for &alg in algs {
            self.ensure_algorithm(alg)?;
        }
        let payload = Self::serialize(cr.as_multihash())?;
        self.inner
            .set(CR_CELL, payload, Vec::new())
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))
    }

    /// Generate a self-contained inclusion proof for the Commit Root, cell 1,
    /// under `alg_id` — the hop-2 witness of the two-step transaction
    /// inclusion verification (see
    /// [`Principal::verify_transaction_inclusion`](crate::principal::Principal::verify_transaction_inclusion)):
    /// "CR is included in PR." Deliberately scoped to `CR_CELL` only, not a
    /// general "prove any cell" facility — cell 0 (SR) has no analogous
    /// external consumer today.
    ///
    /// Returns `None` if `alg_id` is unregistered or cell 1 has not yet been
    /// set (no commits exist yet — a genesis principal has no CR to prove).
    #[must_use]
    pub fn cr_inclusion_proof(&self, alg_id: u64) -> Option<eml::LeafProof> {
        self.inner.leaf_proof(alg_id, CR_CELL)
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
/// on. This is cheap regardless: the tree never holds more than 2 cells.
impl Clone for PrincipalTree {
    fn clone(&self) -> Self {
        let mut inner = eml::EpochTree::new(eml::CmtConfig { arity: ARITY })
            .expect("arity 2 is within the spine's 2..=256 range");
        for &alg in &self.algs {
            let alg_id = hash_alg_to_u64(alg);
            inner
                .register_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
                .expect("self.algs is already deduplicated by ensure_algorithm");
        }
        for index in 0..self.inner.len() {
            let payload = self
                .inner
                .get(index)
                .expect("index within len")
                .to_vec();
            let metadata = self.inner.metadata(index).unwrap_or(&[]).to_vec();
            inner
                .set(index, payload, metadata)
                .expect("dense in-order replay of an already-valid tree cannot gap");
        }
        Self {
            inner,
            algs: self.algs.clone(),
        }
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
        let sk = eml::rebalanced_skeleton(proof.tree_size, proof.arity, proof.index).unwrap();
        assert!(proof.verify(&hasher, &sk, root.get(HashAlg::Sha256).unwrap()));
    }

    /// Proves the mechanism `CommitScope` isolation depends on: mutating a
    /// clone never touches the source tree's materialized roots.
    #[test]
    fn clone_is_independent_of_source() {
        let mut original = PrincipalTree::new();
        original.set_sr(&sr(&[0x01; 32]), &[HashAlg::Sha256]).unwrap();
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
