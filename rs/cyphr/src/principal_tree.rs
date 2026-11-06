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
        self.inner = inner;
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
            self.ensure_algorithm(alg);
        }
        self.sr = Some(Self::serialize(sr.as_multihash())?);
        self.rebuild()
    }

    /// Write the Commit Root into cell 1, registering any newly active
    /// algorithms first. Cell 0 (SR) must already be set.
    ///
    /// # Errors
    ///
    /// `Storage` if cell 0 is unset: the tree is dense, so CR cannot be
    /// placed before SR.
    pub fn set_cr(&mut self, cr: &CommitRoot, algs: &[HashAlg]) -> Result<()> {
        if self.sr.is_none() {
            return Err(Error::Storage(
                "principal tree cell 1 (CR) set before cell 0 (SR)".to_string(),
            ));
        }
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
        if 2 + sorted.len() as u64 > NONCE_ARITY {
            return Err(Error::CollectionArityExceeded(2 + sorted.len()));
        }
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
        self.inner.leaf_proof(alg_id, CR_CELL)
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
