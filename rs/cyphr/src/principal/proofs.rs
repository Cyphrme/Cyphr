//! Inclusion and consistency proofs over a principal's trees.

use coz::Thumbprint;

use super::Principal;
use crate::error::{Error, Result};
use crate::multihash::MultihashDigest;
use crate::nonce::NonceLevel;
use crate::semantic_tree::{AuthTree, KeyTree, StateTree, sorted_leaves};
use crate::state::HashAlg;

// ============================================================================
// NodePath: chained multi-hop inclusion proofs
// ============================================================================

/// One hop of a chained inclusion proof: a self-contained leaf proof for a
/// specific level's cell, verified against that level's own root.
///
/// Crate-internal only (see [`NodePath`]'s note on why this isn't a public
/// portable proof type yet).
#[derive(Debug, Clone)]
pub(crate) struct NodePathHop {
    /// The leaf proof for this hop.
    pub(crate) proof: polydigest::LeafProof,
}

/// A top-down chain of inclusion hops used internally by
/// [`Principal::verify_key_inclusion`] — the generalization of
/// [`Principal::verify_transaction_inclusion`]'s 2-hop CR-in-PR chain into a
/// sequence of hops verified top-down from a trusted PR.
/// [`Principal::key_inclusion_proof`] produces the concrete
/// 4-hop instance chaining a key's thumbprint through KT -> AR-node ->
/// SR-node -> PT.
///
/// **Not a portable external proof type (crate-internal only).**
/// [`Self::verify`] requires the caller to already supply every
/// intermediate root (KR/AR/SR), and never binds the target leaf itself —
/// it proves "some leaf at `hops[0]`'s position sits under `roots`", not
/// "thumbprint T is included." In its one current use
/// ([`Principal::verify_key_inclusion`]) that's the right shape: generation
/// is keyed on the target thumbprint and the roots come from the
/// principal's own trusted cache, so it functions correctly as an
/// internal proof/cache cross-check. The genuinely portable proof — one a
/// remote verifier holding only a published PR and a thumbprint can check
/// unassisted — is [`crate::inclusion::verify_key_inclusion`], which adds
/// the missing thumbprint-to-leaf binding this type's `verify` alone does
/// not provide, rather than widening this type itself.
#[derive(Debug, Clone)]
pub(crate) struct NodePath {
    /// Hops in leaf-to-root order.
    pub(crate) hops: Vec<NodePathHop>,
}

impl NodePath {
    /// Verify every hop against its own level's authenticated root
    /// (`roots`, ordered leaf-to-root, one entry per hop), and every
    /// consecutive bridge — hop `i`'s proven leaf value must equal hop
    /// `i - 1`'s authenticated root — mirroring
    /// [`Principal::verify_transaction_inclusion`]'s single bridge check,
    /// scaled to an arbitrary-length chain.
    ///
    /// A promoted (single-cell) level's hop is not special-cased: its
    /// `LeafProof` carries an empty skeleton (a 1-cell tree's root is its
    /// sole leaf verbatim — see [`crate::principal_tree`]'s module docs),
    /// so `verify` reduces to a direct byte-equality check against `roots`
    /// through the same code path every other hop uses.
    #[must_use]
    pub(crate) fn verify(&self, hasher: &dyn eml::Hasher, roots: &[&[u8]]) -> bool {
        if self.hops.len() != roots.len() || self.hops.is_empty() {
            return false;
        }
        for (hop, &root) in self.hops.iter().zip(roots.iter()) {
            let Some(skeleton) = polydigest::rebalanced_skeleton(
                hop.proof.tree_size,
                hop.proof.arity,
                hop.proof.index,
            ) else {
                return false;
            };
            if !hop.proof.verify(hasher, &skeleton, root) {
                return false;
            }
        }
        for i in 1..self.hops.len() {
            if self.hops[i].proof.leaf_hash != roots[i - 1] {
                return false;
            }
        }
        true
    }
}

impl<S: eml::Storage> Principal<S> {
    // ========================================================================
    // MALT Proof Generation
    // ========================================================================

    /// Generate an inclusion proof for the commit at `index` in the
    /// per-algorithm MALT for `alg`.
    ///
    /// The returned proof can be verified standalone with
    /// [`malt::verify_inclusion`] using the tree's root and the
    /// corresponding [`MaltHasher`](crate::commit_root::MaltHasher).
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT.
    /// - Propagates [`malt::Error`] for empty tree or out-of-bounds index.
    pub fn inclusion_proof(&self, alg: HashAlg, index: u64) -> Result<crate::InclusionProof> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        if !self.commit_trees.has_algorithm(alg_id) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }
        self.commit_trees
            .inclusion_proof(alg_id, index)
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Generate a consistency proof from `old_size` to the current tree
    /// size for the per-algorithm MALT at `alg`.
    ///
    /// The returned proof can be verified standalone with
    /// [`verify_consistency`] using the old and new roots and the
    /// corresponding [`MaltHasher`](crate::commit_root::MaltHasher).
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT.
    /// - Propagates [`Error`] for invalid old_size.
    pub fn consistency_proof(
        &self,
        alg: HashAlg,
        old_size: u64,
    ) -> Result<crate::ConsistencyProof> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        if !self.commit_trees.has_algorithm(alg_id) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }
        self.commit_trees
            .consistency_proof(alg_id, old_size)
            .map_err(|e| Error::Storage(e.to_string()))
    }

    /// Generate an inclusion proof for this principal's current State Root
    /// (SR), as PT cell 0's payload, in the Principal Root (PR), for hash
    /// algorithm `alg` — hop 4 of [`Self::key_inclusion_proof`]'s 4-hop
    /// KT -> AR-node -> SR-node -> PT chain, exposed standalone because
    /// [`Self::pt`](#structfield.pt) is crate-internal: a portable verifier
    /// ([`crate::inclusion::verify_key_inclusion`]) that never owns this
    /// `Principal` still needs hop 4's material to assemble the chain
    /// itself (issue #19).
    ///
    /// Returns `None` if `alg` has no PT registration, mirroring
    /// [`crate::principal_tree::PrincipalTree::sr_inclusion_proof`].
    #[must_use]
    pub fn sr_inclusion_proof(&self, alg: HashAlg) -> Option<polydigest::LeafProof> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        self.pt.sr_inclusion_proof(alg_id)
    }

    /// Verify that transaction `tr`, claimed at commit `index`, is really
    /// included under this principal's *current* Principal Root (PR), for
    /// hash algorithm `alg` — by chaining two independent, already-existing
    /// inclusion proofs. No new composite proof type is introduced:
    ///
    /// 1. **Hop 1** — `tr` included in the Commit Root (CR): the commit log's own inclusion proof
    ///    ([`Self::inclusion_proof`], verified with [`crate::verify_inclusion`]).
    /// 2. **Hop 2** — CR, as PT cell 1's payload, included in PR: the Principal Tree's own
    ///    inclusion proof ([`PrincipalTree::cr_inclusion_proof`], verified with
    ///    [`polydigest::LeafProof::verify`]).
    ///
    /// The hops are bridged explicitly: hop 2's proven leaf value must equal
    /// hop 1's proven CR root. Without that check the two hops would each
    /// verify independently true facts about two *unrelated* trees; the
    /// bridge is what makes them jointly prove `tr` sits under the current
    /// PR specifically.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT/PT registration, or has no committed
    ///   CR yet (a genesis principal has nothing to chain through PT cell 1 — there is no valid
    ///   `index` to call this with).
    /// - Propagates [`Error`] for an out-of-bounds commit `index`.
    pub fn verify_transaction_inclusion(
        &self,
        alg: HashAlg,
        index: u64,
        tr: &MultihashDigest,
    ) -> Result<bool> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);

        // Hop 1 material: tr's claimed inclusion in CR.
        let hop1_proof = self.inclusion_proof(alg, index)?;
        let tree_size = self
            .commit_trees
            .tree_size(alg_id)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let cr = self
            .cr
            .as_ref()
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let cr_bytes = cr
            .as_multihash()
            .get(alg)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        // Hop 2 material: CR's (PT cell 1) claimed inclusion in PR.
        let hop2_proof = self
            .pt
            .cr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let pr_bytes = self
            .pr
            .0
            .get(alg)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        Ok(crate::inclusion::verify_transaction_inclusion(
            alg,
            tr,
            &crate::inclusion::TransactionHop1 {
                index,
                tree_size,
                proof: &hop1_proof,
                cr_root: cr_bytes,
            },
            &crate::inclusion::TransactionHop2 {
                proof: &hop2_proof,
                pr_root: pr_bytes,
            },
        ))
    }

    /// Prove that the currently active key with thumbprint `tmb` is
    /// included under this principal's *current* Principal Root (PR), for
    /// hash algorithm `alg` — a 4-hop generalization of
    /// [`Self::verify_transaction_inclusion`]'s 2-hop CR-in-PR chain over
    /// the full identity hierarchy: thumbprint -> KT -> AR-node -> SR-node
    /// -> PT.
    ///
    /// Rebuilds KT/AR-node/SR-node fresh from the principal's current key
    /// set and Data Root — none of the three keep long-lived state on
    /// `Principal` (see [`crate::semantic_tree`]'s module docs); `PT` is the
    /// one node type that does, so its hop reuses `self.pt` directly.
    ///
    /// Crate-internal only (returns [`NodePath`], which is not a public
    /// type — see its doc comment). [`Self::verify_key_inclusion`] is the
    /// public entry point.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] if `alg` is not currently active, or
    /// `tmb` does not name a currently active key.
    pub(crate) fn key_inclusion_proof(&self, alg: HashAlg, tmb: &Thumbprint) -> Result<NodePath> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let active_algs = self.active_algs();
        if !active_algs.contains(&alg) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }

        // Lexical-sort position among the thumbprints and KT nonces, from
        // the same ordering KeyTree builds with.
        let thumbprints: Vec<&Thumbprint> = self.auth.keys.values().map(|k| k.tmb()).collect();
        let tmbs: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
        let kt_nonces = self.nonces.at_level(NonceLevel::Kt);
        let sorted = sorted_leaves(&tmbs, &kt_nonces);
        let index = sorted
            .iter()
            .position(|&b| b == tmb.as_bytes())
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?
            as u64;

        let kt = KeyTree::build_tree_with_nonces(&thumbprints, &kt_nonces, &active_algs)?;
        let kr = kt.root(&active_algs)?;
        let ar_node = AuthTree::build_tree_with_nonces(
            &kr,
            &self.nonces.at_level(NonceLevel::At),
            &active_algs,
        )?;
        let ar = ar_node.root(&active_algs)?;
        let sr_node = StateTree::build_tree(&ar, self.dr.as_ref(), &active_algs)?;

        let hop1 = kt
            .thumbprint_inclusion_proof(alg_id, index)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop2 = ar_node
            .kr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop3 = sr_node
            .ar_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop4 = self
            .pt
            .sr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        Ok(NodePath {
            hops: vec![
                NodePathHop { proof: hop1 },
                NodePathHop { proof: hop2 },
                NodePathHop { proof: hop3 },
                NodePathHop { proof: hop4 },
            ],
        })
    }

    /// Generate and verify, in one call, that the currently active key with
    /// thumbprint `tmb` is included under this principal's current PR — see
    /// [`Self::key_inclusion_proof`] for the chain this checks.
    ///
    /// Verifies each hop against `self.kr`/`self.ar`/`self.sr`/`self.pr` —
    /// the principal's independently-maintained root cache (kept in
    /// lockstep with every mutation) — rather than re-deriving the roots
    /// from the same freshly-rebuilt trees the proof itself was generated
    /// from; a staleness bug in either path would then show up as a
    /// verification failure instead of silently self-confirming.
    ///
    /// # Errors
    ///
    /// See [`Self::key_inclusion_proof`].
    pub fn verify_key_inclusion(&self, alg: HashAlg, tmb: &Thumbprint) -> Result<bool> {
        let path = self.key_inclusion_proof(alg, tmb)?;

        let kr_bytes = self
            .kr
            .as_ref()
            .ok_or(Error::NoActiveKeys)?
            .0
            .get_or_err(alg)?;
        let ar_bytes = self
            .ar
            .as_ref()
            .ok_or(Error::NoActiveKeys)?
            .0
            .get_or_err(alg)?;
        let sr_bytes = self
            .sr
            .as_ref()
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?
            .0
            .get_or_err(alg)?;
        let pr_bytes = self.pr.0.get_or_err(alg)?;

        let hops: Vec<polydigest::LeafProof> = path.hops.iter().map(|h| h.proof.clone()).collect();
        let roots: [&[u8]; 4] = [kr_bytes, ar_bytes, sr_bytes, pr_bytes];

        Ok(crate::inclusion::verify_key_inclusion(
            alg, tmb, &hops, &roots,
        ))
    }
}
