//! Semantic Tree nodes: KT (Key Tree), AR-node, SR-node.
//!
//! Generalizes [`crate::principal_tree::PrincipalTree`]'s pattern (a small
//! `polydigest::EpochTree` + identity-extract [`MaltHasher`] + per-algorithm
//! JSON-map cell payloads) from "one instance at the root" to "one instance
//! per semantic node" (`.scratch/eml-emt-integration/REMEDIATION.md`).
//!
//! Prior to this module, Key Root (KR), Auth Root (AR), and State Root (SR)
//! were computed by hand-rolled flat-hash formulas (`compute_kr`/`compute_ar`/
//! `compute_sr` in [`crate::state`]) entirely outside any tree. Those formulas
//! are now demoted to differential test-only oracles; the values `Principal`
//! actually uses come from the tree types here:
//!
//! - [`KeyTree`] — a k=256 collection node, one leaf per active key
//!   thumbprint, lexically sorted. Its root is KR. A thumbprint's raw byte
//!   length is native to *its own signing key's* algorithm (an ES256 tmb is
//!   32 bytes, an Ed25519 tmb is 64), so a mixed-algorithm keyset's
//!   thumbprints do not share a width. `EpochTree`'s generic node fold
//!   requires same-width siblings (an unprefixed concatenation is only
//!   unambiguously parseable when children share a width — see
//!   `spine::nary_mr`'s contract), so each non-native thumbprint is
//!   converted to its canonical digest under the target algorithm before
//!   folding, via the same `infer_alg_from_len`/`hash_bytes` mechanism
//!   [`crate::state::compute_dr`] already uses for czd content
//!   (REMEDIATION.md §4: "Leaf-level cross-alg conversion... keeps the
//!   existing convert_to/infer_alg_from_len semantics"). This is a real,
//!   authorized divergence from `compute_kr`'s raw-concat-regardless-of-size
//!   behavior for mixed-algorithm keysets — single-algorithm keysets are
//!   unaffected (every thumbprint is already native, so conversion is a
//!   no-op).
//! - [`AuthTree`] — a k=2 role-slot node: cell 0 = KT's root, cell 1 = RT's
//!   root (Rule Tree — Level 5, not yet implemented, permanently absent).
//!   Its root is AR. Because cell 1 never gets set, AR always promotes from
//!   KT alone (native singleton promotion — see
//!   [`crate::principal_tree::PrincipalTree`]'s own genesis test).
//! - [`StateTree`] — a k=2 role-slot node: cell 0 = AR-node's root, cell 1 =
//!   DR (Data Root). DR itself keeps coming from the unchanged
//!   [`crate::state::compute_dr`] (SPEC §14.2's per-algorithm conversion
//!   logic survives as the DT leaf producer) — only the final concat step
//!   that used to fold DR into SR by hand moves into this tree, embedding DR
//!   as an opaque leaf exactly as [`crate::principal_tree::PrincipalTree`]
//!   already embeds CR into PT's cell 1.
//!
//! `StateTree`'s root then becomes the value written into
//! [`crate::principal_tree::PrincipalTree`]'s existing cell 0 — PT's root
//! level (`[SR@0, CR@1]`) is unchanged by this module.
//!
//! None of these types keep long-lived mutable state across a `Principal`'s
//! lifetime: each mutation rebuilds the affected node fresh from current
//! state (REMEDIATION.md's recommended strategy — every level here is
//! `O(children)` with trees this small) via the `build_*` associated
//! functions. This also makes algorithm shrinkage trivially correct: a fresh
//! tree only ever registers the `algs` it is given, so a revoked algorithm's
//! entry can never survive into a rebuilt tree (c-liveness-shrinkage-rebuild).

use std::collections::BTreeMap;

use coz::Thumbprint;

use crate::commit_root::{MaltHasher, hash_alg_to_u64};
use crate::error::{Error, Result};
use crate::multihash::MultihashDigest;
use crate::state::{AuthRoot, DataRoot, HashAlg, KeyRoot, StateRoot};

/// Collection-node arity: dense, left-filled, one leaf per item. At size
/// `<= 256` the tree folds as a single `H(child_0 ∥ … ∥ child_n)` — the same
/// bytes the old flat formulas produced (REMEDIATION.md §2). Beyond 256
/// items the spine's canonical fold takes over; that boundary is explicitly
/// out of this node's scope (reserved — see the worker IBC).
const COLLECTION_ARITY: u64 = 256;

/// Role-slot arity: fixed two cells, position IS the semantics.
const ROLE_ARITY: u64 = 2;

/// Cell index of a role-slot node's primary (always-present) child.
const PRIMARY_CELL: u64 = 0;

/// Cell index of a role-slot node's optional (may-be-absent) child.
const OPTIONAL_CELL: u64 = 1;

/// Register `algs` on a fresh `EpochTree`, deduplicated.
///
/// The single fan-out call site every node type's constructor below uses —
/// c-liveness-centralized-registration: registration cannot drift between
/// node types because there is exactly one place that performs it.
fn register_algs(inner: &mut eml::EpochTree, algs: &[HashAlg]) -> Result<()> {
    let mut seen: Vec<HashAlg> = Vec::new();
    for &alg in algs {
        if seen.contains(&alg) {
            continue;
        }
        let alg_id = hash_alg_to_u64(alg);
        inner
            .register_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        seen.push(alg);
    }
    Ok(())
}

/// Serialize a raw thumbprint digest into the shared cell-payload idiom,
/// converting it to each target algorithm's canonical digest first.
///
/// `bytes`'s own algorithm is inferred from its length
/// ([`crate::state::infer_alg_from_len`]); a target algorithm matching that
/// native algorithm gets the raw bytes unchanged, any other target gets
/// `hash_bytes(target, bytes)` — the exact mechanism
/// [`crate::state::TaggedCzd::convert_to`] already uses for czd content in
/// `compute_dr`. This keeps every algorithm's leaf entry at that
/// algorithm's own native width, which `EpochTree`'s generic node fold
/// requires of its siblings.
fn serialize_converted(bytes: &[u8], algs: &[HashAlg]) -> Result<Vec<u8>> {
    let native = crate::state::infer_alg_from_len(bytes.len()).ok_or_else(|| {
        Error::UnsupportedAlgorithm(format!("invalid digest length: {}", bytes.len()))
    })?;
    let mut mapped = BTreeMap::new();
    for &alg in algs {
        let converted = if alg == native {
            bytes.to_vec()
        } else {
            crate::state::hash_bytes(alg, bytes)
        };
        mapped.insert(hash_alg_to_u64(alg), converted.into_boxed_slice());
    }
    serde_json::to_vec(&mapped).map_err(|_| Error::MalformedPayload)
}

/// Serialize a [`MultihashDigest`]'s per-algorithm variants into the shared
/// cell-payload idiom (mirrors
/// [`crate::principal_tree::PrincipalTree`]'s private `serialize`). Used to
/// embed one node's already-correctly-computed root as an opaque cell in its
/// parent, per algorithm.
fn serialize_digest(md: &MultihashDigest, algs: &[HashAlg]) -> Result<Vec<u8>> {
    let mut mapped = BTreeMap::new();
    for &alg in algs {
        let bytes = md.get_or_err(alg)?;
        mapped.insert(hash_alg_to_u64(alg), bytes.to_vec().into_boxed_slice());
    }
    serde_json::to_vec(&mapped).map_err(|_| Error::MalformedPayload)
}

fn new_tree(arity: u64) -> eml::EpochTree {
    eml::EpochTree::new(eml::CmtConfig { arity })
        .expect("arity is a fixed in-range constant (2 or 256)")
}

/// KT — Key Tree: one leaf per active key thumbprint, lexically sorted by
/// raw digest bytes. `EpochTree::root(alg_id)` is KR.
///
/// Replaces `compute_kr`.
#[derive(Debug)]
pub struct KeyTree {
    inner: eml::EpochTree,
}

impl KeyTree {
    /// Create an empty KT with no algorithms registered.
    fn new() -> Self {
        Self {
            inner: new_tree(COLLECTION_ARITY),
        }
    }

    /// Assemble KR from the tree's current per-algorithm member roots.
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if `algs` is empty or a requested algorithm
    /// has no root yet (no cells set).
    pub fn root(&self, algs: &[HashAlg]) -> Result<KeyRoot> {
        Ok(KeyRoot(assemble(&self.inner, algs)?))
    }

    /// Build KT fresh from `thumbprints`, sorted lexically (matching
    /// `compute_kr`'s existing sort-then-concat order), and return its root
    /// as [`KeyRoot`].
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `algs` is empty. Returns
    /// `CollectionArityExceeded` if `thumbprints.len() > 256` — the
    /// collection-node arity boundary is out of this node's scope (reserved
    /// in the worker IBC; deferred to P10-testing-hardening).
    pub fn build(thumbprints: &[&Thumbprint], algs: &[HashAlg]) -> Result<KeyRoot> {
        if algs.is_empty() {
            return Err(Error::NoActiveKeys);
        }
        if thumbprints.len() as u64 > COLLECTION_ARITY {
            return Err(Error::CollectionArityExceeded(thumbprints.len()));
        }

        let mut sorted: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
        sorted.sort();

        let mut kt = Self::new();
        register_algs(&mut kt.inner, algs)?;
        for (index, tmb) in sorted.iter().enumerate() {
            let payload = serialize_converted(tmb, algs)?;
            kt.inner
                .set(index as u64, payload, Vec::new())
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        }

        kt.root(algs)
    }
}

/// AR-node: a k=2 role-slot node. Cell 0 = KT's root, cell 1 = RT's root
/// (Rule Tree — Level 5, not yet implemented; permanently absent). Its root
/// is AR.
///
/// Replaces `compute_ar`. Because cell 1 is never set, AR always promotes
/// from KT alone (native singleton promotion, the same mechanism
/// [`crate::principal_tree::PrincipalTree`]'s `genesis_pr_equals_sr_verbatim`
/// proves at the root) — unconditionally, for every call, until a future
/// node implements RT.
#[derive(Debug)]
pub struct AuthTree {
    inner: eml::EpochTree,
}

impl AuthTree {
    fn new() -> Self {
        Self {
            inner: new_tree(ROLE_ARITY),
        }
    }

    /// Assemble AR from the tree's current per-algorithm member roots.
    pub fn root(&self, algs: &[HashAlg]) -> Result<AuthRoot> {
        Ok(AuthRoot(assemble(&self.inner, algs)?))
    }

    /// Build AR-node fresh from `kr` and return its root as [`AuthRoot`].
    pub fn build(kr: &KeyRoot, algs: &[HashAlg]) -> Result<AuthRoot> {
        let mut node = Self::new();
        register_algs(&mut node.inner, algs)?;
        let payload = serialize_digest(&kr.0, algs)?;
        node.inner
            .set(PRIMARY_CELL, payload, Vec::new())
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;

        node.root(algs)
    }
}

/// SR-node: a k=2 role-slot node. Cell 0 = AR-node's root, cell 1 = DR (Data
/// Root, embedded as an opaque leaf when present — see this module's
/// top-level docs). Its root is SR.
///
/// Replaces `compute_sr`. When `dr` is absent, cell 1 is never set and SR
/// promotes from AR alone, unconditionally matching `compute_sr`'s existing
/// promotion branch. When `dr` is present, SR = `H(AR ∥ DR)` — positional
/// (cell order), which is where this node's one predicted, proven byte
/// divergence from the old `compute_sr` (lexical `H(sort(AR, DR))`) lives;
/// see the `oracle_ar_sr_*` differential tests in [`crate::state`].
#[derive(Debug)]
pub struct StateTree {
    inner: eml::EpochTree,
}

impl StateTree {
    fn new() -> Self {
        Self {
            inner: new_tree(ROLE_ARITY),
        }
    }

    /// Assemble SR from the tree's current per-algorithm member roots.
    pub fn root(&self, algs: &[HashAlg]) -> Result<StateRoot> {
        Ok(StateRoot(assemble(&self.inner, algs)?))
    }

    /// Build SR-node fresh from `ar` and optional `dr`, and return its root
    /// as [`StateRoot`].
    pub fn build(ar: &AuthRoot, dr: Option<&DataRoot>, algs: &[HashAlg]) -> Result<StateRoot> {
        let mut node = Self::new();
        register_algs(&mut node.inner, algs)?;
        let ar_payload = serialize_digest(&ar.0, algs)?;
        node.inner
            .set(PRIMARY_CELL, ar_payload, Vec::new())
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        if let Some(dr) = dr {
            let dr_payload = serialize_digest(&dr.0, algs)?;
            node.inner
                .set(OPTIONAL_CELL, dr_payload, Vec::new())
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        }

        node.root(algs)
    }
}

/// Assemble a [`MultihashDigest`] from a tree's current per-algorithm member
/// roots — `variants[alg] = EpochTree::root(alg_id)`, mirroring
/// [`crate::principal_tree::PrincipalTree::pr`]'s exact assembly pattern.
///
/// No node type in this module ever exposes "roots for every registered
/// algorithm" — every caller threads `algs` explicitly (c-liveness-explicit-algs).
fn assemble(inner: &eml::EpochTree, algs: &[HashAlg]) -> Result<MultihashDigest> {
    let mut variants = BTreeMap::new();
    for &alg in algs {
        let alg_id = hash_alg_to_u64(alg);
        let root = inner.root(alg_id).ok_or(Error::EmptyMultihash)?;
        variants.insert(alg, root.into_boxed_slice());
    }
    MultihashDigest::new(variants)
}

/// Rebuild the full KT → AR-node → SR-node chain fresh from the current key
/// set and (optional) Data Root, and return `(KR, AR, SR)`.
///
/// The tree-based replacement for `derive_auth_state` (`state.rs`), now
/// producing real tree node roots instead of flat-hash formula outputs.
/// Mirrors `derive_auth_state`'s exact signature so call sites need only
/// swap the function, not restructure their surrounding code.
pub fn derive_state_roots(
    thumbprints: &[&Thumbprint],
    dr: Option<&DataRoot>,
    algs: &[HashAlg],
) -> Result<(KeyRoot, AuthRoot, StateRoot)> {
    let kr = KeyTree::build(thumbprints, algs)?;
    let ar = AuthTree::build(&kr, algs)?;
    let sr = StateTree::build(&ar, dr, algs)?;
    Ok((kr, ar, sr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmb(bytes: &[u8]) -> Thumbprint {
        Thumbprint::from_bytes(bytes.to_vec())
    }

    #[test]
    fn kt_single_key_promotes_verbatim() {
        let t = tmb(&[0xAA; 32]);
        let kr = KeyTree::build(&[&t], &[HashAlg::Sha256]).unwrap();
        assert_eq!(kr.0.get(HashAlg::Sha256).unwrap(), t.as_bytes());
    }

    #[test]
    fn ar_node_promotes_from_kt_verbatim() {
        let t = tmb(&[0xAA; 32]);
        let kr = KeyTree::build(&[&t], &[HashAlg::Sha256]).unwrap();
        let ar = AuthTree::build(&kr, &[HashAlg::Sha256]).unwrap();
        assert_eq!(
            ar.0.get(HashAlg::Sha256).unwrap(),
            kr.0.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn sr_node_promotes_from_ar_when_dr_absent() {
        let t = tmb(&[0xAA; 32]);
        let kr = KeyTree::build(&[&t], &[HashAlg::Sha256]).unwrap();
        let ar = AuthTree::build(&kr, &[HashAlg::Sha256]).unwrap();
        let sr = StateTree::build(&ar, None, &[HashAlg::Sha256]).unwrap();
        assert_eq!(
            sr.0.get(HashAlg::Sha256).unwrap(),
            ar.0.get(HashAlg::Sha256).unwrap()
        );
    }

    #[test]
    fn kt_empty_algs_rejected() {
        let t = tmb(&[0xAA; 32]);
        assert!(matches!(
            KeyTree::build(&[&t], &[]),
            Err(Error::NoActiveKeys)
        ));
    }

    #[test]
    fn kt_mixed_algorithm_keyset_converts_instead_of_panicking() {
        // A 32-byte (SHA-256-native) and a 64-byte (SHA-512-native)
        // thumbprint together used to panic `nary_mr`'s same-width
        // contract; conversion must make both target folds width-uniform.
        let a = tmb(&[0x11; 32]);
        let b = tmb(&[0x22; 64]);
        let kr = KeyTree::build(&[&a, &b], &[HashAlg::Sha256, HashAlg::Sha512]).unwrap();
        assert!(kr.0.get(HashAlg::Sha256).unwrap().len() == 32);
        assert!(kr.0.get(HashAlg::Sha512).unwrap().len() == 64);
    }

    #[test]
    fn kt_arity_boundary_rejected() {
        let raw: Vec<Thumbprint> = (0..257u16)
            .map(|i| Thumbprint::from_bytes(vec![(i % 256) as u8; 32]))
            .collect();
        let refs: Vec<&Thumbprint> = raw.iter().collect();
        assert!(matches!(
            KeyTree::build(&refs, &[HashAlg::Sha256]),
            Err(Error::CollectionArityExceeded(257))
        ));
    }
}
