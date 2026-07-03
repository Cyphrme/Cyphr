//! Semantic Tree nodes: KT (Key Tree), AR-node, SR-node.
//!
//! Generalizes [`crate::principal_tree::PrincipalTree`]'s pattern (a small
//! `polydigest::EpochTree` + identity-extract [`MaltHasher`] + per-algorithm
//! JSON-map cell payloads) from "one instance at the root" to "one instance
//! per semantic node".
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
//!   [`crate::state::compute_dr`] already uses for czd content. This is a
//!   real, authorized divergence from `compute_kr`'s raw-concat-regardless-of-size
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
//! state (every level here is `O(children)` with trees this small) via the
//! `build_*` associated
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
/// bytes the old flat formulas produced. Beyond 256
/// items the spine's canonical fold takes over; that boundary is explicitly
/// out of this node's scope (reserved for future work).
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
    /// `compute_kr`'s existing sort-then-concat order), and return the tree
    /// itself (rather than just its root), so a caller can also generate
    /// inclusion proofs over it via [`Self::thumbprint_inclusion_proof`].
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `algs` is empty. Returns
    /// `CollectionArityExceeded` if `thumbprints.len() > 256` — the
    /// collection-node arity boundary is out of this node's scope (reserved
    /// for future work).
    pub fn build_tree(thumbprints: &[&Thumbprint], algs: &[HashAlg]) -> Result<Self> {
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

        Ok(kt)
    }

    /// Build KT fresh from `thumbprints` and return its root as [`KeyRoot`].
    ///
    /// # Errors
    ///
    /// See [`Self::build_tree`].
    pub fn build(thumbprints: &[&Thumbprint], algs: &[HashAlg]) -> Result<KeyRoot> {
        Self::build_tree(thumbprints, algs)?.root(algs)
    }

    /// Generate a self-contained inclusion proof for the thumbprint at
    /// lexical-sort position `index`, under `alg_id` — the hop-1 witness of
    /// the key-membership chain (see
    /// [`crate::principal::Principal::verify_key_inclusion`]): "this
    /// thumbprint is included in KR." Mirrors
    /// [`crate::principal_tree::PrincipalTree::cr_inclusion_proof`]'s
    /// pattern, but takes an explicit index since KT's cells are dynamic
    /// (one per active key, not a fixed role constant).
    ///
    /// Returns `None` if `alg_id` is unregistered or `index` is out of
    /// range.
    #[must_use]
    pub fn thumbprint_inclusion_proof(&self, alg_id: u64, index: u64) -> Option<eml::LeafProof> {
        self.inner.leaf_proof(alg_id, index)
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

    /// Build AR-node fresh from `kr` and return the node itself (rather than
    /// just its root), so a caller can also generate inclusion proofs over
    /// it via [`Self::kr_inclusion_proof`].
    pub fn build_tree(kr: &KeyRoot, algs: &[HashAlg]) -> Result<Self> {
        let mut node = Self::new();
        register_algs(&mut node.inner, algs)?;
        let payload = serialize_digest(&kr.0, algs)?;
        node.inner
            .set(PRIMARY_CELL, payload, Vec::new())
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;

        Ok(node)
    }

    /// Build AR-node fresh from `kr` and return its root as [`AuthRoot`].
    pub fn build(kr: &KeyRoot, algs: &[HashAlg]) -> Result<AuthRoot> {
        Self::build_tree(kr, algs)?.root(algs)
    }

    /// Generate a self-contained inclusion proof for cell 0 (KR) under
    /// `alg_id` — the hop-2 witness of the key-membership chain (see
    /// [`crate::principal::Principal::verify_key_inclusion`]): "KR is
    /// included in AR." Mirrors
    /// [`crate::principal_tree::PrincipalTree::cr_inclusion_proof`]'s
    /// pattern; deliberately scoped to `PRIMARY_CELL` only — cell 1 (RT) has
    /// no analogous witness since RT is permanently absent.
    ///
    /// Returns `None` if `alg_id` is unregistered.
    #[must_use]
    pub fn kr_inclusion_proof(&self, alg_id: u64) -> Option<eml::LeafProof> {
        self.inner.leaf_proof(alg_id, PRIMARY_CELL)
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

    /// Build SR-node fresh from `ar` and optional `dr`, and return the node
    /// itself (rather than just its root), so a caller can also generate
    /// inclusion proofs over it via [`Self::ar_inclusion_proof`].
    pub fn build_tree(ar: &AuthRoot, dr: Option<&DataRoot>, algs: &[HashAlg]) -> Result<Self> {
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

        Ok(node)
    }

    /// Build SR-node fresh from `ar` and optional `dr`, and return its root
    /// as [`StateRoot`].
    pub fn build(ar: &AuthRoot, dr: Option<&DataRoot>, algs: &[HashAlg]) -> Result<StateRoot> {
        Self::build_tree(ar, dr, algs)?.root(algs)
    }

    /// Generate a self-contained inclusion proof for cell 0 (AR) under
    /// `alg_id` — the hop-3 witness of the key-membership chain (see
    /// [`crate::principal::Principal::verify_key_inclusion`]): "AR is
    /// included in SR." Mirrors
    /// [`crate::principal_tree::PrincipalTree::cr_inclusion_proof`]'s
    /// pattern; deliberately scoped to `PRIMARY_CELL` only — cell 1 (DR) has
    /// no analogous witness in this chain (the key-membership proof does not
    /// prove anything about DR).
    ///
    /// Returns `None` if `alg_id` is unregistered.
    #[must_use]
    pub fn ar_inclusion_proof(&self, alg_id: u64) -> Option<eml::LeafProof> {
        self.inner.leaf_proof(alg_id, PRIMARY_CELL)
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

/// Differential oracle tests: cross-check the tree types here against the
/// demoted flat-hash formulas in [`crate::state`] (c-oracle-kr,
/// c-oracle-ar-sr). Each test asserts the *precise* predicted relationship
/// (unconditional equality, or an exactly-characterized divergence) rather
/// than a blanket equality or inequality.
#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::state::{
        StateDigest, compute_ar, compute_kr, compute_sr, derive_auth_state, hash_bytes,
        hash_concat_bytes, infer_alg_from_len,
    };

    fn tmb(bytes: &[u8]) -> Thumbprint {
        Thumbprint::from_bytes(bytes.to_vec())
    }

    fn key(alg: HashAlg, tag: u8) -> Thumbprint {
        let len = match alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        };
        tmb(&vec![tag; len])
    }

    // -- c-oracle-kr --------------------------------------------------------

    #[test]
    fn oracle_kr_single_algorithm_keyset_matches_exactly() {
        let a = key(HashAlg::Sha256, 0x11);
        let b = key(HashAlg::Sha256, 0x22);
        let c = key(HashAlg::Sha256, 0x33);
        let algs = [HashAlg::Sha256];

        let old = compute_kr(&[&a, &b, &c], None, &algs).unwrap();
        let new = KeyTree::build(&[&a, &b, &c], &algs).unwrap();

        assert_eq!(old.get(HashAlg::Sha256), new.get(HashAlg::Sha256));
    }

    #[test]
    fn oracle_kr_single_key_promotion_matches_exactly() {
        let a = key(HashAlg::Sha256, 0xAA);
        let algs = [HashAlg::Sha256];

        let old = compute_kr(&[&a], None, &algs).unwrap();
        let new = KeyTree::build(&[&a], &algs).unwrap();

        assert_eq!(old.get(HashAlg::Sha256), new.get(HashAlg::Sha256));
        assert_eq!(new.get(HashAlg::Sha256).unwrap(), a.as_bytes());
    }

    /// c-oracle-kr's predicted, authorized divergence: for a mixed-algorithm
    /// keyset, KT converts each non-native thumbprint to the target
    /// algorithm's canonical digest before folding; `compute_kr` does not.
    /// The two roots must therefore differ, AND the new root must equal an
    /// independently-computed conversion fold — proving the divergence is
    /// exactly this predicted conversion, not an unrelated bug.
    #[test]
    fn oracle_kr_mixed_algorithm_keyset_diverges_via_conversion() {
        let es256 = key(HashAlg::Sha256, 0x11); // 32B, native Sha256
        let ed25519 = key(HashAlg::Sha512, 0x22); // 64B, native Sha512
        let algs = [HashAlg::Sha256, HashAlg::Sha512];

        // compute_kr concatenates raw bytes regardless of size — this
        // itself would panic if fed through the tree's generic fold, which
        // is exactly why KT cannot reuse it unconditionally. Compute it
        // manually here (compute_kr's own documented behavior) rather than
        // calling it, to avoid masking the point under test.
        let mut sorted: Vec<&[u8]> = vec![es256.as_bytes(), ed25519.as_bytes()];
        sorted.sort();

        let new = KeyTree::build(&[&es256, &ed25519], &algs).unwrap();

        for &alg in &algs {
            // Old (undocumented-unsafe) raw concat, replicated by hand.
            let mut concat = Vec::new();
            for c in &sorted {
                concat.extend_from_slice(c);
            }
            let old_bytes = hash_bytes(alg, &concat);

            // Independently-computed conversion fold: each thumbprint
            // converted to `alg`'s canonical digest (native passthrough or
            // hash_bytes re-hash), in the same lexical (RAW-byte) order KT
            // itself sorts by — must equal KT's root.
            let converted: Vec<Vec<u8>> = sorted
                .iter()
                .map(|raw| {
                    let native = infer_alg_from_len(raw.len()).unwrap();
                    if native == alg {
                        raw.to_vec()
                    } else {
                        hash_bytes(alg, raw)
                    }
                })
                .collect();
            let refs: Vec<&[u8]> = converted.iter().map(|v| v.as_slice()).collect();
            let expected_new = hash_concat_bytes(alg, &refs);

            let new_bytes = new.get(alg).unwrap();
            assert_eq!(
                new_bytes, expected_new,
                "KT root for {alg:?} must equal the independently-computed \
                 conversion fold"
            );
            assert_ne!(
                new_bytes, old_bytes,
                "KT root for {alg:?} must diverge from compute_kr's raw \
                 concat for a mixed-algorithm keyset"
            );
        }
    }

    // -- c-oracle-ar-sr -------------------------------------------------

    #[test]
    fn oracle_ar_matches_exactly_rt_always_absent() {
        let a = key(HashAlg::Sha256, 0x11);
        let b = key(HashAlg::Sha256, 0x22);
        let algs = [HashAlg::Sha256];

        let kr = KeyTree::build(&[&a, &b], &algs).unwrap();
        let old = compute_ar(&kr, None, None, &algs).unwrap();
        let new = AuthTree::build(&kr, &algs).unwrap();

        assert_eq!(old.get(HashAlg::Sha256), new.get(HashAlg::Sha256));
    }

    #[test]
    fn oracle_sr_matches_exactly_when_dr_absent() {
        let a = key(HashAlg::Sha256, 0x11);
        let algs = [HashAlg::Sha256];

        let kr = KeyTree::build(&[&a], &algs).unwrap();
        let ar = AuthTree::build(&kr, &algs).unwrap();
        let old = compute_sr(&ar, None, None, &algs).unwrap();
        let new = StateTree::build(&ar, None, &algs).unwrap();

        assert_eq!(old.get(HashAlg::Sha256), new.get(HashAlg::Sha256));
    }

    /// c-oracle-ar-sr's predicted, authorized divergence: when DR is
    /// present and its bytes lexically precede AR's, `compute_sr`'s lexical
    /// sort puts DR first (`H(DR ∥ AR)`) while `StateTree`'s fixed cell
    /// order puts AR first (`H(AR ∥ DR)`) — the two must differ, and the
    /// new root must equal the independently-computed positional fold.
    #[test]
    fn oracle_sr_diverges_exactly_by_positional_reorder_when_dr_precedes_ar() {
        use crate::state::DataRoot;

        let a = key(HashAlg::Sha256, 0x11);
        let algs = [HashAlg::Sha256];
        let kr = KeyTree::build(&[&a], &algs).unwrap();
        let ar = AuthTree::build(&kr, &algs).unwrap();
        let ar_bytes = ar.get(HashAlg::Sha256).unwrap().to_vec();

        // Construct a DR whose bytes lexically precede AR's bytes.
        let mut dr_bytes = ar_bytes.clone();
        dr_bytes[0] = 0x00;
        assert!(dr_bytes < ar_bytes, "test fixture must have DR <lex AR");
        let dr = DataRoot(
            crate::multihash::MultihashDigest::from_single(HashAlg::Sha256, dr_bytes.clone())
                .unwrap(),
        );

        let old = compute_sr(&ar, Some(&dr), None, &algs).unwrap();
        let new = StateTree::build(&ar, Some(&dr), &algs).unwrap();

        let old_bytes = old.get(HashAlg::Sha256).unwrap();
        let new_bytes = new.get(HashAlg::Sha256).unwrap();
        assert_ne!(
            old_bytes, new_bytes,
            "old (lexical H(DR||AR)) and new (positional H(AR||DR)) must diverge"
        );

        let expected_new = hash_concat_bytes(HashAlg::Sha256, &[&ar_bytes, &dr_bytes]);
        assert_eq!(
            new_bytes, expected_new,
            "new root must equal the independently-computed positional fold H(AR||DR)"
        );

        let expected_old = {
            let mut sorted = [ar_bytes.as_slice(), dr_bytes.as_slice()];
            sorted.sort();
            crate::state::hash_sorted_concat_bytes(HashAlg::Sha256, &sorted)
        };
        assert_eq!(
            old_bytes, expected_old,
            "old root must equal the independently-computed lexical fold H(sort(AR,DR))"
        );
    }

    #[test]
    fn oracle_sr_matches_exactly_when_ar_precedes_dr_lexically() {
        use crate::state::DataRoot;

        let a = key(HashAlg::Sha256, 0x11);
        let algs = [HashAlg::Sha256];
        let kr = KeyTree::build(&[&a], &algs).unwrap();
        let ar = AuthTree::build(&kr, &algs).unwrap();
        let ar_bytes = ar.get(HashAlg::Sha256).unwrap().to_vec();

        // Construct a DR whose bytes lexically FOLLOW AR's bytes, so
        // lexical order and positional order coincide.
        let mut dr_bytes = ar_bytes.clone();
        dr_bytes[0] = 0xFF;
        assert!(dr_bytes > ar_bytes, "test fixture must have DR >lex AR");
        let dr = DataRoot(
            crate::multihash::MultihashDigest::from_single(HashAlg::Sha256, dr_bytes).unwrap(),
        );

        let old = compute_sr(&ar, Some(&dr), None, &algs).unwrap();
        let new = StateTree::build(&ar, Some(&dr), &algs).unwrap();

        assert_eq!(old.get(HashAlg::Sha256), new.get(HashAlg::Sha256));
    }

    #[test]
    fn oracle_derive_state_roots_matches_derive_auth_state_single_algorithm() {
        let a = key(HashAlg::Sha256, 0x11);
        let b = key(HashAlg::Sha256, 0x22);
        let algs = [HashAlg::Sha256];

        let (old_kr, old_ar, old_sr) = derive_auth_state(&[&a, &b], None, &algs).unwrap();
        let (new_kr, new_ar, new_sr) = derive_state_roots(&[&a, &b], None, &algs).unwrap();

        assert_eq!(
            old_kr.get(HashAlg::Sha256),
            new_kr.get(HashAlg::Sha256)
        );
        assert_eq!(
            old_ar.get(HashAlg::Sha256),
            new_ar.get(HashAlg::Sha256)
        );
        assert_eq!(
            old_sr.get(HashAlg::Sha256),
            new_sr.get(HashAlg::Sha256)
        );
    }
}

/// Property-based (generative) counterparts to `oracle_tests` above: the
/// same c-oracle-kr / c-oracle-ar-sr divergence conditions, checked against
/// randomly generated keysets, digest bytes, and algorithm combinations
/// instead of one hand-picked case each. Each property asserts the
/// *relationship* the doc comments on `compute_kr`/`compute_ar`/`compute_sr`
/// predict for the generated case (agreement or a specific characterized
/// divergence), never a blanket equality or inequality.
#[cfg(test)]
mod oracle_properties {
    use proptest::prelude::*;

    use super::*;
    use crate::state::{DataRoot, StateDigest, compute_ar, compute_kr, compute_sr};

    fn hash_alg_strategy() -> impl Strategy<Value = HashAlg> {
        prop_oneof![
            Just(HashAlg::Sha256),
            Just(HashAlg::Sha384),
            Just(HashAlg::Sha512),
        ]
    }

    /// Native digest length for `alg` — the same three-way match `key()`
    /// (in `oracle_tests`) hard-codes for its fixed cases.
    fn native_len(alg: HashAlg) -> usize {
        match alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    /// A digest's worth of random bytes, tagged with the algorithm it is
    /// native to (i.e. its length matches that algorithm's digest size).
    fn alg_and_native_bytes_strategy() -> impl Strategy<Value = (HashAlg, Vec<u8>)> {
        hash_alg_strategy()
            .prop_flat_map(|alg| (Just(alg), prop::collection::vec(any::<u8>(), native_len(alg))))
    }

    /// A random thumbprint, tagged with the algorithm it is native to.
    fn tagged_thumbprint_strategy() -> impl Strategy<Value = (HashAlg, Thumbprint)> {
        alg_and_native_bytes_strategy().prop_map(|(alg, bytes)| (alg, Thumbprint::from_bytes(bytes)))
    }

    /// A pair of independently random byte strings, both sized to `alg`'s
    /// native digest length (required by `MultihashDigest::from_single`) —
    /// used to build an AR/DR pair whose relative lexical order is what the
    /// SR positional-vs-lexical divergence property below turns on.
    fn same_alg_byte_pair_strategy() -> impl Strategy<Value = (HashAlg, Vec<u8>, Vec<u8>)> {
        hash_alg_strategy().prop_flat_map(|alg| {
            let len = native_len(alg);
            (
                Just(alg),
                prop::collection::vec(any::<u8>(), len),
                prop::collection::vec(any::<u8>(), len),
            )
        })
    }

    proptest! {
        /// c-oracle-kr, generalized: `compute_kr` and `KeyTree` agree for
        /// `target_alg`'s variant exactly when every generated thumbprint is
        /// already native to `target_alg` (a genuinely single-algorithm
        /// keyset for that target — KT's per-thumbprint conversion is then a
        /// no-op everywhere); they diverge whenever at least one thumbprint
        /// is native to a different algorithm (KT converts it, `compute_kr`
        /// does not).
        #[test]
        fn oracle_kr_agrees_iff_keyset_native_to_target_alg(
            target_alg in hash_alg_strategy(),
            tagged in prop::collection::vec(tagged_thumbprint_strategy(), 2..12),
        ) {
            let thumbprints: Vec<&Thumbprint> = tagged.iter().map(|(_, t)| t).collect();
            let all_native = tagged.iter().all(|(alg, _)| *alg == target_alg);

            let old = compute_kr(&thumbprints, None, &[target_alg]).unwrap();
            let new = KeyTree::build(&thumbprints, &[target_alg]).unwrap();

            if all_native {
                prop_assert_eq!(old.get(target_alg), new.get(target_alg));
            } else {
                prop_assert_ne!(old.get(target_alg), new.get(target_alg));
            }
        }

        /// c-oracle-kr's single-key implicit-promotion branch: both
        /// implementations promote a lone thumbprint verbatim, for any
        /// random native content (not just the fixed `0xAA`-filled case in
        /// `oracle_tests`).
        #[test]
        fn oracle_kr_single_key_promotion_agrees_for_any_native_key(
            (alg, bytes) in alg_and_native_bytes_strategy(),
        ) {
            let t = Thumbprint::from_bytes(bytes);
            let old = compute_kr(&[&t], None, &[alg]).unwrap();
            let new = KeyTree::build(&[&t], &[alg]).unwrap();
            prop_assert_eq!(old.get(alg), new.get(alg));
        }

        /// c-oracle-ar-sr (AR half): RT is permanently absent, so AR always
        /// promotes from KT alone — `compute_ar` and `AuthTree` must agree
        /// unconditionally, even when the upstream keyset is mixed-algorithm
        /// (i.e. even when KR itself diverged going in).
        #[test]
        fn oracle_ar_always_agrees_regardless_of_upstream_kr(
            target_alg in hash_alg_strategy(),
            tagged in prop::collection::vec(tagged_thumbprint_strategy(), 1..12),
        ) {
            let thumbprints: Vec<&Thumbprint> = tagged.iter().map(|(_, t)| t).collect();
            let kr = KeyTree::build(&thumbprints, &[target_alg]).unwrap();

            let old = compute_ar(&kr, None, None, &[target_alg]).unwrap();
            let new = AuthTree::build(&kr, &[target_alg]).unwrap();

            prop_assert_eq!(old.get(target_alg), new.get(target_alg));
        }

        /// c-oracle-ar-sr (SR half), DR-absent branch: SR always promotes
        /// from AR alone when DR is absent — `compute_sr` and `StateTree`
        /// must agree unconditionally, for any random AR value/algorithm.
        #[test]
        fn oracle_sr_always_agrees_when_dr_absent(
            (alg, ar_bytes) in alg_and_native_bytes_strategy(),
        ) {
            let ar = AuthRoot(MultihashDigest::from_single(alg, ar_bytes).unwrap());

            let old = compute_sr(&ar, None, None, &[alg]).unwrap();
            let new = StateTree::build(&ar, None, &[alg]).unwrap();

            prop_assert_eq!(old.get(alg), new.get(alg));
        }

        /// c-oracle-ar-sr (SR half), DR-present branch: `compute_sr` sorts
        /// AR/DR lexically before concatenating while `StateTree` always
        /// concatenates positionally (AR, then DR) — the two agree exactly
        /// when AR already sorts first (AR <= DR lexically, so sorting is a
        /// no-op) and diverge exactly when DR would sort first (DR < AR, so
        /// sorting reorders relative to the tree's fixed cell order).
        #[test]
        fn oracle_sr_agrees_iff_ar_precedes_dr_lexically(
            (alg, ar_bytes, dr_bytes) in same_alg_byte_pair_strategy(),
        ) {
            let ar = AuthRoot(MultihashDigest::from_single(alg, ar_bytes.clone()).unwrap());
            let dr = DataRoot(MultihashDigest::from_single(alg, dr_bytes.clone()).unwrap());

            let old = compute_sr(&ar, Some(&dr), None, &[alg]).unwrap();
            let new = StateTree::build(&ar, Some(&dr), &[alg]).unwrap();

            if ar_bytes <= dr_bytes {
                prop_assert_eq!(old.get(alg), new.get(alg));
            } else {
                prop_assert_ne!(old.get(alg), new.get(alg));
            }
        }
    }
}

/// c-liveness-payload-inertness: a stale/foreign algorithm's entry inside a
/// cell's JSON payload map must be provably inert — each algorithm's
/// identity-extract [`MaltHasher`] only ever reads its own map entry, never
/// the map's full bytes, so injecting a foreign algorithm's variant into a
/// live cell must not change any live algorithm's root, at any node type.
#[cfg(test)]
mod liveness_tests {
    use super::*;
    use crate::state::StateDigest;

    /// An arbitrary alg_id no `HashAlg` variant maps to — simulates an
    /// unregistered/foreign algorithm's leftover payload entry.
    const FOREIGN_ALG_ID: u64 = 999;

    fn payload_with_foreign(native_alg: HashAlg, bytes: &[u8]) -> Vec<u8> {
        let mut mapped: BTreeMap<u64, Box<[u8]>> = BTreeMap::new();
        mapped.insert(hash_alg_to_u64(native_alg), bytes.to_vec().into_boxed_slice());
        mapped.insert(FOREIGN_ALG_ID, vec![0xFF; 32].into_boxed_slice());
        serde_json::to_vec(&mapped).unwrap()
    }

    #[test]
    fn kt_payload_inertness_foreign_algorithm_entry_does_not_affect_live_root() {
        let t = Thumbprint::from_bytes(vec![0xAA; 32]);
        let algs = [HashAlg::Sha256];
        let root_before = KeyTree::build(&[&t], &algs).unwrap();

        // Manually build the same tree, but with a foreign algorithm's
        // variant spliced into the live cell's payload map.
        let mut inner = new_tree(COLLECTION_ARITY);
        register_algs(&mut inner, &algs).unwrap();
        let payload = payload_with_foreign(HashAlg::Sha256, t.as_bytes());
        inner.set(0, payload, Vec::new()).unwrap();
        let tampered = KeyTree { inner };
        let root_after = tampered.root(&algs).unwrap();

        assert_eq!(
            root_before.get(HashAlg::Sha256),
            root_after.get(HashAlg::Sha256),
            "a foreign algorithm's payload entry must not affect a live algorithm's root"
        );
    }

    #[test]
    fn ar_node_payload_inertness_foreign_algorithm_entry_does_not_affect_live_root() {
        let t = Thumbprint::from_bytes(vec![0xAA; 32]);
        let algs = [HashAlg::Sha256];
        let kr = KeyTree::build(&[&t], &algs).unwrap();
        let root_before = AuthTree::build(&kr, &algs).unwrap();

        let mut inner = new_tree(ROLE_ARITY);
        register_algs(&mut inner, &algs).unwrap();
        let payload = payload_with_foreign(HashAlg::Sha256, kr.get(HashAlg::Sha256).unwrap());
        inner.set(PRIMARY_CELL, payload, Vec::new()).unwrap();
        let tampered = AuthTree { inner };
        let root_after = tampered.root(&algs).unwrap();

        assert_eq!(
            root_before.get(HashAlg::Sha256),
            root_after.get(HashAlg::Sha256),
            "a foreign algorithm's payload entry must not affect a live algorithm's root"
        );
    }

    #[test]
    fn sr_node_payload_inertness_foreign_algorithm_entry_does_not_affect_live_root() {
        let t = Thumbprint::from_bytes(vec![0xAA; 32]);
        let algs = [HashAlg::Sha256];
        let kr = KeyTree::build(&[&t], &algs).unwrap();
        let ar = AuthTree::build(&kr, &algs).unwrap();
        let root_before = StateTree::build(&ar, None, &algs).unwrap();

        let mut inner = new_tree(ROLE_ARITY);
        register_algs(&mut inner, &algs).unwrap();
        let payload = payload_with_foreign(HashAlg::Sha256, ar.get(HashAlg::Sha256).unwrap());
        inner.set(PRIMARY_CELL, payload, Vec::new()).unwrap();
        let tampered = StateTree { inner };
        let root_after = tampered.root(&algs).unwrap();

        assert_eq!(
            root_before.get(HashAlg::Sha256),
            root_after.get(HashAlg::Sha256),
            "a foreign algorithm's payload entry must not affect a live algorithm's root"
        );
    }
}
