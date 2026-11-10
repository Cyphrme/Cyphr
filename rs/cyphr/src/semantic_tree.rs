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
//! - [`KeyTree`] — a k=256 collection node, one leaf per active key thumbprint, lexically sorted.
//!   Its root is KR. A thumbprint's raw byte length is native to *its own signing key's* algorithm
//!   (an ES256 tmb is 32 bytes, an Ed25519 tmb is 64), so a mixed-algorithm keyset's thumbprints do
//!   not share a width. `EpochTree`'s generic node fold requires same-width siblings (an unprefixed
//!   concatenation is only unambiguously parseable when children share a width — see
//!   `spine::nary_mr`'s contract), so each non-native thumbprint is converted to its canonical
//!   digest under the target algorithm before folding, from the algorithm its key names, the same
//!   `hash_bytes` conversion [`crate::state::compute_dr`] applies to czd content. This is a real,
//!   authorized divergence from `compute_kr`'s raw-concat-regardless-of-size behavior for
//!   mixed-algorithm keysets — single-algorithm keysets are unaffected (every thumbprint is already
//!   native, so conversion is a no-op).
//! - [`AuthTree`] — a k=2 role-slot node: cell 0 = KT's root, cell 1 = RT's root (Rule Tree — Level
//!   5, not yet implemented, permanently absent). Its root is AR. Because cell 1 never gets set, AR
//!   always promotes from KT alone (native singleton promotion — see
//!   [`crate::principal_tree::PrincipalTree`]'s own genesis test).
//! - [`StateTree`] — a k=2 role-slot node: cell 0 = AR-node's root, cell 1 = DR (Data Root). DR
//!   itself keeps coming from the unchanged [`crate::state::compute_dr`] (SPEC §14.2's
//!   per-algorithm conversion logic survives as the DT leaf producer) — only the final concat step
//!   that used to fold DR into SR by hand moves into this tree, embedding DR as an opaque leaf
//!   exactly as [`crate::principal_tree::PrincipalTree`] already embeds CR into PT's cell 1.
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

#[cfg(test)]
use coz::Thumbprint;

use crate::commit_root::{MaltHasher, hash_alg_to_u64};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::multihash::MultihashDigest;
use crate::nonce::{NonceLevel, NonceSets};
use crate::state::{AuthRoot, DataRoot, HashAlg, KeyRoot, StateRoot};

/// Collection-node arity: dense, left-filled, one leaf per item. At size
/// `<= 256` the tree folds as a single `H(child_0 ∥ … ∥ child_n)` — the same
/// bytes the old flat formulas produced. Beyond 256 items the spine's
/// rebalanced fold adds levels of 256 (SPEC §4: the Merkle primitive
/// supports n-arity); there is no item bound.
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
///
/// # Error mapping
///
/// `EpochTree` wraps `canonical-mt`'s `Cmt`, which has no `Storage`-generic
/// backend anywhere in its type — it is pure in-memory. Its errors
/// (`DuplicateAlgorithm` here; `IndexGap` from this file's `set()` call
/// sites below) are dense-tree invariant violations, never I/O. They still
/// map to `Error::Storage`: that is the closest existing variant for an
/// "this should be unreachable against crate-internal alg IDs" condition,
/// not a genuine storage diagnosis — contrast `crate::principal`'s
/// `CommitTrees`-backed sites, which wrap `eml::Storage` and fail on real
/// backend I/O.
fn register_algs(inner: &mut polydigest::EpochTree, algs: &[HashAlg]) -> Result<()> {
    let mut seen: Vec<HashAlg> = Vec::new();
    for &alg in algs {
        if seen.contains(&alg) {
            continue;
        }
        let alg_id = hash_alg_to_u64(alg);
        inner
            .register_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
            .map_err(|e| Error::Storage(e.to_string()))?;
        seen.push(alg);
    }
    Ok(())
}

/// A tree leaf: digest bytes and the hash algorithm they are in (a key's
/// thumbprint under its key's algorithm, a nonce under its label's).
pub type Leaf<'a> = (&'a [u8], HashAlg);

/// A key's KT leaf: its thumbprint, in its key's hash algorithm.
pub fn key_leaf(key: &Key) -> Leaf<'_> {
    (key.tmb().as_bytes(), key.hash_alg())
}

/// Serialize a leaf into the shared cell-payload idiom, converting it to
/// each target algorithm's canonical digest first.
///
/// A target algorithm matching the leaf's own gets the raw bytes
/// unchanged, any other target gets `hash_bytes(target, bytes)` — the
/// exact mechanism [`crate::state::TaggedCzd::convert_to`] already uses for
/// czd content in `compute_dr`. This keeps every algorithm's leaf entry at
/// that algorithm's own native width, which `EpochTree`'s generic node fold
/// requires of its siblings.
pub(crate) fn serialize_converted((bytes, native): Leaf<'_>, algs: &[HashAlg]) -> Result<Vec<u8>> {
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

fn new_tree(arity: u64) -> polydigest::EpochTree {
    polydigest::EpochTree::new(polydigest::CmtConfig { arity })
        .expect("arity is a fixed in-range constant (2 or 256)")
}

/// The leaves of a collection node: `members` and `nonces` together,
/// lexically sorted by raw digest bytes (SPEC §3.7: a nonce sorts with the
/// other digests). The one place that order is defined, so a proof's index
/// is found in the same order the tree was built in.
pub(crate) fn sorted_leaves<'a>(members: &[Leaf<'a>], nonces: &[Leaf<'a>]) -> Vec<Leaf<'a>> {
    let mut leaves: Vec<Leaf<'a>> = members.iter().chain(nonces).copied().collect();
    leaves.sort_by(|a, b| a.0.cmp(b.0));
    leaves
}

/// Cell payloads for a role-slot node's nonces: they follow the node's
/// defined slots, in ascending byte order (SPEC §3.7.1).
fn nonce_payloads(nonces: &[Leaf<'_>], algs: &[HashAlg]) -> Result<Vec<Vec<u8>>> {
    let mut sorted = nonces.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .into_iter()
        .map(|n| serialize_converted(n, algs))
        .collect()
}

/// Arity for a role-slot node: its two role slots alone, or the collection
/// arity once nonces follow them (a nonce fold is a flat `H(c0 ∥ … ∥ cn)`,
/// the same bytes as the two-slot fold when only the slots are filled).
pub(crate) fn role_arity(nonce_count: usize) -> u64 {
    if nonce_count == 0 {
        ROLE_ARITY
    } else {
        COLLECTION_ARITY
    }
}

/// KT — Key Tree: one leaf per active key thumbprint and per KT nonce,
/// lexically sorted by raw digest bytes. `EpochTree::root(alg_id)` is KR.
///
/// Replaces `compute_kr`.
#[derive(Debug)]
pub struct KeyTree {
    inner: polydigest::EpochTree,
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

    /// Build KT fresh from `members` (key leaves, see [`key_leaf`]), sorted
    /// lexically by thumbprint (matching
    /// `compute_kr`'s existing sort-then-concat order), and return the tree
    /// itself (rather than just its root), so a caller can also generate
    /// inclusion proofs over it via [`Self::thumbprint_inclusion_proof`].
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `algs` is empty.
    pub fn build_tree(members: &[Leaf<'_>], algs: &[HashAlg]) -> Result<Self> {
        Self::build_tree_with_nonces(members, &[], algs)
    }

    /// KT from `members` (key leaves, see [`key_leaf`]) with the KT-level
    /// nonces sorted in among them (SPEC §3.7, §10.2).
    ///
    /// # Errors
    ///
    /// `NoActiveKeys` if `algs` is empty.
    pub(crate) fn build_tree_with_nonces(
        members: &[Leaf<'_>],
        nonces: &[Leaf<'_>],
        algs: &[HashAlg],
    ) -> Result<Self> {
        if algs.is_empty() {
            return Err(Error::NoActiveKeys);
        }
        let sorted = sorted_leaves(members, nonces);

        let mut kt = Self::new();
        register_algs(&mut kt.inner, algs)?;
        for (index, &leaf) in sorted.iter().enumerate() {
            let payload = serialize_converted(leaf, algs)?;
            kt.inner
                .set(index as u64, payload, Vec::new())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }

        Ok(kt)
    }

    /// Build KT fresh from `members` and return its root as [`KeyRoot`].
    ///
    /// # Errors
    ///
    /// See [`Self::build_tree`].
    pub fn build(members: &[Leaf<'_>], algs: &[HashAlg]) -> Result<KeyRoot> {
        Self::build_tree(members, algs)?.root(algs)
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
    pub fn thumbprint_inclusion_proof(
        &self,
        alg_id: u64,
        index: u64,
    ) -> Option<polydigest::LeafProof> {
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
    inner: polydigest::EpochTree,
}

impl AuthTree {
    fn new(arity: u64) -> Self {
        Self {
            inner: new_tree(arity),
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
        Self::build_tree_with_nonces(kr, &[], algs)
    }

    /// [`Self::build_tree`] with the AT-level nonces after the node's
    /// defined slots (SPEC §3.7.1). RT, the one other slot, is permanently
    /// absent, so the nonces fill the cells after KR.
    ///
    /// # Errors
    ///
    /// As [`Self::build_tree`].
    pub(crate) fn build_tree_with_nonces(
        kr: &KeyRoot,
        nonces: &[Leaf<'_>],
        algs: &[HashAlg],
    ) -> Result<Self> {
        let mut node = Self::new(role_arity(nonces.len()));
        register_algs(&mut node.inner, algs)?;
        let payload = serialize_digest(&kr.0, algs)?;
        node.inner
            .set(PRIMARY_CELL, payload, Vec::new())
            .map_err(|e| Error::Storage(e.to_string()))?;
        for (offset, payload) in nonce_payloads(nonces, algs)?.into_iter().enumerate() {
            node.inner
                .set(OPTIONAL_CELL + offset as u64, payload, Vec::new())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }

        Ok(node)
    }

    /// AR of a principal whose KT is empty but which holds AT nonces: with
    /// KR absent the nonces fill the cells from 0 (SPEC 3.7: an empty
    /// component is omitted), so one nonce is promoted.
    pub(crate) fn build_nonces_only(nonces: &[Leaf<'_>], algs: &[HashAlg]) -> Result<AuthRoot> {
        let mut node = Self::new(role_arity(nonces.len()));
        register_algs(&mut node.inner, algs)?;
        for (index, payload) in nonce_payloads(nonces, algs)?.into_iter().enumerate() {
            node.inner
                .set(index as u64, payload, Vec::new())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        node.root(algs)
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
    pub fn kr_inclusion_proof(&self, alg_id: u64) -> Option<polydigest::LeafProof> {
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
    inner: polydigest::EpochTree,
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
            .map_err(|e| Error::Storage(e.to_string()))?;
        if let Some(dr) = dr {
            let dr_payload = serialize_digest(&dr.0, algs)?;
            node.inner
                .set(OPTIONAL_CELL, dr_payload, Vec::new())
                .map_err(|e| Error::Storage(e.to_string()))?;
        }

        Ok(node)
    }

    /// SR of a principal with no keys: the DR alone, promoted (SPEC 3.7).
    /// The one cell is cell 0, so the root is the DR verbatim.
    pub fn build_data_only(dr: &DataRoot, algs: &[HashAlg]) -> Result<StateRoot> {
        let mut node = Self::new();
        register_algs(&mut node.inner, algs)?;
        node.inner
            .set(PRIMARY_CELL, serialize_digest(&dr.0, algs)?, Vec::new())
            .map_err(|e| Error::Storage(e.to_string()))?;
        node.root(algs)
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
    pub fn ar_inclusion_proof(&self, alg_id: u64) -> Option<polydigest::LeafProof> {
        self.inner.leaf_proof(alg_id, PRIMARY_CELL)
    }
}

/// Assemble a [`MultihashDigest`] from a tree's current per-algorithm member
/// roots — `variants[alg] = EpochTree::root(alg_id)`, mirroring
/// [`crate::principal_tree::PrincipalTree::pr`]'s exact assembly pattern.
///
/// No node type in this module ever exposes "roots for every registered
/// algorithm" — every caller threads `algs` explicitly (c-liveness-explicit-algs).
fn assemble(inner: &polydigest::EpochTree, algs: &[HashAlg]) -> Result<MultihashDigest> {
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
    members: &[Leaf<'_>],
    dr: Option<&DataRoot>,
    algs: &[HashAlg],
) -> Result<(KeyRoot, AuthRoot, StateRoot)> {
    let (kr, ar, sr) = derive_state_roots_with_nonces(members, dr, &NonceSets::default(), algs)?;
    match (kr, ar, sr) {
        (Some(kr), Some(ar), Some(sr)) => Ok((kr, ar, sr)),
        _ => Err(Error::NoActiveKeys),
    }
}

/// [`derive_state_roots`] with the nonces held at the KT and AT levels. PR
/// nonces are not an input here: they enter the Principal Tree, above SR.
///
/// A principal with no keys (Dead, SPEC 11) has KR and AR only from the
/// nonces it still holds, and SR is the DR promoted alone when AR is absent
/// (`None` when there is no data either). `algs` is the set the roots hash
/// under; for the commit that leaves no key, the caller supplies the set in
/// force before the commit.
pub(crate) fn derive_state_roots_with_nonces(
    members: &[Leaf<'_>],
    dr: Option<&DataRoot>,
    nonces: &NonceSets,
    algs: &[HashAlg],
) -> Result<(Option<KeyRoot>, Option<AuthRoot>, Option<StateRoot>)> {
    // Each root is built from its components that exist (SPEC 3.7: empty
    // ones are omitted, a lone one is promoted). A principal with no keys
    // (Dead, SPEC 11) still holds its nonces, which only `nonce/delete`
    // removes (10.2), so KR and AR survive as long as a KT or AT nonce does.
    let kt_nonces = nonces.at_level(NonceLevel::Kt);
    let at_nonces = nonces.at_level(NonceLevel::At);
    let kr = if members.is_empty() && kt_nonces.is_empty() {
        None
    } else {
        Some(KeyTree::build_tree_with_nonces(members, &kt_nonces, algs)?.root(algs)?)
    };
    let ar = match &kr {
        Some(kr) => Some(AuthTree::build_tree_with_nonces(kr, &at_nonces, algs)?.root(algs)?),
        None if at_nonces.is_empty() => None,
        None => Some(AuthTree::build_nonces_only(&at_nonces, algs)?),
    };
    let sr = match (&ar, dr) {
        (Some(ar), dr) => Some(StateTree::build(ar, dr, algs)?),
        (None, Some(dr)) => Some(StateTree::build_data_only(dr, algs)?),
        (None, None) => None,
    };
    Ok((kr, ar, sr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmb(bytes: &[u8]) -> Thumbprint {
        Thumbprint::from_bytes(bytes.to_vec())
    }

    /// 32-byte nonce values, distinct per index.
    fn nonce_values(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut v = vec![0xEE; 32];
                v[..2].copy_from_slice(&(i as u16).to_be_bytes());
                v
            })
            .collect()
    }

    const PIN_KT_1: &str = "0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PIN_KT_256: &str = "b105a52d7742b86414e74bab99137409d59ee4e61ab2369cfd4d36ffc2d56826";
    const PIN_KT_MIXED_256: &str =
        "245553cd5fc13b6acf13dbbec6abb8eb5c42232f49bb402cbcfb6fd98cb3a674";
    const PIN_AT_256: &str = "1a68338dc3ff6d47d1d03456025a0bc836d51f57d3196b95851e0b5a35afe307";
    const PIN_KT_256_TWO_ALGS: &str = "13ee9c71c1db9594ebbb08461a071adc76ffc2483c2ee26406fe35b4e14ae1b0f0f1c73339c0967c8be70daec5ceacd1bf19463a558446a9b3b30609b0a3b9fe";
    const PIN_FP_KT_KEYS: u64 = 4_641_058_611_099_592_328;
    const PIN_FP_KT_MIXED: u64 = 10_905_821_410_972_046_323;
    const PIN_FP_AT: u64 = 14_728_611_661_474_525_612;

    /// Distinct 32-byte thumbprints, `n` of them, differing in the first two
    /// bytes so lexical order is index order.
    fn distinct_tmbs(n: usize) -> Vec<Thumbprint> {
        (0..n)
            .map(|i| {
                let mut v = vec![0xAA; 32];
                v[..2].copy_from_slice(&(i as u16).to_be_bytes());
                Thumbprint::from_bytes(v)
            })
            .collect()
    }

    /// FNV-1a over the concatenation of `parts`: a dependency-free,
    /// version-stable fingerprint, so one pinned value covers a root at many
    /// counts.
    fn fingerprint(parts: &[Vec<u8>]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in parts.iter().flatten() {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
        h
    }

    /// Counts the golden pins sample: every count to 20, every ninth, and
    /// the whole approach to the 256 boundary. (All 256 counts cost 40 s
    /// unoptimized: the folds are quadratic in total.)
    fn pinned_counts() -> impl Iterator<Item = usize> {
        (1..=256usize).filter(|n| *n <= 20 || n % 9 == 0 || *n >= 250)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Root, under the last of `algs`, of a KT of `keys` thumbprints and
    /// `nonces` nonces.
    fn kt_root(keys: usize, nonces: usize, algs: &[HashAlg]) -> Vec<u8> {
        let raw = distinct_tmbs(keys);
        let refs: Vec<Leaf<'_>> = raw
            .iter()
            .map(|t| (t.as_bytes(), HashAlg::Sha256))
            .collect();
        let nv = nonce_values(nonces);
        let nr: Vec<Leaf<'_>> = nv.iter().map(|n| (n.as_slice(), HashAlg::Sha256)).collect();
        let kt = KeyTree::build_tree_with_nonces(&refs, &nr, algs)
            .unwrap_or_else(|e| panic!("KT of {keys} keys + {nonces} nonces refused: {e:?}"));
        let last = algs[algs.len() - 1];
        kt.root(algs).unwrap().0.get(last).unwrap().to_vec()
    }

    fn at_root(nonces: usize, algs: &[HashAlg]) -> Vec<u8> {
        let t = tmb(&[0xAA; 32]);
        let kr = KeyTree::build(&[(t.as_bytes(), HashAlg::Sha256)], algs).unwrap();
        let nv = nonce_values(nonces);
        let nr: Vec<Leaf<'_>> = nv.iter().map(|n| (n.as_slice(), HashAlg::Sha256)).collect();
        let at = AuthTree::build_tree_with_nonces(&kr, &nr, algs)
            .unwrap_or_else(|e| panic!("AT of KR + {nonces} nonces refused: {e:?}"));
        at.root(algs).unwrap().0.get(algs[0]).unwrap().to_vec()
    }

    /// Backs "no root for 256 items or fewer changes" (AR1, SPEC 4) for KT
    /// and AT. Golden characterization, green on the pre-AR1 tree: the roots
    /// were captured before the cap was lifted. The fingerprints cover a
    /// fixed sample of counts on both sides of every small-size regime (see
    /// `pinned_counts`; KT keys only; KT one key plus n-1 nonces; AT KR plus
    /// n-1 nonces); the hex roots pin the ends so a fingerprint failure is
    /// diagnosable. Turns red if lifting the cap changes any root at or
    /// below 256 items (a re-leveled fold, a changed leaf order or a
    /// prefixed fold applied below the boundary). Unit level: reaching 256
    /// leaves by signed scenario is not cheap.
    #[test]
    fn arity_roots_up_to_256_items_are_pinned() {
        let a = [HashAlg::Sha256];
        let kt_keys: Vec<_> = pinned_counts().map(|n| kt_root(n, 0, &a)).collect();
        let kt_mixed: Vec<_> = pinned_counts().map(|n| kt_root(1, n - 1, &a)).collect();
        let at: Vec<_> = pinned_counts().map(|n| at_root(n - 1, &a)).collect();
        assert_eq!(hex(&kt_keys[0]), PIN_KT_1);
        assert_eq!(hex(kt_keys.last().unwrap()), PIN_KT_256);
        assert_eq!(hex(kt_mixed.last().unwrap()), PIN_KT_MIXED_256);
        assert_eq!(hex(at.last().unwrap()), PIN_AT_256);
        assert_eq!(fingerprint(&kt_keys), PIN_FP_KT_KEYS, "KT keys");
        assert_eq!(fingerprint(&kt_mixed), PIN_FP_KT_MIXED, "KT mixed");
        assert_eq!(fingerprint(&at), PIN_FP_AT, "AT nonces");
        let two = [HashAlg::Sha256, HashAlg::Sha512];
        assert_eq!(hex(&kt_root(256, 0, &two)), PIN_KT_256_TWO_ALGS);
    }

    /// Backs SPEC 4 ("Merkle tree primitive must support n-arity") at KT with
    /// nonces counted (SPEC 10.1): beyond 256 items (keys, nonces, or both)
    /// the tree builds; every size gives a distinct root that also differs
    /// from the 256-item root; the root does not depend on input order; and
    /// building the smaller set again gives the earlier root (removing items
    /// restores it). Turns red if: the cap stays or is off by one (build
    /// refused), items past 256 are dropped (root equals the 256 root), or
    /// the growth scheme depends on input order. Unit
    /// level, as above; the removal check on a stateful path is the PR test and the signed
    /// lifecycle in `spec_conformance.rs`.
    #[test]
    fn arity_kt_builds_beyond_256_and_removal_restores_the_root() {
        let a = [HashAlg::Sha256];
        let base = kt_root(256, 0, &a);
        let mut seen = vec![base.clone()];
        for (keys, nonces) in [(257, 0), (1, 256), (300, 300), (1000, 0), (2048, 0)] {
            let r = kt_root(keys, nonces, &a);
            assert!(!seen.contains(&r), "{keys} keys + {nonces} nonces collided");
            seen.push(r);
        }
        let raw = distinct_tmbs(1000);
        let fwd: Vec<Leaf<'_>> = raw.iter().map(|t| (t.as_bytes(), a[0])).collect();
        let rev: Vec<Leaf<'_>> = fwd.iter().rev().copied().collect();
        assert_eq!(
            KeyTree::build(&fwd, &a).unwrap().0.get(a[0]),
            KeyTree::build(&rev, &a).unwrap().0.get(a[0]),
            "root depends on input order"
        );
        assert_eq!(
            kt_root(256, 0, &a),
            base,
            "removal did not restore the root"
        );
    }

    /// Backs the same n-arity claim at AT, where KR takes one slot and the
    /// nonces follow it: 256, 300 and 1000 nonces build with distinct roots
    /// that differ from the 255-nonce (full-fold) root, and rebuilding with
    /// 255 nonces gives the earlier root. Turns red if the cap stays or
    /// items past the fold are dropped. Unit level, as above.
    #[test]
    fn arity_at_builds_beyond_256_and_removal_restores_the_root() {
        let a = [HashAlg::Sha256];
        let base = at_root(255, &a);
        let mut seen = vec![base.clone()];
        for n in [256, 300, 1000] {
            let r = at_root(n, &a);
            assert!(!seen.contains(&r), "KR + {n} nonces collided");
            seen.push(r);
        }
        assert_eq!(at_root(255, &a), base, "removal did not restore the root");
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
    use crate::state::{StateDigest, derive_auth_state};

    fn tmb(bytes: &[u8]) -> Thumbprint {
        Thumbprint::from_bytes(bytes.to_vec())
    }

    fn key(alg: HashAlg, tag: u8) -> Thumbprint {
        let len = crate::state::TaggedDigest::expected_len(alg);
        tmb(&vec![tag; len])
    }

    // -- c-oracle-kr --------------------------------------------------------

    // -- c-oracle-ar-sr -------------------------------------------------

    #[test]
    fn oracle_derive_state_roots_matches_derive_auth_state_single_algorithm() {
        let a = key(HashAlg::Sha256, 0x11);
        let b = key(HashAlg::Sha256, 0x22);
        let algs = [HashAlg::Sha256];

        let (old_kr, old_ar, old_sr) = derive_auth_state(&[&a, &b], None, &algs).unwrap();
        let leaves = [
            (a.as_bytes(), HashAlg::Sha256),
            (b.as_bytes(), HashAlg::Sha256),
        ];
        let (new_kr, new_ar, new_sr) = derive_state_roots(&leaves, None, &algs).unwrap();

        assert_eq!(old_kr.get(HashAlg::Sha256), new_kr.get(HashAlg::Sha256));
        assert_eq!(old_ar.get(HashAlg::Sha256), new_ar.get(HashAlg::Sha256));
        assert_eq!(old_sr.get(HashAlg::Sha256), new_sr.get(HashAlg::Sha256));
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

    /// Native digest length for `alg`.
    fn native_len(alg: HashAlg) -> usize {
        crate::state::TaggedDigest::expected_len(alg)
    }

    /// A digest's worth of random bytes, tagged with the algorithm it is
    /// native to (i.e. its length matches that algorithm's digest size).
    fn alg_and_native_bytes_strategy() -> impl Strategy<Value = (HashAlg, Vec<u8>)> {
        hash_alg_strategy().prop_flat_map(|alg| {
            (
                Just(alg),
                prop::collection::vec(any::<u8>(), native_len(alg)),
            )
        })
    }

    /// A random thumbprint, tagged with the algorithm it is native to.
    fn tagged_thumbprint_strategy() -> impl Strategy<Value = (HashAlg, Thumbprint)> {
        alg_and_native_bytes_strategy()
            .prop_map(|(alg, bytes)| (alg, Thumbprint::from_bytes(bytes)))
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
            let leaves: Vec<Leaf<'_>> =
                tagged.iter().map(|(alg, t)| (t.as_bytes(), *alg)).collect();
            let all_native = tagged.iter().all(|(alg, _)| *alg == target_alg);

            let old = compute_kr(&thumbprints, None, &[target_alg]).unwrap();
            let new = KeyTree::build(&leaves, &[target_alg]).unwrap();

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
            let new = KeyTree::build(&[(t.as_bytes(), alg)], &[alg]).unwrap();
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
            let leaves: Vec<Leaf<'_>> =
                tagged.iter().map(|(alg, t)| (t.as_bytes(), *alg)).collect();
            let kr = KeyTree::build(&leaves, &[target_alg]).unwrap();

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
        mapped.insert(
            hash_alg_to_u64(native_alg),
            bytes.to_vec().into_boxed_slice(),
        );
        mapped.insert(FOREIGN_ALG_ID, vec![0xFF; 32].into_boxed_slice());
        serde_json::to_vec(&mapped).unwrap()
    }

    #[test]
    fn kt_payload_inertness_foreign_algorithm_entry_does_not_affect_live_root() {
        let t = Thumbprint::from_bytes(vec![0xAA; 32]);
        let algs = [HashAlg::Sha256];
        let root_before = KeyTree::build(&[(t.as_bytes(), HashAlg::Sha256)], &algs).unwrap();

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
        let kr = KeyTree::build(&[(t.as_bytes(), HashAlg::Sha256)], &algs).unwrap();
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
        let kr = KeyTree::build(&[(t.as_bytes(), HashAlg::Sha256)], &algs).unwrap();
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
