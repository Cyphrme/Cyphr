//! Portable inclusion-proof verification (F9 / forge issue #19).
//!
//! [`crate::principal::Principal::verify_transaction_inclusion`] and
//! [`crate::principal::Principal::verify_key_inclusion`] are `&self` methods
//! that read their trusted root (CR/PR) directly from the live `Principal`,
//! so a caller can only verify a proof against a `Principal` it already fully
//! owns and trusts. The free functions here take the same proof material and
//! a caller-supplied trusted root as plain parameters instead — genuinely
//! callable with no `Principal`, no engine, and no server dependency. The
//! `&self` methods are thin wrappers over these (see their bodies).

use std::collections::BTreeMap;

use coz::Thumbprint;
use eml::Hasher as _;

use crate::commit_root::{MaltHasher, hash_alg_to_u64};
use crate::multihash::MultihashDigest;
use crate::principal::{NodePath, NodePathHop};
use crate::state::HashAlg;

/// The canonical per-algorithm digest of a thumbprint's raw bytes: the exact
/// value [`crate::semantic_tree::KeyTree`] stores as `alg`'s entry in a KT
/// leaf's cell payload (see `semantic_tree::serialize_converted`) — verbatim
/// if `alg` is the thumbprint's own native algorithm (inferred from its
/// length), else `alg`'s hash of the raw bytes.
///
/// Returns `None` for a byte length that names no known algorithm — mirrors
/// `serialize_converted`'s own rejection of an unrecognized digest length
/// rather than silently hashing it under `alg` anyway.
fn canonical_thumbprint_digest(bytes: &[u8], alg: HashAlg) -> Option<Vec<u8>> {
    let native = crate::state::infer_alg_from_len(bytes.len())?;
    Some(if native == alg {
        bytes.to_vec()
    } else {
        crate::state::hash_bytes(alg, bytes)
    })
}

/// Hop-1 witness material: `tr`'s claimed inclusion, at commit `index`, in a
/// hash-`alg` Commit Root (CR) tree of size `tree_size` — a MALT inclusion
/// proof. `index` and `tree_size` are trusted parameters (see
/// [`crate::commit_root::verify_inclusion`]'s trust contract): they must come
/// from an authenticated source, never the proof.
pub struct TransactionHop1<'a> {
    /// Claimed commit index.
    pub index: u64,
    /// Trusted size of the Commit Root tree.
    pub tree_size: u64,
    /// The MALT inclusion proof itself.
    pub proof: &'a eml::InclusionProof,
    /// The trusted Commit Root, for `alg`.
    pub cr_root: &'a [u8],
}

/// Hop-2 witness material: the Commit Root's claimed inclusion — as PT cell
/// 1's payload — in the Principal Root (PR), for hash algorithm `alg`.
pub struct TransactionHop2<'a> {
    /// The self-contained leaf proof itself.
    pub proof: &'a polydigest::LeafProof,
    /// The trusted Principal Root, for `alg`.
    pub pr_root: &'a [u8],
}

/// Verify that transaction `tr` is included under `hop2`'s trusted Principal
/// Root — by chaining two independent leaf proofs, exactly as
/// [`crate::principal::Principal::verify_transaction_inclusion`] does, but
/// with every trusted root and every proof supplied as plain parameters
/// instead of read from a live `Principal`.
///
/// 1. **Hop 1** — `tr` included in the Commit Root (`hop1.cr_root`).
/// 2. **Hop 2** — `hop1.cr_root`, as PT cell 1's payload, included in
///    `hop2.pr_root`.
///
/// The hops are bridged explicitly: hop 2's proven leaf value must equal
/// `hop1.cr_root` — otherwise the two hops would each verify independently
/// true facts about two *unrelated* trees.
#[must_use]
pub fn verify_transaction_inclusion(
    alg: HashAlg,
    tr: &MultihashDigest,
    hop1: &TransactionHop1<'_>,
    hop2: &TransactionHop2<'_>,
) -> bool {
    let hasher = MaltHasher::new(alg);

    let mut mapped = BTreeMap::new();
    for (&a, digest) in tr.variants() {
        mapped.insert(hash_alg_to_u64(a), digest.clone());
    }
    let Ok(serialized) = serde_json::to_vec(&mapped) else {
        return false;
    };
    let leaf_hash = hasher.leaf(&serialized);

    let hop1_ok = crate::verify_inclusion(
        &hasher,
        &leaf_hash,
        hop1.index,
        hop1.tree_size,
        hop1.proof,
        hop1.cr_root,
    );

    let Some(hop2_skeleton) = polydigest::rebalanced_skeleton(
        hop2.proof.tree_size,
        hop2.proof.arity,
        hop2.proof.index,
    ) else {
        return false;
    };
    let hop2_ok = hop2.proof.verify(&hasher, &hop2_skeleton, hop2.pr_root);

    let bridge_ok = hop2.proof.leaf_hash == hop1.cr_root;

    hop1_ok && hop2_ok && bridge_ok
}

/// Verify that the key with thumbprint `tmb` is included under trusted root
/// `roots[roots.len() - 1]` (the Principal Root), for hash algorithm `alg` —
/// a portable generalization of
/// [`crate::principal::Principal::verify_key_inclusion`]'s 4-hop
/// thumbprint -> KT -> AR-node -> SR-node -> PT chain, with every trusted
/// root and every hop's proof supplied as plain parameters instead of read
/// from a live `Principal`.
///
/// `hops` and `roots` are ordered leaf-to-root, one root per hop (KR, AR, SR,
/// PR for the concrete 4-hop chain). Unlike [`NodePath::verify`] — which
/// only proves "some leaf at `hops[0]`'s position sits under `roots`", not
/// "thumbprint `tmb` is included" (safe only because its sole internal
/// caller always generates `hops[0]` fresh from `tmb`'s own real tree
/// position) — this function additionally binds `hops[0]`'s proven leaf to
/// `tmb`'s own canonical digest before checking the chain, which a genuinely
/// portable verifier — one that cannot regenerate the hop material itself —
/// must do to actually prove the claimed identity rather than merely a
/// self-consistent but unbound chain.
#[must_use]
pub fn verify_key_inclusion(
    alg: HashAlg,
    tmb: &Thumbprint,
    hops: &[polydigest::LeafProof],
    roots: &[&[u8]],
) -> bool {
    let Some(first_hop) = hops.first() else {
        return false;
    };
    let Some(expected_leaf) = canonical_thumbprint_digest(tmb.as_bytes(), alg) else {
        return false;
    };
    if first_hop.leaf_hash != expected_leaf {
        return false;
    }

    let path = NodePath {
        hops: hops
            .iter()
            .cloned()
            .map(|proof| NodePathHop { proof })
            .collect(),
    };
    let hasher = MaltHasher::new(alg);
    path.verify(&hasher, roots)
}
