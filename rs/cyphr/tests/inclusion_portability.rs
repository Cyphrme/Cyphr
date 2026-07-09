//! Proves F9 (forge issue #19): [`cyphr::verify_transaction_inclusion`] and
//! [`cyphr::verify_key_inclusion`] are genuinely portable — every test below
//! constructs its proof material via the crate's own tree-building blocks
//! (`CommitTrees`, `PrincipalTree`, `KeyTree`, `AuthTree`, `StateTree`) and
//! calls the free function directly. No `Principal` is ever constructed.

use std::collections::BTreeMap;

use coz::Thumbprint;
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::principal_tree::PrincipalTree;
use cyphr::semantic_tree::{AuthTree, KeyTree, StateTree};
use cyphr::{CommitRoot, CommitTrees, HashAlg, MaltHasher, MultihashDigest, StateRoot};

/// Serialize a transaction's per-algorithm variants into the same
/// `BTreeMap<alg_id, digest>` JSON payload the real commit path appends as a
/// leaf (mirrors `Principal`'s commit-application logic).
fn tx_leaf_payload(tr: &MultihashDigest) -> Vec<u8> {
    let mut mapped = BTreeMap::new();
    for (&alg, digest) in tr.variants() {
        mapped.insert(hash_alg_to_u64(alg), digest.clone());
    }
    serde_json::to_vec(&mapped).unwrap()
}

#[test]
fn transaction_inclusion_verifies_without_principal() {
    let alg = HashAlg::Sha256;
    let alg_id = hash_alg_to_u64(alg);

    // Build a Commit Tree directly (no Principal) and append two leaves.
    let commit_trees = CommitTrees::open(eml::MemoryStorage::new()).unwrap();
    commit_trees
        .add_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
        .unwrap();

    let tr = MultihashDigest::from_single(alg, vec![0xAB; 32]).unwrap();
    commit_trees.append(&tx_leaf_payload(&tr)).unwrap();
    let other_tr = MultihashDigest::from_single(alg, vec![0xCD; 32]).unwrap();
    commit_trees.append(&tx_leaf_payload(&other_tr)).unwrap();

    let index = 0u64;
    let tree_size = commit_trees.tree_size(alg_id).unwrap();
    let hop1_proof = commit_trees.inclusion_proof(alg_id, index).unwrap();
    let cr = CommitRoot(MultihashDigest::new(BTreeMap::from([(
        alg,
        commit_trees.root(alg_id).unwrap().into_boxed_slice(),
    )]))
    .unwrap());

    // Build a Principal Tree directly (no Principal), write SR and CR.
    let mut pt = PrincipalTree::new();
    let sr = StateRoot(MultihashDigest::from_single(alg, vec![0x11; 32]).unwrap());
    pt.set_sr(&sr, &[alg]).unwrap();
    pt.set_cr(&cr, &[alg]).unwrap();
    let pr = pt.pr(&[alg]).unwrap();
    let hop2_proof = pt.cr_inclusion_proof(alg_id).unwrap();

    let cr_bytes = cr.as_multihash().get(alg).unwrap();
    let pr_bytes = pr.0.get(alg).unwrap();

    assert!(cyphr::verify_transaction_inclusion(
        alg,
        &tr,
        &cyphr::TransactionHop1 {
            index,
            tree_size,
            proof: &hop1_proof,
            cr_root: cr_bytes,
        },
        &cyphr::TransactionHop2 {
            proof: &hop2_proof,
            pr_root: pr_bytes,
        },
    ));
}

#[test]
fn transaction_inclusion_rejects_forged_transaction_without_principal() {
    let alg = HashAlg::Sha256;
    let alg_id = hash_alg_to_u64(alg);

    let commit_trees = CommitTrees::open(eml::MemoryStorage::new()).unwrap();
    commit_trees
        .add_algorithm(alg_id, Box::new(MaltHasher::new(alg)))
        .unwrap();

    let tr = MultihashDigest::from_single(alg, vec![0xAB; 32]).unwrap();
    commit_trees.append(&tx_leaf_payload(&tr)).unwrap();

    let index = 0u64;
    let tree_size = commit_trees.tree_size(alg_id).unwrap();
    let hop1_proof = commit_trees.inclusion_proof(alg_id, index).unwrap();
    let cr = CommitRoot(MultihashDigest::new(BTreeMap::from([(
        alg,
        commit_trees.root(alg_id).unwrap().into_boxed_slice(),
    )]))
    .unwrap());

    let mut pt = PrincipalTree::new();
    let sr = StateRoot(MultihashDigest::from_single(alg, vec![0x11; 32]).unwrap());
    pt.set_sr(&sr, &[alg]).unwrap();
    pt.set_cr(&cr, &[alg]).unwrap();
    let pr = pt.pr(&[alg]).unwrap();
    let hop2_proof = pt.cr_inclusion_proof(alg_id).unwrap();

    let cr_bytes = cr.as_multihash().get(alg).unwrap();
    let pr_bytes = pr.0.get(alg).unwrap();

    // A transaction that never was appended must not verify at index 0.
    let forged = MultihashDigest::from_single(alg, vec![0xEE; 32]).unwrap();
    assert!(!cyphr::verify_transaction_inclusion(
        alg,
        &forged,
        &cyphr::TransactionHop1 {
            index,
            tree_size,
            proof: &hop1_proof,
            cr_root: cr_bytes,
        },
        &cyphr::TransactionHop2 {
            proof: &hop2_proof,
            pr_root: pr_bytes,
        },
    ));
}

/// Builds the 4-hop KT -> AR-node -> SR-node -> PT chain for `tmb_a` and
/// `tmb_b` directly (no Principal), returning `(hops for tmb_a, roots,
/// tmb_a, tmb_b)`.
fn build_key_inclusion_material(
    alg: HashAlg,
) -> (Vec<polydigest::LeafProof>, Vec<Vec<u8>>, Thumbprint, Thumbprint) {
    let alg_id = hash_alg_to_u64(alg);
    let tmb_a = Thumbprint::from_bytes(vec![0x01; 32]);
    let tmb_b = Thumbprint::from_bytes(vec![0x02; 32]);
    let thumbprints = vec![&tmb_a, &tmb_b];

    let kt = KeyTree::build_tree(&thumbprints, &[alg]).unwrap();
    let kr = kt.root(&[alg]).unwrap();
    let ar_node = AuthTree::build_tree(&kr, &[alg]).unwrap();
    let ar = ar_node.root(&[alg]).unwrap();
    let sr_node = StateTree::build_tree(&ar, None, &[alg]).unwrap();
    let sr = sr_node.root(&[alg]).unwrap();
    let mut pt = PrincipalTree::new();
    pt.set_sr(&sr, &[alg]).unwrap();
    let pr = pt.pr(&[alg]).unwrap();

    let mut sorted: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    sorted.sort();
    let index = sorted
        .iter()
        .position(|&b| b == tmb_a.as_bytes())
        .unwrap() as u64;

    let hops = vec![
        kt.thumbprint_inclusion_proof(alg_id, index).unwrap(),
        ar_node.kr_inclusion_proof(alg_id).unwrap(),
        sr_node.ar_inclusion_proof(alg_id).unwrap(),
        pt.sr_inclusion_proof(alg_id).unwrap(),
    ];
    let roots = vec![
        kr.0.get(alg).unwrap().to_vec(),
        ar.0.get(alg).unwrap().to_vec(),
        sr.0.get(alg).unwrap().to_vec(),
        pr.0.get(alg).unwrap().to_vec(),
    ];

    (hops, roots, tmb_a, tmb_b)
}

#[test]
fn key_inclusion_verifies_without_principal() {
    let alg = HashAlg::Sha256;
    let (hops, roots, tmb_a, _tmb_b) = build_key_inclusion_material(alg);
    let root_refs: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();

    assert!(cyphr::verify_key_inclusion(alg, &tmb_a, &hops, &root_refs));
}

/// The load-bearing regression this node exists to fix: hop material
/// genuinely valid for `tmb_a`'s tree position must NOT verify as proof of a
/// *different* thumbprint's inclusion, even though the hop chain and every
/// root reconstruct correctly. A free-function verifier that only checked
/// the hop chain (without binding hop 1's leaf to the claimed thumbprint)
/// would wrongly accept this.
#[test]
fn key_inclusion_rejects_mismatched_thumbprint_without_principal() {
    let alg = HashAlg::Sha256;
    let (hops, roots, _tmb_a, tmb_b) = build_key_inclusion_material(alg);
    let root_refs: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();

    assert!(!cyphr::verify_key_inclusion(alg, &tmb_b, &hops, &root_refs));
}
