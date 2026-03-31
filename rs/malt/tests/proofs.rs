//! Proof tests for DAOLFMT.
//!
//! Tests verify the proof invariants from the formal model:
//!
//! - **I-SOUND**: correctly generated inclusion proofs always verify
//! - **K-SOUND**: correctly generated consistency proofs always verify
//! - **I-SIZE / K-SIZE**: proof sizes are logarithmically bounded
//! - Rejection of tampered proofs and invalid inputs

mod common;

use common::{SimpleHasher, build_log};
use malt::{Log, TreeHasher, verify_consistency, verify_inclusion};

// ---------------------------------------------------------------------------
// I-SOUND: Generated inclusion proofs verify correctly.
// ---------------------------------------------------------------------------

/// I-SOUND: for every leaf in trees of size 1..=17, the generated
/// inclusion proof verifies against the tree root.
#[test]
fn i_sound_inclusion_proofs_verify() {
    for n in 1u64..=17 {
        let log = build_log(n);
        let root = log.root();
        for m in 0..n {
            let proof = log.inclusion_proof(m).expect("proof generation failed");
            // Compute leaf hash via the hasher directly (public API).
            let leaf_hash = SimpleHasher.leaf(format!("leaf-{m}").as_bytes());
            assert!(
                verify_inclusion(&SimpleHasher, &leaf_hash, &proof, &root),
                "I-SOUND failed: n={n}, m={m}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// K-SOUND: Generated consistency proofs verify correctly.
// ---------------------------------------------------------------------------

/// K-SOUND: for every valid (old_size, new_size) pair up to 17, the
/// generated consistency proof verifies against both roots.
#[test]
fn k_sound_consistency_proofs_verify() {
    for n in 2u64..=17 {
        let log = build_log(n);
        let new_root = log.root();
        for m in 1..n {
            let proof = log.consistency_proof(m).expect("proof generation failed");
            // Compute old root by building a separate log of size m (public API).
            let old_log = build_log(m);
            let old_root = old_log.root();
            assert!(
                verify_consistency(&SimpleHasher, &proof, &old_root, &new_root),
                "K-SOUND failed: m={m}, n={n}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Rejection tests: tampered proofs must fail.
// ---------------------------------------------------------------------------

/// Inclusion verification rejects a wrong leaf hash.
#[test]
fn inclusion_rejects_wrong_leaf() {
    let log = build_log(8);
    let root = log.root();
    let proof = log.inclusion_proof(3).unwrap();
    let wrong_hash = SimpleHasher.leaf(b"not-the-right-leaf");
    assert!(
        !verify_inclusion(&SimpleHasher, &wrong_hash, &proof, &root),
        "should reject wrong leaf hash"
    );
}

/// Inclusion verification rejects a wrong root.
#[test]
fn inclusion_rejects_wrong_root() {
    let log = build_log(8);
    let proof = log.inclusion_proof(3).unwrap();
    let leaf_hash = SimpleHasher.leaf(b"leaf-3");
    let wrong_root = SimpleHasher.leaf(b"wrong-root");
    assert!(
        !verify_inclusion(&SimpleHasher, &leaf_hash, &proof, &wrong_root),
        "should reject wrong root"
    );
}

/// Consistency verification rejects a wrong old root.
#[test]
fn consistency_rejects_wrong_old_root() {
    let log = build_log(8);
    let new_root = log.root();
    let proof = log.consistency_proof(4).unwrap();
    let wrong_old_root = SimpleHasher.leaf(b"wrong-old-root");
    assert!(
        !verify_consistency(&SimpleHasher, &proof, &wrong_old_root, &new_root),
        "should reject wrong old root"
    );
}

/// Consistency verification rejects a wrong new root.
#[test]
fn consistency_rejects_wrong_new_root() {
    let log = build_log(8);
    let proof = log.consistency_proof(4).unwrap();
    let old_log = build_log(4);
    let old_root = old_log.root();
    let wrong_new_root = SimpleHasher.leaf(b"wrong-new-root");
    assert!(
        !verify_consistency(&SimpleHasher, &proof, &old_root, &wrong_new_root),
        "should reject wrong new root"
    );
}

// ---------------------------------------------------------------------------
// Proof size bounds.
// ---------------------------------------------------------------------------

/// I-SIZE: inclusion proof path length ≤ ceil(log2(n)).
#[test]
fn inclusion_proof_size_bounded() {
    for n in 1u64..=33 {
        let log = build_log(n);
        let max_path_len = ceil_log2(n);
        for m in 0..n {
            let proof = log.inclusion_proof(m).unwrap();
            assert!(
                proof.path.len() <= max_path_len,
                "I-SIZE: n={n}, m={m}, path_len={}, max={}",
                proof.path.len(),
                max_path_len
            );
        }
    }
}

/// K-SIZE: consistency proof path length ≤ ceil(log2(n)) + 1.
#[test]
fn consistency_proof_size_bounded() {
    for n in 2u64..=33 {
        let log = build_log(n);
        let max_path_len = ceil_log2(n) + 1;
        for m in 1..n {
            let proof = log.consistency_proof(m).unwrap();
            assert!(
                proof.path.len() <= max_path_len,
                "K-SIZE: m={m}, n={n}, path_len={}, max={}",
                proof.path.len(),
                max_path_len
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Error cases.
// ---------------------------------------------------------------------------

/// Inclusion proof on an empty tree returns EmptyTree error.
#[test]
fn inclusion_proof_empty_tree() {
    let log = Log::new(SimpleHasher);
    assert!(log.inclusion_proof(0).is_err());
}

/// Inclusion proof with out-of-bounds index returns error.
#[test]
fn inclusion_proof_out_of_bounds() {
    let log = build_log(5);
    assert!(log.inclusion_proof(5).is_err());
    assert!(log.inclusion_proof(100).is_err());
}

/// Consistency proof on an empty tree returns EmptyTree error.
#[test]
fn consistency_proof_empty_tree() {
    let log = Log::new(SimpleHasher);
    assert!(log.consistency_proof(0).is_err());
}

/// Consistency proof with old_size=0 returns error.
#[test]
fn consistency_proof_old_size_zero() {
    let log = build_log(5);
    assert!(log.consistency_proof(0).is_err());
}

/// Consistency proof with old_size >= new_size returns error.
#[test]
fn consistency_proof_old_size_ge_new_size() {
    let log = build_log(5);
    assert!(log.consistency_proof(5).is_err());
    assert!(log.consistency_proof(6).is_err());
}

/// Verify inclusion rejects index >= tree_size.
#[test]
fn verify_inclusion_rejects_bad_index() {
    use malt::InclusionProof;
    let proof = InclusionProof {
        index: 5,
        tree_size: 5,
        path: vec![],
    };
    let leaf_hash = SimpleHasher.leaf(b"x");
    let root = SimpleHasher.empty();
    assert!(!verify_inclusion(&SimpleHasher, &leaf_hash, &proof, &root));
}

/// Verify consistency rejects old_size=0.
#[test]
fn verify_consistency_rejects_old_size_zero() {
    use malt::ConsistencyProof;
    let proof = ConsistencyProof {
        old_size: 0,
        new_size: 5,
        path: vec![],
    };
    let root = SimpleHasher.empty();
    assert!(!verify_consistency(&SimpleHasher, &proof, &root, &root));
}

/// Verify consistency rejects old_size >= new_size.
#[test]
fn verify_consistency_rejects_old_ge_new() {
    use malt::ConsistencyProof;
    let proof = ConsistencyProof {
        old_size: 5,
        new_size: 5,
        path: vec![],
    };
    let root = SimpleHasher.empty();
    assert!(!verify_consistency(&SimpleHasher, &proof, &root, &root));
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn ceil_log2(n: u64) -> usize {
    if n <= 1 {
        return 0;
    }
    (u64::BITS - (n - 1).leading_zeros()) as usize
}
