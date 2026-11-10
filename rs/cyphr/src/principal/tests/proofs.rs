//! Inclusion and consistency proof tests.

use std::collections::BTreeMap;

use super::*;
use crate::multihash::MultihashDigest;

// ========================================================================
// MALT Proof Generation Tests
// ========================================================================

// ========================================================================
// Two-step transaction inclusion verification (composite hop 1 + hop 2)
// ========================================================================

/// Helper: build a multi-algorithm principal (ES256/SHA-256 +
/// Ed25519/SHA-512) with N commits via key/create transactions —
/// mirrors `build_principal_with_commits` but drives two active hash
/// algorithms from genesis, so per-algorithm coverage is observable (a
/// single-algorithm principal cannot distinguish `root(alg_id)` from
/// `combined_root()`, per `multi_alg_genesis_pg_equals_sr_for_every_algorithm`).
fn build_multi_alg_principal_with_commits(n_commits: usize) -> (Principal, Vec<Key>) {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let mut keys = vec![make_test_key(0x01), make_test_key_ed25519(0x02)];
    let mut principal = Principal::explicit(keys.clone()).unwrap();
    principal.genesis_test().unwrap();
    let signer = keys[0].tmb().clone();

    for i in 0..n_commits {
        let new_key = make_test_key((i + 3) as u8);

        let cz = ParsedCoz {
            kind: CozKind::KeyCreate {
                id: new_key.tmb().clone(),
            },
            signer: signer.clone(),
            now: (1000 + (i as i64 + 1) * 1000),
            czd: Czd::from_bytes(vec![0xC0 + i as u8; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        principal
            .apply_transaction_test(cz, Some(new_key.clone()))
            .unwrap();
        keys.push(new_key);
    }

    (principal, keys)
}

/// c2/a2 — the composite two-step verification accepts every real
/// committed transaction, under every active hash algorithm, for a
/// multi-algorithm principal — proving the transaction is really
/// included under the *current* Principal Root, not just under some CR.
#[test]
fn two_step_verification_accepts_every_commit_every_algorithm() {
    let (principal, _keys) = build_multi_alg_principal_with_commits(4);

    // EML hashes every leaf under every active algorithm, so each commit's
    // TR carries both variants and each is checked against its own tree. The
    // count guards against the loop degenerating (or a variant going null,
    // which would hash to a constant on both sides and pass vacuously).
    let mut checked = 0;
    for alg in [HashAlg::Sha256, HashAlg::Sha512] {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let size = principal.commit_trees().tree_size(alg_id).unwrap();
        for i in 0..size {
            let tr = principal.commits().nth(i as usize).unwrap().tr().0.clone();
            assert!(
                tr.contains(alg),
                "commit {i}'s TR has no {alg:?} variant for an active algorithm"
            );
            assert!(
                principal.verify_transaction_inclusion(alg, i, &tr).unwrap(),
                "composite verification failed for alg {alg:?} index {i}"
            );
            checked += 1;
        }
    }
    assert_eq!(
        checked, 10,
        "2 algorithms x (genesis + 4) commits must all be checked"
    );
}

/// SPEC 12.1 / EML: a TR lacking the algorithm being verified is not
/// evidence of inclusion under it. Scenario: a genuine commit's TR with the
/// SHA-512 variant stripped is claimed at its real index under SHA-512.
/// Turns red if verification returns true (a stripped TR hashes to the
/// null constant, which must never stand in for the real leaf).
#[test]
fn stripped_variant_never_verifies() {
    let (principal, _keys) = build_multi_alg_principal_with_commits(3);
    for i in 0..3u64 {
        let full = principal.commits().nth(i as usize).unwrap().tr().0.clone();
        let stripped = MultihashDigest::from_single(
            HashAlg::Sha256,
            full.get(HashAlg::Sha256).unwrap().to_vec(),
        )
        .unwrap();
        assert!(
            !principal
                .verify_transaction_inclusion(HashAlg::Sha512, i, &stripped)
                .unwrap(),
            "a TR without the SHA-512 variant verified at index {i}"
        );
    }
}

/// c3/a3 — a genuine transaction claimed at the wrong index must be
/// rejected (not silently accepted, not panic).
#[test]
fn two_step_verification_rejects_wrong_index() {
    let (principal, _keys) = build_multi_alg_principal_with_commits(3);
    let alg = HashAlg::Sha256;

    // tr0 genuinely sits at index 0, not 1.
    let tr0 = principal.commits().next().unwrap().tr().0.clone();
    let ok = principal
        .verify_transaction_inclusion(alg, 1, &tr0)
        .unwrap();
    assert!(!ok, "wrong index must not verify");
}

/// c3/a3 — a forged transaction (wrong claimed leaf value) must be
/// rejected at the claimed index.
#[test]
fn two_step_verification_rejects_forged_transaction() {
    let (principal, _keys) = build_multi_alg_principal_with_commits(3);
    let alg = HashAlg::Sha256;

    let forged = MultihashDigest::from_single(alg, vec![0xEE; 32]).unwrap();
    let ok = principal
        .verify_transaction_inclusion(alg, 0, &forged)
        .unwrap();
    assert!(!ok, "forged transaction must not verify");
}

// ========================================================================
// Key-membership inclusion verification (chained 4-hop NodePath)
// ========================================================================

/// c3/a3 — the chained 4-hop key-membership proof accepts every active
/// key, under every active hash algorithm, for a multi-algorithm
/// principal — proving each key's thumbprint is really included under
/// the *current* Principal Root via KT -> AR-node -> SR-node -> PT.
#[test]
fn key_inclusion_accepts_every_active_key_every_algorithm() {
    let (principal, keys) = build_multi_alg_principal_with_commits(4);

    for alg in [HashAlg::Sha256, HashAlg::Sha512] {
        for key in &keys {
            assert!(
                principal.verify_key_inclusion(alg, key.tmb()).unwrap(),
                "key inclusion failed for alg {alg:?} tmb {:?}",
                key.tmb()
            );
        }
    }
}

/// c3/a3 — a claimed thumbprint that does not name any currently active
/// key cannot even produce a proof (there is no lexical-sort position to
/// chain from), so generation itself must reject it.
#[test]
fn key_inclusion_rejects_thumbprint_of_inactive_key() {
    let (principal, _keys) = build_multi_alg_principal_with_commits(2);
    let alg = HashAlg::Sha256;

    let never_active = Thumbprint::from_bytes(vec![0xEE; 32]);
    let result = principal.key_inclusion_proof(alg, &never_active);
    assert!(
        result.is_err(),
        "an inactive thumbprint must not produce a proof"
    );
}

/// c3/a3 — a genuine proof for a real key, with hop 1's proven leaf
/// value tampered (as if a different thumbprint were being claimed at
/// that same lexical position), must be rejected by verification even
/// though every other hop and bridge in the chain is untouched and
/// genuinely valid.
#[test]
fn key_inclusion_rejects_forged_leaf_at_real_position() {
    let (principal, keys) = build_multi_alg_principal_with_commits(2);
    let alg = HashAlg::Sha256;
    let genuine_tmb = keys[0].tmb().clone();

    let mut path = principal.key_inclusion_proof(alg, &genuine_tmb).unwrap();
    path.hops[0].proof.leaf_hash = vec![0xEE; 32];

    let hasher = MaltHasher::new(alg);
    let kr_bytes = principal
        .key_root()
        .expect("a live principal has a KR")
        .get(alg)
        .unwrap();
    let ar_bytes = principal
        .auth_root()
        .expect("a live principal has an AR")
        .get(alg)
        .unwrap();
    let sr_bytes = principal.sr().unwrap().get(alg).unwrap();
    let pr_bytes = principal.pr().get(alg).unwrap();

    assert!(
        !path.verify(&hasher, &[kr_bytes, ar_bytes, sr_bytes, pr_bytes]),
        "a forged hop-1 leaf value must not verify"
    );
}

/// c3/a3 — the promotion/genesis case: a single-key implicit-genesis
/// principal, where KT, AR-node, SR-node, and PT are all simultaneously
/// 1-cell promotions (KR == tmb, AR == KR, SR == AR, PR == SR, all
/// verbatim). The chained proof must still verify correctly through
/// every "skip" hop without any special-case code, since
/// [`NodePath::verify`] treats a
/// zero-sibling skeleton identically to any other.
#[test]
fn key_inclusion_verifies_through_genesis_promotion_chain() {
    let key = make_test_key(0xAA);
    let tmb = key.tmb().clone();
    let principal = Principal::implicit(key).unwrap();
    let alg = principal.hash_alg();

    // Every intermediate level is a verbatim promotion at genesis.
    assert_eq!(
        principal
            .key_root()
            .expect("a live principal has a KR")
            .get(alg),
        Some(tmb.as_bytes())
    );
    assert_eq!(
        principal
            .auth_root()
            .expect("a live principal has an AR")
            .get(alg),
        Some(tmb.as_bytes())
    );
    assert_eq!(principal.sr().unwrap().get(alg), Some(tmb.as_bytes()));
    assert_eq!(principal.pr().get(alg), Some(tmb.as_bytes()));

    assert!(principal.verify_key_inclusion(alg, &tmb).unwrap());
}

/// issue #19 — [`Principal::sr_inclusion_proof`] is the public
/// accessor a portable, third-party verifier needs for hop 4 (SR-in-PT)
/// of the chained key-inclusion proof, since [`Principal::pt`] itself is
/// crate-internal. It must return exactly the same leaf proof
/// [`Principal::key_inclusion_proof`] already generates internally, and
/// that proof must verify standalone against the current PR.
#[test]
fn sr_inclusion_proof_matches_hop_four() {
    let (principal, keys) = build_multi_alg_principal_with_commits(3);
    let alg = HashAlg::Sha256;
    let tmb = keys[0].tmb().clone();

    let path = principal.key_inclusion_proof(alg, &tmb).unwrap();
    let hop4 = principal
        .sr_inclusion_proof(alg)
        .expect("alg is registered on this principal's PT");

    assert_eq!(
        hop4.leaf_hash, path.hops[3].proof.leaf_hash,
        "the accessor must return the exact hop 4 key_inclusion_proof already generates"
    );

    let hasher = MaltHasher::new(alg);
    let pr_bytes = principal.pr().get(alg).unwrap();
    let skeleton = polydigest::rebalanced_skeleton(hop4.tree_size, hop4.arity, hop4.index)
        .expect("valid skeleton");
    assert!(
        hop4.verify(&hasher, &skeleton, pr_bytes),
        "sr_inclusion_proof must verify standalone against the current PR"
    );
}

/// c3/a3 — the bridge loop itself, isolated from the hop-verify loop.
///
/// Splices hop 0 from principal A's genuine key-inclusion chain with
/// hops 1..3 from principal B's genuine (unrelated) chain. Every
/// spliced hop is independently checked below to verify `true` against
/// its own matched root — proving the hop-verify loop alone would
/// accept this `NodePath` and cannot be what rejects it. Only the
/// bridge loop — hop `i`'s proven leaf value must equal hop `i-1`'s
/// root — can catch that hop 1's proven leaf (B's KR) does not match
/// hop 0's root (A's KR, a different key's tmb since A and B never
/// shared a genesis key). `key_inclusion_rejects_forged_leaf_at_real_position`
/// (above) instead fails in the hop-verify loop before the bridge loop
/// ever runs, so it does not cover this.
#[test]
fn key_inclusion_bridge_rejects_spliced_hops_that_individually_verify() {
    let key_a = make_test_key(0xAA);
    let tmb_a = key_a.tmb().clone();
    let principal_a = Principal::implicit(key_a).unwrap();

    let key_b = make_test_key(0xBB);
    let tmb_b = key_b.tmb().clone();
    let principal_b = Principal::implicit(key_b).unwrap();

    let alg = principal_a.hash_alg();
    assert_eq!(alg, principal_b.hash_alg());

    let path_a = principal_a.key_inclusion_proof(alg, &tmb_a).unwrap();
    let path_b = principal_b.key_inclusion_proof(alg, &tmb_b).unwrap();

    let kr_a = principal_a
        .key_root()
        .expect("a live principal has a KR")
        .get(alg)
        .unwrap();
    let ar_b = principal_b
        .auth_root()
        .expect("a live principal has an AR")
        .get(alg)
        .unwrap();
    let sr_b = principal_b.sr().unwrap().get(alg).unwrap();
    let pr_b = principal_b.pr().get(alg).unwrap();
    assert_ne!(
        kr_a,
        principal_b
            .key_root()
            .expect("a live principal has a KR")
            .get(alg)
            .unwrap(),
        "test fixture requires A and B to have genuinely different KRs"
    );

    let spliced = NodePath {
        hops: vec![
            path_a.hops[0].clone(),
            path_b.hops[1].clone(),
            path_b.hops[2].clone(),
            path_b.hops[3].clone(),
        ],
    };

    let hasher = MaltHasher::new(alg);
    let roots: [&[u8]; 4] = [kr_a, ar_b, sr_b, pr_b];

    // The hop-verify loop alone accepts every spliced hop: each proof
    // is genuine and matched against its own originating root here.
    for (hop, &root) in spliced.hops.iter().zip(roots.iter()) {
        let skeleton =
            polydigest::rebalanced_skeleton(hop.proof.tree_size, hop.proof.arity, hop.proof.index)
                .unwrap();
        assert!(
            hop.proof.verify(&hasher, &skeleton, root),
            "each spliced hop must verify in isolation against its own root"
        );
    }

    // Only the bridge loop can reject the chain as a whole: hop 1's
    // proven leaf (B's KR) does not equal hop 0's root (A's KR).
    assert!(
        !spliced.verify(&hasher, &roots),
        "spliced hops that individually verify must still be rejected by the bridge linkage check"
    );
}

/// Backs SPEC 12.1 (EML log): a consistency proof from every earlier commit count verifies against
/// the current commit-log root. Unit: no server route or scenario serves consistency proofs, so
/// only the library API can reach it.
#[test]
fn consistency_proof_verifies() {
    let (principal, _keys) = build_principal_with_commits(5);

    let alg = principal.hash_alg();
    let alg_id = crate::commit_root::hash_alg_to_u64(alg);
    let new_root = principal.commit_trees().root(alg_id).unwrap();
    let hasher = MaltHasher::new(alg);

    // Build a reference EML log to capture intermediate roots.
    let mut ref_log =
        futures::executor::block_on(eml::from_storage(eml::MemoryStorage::new(), Vec::new()))
            .unwrap();
    futures::executor::block_on(ref_log.add_algorithm(alg_id, Box::new(MaltHasher::new(alg))))
        .unwrap();
    let mut roots = Vec::new();
    for commit in principal.commits() {
        let mut mapped_variants = BTreeMap::new();
        for (&a, val) in commit.tr().0.variants() {
            let a_id = crate::commit_root::hash_alg_to_u64(a);
            mapped_variants.insert(a_id, val.clone());
        }
        let tr_bytes = serde_json::to_vec(&mapped_variants).unwrap();
        futures::executor::block_on(ref_log.append_leaf(&tr_bytes)).unwrap();
        roots.push(ref_log.root_for(alg_id).unwrap());
    }

    // Verify consistency from each prior size to current.
    let size = principal.commit_trees().tree_size(alg_id).unwrap();
    for old_size in 1..size {
        let proof = principal.consistency_proof(alg, old_size).unwrap();
        let old_root = &roots[(old_size - 1) as usize];
        assert!(
            crate::verify_consistency(&hasher, old_size, size, &proof, old_root, &new_root),
            "consistency proof failed for old_size {old_size}"
        );
    }
}

/// Backs the proof API contract (SPEC 12.1): an out-of-range index, a
/// zero or too-large `old_size`, and an algorithm the principal never used
/// are typed refusals, not panics.
/// Unit: the server only forwards well-formed requests, so no scenario
/// reaches these arguments.
#[test]
fn proof_requests_out_of_range_are_refused() {
    let (principal, _keys) = build_principal_with_commits(3);
    let alg = principal.hash_alg();

    assert!(principal.inclusion_proof(alg, 4).is_err());
    assert!(principal.inclusion_proof(alg, 999).is_err());
    assert!(principal.consistency_proof(alg, 0).is_err());
    assert!(principal.consistency_proof(alg, 4).is_err());
    // SHA-384 was never introduced (all test keys use ES256/SHA-256).
    assert!(principal.inclusion_proof(HashAlg::Sha384, 0).is_err());
    assert!(principal.consistency_proof(HashAlg::Sha384, 1).is_err());
    assert!(principal.sr_inclusion_proof(HashAlg::Sha384).is_none());
}
