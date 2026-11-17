//! Extension proofs (SPEC 4.4: CR is the append-only Merkle root of all
//! commits, and clients obtain consistency proofs over it): "the offered
//! tip extends the tip I hold" is checked from the held, already verified
//! commit root and the offered size and root, which are never read from the
//! proof itself.
//!
//! Chains are real `cyphr` principals; the oracle for "extends" is equality
//! of the two logs' roots at the older size, which the verifier never sees.

mod common;

use common::*;
use cyphr::Principal;
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::eml::MemoryStorage;
use cyphr_client::{Extension, ExtensionFailure, confirm_extension, verify_extension};
use serde_json::json;

const T0: i64 = 1_700_000_000;
const LONGEST: usize = 24;

/// A chain of `n` commits after genesis built from `keys`, the first
/// `shared` of them on `keys`, the rest on `rival` keys, one snapshot of
/// the principal per tree size on the way.
async fn grown<'a>(
    g: &'a Kp,
    keys: &[Kp],
    rival: &[Kp],
    shared: usize,
) -> (Chain<'a>, Vec<Principal<MemoryStorage>>) {
    let mut chain = Chain::new(g).await;
    let mut at_size = vec![chain.principal.fork().await.expect("fork")];
    for i in 0..keys.len() {
        let key = if i < shared { &keys[i] } else { &rival[i] };
        chain.commit(key, T0 + 100 + i as i64).await;
        at_size.push(chain.principal.fork().await.expect("fork"));
    }
    (chain, at_size)
}

fn tree_size(p: &Principal<MemoryStorage>) -> u64 {
    let alg = hash_alg_to_u64(p.hash_alg());
    p.commit_trees().tree_size(alg).expect("registered")
}

/// Backs: for every older size the held principal can stand at, the proof a
/// longer chain serves verifies, and holds at most 2 * (floor(log2 m) + 1)
/// hashes for a log of m commits: the boundary peak, the path lifting it
/// into the peak that absorbed it (at most floor(log2 m) siblings), and the
/// new frontier (at most floor(log2 m) + 1 peaks). A tighter
/// ceil(log2 m) + 1 does not hold of this proof shape (1 -> 25 takes 8).
#[tokio::test]
async fn an_honest_extension_verifies_with_a_logarithmic_proof() {
    let g = kp();
    let keys: Vec<Kp> = (0..LONGEST).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], LONGEST).await;
    let new = &chain.principal;
    let m = tree_size(new);
    for held in &at_size {
        let n = tree_size(held);
        if n == 0 || n >= m {
            continue;
        }
        let ext = Extension::of(new, n).await.expect("proof");
        assert_eq!(verify_extension(held, &ext), Ok(()), "{n} -> {m}");
        let nodes = 1
            + ext
                .proof
                .peak_path
                .iter()
                .map(|s| s.siblings.len())
                .sum::<usize>()
            + ext.proof.new_peaks.len();
        let bound = 2 * (m.ilog2() as usize + 1);
        assert!(nodes <= bound, "{n} -> {m}: {nodes} hashes > {bound}");
    }
}

/// Backs: a pair of chains that agree up to a position and differ after it
/// verifies exactly for the older sizes inside the shared prefix; a fork is
/// never reported as an extension.
#[tokio::test]
async fn a_forked_pair_fails_exactly_past_the_shared_prefix() {
    let g = kp();
    let keys: Vec<Kp> = (0..LONGEST).map(|_| kp()).collect();
    let rival: Vec<Kp> = (0..LONGEST).map(|_| kp()).collect();
    for shared in [0, 1, 5, 11] {
        let (a, a_at) = grown(&g, &keys, &rival, LONGEST).await;
        let (b, _) = grown(&g, &keys, &rival, shared).await;
        let m = tree_size(&b.principal);
        for held in &a_at {
            let n = tree_size(held);
            if n == 0 || n >= m {
                continue;
            }
            let ext = Extension::of(&b.principal, n).await.expect("proof");
            let alg = hash_alg_to_u64(a.principal.hash_alg());
            let agree = a.principal.commit_trees().root_at(alg, n).await
                == b.principal.commit_trees().root_at(alg, n).await;
            let verdict = verify_extension(held, &ext);
            assert_eq!(verdict.is_ok(), agree, "shared {shared}, held {n}: {verdict:?}");
            if !agree {
                assert_eq!(verdict, Err(ExtensionFailure::NotAnExtension));
            }
        }
    }
}

/// Backs: the verifier takes the older size and root from the principal it
/// holds and the newer size and root from the offer, never from the proof.
/// An offer that states another root than the log the proof was made over,
/// or a size with another frontier shape, is refused, though the proof is
/// untouched. A Commit Root does not commit to its size (a size with the
/// same frontier shape, one more commit here, verifies), so the stated size
/// is held to the replayed log by `confirm_extension` instead.
#[tokio::test]
async fn sizes_and_roots_come_from_outside_the_proof() {
    let g = kp();
    let keys: Vec<Kp> = (0..8).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], 8).await;
    let held = &at_size[3];
    let ext = Extension::of(&chain.principal, tree_size(held))
        .await
        .expect("proof");
    assert_eq!(verify_extension(held, &ext), Ok(()));

    let mut wrong_shape = ext.clone();
    wrong_shape.size = ext.size.next_power_of_two() * 2;
    assert_eq!(
        verify_extension(held, &wrong_shape),
        Err(ExtensionFailure::NotAnExtension)
    );

    let mut same_shape = ext.clone();
    same_shape.size += 1;
    assert_eq!(verify_extension(held, &same_shape), Ok(()));
    let replayed = &chain.principal;
    assert_eq!(confirm_extension(replayed, &ext), Ok(()));
    assert_eq!(
        confirm_extension(replayed, &same_shape),
        Err(ExtensionFailure::Unconfirmed)
    );

    // Another root of the same width (the held principal's own tip commit
    // root: a real digest, only not the offer's).
    let mut wrong_root = ext.clone();
    wrong_root.cr = at_size[2]
        .cr()
        .map(|cr| cyphr::state::TaggedDigest::new(held.hash_alg(), cr_bytes(cr, held)))
        .expect("held CR")
        .expect("tagged");
    assert_eq!(
        verify_extension(held, &wrong_root),
        Err(ExtensionFailure::NotAnExtension)
    );

    // An offer no longer than the held log proves nothing.
    let mut not_longer = ext.clone();
    not_longer.size = tree_size(held);
    assert_eq!(
        verify_extension(held, &not_longer),
        Err(ExtensionFailure::NotLonger)
    );
}

fn cr_bytes(cr: &cyphr::CommitRoot, held: &Principal<MemoryStorage>) -> Vec<u8> {
    cr.as_multihash()
        .get(held.hash_alg())
        .expect("variant")
        .to_vec()
}

/// Backs: a payload that is not the wire shape, or whose lengths exceed
/// what a log of that size can need, fails closed at the parse, before any
/// hashing.
#[tokio::test]
async fn a_malformed_wire_proof_fails_closed() {
    let g = kp();
    let keys: Vec<Kp> = (0..8).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], 8).await;
    let ext = Extension::of(&chain.principal, tree_size(&at_size[3]))
        .await
        .expect("proof");
    let good = ext.to_payload();
    assert_eq!(Extension::from_payload(&good).as_ref(), Ok(&ext));

    let mut cases = Vec::new();
    for field in ["size", "cr", "proof"] {
        let mut v = good.clone();
        v.as_object_mut().expect("object").remove(field);
        cases.push(v);
    }
    let mut bad_b64 = good.clone();
    bad_b64["proof"]["boundary_hash"] = json!("not base64 !");
    cases.push(bad_b64);
    let mut bad_width = good.clone();
    bad_width["proof"]["boundary_hash"] = json!("AAAA");
    cases.push(bad_width);
    let mut many_peaks = good.clone();
    many_peaks["proof"]["new_peaks"] = json!(vec![good["proof"]["boundary_hash"].clone(); 200]);
    cases.push(many_peaks);
    let mut deep = good.clone();
    deep["proof"]["peak_path"] = json!(vec![json!({"position": 0, "siblings": []}); 200]);
    cases.push(deep);
    for case in cases {
        assert!(
            matches!(
                Extension::from_payload(&case),
                Err(ExtensionFailure::Malformed(_))
            ),
            "{case}"
        );
    }
}
