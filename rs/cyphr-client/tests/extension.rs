//! ExtensionOffer certificates (SPEC 4.4: CR is the append-only Merkle root of
//! all commits, and clients obtain consistency proofs over it): "the
//! offered head extends the log I hold" is checked against the held,
//! already verified chain, and the head is the peer's claim, never read
//! from the certificate and never pinned.
//!
//! Chains are real `cyphr` principals; the oracle for "extends" is equality
//! of the two logs' roots at the older size, which the verifier never sees.

mod common;

use common::*;
use cyphr::Principal;
use cyphr::eml::MemoryStorage;
use cyphr::proof::Claim;
use cyphr_client::{ExtensionFailure, ExtensionOffer, confirm_extension, verify_extension};
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

fn size_of(p: &Principal<MemoryStorage>) -> u64 {
    p.commit_count() as u64
}

/// What a peer serving `p` offers a holder of `from` commits: its head and
/// the certificate that it extends them.
async fn offer(p: &Principal<MemoryStorage>, from: u64) -> ExtensionOffer {
    let to = size_of(p);
    ExtensionOffer::new(
        p.root_at(to).expect("a head"),
        p.prove(
            to,
            &Claim::Extends {
                from,
                head: p.root_at(to).expect("a head").pr,
            },
        )
        .await
        .expect("certificate"),
    )
}

/// The hashes of the certificate's terminal consistency proof: the
/// boundary peak, the path lifting it, and the new frontier.
fn hashes(ext: &ExtensionOffer) -> usize {
    let t = &serde_json::to_value(&ext.certificate).expect("certificate")["terminal"];
    let len = |v: &serde_json::Value| v.as_array().map_or(0, Vec::len);
    1 + t["peak_path"]
        .as_array()
        .map_or(0, |steps| steps.iter().map(|s| len(&s["siblings"])).sum())
        + len(&t["new_peaks"])
}

/// Backs: for every older size the held principal can stand at, the
/// certificate a longer chain serves verifies, and its terminal holds at
/// most 2 * (floor(log2 m) + 1) hashes for a log of m commits: the boundary
/// peak, the path lifting it into the peak that absorbed it (at most
/// floor(log2 m) siblings), and the new frontier (at most floor(log2 m) + 1
/// peaks). A tighter ceil(log2 m) + 1 does not hold of this proof shape
/// (1 -> 25 takes 8).
#[tokio::test]
async fn an_honest_extension_verifies_with_a_logarithmic_proof() {
    let g = kp();
    let keys: Vec<Kp> = (0..LONGEST).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], LONGEST).await;
    let new = &chain.principal;
    let m = size_of(new);
    for held in &at_size {
        let n = size_of(held);
        if n == 0 || n >= m {
            continue;
        }
        let ext = offer(new, n).await;
        assert_eq!(verify_extension(held, &ext), Ok(()), "{n} -> {m}");
        let bound = 2 * (m.ilog2() as usize + 1);
        let nodes = hashes(&ext);
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
        let m = size_of(&b.principal);
        for held in &a_at {
            let n = size_of(held);
            if n == 0 || n >= m {
                continue;
            }
            let ext = offer(&b.principal, n).await;
            let agree = a.principal.root_at(n) == b.principal.root_at(n);
            let verdict = verify_extension(held, &ext);
            assert_eq!(
                verdict.is_ok(),
                agree,
                "shared {shared}, held {n}: {verdict:?}"
            );
            if !agree {
                assert_eq!(verdict, Err(ExtensionFailure::NotAnExtension));
            }
        }
    }
}

/// Backs: the verifier takes the held log from the principal it holds and
/// the head from the offer, never from the certificate. An offer that states
/// another root than the log the certificate was made over is refused,
/// though the certificate is untouched. A Commit Root does not commit to
/// its size (a size with the same frontier shape, one more commit here,
/// verifies), so the stated size is held to the replayed log by
/// `confirm_extension` instead.
#[tokio::test]
async fn heads_come_from_outside_the_certificate() {
    let g = kp();
    let keys: Vec<Kp> = (0..8).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], 8).await;
    let held = &at_size[3];
    let ext = offer(&chain.principal, size_of(held)).await;
    assert_eq!(verify_extension(held, &ext), Ok(()));

    let mut wrong_shape = ExtensionOffer::new(
        ext.head.clone(),
        offer(&chain.principal, 4).await.certificate,
    );
    wrong_shape.head.size = ext.head.size.next_power_of_two() * 2;
    assert_eq!(
        verify_extension(held, &wrong_shape),
        Err(ExtensionFailure::NotAnExtension)
    );

    let mut same_shape = ExtensionOffer::new(
        ext.head.clone(),
        offer(&chain.principal, 4).await.certificate,
    );
    same_shape.head.size += 1;
    assert_eq!(verify_extension(held, &same_shape), Ok(()));
    let replayed = &chain.principal;
    assert_eq!(confirm_extension(replayed, &ext), Ok(()));
    assert_eq!(
        confirm_extension(replayed, &same_shape),
        Err(ExtensionFailure::Unconfirmed)
    );

    // Another root (the held principal's own, a real one, only not the
    // offer's).
    let mut wrong_root = ExtensionOffer::new(
        ext.head.clone(),
        offer(&chain.principal, 4).await.certificate,
    );
    wrong_root.head.pr = at_size[2].root_at(size_of(&at_size[2])).expect("root").pr;
    assert!(
        matches!(
            verify_extension(held, &wrong_root),
            Err(ExtensionFailure::Refused(_))
        ),
        "a head the certificate does not open is no verdict"
    );

    // An offer no longer than the held log proves nothing.
    let mut not_longer = ExtensionOffer::new(
        ext.head.clone(),
        offer(&chain.principal, 4).await.certificate,
    );
    not_longer.head.size = size_of(held);
    assert_eq!(
        verify_extension(held, &not_longer),
        Err(ExtensionFailure::NotLonger)
    );
}

/// Backs: a payload that is not the wire shape, or whose lengths exceed
/// what a log of that size can need, fails closed at the parse, before any
/// hashing.
#[tokio::test]
async fn a_malformed_wire_certificate_fails_closed() {
    let g = kp();
    let keys: Vec<Kp> = (0..8).map(|_| kp()).collect();
    let (chain, at_size) = grown(&g, &keys, &[], 8).await;
    let ext = offer(&chain.principal, size_of(&at_size[3])).await;
    let good = json!({ "certificate": ext.certificate });
    assert!(ExtensionOffer::certificate_from_payload(&good).is_ok());

    let mut cases = Vec::new();
    let mut missing = good.clone();
    missing.as_object_mut().expect("object").clear();
    cases.push(missing);
    let mut extra = good.clone();
    extra["principal_id"] = json!("echoed");
    cases.push(extra);
    for field in ["top", "stitches", "terminal"] {
        let mut v = good.clone();
        v["certificate"]
            .as_object_mut()
            .expect("object")
            .remove(field);
        cases.push(v);
    }
    let boundary = good["certificate"]["terminal"]["boundary_hash"].clone();
    let mut bad_b64 = good.clone();
    bad_b64["certificate"]["terminal"]["boundary_hash"] = json!("not base64 !");
    cases.push(bad_b64);
    let mut bad_width = good.clone();
    bad_width["certificate"]["terminal"]["boundary_hash"] = json!("AAAA");
    cases.push(bad_width);
    let mut many_peaks = good.clone();
    many_peaks["certificate"]["terminal"]["new_peaks"] = json!(vec![boundary; 200]);
    cases.push(many_peaks);
    let mut deep = good.clone();
    deep["certificate"]["terminal"]["peak_path"] =
        json!(vec![json!({"position": 0, "siblings": []}); 200]);
    cases.push(deep);
    for case in cases {
        assert!(
            matches!(
                ExtensionOffer::certificate_from_payload(&case),
                Err(ExtensionFailure::Malformed(_))
            ),
            "{case}"
        );
    }
    assert!(matches!(
        ExtensionOffer::head_from_payload(&json!({"size": "many"})),
        Err(ExtensionFailure::Malformed(_))
    ));
}

/// Backs: a holder whose log was reopened from a frontier (the server's
/// gossip holds principals so) still has its own root at every size it has
/// stood at, which locating a fork needs: each commit keeps its own.
#[tokio::test]
async fn a_detached_holder_has_its_root_at_every_size() {
    let g = kp();
    let keys: Vec<Kp> = (0..9).map(|_| kp()).collect();
    let (chain, _) = grown(&g, &keys, &[], 9).await;
    let whole = &chain.principal;
    let detached = whole
        .fork()
        .await
        .expect("fork")
        .detach()
        .await
        .expect("detach");
    for size in 1..=size_of(whole) {
        assert!(whole.root_at(size).is_some(), "size {size}");
        assert_eq!(detached.root_at(size), whole.root_at(size), "size {size}");
    }
}
