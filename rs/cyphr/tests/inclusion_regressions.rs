//! Regressions for the two forgeries that took the portable verifiers'
//! tree shape from the prover (close review: `close/crypto.md` 5 and
//! `hacker-keyinc.log`). Both used genuine hashes of an honest two-key
//! principal and no preimage.
//!
//! 7. A thumbprint passed as a transaction root: the State Root stood in the Commit Root's place
//!    and the index-0 path's sibling was the second key's thumbprint. Rebuilt here as a
//!    certificate; no bundle may verify under it, and at index 0 only commit 0's does.
//! 8. The State Root passed as a key: no `Key` can carry it as its thumbprint, and the key verifier
//!    takes a `Key`, not bytes (the `compile_fail` doctest in `lib.rs`).
//!
//! Red before P.1: 7 and 8 name `verify_transaction_inclusion`'s and
//! `verify_key_inclusion`'s new signatures and `KeyOpening`, so the file
//! fails to compile until they exist. `Key::new` refusing a tmb that is not
//! the public key's already holds and stays a guard.

mod inclusion_support;

use cyphr::commit_root::hash_alg_to_u64;
use cyphr::proof::Certificate;
use cyphr::replay::WireBundle;
use cyphr::{
    Error, HashAlg, Key, KeyOpening, Principal, StateDigest, verify_key_inclusion,
    verify_transaction_inclusion,
};
use inclusion_support::*;
use proptest::prelude::*;
use serde_json::{Value, json};

/// The honest principal of both reproductions: alice's genesis, then bob
/// added in commit 1.
async fn two_keys() -> (Principal, Kp, Kp) {
    let (alice, bob) = (kp(coz::Alg::ES256), kp(coz::Alg::ES256));
    let mut p = Principal::implicit(key_of(&alice)).await.expect("open");
    p.commit_genesis(&signer(&alice), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    commit_key(&mut p, &alice, &bob, T + 10).await;
    assert_eq!(p.commit_count(), 2, "setup");
    (p, alice, bob)
}

fn bundle(p: &Principal, i: usize) -> WireBundle {
    WireBundle::of_commit(p.commit_at(i).expect("commit")).expect("bundle")
}

fn cell(alg: HashAlg, bytes: &[u8]) -> String {
    b64(&serde_json::to_vec(&json!({ hash_alg_to_u64(alg).to_string(): bytes })).expect("cell"))
}

#[tokio::test]
async fn a_thumbprint_is_not_a_transaction_root() {
    let (p, _alice, bob) = two_keys().await;
    let pr = p.pr().clone();
    let sr = p
        .sr()
        .expect("sr")
        .as_multihash()
        .get(HashAlg::Sha256)
        .expect("sr")
        .to_vec();
    let honest_claim = cyphr::proof::Claim::Member {
        index: 0,
        commit: bundle(&p, 0),
    };
    let honest = p.prove(2, &honest_claim).await.expect("prove");

    let mut wire: Value = serde_json::to_value(&honest).expect("wire");
    wire["top"]["pt_cells"][1] = json!(cell(HashAlg::Sha256, &sr));
    wire["terminal"]["steps"][0]["siblings"] = json!([b64(bob.tmb.as_bytes())]);
    let forged = serde_json::from_value::<Certificate>(wire);

    for c in 0..2 {
        if let Ok(forged) = &forged {
            assert!(
                verify_transaction_inclusion(&pr, 2, 0, &bundle(&p, c), forged).is_err(),
                "bundle {c} verified under the forged certificate"
            );
        }
        let accepted = verify_transaction_inclusion(&pr, 2, 0, &bundle(&p, c), &honest).is_ok();
        assert_eq!(
            accepted,
            c == 0,
            "bundle {c} at index 0 under the honest certificate"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn the_state_root_cannot_be_a_key(alg in 0u8..3) {
        run(async {
            let (p, _a, _b) = two_keys().await;
            let sr = p.sr().expect("sr");
            let sr = sr.as_multihash().get(HashAlg::Sha256).expect("sr").to_vec();
            let k = match alg { 0 => coz::Alg::Ed25519, 1 => coz::Alg::ES256, _ => coz::Alg::ES384 }
                .generate_keypair();
            let forged = Key::new(k.alg.name(), coz::Thumbprint::from_bytes(sr), k.pub_bytes);
            prop_assert!(matches!(forged, Err(Error::TmbMismatch)), "{forged:?}");
            Ok::<(), TestCaseError>(())
        })?;
    }
}

/// Property 3 on the reproduction's principal: a stranger is refused under
/// each honest opening and the empty one.
#[tokio::test]
async fn a_stranger_is_not_included_in_the_two_key_principal() {
    let (p, ..) = two_keys().await;
    let st = p.state();
    let stranger = key_of(&kp(coz::Alg::ES256));
    let empty = KeyOpening {
        kt: vec![],
        at_nonces: vec![],
        dr: None,
        cr: None,
        pr_nonces: vec![],
    };
    assert!(verify_key_inclusion(&stranger, st.pr(), &empty).is_err());
    for key in st.active_keys() {
        let opening = st.key_opening(key.tmb()).expect("opening");
        assert!(verify_key_inclusion(&stranger, st.pr(), &opening).is_err());
    }
}
