//! With no State Root, the Principal Tree's cells are `[CR, nonces...]`,
//! not `[SR, CR, ...]`, so a certificate must not read cell 1 as the
//! Commit Root: a Principal-Root nonce sits there.
//!
//! Source: the hacker's reproduction (`verifier/hacker-repro.md` 2). The
//! key holder plants the nonce `N = H(s || x)`, `x` the czd of a coz it
//! signed and never committed, then deletes its only key (no key and no
//! data, so no State Root). A hand-built certificate with cells `[CR, N]`
//! folds to the genuine Principal Root and its path `s -> N` reaches the
//! never-committed coz as a "leaf", so the real Commit Root in cell 0 is
//! never consulted.
//!
//! Property: for that principal at its true size, no claim that commit 2
//! (or any index) is the fabricated coz verifies, whichever side the
//! sibling is on.
//!
//! Red today: `verify` returns `Ok(())` for the index-2, position-1 forgery.

mod inclusion_support;

use cyphr::eml::Hasher as _;
use cyphr::proof::{Anchor, Certificate, Claim, verify};
use cyphr::replay::WireBundle;
use cyphr::{HashAlg, MaltHasher, StateDigest};
use inclusion_support::*;
use serde_json::{Value, json};

#[tokio::test]
async fn a_nonce_in_cell_one_is_not_the_commit_root() {
    let owner = kp(coz::Alg::ES256);
    let alg = owner.alg.clone();
    let sign = |mut pay: Value| {
        pay.as_object_mut().expect("pay").sort_keys();
        let v = serde_json::to_vec(&pay).expect("pay");
        let (sig, cad) = coz::sign_json(&v, &alg, &owner.prv, &owner.pubb).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &alg).expect("czd");
        (v, sig, czd)
    };
    // A coz that is never committed; its transaction root is its czd.
    let (fv, fsig, fczd) = sign(json!({"alg": alg, "now": T + 5, "tmb": b64(owner.tmb.as_bytes()),
        "typ": "cyphr.me/fabricated/claim", "msg": "this was never committed"}));
    let fake_blob = serde_json::to_vec(&json!({
        "pay": serde_json::from_slice::<Value>(&fv).expect("pay"), "sig": b64(&fsig)
    }))
    .expect("blob");
    let sib = vec![7u8; 32];
    let nonce = MaltHasher::new(HashAlg::Sha256).node(&[&sib, fczd.as_bytes()]);

    let mut p = cyphr::Principal::implicit(key_of(&owner)).await.expect("open");
    p.commit_genesis(&signer(&owner), &[], T, AUTHORITY).await.expect("genesis");
    commit_nonce(&mut p, &owner, Level::Pr, &nonce, T + 10).await;
    let (v, sig, czd) = sign(json!({"alg": alg, "id": b64(owner.tmb.as_bytes()), "now": T + 20,
        "tmb": b64(owner.tmb.as_bytes()), "typ": "cyphr.me/cyphr/key/delete"}));
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, None).expect("self-delete");
    scope
        .finalize_with_software(&signer(&owner), T + 21, AUTHORITY)
        .await
        .expect("commit");
    let n = p.commit_count() as u64;
    assert!(p.sr().is_none(), "setup: no key and no data leave no State Root");

    let cell = |b: &[u8]| b64(&serde_json::to_vec(&json!({"1": b})).expect("cell"));
    let cr = p.cr().expect("cr").as_multihash().get(HashAlg::Sha256).expect("sha256").to_vec();
    let anchor = Anchor::pin(p.root_at(n).expect("root"));
    // Every index and sibling side of the hand-built path.
    for (index, pos) in [(2u64, 1u64), (2, 0), (1, 1), (0, 1)] {
        let wire = json!({"top": {"pt_cells": [cell(&cr), cell(&nonce)]}, "stitches": [],
            "terminal": {"alg": "SHA-256", "index": index, "size": n,
                "steps": [{"position": pos, "siblings": [b64(&sib)]}]}});
        let forged: Certificate = serde_json::from_value(wire).expect("parses");
        let claim = Claim::Member {
            index,
            commit: WireBundle { actions: vec![], txs: vec![vec![fake_blob.clone()]], keys: vec![] },
        };
        assert!(
            verify(&anchor, &forged, n, &claim).is_err(),
            "the fabricated coz verified as commit {index} (sibling position {pos})"
        );
    }
}
