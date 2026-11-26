//! A verifier told a log size smaller than the true one must refuse, not
//! accept a regrouping of real commits as one commit of a smaller log.
//!
//! Source: the hacker's reproduction (`verifier/hacker-repro.md` 1), run
//! against `proof::verify`. Nothing in the Principal Root binds the commit
//! count, so a size the verifier is told is checked only against the path;
//! the path of a smaller log makes an internal node of the true log a leaf.
//! A claimed size must be checked against what the root commits to.
//!
//! Property: pinning the honest root of a log of `n` commits at any size
//! below `n` refuses a commit whose two transactions are the cozies of
//! commits 0 and 1 regrouped, with the honest path trimmed by a step and
//! its size rewritten to the lie.
//!
//! Red today: `verify` returns `Ok(())` for the forged claim at size 2.

mod inclusion_support;

use cyphr::proof::{Anchor, Certificate, Claim, Root, verify};
use cyphr::replay::WireBundle;
use inclusion_support::*;
use serde_json::{Value, json};

#[tokio::test]
async fn a_lying_log_size_is_refused() {
    let owner = kp(coz::Alg::ES256);
    let mut p = cyphr::Principal::implicit(key_of(&owner)).await.expect("open");
    p.commit_genesis(&signer(&owner), &[], T, AUTHORITY).await.expect("genesis");
    for i in 1..4 {
        commit_key(&mut p, &owner, &kp(coz::Alg::ES256), T + 10 * i).await;
    }
    let n = p.commit_count() as u64;
    assert_eq!(n, 4, "setup");
    let real = p.root_at(n).expect("root");
    let bundle = |i| WireBundle::of_commit(p.commit_at(i).expect("commit")).expect("bundle");
    let (c0, c1) = (bundle(0), bundle(1));
    let honest = Claim::Member { index: 0, commit: c0.clone() };
    let cert = p.prove(n, &honest).await.expect("prove");
    assert_eq!(
        verify(&Anchor::pin(real.clone()), &cert, n, &honest),
        Ok(()),
        "honest baseline"
    );

    // Commits 0 and 1 regrouped as the two transactions of one "commit 0".
    let flat = |b: &WireBundle| -> Vec<Vec<u8>> { b.txs.iter().flatten().cloned().collect() };
    let forged_claim = Claim::Member {
        index: 0,
        commit: WireBundle { actions: vec![], txs: vec![flat(&c0), flat(&c1)], keys: vec![] },
    };
    let mut wire: Value = serde_json::to_value(&cert).expect("wire");
    wire["terminal"]["steps"].as_array_mut().expect("steps").remove(0);
    wire["terminal"]["size"] = json!(2);
    let forged: Certificate = serde_json::from_value(wire).expect("parses");
    let lie = Anchor::pin(Root { size: 2, pr: real.pr });
    assert!(
        verify(&lie, &forged, 2, &forged_claim).is_err(),
        "a regrouping of commits 0 and 1 was accepted as commit 0 of a 2-commit log"
    );
}
