//! The two portable inclusion verifiers (forge #19, node P.1): a third
//! party holding only the Principal Root and what the principal discloses
//! can check that a commit is in the log or a key is in the key tree, and
//! nothing the prover supplies decides the tree's shape.
//!
//! Properties, over generated principals (one to three keys of mixed
//! algorithms, nonces at each level, with and without data):
//!
//! 1. key inclusion is complete from the three values alone;
//! 2. any one edit to an honest opening, or a foreign root or key, is refused;
//! 3. a key never held is refused under every opening;
//! 4. the transaction verdict is `proof::verify`'s, and is "this is the commit at that index";
//! 5. another commit, a wrong index or an altered coz is refused;
//! 6. a size other than the true one is refused;
//! 9. the documented limit: a key-tree nonce equal to a thumbprint verifies for that key.
//!
//! Red before P.1: the verifiers take hop proofs and trusted roots, and
//! `KeyOpening`/`PrincipalState::key_opening` do not exist, so the file
//! fails to compile at its first use of them.

mod inclusion_support;

use cyphr::proof::{Anchor, Certificate, Claim, Root, verify};
use cyphr::replay::WireBundle;
use cyphr::state::TaggedDigest;
use cyphr::{
    CommitRoot, DataRoot, HashAlg, Key, KeyOpening, MultihashDigest, PrincipalRoot,
    verify_key_inclusion, verify_transaction_inclusion,
};
use inclusion_support::*;
use proptest::prelude::*;
use serde_json::{Value, json};

fn dup(o: &KeyOpening) -> KeyOpening {
    KeyOpening {
        kt: o.kt.clone(),
        at_nonces: o.at_nonces.clone(),
        dr: o.dr.clone(),
        cr: o.cr.clone(),
        pr_nonces: o.pr_nonces.clone(),
    }
}

fn fresh() -> TaggedDigest {
    TaggedDigest::new(HashAlg::Sha256, vec![0xEE; 32]).expect("digest")
}

fn flipped(d: &TaggedDigest) -> TaggedDigest {
    let mut bytes = d.as_bytes().to_vec();
    bytes[0] ^= 1;
    TaggedDigest::new(d.alg(), bytes).expect("digest")
}

/// `md` with one variant's bytes changed.
fn change_variant(md: &MultihashDigest) -> MultihashDigest {
    let mut variants = md.variants().clone();
    let (_, bytes) = variants.iter_mut().next().expect("a variant");
    let mut b = bytes.to_vec();
    b[0] ^= 1;
    *bytes = b.into();
    MultihashDigest::new(variants).expect("digest")
}

/// `md` with one variant removed, when it has more than one.
fn drop_variant(md: &MultihashDigest) -> Option<MultihashDigest> {
    let mut variants = md.variants().clone();
    if variants.len() < 2 {
        return None;
    }
    let first = *variants.keys().next().expect("a variant");
    variants.remove(&first);
    Some(MultihashDigest::new(variants).expect("digest"))
}

fn list<'a>(name: &str, e: &'a mut KeyOpening) -> &'a mut Vec<TaggedDigest> {
    match name {
        "kt" => &mut e.kt,
        "at" => &mut e.at_nonces,
        _ => &mut e.pr_nonces,
    }
}

/// Every single edit of an opening: each list element removed, added or
/// changed, `dr` and `cr` set, cleared or changed, one variant of either
/// dropped or changed.
fn edits(o: &KeyOpening) -> Vec<(String, KeyOpening)> {
    let mut out = vec![];
    for (name, len) in [
        ("kt", o.kt.len()),
        ("at", o.at_nonces.len()),
        ("pr", o.pr_nonces.len()),
    ] {
        let mut e = dup(o);
        list(name, &mut e).push(fresh());
        out.push((format!("{name}: add"), e));
        for i in 0..len {
            let mut e = dup(o);
            list(name, &mut e).remove(i);
            out.push((format!("{name}: remove {i}"), e));
            let mut e = dup(o);
            let changed = flipped(&list(name, &mut e)[i]);
            list(name, &mut e)[i] = changed;
            out.push((format!("{name}: change {i}"), e));
        }
    }
    let mut e = dup(o);
    e.dr = match &o.dr {
        None => Some(DataRoot(
            MultihashDigest::from_single(HashAlg::Sha256, vec![9; 32]).expect("dr"),
        )),
        Some(_) => None,
    };
    out.push(("dr: set or clear".into(), e));
    if let Some(dr) = &o.dr {
        let mut e = dup(o);
        e.dr = Some(DataRoot(change_variant(&dr.0)));
        out.push(("dr: change a variant".into(), e));
        if let Some(m) = drop_variant(&dr.0) {
            let mut e = dup(o);
            e.dr = Some(DataRoot(m));
            out.push(("dr: drop a variant".into(), e));
        }
    }
    let mut e = dup(o);
    e.cr = match &o.cr {
        None => Some(CommitRoot(
            MultihashDigest::from_single(HashAlg::Sha256, vec![8; 32]).expect("cr"),
        )),
        Some(_) => None,
    };
    out.push(("cr: set or clear".into(), e));
    if let Some(cr) = &o.cr {
        let mut e = dup(o);
        e.cr = Some(CommitRoot(change_variant(&cr.0)));
        out.push(("cr: change a variant".into(), e));
        if let Some(m) = drop_variant(&cr.0) {
            let mut e = dup(o);
            e.cr = Some(CommitRoot(m));
            out.push(("cr: drop a variant".into(), e));
        }
    }
    out
}

fn held(w: &World) -> Vec<Key> {
    w.p.state().active_keys().cloned().collect()
}

// 1. Complete.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn every_held_key_is_included(spec in spec()) {
        run(async {
            let w = world(&spec).await;
            let st = w.p.state();
            for key in held(&w) {
                let opening = st.key_opening(key.tmb()).expect("held key opens");
                let verdict = verify_key_inclusion(&key, st.pr(), &opening);
                prop_assert_eq!(verdict, Ok(()), "{:?}", key.tmb());
            }
            Ok::<(), TestCaseError>(())
        })?;
    }

    // 2. Sound under edits.
    #[test]
    fn no_edit_of_an_honest_opening_verifies(spec in spec(), other in spec()) {
        run(async {
            let (w, foreign) = (world(&spec).await, world(&other).await);
            let st = w.p.state();
            let keys = held(&w);
            for key in &keys {
                let honest = st.key_opening(key.tmb()).expect("opening");
                for (what, e) in edits(&honest) {
                    prop_assert!(
                        verify_key_inclusion(key, st.pr(), &e).is_err(),
                        "edit accepted: {what}"
                    );
                }
                // Another principal's root.
                prop_assert!(verify_key_inclusion(key, foreign.p.state().pr(), &honest).is_err());
                // Another held key under this key's opening.
                for other_key in keys.iter().filter(|k| k.tmb() != key.tmb()) {
                    prop_assert!(
                        verify_key_inclusion(other_key, st.pr(), &honest).is_err(),
                        "opening of {:?} accepted for {:?}", key.tmb(), other_key.tmb()
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }

    // 3. Not held.
    #[test]
    fn a_key_never_held_is_refused_under_every_opening(spec in spec()) {
        run(async {
            let w = world(&spec).await;
            let st = w.p.state();
            let stranger = key_of(&kp(coz::Alg::ES256));
            let empty = KeyOpening {
                kt: vec![], at_nonces: vec![], dr: None, cr: None, pr_nonces: vec![],
            };
            prop_assert!(verify_key_inclusion(&stranger, st.pr(), &empty).is_err());
            for key in held(&w) {
                let honest = st.key_opening(key.tmb()).expect("opening");
                prop_assert!(verify_key_inclusion(&stranger, st.pr(), &honest).is_err());
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

// 9. The documented limit.
#[tokio::test]
async fn a_key_tree_nonce_equal_to_a_thumbprint_verifies_for_that_key() {
    let (owner, stranger) = (kp(coz::Alg::ES256), kp(coz::Alg::ES256));
    let mut p = cyphr::Principal::implicit(key_of(&owner))
        .await
        .expect("open");
    p.commit_genesis(&signer(&owner), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    // The principal plants the stranger's thumbprint as a key-tree nonce.
    commit_nonce(&mut p, &owner, Level::Kt, stranger.tmb.as_bytes(), T + 10).await;
    let st = p.state();
    let mut opening = st.key_opening(&owner.tmb).expect("opening");
    // The opening of the stranger's leaf discloses the owner's, in place of
    // the nonce that is the stranger's thumbprint.
    opening.kt =
        vec![TaggedDigest::new(HashAlg::Sha256, owner.tmb.as_bytes().to_vec()).expect("tmb")];
    assert_eq!(
        verify_key_inclusion(&key_of(&stranger), st.pr(), &opening),
        Ok(()),
        "a leaf of the key tree is not an active key: nonces and thumbprints are not told apart"
    );
}

// ---- transactions ----

fn bundle(p: &cyphr::Principal, i: usize) -> WireBundle {
    WireBundle::of_commit(p.commit_at(i).expect("commit")).expect("bundle")
}

async fn cert(p: &cyphr::Principal, size: u64, index: u64) -> Certificate {
    let claim = Claim::Member {
        index,
        commit: bundle(p, index as usize),
    };
    p.prove(size, &claim).await.expect("prove")
}

fn tx_ok(
    pr: &PrincipalRoot,
    size: u64,
    index: u64,
    commit: &WireBundle,
    cert: &Certificate,
) -> bool {
    verify_transaction_inclusion(pr, size, index, commit, cert).is_ok()
}

fn root(p: &cyphr::Principal, size: u64) -> (PrincipalRoot, Root) {
    let r = p.root_at(size).expect("root");
    (r.pr.clone(), r)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6))]

    // 4 and 5. Same verdict as the certificate path, and it is "this is the
    // commit at that index".
    #[test]
    fn the_transaction_verdict_is_the_certificate_verdict(spec in spec()) {
        run(async {
            let w = world(&spec).await;
            let p = &w.p;
            let n = p.commit_count() as u64;
            for size in 1..=n {
                let (pr, pinned) = root(p, size);
                for index in 0..size {
                    let cert = cert(p, size, index).await;
                    for c in 0..size as usize {
                        let commit = bundle(p, c);
                        let claim = Claim::Member { index, commit: commit.clone() };
                        let anchor = Anchor::pin(pinned.clone());
let via_cert = verify(&anchor, &cert, size, &claim).is_ok();
                        let direct = tx_ok(&pr, size, index, &commit, &cert);
                        let at = format!("size {size} index {index} bundle {c}");
                        prop_assert_eq!(direct, via_cert, "{}", at);
                        prop_assert_eq!(direct, c as u64 == index, "{}", at);
                    }
                    // A wrong index for the right bundle and certificate.
                    for wrong in (0..size).filter(|&j| j != index) {
                        let commit = bundle(p, index as usize);
                        prop_assert!(
                            verify_transaction_inclusion(&pr, size, wrong, &commit, &cert).is_err(),
                            "index {} claimed as {}", index, wrong
                        );
                    }
                    // One coz altered.
                    let mut altered = bundle(p, index as usize);
                    let blob = altered.txs[0][0].last_mut().expect("bytes");
                    *blob ^= 1;
                    prop_assert!(
                        verify_transaction_inclusion(&pr, size, index, &altered, &cert).is_err(),
                        "altered coz at {} accepted", index
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }

    // 6. The size is verified.
    #[test]
    fn a_size_other_than_the_true_one_is_refused(spec in spec()) {
        run(async {
            let w = world(&spec).await;
            let p = &w.p;
            let n = p.commit_count() as u64;
            let (pr_n, _) = root(p, n);
            let honest_n = cert(p, n, 0).await;
            for claimed in (1..=n + 2).filter(|&s| s != n) {
                // The honest certificate at n, a lying size.
                prop_assert!(
                    !tx_ok(&pr_n, claimed, 0, &bundle(p, 0), &honest_n),
                    "true size {}, claimed {}", n, claimed
                );
            }
            for size in (1..n).filter(|&s| s != n) {
                // Certificates made honestly at a smaller size, and the same
                // with their path size rewritten to the true one.
                let small = cert(p, size, 0).await;
                prop_assert!(
                    verify_transaction_inclusion(&pr_n, n, 0, &bundle(p, 0), &small).is_err(),
                    "a size-{} certificate at size {}", size, n
                );
                let mut wire: Value = serde_json::to_value(&small).expect("wire");
                wire["terminal"]["size"] = json!(n);
                if let Ok(rewritten) = serde_json::from_value::<Certificate>(wire) {
                    prop_assert!(
                        !tx_ok(&pr_n, n, 0, &bundle(p, 0), &rewritten),
                        "a size-{} path rewritten to {}", size, n
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

/// Property 6 at its known reproduction (`verifier/hacker-repro.md` 1):
/// told size 2 for a genuine 4-commit root, the verifier must not take
/// commits 0 and 1 regrouped as two transactions for "commit 0", with the
/// honest path trimmed of a step and its size rewritten to 2.
#[tokio::test]
async fn regrouped_commits_are_not_a_commit_of_a_smaller_log() {
    let owner = kp(coz::Alg::ES256);
    let mut p = cyphr::Principal::implicit(key_of(&owner))
        .await
        .expect("open");
    p.commit_genesis(&signer(&owner), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    for i in 1..4 {
        commit_key(&mut p, &owner, &kp(coz::Alg::ES256), T + 10 * i).await;
    }
    let n = p.commit_count() as u64;
    let (pr, _) = root(&p, n);
    let honest = cert(&p, n, 0).await;
    assert_eq!(
        verify_transaction_inclusion(&pr, n, 0, &bundle(&p, 0), &honest),
        Ok(()),
        "honest baseline"
    );
    let flat = |b: &WireBundle| -> Vec<Vec<u8>> { b.txs.iter().flatten().cloned().collect() };
    let regrouped = WireBundle {
        actions: vec![],
        txs: vec![flat(&bundle(&p, 0)), flat(&bundle(&p, 1))],
        keys: vec![],
    };
    let mut wire: Value = serde_json::to_value(&honest).expect("wire");
    wire["terminal"]["steps"]
        .as_array_mut()
        .expect("steps")
        .remove(0);
    wire["terminal"]["size"] = json!(2);
    let forged: Certificate = serde_json::from_value(wire).expect("parses");
    assert!(
        verify_transaction_inclusion(&pr, 2, 0, &regrouped, &forged).is_err(),
        "a regrouping of commits 0 and 1 verified as commit 0 of a 2-commit log"
    );
}
