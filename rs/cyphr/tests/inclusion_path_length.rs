//! Regression: a membership certificate once accepted a bundle that was
//! never committed, by prepending "subtree prefix" steps to the terminal
//! path. The spine verifier checks only the trailing steps against the
//! skeleton and hash-chains the leading ones, so a path's length has to be
//! pinned to the skeleton by Cyphr itself.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{Anchor, Cause, Certificate, Claim, ProofError, verify};
use cyphr::replay::{StoredCoz, WireBundle};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::{Value, json};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let k = coz::Alg::Ed25519.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).unwrap();
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}
fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).unwrap()
}
fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}
fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

#[tokio::test]
async fn prefix_steps_do_not_prove_a_bundle_never_committed() {
    let (alice, bob) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&alice)).await.unwrap();
    p.commit_genesis(&signer(&alice), &[], T, AUTHORITY)
        .await
        .unwrap();

    // Commit 1 = [[key/create bob], [commit/create]].
    let mut pay = json!({"alg": alice.alg, "id": b64(bob.tmb.as_bytes()), "now": T + 10,
        "tmb": b64(alice.tmb.as_bytes()), "typ": format!("{AUTHORITY}/cyphr/key/create")});
    pay.as_object_mut().unwrap().sort_keys();
    let v = serde_json::to_vec(&pay).unwrap();
    let (sig, cad) = coz::sign_json(&v, &alice.alg, &alice.prv, &alice.pubb).unwrap();
    let czd = coz::czd_for_alg(&cad, &sig, &alice.alg).unwrap();
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, Some(key_of(&bob)))
        .unwrap();
    scope
        .finalize_with_software(&signer(&alice), T + 11, AUTHORITY)
        .await
        .unwrap();

    let honest = WireBundle::of_commit(p.commit_at(1).unwrap()).unwrap();
    assert_eq!(honest.txs.len(), 2, "setup: one mutation tx + commit tx");
    let (m_blob, c_blob) = (honest.txs[0][0].clone(), honest.txs[1][0].clone());
    let czd_m = StoredCoz::from_wire(&m_blob)
        .unwrap()
        .czd()
        .as_bytes()
        .to_vec();
    let czd_c = StoredCoz::from_wire(&c_blob)
        .unwrap()
        .czd()
        .as_bytes()
        .to_vec();

    let root = p.root_at(2).unwrap();
    let anchor = Anchor::pin(root);
    let honest_claim = Claim::Member {
        index: 1,
        commit: honest,
    };
    let cert = p.prove(2, &honest_claim).await.unwrap();
    assert_eq!(
        verify(&anchor, &cert, 2, &honest_claim),
        Ok(()),
        "honest baseline"
    );

    let forge = |pos: usize, sib: &[u8]| -> Certificate {
        let mut w: Value = serde_json::to_value(&cert).unwrap();
        let steps = w["terminal"]["steps"].as_array_mut().unwrap();
        steps.insert(0, json!({"position": pos, "siblings": [b64(sib)]}));
        serde_json::from_value(w).unwrap()
    };

    // Forgery A: commit 1 "was" only the commit/create coz (the key/create dropped).
    let only_commit = Claim::Member {
        index: 1,
        commit: WireBundle {
            actions: vec![],
            txs: vec![vec![c_blob.clone()]],
            keys: vec![],
        },
    };
    let ra = verify(&anchor, &forge(1, &czd_m), 2, &only_commit);
    println!("forgery A (bundle [[commit/create]] at index 1): {ra:?}");

    // Forgery B: commit 1 "was" only the key/create coz, standing as its own commit tx.
    let only_mut = Claim::Member {
        index: 1,
        commit: WireBundle {
            actions: vec![],
            txs: vec![vec![m_blob.clone()]],
            keys: vec![],
        },
    };
    let rb = verify(&anchor, &forge(0, &czd_c), 2, &only_mut);
    println!("forgery B (bundle [[key/create]] at index 1): {rb:?}");

    // Refused for the reason the regression is about: the claimed bundle
    // is not the leaf at that index. Any other refusal (a framing or
    // arrow failure) would mean the prefix steps were stopped by luck.
    for (name, r) in [("A", ra), ("B", rb)] {
        match r {
            Err(e @ ProofError::Refuted(_)) if matches!(e.cause(), Cause::Mismatch(_)) => {},
            other => panic!("forgery {name} not refused as a leaf mismatch: {other:?}"),
        }
    }
}
