//! A chain on which a hash algorithm leaves (its last key deleted, SPEC 6.2)
//! and returns (a new key of it is created and signs) must replay to the
//! same roots at every holder: the principal built commit by commit and the
//! same commits replayed cold onto a fresh principal agree on every Principal
//! Root. The keys are random, so each run draws new key material; the tests
//! loop over enough draws to be red reliably.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(alg: coz::Alg) -> Kp {
    let k = alg.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// One commit by `by`: `typ` (`create`/`delete`) of `id`.
async fn commit_key(p: &mut Principal, by: &Kp, typ: &str, id: &Kp, now: i64) {
    let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());
    let mut pay = json!({"alg": by.alg, "id": b64(&id.tmb), "now": now,
                         "tmb": b64(&by.tmb), "typ": format!("{AUTHORITY}/cyphr/key/{typ}")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let sidecar = (typ == "create").then(|| key_of(id));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// A data action by `by`, then a `ds/create` of the Data Root over it,
/// signed by `by`, as `cyphr data action` and `cyphr data commit` do.
async fn data_commit(p: &mut Principal, by: &Kp, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let mut pay = json!({"msg": "hello", "now": now, "tmb": Base64UrlUnpadded::encode_string(by.tmb.as_bytes()),
                         "alg": by.alg, "typ": format!("{AUTHORITY}/comment/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    p.verify_and_record_action(&v, &sig, czd.clone())
        .expect("record");
    let action = (v.clone(), sig.clone(), czd);

    let mut scope = p.begin_commit();
    let dr = scope.data_tree_id().expect("dr").expect("a data action");
    let mut pay = json!({"id": dr, "now": now + 1, "tmb": Base64UrlUnpadded::encode_string(by.tmb.as_bytes()),
                         "alg": by.alg, "typ": format!("{AUTHORITY}/{}", cyphr::parsed_coz::typ::DS_CREATE)});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    scope
        .verify_and_apply(&v, &sig, czd, None)
        .expect("ds/create");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
    action
}

async fn genesis(owner: &Kp) -> Principal {
    let mut p = Principal::implicit(key_of(owner)).await.expect("open");
    p.commit_genesis(&signer(owner), &[], T, AUTHORITY)
        .await
        .expect("genesis commit");
    p
}

/// The chain Ed25519 opens, an ES256 key pairs in, is deleted, a new ES256
/// key is created and signs: one draw of key material. Returns the first
/// commit at which a cold replay disagrees with the principal built
/// incrementally, with both Principal Roots.
#[derive(Clone, Copy, Debug)]
enum Copy {
    Fork,
    Detach,
}

async fn first_disagreement(with_data: bool, copy: Copy) -> Option<(usize, String, String)> {
    let owner = kp(coz::Alg::Ed25519);
    let (first, again) = (kp(coz::Alg::ES256), kp(coz::Alg::ES256));
    let spare = kp(coz::Alg::Ed25519);
    let mut built = genesis(&owner).await;
    commit_key(&mut built, &owner, "create", &first, T + 10).await;
    commit_key(&mut built, &owner, "delete", &first, T + 20).await;
    commit_key(&mut built, &owner, "create", &again, T + 30).await;
    let mut action = None;
    if with_data {
        action = Some(data_commit(&mut built, &again, T + 40).await);
    } else {
        commit_key(&mut built, &again, "create", &spare, T + 40).await;
    }

    let mut cold = genesis(&owner).await;
    for (i, commit) in built.commits().enumerate().skip(1) {
        // A holder keeps the chain it replayed and extends a copy of it with
        // what a peer serves next: a fork (the client's `Held::extend`) or a
        // detached copy (the server's gossip, which seeds one from the
        // frontier alone).
        if i > 2 {
            cold = match copy {
                Copy::Fork => cold.fork().await.expect("fork"),
                Copy::Detach => cold.detach().await.expect("detach"),
            };
        }
        // The holder has the commit's data action before the commit.
        if i == 4
            && let Some((v, sig, czd)) = &action
        {
            cold.verify_and_record_action(v, sig, czd.clone())
                .expect("the holder records the action");
        }
        let bundle = WireBundle::of_commit(commit)
            .expect("wire")
            .decode()
            .expect("decode");
        let replayed = cyphr::replay::replay_bundle(&mut cold, &bundle).await;
        let want = format!("{:?}", commit.pr());
        match replayed {
            Ok(_) => {
                let got = format!("{:?}", cold.commits().nth(i).expect("replayed").pr());
                if got != want {
                    return Some((i, want, got));
                }
            },
            Err(e) => return Some((i, want, format!("{e:?}"))),
        }
    }
    None
}

/// Claim: a holder that extends a copy of the chain it replayed (forked, or
/// detached to its frontier) reaches the Principal Roots the incremental
/// build gave, on a chain where SHA-256 leaves with its last key and
/// returns. Turns red if a copy loses the algorithm that left, so the return
/// registers it afresh over a history of nulls and its root (and every arrow
/// signed in it) differs from the owner's.
#[tokio::test]
async fn a_chain_whose_algorithm_returns_replays_on_a_copy() {
    let mut bad = Vec::new();
    for draw in 0..10 {
        for with_data in [false, true] {
            for copy in [Copy::Fork, Copy::Detach] {
                if let Some(d) = first_disagreement(with_data, copy).await {
                    bad.push((draw, with_data, copy, d));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} of 40 runs disagree: {:?}",
        bad.len(),
        bad.first()
            .map(|(draw, data, copy, (at, ..))| (draw, data, copy, at))
    );
}
