//! Certificates for commits as large as admission allows: more than 256
//! Principal Tree cells (PR-level nonces accumulate without bound), a
//! transaction of more than 256 cozies, and a commit of more than 256
//! mutation transactions. Each must prove, round-trip through the
//! certificate's own parser, and verify.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{Anchor, Certificate, Claim, verify};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";
/// More than any count the first implementation capped.
const MANY: usize = 257;

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

fn tmb(k: &Kp) -> String {
    Base64UrlUnpadded::encode_string(k.tmb.as_bytes())
}

fn verified(
    scope: &cyphr::CommitScope<'_, cyphr::eml::MemoryStorage>,
    by: &Kp,
    typ: &str,
    id: String,
    now: i64,
    side: Option<Key>,
) -> cyphr::VerifiedCoz {
    let mut pay = json!({"alg": by.alg, "id": id, "now": now, "tmb": tmb(by),
                         "typ": format!("{AUTHORITY}/cyphr/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    scope.verify(&v, &sig, czd, side).expect("verify")
}

fn nonce(i: usize) -> String {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&seed))
}

/// How the `MANY` nonces of a commit are laid out.
#[derive(Clone, Copy)]
enum Shape {
    /// One transaction of `MANY` cozies.
    Grouped,
    /// `MANY` transactions of one coz.
    Separate,
}

/// Genesis (Ed25519), then one commit of `MANY` PR-level nonces and a
/// `key/replace` to ES256 (so a stitch opens exactly this commit), then
/// data-free commits by the new key to leave a tip: the PR carries
/// `MANY` nonce cells from the first commit on.
async fn chain(shape: Shape) -> Principal {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut p = Principal::implicit(key_of(&a)).await.expect("open");
    p.commit_genesis(&signer(&a), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    let now = T + 10;
    let mut scope = p.begin_commit();
    let nonces: Vec<_> = (0..MANY)
        .map(|i| verified(&scope, &a, "nonce/create", nonce(i), now, None))
        .collect();
    match shape {
        Shape::Grouped => scope.apply_tx(nonces).expect("one transaction"),
        Shape::Separate => {
            for n in nonces {
                scope.apply(n).expect("a nonce");
            }
        },
    }
    let replace = verified(&scope, &a, "key/replace", tmb(&b), now, Some(key_of(&b)));
    scope.apply(replace).expect("replace");
    scope
        .finalize_with_software(&signer(&a), now + 1, AUTHORITY)
        .await
        .expect("commit");
    for k in 0..2 {
        let mut scope = p.begin_commit();
        let id = nonce(MANY + k);
        let n = verified(&scope, &b, "nonce/create", id, now + 20 + k as i64, None);
        scope.apply(n).expect("a nonce");
        scope
            .finalize_with_software(&signer(&b), now + 21 + k as i64, AUTHORITY)
            .await
            .expect("commit");
    }
    p
}

async fn proves_and_verifies(shape: Shape) {
    let p = chain(shape).await;
    let n = p.commit_count() as u64;
    let txs = p.commit_at(1).expect("commit").transactions().len();
    match shape {
        Shape::Grouped => assert_eq!(txs, 3, "a group, the replace, the closing coz"),
        Shape::Separate => assert_eq!(txs, MANY + 2, "every nonce its own transaction"),
    }
    for i in 0..n {
        let bundle = cyphr::replay::WireBundle::of_commit(p.commit_at(i as usize).expect("commit"))
            .expect("bundle");
        let claim = Claim::Member {
            index: i,
            commit: bundle,
        };
        let cert = p.prove(n, &claim).await.expect("prove");
        let back: Certificate =
            serde_json::from_value(serde_json::to_value(&cert).expect("serialize"))
                .unwrap_or_else(|e| panic!("index {i}: an honest certificate is refused: {e}"));
        assert_eq!(
            verify(&Anchor::of_chain(p.state()), &back, n, &claim),
            Ok(()),
            "chain, index {i}"
        );
        assert_eq!(
            verify(&Anchor::pin(p.root_at(n).expect("root")), &back, n, &claim),
            Ok(()),
            "pin, index {i}"
        );
    }
    // And an extension across the same commit, from the genesis alone.
    let holder = {
        let a = kp(coz::Alg::Ed25519);
        let _ = a;
        p.fork().await.expect("fork")
    };
    let head = p.root_at(n).expect("head");
    let claim = Claim::Extends {
        from: 1,
        head: head.pr.clone(),
    };
    let cert = holder.prove(n, &claim).await.expect("prove");
    let back: Certificate =
        serde_json::from_value(serde_json::to_value(&cert).expect("serialize")).expect("parses");
    assert_eq!(
        verify(&Anchor::of_chain(p.state()), &back, n, &claim),
        Ok(())
    );
}

// More than 256 Principal Tree cells (the PR holds MANY nonces) and a
// transaction of more than 256 cozies.
#[tokio::test]
async fn a_grouped_transaction_of_many_cozies_and_many_cells_is_provable() {
    proves_and_verifies(Shape::Grouped).await;
}

// A commit of more than 256 mutation transactions, the transaction root
// over all of them.
#[tokio::test]
async fn a_commit_of_many_transactions_is_provable() {
    proves_and_verifies(Shape::Separate).await;
}
