//! Every digest in the certificate format carries its algorithm label
//! (nrd: "all hashes should be labeled"): a transaction's czds are
//! `ALG:digest`, and a bare digest is refused rather than matched to a
//! family by its width.
//!
//! Property: for a certificate of a commit with a multi-coz transaction,
//! (1) every czd in every opening is a labelled digest whose label names a
//! known family and whose payload has that family's width; (2) the
//! certificate verifies; (3) stripping any one label (leaving the bare
//! digest) makes the certificate unreadable or refused, never accepted.
//!
//! Red before the change: czds are bare base64url strings, so (1) fails and
//! (3) is accepted by width.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::proof::{Anchor, Certificate, Claim, verify};
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

fn at(k: usize) -> i64 {
    T + 10 * k as i64
}

/// One commit by `by`: `typ` (`create`/`delete`/`replace`) of `id`.
async fn commit_key(p: &mut Principal, by: &Kp, typ: &str, id: &Kp, now: i64) {
    let b64 = |t: &coz::Thumbprint| Base64UrlUnpadded::encode_string(t.as_bytes());
    let mut pay = json!({"alg": by.alg, "id": b64(&id.tmb), "now": now,
                         "tmb": b64(&by.tmb), "typ": format!("{AUTHORITY}/cyphr/key/{typ}")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let sidecar = (typ != "delete").then(|| key_of(id));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// A data action by `by`, then a `ds/create` commit over it.
async fn data_commit(p: &mut Principal, by: &Kp, now: i64) {
    let tmb = Base64UrlUnpadded::encode_string(by.tmb.as_bytes());
    let mut pay = json!({"msg": "hello", "now": now, "tmb": tmb, "alg": by.alg,
                         "typ": format!("{AUTHORITY}/comment/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    p.verify_and_record_action(&v, &sig, czd).expect("record");

    let mut scope = p.begin_commit();
    let dr = scope.data_tree_id().expect("dr").expect("a data action");
    let mut pay = json!({"id": dr, "now": now + 1, "tmb": tmb, "alg": by.alg,
                         "typ": format!("{AUTHORITY}/{}", cyphr::parsed_coz::typ::DS_CREATE)});
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
}

async fn genesis(owner: &Kp) -> Principal {
    let mut p = Principal::implicit(key_of(owner)).await.expect("open");
    p.commit_genesis(&signer(owner), &[], T, AUTHORITY)
        .await
        .expect("genesis commit");
    p
}

const N: u64 = 4;
const WIDTHS: [(&str, usize); 3] = [("SHA-256", 32), ("SHA-384", 48), ("SHA-512", 64)];

/// Every czd string of every opening of a certificate's wire form, with a
/// path to it.
fn czds(cert: &Value) -> Vec<(usize, usize, usize)> {
    let mut at = vec![];
    for (s, st) in cert["stitches"]
        .as_array()
        .expect("stitches")
        .iter()
        .enumerate()
    {
        for (t, tx) in st["opening"]["txs"]
            .as_array()
            .expect("txs")
            .iter()
            .enumerate()
        {
            for c in 0..tx.as_array().expect("tx").len() {
                at.push((s, t, c));
            }
        }
    }
    at
}

/// Genesis (Ed25519, SHA-512), one data commit, a `key/replace` to an
/// ES256 key (SHA-256), one more data commit. A holder who pins the log
/// at its first two commits and asks whether the head extends it gets a
/// certificate that crosses the algorithm boundary, which is what opens a
/// commit's transactions and so carries czds.
async fn certified() -> ((), Anchor<'static>, Claim, Value) {
    let (a, b) = (kp(coz::Alg::Ed25519), kp(coz::Alg::ES256));
    let mut p = genesis(&a).await;
    data_commit(&mut p, &a, at(1)).await;
    commit_key(&mut p, &a, "replace", &b, at(2)).await;
    data_commit(&mut p, &b, at(3)).await;
    let n = p.commit_count() as u64;
    let claim = Claim::Extends {
        from: 2,
        head: p.root_at(n).expect("head").pr,
    };
    let anchor = Anchor::pin(p.root_at(2).expect("pinned root"));
    let cert = p.prove(n, &claim).await.expect("prove");
    (
        (),
        anchor,
        claim,
        serde_json::to_value(&cert).expect("wire"),
    )
}

#[tokio::test]
async fn every_czd_in_a_certificate_is_labelled() {
    let (_, anchor, claim, wire) = certified().await;
    let cert: Certificate = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(verify(&anchor, &cert, N, &claim), Ok(()), "baseline");
    let at = czds(&wire);
    assert!(!at.is_empty(), "setup: the certificate opens a transaction");
    for (s, t, c) in at {
        let czd = wire["stitches"][s]["opening"]["txs"][t][c]
            .as_str()
            .expect("a czd is a string");
        let (label, digest) = czd
            .split_once(':')
            .unwrap_or_else(|| panic!("bare czd {czd:?}"));
        let width = WIDTHS
            .iter()
            .find(|(name, _)| *name == label)
            .unwrap_or_else(|| panic!("unknown label in {czd:?}"))
            .1;
        let bytes = Base64UrlUnpadded::decode_vec(digest).expect("digest is base64url");
        assert_eq!(bytes.len(), width, "{czd:?}: width of {label}");
    }
}

#[tokio::test]
async fn a_bare_czd_is_refused_not_matched_by_width() {
    let (_, anchor, claim, wire) = certified().await;
    for (s, t, c) in czds(&wire) {
        let mut bare = wire.clone();
        let slot = &mut bare["stitches"][s]["opening"]["txs"][t][c];
        let labelled = slot.as_str().expect("string").to_owned();
        let digest = labelled
            .split_once(':')
            .map_or(labelled.as_str(), |(_, d)| d);
        *slot = json!(digest);
        let accepted = serde_json::from_value::<Certificate>(bare)
            .ok()
            .is_some_and(|cert| verify(&anchor, &cert, N, &claim).is_ok());
        assert!(!accepted, "bare czd at {s}/{t}/{c} accepted");
    }
}

#[tokio::test]
async fn a_label_that_disagrees_with_the_digest_width_is_refused() {
    let (_, anchor, claim, wire) = certified().await;
    for (s, t, c) in czds(&wire) {
        let czd = wire["stitches"][s]["opening"]["txs"][t][c]
            .as_str()
            .expect("string")
            .to_owned();
        let (label, digest) = czd
            .split_once(':')
            .unwrap_or_else(|| panic!("czd is not labelled: {czd}"));
        let width = |name: &str| WIDTHS.iter().find(|(n, _)| *n == name).expect("family").1;
        // The same digest under every other family's label: its width
        // is not that family's.
        for (other, _) in WIDTHS.iter().filter(|(n, _)| width(n) != width(label)) {
            let mut forged = wire.clone();
            forged["stitches"][s]["opening"]["txs"][t][c] = json!(format!("{other}:{digest}"));
            let accepted = serde_json::from_value::<Certificate>(forged)
                .ok()
                .is_some_and(|cert| verify(&anchor, &cert, N, &claim).is_ok());
            assert!(
                !accepted,
                "{other} label over a {label}-width digest at {s}/{t}/{c} accepted"
            );
        }
    }
}
