//! Refusals that keep the key set well-formed.
//!
//! SPEC 6.3: `key/replace` "removes the signing key and adds a new key
//! atomically". Naming a key the principal already holds either empties the
//! set (the signer) or acts as a silent delete (another held key); SPEC 7.6
//! makes a `create` of an existing item `DUPLICATE`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::{Error, Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let k = coz::Alg::Ed25519.generate_keypair();
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

fn software(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

fn b64(t: &coz::Thumbprint) -> String {
    Base64UrlUnpadded::encode_string(t.as_bytes())
}

type Signed = (Vec<u8>, Vec<u8>, coz::Czd);

fn sign(k: &Kp, mut pay: serde_json::Value) -> Signed {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

fn replace(signer: &Kp, id: &coz::Thumbprint, now: i64) -> Signed {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/replace"}),
    )
}

/// A principal over `keys[0]`'s genesis, which creates the rest.
async fn principal_of(keys: &[Kp]) -> Principal {
    let others: Vec<Key> = keys[1..].iter().map(key_of).collect();
    let mut p = Principal::implicit(key_of(&keys[0]))
        .await
        .expect("implicit");
    p.commit_genesis(&software(&keys[0]), &others, 1, "cyphr.me")
        .await
        .expect("genesis commit");
    p
}

fn state(p: &Principal) -> (cyphr::PrincipalRoot, usize, usize) {
    (p.pr().clone(), p.active_key_count(), p.commits().count())
}

/// Regression: `key/replace` naming the signer left no keys, and naming
/// another held key deleted the signer without adding anything. For every
/// key a principal holds, replacing onto it is refused as a duplicate and
/// leaves the principal untouched; replacing onto a fresh key still swaps.
#[tokio::test]
async fn replace_onto_a_held_key_is_refused_and_a_fresh_key_swaps() {
    let keys = [kp(), kp(), kp()];
    let fresh = kp();
    for named in &keys {
        let mut p = principal_of(&keys).await;
        let before = state(&p);
        let mut scope = p.begin_commit();
        let (pay, sig, czd) = replace(&keys[0], &named.tmb, T);
        let refused = scope.verify_and_apply(&pay, &sig, czd, Some(key_of(named)));
        assert!(
            matches!(refused, Err(Error::DuplicateKey)),
            "naming a held key: {refused:?}"
        );
        drop(scope);
        assert_eq!(before, state(&p), "a refused replace changed state");
    }

    let mut p = principal_of(&keys).await;
    let mut scope = p.begin_commit();
    let (pay, sig, czd) = replace(&keys[0], &fresh.tmb, T);
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(&fresh)))
        .expect("replace onto a fresh key");
    scope
        .finalize_with_software(&software(&fresh), T + 1, "cyphr.me")
        .await
        .expect("finalize");
    assert_eq!(p.active_key_count(), keys.len());
    assert!(!p.is_key_active(&keys[0].tmb));
    assert!(p.is_key_active(&fresh.tmb));
}
