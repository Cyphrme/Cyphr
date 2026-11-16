//! SPEC 7.6: replaying a data action the principal already holds is
//! ignored and changes no state. That must hold when the action's signer
//! was retired by a commit dated the same second (a signature dated exactly
//! at a removal is judged after it by the key timeline, forge #213), because every client that
//! pushes or saves resubmits the actions it holds after its commits.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::signer::SoftwareSigner;
use serde_json::json;

const T: i64 = 1_700_000_000;

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn sign(k: &coz::KeyPair, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay bytes");
    let alg = k.alg.name();
    let (sig, cad) = coz::sign_json(&v, alg, &k.prv_bytes, &k.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
    (v, sig, czd)
}

/// Red before the fix (NETSIM-2): the signer is judged (`UnknownKey`) before the
/// held-czd check, so the re-presented action is refused instead of ignored.
#[tokio::test]
async fn held_action_resubmitted_after_same_second_replace_is_ignored() {
    let g = coz::Alg::Ed25519.generate_keypair();
    let g_tmb = g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb");
    let k2 = coz::Alg::Ed25519.generate_keypair();
    let k2_tmb = k2.alg.compute_thumbprint(&k2.pub_bytes).expect("tmb");
    let key = |k: &coz::KeyPair, t: &coz::Thumbprint| {
        cyphr::Key::new(k.alg.name().to_string(), t.clone(), k.pub_bytes.clone()).expect("key")
    };

    let mut p = Principal::implicit(key(&g, &g_tmb)).await.expect("genesis");
    p.commit_genesis(
        &SoftwareSigner::new(g.alg.name(), &g.prv_bytes, &g.pub_bytes, &g_tmb),
        &[],
        1,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");

    // An action by g at T + 5 is held.
    let (apay, asig, aczd) = sign(
        &g,
        json!({"alg": g.alg.name(), "now": T + 5, "tmb": b64(g_tmb.as_bytes()),
               "typ": "cyphr.me/cyphr/data/x"}),
    );
    p.verify_and_record_action(&apay, &asig, aczd.clone())
        .expect("first inclusion");

    // g replaces itself by k2 in a commit dated the same second.
    let (rpay, rsig, rczd) = sign(
        &g,
        json!({"alg": g.alg.name(), "id": b64(k2_tmb.as_bytes()), "now": T + 5,
               "tmb": b64(g_tmb.as_bytes()), "typ": "cyphr.me/cyphr/key/replace"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&rpay, &rsig, rczd, Some(key(&k2, &k2_tmb)))
        .expect("replace applies");
    scope
        .finalize_with_software(
            &SoftwareSigner::new(g.alg.name(), &g.prv_bytes, &g.pub_bytes, &g_tmb),
            T + 5,
            "cyphr.me",
        )
        .await
        .expect("finalize");

    p.verify_and_record_action(&apay, &asig, aczd)
        .expect("a held action is ignored when presented again (SPEC 7.6)");
}
