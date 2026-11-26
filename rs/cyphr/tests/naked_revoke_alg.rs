//! A naked revoke's `pay.alg` is the signing key's algorithm (SPEC 2.3.1:
//! "All cozies must have the fields: `alg` ..., `alg` is the algorithm of
//! the signing key"). `verify_naked_revoke` read the disclosed key's
//! algorithm and never `pay.alg`, so an envelope with no `alg`, or one
//! naming another algorithm, was accepted.
//!
//! Property: for a correctly signed revoke, accepted exactly when
//! `pay.alg` is present and equals the disclosed key's algorithm; absent
//! is `Malformed("pay has no alg")`, different is `KeyMismatch`.
//!
//! Red before the `verify_signed` split: both refusals were accepted.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::revoke::{RevokeFailure, verify_naked_revoke};
use serde_json::{Value, json};

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// A naked revoke of `golden` signed by it; `alg` is the `pay.alg` it
/// carries (`None` leaves the field out). The signature covers that pay.
fn envelope(alg: Option<&str>) -> Value {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut pay = json!({
        "now": 1_700_000_000,
        "rvk": 1_700_000_000,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    if let Some(alg) = alg {
        pay["alg"] = json!(alg);
    }
    pay.as_object_mut().expect("object").sort_keys();
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_deref().expect("prv")).expect("prv");
    let public = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub");
    let (sig, _) = coz::sign_json(&bytes, &golden.alg, &prv, &public).expect("sign");
    json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": golden.alg, "pub": golden.pub_key},
    })
}

#[test]
fn a_matching_alg_is_accepted() {
    let alg = pool().get("golden").expect("golden").alg.clone();
    assert!(verify_naked_revoke(&envelope(Some(&alg))).is_ok());
}

#[test]
fn a_missing_alg_is_malformed() {
    assert_eq!(
        verify_naked_revoke(&envelope(None)),
        Err(RevokeFailure::Malformed("pay has no alg"))
    );
}

#[test]
fn a_different_alg_is_a_key_mismatch() {
    let golden_alg = pool().get("golden").expect("golden").alg.clone();
    for other in ["ES256", "ES384", "Ed25519"] {
        if other == golden_alg {
            continue;
        }
        assert_eq!(
            verify_naked_revoke(&envelope(Some(other))),
            Err(RevokeFailure::KeyMismatch),
            "pay.alg {other} over a {golden_alg} key"
        );
    }
}
