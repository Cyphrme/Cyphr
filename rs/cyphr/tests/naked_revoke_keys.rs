//! A naked revoke discloses its signer in `keys`, a required array of
//! exactly one key (SPEC 4.6.1: "If a plural is possibly valid, the plural
//! is always used"; `key` is prohibited).
//!
//! Property: over every correctly signed revoke, the envelope is accepted
//! exactly when `keys` is an array of one `{alg, pub}` and `key` is not
//! how the key is given. A singular `key`, no key field, an empty array,
//! two keys, or a non-array are each `Malformed`, and none is read as the
//! disclosed key.
//!
//! Red before the rename: `keys` is not read, so the accepted shape is
//! refused and the prohibited `key` is accepted.

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

/// A signed naked revoke of `golden` and the key object that discloses it.
fn signed() -> (Value, Value) {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut pay = json!({
        "alg": golden.alg,
        "now": 1_700_000_000,
        "rvk": 1_700_000_000,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    pay.as_object_mut().expect("object").sort_keys();
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_deref().expect("prv")).expect("prv");
    let public = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub");
    let (sig, _) = coz::sign_json(&bytes, &golden.alg, &prv, &public).expect("sign");
    (
        json!({"pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig)}),
        json!({"alg": golden.alg, "pub": golden.pub_key}),
    )
}

fn with(field: &str, value: Value) -> Value {
    let (mut envelope, _) = signed();
    envelope[field] = value;
    envelope
}

fn assert_malformed(envelope: &Value, why: &str) {
    assert!(
        matches!(
            verify_naked_revoke(envelope),
            Err(RevokeFailure::Malformed(_))
        ),
        "{why}: {:?}",
        verify_naked_revoke(envelope)
    );
}

#[test]
fn one_key_in_keys_is_accepted() {
    let (_, key) = signed();
    assert!(verify_naked_revoke(&with("keys", json!([key]))).is_ok());
}

#[test]
fn the_prohibited_singular_key_is_not_read() {
    let (_, key) = signed();
    assert_malformed(&with("key", key), "singular `key`");
}

#[test]
fn keys_of_any_other_size_or_shape_is_malformed() {
    let (envelope, key) = signed();
    assert_malformed(&envelope, "no key field");
    assert_malformed(&with("keys", json!([])), "empty keys");
    assert_malformed(&with("keys", json!([key.clone(), key.clone()])), "two keys");
    assert_malformed(&with("keys", key), "keys as an object, not an array");
}

#[test]
fn a_singular_key_beside_keys_is_malformed() {
    let (_, key) = signed();
    let mut envelope = with("keys", json!([key.clone()]));
    envelope["key"] = key;
    assert_malformed(&envelope, "`key` is prohibited even beside a valid `keys`");
}
