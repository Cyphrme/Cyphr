//! Genesis-key validation (N12). Checkpoint restore is cut, so its tests
//! are gone with it.
//!
//! - `genesis_*`: the genesis key is validated: a pre-revoked key is refused with `KeyRevoked`, the
//!   refusal `key/create` gives a revoked tmb (SPEC be0663f 7.7: every key, the first included,
//!   needs a `key/create`; 6.4: a revoked key is never trusted again). Every further key enters by
//!   `key/create`, whose duplicate refusal the golden `duplicate_key_fails` vector pins.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Key, Principal};

const T: i64 = 1_700_000_000;

// ============================================================================
// Harness
// ============================================================================

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

fn pool_key(name: &str) -> Kp {
    let pool = pool();
    let pk = pool.get(name).expect("key in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    Kp {
        alg: pk.alg.clone(),
        pubb: d(&pk.pub_key),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

// ============================================================================
// Genesis: the genesis key is validated
// ============================================================================

/// Claim: a pre-revoked genesis key is refused with `KeyRevoked`, the
/// refusal `key/create` gives a revoked tmb (SPEC be0663f 7.7 and 6.4).
/// Turns red if genesis accepts it or refuses with another error. Not
/// end-to-end: no scenario reaches the constructor's check more cheaply.
#[test]
fn genesis_refuses_pre_revoked_key() {
    let g = pool_key("golden");
    let revoked = key_of(&g).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let r = Principal::implicit(revoked).map(|_| ());
    assert!(
        matches!(r, Err(cyphr::Error::KeyRevoked)),
        "genesis of a pre-revoked key: expected Err(KeyRevoked), got {r:?}"
    );
}
