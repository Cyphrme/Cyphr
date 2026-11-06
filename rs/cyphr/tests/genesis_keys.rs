//! Genesis-key validation (N12). Checkpoint restore is cut, so its tests
//! are gone with it.
//!
//! - `genesis_*`: every genesis key is validated (a duplicate key is refused, not dropped), and
//!   implicit and explicit genesis both refuse a pre-revoked key with `KeyRevoked`, the refusal
//!   `key/create` gives a revoked tmb (SPEC be0663f 7.7: every key, the first included, needs a
//!   `key/create`; 6.4: a revoked key is never trusted again).

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
// Genesis: every key validated; implicit and explicit agree
// ============================================================================

/// Claim: genesis refuses a duplicate key instead of silently collapsing
/// it. Turns red if a duplicate genesis key is dropped (the principal is
/// built from fewer keys than the caller named, so its roots differ from
/// what the caller computed). Not end-to-end: no scenario reaches the
/// constructor's argument check more cheaply.
#[test]
fn genesis_refuses_duplicate_key() {
    let (g, a) = (pool_key("golden"), pool_key("key_a"));
    for keys in [
        vec![key_of(&g), key_of(&g)],
        vec![key_of(&g), key_of(&a), key_of(&g)],
    ] {
        let n = keys.len();
        let r = Principal::explicit(keys);
        assert!(
            matches!(r, Err(cyphr::Error::DuplicateKey)),
            "{n}-key genesis with a repeated key was not refused as DuplicateKey: {:?}",
            r.map(|p| p.active_key_count())
        );
    }
}

/// Claim: a pre-revoked genesis key is refused by both genesis paths
/// with `KeyRevoked`, the refusal `key/create` gives a revoked tmb (SPEC be0663f 7.7 and 6.4).
/// Turns red if either path accepts it or refuses with another error (today implicit
/// genesis returns `Ok`, explicit returns `NoActiveKeys`).
#[test]
fn genesis_implicit_and_explicit_agree_on_pre_revoked_key() {
    let g = pool_key("golden");
    let revoked = key_of(&g).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let implicit = Principal::implicit(revoked.clone()).map(|_| ());
    let explicit = Principal::explicit(vec![revoked]).map(|_| ());
    for (path, r) in [("implicit", &implicit), ("explicit", &explicit)] {
        assert!(
            matches!(r, Err(cyphr::Error::KeyRevoked)),
            "{path} genesis of a pre-revoked key: expected Err(KeyRevoked), got {r:?}"
        );
    }
}
