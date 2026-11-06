//! Genesis-key validation (N12). Checkpoint restore is cut, so its tests
//! are gone with it.
//!
//! - `genesis_*`: every genesis key is validated (a duplicate key is refused, not dropped), and
//!   implicit and explicit genesis both refuse a pre-revoked key with the same typed error (SPEC
//!   be0663f 7.7: every key, the first included, needs a `key/create`; 6.4: a revoked key is never
//!   trusted again).
//!
//! Run the red ones with `cargo test -p cyphr --test genesis_keys -- --ignored`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::HashAlg;
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
#[ignore = "RED(N12): explicit genesis collapses duplicate keys into the key map"]
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

/// Characterization: an unsupported algorithm cannot reach genesis at
/// all, because `Key` refuses to exist for it (no thumbprint), so the
/// "validate every key's algorithm" duty is discharged by the type. Turns
/// red if `Key` starts admitting a key whose algorithm has no hash
/// algorithm, which would reopen the `keys[0]`-only check in genesis.
#[test]
fn genesis_unsupported_algorithm_is_unconstructible() {
    let bad = pool_key("unsupported_key");
    assert_eq!(bad.alg, "RS256", "premise: the pool's unsupported key");
    let r = Key::new(bad.alg.clone(), bad.tmb.clone(), bad.pubb.clone());
    assert!(matches!(r, Err(cyphr::Error::UnknownAlg)), "{r:?}");
}

/// Claim: a pre-revoked genesis key is refused by both genesis paths
/// with the same typed error (SPEC be0663f 7.7 and 6.4). Turns red if
/// either path accepts it or the two refuse differently (today implicit
/// genesis returns `Ok`, explicit returns `NoActiveKeys`).
#[test]
#[ignore = "RED(N12): implicit genesis accepts a pre-revoked key; the paths disagree"]
fn genesis_implicit_and_explicit_agree_on_pre_revoked_key() {
    let g = pool_key("golden");
    let revoked = key_of(&g).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let implicit = Principal::implicit(revoked.clone()).map(|_| ());
    let explicit = Principal::explicit(vec![revoked]).map(|_| ());
    let (Err(i), Err(e)) = (&implicit, &explicit) else {
        panic!("pre-revoked genesis key accepted: implicit {implicit:?}, explicit {explicit:?}");
    };
    assert_eq!(
        std::mem::discriminant(i),
        std::mem::discriminant(e),
        "refused with different errors: implicit {i:?}, explicit {e:?}"
    );
}

/// Green control for the agreed paths: one supported key gives the same
/// algorithm set through implicit and explicit genesis, and a mixed-algorithm
/// explicit genesis derives the union. Catches a "fix" that breaks the
/// ordinary genesis while tightening validation.
#[test]
fn genesis_control_valid_keys_agree_and_derive_algs() {
    for name in ["golden", "diana_es384", "eve_ed25519"] {
        let k = key_of(&pool_key(name));
        let i = Principal::implicit(k.clone()).expect("implicit");
        let e = Principal::explicit(vec![k]).expect("explicit");
        assert_eq!(i.active_algs(), e.active_algs(), "{name}: alg set");
        assert_eq!(i.pr(), e.pr(), "{name}: PR");
    }
    let mixed = Principal::explicit(vec![
        key_of(&pool_key("golden")),
        key_of(&pool_key("diana_es384")),
    ])
    .expect("mixed explicit");
    assert_eq!(mixed.active_algs(), vec![HashAlg::Sha256, HashAlg::Sha384]);
}
