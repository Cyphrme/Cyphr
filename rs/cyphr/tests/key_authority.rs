//! One key-authority answer: `Principal::authorize(&tmb, now)` says
//! whether `tmb` may sign a message dated `now`, and returns the key.
//!
//! Scenario: `golden` creates `key_a` at genesis (time `T`) and deletes it
//! in a later commit at `T + 10`. Properties:
//! - a key is authorized exactly from the commit that added it up to the
//!   commit that removed it; a message dated at the removal is judged
//!   after it (`principal/timeline.rs` `authorize` doc), and one dated
//!   before genesis finds no key;
//! - a thumbprint the principal never held is `UnknownKey`;
//! - the key returned is the key asked for;
//! - metamorphic against the existing predicate: at a `now` after every
//!   commit, `authorize` succeeds exactly when `is_key_active` says so,
//!   for every key of the pool.
//!
//! Red before K1: `Principal::authorize` is not public, so the storage,
//! client and server copies of this rule had nothing to call.

use cyphr::{Error, Principal};

const T: i64 = 1_700_000_000;
const AFTER_ALL: i64 = T + 1_000;

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// Genesis with `key_a` at `T`, then `golden` deletes `key_a` at `T + 10`.
async fn principal(pool: &test_fixtures::Pool) -> Principal {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &[key_a.key().expect("key")],
        T,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");

    let mut pay = serde_json::json!({
        "alg": golden.alg, "id": key_a.compute_tmb_b64().expect("tmb"), "now": T + 10,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/key/delete",
    });
    pay.as_object_mut().expect("object").sort_keys();
    let pay = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_deref().expect("prv")).expect("prv");
    let pubk = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub");
    let (sig, cad) = coz::sign_json(&pay, &golden.alg, &prv, &pubk).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("key/delete applies");
    scope
        .finalize_with_software(&golden.software_signer().expect("signer"), T + 10, "cyphr.me")
        .await
        .expect("commit");
    p
}

#[tokio::test]
async fn a_key_is_authorized_from_its_commit_to_its_removal() {
    let pool = pool();
    let p = principal(&pool).await;
    let tmb = pool.get("key_a").expect("key_a").compute_tmb().expect("tmb");

    assert!(p.authorize(&tmb, T - 1).is_err(), "before genesis");
    for now in [T, T + 5, T + 9] {
        let key = p.authorize(&tmb, now).expect("held");
        assert_eq!(key.tmb(), &tmb, "the key returned is the key asked for");
    }
    for now in [T + 10, T + 11, AFTER_ALL] {
        assert!(
            matches!(p.authorize(&tmb, now), Err(Error::UnknownKey)),
            "now {now}"
        );
    }
}

#[tokio::test]
async fn a_key_the_principal_never_held_is_unknown() {
    let pool = pool();
    let p = principal(&pool).await;
    let tmb = pool.get("alice").expect("alice").compute_tmb().expect("tmb");
    assert!(matches!(p.authorize(&tmb, T + 5), Err(Error::UnknownKey)));
}

#[tokio::test]
async fn authorize_after_every_commit_is_is_key_active() {
    let pool = pool();
    let p = principal(&pool).await;
    for name in ["golden", "key_a", "alice", "bob"] {
        let tmb = pool.get(name).expect(name).compute_tmb().expect("tmb");
        assert_eq!(
            p.authorize(&tmb, AFTER_ALL).is_ok(),
            p.is_key_active(&tmb),
            "{name}"
        );
    }
}
