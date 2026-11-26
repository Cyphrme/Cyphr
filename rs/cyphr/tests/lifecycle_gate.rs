//! One lifecycle gate: `Principal::require_active` is `Ok` exactly when
//! the principal's lifecycle state is `Active`, and an error otherwise.
//!
//! Scenario walk over one principal: active, frozen (`freeze/create`),
//! thawed (`freeze/delete`), deleted (`principal/delete`). At each step
//! the gate is compared with `lifecycle_state()`, the value the server
//! and client copies of this gate compare by hand today
//! (`!= LifecycleState::Active`). Which error a refusal carries is the
//! exact contracts fix: Frozen gives `Frozen`, Deleted gives
//! `AlreadyDeleted`. `authorize` carries the same gates (it is `judge` for
//! a submission), so it refuses a frozen or deleted principal's own key
//! the same way and accepts it again after the thaw. Dead, Zombie and
//! Nuked (`NoActiveKeys`, `AlreadyDeleted`) are not reached: they need a
//! revoke-everything or level-4 history this walk does not build.
//!
//! Red before K1: `require_active` does not exist.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::lifecycle::LifecycleState;
use cyphr::{Error, Principal};

const T: i64 = 1_700_000_000;

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// One commit of `golden` applying a lifecycle coz over `p`'s own root.
async fn lifecycle(p: &mut Principal, golden: &test_fixtures::PoolKey, suffix: &str, now: i64) {
    let mut pay = serde_json::json!({
        "alg": golden.alg, "id": p.pr_tagged().expect("pr"), "now": now,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": format!("cyphr.me/cyphr/{suffix}"),
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
        .unwrap_or_else(|e| panic!("{suffix} applies: {e:?}"));
    scope
        .finalize_with_software(&golden.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .unwrap_or_else(|e| panic!("{suffix} commits: {e:?}"));
}

fn assert_gate_matches_state(p: &Principal, want: LifecycleState) {
    assert_eq!(
        p.lifecycle_state(),
        want,
        "premise: the walk reached {want:?}"
    );
    let gate = p.require_active();
    match want {
        LifecycleState::Active => assert!(gate.is_ok(), "{gate:?}"),
        LifecycleState::Frozen => assert!(matches!(gate, Err(Error::Frozen)), "{gate:?}"),
        LifecycleState::Deleted => assert!(matches!(gate, Err(Error::AlreadyDeleted)), "{gate:?}"),
        other => panic!("the walk does not build {other:?}"),
    }
}

/// `authorize` of the signing key, valid for the key itself at every
/// `now` the walk uses, so only the principal's state can refuse it.
fn authorize_golden(p: &Principal, tmb: &coz::Thumbprint, now: i64) -> Result<(), Error> {
    p.authorize(tmb, now).map(|_| ())
}

#[tokio::test]
async fn the_gate_is_open_exactly_while_active() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let tmb = golden.compute_tmb().expect("tmb");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    assert!(
        matches!(authorize_golden(&p, &tmb, T), Err(Error::GenesisIncomplete)),
        "before the genesis commit"
    );
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &[],
        T,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    assert_gate_matches_state(&p, LifecycleState::Active);
    assert!(authorize_golden(&p, &tmb, T + 5).is_ok());

    lifecycle(&mut p, golden, "freeze/create", T + 10).await;
    assert_gate_matches_state(&p, LifecycleState::Frozen);
    assert!(matches!(
        authorize_golden(&p, &tmb, T + 11),
        Err(Error::Frozen)
    ));

    lifecycle(&mut p, golden, "freeze/delete", T + 20).await;
    assert_gate_matches_state(&p, LifecycleState::Active);
    assert!(authorize_golden(&p, &tmb, T + 21).is_ok());

    lifecycle(&mut p, golden, "principal/delete", T + 30).await;
    assert_gate_matches_state(&p, LifecycleState::Deleted);
    assert!(matches!(
        authorize_golden(&p, &tmb, T + 31),
        Err(Error::AlreadyDeleted)
    ));
}

/// Regression: `require_active` once sat on `impl Principal` (default
/// storage only), so a caller generic over `Principal<S>` could not call
/// it. This must compile for any storage.
fn gate<S: eml::Storage>(p: &Principal<S>) -> Result<(), Error> {
    p.require_active()
}

#[tokio::test]
async fn the_gate_is_callable_for_any_storage() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &[],
        T,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    assert!(gate(&p).is_ok());
}
