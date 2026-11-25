//! One lifecycle gate: `Principal::require_active` is `Ok` exactly when
//! the principal's lifecycle state is `Active`, and an error otherwise.
//!
//! Scenario walk over one principal: active, frozen (`freeze/create`),
//! thawed (`freeze/delete`), deleted (`principal/delete`). At each step
//! the gate is compared with `lifecycle_state()`, the value the server
//! and client copies of this gate compare by hand today
//! (`!= LifecycleState::Active`). Which error a refusal carries is the
//! frame's to leave open; only refusal is asserted.
//!
//! Red before K1: `require_active` does not exist.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::lifecycle::LifecycleState;
use cyphr::Principal;

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
    assert_eq!(p.lifecycle_state(), want, "premise: the walk reached {want:?}");
    assert_eq!(
        p.require_active().is_ok(),
        want == LifecycleState::Active,
        "{want:?}"
    );
}

#[tokio::test]
async fn the_gate_is_open_exactly_while_active() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    p.commit_genesis(&golden.software_signer().expect("signer"), &[], T, "cyphr.me")
        .await
        .expect("genesis commit");
    assert_gate_matches_state(&p, LifecycleState::Active);

    lifecycle(&mut p, golden, "freeze/create", T + 10).await;
    assert_gate_matches_state(&p, LifecycleState::Frozen);

    lifecycle(&mut p, golden, "freeze/delete", T + 20).await;
    assert_gate_matches_state(&p, LifecycleState::Active);

    lifecycle(&mut p, golden, "principal/delete", T + 30).await;
    assert!(
        p.require_active().is_err(),
        "a deleted principal passed the gate"
    );
}
