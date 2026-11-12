//! SPEC 7.6: re-including a transaction coz the principal already holds is
//! `COZ_REUSE`, even when that coz retired its own signer (`key/replace`,
//! `key/revoke`, `key/delete` of the signer). The reuse check must not
//! depend on the signer still being active, or a re-push of a held
//! signer-retiring commit is refused as `UnknownKey` instead.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::{Error, Key, Principal};

const T: i64 = 1_700_000_000;

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repo root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

fn key_of(e: &test_fixtures::PoolKey) -> Key {
    Key::new(
        e.alg.clone(),
        e.compute_tmb().expect("tmb"),
        Base64UrlUnpadded::decode_vec(&e.pub_key).expect("pub b64"),
    )
    .expect("key binds its tmb")
}

struct Signed {
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
}

/// `signer` signs `typ` over `target`.
fn sign(signer: &test_fixtures::PoolKey, typ: &str, target: &test_fixtures::PoolKey) -> Signed {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg,
        "id": target.compute_tmb_b64().expect("tmb"),
        "now": T,
        "tmb": signer.compute_tmb_b64().expect("tmb"),
        "typ": typ,
    }))
    .expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    Signed { pay, sig, czd }
}

/// Backs SPEC 7.6 (`COZ_REUSE`, "the first inclusion ... is authoritative"):
/// `golden` replaces itself with `key_a` in commit 1; presenting that same
/// coz again, now that its signer is gone, is `CozReuse` and the chain is
/// unchanged. Red before the fix: the signer is resolved first, so the
/// answer is `UnknownKey`.
#[tokio::test]
async fn reinclusion_of_a_signer_retiring_coz_is_coz_reuse() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let mut p = Principal::implicit(key_of(golden)).await.expect("genesis");
    test_fixtures::bundle::genesis_bundle(&mut p, golden, &[], T)
        .await
        .expect("genesis commit");

    let replace = sign(golden, "cyphr.me/cyphr/key/replace", key_a);
    let sidecar = key_of(key_a).with_first_seen(T);
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(
            &replace.pay,
            &replace.sig,
            replace.czd.clone(),
            Some(sidecar.clone()),
        )
        .expect("first inclusion");
    let prv = Base64UrlUnpadded::decode_vec(key_a.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("pub b64");
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&key_a.alg, &prv, &pubb, &key_a.compute_tmb().expect("tmb")),
            T,
            "cyphr.me",
        )
        .await
        .expect("finalize");
    let (pr, count) = (p.pr().clone(), p.commits().count());

    let scope = p.begin_commit();
    let refused = scope
        .verify(
            &replace.pay,
            &replace.sig,
            replace.czd.clone(),
            Some(sidecar),
        )
        .expect_err("re-inclusion must be refused");
    assert!(matches!(refused, Error::CozReuse), "got {refused:?}");
    drop(scope);
    assert_eq!((p.pr().clone(), p.commits().count()), (pr, count));
}
