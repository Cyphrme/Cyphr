//! A principal's state does not depend on whether a naked revoke arrived
//! before a later commit or after every commit (U3: a state kept past a
//! revoke must be the one a replay of the same history builds, and a
//! replay takes revokes in after the commits).
//!
//! Scenario: `key_a` is a key of the principal and stays in its Key Tree
//! through two later commits. A principal that took in a naked revoke of
//! `key_a` between the two commits (a live one) and one that replayed both
//! commits and then took it in (a rebuild) hold the same state, and judge
//! `key_a`'s data actions the same way. Red before: the live principal
//! opened a second, empty period for `key_a` at every commit after the
//! revoke, so the two states differed, and a commit that removed the key
//! at a time before the revoke's cutoff left it authorized until the
//! cutoff.
//! End to end: yes (signed commits replayed through the public entry
//! point).

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::{Bundle, StoredCoz, replay_bundle};
use cyphr::{Key, Principal};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

/// One commit of `author` in which `golden` creates (or deletes) `name`,
/// as the bundle a replay takes.
async fn commit(
    author: &mut Principal,
    golden: &test_fixtures::PoolKey,
    typ: &str,
    name: &test_fixtures::PoolKey,
    now: i64,
) -> Bundle {
    let mut pay = serde_json::json!({
        "alg": golden.alg, "id": name.compute_tmb_b64().expect("tmb"), "now": now,
        "tmb": golden.compute_tmb_b64().expect("tmb"),
        "typ": format!("{AUTHORITY}/cyphr/key/{typ}"),
    });
    pay.as_object_mut().expect("object").sort_keys();
    let pay = serde_json::to_vec(&pay).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_deref().expect("prv")).expect("prv");
    let pubk = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("pub");
    let (sig, cad) = coz::sign_json(&pay, &golden.alg, &prv, &pubk).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");
    let introduced: Vec<Key> = if typ == "create" {
        vec![name.key().expect("key")]
    } else {
        Vec::new()
    };
    let mut scope = author.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, introduced.first().cloned())
        .expect("applies");
    let commit = scope
        .finalize_with_software(
            &golden.software_signer().expect("signer"),
            now + 1,
            AUTHORITY,
        )
        .await
        .expect("finalizes");
    let txs: Vec<Vec<StoredCoz>> = commit
        .transactions()
        .iter()
        .map(|tx| {
            tx.0.iter()
                .map(|vc| StoredCoz::new(&vc.raw().pay, vc.raw().sig.clone()).expect("coz"))
                .collect()
        })
        .collect();
    Bundle::new(Vec::new(), txs, introduced).expect("bundle")
}

async fn genesis(pool: &test_fixtures::Pool) -> Principal {
    let golden = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(golden.key().expect("key"))
        .await
        .expect("open");
    let key_a = pool.get("key_a").expect("key_a").key().expect("key");
    p.commit_genesis(
        &golden.software_signer().expect("signer"),
        &[key_a],
        T,
        AUTHORITY,
    )
    .await
    .expect("genesis commit");
    p
}

#[tokio::test]
async fn a_naked_revoke_taken_in_before_a_commit_leaves_the_state_a_replay_builds() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let key_a = pool.get("key_a").expect("key_a");
    let tmb_a = key_a.compute_tmb().expect("tmb");

    // The commits, authored once: `key_a` stays in the Key Tree throughout.
    let mut author = genesis(&pool).await;
    let first = commit(
        &mut author,
        golden,
        "create",
        pool.get("alice").expect("alice"),
        T + 10,
    )
    .await;
    let second = commit(
        &mut author,
        golden,
        "create",
        pool.get("bob").expect("bob"),
        T + 30,
    )
    .await;

    let mut live = genesis(&pool).await;
    replay_bundle(&mut live, &first).await.expect("first");
    live.note_naked_revoke(&tmb_a, T + 20);
    replay_bundle(&mut live, &second).await.expect("second");

    let mut rebuilt = genesis(&pool).await;
    replay_bundle(&mut rebuilt, &first).await.expect("first");
    replay_bundle(&mut rebuilt, &second).await.expect("second");
    rebuilt.note_naked_revoke(&tmb_a, T + 20);

    assert!(
        format!("{:#?}", *live) == format!("{:#?}", *rebuilt),
        "the state of a principal that took the revoke in between its commits is not the state of \
         the replay"
    );
}
