//! A principal detached onto an in-memory log keeps checking commits as
//! the original does (SPEC 3: the Commit Root is the root of the commit
//! log, so a holder that continues a chain must derive the same roots from
//! the same commits whatever store its log sits on).
//!
//! Scenario: a principal with a genesis commit and three more is replayed
//! to each prefix, detached there, and given the remaining commits. At
//! every prefix the result holds the state, and so the PR and Commit Root,
//! of the principal that replayed the whole chain without detaching.
//! Turns red if: the seeded log's frontier differs from the original's (a
//! later commit's Commit Root, hence its PR, would differ and the commit
//! would be refused or admitted to another state), or a detached principal
//! cannot append.
//! End to end: yes (signed commits through the public replay entry point).

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
async fn a_detached_principal_derives_the_roots_of_the_original_at_every_prefix() {
    let pool = pool();
    let golden = pool.get("golden").expect("golden");
    let mut author = genesis(&pool).await;
    let mut bundles = Vec::new();
    for (name, at) in [("alice", 10), ("bob", 20), ("carol", 30)] {
        let named = pool.get(name).expect("pool key");
        bundles.push(commit(&mut author, golden, "create", named, T + at).await);
    }

    let mut whole = genesis(&pool).await;
    for bundle in &bundles {
        replay_bundle(&mut whole, bundle).await.expect("replays");
    }

    for prefix in 0..=bundles.len() {
        let mut held = genesis(&pool).await;
        for bundle in &bundles[..prefix] {
            replay_bundle(&mut held, bundle).await.expect("replays");
        }
        let mut detached = held.detach().await.expect("detaches");
        for bundle in &bundles[prefix..] {
            replay_bundle(&mut detached, bundle)
                .await
                .expect("a detached principal appends");
        }
        assert_eq!(
            detached.projection(),
            whole.projection(),
            "detached after {prefix} commits"
        );
        let count = detached.commit_count();
        assert_eq!(count, bundles.len() + 1, "the genesis commit and the rest");
        assert!(detached.commit_at(count - 1).is_some());
        assert!(detached.commit_at(count).is_none());
    }
}
