//! A genesis whose keys use two hash families (ES256 and Ed25519: SHA-256
//! and SHA-512) names its principal by two variants of one PG. The engine
//! keys the principal by the canonical one (the first, SHA-256).
//!
//! Regression for the claim check in `submit_commit` (SPEC 12.1: every hash
//! variant of a genesis is equivalent): a claim by any variant of the
//! genesis the bundle derives is accepted, and the principal is stored under
//! the canonical id. A digest that is no variant of that genesis is refused.
//! Once stored, either variant reads the principal through the index's
//! aliases.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::HashAlg;
use cyphr::{PrincipalGenesis, StateDigest};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;
use cyphr_storage::{Genesis, KeyEntry};

fn pool_key(name: &str) -> test_fixtures::PoolKey {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool.toml");
    pool.get(name).expect("pool key").clone()
}

fn domain_key(pk: &test_fixtures::PoolKey) -> cyphr::Key {
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub base64");
    cyphr::Key::new(pk.alg.clone(), pk.compute_tmb().expect("tmb"), pub_bytes).expect("key")
}

fn raw_blob(pay: &[u8], sig: &[u8]) -> Vec<u8> {
    let pay: serde_json::Value = serde_json::from_slice(pay).expect("pay json");
    serde_json::to_vec(&serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(sig),
    }))
    .expect("blob")
}

#[tokio::test]
async fn a_mixed_algorithm_genesis_is_claimed_by_any_of_its_variants() {
    let key_a = pool_key("golden");
    let key_b = pool_key("eve_ed25519");
    let now = 1_700_000_000i64;
    let keys = vec![domain_key(&key_a), domain_key(&key_b)];
    let prv_a = Base64UrlUnpadded::decode_vec(key_a.prv.as_ref().expect("prv")).expect("prv");
    let pub_a = Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("pub");
    let tmb_a = key_a.compute_tmb().expect("tmb");
    let signer = cyphr::signer::SoftwareSigner::new(&key_a.alg, &prv_a, &pub_a, &tmb_a);

    let mut client = cyphr::Principal::implicit(keys[0].clone())
        .await
        .expect("genesis");
    let mut scope = client.begin_commit();
    let creates: Vec<Vec<u8>> = scope
        .create_genesis_keys(&signer, &keys[1..], now, "cyphr.me")
        .await
        .expect("genesis key/creates")
        .iter()
        .map(|c| serde_json::to_vec(c).expect("blob"))
        .collect();
    let first_variant = scope.genesis_id().expect("genesis id");
    let pc_pay = serde_json::to_vec(&serde_json::json!({
        "alg": key_a.alg,
        "id": &first_variant,
        "now": now,
        "tmb": key_a.compute_tmb_b64().expect("tmb"),
        "typ": "cyphr.me/cyphr/principal/create",
    }))
    .expect("pay");
    let cad = coz::canonical_hash_for_alg(&pc_pay, &key_a.alg, None).expect("cad");
    let sig = coz::sign_json(&pc_pay, &key_a.alg, &prv_a, &pub_a)
        .expect("sign")
        .0;
    let czd = coz::czd_for_alg(&cad, &sig, &key_a.alg).expect("czd");
    scope
        .verify_and_apply(&pc_pay, &sig, czd, None)
        .expect("principal/create");
    let commit = scope
        .finalize_with_software(&signer, now + 1, "cyphr.me")
        .await
        .expect("commit");
    let cc_blob = serde_json::to_vec(commit.commit_tx().0[0].raw()).expect("commit blob");

    let pg = client.pg().expect("PG established").clone();
    let variants = pg.as_multihash().variants();
    assert_eq!(variants.len(), 2, "premise: one variant per hash family");
    let second = PrincipalGenesis::from_digest(
        HashAlg::Sha512,
        variants
            .get(&HashAlg::Sha512)
            .expect("SHA-512 variant")
            .to_vec(),
    )
    .expect("width");
    assert_ne!(
        second, first_variant,
        "premise: the second variant is another spelling"
    );

    let bundle = cyphr::replay::WireBundle {
        txs: creates
            .iter()
            .chain([&raw_blob(&pc_pay, &sig), &cc_blob])
            .map(|b| vec![b.clone()])
            .collect(),
        keys: keys.iter().map(KeyEntry::of).collect(),
        ..Default::default()
    };
    let new_engine = || {
        StorageEngine::new(
            cyphr_storage::blob::MemoryBlobStore::new(),
            MemoryIndexer::new(),
        )
    };
    // SPEC 12.1: any variant of the derived genesis names it. Claimed by
    // the SHA-512 variant alone, the principal is stored under the
    // canonical id and read back by either variant.
    let engine = new_engine();
    let stored = engine
        .submit_commit(&second, Some(Genesis::Disclosed(keys.clone())), &bundle)
        .await
        .expect("a claim by the SHA-512 variant of the genesis names it");

    assert_eq!(stored.principal_id, pg, "stored under the canonical id");
    assert_eq!(
        stored.principal_id, first_variant,
        "which is the first variant"
    );
    for id in [&pg, &first_variant, &second] {
        let tip = engine.get_tip(id).await.expect("tip").expect("stored");
        assert_eq!(tip.principal_id, pg, "read by {id}");
    }

    // A digest that is no variant of the genesis still names nothing.
    let other = PrincipalGenesis::from_digest(HashAlg::Sha512, vec![9u8; 64]).expect("width");
    let refused = new_engine()
        .submit_commit(&other, Some(Genesis::Disclosed(keys)), &bundle)
        .await
        .expect_err("a digest that is no variant of the genesis names nothing");
    assert!(
        matches!(refused, cyphr_storage::engine::EngineError::InvalidInput(_)),
        "{refused:?}"
    );
}
