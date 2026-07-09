//! F40 investigation: does a genuinely fresh explicit multi-key genesis
//! (2+ keys, zero prior commits), signed and submitted through the real
//! production path, accept a second commit on top of it?
//!
//! This drives `StorageEngine::submit_commit` twice against a *durable*
//! fjall backend (not the in-memory default), sharing one physical
//! database across both calls exactly like `multitenancy.rs`/
//! `durable_commit_trees.rs` do — the scenario `cyphr-storage/src/engine/
//! tests.rs`'s in-memory-backend regression test (of the same shape)
//! could not reproduce a failure in.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::engine::StorageEngine;

fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

fn pool_key_to_domain(pk: &test_fixtures::PoolKey) -> cyphr::Key {
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub base64");
    let tmb = pk.compute_tmb().expect("pool tmb");
    cyphr::Key {
        alg: pk.alg.clone(),
        tmb,
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn pool_key_json(pk: &test_fixtures::PoolKey) -> serde_json::Value {
    serde_json::json!({
        "alg": pk.alg,
        "pub": pk.pub_key,
        "tmb": pk.compute_tmb_b64().expect("pool tmb b64"),
    })
}

fn sign_pay(pk: &test_fixtures::PoolKey, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    let mut pay = pay;
    pay.as_object_mut().expect("pay object").sort_keys();
    let pay_vec = serde_json::to_vec(&pay).expect("serialize pay");

    let prv_bytes = Base64UrlUnpadded::decode_vec(
        pk.prv
            .as_ref()
            .unwrap_or_else(|| panic!("pool key '{}' has no private key material", pk.name)),
    )
    .expect("pool prv base64");
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub base64");

    let (sig, _cad) =
        coz::sign_json(&pay_vec, &pk.alg, &prv_bytes, &pub_bytes).expect("sign_json");
    (pay_vec, sig)
}

fn raw_blob(pay_bytes: &[u8], sig: &[u8], key: Option<serde_json::Value>) -> Vec<u8> {
    let pay_val: serde_json::Value = serde_json::from_slice(pay_bytes).expect("pay json");
    let mut obj = serde_json::Map::new();
    obj.insert("pay".to_string(), pay_val);
    obj.insert(
        "sig".to_string(),
        serde_json::json!(Base64UrlUnpadded::encode_string(sig)),
    );
    if let Some(k) = key {
        obj.insert("key".to_string(), k);
    }
    serde_json::to_vec(&serde_json::Value::Object(obj)).expect("serialize blob")
}

fn commit_tx_raw_blob(commit: &cyphr::commit::Commit, n: usize) -> Vec<u8> {
    let vtx = &commit.commit_tx().0[n];
    let raw = vtx.raw();
    serde_json::to_vec(raw).expect("serialize raw coz json")
}

/// F40: mirrors `submit_commit_explicit_multi_key_genesis_second_commit_succeeds`
/// in `cyphr-storage/src/engine/tests.rs` exactly, except the engine is
/// backed by a *durable* fjall database (shared across both `submit_commit`
/// calls in-process, exactly as `multitenancy.rs` wires it) instead of the
/// in-memory default — the one combination that regression test could not
/// cover, since `load_principal`'s replay of commit #1 during the second
/// call hits fjall's `already_durable` branch in `finalize_commit` (the
/// leaf is already on disk from the first `submit_commit`), not a fresh
/// append.
#[tokio::test]
async fn submit_commit_durable_explicit_multi_key_genesis_second_commit() {
    let pool = load_pool();
    let key_a = pool.get("golden").expect("pool key golden");
    let key_b = pool.get("alice").expect("pool key alice");
    let key_c = pool.get("bob").expect("pool key bob");

    let now = 1_700_000_000i64;
    let a_tmb_b64 = key_a.compute_tmb_b64().expect("golden tmb b64");
    let tmb_a = key_a.compute_tmb().expect("golden tmb");

    let genesis_domain_keys = vec![pool_key_to_domain(key_a), pool_key_to_domain(key_b)];
    let genesis = Genesis::Explicit(genesis_domain_keys.clone());

    let mut client = cyphr::Principal::explicit(genesis_domain_keys).expect("client genesis");
    let id_tagged = client
        .pr_tagged()
        .expect("pr_tagged should succeed for a fresh genesis");

    let pc_pay = serde_json::json!({
        "alg": key_a.alg,
        "id": id_tagged,
        "now": now,
        "tmb": a_tmb_b64,
        "typ": "cyphr.me/cyphr/principal/create",
    });
    let (pc_pay_bytes, pc_sig) = sign_pay(key_a, pc_pay);
    let pc_blob = raw_blob(&pc_pay_bytes, &pc_sig, None);
    let pc_czd = {
        let cad = coz::canonical_hash_for_alg(&pc_pay_bytes, &key_a.alg, None).expect("cad");
        coz::czd_for_alg(&cad, &pc_sig, &key_a.alg).expect("czd")
    };

    let mut scope1 = client.begin_commit();
    scope1
        .verify_and_apply(&pc_pay_bytes, &pc_sig, pc_czd, None)
        .expect("principal/create should apply to a fresh multi-key genesis (client side)");

    let prv_a = Base64UrlUnpadded::decode_vec(key_a.prv.as_ref().expect("golden has prv"))
        .expect("golden prv base64");
    let pub_a = Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("golden pub base64");

    let commit1 = scope1
        .finalize_with_arrow(&key_a.alg, &prv_a, &pub_a, &tmb_a, now + 1, "cyphr.me")
        .expect("genesis commit should finalize (client side)");
    assert_eq!(commit1.len(), 2, "principal/create + commit/create");
    let cc1_blob = commit_tx_raw_blob(commit1, 0);

    assert!(
        client.pg().is_some(),
        "PG must be established after the genesis commit (client side)"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("db");
    let index_path = dir.path().join("index");
    let principal_id = "f40-durable-multi-key-genesis";

    let db = fjall::Database::builder(&db_path).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let indexer = FjallIndexer::open(&index_path).expect("open indexer");
    let engine = StorageEngine::with_storage_factory(blob_store, indexer, move |pid: &str| {
        cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), pid).map_err(|e| e.to_string())
    });

    engine
        .submit_commit(principal_id, Some(genesis.clone()), &[&pc_blob, &cc1_blob])
        .await
        .expect(
            "genesis commit should submit through the real durable StorageEngine write path",
        );

    let kc_pay = serde_json::json!({
        "alg": key_a.alg,
        "id": key_c.compute_tmb_b64().expect("bob tmb b64"),
        "now": now + 2,
        "tmb": a_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let (kc_pay_bytes, kc_sig) = sign_pay(key_a, kc_pay);
    let kc_blob = raw_blob(&kc_pay_bytes, &kc_sig, Some(pool_key_json(key_c)));
    let kc_czd = {
        let cad = coz::canonical_hash_for_alg(&kc_pay_bytes, &key_a.alg, None).expect("cad");
        coz::czd_for_alg(&cad, &kc_sig, &key_a.alg).expect("czd")
    };

    let mut scope2 = client.begin_commit();
    scope2
        .verify_and_apply(
            &kc_pay_bytes,
            &kc_sig,
            kc_czd,
            Some(pool_key_to_domain(key_c)),
        )
        .expect("key/create mutation should apply to the second commit (client side)");
    let commit2 = scope2
        .finalize_with_arrow(&key_a.alg, &prv_a, &pub_a, &tmb_a, now + 3, "cyphr.me")
        .expect("second commit should finalize (client side)");
    let cc2_blob = commit_tx_raw_blob(commit2, 0);

    engine
        .submit_commit(principal_id, Some(genesis), &[&kc_blob, &cc2_blob])
        .await
        .expect(
            "a second commit signed on top of a fresh multi-key established genesis must \
             submit without a state-root mismatch (F40), through a durable backend",
        );
}
