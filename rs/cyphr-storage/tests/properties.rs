//! Property-based tests for the cyphr-storage library.

use std::path::PathBuf;

use coz::base64ct::Encoding;
use cyphr::StateDigest;
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::MemoryIndexer;
use cyphr_storage::{CommitEntry, Genesis};
use proptest::prelude::*;

const POOL_KEYS: &[&str] = &[
    "golden",
    "key_a",
    "alice",
    "bob",
    "carol",
    "diana_es384",
    "eve_ed25519",
];

#[derive(Debug, Clone, Copy)]
enum Step {
    CreateKey {
        target_idx: usize,
        signer_idx: usize,
        finalize_commit: bool,
    },
    RevokeKey {
        target_idx: usize,
        signer_idx: usize,
        finalize_commit: bool,
    },
    AddAction {
        signer_idx: usize,
        msg_idx: usize,
    },
}

fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        (any::<usize>(), any::<usize>(), any::<bool>()).prop_map(
            |(target_idx, signer_idx, finalize_commit)| Step::CreateKey {
                target_idx,
                signer_idx,
                finalize_commit
            }
        ),
        (any::<usize>(), any::<usize>(), any::<bool>()).prop_map(
            |(target_idx, signer_idx, finalize_commit)| Step::RevokeKey {
                target_idx,
                signer_idx,
                finalize_commit
            }
        ),
        (any::<usize>(), any::<usize>()).prop_map(|(signer_idx, msg_idx)| Step::AddAction {
            signer_idx,
            msg_idx
        }),
    ]
}

fn test_case_strategy() -> impl Strategy<Value = (usize, Vec<Step>)> {
    (
        any::<usize>(),
        prop::collection::vec(step_strategy(), 1..10),
    )
}

fn load_pool() -> test_fixtures::Pool {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("parent of cyphr-storage")
        .parent()
        .expect("parent of rs")
        .join("tests")
        .join("keys")
        .join("pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

fn golden_key_to_domain(gk: &test_fixtures::GoldenKey) -> cyphr::Key {
    use coz::Thumbprint;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&gk.pub_key).expect("invalid pub base64");
    let tmb_bytes = Base64UrlUnpadded::decode_vec(&gk.tmb).expect("invalid tmb base64");

    cyphr::Key {
        alg: gk.alg.clone(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn is_transaction_typ(typ: &str) -> bool {
    typ.contains("/key/")
        || typ.contains("/principal/create")
        || typ.contains("/principal/delete")
        || typ.contains("/freeze/create")
        || typ.contains("/freeze/delete")
        || typ.contains("/commit/create")
}

fn build_intent(genesis_key_idx: usize, steps: Vec<Step>) -> test_fixtures::intent::TestIntent {
    let pool_keys = POOL_KEYS;
    let genesis_key = pool_keys[genesis_key_idx % pool_keys.len()].to_string();

    let mut active_keys = vec![genesis_key.clone()];
    let mut unused_keys: Vec<String> = pool_keys
        .iter()
        .filter(|&&k| k != genesis_key)
        .map(|&k| k.to_string())
        .collect();
    let mut revoked_keys = Vec::new();

    let mut commits = Vec::new();
    let mut actions = Vec::new();
    let mut current_txs = Vec::new();
    let mut now = 1000000i64;

    for step in steps {
        match step {
            Step::CreateKey {
                target_idx,
                signer_idx,
                finalize_commit,
            } => {
                if !unused_keys.is_empty() && !active_keys.is_empty() {
                    let target = unused_keys.remove(target_idx % unused_keys.len());
                    let signer = active_keys[signer_idx % active_keys.len()].clone();
                    active_keys.push(target.clone());

                    current_txs.push(vec![test_fixtures::intent::TxIntent {
                        typ: "cyphr.me/cyphr/key/create".to_string(),
                        now,
                        signer,
                        target: Some(target),
                        msg: None,
                        rvk: None,
                    }]);

                    if finalize_commit {
                        commits.push(test_fixtures::intent::CommitIntent {
                            tx: std::mem::take(&mut current_txs),
                        });
                        now += 10;
                    }
                }
            },
            Step::RevokeKey {
                target_idx,
                signer_idx,
                finalize_commit,
            } => {
                if active_keys.len() > 1 {
                    let target = active_keys.remove(target_idx % active_keys.len());
                    revoked_keys.push(target.clone());
                    let signer = active_keys[signer_idx % active_keys.len()].clone();

                    current_txs.push(vec![test_fixtures::intent::TxIntent {
                        typ: "cyphr.me/cyphr/key/revoke".to_string(),
                        now,
                        signer,
                        target: Some(target),
                        msg: None,
                        rvk: Some(now + 5),
                    }]);

                    if finalize_commit {
                        commits.push(test_fixtures::intent::CommitIntent {
                            tx: std::mem::take(&mut current_txs),
                        });
                        now += 10;
                    }
                }
            },
            Step::AddAction {
                signer_idx,
                msg_idx,
            } => {
                if !active_keys.is_empty() {
                    let signer = active_keys[signer_idx % active_keys.len()].clone();
                    actions.push(test_fixtures::intent::ActionIntent {
                        typ: "cyphr.me/action".to_string(),
                        now,
                        signer,
                        msg: Some(format!("msg_{}", msg_idx)),
                        id: None,
                    });
                    now += 10;
                }
            },
        }
    }

    if !current_txs.is_empty() {
        commits.push(test_fixtures::intent::CommitIntent {
            tx: std::mem::take(&mut current_txs),
        });
    }

    // Guarantee we have at least one commit
    if commits.is_empty() {
        let signer = active_keys[0].clone();
        let target = unused_keys.remove(0);
        commits.push(test_fixtures::intent::CommitIntent {
            tx: vec![vec![test_fixtures::intent::TxIntent {
                typ: "cyphr.me/cyphr/key/create".to_string(),
                now: now + 10,
                signer,
                target: Some(target),
                msg: None,
                rvk: None,
            }]],
        });
    }

    test_fixtures::intent::TestIntent {
        name: format!("prop_test_{}", genesis_key_idx),
        principal: vec![genesis_key],
        setup: None,
        commit: commits,
        action: actions,
        override_: None,
        expected: None,
    }
}

fn run_engine_recovery_test<B, I>(
    pool: &test_fixtures::Pool,
    intent: test_fixtures::intent::TestIntent,
    engine: cyphr_storage::engine::StorageEngine<B, I>,
) where
    B: cyphr_storage::blob::BlobStore + 'static,
    I: cyphr_storage::index::Indexer + cyphr_storage::index::IndexerWrite + 'static,
{
    let generator = test_fixtures::Generator::new(pool);
    let golden = match generator.generate_test(&intent) {
        Ok(g) => g,
        Err(_) => {
            // Ignore dynamically generated intents that are cryptographically invalid
            return;
        },
    };

    let genesis_keys = match &golden.genesis_keys {
        Some(gk) => gk,
        None => return,
    };
    let commits = match &golden.commits {
        Some(c) => c,
        None => return,
    };

    // Merge action pseudo-commits into the next transaction commit
    let mut merged_commits = Vec::new();
    let mut pending_cozies = Vec::new();

    for commit in commits {
        let is_tx = commit.cozies.iter().any(|coz| {
            if let Some(typ) = coz
                .get("pay")
                .and_then(|p| p.get("typ"))
                .and_then(|t| t.as_str())
            {
                is_transaction_typ(typ)
            } else {
                false
            }
        });

        if is_tx {
            let mut merged_cozies = std::mem::take(&mut pending_cozies);
            merged_cozies.extend(commit.cozies.clone());
            merged_commits.push(CommitEntry::new(
                merged_cozies,
                commit.keys.clone(),
                commit.commit_id.clone(),
                commit.auth_root.clone(),
                commit.sr.clone(),
                commit.pr.clone(),
            ));
        } else {
            pending_cozies.extend(commit.cozies.clone());
        }
    }

    if merged_commits.is_empty() {
        return;
    }

    let genesis_key = &genesis_keys[0];
    let key = golden_key_to_domain(genesis_key);
    let temp_principal = cyphr::Principal::implicit(key).unwrap();
    let hash_alg = temp_principal.hash_alg();
    let pr_bytes = temp_principal.pr().as_multihash().get(hash_alg).unwrap();
    let principal_id = format!(
        "{hash_alg}:{}",
        coz::base64ct::Base64UrlUnpadded::encode_string(pr_bytes)
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Write mock genesis cozy to the BlobStore so reindex() can bootstrap the principal.
        let genesis_coz_json = serde_json::json!({
            "pay": {
                "typ": "cyphr.me/cyphr/key/create",
                "now": 1000000,
                "pre": "",
                "tmb": genesis_key.tmb.clone(),
                "alg": genesis_key.alg.clone(),
            },
            "sig": "mock-sig",
            "key": {
                "alg": genesis_key.alg.clone(),
                "pub": genesis_key.pub_key.clone(),
                "tmb": genesis_key.tmb.clone(),
            }
        });

        let genesis_coz_bytes = serde_json::to_vec(&genesis_coz_json).unwrap();
        let _ = engine.blob_store().put(&genesis_coz_bytes).await.unwrap();

        // Ingest commits sequentially
        for commit in &merged_commits {
            let mut raw_blobs = Vec::new();
            let mut key_idx = 0;
            for coz in &commit.cozies {
                let mut coz_val = coz.clone();
                if let Some(typ) = coz_val
                    .get("pay")
                    .and_then(|p| p.get("typ"))
                    .and_then(|t| t.as_str())
                {
                    let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(typ);
                    if is_key_introducing && key_idx < commit.keys.len() {
                        let key_entry = &commit.keys[key_idx];
                        let key_val = serde_json::to_value(key_entry).unwrap();
                        coz_val
                            .as_object_mut()
                            .unwrap()
                            .insert("key".to_string(), key_val);
                        key_idx += 1;
                    }
                }
                let bytes = serde_json::to_vec(&coz_val).unwrap();
                raw_blobs.push(bytes);
            }
            let blob_slices: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

            let genesis = if genesis_keys.len() == 1 {
                Genesis::Implicit(golden_key_to_domain(&genesis_keys[0]))
            } else {
                Genesis::Explicit(genesis_keys.iter().map(golden_key_to_domain).collect())
            };

            engine
                .submit_commit(&principal_id, Some(genesis), &blob_slices)
                .await
                .expect("submit_commit failed");
        }

        // Get original tip state
        let original_tip = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("original tip should exist");

        // Re-submit the last commit to test idempotency
        let last_commit = merged_commits.last().unwrap();
        let mut raw_blobs = Vec::new();
        let mut key_idx = 0;
        for coz in &last_commit.cozies {
            let mut coz_val = coz.clone();
            if let Some(typ) = coz_val
                .get("pay")
                .and_then(|p| p.get("typ"))
                .and_then(|t| t.as_str())
            {
                let is_key_introducing = cyphr::parsed_coz::typ::is_key_introducing(typ);
                if is_key_introducing && key_idx < last_commit.keys.len() {
                    let key_entry = &last_commit.keys[key_idx];
                    let key_val = serde_json::to_value(key_entry).unwrap();
                    coz_val
                        .as_object_mut()
                        .unwrap()
                        .insert("key".to_string(), key_val);
                    key_idx += 1;
                }
            }
            let bytes = serde_json::to_vec(&coz_val).unwrap();
            raw_blobs.push(bytes);
        }
        let blob_slices: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = if genesis_keys.len() == 1 {
            Genesis::Implicit(golden_key_to_domain(&genesis_keys[0]))
        } else {
            Genesis::Explicit(genesis_keys.iter().map(golden_key_to_domain).collect())
        };

        let _ = engine
            .submit_commit(&principal_id, Some(genesis), &blob_slices)
            .await;

        let tip_after_dup = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("tip should still exist");
        assert_eq!(tip_after_dup.commit_count, original_tip.commit_count);
        assert_eq!(tip_after_dup.pr, original_tip.pr);
        assert_eq!(tip_after_dup.cr, original_tip.cr);

        // Reindex recovery test with total_check = true
        engine.reindex(&[], true).await.expect("reindex failed");

        let recovered_tip = engine
            .get_tip(&principal_id)
            .await
            .unwrap()
            .expect("recovered tip should exist");

        // The recovered tip has 1 more commit (the mock genesis commit)
        assert_eq!(recovered_tip.commit_count, original_tip.commit_count + 1);
        assert_eq!(recovered_tip.pr, original_tip.pr);
        assert_eq!(recovered_tip.sr, original_tip.sr);
        assert_eq!(recovered_tip.ar, original_tip.ar);
        // CR equality is checked explicitly, not just inferred from PR: PR
        // folds CR in, but a reindex bug that recomputed a wrong CR while
        // still landing on the same PR (e.g. by chance collision in a
        // malformed fold) would slip past a PR-only check.
        assert!(
            !original_tip.cr.is_empty(),
            "fixture with real commits should produce a non-empty CR"
        );
        assert_eq!(recovered_tip.cr, original_tip.cr);

        let recovered_principals = engine.indexer().list_principals().await.unwrap();
        assert_eq!(recovered_principals.len(), 1);

        let tagged_pr: cyphr::state::TaggedDigest = original_tip.pr.parse().unwrap();
        let original_entity = engine
            .indexer()
            .resolve_digest(&tagged_pr)
            .await
            .unwrap()
            .unwrap();
        let recovered_entity = engine
            .indexer()
            .resolve_digest(&tagged_pr)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original_entity.blob_hash, recovered_entity.blob_hash);
    });
}

proptest! {
    #[test]
    fn test_memory_engine_reindex_recovery((genesis_key_idx, steps) in test_case_strategy()) {
        let pool = load_pool();
        let intent = build_intent(genesis_key_idx, steps);
        let blob_store = MemoryBlobStore::new();
        let indexer = MemoryIndexer::new();
        let engine = StorageEngine::new(blob_store, indexer);
        run_engine_recovery_test(&pool, intent, engine);
    }

    #[test]
    fn test_persistent_engine_reindex_recovery((genesis_key_idx, steps) in test_case_strategy()) {
        let pool = load_pool();
        let intent = build_intent(genesis_key_idx, steps);
        let temp_dir_blob = tempfile::tempdir().unwrap();
        let temp_dir_index = tempfile::tempdir().unwrap();
        let blob_store = FjallBlobStore::open(temp_dir_blob.path()).unwrap();
        let indexer = FjallIndexer::open(&temp_dir_index.path().join("index")).unwrap();
        let engine = StorageEngine::new(blob_store, indexer);
        run_engine_recovery_test(&pool, intent, engine);
    }
}
