use super::*;
use crate::blob::MemoryBlobStore;
use crate::index::MemoryIndexer;

/// Build a test engine with memory backends.
fn test_engine() -> StorageEngine<MemoryBlobStore, MemoryIndexer> {
    StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
}

/// Build test metadata for a commit.
fn make_meta(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let dummy_hash = crate::blob::Blake3Hash::from_bytes([0; 32]);
    IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec![format!("SHA-256:commit-{principal_id}-{seq}")],
        sequence: seq,
        pre: if seq == 0 {
            None
        } else {
            Some(format!("SHA-256:pr-{principal_id}-{}", seq - 1))
        },
        prs: vec![format!("SHA-256:pr-{principal_id}-{seq}")],
        srs: vec![format!("SHA-256:sr-{principal_id}-{seq}")],
        ars: vec![format!("SHA-256:ar-{principal_id}-{seq}")],
        crs: vec![format!("SHA-256:cr-{principal_id}-{seq}")],
        blob_hashes: vec![dummy_hash],
        cozies: vec![IndexableCoz {
            blob_hash: dummy_hash,
            czd: format!("SHA-256:czd-{principal_id}-{seq}"),
            typ: "key/create".to_string(),
            tmb: "thumbprint".to_string(),
            alg: "ED25519".to_string(),
            now: timestamp,
            payload: None,
        }],
        timestamp,
        keys: Vec::new(),
    }
}

#[tokio::test]
async fn ingest_then_get_tip() {
    let engine = test_engine();
    let blobs: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":1000}}"];
    let meta = make_meta("alice", 0, 1000);

    engine
        .ingest_commit(&blobs, meta)
        .await
        .expect("ingest failed");

    let tip = engine
        .get_tip("alice")
        .await
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.principal_id, "alice");
    assert_eq!(tip.pr, "SHA-256:pr-alice-0");
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.last_updated, 1000);
}

#[tokio::test]
async fn get_tip_unknown_returns_none() {
    let engine = test_engine();
    let tip = engine.get_tip("nonexistent").await.expect("get_tip failed");
    assert!(tip.is_none());
}

#[tokio::test]
async fn ingest_two_then_get_patch_full() {
    let engine = test_engine();

    let blob_0 = b"{\"pay\":{\"now\":1000},\"typ\":\"cyphr/key/create\"}";
    let blob_1 = b"{\"pay\":{\"now\":2000},\"typ\":\"cyphr/key/create\"}";

    engine
        .ingest_commit(&[blob_0.as_slice()], make_meta("alice", 0, 1000))
        .await
        .expect("first ingest");
    engine
        .ingest_commit(&[blob_1.as_slice()], make_meta("alice", 1, 2000))
        .await
        .expect("second ingest");

    let patch = engine
        .get_patch("alice", None, None)
        .await
        .expect("get_patch failed");

    assert_eq!(patch.principal_id, "alice");
    assert_eq!(patch.entries.len(), 2);

    // Verify blob content is fetched correctly.
    assert_eq!(patch.entries[0].blobs.len(), 1);
    assert_eq!(patch.entries[0].blobs[0], blob_0.as_slice());
    assert_eq!(patch.entries[1].blobs[0], blob_1.as_slice());

    // Verify ordering.
    assert_eq!(patch.entries[0].commit.sequence, 0);
    assert_eq!(patch.entries[1].commit.sequence, 1);
}

#[tokio::test]
async fn get_patch_with_range() {
    let engine = test_engine();

    for seq in 0..5u64 {
        let blob = format!("{{\"pay\":{{\"now\":{}}}}}", 1000 + seq);
        engine
            .ingest_commit(
                &[blob.as_bytes()],
                make_meta("alice", seq, 1000 + seq as i64),
            )
            .await
            .expect("ingest");
    }

    let patch = engine
        .get_patch("alice", Some(1), Some(3))
        .await
        .expect("get_patch");
    assert_eq!(patch.entries.len(), 3);
    assert_eq!(patch.entries[0].commit.sequence, 1);
    assert_eq!(patch.entries[2].commit.sequence, 3);
}

#[tokio::test]
async fn get_patch_unknown_returns_empty() {
    let engine = test_engine();
    let patch = engine
        .get_patch("nonexistent", None, None)
        .await
        .expect("get_patch");
    assert!(patch.entries.is_empty());
}

#[tokio::test]
async fn get_entity_returns_none_for_unknown() {
    let engine = test_engine();

    let digest: cyphr::state::TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
        .parse()
        .expect("parse digest");

    let result = engine.get_entity(&digest).await.expect("get_entity failed");
    assert!(result.is_none());
}

#[tokio::test]
async fn ingest_returns_blob_hashes() {
    let engine = test_engine();
    let blob_a = b"transaction-a";
    let blob_b = b"transaction-b";

    let result = engine
        .ingest_commit(
            &[blob_a.as_slice(), blob_b.as_slice()],
            make_meta("alice", 0, 1000),
        )
        .await
        .expect("ingest");

    assert_eq!(result.blob_hashes.len(), 2);

    // Verify hashes are correct BLAKE3 digests.
    let expected_a = blake3::hash(blob_a);
    let expected_b = blake3::hash(blob_b);
    assert_eq!(result.blob_hashes[0].as_bytes(), expected_a.as_bytes());
    assert_eq!(result.blob_hashes[1].as_bytes(), expected_b.as_bytes());
}

#[tokio::test]
async fn ingest_idempotent() {
    let engine = test_engine();
    let blob = b"same-content";
    let meta = make_meta("alice", 0, 1000);

    engine
        .ingest_commit(&[blob.as_slice()], meta.clone())
        .await
        .expect("first");
    engine
        .ingest_commit(&[blob.as_slice()], meta)
        .await
        .expect("duplicate");

    let tip = engine
        .get_tip("alice")
        .await
        .expect("tip")
        .expect("should exist");
    assert_eq!(tip.commit_count, 1, "duplicate ingest should be idempotent");
}

#[tokio::test]
async fn multi_principal_isolation() {
    let engine = test_engine();

    engine
        .ingest_commit(&[b"alice-genesis"], make_meta("alice", 0, 1000))
        .await
        .expect("alice");
    engine
        .ingest_commit(&[b"bob-genesis"], make_meta("bob", 0, 2000))
        .await
        .expect("bob");

    let alice_tip = engine
        .get_tip("alice")
        .await
        .expect("tip")
        .expect("alice tip");
    let bob_tip = engine.get_tip("bob").await.expect("tip").expect("bob tip");

    assert_eq!(alice_tip.pr, "SHA-256:pr-alice-0");
    assert_eq!(bob_tip.pr, "SHA-256:pr-bob-0");

    // Alice's patch should not contain Bob's data.
    let alice_patch = engine.get_patch("alice", None, None).await.expect("patch");
    assert_eq!(alice_patch.entries.len(), 1);
    assert_eq!(alice_patch.entries[0].blobs[0], b"alice-genesis");
}

// ========================================================================
// Principal lifecycle tests
// ========================================================================

/// Load a golden fixture from the shared test vectors.
fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

/// Convert a golden fixture's genesis key JSON to a cyphr::Key.
fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    use coz::Thumbprint;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();

    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();

    cyphr::Key {
        alg: alg.to_string(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Build genesis from a golden fixture's genesis_keys array.
fn make_genesis(genesis_keys: &[serde_json::Value]) -> crate::Genesis {
    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    if keys.len() == 1 {
        crate::Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        crate::Genesis::Explicit(keys)
    }
}

/// Ingest a golden fixture's commits into the engine.
///
/// Each coz in the fixture becomes a separate blob. Key material from the
/// commit-level `keys[]` array is embedded into the corresponding coz blob's
/// `"key"` field, mirroring the wire format a server would receive.
async fn ingest_fixture(
    engine: &StorageEngine<MemoryBlobStore, MemoryIndexer>,
    principal_id: &str,
    commits: &[serde_json::Value],
) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    for (seq, commit) in commits.iter().enumerate() {
        let cozies_json = commit["txs"].as_array().expect("txs array");
        let keys_json = commit["keys"].as_array();
        let mut key_idx = 0;

        let mut blobs: Vec<Vec<u8>> = Vec::new();
        let mut cozies = Vec::new();
        let mut extracted_keys = Vec::new();

        for coz_value in cozies_json {
            let mut coz = coz_value.clone();

            // If this is a key-introducing transaction, embed the key
            // material from the commit-level keys[] into the blob.
            let typ = coz["pay"]["typ"].as_str().unwrap_or("").to_string();
            let is_key_introducing = typ.contains("/key/create")
                || typ.contains("/key/replace")
                || typ.contains("/key/add");

            if is_key_introducing {
                if let Some(ks) = keys_json {
                    if key_idx < ks.len() {
                        coz.as_object_mut()
                            .unwrap()
                            .insert("key".to_string(), ks[key_idx].clone());
                        key_idx += 1;
                    }
                }
            }

            let blob_bytes = serde_json::to_vec(&coz).unwrap();
            blobs.push(blob_bytes.clone());

            // Parse for IndexableCoz and PublicKeyInfo
            let pay = coz.get("pay").unwrap();
            let sig_b64 = coz.get("sig").unwrap().as_str().unwrap();
            let sig = Base64UrlUnpadded::decode_vec(sig_b64).unwrap();

            let mut pay_val = pay.clone();
            crate::import::canonicalize_value(&mut pay_val);
            let pay_json = serde_json::to_vec(&pay_val).unwrap();
            let alg = pay.get("alg").unwrap().as_str().unwrap().to_string();

            let cad = coz::canonical_hash_for_alg(&pay_json, &alg, None).unwrap();
            let czd_bytes = coz::czd_for_alg(&cad, &sig, &alg).unwrap();

            let source_alg =
                cyphr::state::hash_alg_from_str(&alg).unwrap_or(cyphr::state::HashAlg::Sha256);
            let tagged = cyphr::state::TaggedCzd::new(&czd_bytes, source_alg);
            let converted = tagged.convert_to(source_alg);
            let czd = format!(
                "{source_alg}:{}",
                Base64UrlUnpadded::encode_string(&converted)
            );

            let tmb = pay
                .get("tmb")
                .unwrap_or(&serde_json::Value::Null)
                .as_str()
                .unwrap_or("")
                .to_string();
            let now = pay.get("now").unwrap().as_i64().unwrap();
            let payload = Some(serde_json::to_string(&pay_val).unwrap());

            cozies.push(IndexableCoz {
                blob_hash: crate::blob::Blake3Hash::from_bytes([0; 32]),
                czd,
                typ: typ.clone(),
                tmb,
                alg,
                now,
                payload,
            });

            if is_key_introducing {
                if let Some(k) = coz.get("key") {
                    extracted_keys.push(crate::index::PublicKeyInfo {
                        thumbprint: k.get("tmb").unwrap().as_str().unwrap().to_string(),
                        algorithm: k.get("alg").unwrap().as_str().unwrap().to_string(),
                        public_key: k.get("pub").unwrap().as_str().unwrap().to_string(),
                    });
                }
            }
        }

        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();

        let pre = if seq == 0 {
            None
        } else {
            Some(commits[seq - 1]["pr"].as_str().unwrap_or("").to_string())
        };

        let meta = IndexableCommit {
            principal_id: principal_id.to_string(),
            commit_ids: vec![
                commit["commit_id"]
                    .as_str()
                    .unwrap_or(&format!("commit-{seq}"))
                    .to_string(),
            ],
            sequence: seq as u64,
            pre,
            prs: vec![commit["pr"].as_str().unwrap_or("").to_string()],
            srs: vec![commit["sr"].as_str().unwrap_or("").to_string()],
            ars: vec![commit["ar"].as_str().unwrap_or("").to_string()],
            // Golden fixtures predate CR tracking; ingest_fixture is a raw
            // index-population helper, not a source of truth for CR.
            crs: Vec::new(),
            blob_hashes: Vec::new(),
            cozies,
            timestamp: cozies_json
                .last()
                .and_then(|c| c["pay"]["now"].as_i64())
                .unwrap_or(0),
            keys: extracted_keys,
        };

        engine
            .ingest_commit(&blob_slices, meta)
            .await
            .unwrap_or_else(|e| panic!("ingest commit {seq} failed: {e}"));
    }
}

#[tokio::test]
async fn load_principal_genesis_only() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let engine = test_engine();

    // No commits ingested — load should return genesis-only principal.
    let principal = engine
        .load_principal("test-principal", genesis)
        .await
        .expect("load_principal failed");

    assert_eq!(principal.active_key_count(), 1);
}

#[tokio::test]
async fn load_principal_after_ingest() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "test-principal";

    // Ingest the fixture's commits.
    ingest_fixture(&engine, principal_id, commits).await;

    // Load the principal back from storage.
    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    // Verify against fixture expectations.
    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch"
        );
    }
    if let Some(level) = expected["level"].as_u64() {
        assert_eq!(principal.level() as u64, level, "level mismatch");
    }
}

#[tokio::test]
async fn load_principal_multi_commit_replay() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "seq-principal";

    ingest_fixture(&engine, principal_id, commits).await;

    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch after multi-commit replay"
        );
    }
}

#[tokio::test]
async fn load_principal_unknown_returns_genesis() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let engine = test_engine();

    // Load from a principal_id with no indexed commits.
    let principal = engine
        .load_principal("nonexistent", genesis)
        .await
        .expect("load should succeed with no commits");

    assert_eq!(principal.active_key_count(), 1, "should be genesis-only");
}

// ========================================================================
// submit_commit tests (validated write path)
// ========================================================================

/// Build raw coz blobs from a golden fixture's commit, ready for submit_commit.
///
/// Embeds key material from commit-level `keys[]` into each key-introducing
/// coz blob, matching the wire format a client would send.
fn build_raw_blobs(commit: &serde_json::Value) -> Vec<Vec<u8>> {
    let cozies = commit["txs"].as_array().expect("txs array");
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    let mut blobs = Vec::new();

    for coz_value in cozies {
        let mut coz = coz_value.clone();

        let typ = coz["pay"]["typ"].as_str().unwrap_or("");
        let is_key_introducing = typ.contains("/key/create") || typ.contains("/key/replace");

        if is_key_introducing {
            if let Some(ks) = keys {
                if key_idx < ks.len() {
                    coz.as_object_mut()
                        .unwrap()
                        .insert("key".to_string(), ks[key_idx].clone());
                    key_idx += 1;
                }
            }
        }

        blobs.push(serde_json::to_vec(&coz).unwrap());
    }

    blobs
}

#[tokio::test]
async fn submit_commit_valid_fixture() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "submit-test";

    // Submit each commit in the fixture through the validated write path.
    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    // Verify stored state via tip.
    let tip = engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist after submit");

    assert_eq!(tip.commit_count, commits.len() as u64);

    // Verify loadable principal matches expected state.
    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load after submit failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch"
        );
    }
    if let Some(level) = expected["level"].as_u64() {
        assert_eq!(principal.level() as u64, level, "level mismatch");
    }
}

#[tokio::test]
async fn submit_commit_bad_signature_rejected() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let engine = test_engine();
    let principal_id = "submit-bad-sig";

    // Build blobs from the first commit but tamper with the signature.
    let first_commit = &commits[0];
    let mut blobs = build_raw_blobs(first_commit);

    // Tamper: flip a byte in the first blob's sig field.
    let mut tampered: serde_json::Value = serde_json::from_slice(&blobs[0]).unwrap();
    if let Some(sig) = tampered.get("sig").and_then(|s| s.as_str()) {
        let mut sig_chars: Vec<char> = sig.chars().collect();
        if !sig_chars.is_empty() {
            // Flip the first character.
            sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        }
        let tampered_sig: String = sig_chars.into_iter().collect();
        tampered["sig"] = serde_json::Value::String(tampered_sig);
    }
    blobs[0] = serde_json::to_vec(&tampered).unwrap();

    let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let genesis = make_genesis(genesis_keys);

    // Submission should fail — protocol error, not stored.
    let result = engine
        .submit_commit(principal_id, Some(genesis), &blob_slices)
        .await;
    assert!(result.is_err(), "tampered commit should be rejected");

    // Verify nothing was stored.
    let tip = engine.get_tip(principal_id).await.expect("get_tip failed");
    assert!(tip.is_none(), "no tip should exist after rejected submit");
}

#[tokio::test]
async fn submit_commit_empty_rejected() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();

    let engine = test_engine();
    let genesis = make_genesis(genesis_keys);

    let result = engine.submit_commit("empty-test", Some(genesis), &[]).await;
    assert!(result.is_err(), "empty blob list should be rejected");
}

#[tokio::test]
async fn submit_then_load_round_trip() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "round-trip-submit";

    // Submit all commits.
    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    // Load and verify.
    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch in round-trip"
        );
    }

    // Verify sequence count.
    let tip = engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(tip.commit_count, commits.len() as u64);
}

#[tokio::test]
async fn test_reindex_recovery() {
    use coz::base64ct::Encoding;

    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let blob_store = MemoryBlobStore::new();
    let indexer = MemoryIndexer::new();
    let engine = StorageEngine::new(blob_store.clone(), indexer);

    // Compute the actual principal_id from the genesis key
    let key = golden_key_to_domain(&genesis_keys[0]);
    let temp_principal = cyphr::Principal::implicit(key).unwrap();
    let pr_bytes = temp_principal
        .pr()
        .as_multihash()
        .get(cyphr::state::HashAlg::Sha256)
        .unwrap();
    let principal_id = format!(
        "SHA-256:{}",
        coz::base64ct::Base64UrlUnpadded::encode_string(pr_bytes)
    );

    // Submit all commits.
    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        engine
            .submit_commit(&principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    // Create and write a mock genesis cozy to the BlobStore so reindex() can bootstrap the
    // principal.
    let genesis_key = &genesis_keys[0];
    let genesis_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/key/create",
            "now": 1000000,
            "pre": "",
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig",
        "key": genesis_key
    });

    let genesis_coz_bytes = serde_json::to_vec(&genesis_coz_json).unwrap();
    let _genesis_blob_hash = blob_store.put(&genesis_coz_bytes).await.unwrap();

    // Get original tip state.
    let original_tip = engine
        .get_tip(&principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist");

    // Get a digest to resolve later as a sanity check.
    let tagged_digest: TaggedDigest = original_tip.pr.parse().unwrap();
    let original_entity = engine
        .indexer
        .resolve_digest(&tagged_digest)
        .await
        .unwrap()
        .unwrap();

    // Create a new engine sharing the same blob store but with a completely empty indexer.
    let new_indexer = MemoryIndexer::new();
    let recovery_engine = StorageEngine::new(blob_store, new_indexer);

    // Reindex from the blobs.
    recovery_engine
        .reindex(&[], false)
        .await
        .expect("reindex failed");

    // Verify recovery.
    let recovered_tip = recovery_engine
        .get_tip(&principal_id)
        .await
        .expect("get_tip failed")
        .expect("recovered tip should exist");

    // Recovered tip should have 1 more commit (the mock genesis commit).
    assert_eq!(recovered_tip.commit_count, original_tip.commit_count + 1);
    assert_eq!(recovered_tip.pr, original_tip.pr);
    assert_eq!(recovered_tip.sr, original_tip.sr);
    assert_eq!(recovered_tip.ar, original_tip.ar);

    // Verify digest resolution.
    let recovered_entity = recovery_engine
        .indexer
        .resolve_digest(&tagged_digest)
        .await
        .unwrap()
        .expect("digest should resolve in recovered indexer");

    assert_eq!(recovered_entity.blob_hash, original_entity.blob_hash);
}

#[tokio::test]
async fn test_reindex_recovery_with_crashed_commit() {
    use coz::base64ct::Encoding;

    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let blob_store = MemoryBlobStore::new();
    let indexer = MemoryIndexer::new();
    let engine = StorageEngine::new(blob_store.clone(), indexer);

    // Compute the actual principal_id from the genesis key
    let key = golden_key_to_domain(&genesis_keys[0]);
    let temp_principal = cyphr::Principal::implicit(key).unwrap();
    let pr_bytes = temp_principal
        .pr()
        .as_multihash()
        .get(cyphr::state::HashAlg::Sha256)
        .unwrap();
    let principal_id = format!(
        "SHA-256:{}",
        coz::base64ct::Base64UrlUnpadded::encode_string(pr_bytes)
    );

    // Submit all commits.
    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);

        engine
            .submit_commit(&principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    // Write a mock genesis cozy to the BlobStore
    let genesis_key = &genesis_keys[0];
    let genesis_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/key/create",
            "now": 1000000,
            "pre": "",
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig",
        "key": genesis_key
    });

    let genesis_coz_bytes = serde_json::to_vec(&genesis_coz_json).unwrap();
    let _ = blob_store.put(&genesis_coz_bytes).await.unwrap();

    // Now write a random transaction cozy simulating a crashed commit write (missing finalizer
    // cozy)
    let crashed_coz_json = serde_json::json!({
        "pay": {
            "typ": "cyphr.me/cyphr/key/add",
            "now": 1800000000,
            "pre": "some-pre-hash",
            "tmb": genesis_key["tmb"].as_str().unwrap(),
            "alg": genesis_key["alg"].as_str().unwrap(),
        },
        "sig": "mock-sig-crashed",
        "key": genesis_key
    });
    let crashed_coz_bytes = serde_json::to_vec(&crashed_coz_json).unwrap();
    let _ = blob_store.put(&crashed_coz_bytes).await.unwrap();

    // Create a new engine sharing the same blob store but with a completely empty indexer.
    let new_indexer = MemoryIndexer::new();
    let recovery_engine = StorageEngine::new(blob_store, new_indexer);

    // Reindex from the blobs. This must succeed, skipping the crashed/unfinalized cozy.
    recovery_engine
        .reindex(&[], false)
        .await
        .expect("reindex recovery with crashed commit failed");

    // Verify recovery.
    let recovered_tip = recovery_engine
        .get_tip(&principal_id)
        .await
        .expect("get_tip failed")
        .expect("recovered tip should exist");

    // Tip commit count should match original_tip + 1 (for genesis_coz), completely ignoring the
    // crashed cozy.
    let original_tip = engine.get_tip(&principal_id).await.unwrap().unwrap();
    assert_eq!(recovered_tip.commit_count, original_tip.commit_count + 1);
}

/// A principal's CR must survive a checkpoint save/restore cycle
/// byte-identically once the caller threads real `CommitTrees` through.
#[tokio::test]
async fn checkpoint_round_trip_preserves_cr() {
    use crate::import::{Checkpoint, load_from_checkpoint};

    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let engine = test_engine();
    let principal_id = "checkpoint-cr-test";

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);
        engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load after submit failed");

    let original_cr = principal.cr().cloned();
    assert!(
        original_cr.is_some(),
        "fixture with real commits should produce a CR"
    );

    let trees = principal.commit_trees().clone();
    let keys: Vec<cyphr::Key> = principal.active_keys().cloned().collect();

    let checkpoint = Checkpoint {
        auth_root: principal.auth_root().clone(),
        keys,
        attestor: None,
        cr: original_cr.clone(),
    };

    let restored = load_from_checkpoint(principal.pg().cloned(), checkpoint, Some(trees), &[])
        .expect("load_from_checkpoint failed");

    assert_eq!(
        restored.cr().cloned(),
        original_cr,
        "checkpoint round-trip must preserve CR byte-identically"
    );
}

/// `load_from_checkpoint` without trees must keep today's backward-
/// compatible behavior: no CR, empty commit_trees.
#[tokio::test]
async fn checkpoint_without_trees_still_has_no_cr() {
    use crate::import::{Checkpoint, load_from_checkpoint};

    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let engine = test_engine();
    let principal_id = "checkpoint-no-trees-test";

    for commit in commits {
        let blobs = build_raw_blobs(commit);
        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let genesis = make_genesis(genesis_keys);
        engine
            .submit_commit(principal_id, Some(genesis), &blob_slices)
            .await
            .expect("submit_commit failed");
    }

    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load after submit failed");

    let keys: Vec<cyphr::Key> = principal.active_keys().cloned().collect();
    let checkpoint = Checkpoint {
        auth_root: principal.auth_root().clone(),
        keys,
        attestor: None,
        cr: None,
    };

    let restored = load_from_checkpoint(principal.pg().cloned(), checkpoint, None, &[])
        .expect("load_from_checkpoint failed");

    assert!(
        restored.cr().is_none(),
        "load_from_checkpoint without trees must have no CR"
    );
    assert!(
        restored.commit_trees().is_empty(),
        "load_from_checkpoint without trees must have empty commit_trees"
    );
}
