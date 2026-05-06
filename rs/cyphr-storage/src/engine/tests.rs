use super::*;
use crate::blob::MemoryBlobStore;
use crate::index::MemoryIndexer;

/// Build a test engine with memory backends.
fn test_engine() -> StorageEngine<MemoryBlobStore, MemoryIndexer> {
    StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
}

/// Build test metadata for a commit.
fn make_meta(principal_id: &str, seq: u64, timestamp: i64) -> IngestMeta {
    IngestMeta {
        principal_id: principal_id.to_string(),
        commit_id: format!("SHA-256:commit-{principal_id}-{seq}"),
        sequence: seq,
        pr: format!("SHA-256:pr-{principal_id}-{seq}"),
        sr: format!("SHA-256:sr-{principal_id}-{seq}"),
        ar: format!("SHA-256:ar-{principal_id}-{seq}"),
        transaction_types: vec!["key/create".to_string()],
        timestamp,
    }
}

#[test]
fn ingest_then_get_tip() {
    let engine = test_engine();
    let blobs: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":1000}}"];
    let meta = make_meta("alice", 0, 1000);

    engine.ingest_commit(&blobs, meta).expect("ingest failed");

    let tip = engine
        .get_tip("alice")
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.principal_id, "alice");
    assert_eq!(tip.pr, "SHA-256:pr-alice-0");
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.last_updated, 1000);
}

#[test]
fn get_tip_unknown_returns_none() {
    let engine = test_engine();
    let tip = engine.get_tip("nonexistent").expect("get_tip failed");
    assert!(tip.is_none());
}

#[test]
fn ingest_two_then_get_patch_full() {
    let engine = test_engine();

    let blob_0 = b"{\"pay\":{\"now\":1000},\"typ\":\"cyphr/key/create\"}";
    let blob_1 = b"{\"pay\":{\"now\":2000},\"typ\":\"cyphr/key/create\"}";

    engine
        .ingest_commit(&[blob_0.as_slice()], make_meta("alice", 0, 1000))
        .expect("first ingest");
    engine
        .ingest_commit(&[blob_1.as_slice()], make_meta("alice", 1, 2000))
        .expect("second ingest");

    let patch = engine
        .get_patch("alice", None, None)
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

#[test]
fn get_patch_with_range() {
    let engine = test_engine();

    for seq in 0..5u64 {
        let blob = format!("{{\"pay\":{{\"now\":{}}}}}", 1000 + seq);
        engine
            .ingest_commit(
                &[blob.as_bytes()],
                make_meta("alice", seq, 1000 + seq as i64),
            )
            .expect("ingest");
    }

    let patch = engine
        .get_patch("alice", Some(1), Some(3))
        .expect("get_patch");
    assert_eq!(patch.entries.len(), 3);
    assert_eq!(patch.entries[0].commit.sequence, 1);
    assert_eq!(patch.entries[2].commit.sequence, 3);
}

#[test]
fn get_patch_unknown_returns_empty() {
    let engine = test_engine();
    let patch = engine
        .get_patch("nonexistent", None, None)
        .expect("get_patch");
    assert!(patch.entries.is_empty());
}

#[test]
fn get_entity_returns_none_for_unknown() {
    let engine = test_engine();

    let digest: cyphr::state::TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
        .parse()
        .expect("parse digest");

    let result = engine.get_entity(&digest).expect("get_entity failed");
    assert!(result.is_none());
}

#[test]
fn ingest_returns_blob_hashes() {
    let engine = test_engine();
    let blob_a = b"transaction-a";
    let blob_b = b"transaction-b";

    let result = engine
        .ingest_commit(
            &[blob_a.as_slice(), blob_b.as_slice()],
            make_meta("alice", 0, 1000),
        )
        .expect("ingest");

    assert_eq!(result.blob_hashes.len(), 2);

    // Verify hashes are correct BLAKE3 digests.
    let expected_a = blake3::hash(blob_a);
    let expected_b = blake3::hash(blob_b);
    assert_eq!(result.blob_hashes[0].as_bytes(), expected_a.as_bytes());
    assert_eq!(result.blob_hashes[1].as_bytes(), expected_b.as_bytes());
}

#[test]
fn ingest_idempotent() {
    let engine = test_engine();
    let blob = b"same-content";
    let meta = make_meta("alice", 0, 1000);

    engine
        .ingest_commit(&[blob.as_slice()], meta.clone())
        .expect("first");
    engine
        .ingest_commit(&[blob.as_slice()], meta)
        .expect("duplicate");

    let tip = engine.get_tip("alice").expect("tip").expect("should exist");
    assert_eq!(tip.commit_count, 1, "duplicate ingest should be idempotent");
}

#[test]
fn multi_principal_isolation() {
    let engine = test_engine();

    engine
        .ingest_commit(&[b"alice-genesis"], make_meta("alice", 0, 1000))
        .expect("alice");
    engine
        .ingest_commit(&[b"bob-genesis"], make_meta("bob", 0, 2000))
        .expect("bob");

    let alice_tip = engine.get_tip("alice").expect("tip").expect("alice tip");
    let bob_tip = engine.get_tip("bob").expect("tip").expect("bob tip");

    assert_eq!(alice_tip.pr, "SHA-256:pr-alice-0");
    assert_eq!(bob_tip.pr, "SHA-256:pr-bob-0");

    // Alice's patch should not contain Bob's data.
    let alice_patch = engine.get_patch("alice", None, None).expect("patch");
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
fn ingest_fixture(
    engine: &StorageEngine<MemoryBlobStore, MemoryIndexer>,
    principal_id: &str,
    commits: &[serde_json::Value],
) {
    for (seq, commit) in commits.iter().enumerate() {
        let cozies = commit["txs"].as_array().expect("txs array");
        let keys = commit["keys"].as_array();
        let mut key_idx = 0;

        let mut blobs: Vec<Vec<u8>> = Vec::new();

        for coz_value in cozies {
            let mut coz = coz_value.clone();

            // If this is a key-introducing transaction, embed the key
            // material from the commit-level keys[] into the blob.
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

        let blob_slices: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();

        let meta = IngestMeta {
            principal_id: principal_id.to_string(),
            commit_id: commit["commit_id"]
                .as_str()
                .unwrap_or(&format!("commit-{seq}"))
                .to_string(),
            sequence: seq as u64,
            pr: commit["pr"].as_str().unwrap_or("").to_string(),
            sr: commit["sr"].as_str().unwrap_or("").to_string(),
            ar: commit["ar"].as_str().unwrap_or("").to_string(),
            transaction_types: cozies
                .iter()
                .filter_map(|c| c["pay"]["typ"].as_str().map(String::from))
                .collect(),
            timestamp: cozies
                .last()
                .and_then(|c| c["pay"]["now"].as_i64())
                .unwrap_or(0),
        };

        engine
            .ingest_commit(&blob_slices, meta)
            .unwrap_or_else(|e| panic!("ingest commit {seq} failed: {e}"));
    }
}

#[test]
fn load_principal_genesis_only() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let engine = test_engine();

    // No commits ingested — load should return genesis-only principal.
    let principal = engine
        .load_principal("test-principal", genesis)
        .expect("load_principal failed");

    assert_eq!(principal.active_key_count(), 1);
}

#[test]
fn load_principal_after_ingest() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "test-principal";

    // Ingest the fixture's commits.
    ingest_fixture(&engine, principal_id, commits);

    // Load the principal back from storage.
    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
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

#[test]
fn load_principal_multi_commit_replay() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "seq-principal";

    ingest_fixture(&engine, principal_id, commits);

    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .expect("load_principal failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch after multi-commit replay"
        );
    }
}

#[test]
fn load_principal_unknown_returns_genesis() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let engine = test_engine();

    // Load from a principal_id with no indexed commits.
    let principal = engine
        .load_principal("nonexistent", genesis)
        .expect("load should succeed with no commits");

    assert_eq!(principal.active_key_count(), 1, "should be genesis-only");
}
