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
