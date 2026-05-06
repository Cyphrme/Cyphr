use super::*;

/// Build a test commit for indexing.
fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let blob_data = format!("{principal_id}-commit-{seq}");
    let blob_hash =
        crate::blob::Blake3Hash::from_bytes(*blake3::hash(blob_data.as_bytes()).as_bytes());

    IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_id: format!("SHA-256:commit-{principal_id}-{seq}"),
        sequence: seq,
        pr: format!("SHA-256:pr-{principal_id}-{seq}"),
        sr: format!("SHA-256:sr-{principal_id}-{seq}"),
        ar: format!("SHA-256:ar-{principal_id}-{seq}"),
        blob_hashes: vec![blob_hash],
        transaction_types: vec!["key/create".to_string()],
        timestamp,
    }
}

#[test]
fn index_commit_and_get_tip() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer.index_commit(&commit).expect("index_commit failed");

    let tip = indexer
        .get_tip("alice")
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.principal_id, "alice");
    assert_eq!(tip.pr, "SHA-256:pr-alice-0");
    assert_eq!(tip.sr, "SHA-256:sr-alice-0");
    assert_eq!(tip.ar, "SHA-256:ar-alice-0");
    assert_eq!(tip.commit_id, "SHA-256:commit-alice-0");
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.last_updated, 1000);
}

#[test]
fn get_tip_unknown_returns_none() {
    let indexer = MemoryIndexer::new();
    let tip = indexer.get_tip("nonexistent").expect("get_tip failed");
    assert!(tip.is_none(), "unknown principal should return None");
}

#[test]
fn tip_updates_on_subsequent_commits() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .expect("first commit");
    indexer
        .index_commit(&make_commit("alice", 1, 2000))
        .expect("second commit");

    let tip = indexer
        .get_tip("alice")
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.commit_count, 2);
    assert_eq!(tip.pr, "SHA-256:pr-alice-1");
    assert_eq!(tip.last_updated, 2000);
}

#[test]
fn index_commit_idempotent() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer.index_commit(&commit).expect("first index");
    indexer.index_commit(&commit).expect("duplicate index");

    let tip = indexer
        .get_tip("alice")
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(tip.commit_count, 1, "duplicate should not increase count");
}

#[test]
fn get_commit_chain_full() {
    let indexer = MemoryIndexer::new();

    for seq in 0..5 {
        indexer
            .index_commit(&make_commit("alice", seq, 1000 + seq as i64))
            .expect("index failed");
    }

    let chain = indexer
        .get_commit_chain("alice", None, None)
        .expect("chain failed");
    assert_eq!(chain.len(), 5);
    for (i, c) in chain.iter().enumerate() {
        assert_eq!(c.sequence, i as u64);
    }
}

#[test]
fn get_commit_chain_range() {
    let indexer = MemoryIndexer::new();

    for seq in 0..5 {
        indexer
            .index_commit(&make_commit("alice", seq, 1000 + seq as i64))
            .expect("index failed");
    }

    let chain = indexer
        .get_commit_chain("alice", Some(1), Some(3))
        .expect("chain failed");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].sequence, 1);
    assert_eq!(chain[2].sequence, 3);
}

#[test]
fn get_commit_chain_unknown_returns_empty() {
    let indexer = MemoryIndexer::new();
    let chain = indexer
        .get_commit_chain("nonexistent", None, None)
        .expect("chain failed");
    assert!(chain.is_empty());
}

#[test]
fn resolve_digest_returns_none_for_unknown() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer.index_commit(&commit).expect("index failed");

    // The memory indexer uses blob hash hex as synthetic digest keys.
    // A real TaggedDigest (base64url-encoded, algorithm-prefixed) will
    // not match hex keys, validating the lookup path returns None
    // for unindexed digests.
    let real_digest: cyphr::state::TaggedDigest =
        "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
            .parse()
            .expect("parse tagged digest");

    let result = indexer
        .resolve_digest(&real_digest)
        .expect("resolve failed");
    assert!(
        result.is_none(),
        "unindexed tagged digest should return None",
    );
}

#[test]
fn indexed_blobs_tracked_in_commit_chain() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);
    let blob_hash = commit.blob_hashes[0];

    indexer.index_commit(&commit).expect("index failed");

    // Verify blobs are tracked via commit chain (public API).
    let chain = indexer
        .get_commit_chain("alice", None, None)
        .expect("chain failed");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].blob_hashes.len(), 1);
    assert_eq!(chain[0].blob_hashes[0], blob_hash);
}

#[test]
fn list_principals_returns_all() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .expect("alice");
    indexer
        .index_commit(&make_commit("bob", 0, 2000))
        .expect("bob");

    let principals = indexer.list_principals().expect("list failed");
    assert_eq!(principals.len(), 2);

    let ids: Vec<&str> = principals.iter().map(|p| p.principal_id.as_str()).collect();
    assert!(ids.contains(&"alice"));
    assert!(ids.contains(&"bob"));
}

#[test]
fn principal_summary_tracks_creation_time() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .expect("genesis");
    indexer
        .index_commit(&make_commit("alice", 1, 5000))
        .expect("second");

    let principals = indexer.list_principals().expect("list");
    let alice = principals
        .iter()
        .find(|p| p.principal_id == "alice")
        .expect("alice");
    assert_eq!(alice.created, 1000, "created should be genesis timestamp");
    assert_eq!(alice.last_updated, 5000, "last_updated should be latest");
}
