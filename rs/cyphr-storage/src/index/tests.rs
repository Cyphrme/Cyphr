use super::*;

/// Build a test commit for indexing.
fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let blob_data = format!("{principal_id}-commit-{seq}");
    let blob_hash =
        crate::blob::Blake3Hash::from_bytes(*blake3::hash(blob_data.as_bytes()).as_bytes());

    IndexableCommit {
        principal_id: principal_id.to_string(),
        commit_ids: vec![format!("SHA-256:commit-{principal_id}-{seq}")],
        sequence: seq,
        pre: None,
        prs: vec![format!("SHA-256:pr-{principal_id}-{seq}")],
        srs: vec![format!("SHA-256:sr-{principal_id}-{seq}")],
        ars: vec![format!("SHA-256:ar-{principal_id}-{seq}")],
        blob_hashes: vec![blob_hash],
        cozies: vec![IndexableCoz {
            blob_hash,
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
async fn index_commit_and_get_tip() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer
        .index_commit(&commit)
        .await
        .expect("index_commit failed");

    let tip = indexer
        .get_tip("alice")
        .await
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

#[tokio::test]
async fn get_tip_unknown_returns_none() {
    let indexer = MemoryIndexer::new();
    let tip = indexer
        .get_tip("nonexistent")
        .await
        .expect("get_tip failed");
    assert!(tip.is_none(), "unknown principal should return None");
}

#[tokio::test]
async fn tip_updates_on_subsequent_commits() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .await
        .expect("first commit");
    indexer
        .index_commit(&make_commit("alice", 1, 2000))
        .await
        .expect("second commit");

    let tip = indexer
        .get_tip("alice")
        .await
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.commit_count, 2);
    assert_eq!(tip.pr, "SHA-256:pr-alice-1");
    assert_eq!(tip.last_updated, 2000);
}

#[tokio::test]
async fn index_commit_idempotent() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer.index_commit(&commit).await.expect("first index");
    indexer
        .index_commit(&commit)
        .await
        .expect("duplicate index");

    let tip = indexer
        .get_tip("alice")
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(tip.commit_count, 1, "duplicate should not increase count");
}

#[tokio::test]
async fn get_commit_chain_full() {
    let indexer = MemoryIndexer::new();

    for seq in 0..5 {
        indexer
            .index_commit(&make_commit("alice", seq, 1000 + seq as i64))
            .await
            .expect("index failed");
    }

    let chain = indexer
        .get_commit_chain("alice", None, None)
        .await
        .expect("chain failed");
    assert_eq!(chain.len(), 5);
    for (i, c) in chain.iter().enumerate() {
        assert_eq!(c.sequence, i as u64);
    }
}

#[tokio::test]
async fn get_commit_chain_range() {
    let indexer = MemoryIndexer::new();

    for seq in 0..5 {
        indexer
            .index_commit(&make_commit("alice", seq, 1000 + seq as i64))
            .await
            .expect("index failed");
    }

    let chain = indexer
        .get_commit_chain("alice", Some(1), Some(3))
        .await
        .expect("chain failed");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].sequence, 1);
    assert_eq!(chain[2].sequence, 3);
}

#[tokio::test]
async fn get_commit_chain_unknown_returns_empty() {
    let indexer = MemoryIndexer::new();
    let chain = indexer
        .get_commit_chain("nonexistent", None, None)
        .await
        .expect("chain failed");
    assert!(chain.is_empty());
}

#[tokio::test]
async fn resolve_digest_returns_none_for_unknown() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);

    indexer.index_commit(&commit).await.expect("index failed");

    let real_digest: cyphr::state::TaggedDigest =
        "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
            .parse()
            .expect("parse tagged digest");

    let result = indexer
        .resolve_digest(&real_digest)
        .await
        .expect("resolve failed");
    assert!(
        result.is_none(),
        "unindexed tagged digest should return None",
    );
}

#[tokio::test]
async fn indexed_blobs_tracked_in_commit_chain() {
    let indexer = MemoryIndexer::new();
    let commit = make_commit("alice", 0, 1000);
    let blob_hash = commit.blob_hashes[0];

    indexer.index_commit(&commit).await.expect("index failed");

    // Verify blobs are tracked via commit chain (public API).
    let chain = indexer
        .get_commit_chain("alice", None, None)
        .await
        .expect("chain failed");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].blob_hashes.len(), 1);
    assert_eq!(chain[0].blob_hashes[0], blob_hash);
}

#[tokio::test]
async fn list_principals_returns_all() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .await
        .expect("alice");
    indexer
        .index_commit(&make_commit("bob", 0, 2000))
        .await
        .expect("bob");

    let principals = indexer.list_principals().await.expect("list failed");
    assert_eq!(principals.len(), 2);

    let ids: Vec<&str> = principals.iter().map(|p| p.principal_id.as_str()).collect();
    assert!(ids.contains(&"alice"));
    assert!(ids.contains(&"bob"));
}

#[tokio::test]
async fn principal_summary_tracks_creation_time() {
    let indexer = MemoryIndexer::new();

    indexer
        .index_commit(&make_commit("alice", 0, 1000))
        .await
        .expect("genesis");
    indexer
        .index_commit(&make_commit("alice", 1, 5000))
        .await
        .expect("second");

    let principals = indexer.list_principals().await.expect("list");
    let alice = principals
        .iter()
        .find(|p| p.principal_id == "alice")
        .expect("alice");
    assert_eq!(alice.created, 1000, "created should be genesis timestamp");
    assert_eq!(alice.last_updated, 5000, "last_updated should be latest");
}

#[tokio::test]
async fn test_new_indexer_methods_memory() {
    let indexer = MemoryIndexer::new();
    run_new_indexer_methods_tests(&indexer).await;
}

async fn run_new_indexer_methods_tests<I: Indexer>(indexer: &I) {
    let key_info = PublicKeyInfo {
        thumbprint: "tmb123".to_string(),
        algorithm: "ED25519".to_string(),
        public_key: "pubkey123".to_string(),
    };

    let mut commit = make_commit("alice", 0, 1000);
    commit.keys.push(key_info.clone());

    let blob_hash = commit.blob_hashes[0];

    // Initially, blob is not indexed, key is not found
    assert!(!indexer.is_blob_indexed(&blob_hash).await.unwrap());
    assert!(indexer.get_key("tmb123").await.unwrap().is_none());

    // Index the commit
    indexer.index_commit(&commit).await.unwrap();

    // Now, blob is indexed, key is found
    assert!(indexer.is_blob_indexed(&blob_hash).await.unwrap());
    let retrieved = indexer.get_key("tmb123").await.unwrap().unwrap();
    assert_eq!(retrieved, key_info);

    // Let's test get_commit_chain
    for seq in 0..5 {
        indexer
            .index_commit(&make_commit("bob", seq, 1000 + seq as i64))
            .await
            .unwrap();
    }

    let chain = indexer.get_commit_chain("bob", None, None).await.unwrap();
    assert_eq!(chain.len(), 5);
    for (i, c) in chain.iter().enumerate() {
        assert_eq!(c.sequence, i as u64);
    }

    let range_chain = indexer
        .get_commit_chain("bob", Some(1), Some(3))
        .await
        .unwrap();
    assert_eq!(range_chain.len(), 3);
    assert_eq!(range_chain[0].sequence, 1);
    assert_eq!(range_chain[2].sequence, 3);

    // Clear the indexer
    indexer.clear().await.unwrap();

    // After clear, blob is not indexed, key is not found, tip is None, chain is empty
    assert!(!indexer.is_blob_indexed(&blob_hash).await.unwrap());
    assert!(indexer.get_key("tmb123").await.unwrap().is_none());
    assert!(indexer.get_tip("alice").await.unwrap().is_none());
    assert!(
        indexer
            .get_commit_chain("bob", None, None)
            .await
            .unwrap()
            .is_empty()
    );
}
