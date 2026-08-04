//! `FjallIndexer` conformance + injectivity tests.
//!
//! The conformance functions are the same ones `MemoryIndexer`'s own
//! test suite calls (`cyphr_storage::index::conformance`, gated behind
//! that crate's `conformance-tests` dev-dependency feature) — per the
//! shared-conformance-suite requirement the KV-index migration established,
//! this backend must be held to the identical behavioral bar, not a
//! hand-picked subset.

use cyphr_storage::index::conformance;

use super::*;

macro_rules! conformance_test {
    ($name:ident) => {
        #[tokio::test]
        async fn $name() {
            let (indexer, _dir) = FjallIndexer::temp().expect("open temp indexer");
            conformance::$name(&indexer).await;
        }
    };
}

conformance_test!(index_commit_and_get_tip);
conformance_test!(get_tip_unknown_returns_none);
conformance_test!(tip_updates_on_subsequent_commits);
conformance_test!(index_commit_idempotent);
conformance_test!(get_commit_chain_full);
conformance_test!(get_commit_chain_range);
conformance_test!(get_commit_chain_unknown_returns_empty);
conformance_test!(resolve_digest_returns_none_for_unknown);
conformance_test!(resolve_digest_returns_indexed_position);
conformance_test!(indexed_blobs_tracked_in_commit_chain);
conformance_test!(list_principals_returns_all);
conformance_test!(principal_summary_tracks_creation_time);

#[tokio::test]
async fn new_indexer_methods() {
    let (indexer, _dir) = FjallIndexer::temp().expect("open temp indexer");
    conformance::new_indexer_methods(&indexer).await;
}

/// A durably-reopened `FjallIndexer` (fresh `Database`, not a clone of the
/// live one) must see everything written before the reopen — otherwise
/// this backend would be strictly weaker than `SqliteIndexer::open`
/// against a real file, which the conformance suite (in-memory only)
/// can't itself catch.
#[tokio::test]
async fn survives_disk_reload() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let indexer = FjallIndexer::open(dir.path()).expect("open");
        indexer
            .index_commit(&conformance::make_commit("alice", 0, 1000))
            .await
            .expect("index");
    }

    let reopened = FjallIndexer::open(dir.path()).expect("reopen");
    let tip = reopened
        .get_tip("alice")
        .await
        .expect("get_tip")
        .expect("tip survives reload");
    assert_eq!(tip.commit_count, 1);
}

// ---------------------------------------------------------------------
// c4: multi-tenant keyspace scoping must be collision-free.
// ---------------------------------------------------------------------

/// F11 left `sanitize_fjall_prefix` (a raw character-substitution scheme)
/// with no proof that distinct principal IDs map to distinct keyspaces.
/// `commit_key`'s length-prefixed construction must not repeat that gap:
/// two principal IDs where one is a literal byte-prefix of the other
/// (the case a naive, unprefixed `pid ++ sequence` encoding gets wrong,
/// per `commit_key`'s doc comment) must never produce keys whose ranges
/// overlap.
#[test]
fn commit_key_prefix_principals_do_not_overlap() {
    // "alice" is a literal prefix of "alice2" -- exactly the adversarial
    // case a naive scheme collides on.
    let short = "alice";
    let long = "alice2";

    for seq_short in [0u64, 1, u64::MAX] {
        for seq_long in [0u64, 1, u64::MAX] {
            assert_ne!(
                commit_key(short, seq_short),
                commit_key(long, seq_long),
                "distinct principal IDs must never produce equal keys"
            );
        }
    }

    // The stronger property `get_commit_chain` actually depends on: no key
    // belonging to `long` falls within `short`'s full range scan bounds
    // (and vice versa), for every sequence number either principal could
    // ever be indexed at.
    let (short_lo, short_hi) = commit_key_range(short, 0, u64::MAX);
    let (long_lo, long_hi) = commit_key_range(long, 0, u64::MAX);

    for seq in [0u64, 1, 42, u64::MAX] {
        let long_key = commit_key(long, seq);
        assert!(
            long_key < short_lo || long_key > short_hi,
            "principal '{long}' sequence {seq} must fall outside '{short}''s range"
        );

        let short_key = commit_key(short, seq);
        assert!(
            short_key < long_lo || short_key > long_hi,
            "principal '{short}' sequence {seq} must fall outside '{long}''s range"
        );
    }
}

/// Same-length principal IDs differing only in content must never
/// collide or overlap ranges either -- the other adversarial case a weak
/// scheme can get wrong.
#[test]
fn commit_key_same_length_principals_do_not_overlap() {
    let a = "alice";
    let b = "alicf"; // same length, differs in the last byte

    assert_ne!(commit_key(a, 0), commit_key(b, 0));

    let (a_lo, a_hi) = commit_key_range(a, 0, u64::MAX);
    let (b_lo, b_hi) = commit_key_range(b, 0, u64::MAX);
    assert!(
        a_hi < b_lo || b_hi < a_lo,
        "ranges for distinct same-length principals must not overlap"
    );
}

/// End-to-end: two principals whose IDs are literal prefixes of one
/// another must be indexed and queried without any cross-tenant leakage
/// through the real `Indexer` API, not just at the key-encoding level.
#[tokio::test]
async fn multitenancy_prefix_principals_are_isolated() {
    let (indexer, _dir) = FjallIndexer::temp().expect("open temp indexer");

    for seq in 0..3 {
        indexer
            .index_commit(&conformance::make_commit("alice", seq, 1000 + seq as i64))
            .await
            .expect("index alice");
    }
    for seq in 0..2 {
        indexer
            .index_commit(&conformance::make_commit("alice2", seq, 2000 + seq as i64))
            .await
            .expect("index alice2");
    }

    let alice_chain = indexer
        .get_commit_chain("alice", None, None)
        .await
        .expect("alice chain");
    assert_eq!(
        alice_chain.len(),
        3,
        "alice must see only its own 3 commits"
    );

    let alice2_chain = indexer
        .get_commit_chain("alice2", None, None)
        .await
        .expect("alice2 chain");
    assert_eq!(
        alice2_chain.len(),
        2,
        "alice2 must see only its own 2 commits"
    );

    let alice_tip = indexer.get_tip("alice").await.unwrap().unwrap();
    assert_eq!(alice_tip.commit_count, 3);
    let alice2_tip = indexer.get_tip("alice2").await.unwrap().unwrap();
    assert_eq!(alice2_tip.commit_count, 2);
}
