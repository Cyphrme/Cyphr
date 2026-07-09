//! `MemoryIndexer` conformance wrappers.
//!
//! Each test delegates to a shared, generic behavior function in
//! [`super::conformance`] — the same functions any other `Indexer`
//! implementation's own test suite calls, so `MemoryIndexer` and every
//! durable backend are held to one behavioral bar, not independently
//! hand-duplicated ones.

use super::{conformance, *};

#[tokio::test]
async fn index_commit_and_get_tip() {
    conformance::index_commit_and_get_tip(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn get_tip_unknown_returns_none() {
    conformance::get_tip_unknown_returns_none(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn tip_updates_on_subsequent_commits() {
    conformance::tip_updates_on_subsequent_commits(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn index_commit_idempotent() {
    conformance::index_commit_idempotent(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn get_commit_chain_full() {
    conformance::get_commit_chain_full(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn get_commit_chain_range() {
    conformance::get_commit_chain_range(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn get_commit_chain_unknown_returns_empty() {
    conformance::get_commit_chain_unknown_returns_empty(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn resolve_digest_returns_none_for_unknown() {
    conformance::resolve_digest_returns_none_for_unknown(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn indexed_blobs_tracked_in_commit_chain() {
    conformance::indexed_blobs_tracked_in_commit_chain(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn list_principals_returns_all() {
    conformance::list_principals_returns_all(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn principal_summary_tracks_creation_time() {
    conformance::principal_summary_tracks_creation_time(&MemoryIndexer::new()).await;
}

#[tokio::test]
async fn test_new_indexer_methods_memory() {
    conformance::new_indexer_methods(&MemoryIndexer::new()).await;
}
