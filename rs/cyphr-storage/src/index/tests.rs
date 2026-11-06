//! `MemoryIndexer` run of the shared `Indexer` conformance suite.

use super::{conformance, *};

/// Backs the `Indexer` contract (tips, chains, digest and PG-alias
/// resolution, conflicts, holder sets, position-keyed idempotency) for
/// the in-memory backend: it runs every shared function in
/// [`super::conformance`], the same bar `FjallIndexer` is held to. Unit:
/// the `Indexer` trait seam is internal; no end-to-end route names a
/// backend-independent contract.
#[tokio::test]
async fn memory_indexer_passes_the_shared_conformance_suite() {
    conformance::index_commit_with_absent_roots_reads_back_none(&MemoryIndexer::new()).await;
    conformance::index_commit_and_get_tip(&MemoryIndexer::new()).await;
    conformance::get_tip_unknown_returns_none(&MemoryIndexer::new()).await;
    conformance::tip_updates_on_subsequent_commits(&MemoryIndexer::new()).await;
    conformance::index_commit_idempotent(&MemoryIndexer::new()).await;
    conformance::get_commit_chain_full(&MemoryIndexer::new()).await;
    conformance::get_commit_chain_range(&MemoryIndexer::new()).await;
    conformance::get_commit_chain_unknown_returns_empty(&MemoryIndexer::new()).await;
    conformance::resolve_digest_returns_none_for_unknown(&MemoryIndexer::new()).await;
    conformance::resolve_digest_returns_indexed_position(&MemoryIndexer::new()).await;
    conformance::indexed_blobs_tracked_in_commit_chain(&MemoryIndexer::new()).await;
    conformance::list_principals_returns_all(&MemoryIndexer::new()).await;
    conformance::principal_summary_tracks_creation_time(&MemoryIndexer::new()).await;
    conformance::new_indexer_methods(&MemoryIndexer::new()).await;
    conformance::alias_pg_variants_resolve_to_the_principal(&MemoryIndexer::new()).await;
    conformance::pg_established_marker_tracks_the_pg_commit(&MemoryIndexer::new()).await;
    conformance::alias_conflict_second_principal_is_refused(&MemoryIndexer::new()).await;
    conformance::alias_conflict_naming_another_principal_is_refused(&MemoryIndexer::new()).await;
    conformance::digest_conflict_same_principal_repeat_is_allowed(&MemoryIndexer::new()).await;
    conformance::digest_holders_shared_digest_names_every_holder(&MemoryIndexer::new()).await;
    conformance::index_commit_idempotency_is_keyed_by_chain_position(&MemoryIndexer::new()).await;
    conformance::digest_holders_do_not_depend_on_arrival_order(
        &MemoryIndexer::new(),
        &MemoryIndexer::new(),
    )
    .await;
    conformance::digest_holders_are_a_duplicate_free_set(
        &MemoryIndexer::new(),
        &MemoryIndexer::new(),
    )
    .await;
}
