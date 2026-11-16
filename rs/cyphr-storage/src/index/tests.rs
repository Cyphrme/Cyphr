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
    conformance::run_all(|| (MemoryIndexer::new(), ())).await;
}
