//! `FjallIndexer` conformance + injectivity tests.
//!
//! The conformance functions are the same ones `MemoryIndexer`'s own
//! test suite calls (`cyphr_storage::index::conformance`, gated behind
//! that crate's `conformance-tests` dev-dependency feature) — per the
//! shared-conformance-suite requirement the KV-index migration established,
//! this backend must be held to the identical behavioral bar, not a
//! hand-picked subset.

use cyphr_storage::index::{DeriveToken, IndexerWrite, conformance};

use super::*;

/// Backs the `Indexer` contract (tips, chains, digest and PG-alias
/// resolution, conflicts, holder sets, position-keyed idempotency) for
/// the durable backend: every shared function in
/// `cyphr_storage::index::conformance` against a fresh `FjallIndexer`.
/// Unit: the `Indexer` trait seam is internal; no end-to-end route names
/// a backend-independent contract.
#[tokio::test]
async fn fjall_indexer_passes_the_shared_conformance_suite() {
    conformance::index_commit_with_absent_roots_reads_back_none(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::index_commit_and_get_tip(&FjallIndexer::temp().expect("open temp indexer").0)
        .await;
    conformance::get_tip_unknown_returns_none(&FjallIndexer::temp().expect("open temp indexer").0)
        .await;
    conformance::tip_updates_on_subsequent_commits(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::index_commit_idempotent(&FjallIndexer::temp().expect("open temp indexer").0).await;
    conformance::get_commit_chain_full(&FjallIndexer::temp().expect("open temp indexer").0).await;
    conformance::get_commit_chain_range(&FjallIndexer::temp().expect("open temp indexer").0).await;
    conformance::get_commit_chain_unknown_returns_empty(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::resolve_digest_returns_none_for_unknown(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::resolve_digest_returns_indexed_position(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::indexed_blobs_tracked_in_commit_chain(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::list_principals_returns_all(&FjallIndexer::temp().expect("open temp indexer").0)
        .await;
    conformance::principal_summary_tracks_creation_time(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::new_indexer_methods(&FjallIndexer::temp().expect("open temp indexer").0).await;
    conformance::alias_pg_variants_resolve_to_the_principal(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::pg_established_marker_tracks_the_pg_commit(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::alias_conflict_second_principal_is_refused(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::alias_conflict_naming_another_principal_is_refused(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::digest_conflict_same_principal_repeat_is_allowed(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::digest_holders_shared_digest_names_every_holder(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::replace_chain_from_repoints_the_chain(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::index_commit_idempotency_is_keyed_by_chain_position(
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    // The pair-taking functions compare two indexers fed in opposite orders.
    conformance::digest_holders_do_not_depend_on_arrival_order(
        &FjallIndexer::temp().expect("open temp indexer").0,
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
    conformance::digest_holders_are_a_duplicate_free_set(
        &FjallIndexer::temp().expect("open temp indexer").0,
        &FjallIndexer::temp().expect("open temp indexer").0,
    )
    .await;
}

/// Backs R3 (AGENTS.md): the alias table is ONE KV table registered in the
/// index meta-table, not a side channel. After a PG-establishing commit is
/// indexed the registry lists every other partition plus exactly one
/// more. Turns red if no partition is registered for the alias, or
/// more than one is. A unit test: the registry is not reachable from any
/// end-to-end scenario.
#[tokio::test]
async fn alias_table_is_one_registered_kv_table() {
    let (indexer, _dir) = FjallIndexer::temp().expect("open temp indexer");
    let mut commit = conformance::make_commit("SHA-256:genesis-digest", 0, 1000);
    commit.pg = vec!["SHA-256:pg-digest".to_string()];
    commit.cozies[0].typ = "cyphr.me/cyphr/principal/create".to_string();
    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index");

    let registry = indexer.registry().expect("registry");
    let before = [
        "index_tips",
        "index_principals",
        "index_commits",
        "index_digests",
        "index_public_keys",
    ];
    for name in before {
        assert!(
            registry.contains(name),
            "registry lost {name}: {registry:?}"
        );
    }
    assert_eq!(
        registry.len(),
        before.len() + 1,
        "the alias table must be exactly one newly registered partition: {registry:?}"
    );
}

/// A durably-reopened `FjallIndexer` (fresh `Database`, not a clone of the
/// live one) must see everything written before the reopen — otherwise
/// this backend would silently lose durability across a reopen, a
/// regression the conformance suite (in-memory only) can't itself catch.
#[tokio::test]
async fn survives_disk_reload() {
    let dir = tempfile::tempdir().expect("tempdir");

    {
        let indexer = FjallIndexer::open(dir.path()).expect("open");
        indexer
            .index_commit(
                &conformance::make_commit("alice", 0, 1000),
                &DeriveToken::for_conformance_tests(),
            )
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
            .index_commit(
                &conformance::make_commit("alice", seq, 1000 + seq as i64),
                &DeriveToken::for_conformance_tests(),
            )
            .await
            .expect("index alice");
    }
    for seq in 0..2 {
        indexer
            .index_commit(
                &conformance::make_commit("alice2", seq, 2000 + seq as i64),
                &DeriveToken::for_conformance_tests(),
            )
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

/// An index commit of principal `p<i>` whose coz carries the shared `czd`.
fn commit_sharing(i: usize, czd: &str) -> cyphr_storage::index::IndexableCommit {
    let mut c = conformance::make_commit(&format!("SHA-256:p{i:04}"), 0, 1000);
    c.cozies[0].czd = czd.to_string();
    c
}

/// Claim: a digest held by many principals costs one small write per
/// holder, not a rewrite of the whole set: no stored value grows with the
/// holder count (F-D: 3001 holders made a ~1 MB value rewritten under the
/// global write lock on every push), and reads still see every holder, the
/// first in canonical order. Turns red if holders share one value.
#[tokio::test]
async fn digest_holder_writes_do_not_grow_with_the_holder_count() {
    let (indexer, _dir) = FjallIndexer::temp().expect("open temp indexer");
    let czd = format!("SHA-256:{}", "A".repeat(43));
    let token = DeriveToken::for_conformance_tests();
    const HOLDERS: usize = 300;
    for i in 0..HOLDERS {
        indexer
            .index_commit(&commit_sharing(i, &czd), &token)
            .await
            .unwrap();
    }
    let digest: cyphr::state::TaggedDigest = czd.parse().unwrap();
    let holders = indexer.resolve_digest_holders(&digest).await.unwrap();
    assert_eq!(holders.len(), HOLDERS);
    let first = indexer.resolve_digest(&digest).await.unwrap().unwrap();
    assert_eq!(first.principal_id.as_deref(), Some("SHA-256:p0000"));

    let ks = indexer.keyspaces();
    let largest = ks
        .digests
        .iter()
        .map(|g| g.value().unwrap().len())
        .max()
        .unwrap();
    assert!(
        largest < 1024,
        "a stored digest value is {largest} bytes after {HOLDERS} holders"
    );
}

// ---------------------------------------------------------------------
// N13: the index schema version is read and checked at open.
// ---------------------------------------------------------------------

/// Index a commit into a fresh store at `dir` (stamping the current schema),
/// close it, then rewrite its `index_meta` record's version to `version`, as
/// an older or newer build would have left it.
fn store_stamped_with(dir: &std::path::Path, version: u64) {
    {
        let indexer = FjallIndexer::open(dir).expect("open");
        block_on(indexer.index_commit(
            &conformance::make_commit("alice", 0, 1000),
            &DeriveToken::for_conformance_tests(),
        ))
        .expect("index");
    }
    let db = Database::builder(dir).open().expect("raw open");
    let meta = db
        .keyspace("index_meta", KeyspaceCreateOptions::default)
        .expect("meta keyspace");
    let raw = meta.get(META_KEY).expect("read").expect("a stamped record");
    let mut record: serde_json::Value = serde_json::from_slice(&raw).expect("json record");
    record["version"] = version.into();
    meta.insert(META_KEY, serde_json::to_vec(&record).unwrap())
        .expect("rewrite");
    db.persist(fjall::PersistMode::SyncAll).expect("persist");
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// Backs a-versions for the index: a store stamped with a FUTURE schema
/// version (a downgrade) is refused at open as a typed `UnsupportedVersion`,
/// never read as if it were current. Older or missing versions are not
/// refused: the index is a cache and is rebuilt (see `legacy_store_*`). Turns red on an `open` that
/// ignores the recorded version. A unit test: the stamp is reachable only here.
#[test]
fn version_index_unknown_is_refused() {
    let unknown = 99u64;
    let dir = tempfile::tempdir().expect("tempdir");
    store_stamped_with(dir.path(), unknown);
    let refused = FjallIndexer::open(dir.path()).err();
    assert!(
        matches!(
            refused,
            Some(IndexerError::UnsupportedVersion { found, .. }) if found == unknown
        ),
        "v{unknown} must be refused as UnsupportedVersion: {refused:?}"
    );
}

/// Backs the version-4 bump: SR and AR became optional (`null` for a Dead
/// principal), where version 3 recorded an absent root as an empty string.
/// Scenario: a store stamped version 3 whose tip row holds the legacy shape
/// (`"sr": ""`) is discarded at open, not read (read as `Some("")` it would
/// report an empty root for a Dead principal), and re-indexing the commit
/// restores the tip in the current shape. Turns red if the schema version is
/// not raised, so a version-3 row is read as current. End to end: yes
/// (open, discard, re-derive).
#[test]
fn schema_v3_index_with_empty_string_roots_is_rebuilt_not_misread() {
    let dir = tempfile::tempdir().expect("tempdir");
    store_stamped_with(dir.path(), 3);
    {
        let db = Database::builder(dir.path()).open().expect("raw open");
        let tips = db
            .keyspace("index_tips", KeyspaceCreateOptions::default)
            .expect("tips keyspace");
        let rows: Vec<(Vec<u8>, Vec<u8>)> = tips
            .iter()
            .map(|g| {
                let (k, v) = g.into_inner().expect("row");
                (k.to_vec(), v.to_vec())
            })
            .collect();
        assert_eq!(rows.len(), 1, "premise: one tip row");
        let mut tip: serde_json::Value = serde_json::from_slice(&rows[0].1).expect("json");
        tip["sr"] = "".into();
        tip["ar"] = "".into();
        tips.insert(&rows[0].0, serde_json::to_vec(&tip).unwrap())
            .expect("write legacy row");
        db.persist(fjall::PersistMode::SyncAll).expect("persist");
    }

    let indexer = FjallIndexer::open(dir.path()).expect("an older index opens");
    assert!(
        block_on(indexer.get_tip("alice")).unwrap().is_none(),
        "a version-3 tip row survived the open and would be misread"
    );

    block_on(indexer.index_commit(
        &conformance::make_commit("alice", 0, 1000),
        &DeriveToken::for_conformance_tests(),
    ))
    .expect("re-index");
    let tip = block_on(indexer.get_tip("alice")).unwrap().expect("tip");
    assert_eq!(tip.sr.as_deref(), Some("SHA-256:sr-alice-0"));
}
