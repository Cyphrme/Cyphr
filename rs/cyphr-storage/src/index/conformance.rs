//! Shared behavioral conformance suite for [`Indexer`] implementations.
//!
//! Every `Indexer` backend (in this crate or another) is held to the same
//! functions here rather than a hand-duplicated, backend-specific subset —
//! the same shared-conformance-suite requirement the KV-index migration
//! established. Feature-gated (`conformance-tests`) so an
//! out-of-crate backend can add this crate as a dev-dependency with that
//! feature enabled and call these functions directly from its own
//! `#[tokio::test]` wrappers.

use cyphr::state::TaggedDigest;

use super::{DeriveToken, IndexerWrite, *};

/// Build a test commit for indexing.
pub fn make_commit(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
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
        crs: vec![format!("SHA-256:cr-{principal_id}-{seq}")],
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
        pg: Vec::new(),
    }
}

pub async fn index_commit_and_get_tip<I: Indexer + IndexerWrite>(indexer: &I) {
    let commit = make_commit("alice", 0, 1000);

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
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

pub async fn get_tip_unknown_returns_none<I: Indexer + IndexerWrite>(indexer: &I) {
    let tip = indexer
        .get_tip("nonexistent")
        .await
        .expect("get_tip failed");
    assert!(tip.is_none(), "unknown principal should return None");
}

pub async fn tip_updates_on_subsequent_commits<I: Indexer + IndexerWrite>(indexer: &I) {
    indexer
        .index_commit(
            &make_commit("alice", 0, 1000),
            &DeriveToken::for_conformance_tests(),
        )
        .await
        .expect("first commit");
    indexer
        .index_commit(
            &make_commit("alice", 1, 2000),
            &DeriveToken::for_conformance_tests(),
        )
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

pub async fn index_commit_idempotent<I: Indexer + IndexerWrite>(indexer: &I) {
    let commit = make_commit("alice", 0, 1000);

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("first index");
    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("duplicate index");

    let tip = indexer
        .get_tip("alice")
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(tip.commit_count, 1, "duplicate should not increase count");
}

pub async fn get_commit_chain_full<I: Indexer + IndexerWrite>(indexer: &I) {
    for seq in 0..5 {
        indexer
            .index_commit(
                &make_commit("alice", seq, 1000 + seq as i64),
                &DeriveToken::for_conformance_tests(),
            )
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

pub async fn get_commit_chain_range<I: Indexer + IndexerWrite>(indexer: &I) {
    for seq in 0..5 {
        indexer
            .index_commit(
                &make_commit("alice", seq, 1000 + seq as i64),
                &DeriveToken::for_conformance_tests(),
            )
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

pub async fn get_commit_chain_unknown_returns_empty<I: Indexer + IndexerWrite>(indexer: &I) {
    let chain = indexer
        .get_commit_chain("nonexistent", None, None)
        .await
        .expect("chain failed");
    assert!(chain.is_empty());
}

pub async fn resolve_digest_returns_none_for_unknown<I: Indexer + IndexerWrite>(indexer: &I) {
    let commit = make_commit("alice", 0, 1000);

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index failed");

    let real_digest: TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
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

/// A commit-level digest variant (PR here, but any of commit_id/pr/sr/ar/cr
/// share the same code path -- see `index_commit`) must resolve to the
/// chain position it was produced at, not merely to a blob -- this is the
/// lookup the content-addressed resync anchor (Zami #140) is built on.
/// `make_commit`'s default `prs` value is a placeholder string, not a
/// parseable `TaggedDigest`, so this overrides just that field with a real
/// digest the test can independently resolve by.
pub async fn resolve_digest_returns_indexed_position<I: Indexer + IndexerWrite>(indexer: &I) {
    let real_pr: TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
        .parse()
        .expect("parse tagged digest");

    let mut commit = make_commit("alice", 2, 3000);
    commit.prs = vec![real_pr.to_string()];

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index failed");

    let resolved = indexer
        .resolve_digest(&real_pr)
        .await
        .expect("resolve failed")
        .expect("digest should resolve to an entity");

    assert_eq!(
        resolved.sequence,
        Some(2),
        "a commit-level digest must resolve to the chain position (sequence) it was produced at",
    );
}

pub async fn indexed_blobs_tracked_in_commit_chain<I: Indexer + IndexerWrite>(indexer: &I) {
    let commit = make_commit("alice", 0, 1000);
    let blob_hash = commit.blob_hashes[0];

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index failed");

    // Verify blobs are tracked via commit chain (public API).
    let chain = indexer
        .get_commit_chain("alice", None, None)
        .await
        .expect("chain failed");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].blob_hashes.len(), 1);
    assert_eq!(chain[0].blob_hashes[0], blob_hash);
}

pub async fn list_principals_returns_all<I: Indexer + IndexerWrite>(indexer: &I) {
    indexer
        .index_commit(
            &make_commit("alice", 0, 1000),
            &DeriveToken::for_conformance_tests(),
        )
        .await
        .expect("alice");
    indexer
        .index_commit(
            &make_commit("bob", 0, 2000),
            &DeriveToken::for_conformance_tests(),
        )
        .await
        .expect("bob");

    let principals = indexer.list_principals().await.expect("list failed");
    assert_eq!(principals.len(), 2);

    let ids: Vec<&str> = principals.iter().map(|p| p.principal_id.as_str()).collect();
    assert!(ids.contains(&"alice"));
    assert!(ids.contains(&"bob"));
}

pub async fn principal_summary_tracks_creation_time<I: Indexer + IndexerWrite>(indexer: &I) {
    indexer
        .index_commit(
            &make_commit("alice", 0, 1000),
            &DeriveToken::for_conformance_tests(),
        )
        .await
        .expect("genesis");
    indexer
        .index_commit(
            &make_commit("alice", 1, 5000),
            &DeriveToken::for_conformance_tests(),
        )
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

pub async fn new_indexer_methods<I: Indexer + IndexerWrite>(indexer: &I) {
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
    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .unwrap();

    // Now, blob is indexed, key is found
    assert!(indexer.is_blob_indexed(&blob_hash).await.unwrap());
    let retrieved = indexer.get_key("tmb123").await.unwrap().unwrap();
    assert_eq!(retrieved, key_info);

    // Let's test get_commit_chain
    for seq in 0..5 {
        indexer
            .index_commit(
                &make_commit("bob", seq, 1000 + seq as i64),
                &DeriveToken::for_conformance_tests(),
            )
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
    indexer
        .clear(&DeriveToken::for_conformance_tests())
        .await
        .unwrap();

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

/// Hash variants of a principal's PG (SPEC §3.7.1): the PR it held
/// immediately BEFORE the `principal/create` commit, not that commit's own
/// post-commit PR.
fn pg_variants() -> Vec<String> {
    ["SHA-256", "SHA-384", "SHA-512"]
        .iter()
        .map(|alg| format!("{alg}:pg-digest-{alg}"))
        .collect()
}

/// A commit carrying `principal/create`. Its `prs` are the post-commit PR
/// (which differs from the PG); `pg` is what the engine records for the
/// PG-establishing commit.
fn principal_create_commit(principal_id: &str, seq: u64) -> IndexableCommit {
    let mut commit = make_commit(principal_id, seq, 1000 + seq as i64);
    commit.cozies[0].typ = "cyphr.me/cyphr/principal/create".to_string();
    commit.pg = pg_variants();
    commit
}

/// Backs SPEC §3.7.1/§12.1 (the PG, in every hash variant, names one
/// principal; nothing else does) at the index seam, for every backend: once
/// the PG-establishing commit is indexed, each PG variant resolves to the
/// principal's chain and tip; a label-forged spelling, and every PR the
/// principal has held that is not its PG (before and after the create
/// commit), resolve to nothing and create no principal; `clear` drops the
/// aliases (derived, I1).
///
/// A unit test because the engine-level scenarios cannot tell which backend
/// failed.
pub async fn alias_pg_variants_resolve_to_the_principal<I: Indexer + IndexerWrite>(indexer: &I) {
    let token = DeriveToken::for_conformance_tests();
    let id = "SHA-256:genesis-digest";
    indexer
        .index_commit(&make_commit(id, 0, 1000), &token)
        .await
        .expect("index commit 0");

    let variants = pg_variants();
    for v in &variants {
        assert!(
            indexer
                .get_commit_chain(v, None, None)
                .await
                .unwrap()
                .is_empty(),
            "{v} resolved before the PG was established"
        );
    }

    indexer
        .index_commit(&principal_create_commit(id, 1), &token)
        .await
        .expect("index principal/create commit");
    // Re-indexing is a no-op and must not duplicate or move an alias.
    indexer
        .index_commit(&principal_create_commit(id, 1), &token)
        .await
        .expect("re-index principal/create commit");

    let want_chain = indexer.get_commit_chain(id, None, None).await.unwrap();
    let want_tip = indexer.get_tip(id).await.unwrap().expect("tip");
    assert_eq!(want_chain.len(), 2, "control: the canonical chain");
    for v in &variants {
        assert_eq!(
            indexer.get_commit_chain(v, None, None).await.unwrap(),
            want_chain,
            "PG variant {v} does not resolve to the principal's chain"
        );
        assert_eq!(
            indexer.get_tip(v).await.unwrap().as_ref(),
            Some(&want_tip),
            "PG variant {v} does not resolve to the principal's tip"
        );
    }

    // Not the PG: a digest the PG has under another label, a label no
    // variant has, and PRs the principal held (commit 0's, and the create
    // commit's own post-commit PR).
    let held = [format!("SHA-256:pr-{id}-0"), format!("SHA-256:pr-{id}-1")];
    for forged in [
        "SHA-512:pg-digest-SHA-256",
        "SHA3-256:pg-digest-SHA-256",
        held[0].as_str(),
        held[1].as_str(),
    ] {
        assert!(
            indexer
                .get_commit_chain(forged, None, None)
                .await
                .unwrap()
                .is_empty(),
            "{forged} resolved but is not the PG or the genesis id"
        );
        assert!(indexer.get_tip(forged).await.unwrap().is_none());
    }
    assert_eq!(
        indexer.list_principals().await.unwrap().len(),
        1,
        "an alias must not appear as a second principal"
    );

    indexer.clear(&token).await.expect("clear");
    for v in &variants {
        assert!(
            indexer
                .get_commit_chain(v, None, None)
                .await
                .unwrap()
                .is_empty(),
            "alias {v} survived clear: the alias table is not derived state"
        );
    }
}

/// Backs the read-path DoS bound at the index seam: the established-PG
/// marker is false until the PG-establishing commit is indexed, true for
/// that principal only (not for a PG variant or another principal), and
/// dropped by `clear` (derived, I1). Turns red if the marker is set early,
/// leaks to an alias, or survives `clear`. A unit test: the engine-level
/// test cannot tell which backend failed.
pub async fn pg_established_marker_tracks_the_pg_commit<I: Indexer + IndexerWrite>(indexer: &I) {
    let token = DeriveToken::for_conformance_tests();
    let id = "SHA-256:genesis-digest";
    indexer
        .index_commit(&make_commit(id, 0, 1000), &token)
        .await
        .expect("index commit 0");
    assert!(!indexer.is_pg_established(id).await.unwrap());

    indexer
        .index_commit(&principal_create_commit(id, 1), &token)
        .await
        .expect("index principal/create commit");
    assert!(indexer.is_pg_established(id).await.unwrap());
    for v in pg_variants() {
        assert!(
            !indexer.is_pg_established(&v).await.unwrap(),
            "the marker leaked to the alias {v}"
        );
    }
    assert!(!indexer.is_pg_established("SHA-256:other").await.unwrap());
    assert!(!indexer.is_pg_established("").await.unwrap());

    indexer.clear(&token).await.expect("clear");
    assert!(!indexer.is_pg_established(id).await.unwrap());
}

/// A `principal/create` commit for `id` whose PG variants are `pg`.
fn create_commit_with_pg(id: &str, seq: u64, pg: &[&str]) -> IndexableCommit {
    let mut c = make_commit(id, seq, 1000 + seq as i64);
    c.cozies[0].typ = "cyphr.me/cyphr/principal/create".to_string();
    c.pg = pg.iter().map(|s| s.to_string()).collect();
    c
}

/// Backs "no hostile write can re-point a principal alias" at the index
/// seam, for every backend. Principal A establishes a PG; a later commit
/// of principal B naming the same PG variant is refused as
/// [`IndexerError::Conflict`], writes nothing (B has no chain, tip or
/// alias), and A's alias still resolves to A. Re-indexing A's own commit
/// stays a no-op. Turns red if the second writer is silently ignored
/// (first-writer-wins) or wins (overwrite). A unit test: engine-level
/// scenarios cannot reach a second principal claiming the same PG.
pub async fn alias_conflict_second_principal_is_refused<I: Indexer + IndexerWrite>(indexer: &I) {
    let token = DeriveToken::for_conformance_tests();
    let (a, b) = ("SHA-256:alice-id", "SHA-256:bob-id");
    let pg = "SHA-256:contested-pg";
    for id in [a, b] {
        indexer
            .index_commit(&make_commit(id, 0, 1000), &token)
            .await
            .expect("commit 0");
    }
    indexer
        .index_commit(&create_commit_with_pg(a, 1, &[pg]), &token)
        .await
        .expect("A establishes the PG");

    let err = indexer
        .index_commit(&create_commit_with_pg(b, 1, &[pg]), &token)
        .await
        .expect_err("B re-pointing A's alias must be refused");
    assert!(matches!(err, IndexerError::Conflict(_)), "got {err:?}");

    assert_eq!(
        indexer.get_tip(pg).await.unwrap().map(|t| t.principal_id),
        Some(a.to_string()),
        "A's alias moved or vanished"
    );
    assert_eq!(
        indexer.get_tip(b).await.unwrap().unwrap().commit_count,
        1,
        "the refused commit must write nothing"
    );
    assert!(!indexer.is_pg_established(b).await.unwrap());
    indexer
        .index_commit(&create_commit_with_pg(a, 1, &[pg]), &token)
        .await
        .expect("re-indexing A's own commit stays a no-op");
}

/// An alias that spells another stored principal's id is refused too: the
/// id would be unreachable through the alias and a reader could not tell
/// the two apart. Turns red if the alias is written (shadowed) or ignored.
pub async fn alias_conflict_naming_another_principal_is_refused<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let (a, b) = ("SHA-256:alice-id", "SHA-256:bob-id");
    for id in [a, b] {
        indexer
            .index_commit(&make_commit(id, 0, 1000), &token)
            .await
            .expect("commit 0");
    }
    let err = indexer
        .index_commit(&create_commit_with_pg(b, 1, &[a]), &token)
        .await
        .expect_err("an alias spelling A's id must be refused");
    assert!(matches!(err, IndexerError::Conflict(_)), "got {err:?}");
    assert_eq!(
        indexer.get_tip(a).await.unwrap().unwrap().principal_id,
        a,
        "A still resolves to itself"
    );
}

/// Backs "no hostile write can redirect a digest" at the index seam. A
/// commit of principal B that carries a coz czd (or a commit digest) that
/// principal A already owns is refused as [`IndexerError::Conflict`];
/// the digest still resolves to A, and B's commit is not indexed. Turns
/// red if the digest is overwritten (redirect). A unit test: engine-level
/// scenarios cannot make two principals' derived digests collide.
pub async fn digest_conflict_other_principal_is_refused<I: Indexer + IndexerWrite>(indexer: &I) {
    let token = DeriveToken::for_conformance_tests();
    let (a, b) = ("SHA-256:alice-id", "SHA-256:bob-id");
    // Well-formed digests, so `resolve_digest` can parse them.
    let owned_czd = format!("SHA-256:{}", "A".repeat(43));
    let owned_commit = format!("SHA-256:{}", "B".repeat(42) + "A");
    let mut first = make_commit(a, 0, 1000);
    first.cozies[0].czd = owned_czd.clone();
    first.commit_ids = vec![owned_commit.clone()];
    indexer
        .index_commit(&first, &token)
        .await
        .expect("A commit 0");
    indexer
        .index_commit(&make_commit(b, 0, 1000), &token)
        .await
        .expect("B commit 0");

    for (label, mutate) in [
        (
            "coz czd",
            Box::new(|c: &mut IndexableCommit| c.cozies[0].czd = owned_czd.clone())
                as Box<dyn Fn(&mut IndexableCommit)>,
        ),
        (
            "commit pr",
            Box::new(|c: &mut IndexableCommit| c.prs = vec![owned_commit.clone()]),
        ),
    ] {
        let mut hostile = make_commit(b, 1, 2000);
        mutate(&mut hostile);
        let err = indexer
            .index_commit(&hostile, &token)
            .await
            .expect_err("a colliding digest must be refused");
        assert!(
            matches!(err, IndexerError::Conflict(_)),
            "{label}: got {err:?}"
        );
        for owned in [&owned_czd, &owned_commit] {
            let digest: TaggedDigest = owned.parse().expect("tagged digest");
            let e = indexer.resolve_digest(&digest).await.unwrap().unwrap();
            assert_eq!(e.principal_id.as_deref(), Some(a), "{label}: redirected");
        }
        assert_eq!(
            indexer.get_tip(b).await.unwrap().unwrap().commit_count,
            1,
            "{label}: the refused commit must write nothing"
        );
    }
}

/// Control for the digest check: one principal's own commits may repeat a
/// root (a commit that leaves SR unchanged), and the later commit takes
/// the digest. Turns red if the conflict check is over-broad and refuses
/// an honest history.
pub async fn digest_conflict_same_principal_repeat_is_allowed<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let a = "SHA-256:alice-id";
    let sr = format!("SHA-256:{}", "C".repeat(42) + "A");
    let mut first = make_commit(a, 0, 1000);
    first.srs = vec![sr.clone()];
    indexer.index_commit(&first, &token).await.unwrap();
    let mut next = make_commit(a, 1, 2000);
    next.srs = vec![sr.clone()];
    indexer.index_commit(&next, &token).await.expect("repeat");
    let digest: TaggedDigest = sr.parse().unwrap();
    let e = indexer.resolve_digest(&digest).await.unwrap().unwrap();
    assert_eq!(e.sequence, Some(1));
}

/// Control for the digest check: state and auth roots derive from the key
/// set, so two principals that end on the same keys honestly share them.
/// Both commits are accepted. Turns red if the conflict check covers SR or
/// AR and so rejects an honest commit (or lets a stranger block one).
pub async fn digest_conflict_shared_state_roots_are_not_a_conflict<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let shared = format!("SHA-256:{}", "D".repeat(42) + "A");
    for id in ["SHA-256:alice-id", "SHA-256:bob-id"] {
        let mut commit = make_commit(id, 0, 1000);
        commit.srs = vec![shared.clone()];
        commit.ars = vec![shared.clone()];
        indexer
            .index_commit(&commit, &token)
            .await
            .expect("an honest commit sharing SR/AR with another principal");
    }
}
