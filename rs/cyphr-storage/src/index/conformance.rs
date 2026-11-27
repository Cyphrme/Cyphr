//! Shared behavioral conformance suite for [`Indexer`] implementations.
//!
//! Every `Indexer` backend (in this crate or another) is held to the same
//! functions here rather than a hand-duplicated, backend-specific subset —
//! the same shared-conformance-suite requirement the KV-index migration
//! established. Feature-gated (`conformance-tests`) so an
//! out-of-crate backend can add this crate as a dev-dependency with that
//! feature enabled and call these functions directly from its own
//! `#[tokio::test]` wrappers.

use cyphr::PrincipalGenesis;
use cyphr::state::{HASH_ALGS, HashAlg, TaggedDigest};

use super::{DeriveToken, IndexerWrite, *};

/// `len` bytes of a digest derived from `seed`: a stand-in for any hash.
fn digest_bytes(seed: &str, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    blake3::Hasher::new()
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut bytes);
    bytes
}

/// The principal id of the test principal `name`: a SHA-256 id derived from
/// the name, so each name is one principal.
pub fn pid(name: &str) -> PrincipalGenesis {
    PrincipalGenesis::from_digest(HashAlg::Sha256, digest_bytes(name, 32))
        .expect("a 32-byte digest is a SHA-256 width")
}

/// A tagged SHA-256 digest derived from `seed`.
fn tagged_digest(seed: &str) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    format!(
        "SHA-256:{}",
        Base64UrlUnpadded::encode_string(&digest_bytes(seed, 32))
    )
}

/// Build a test commit of the principal `name` for indexing.
pub fn make_commit(name: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let principal_id = &pid(name);
    let blob_data = format!("{name}-commit-{seq}");
    let blob_hash =
        crate::blob::Blake3Hash::from_bytes(*blake3::hash(blob_data.as_bytes()).as_bytes());

    IndexableCommit {
        principal_id: principal_id.clone(),
        commit_ids: vec![format!("SHA-256:commit-{name}-{seq}")],
        sequence: seq,
        pre: None,
        prs: vec![tagged_digest(&format!("pr-{name}-{seq}"))],
        srs: vec![format!("SHA-256:sr-{name}-{seq}")],
        ars: vec![format!("SHA-256:ar-{name}-{seq}")],
        crs: vec![format!("SHA-256:cr-{name}-{seq}")],
        blob_hashes: vec![blob_hash],
        cozies: vec![IndexableCoz {
            blob_hash,
            czd: format!("SHA-256:czd-{name}-{seq}"),
            typ: "key/create".to_string(),
            tmb: "thumbprint".to_string(),
            alg: "ED25519".to_string(),
            now: timestamp,
            payload: None,
        }],
        timestamp,
        keys: Vec::new(),
        pg: Vec::new(),
        manifest: None,
    }
}

pub async fn index_commit_and_get_tip<I: Indexer + IndexerWrite>(indexer: &I) {
    let commit = make_commit("alice", 0, 1000);

    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index_commit failed");

    let tip = indexer
        .get_tip(&pid("alice"))
        .await
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.principal_id, pid("alice"));
    assert_eq!(tip.pr, tagged_digest("pr-alice-0"));
    assert_eq!(tip.sr.as_deref(), Some("SHA-256:sr-alice-0"));
    assert_eq!(tip.ar.as_deref(), Some("SHA-256:ar-alice-0"));
    assert_eq!(tip.commit_id, "SHA-256:commit-alice-0");
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.last_updated, 1000);
}

/// A commit that left the principal with no key and no data has no SR and
/// no AR (SPEC 3.7). The tip and the chain entry read them back as `None`,
/// never as an empty string. Turns red if an absent root is stored or read
/// as `Some("")`.
pub async fn index_commit_with_absent_roots_reads_back_none<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let mut commit = make_commit("alice", 0, 1000);
    commit.srs.clear();
    commit.ars.clear();
    indexer
        .index_commit(&commit, &DeriveToken::for_conformance_tests())
        .await
        .expect("index_commit failed");
    let tip = indexer
        .get_tip(&pid("alice"))
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!((tip.sr, tip.ar), (None, None));
    let chain = indexer
        .get_commit_chain(&pid("alice"), None, None)
        .await
        .expect("chain");
    assert_eq!((chain[0].sr.clone(), chain[0].ar.clone()), (None, None));
}

pub async fn get_tip_unknown_returns_none<I: Indexer + IndexerWrite>(indexer: &I) {
    let tip = indexer
        .get_tip(&pid("nonexistent"))
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
        .get_tip(&pid("alice"))
        .await
        .expect("get_tip failed")
        .expect("tip should exist");

    assert_eq!(tip.commit_count, 2);
    assert_eq!(tip.pr, tagged_digest("pr-alice-1"));
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
        .get_tip(&pid("alice"))
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
        .get_commit_chain(&pid("alice"), None, None)
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
        .get_commit_chain(&pid("alice"), Some(1), Some(3))
        .await
        .expect("chain failed");
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].sequence, 1);
    assert_eq!(chain[2].sequence, 3);
}

pub async fn get_commit_chain_unknown_returns_empty<I: Indexer + IndexerWrite>(indexer: &I) {
    let chain = indexer
        .get_commit_chain(&pid("nonexistent"), None, None)
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
        .get_commit_chain(&pid("alice"), None, None)
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

    let ids: Vec<&PrincipalGenesis> = principals.iter().map(|p| &p.principal_id).collect();
    assert!(ids.contains(&&pid("alice")));
    assert!(ids.contains(&&pid("bob")));
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
        .find(|p| p.principal_id == pid("alice"))
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

    let chain = indexer
        .get_commit_chain(&pid("bob"), None, None)
        .await
        .unwrap();
    assert_eq!(chain.len(), 5);
    for (i, c) in chain.iter().enumerate() {
        assert_eq!(c.sequence, i as u64);
    }

    let range_chain = indexer
        .get_commit_chain(&pid("bob"), Some(1), Some(3))
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
    assert!(indexer.get_tip(&pid("alice")).await.unwrap().is_none());
    assert!(
        indexer
            .get_commit_chain(&pid("bob"), None, None)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Hash variants of a principal's PG (SPEC §3.7.1): the PR it held
/// immediately BEFORE the `principal/create` commit, not that commit's own
/// post-commit PR.
fn pg_ids() -> Vec<PrincipalGenesis> {
    HASH_ALGS
        .into_iter()
        .map(|alg| {
            PrincipalGenesis::from_digest(
                alg,
                digest_bytes(&format!("pg-digest-{alg}"), alg.digest_size()),
            )
            .expect("a digest of the algorithm's own width")
        })
        .collect()
}

/// [`pg_ids`] as the strings a commit records.
fn pg_variants() -> Vec<String> {
    pg_ids().iter().map(ToString::to_string).collect()
}

/// A commit carrying `principal/create`. Its `prs` are the post-commit PR
/// (which differs from the PG); `pg` is what the engine records for the
/// PG-establishing commit.
fn principal_create_commit(name: &str, seq: u64) -> IndexableCommit {
    let mut commit = make_commit(name, seq, 1000 + seq as i64);
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
    let name = "genesis";
    let id = pid(name);
    indexer
        .index_commit(&make_commit(name, 0, 1000), &token)
        .await
        .expect("index commit 0");

    let variants = pg_ids();
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
        .index_commit(&principal_create_commit(name, 1), &token)
        .await
        .expect("index principal/create commit");
    // Re-indexing is a no-op and must not duplicate or move an alias.
    indexer
        .index_commit(&principal_create_commit(name, 1), &token)
        .await
        .expect("re-index principal/create commit");

    let want_chain = indexer.get_commit_chain(&id, None, None).await.unwrap();
    let want_tip = indexer.get_tip(&id).await.unwrap().expect("tip");
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

    // Not the PG: a digest the PG has under another label, and PRs the
    // principal held (commit 0's, and the create commit's own post-commit
    // PR).
    let relabelled = PrincipalGenesis::from_digest(
        HashAlg::Sha512,
        digest_bytes(&format!("pg-digest-{}", HashAlg::Sha256), 64),
    )
    .expect("a 64-byte digest is a SHA-512 width");
    let held: Vec<PrincipalGenesis> = [0, 1]
        .iter()
        .map(|seq| {
            tagged_digest(&format!("pr-{name}-{seq}"))
                .parse()
                .expect("a tagged SHA-256 digest")
        })
        .collect();
    for forged in [&relabelled, &held[0], &held[1]] {
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
    let name = "genesis";
    let id = pid(name);
    indexer
        .index_commit(&make_commit(name, 0, 1000), &token)
        .await
        .expect("index commit 0");
    assert!(!indexer.is_pg_established(&id).await.unwrap());

    indexer
        .index_commit(&principal_create_commit(name, 1), &token)
        .await
        .expect("index principal/create commit");
    assert!(indexer.is_pg_established(&id).await.unwrap());
    for v in pg_ids() {
        assert!(
            !indexer.is_pg_established(&v).await.unwrap(),
            "the marker leaked to the alias {v}"
        );
    }
    assert!(!indexer.is_pg_established(&pid("other")).await.unwrap());

    indexer.clear(&token).await.expect("clear");
    assert!(!indexer.is_pg_established(&id).await.unwrap());
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
    let (a, b) = ("alice-id", "bob-id");
    let pg_id = PrincipalGenesis::from_digest(HashAlg::Sha256, digest_bytes("contested-pg", 32))
        .expect("a 32-byte digest is a SHA-256 width");
    let pg = pg_id.to_string();
    for id in [a, b] {
        indexer
            .index_commit(&make_commit(id, 0, 1000), &token)
            .await
            .expect("commit 0");
    }
    indexer
        .index_commit(&create_commit_with_pg(a, 1, &[&pg]), &token)
        .await
        .expect("A establishes the PG");

    let err = indexer
        .index_commit(&create_commit_with_pg(b, 1, &[&pg]), &token)
        .await
        .expect_err("B re-pointing A's alias must be refused");
    assert!(matches!(err, IndexerError::Conflict(_)), "got {err:?}");

    assert_eq!(
        indexer
            .get_tip(&pg_id)
            .await
            .unwrap()
            .map(|t| t.principal_id),
        Some(pid(a)),
        "A's alias moved or vanished"
    );
    assert_eq!(
        indexer
            .get_tip(&pid(b))
            .await
            .unwrap()
            .unwrap()
            .commit_count,
        1,
        "the refused commit must write nothing"
    );
    assert!(!indexer.is_pg_established(&pid(b)).await.unwrap());
    indexer
        .index_commit(&create_commit_with_pg(a, 1, &[&pg]), &token)
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
    let (a, b) = ("alice-id", "bob-id");
    for id in [a, b] {
        indexer
            .index_commit(&make_commit(id, 0, 1000), &token)
            .await
            .expect("commit 0");
    }
    let a_spelled = pid(a).to_string();
    let err = indexer
        .index_commit(&create_commit_with_pg(b, 1, &[&a_spelled]), &token)
        .await
        .expect_err("an alias spelling A's id must be refused");
    assert!(matches!(err, IndexerError::Conflict(_)), "got {err:?}");
    assert_eq!(
        indexer
            .get_tip(&pid(a))
            .await
            .unwrap()
            .unwrap()
            .principal_id,
        pid(a),
        "A still resolves to itself"
    );
}

/// One principal's own commits may repeat a root (a commit that leaves SR
/// unchanged); the digest keeps one holder for that principal, at the
/// later commit. Turns red if the repeat is refused or the earlier commit
/// still answers.
pub async fn digest_conflict_same_principal_repeat_is_allowed<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let a = "alice-id";
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

fn valid_digest(fill: char) -> String {
    format!("SHA-256:{}", fill.to_string().repeat(42) + "A")
}

/// Index a commit of `id` whose czd, blob hash and state root are the given
/// shared values.
fn sharing_commit(id: &str, czd: &str, blob_seed: u8, sr: &str) -> IndexableCommit {
    let mut c = make_commit(id, 0, 1000);
    let blob = crate::blob::Blake3Hash::from_bytes([blob_seed; 32]);
    c.blob_hashes = vec![blob];
    c.cozies[0].blob_hash = blob;
    c.cozies[0].czd = czd.to_string();
    c.srs = vec![sr.to_string()];
    c.ars = vec![sr.to_string()];
    c
}

fn holder_ids(holders: &[EntityRef]) -> Vec<PrincipalGenesis> {
    holders
        .iter()
        .filter_map(|h| h.principal_id.clone())
        .collect()
}

/// Backs "a replayed coz can neither block nor misattribute" at the index
/// seam, for every backend. SPEC 7.6 lets principals that share keys reuse a
/// coz, and two principals can honestly reach the same state or auth root,
/// so a czd, a blob hash and an SR/AR each name every principal that holds
/// them: both commits are accepted and `resolve_digest_holders` returns both
/// holders, in canonical (principal id) order. Turns red if the second
/// commit is refused, or either holder is lost or overwritten.
pub async fn digest_holders_shared_digest_names_every_holder<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let (czd, sr) = (valid_digest('A'), valid_digest('C'));
    for id in ["bob-id", "alice-id"] {
        indexer
            .index_commit(&sharing_commit(id, &czd, 7, &sr), &token)
            .await
            .expect("a commit sharing a coz and roots with another principal");
    }
    // The canonical order is the order of the ids, not of their names.
    let mut want = vec![pid("alice-id"), pid("bob-id")];
    want.sort_unstable();
    for digest in [czd.clone(), sr.clone()] {
        let d: TaggedDigest = digest.parse().unwrap();
        let holders = indexer.resolve_digest_holders(&d).await.unwrap();
        assert_eq!(holder_ids(&holders), want, "holders of {digest}");
    }
    let blob = crate::blob::Blake3Hash::from_bytes([7; 32]);
    assert!(indexer.is_blob_indexed(&blob).await.unwrap());
}

/// Backs "the index is a function of the blobs": indexing the same commits
/// in either order gives the same holders for every digest, so a shuffled
/// rebuild cannot change what a digest resolves to. Turns red if the order
/// of arrival shows in the holders.
pub async fn digest_holders_do_not_depend_on_arrival_order<I: Indexer + IndexerWrite>(
    forward: &I,
    backward: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let (czd, sr) = (valid_digest('A'), valid_digest('C'));
    let commits = [
        sharing_commit("alice-id", &czd, 7, &sr),
        sharing_commit("bob-id", &czd, 7, &sr),
    ];
    for c in &commits {
        forward.index_commit(c, &token).await.unwrap();
    }
    for c in commits.iter().rev() {
        backward.index_commit(c, &token).await.unwrap();
    }
    for digest in [czd, sr] {
        let d: TaggedDigest = digest.parse().unwrap();
        assert_eq!(
            forward.resolve_digest_holders(&d).await.unwrap(),
            backward.resolve_digest_holders(&d).await.unwrap(),
            "holders of {digest} depend on arrival order"
        );
        assert_eq!(
            forward.resolve_digest(&d).await.unwrap(),
            backward.resolve_digest(&d).await.unwrap(),
            "the single answer for {digest} depends on arrival order"
        );
    }
}

/// Backs "an indexer's idempotency key is the commit's chain position"
/// (`(principal_id, sequence)`, I2: one writer, one linear chain), for every
/// backend. Replaying the SAME commit is a no-op; a DIFFERENT commit at an
/// already-indexed position is fork evidence and is refused with
/// [`IndexerError::Consistency`], leaving the chain and tip as they were.
/// Turns red on a backend that keys on commit id alone (it appends a second
/// entry at the same sequence) or one that silently ignores the rival.
pub async fn index_commit_idempotency_is_keyed_by_chain_position<I: Indexer + IndexerWrite>(
    indexer: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let first = make_commit("alice", 0, 1000);
    let mut rival = make_commit("alice", 0, 2000);
    rival.commit_ids = vec!["SHA-256:commit-rival".to_string()];
    indexer.index_commit(&first, &token).await.unwrap();
    indexer
        .index_commit(&first, &token)
        .await
        .expect("a replay is a no-op");
    let refused = indexer.index_commit(&rival, &token).await;
    assert!(
        matches!(refused, Err(IndexerError::Consistency(_))),
        "a rival commit at an indexed position is fork evidence: {refused:?}"
    );

    let chain = indexer
        .get_commit_chain(&pid("alice"), None, None)
        .await
        .unwrap();
    assert_eq!(chain.len(), 1, "one chain position, one entry: {chain:?}");
    assert_eq!(chain[0].commit_id, "SHA-256:commit-alice-0");
    let tip = indexer.get_tip(&pid("alice")).await.unwrap().unwrap();
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.last_updated, 1000, "a rival position moved the tip");
}

/// A commit of `id` at `seq` whose state root is the shared `sr`.
fn state_root_commit(id: &str, seq: u64, sr: &str) -> IndexableCommit {
    let mut c = make_commit(id, seq, 1000 + seq as i64);
    c.srs = vec![sr.to_string()];
    c
}

/// Backs "holders are an order-independent SET": a principal that repeats a
/// state root across commits is ONE holder (at its latest sequence), beside
/// every other principal holding it, and arrival order shows in neither the
/// membership nor the multiplicity. Turns red on a backend that appends a
/// holder per commit, or that keeps the first sequence it saw.
pub async fn digest_holders_are_a_duplicate_free_set<I: Indexer + IndexerWrite>(
    forward: &I,
    backward: &I,
) {
    let token = DeriveToken::for_conformance_tests();
    let sr = valid_digest('C');
    let commits = [
        state_root_commit("alice-id", 0, &sr),
        state_root_commit("alice-id", 1, &sr),
        state_root_commit("bob-id", 0, &sr),
    ];
    for c in &commits {
        forward.index_commit(c, &token).await.unwrap();
    }
    for c in commits.iter().rev() {
        backward.index_commit(c, &token).await.unwrap();
    }
    let d: TaggedDigest = sr.parse().unwrap();
    for (name, indexer) in [("forward", forward), ("backward", backward)] {
        let holders = indexer.resolve_digest_holders(&d).await.unwrap();
        let seen: Vec<_> = holders
            .iter()
            .filter_map(|h| Some((h.principal_id.clone()?, h.sequence)))
            .collect();
        let mut want = vec![(pid("alice-id"), Some(1)), (pid("bob-id"), Some(0))];
        want.sort_unstable();
        assert_eq!(seen, want, "{name} holders of the shared state root");
    }
}

/// Backs "[`IndexerWrite::replace_chain_from`] is the one operation that
/// re-points a canonical chain" (SPEC 15.8), for every backend. An ordinary
/// `index_commit` of a rival is still refused; a replacement swaps the
/// positions from `sequence` on, moves the tip, withdraws every digest the
/// replaced commits held (a repeated root falls back to the kept commit
/// that also holds it), and refuses a replacement that would leave a gap.
/// Turns red on a backend that lacks the operation, leaves a replaced
/// commit resolvable, or accepts a rival through `index_commit`.
pub async fn replace_chain_from_repoints_the_chain<I: Indexer + IndexerWrite>(indexer: &I) {
    let token = DeriveToken::for_conformance_tests();
    let sr = valid_digest('D');
    let gone = valid_digest('E');
    let mut held = [
        state_root_commit("alice", 0, &sr),
        state_root_commit("alice", 1, &sr),
        make_commit("alice", 2, 1002),
    ];
    held[2].prs = vec![gone.clone()];
    for c in &held {
        indexer.index_commit(c, &token).await.unwrap();
    }
    let rival = |seq: u64| {
        let mut c = make_commit("alice-rival", seq, 2000 + seq as i64);
        c.principal_id = pid("alice");
        c
    };
    let refused = indexer.index_commit(&rival(1), &token).await;
    assert!(
        matches!(refused, Err(IndexerError::Consistency(_))),
        "index_commit must still refuse a rival: {refused:?}"
    );

    for bad in [
        indexer
            .replace_chain_from(&pid("alice"), 4, &[rival(4)], &token)
            .await,
        indexer
            .replace_chain_from(&pid("alice"), 1, &[], &token)
            .await,
        indexer
            .replace_chain_from(&pid("alice"), 1, &[rival(2)], &token)
            .await,
    ] {
        assert!(matches!(bad, Err(IndexerError::Consistency(_))), "{bad:?}");
    }
    let unchanged = indexer.get_tip(&pid("alice")).await.unwrap().unwrap();
    assert_eq!(unchanged.commit_count, 3, "a refused replacement wrote");

    indexer
        .replace_chain_from(&pid("alice"), 1, &[rival(1), rival(2)], &token)
        .await
        .expect("replace");
    let ids: Vec<String> = indexer
        .get_commit_chain(&pid("alice"), None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.commit_id)
        .collect();
    assert_eq!(
        ids,
        [
            "SHA-256:commit-alice-0",
            "SHA-256:commit-alice-rival-1",
            "SHA-256:commit-alice-rival-2"
        ]
    );
    let tip = indexer.get_tip(&pid("alice")).await.unwrap().unwrap();
    assert_eq!(
        (tip.commit_id.as_str(), tip.commit_count, tip.last_updated),
        ("SHA-256:commit-alice-rival-2", 3, 2002)
    );
    let gone: TaggedDigest = gone.parse().unwrap();
    assert!(
        indexer
            .resolve_digest_holders(&gone)
            .await
            .unwrap()
            .is_empty(),
        "a replaced commit's root must not resolve"
    );
    let sr: TaggedDigest = sr.parse().unwrap();
    let holders = indexer.resolve_digest_holders(&sr).await.unwrap();
    assert_eq!(
        holders.iter().map(|h| h.sequence).collect::<Vec<_>>(),
        [Some(0)],
        "the repeated root falls back to the kept commit"
    );
}

/// Every function in this module on a fresh indexer from `fresh`, which
/// also returns a guard (a temp directory, say) held for the call. A
/// function added to this module is listed here, once, so no backend's
/// suite can leave it unwired.
pub async fn run_all<I: Indexer + IndexerWrite, G>(fresh: impl Fn() -> (I, G)) {
    index_commit_and_get_tip(&fresh().0).await;
    index_commit_with_absent_roots_reads_back_none(&fresh().0).await;
    get_tip_unknown_returns_none(&fresh().0).await;
    tip_updates_on_subsequent_commits(&fresh().0).await;
    index_commit_idempotent(&fresh().0).await;
    get_commit_chain_full(&fresh().0).await;
    get_commit_chain_range(&fresh().0).await;
    get_commit_chain_unknown_returns_empty(&fresh().0).await;
    resolve_digest_returns_none_for_unknown(&fresh().0).await;
    resolve_digest_returns_indexed_position(&fresh().0).await;
    indexed_blobs_tracked_in_commit_chain(&fresh().0).await;
    list_principals_returns_all(&fresh().0).await;
    principal_summary_tracks_creation_time(&fresh().0).await;
    new_indexer_methods(&fresh().0).await;
    alias_pg_variants_resolve_to_the_principal(&fresh().0).await;
    pg_established_marker_tracks_the_pg_commit(&fresh().0).await;
    alias_conflict_second_principal_is_refused(&fresh().0).await;
    alias_conflict_naming_another_principal_is_refused(&fresh().0).await;
    digest_conflict_same_principal_repeat_is_allowed(&fresh().0).await;
    digest_holders_shared_digest_names_every_holder(&fresh().0).await;
    index_commit_idempotency_is_keyed_by_chain_position(&fresh().0).await;
    replace_chain_from_repoints_the_chain(&fresh().0).await;
    // Compares two indexers fed in opposite orders.
    digest_holders_do_not_depend_on_arrival_order(&fresh().0, &fresh().0).await;
    // Compares two indexers fed in opposite orders.
    digest_holders_are_a_duplicate_free_set(&fresh().0, &fresh().0).await;
}
