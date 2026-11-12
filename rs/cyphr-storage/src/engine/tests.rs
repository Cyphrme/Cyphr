use super::*;
use crate::blob::MemoryBlobStore;
use crate::index::MemoryIndexer;

/// A bundle of `blobs`, each coz a transaction of its own: the raw shape
/// the index-path tests store, which never verify a commit.
pub(super) fn singles<B: AsRef<[u8]>>(blobs: &[B]) -> WireBundle {
    WireBundle {
        txs: blobs.iter().map(|b| vec![b.as_ref().to_vec()]).collect(),
        ..WireBundle::default()
    }
}

/// Build a test engine with memory backends.
fn test_engine() -> StorageEngine<MemoryBlobStore, MemoryIndexer> {
    StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
}

/// Build test metadata for a commit.
fn make_meta(principal_id: &str, seq: u64, timestamp: i64) -> IndexableCommit {
    let dummy_hash = crate::blob::Blake3Hash::from_bytes([0; 32]);
    IndexableCommit {
        pg: Vec::new(),
        principal_id: principal_id.to_string(),
        commit_ids: vec![format!("SHA-256:commit-{principal_id}-{seq}")],
        sequence: seq,
        pre: if seq == 0 {
            None
        } else {
            Some(format!("SHA-256:pr-{principal_id}-{}", seq - 1))
        },
        prs: vec![format!("SHA-256:pr-{principal_id}-{seq}")],
        srs: vec![format!("SHA-256:sr-{principal_id}-{seq}")],
        ars: vec![format!("SHA-256:ar-{principal_id}-{seq}")],
        crs: vec![format!("SHA-256:cr-{principal_id}-{seq}")],
        blob_hashes: vec![dummy_hash],
        cozies: vec![IndexableCoz {
            blob_hash: dummy_hash,
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

/// Backs the sync patch (user-visible: a peer pulls a principal's whole
/// chain): `get_patch` returns every commit's blobs in sequence order.
/// Unit: raw `ingest_commit` with placeholder blobs isolates the patch
/// assembly from signature work the signed end-to-end tests already do.
#[tokio::test]
async fn ingest_two_then_get_patch_full() {
    let engine = test_engine();

    let blob_0 = b"{\"pay\":{\"now\":1000},\"typ\":\"cyphr/key/create\"}";
    let blob_1 = b"{\"pay\":{\"now\":2000},\"typ\":\"cyphr/key/create\"}";

    engine
        .ingest_metadata(&singles(&[blob_0.as_slice()]), make_meta("alice", 0, 1000))
        .await
        .expect("first ingest");
    engine
        .ingest_metadata(&singles(&[blob_1.as_slice()]), make_meta("alice", 1, 2000))
        .await
        .expect("second ingest");

    let patch = engine
        .get_patch("alice", None, None)
        .await
        .expect("get_patch failed");

    assert_eq!(patch.principal_id, "alice");
    assert_eq!(patch.entries.len(), 2);

    // Verify blob content is fetched correctly.
    assert_eq!(patch.entries[0].bundle.txs, vec![vec![blob_0.to_vec()]]);
    assert_eq!(patch.entries[1].bundle.txs, vec![vec![blob_1.to_vec()]]);

    // Verify ordering.
    assert_eq!(patch.entries[0].commit.sequence, 0);
    assert_eq!(patch.entries[1].commit.sequence, 1);
}

/// REWRITE (not a mechanical signature patch): the range is now
/// digest-bounded (Zami #140), so this anchors on position 0's PR digest and
/// expects the same tail `Some(1)` used to select directly -- resuming
/// AFTER position 0, through `to = Some(3)`. `make_meta`'s default `prs`
/// value is a placeholder string, not a parseable `TaggedDigest`, so only
/// position 0's `prs` is overridden with a real, resolvable digest.
#[tokio::test]
async fn get_patch_with_range() {
    let engine = test_engine();

    let anchor: cyphr::state::TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
        .parse()
        .expect("parse anchor digest");

    for seq in 0..5u64 {
        let blob = format!("{{\"pay\":{{\"now\":{}}}}}", 1000 + seq);
        let mut meta = make_meta("alice", seq, 1000 + seq as i64);
        if seq == 0 {
            meta.prs = vec![anchor.to_string()];
        }
        engine
            .ingest_metadata(&singles(&[blob.as_bytes()]), meta)
            .await
            .expect("ingest");
    }

    let patch = engine
        .get_patch("alice", Some(&anchor), Some(3))
        .await
        .expect("get_patch");
    assert_eq!(patch.entries.len(), 3);
    assert_eq!(patch.entries[0].commit.sequence, 1);
    assert_eq!(patch.entries[2].commit.sequence, 3);
}

/// An anchor digest never indexed for ANY principal must refuse, not
/// silently degrade to a full resync (S3: an unrecognized anchor is not
/// evidence of a position, sequence zero least of all).
#[tokio::test]
async fn get_patch_unknown_anchor_is_not_found() {
    let engine = test_engine();
    engine
        .ingest_metadata(&singles(&[b"alice-genesis"]), make_meta("alice", 0, 1000))
        .await
        .expect("ingest");

    let unknown: cyphr::state::TaggedDigest = "SHA-256:U5XUZots-WmQVbUsBK4kVbRbz5IaYfuMYXXv_aqgWpc"
        .parse()
        .expect("parse anchor digest");

    let err = engine
        .get_patch("alice", Some(&unknown), None)
        .await
        .expect_err("an unrecognized anchor must be refused, not silently resolved");
    assert!(
        matches!(err, EngineError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
}

// ========================================================================
// Principal lifecycle tests
// ========================================================================

/// Load a golden fixture from the shared test vectors.
fn load_golden(category: &str, name: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/golden")
        .join(category)
        .join(format!("{name}.json"));
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {path:?}: {e}"))
}

/// Convert a golden fixture's genesis key JSON to a cyphr::Key.
fn golden_key_to_domain(gk: &serde_json::Value) -> cyphr::Key {
    use coz::Thumbprint;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let alg = gk["alg"].as_str().unwrap();
    let pub_b64 = gk["pub"].as_str().unwrap();
    let tmb_b64 = gk["tmb"].as_str().unwrap();

    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).unwrap();
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).unwrap();

    cyphr::Key::new(
        alg.to_string(),
        Thumbprint::from_bytes(tmb_bytes),
        pub_bytes,
    )
    .expect("key binds its tmb")
}

/// Build genesis from a golden fixture's genesis_keys array.
fn make_genesis(genesis_keys: &[serde_json::Value]) -> crate::Genesis {
    let keys: Vec<cyphr::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();
    if keys.len() == 1 {
        crate::Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        crate::Genesis::Disclosed(keys)
    }
}

/// Backs the empty-history case: an id with no indexed commits loads as the
/// genesis-only principal rather than failing. Unit: the end-to-end routes
/// never load an unindexed id.
#[tokio::test]
async fn load_principal_unknown_returns_genesis() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let engine = test_engine();

    // Load from a principal_id with no indexed commits.
    let principal = engine
        .load_principal("nonexistent", genesis)
        .await
        .expect("load should succeed with no commits");

    assert_eq!(principal.active_key_count(), 1, "should be genesis-only");
}

// ========================================================================
// submit_commit tests (validated write path)
// ========================================================================

/// A golden fixture's commit line as the wire bundle a client would push.
fn build_bundle(commit: &serde_json::Value) -> WireBundle {
    serde_json::from_value::<crate::CommitEntry>(commit.clone())
        .expect("fixture commit line")
        .bundle()
        .expect("fixture bundle")
}

/// Backs SPEC be0663f section 12 (a commit that does not verify is not
/// stored): a tampered signature is refused and no tip appears.
#[tokio::test]
async fn submit_commit_bad_signature_rejected() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();

    let engine = test_engine();
    let principal_id = genesis_principal_id(&make_genesis(genesis_keys)).unwrap();
    let principal_id = principal_id.as_str();

    // Build blobs from the first commit but tamper with the signature.
    let first_commit = &commits[0];
    let mut bundle = build_bundle(first_commit);

    // Tamper: flip a byte in the first coz's sig field.
    let mut tampered: serde_json::Value = serde_json::from_slice(&bundle.txs[0][0]).unwrap();
    if let Some(sig) = tampered.get("sig").and_then(|s| s.as_str()) {
        let mut sig_chars: Vec<char> = sig.chars().collect();
        if !sig_chars.is_empty() {
            // Flip the first character.
            sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        }
        let tampered_sig: String = sig_chars.into_iter().collect();
        tampered["sig"] = serde_json::Value::String(tampered_sig);
    }
    bundle.txs[0][0] = serde_json::to_vec(&tampered).unwrap();

    let genesis = make_genesis(genesis_keys);

    // Submission should fail — protocol error, not stored.
    let result = engine
        .submit_commit(principal_id, Some(genesis), &bundle)
        .await;
    assert!(result.is_err(), "tampered commit should be rejected");

    // Verify nothing was stored.
    let tip = engine.get_tip(principal_id).await.expect("get_tip failed");
    assert!(tip.is_none(), "no tip should exist after rejected submit");
}

/// Backs the write-path input boundary: a submission with no blobs is
/// refused.
#[tokio::test]
async fn submit_commit_empty_rejected() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();

    let engine = test_engine();
    let genesis = make_genesis(genesis_keys);

    let principal_id = genesis_principal_id(&genesis).unwrap();
    let result = engine
        .submit_commit(&principal_id, Some(genesis), &WireBundle::default())
        .await;
    assert!(result.is_err(), "empty blob list should be rejected");
}

// ========================================================================
// Durable ingest: crash-window closure + order retention
// ========================================================================

/// Crash simulated mid coz-blob loop, before the manifest itself is ever
/// written: a coz blob lands in the blob store directly (bypassing
/// `ingest_commit` entirely), with no manifest tying it to any commit.
///
/// This must resolve to full absence -- the orphaned blob is harmless,
/// content-addressed leftover data (never surfaced through the index),
/// not a half-formed commit.
/// Claim: `rebuild_index_from_scratch` discards the index before rebuilding,
/// so an entry no manifest backs does not survive it, and the returned count
/// is the number of manifests replayed. Turns red if the `clear` is dropped
/// (the orphan stays indexed). End-to-end scenario: yes, a stale index
/// healed through the public recovery entry point.
#[tokio::test]
async fn rebuild_from_scratch_drops_entries_no_manifest_backs() {
    let engine = test_engine();
    // A conformant principal (its genesis commit, SPEC 5.1): the scratch
    // rebuild replays every manifest and quarantines placeholder blobs.
    let pool = load_pool();
    let golden = pool.get("golden").expect("golden");
    let mut principal = cyphr::Principal::implicit(pool_key_to_domain(golden))
        .await
        .unwrap();
    let alice = principal.pr_tagged().unwrap();
    let blobs = test_fixtures::bundle::genesis_bundle(&mut principal, golden, &[], 1000)
        .await
        .unwrap();
    engine
        .submit_commit(&alice, None, &blobs)
        .await
        .expect("genesis commit");

    // An indexed commit with no manifest: what a corrupted or stale index
    // holds that the blob store cannot account for.
    engine
        .indexer()
        .index_commit(&make_meta("orphan", 0, 1000), &DeriveToken::new())
        .await
        .expect("index orphan");
    assert!(engine.indexer().get_tip("orphan").await.unwrap().is_some());

    let rebuilt = engine
        .rebuild_index_from_scratch()
        .await
        .expect("rebuild_index_from_scratch failed");

    assert_eq!(rebuilt, 1, "count must equal the manifests replayed");
    assert!(
        engine.indexer().get_tip("orphan").await.unwrap().is_none(),
        "an entry with no backing manifest must not survive a from-scratch rebuild"
    );
    assert!(
        engine.indexer().get_tip(&alice).await.unwrap().is_some(),
        "the manifest-backed principal must be rebuilt"
    );
}

// ========================================================================
// F40: multi-key genesis + second commit (StorageEngine::submit_commit's
// real replay-based reload path)
// ========================================================================

/// Load the shared test key pool (`tests/keys/pool.toml`).
fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

fn pool_key_to_domain(pk: &test_fixtures::PoolKey) -> cyphr::Key {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub base64");
    let tmb = pk.compute_tmb().expect("pool tmb");
    cyphr::Key::new(pk.alg.clone(), tmb, pub_bytes).expect("key binds its tmb")
}

/// Backs the KA1/D2 claim: `submit_commit` refuses any `principal_id` that
/// is not the id the genesis derives (SPEC §3.1), before touching storage.
/// Fails if `ensure_genesis_derived_id` is removed: the valid genesis commit
/// would then be accepted under the unrelated id and leave a tip behind.
#[tokio::test]
async fn submit_commit_refuses_id_not_derived_from_genesis() {
    let fixture = load_golden("mutations", "key_add_changes_state");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);
    let derived = genesis_principal_id(&genesis).unwrap();
    let wrong = "unrelated-principal-id";
    assert_ne!(wrong, derived);

    let bundle = build_bundle(&commits[0]);
    let engine = test_engine();

    let refused = engine
        .submit_commit(wrong, Some(genesis.clone()), &bundle)
        .await;
    assert!(
        matches!(refused, Err(EngineError::InvalidInput(_))),
        "an id not derived from the genesis must be refused as InvalidInput, got {refused:?}"
    );
    assert!(
        engine.get_tip(wrong).await.unwrap().is_none(),
        "refused submit must leave no commit chain under the wrong id"
    );
    assert!(
        engine.get_tip(&derived).await.unwrap().is_none(),
        "refused submit must leave no commit chain under the derived id"
    );

    // Same commit, derived id: succeeds, so the refusal was about the id.
    engine
        .submit_commit(&derived, Some(genesis), &bundle)
        .await
        .expect("the same commit under the genesis-derived id must be accepted");
    assert!(engine.get_tip(&derived).await.unwrap().is_some());
}

/// Claim: a commit whose PG alias another principal already holds is
/// refused before anything is written, so a refused push leaves no blob or
/// manifest behind and a fresh engine on the same blob store serves every
/// principal. A unit test: two principals claiming one PG cannot be built
/// from signed cozes. Turns red if the refusal comes after the manifest is
/// durable (the store then keeps a manifest every rebuild trips over).
#[tokio::test]
async fn alias_conflict_is_refused_before_anything_is_written() {
    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
    let pg = vec!["SHA-256:contested-pg".to_string()];

    let a0: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":1}}"];
    engine
        .ingest_metadata(&singles(&a0), make_meta("alice", 0, 1))
        .await
        .unwrap();
    let mut a1 = make_meta("alice", 1, 2);
    a1.pg = pg.clone();
    let a1b: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":2}}"];
    engine.ingest_metadata(&singles(&a1b), a1).await.unwrap();
    let b0: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":3}}"];
    engine
        .ingest_metadata(&singles(&b0), make_meta("bob", 0, 3))
        .await
        .unwrap();

    let stored = |store: &MemoryBlobStore| {
        let store = store.clone();
        async move { store.iter().await.unwrap().count() }
    };
    let before = stored(&blobs).await;
    let mut b1 = make_meta("bob", 1, 4);
    b1.pg = pg;
    let b1b: Vec<&[u8]> = vec![b"{\"pay\":{\"now\":4}}"];
    let err = engine
        .ingest_metadata(&singles(&b1b), b1)
        .await
        .expect_err("alias held by alice");
    assert!(
        matches!(
            err,
            EngineError::Indexer(crate::index::IndexerError::Conflict(_))
        ),
        "{err:?}"
    );
    assert_eq!(
        stored(&blobs).await,
        before,
        "a refused commit wrote to the blob store"
    );

    let reopened = StorageEngine::new(blobs, MemoryIndexer::new());
    for who in ["alice", "bob"] {
        let tip = reopened
            .get_tip(who)
            .await
            .expect("a fresh engine heals")
            .expect("served");
        assert_eq!(tip.principal_id, who);
    }
}

/// Claim: two manifests contesting one PG alias do not fail the rebuild:
/// the earlier in canonical order (sequence, then principal id) keeps the
/// alias and the other is quarantined as a conflict, whatever order the
/// manifests were written in. A unit test: the contest cannot be built from
/// signed cozes, and `store_blobs_and_manifest` is the only way to write
/// both manifests past the ingest-time check. Turns red if a contested
/// alias aborts the rebuild or the winner depends on write order.
#[tokio::test]
async fn rebuild_quarantines_a_contested_pg_alias() {
    use super::{QuarantineReason, QuarantinedManifest};
    let pg = vec!["SHA-256:contested-pg".to_string()];
    let mut reports = Vec::new();
    for order in [["alice", "bob"], ["bob", "alice"]] {
        let engine = test_engine();
        for (i, who) in order.iter().enumerate() {
            let blob = format!("{{\"pay\":{{\"now\":{i}}}}}");
            let mut meta = make_meta(who, 0, 10);
            meta.pg = pg.clone();
            engine
                .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), meta, None)
                .await
                .unwrap();
        }
        let report = engine
            .rebuild_index_with_report()
            .await
            .expect("rebuild survives");
        assert_eq!(report.indexed, 1);
        let q: Vec<&QuarantinedManifest> = report.quarantined.iter().collect();
        assert_eq!(q.len(), 1, "{report:?}");
        assert_eq!(q[0].principal_id.as_deref(), Some("bob"));
        assert!(matches!(q[0].reason, QuarantineReason::Conflict(_)));
        reports.push(
            engine
                .indexer()
                .get_tip("SHA-256:contested-pg")
                .await
                .unwrap()
                .map(|t| t.principal_id),
        );
    }
    assert_eq!(reports[0], Some("alice".to_string()));
    assert_eq!(
        reports[0], reports[1],
        "the alias winner depends on write order"
    );
}

/// Claim: whatever the reason a manifest is quarantined, the indexed chain
/// of its principal is a gapless prefix: here seq 1 names a blob the store
/// lacks, so seq 2 must be left out too and the next honest commit still
/// lands at seq 1's successor-free position (the chain length). Turns red if
/// the chain comes out `[0, 2]`.
#[tokio::test]
async fn rebuild_indexes_a_gapless_prefix_when_a_manifest_is_unsupported() {
    use super::QuarantineReason;
    let engine = test_engine();
    for (seq, now) in [(0u64, 1), (2, 3)] {
        let blob = format!("{{\"pay\":{{\"now\":{now}}}}}");
        engine
            .store_blobs_and_manifest(
                &singles(&[blob.as_bytes()]),
                make_meta("alice", seq, now),
                None,
            )
            .await
            .unwrap();
    }
    let mut lost = make_meta("alice", 1, 2);
    let gone = crate::blob::Blake3Hash::from_bytes([0x5a; 32]);
    lost.blob_hashes = vec![gone];
    lost.cozies[0].blob_hash = gone;
    let mut bytes = COMMIT_MANIFEST_PREFIX.to_vec();
    serde_json::to_writer(
        &mut bytes,
        &CommitManifest {
            kind: COMMIT_MANIFEST_KIND.into(),
            commit: lost,
            shape: Shape {
                actions: 0,
                txs: vec![1],
            },
            seen: None,
        },
    )
    .unwrap();
    engine.blob_store().put(&bytes).await.unwrap();

    let report = engine
        .rebuild_index_with_report()
        .await
        .expect("rebuild survives");
    let chain = engine
        .indexer()
        .get_commit_chain("alice", None, None)
        .await
        .unwrap();
    let seqs: Vec<u64> = chain.iter().map(|c| c.sequence).collect();
    assert_eq!(
        seqs,
        vec![0],
        "the chain must be a gapless prefix, got {seqs:?}"
    );
    assert_eq!(report.quarantined.len(), 2, "{report:?}");
    assert!(
        report
            .quarantined
            .iter()
            .any(|q| matches!(q.reason, QuarantineReason::Orphaned(_)))
    );
}

/// Claim: two manifests at one chain position never fail the rebuild: the
/// one the later commit's `pre` extends is canonical, the rival is kept as
/// a retained branch (it forks the canonical parent), and the chain stays
/// whole. Turns red if the rival's `Consistency` error aborts the rebuild
/// (it would wedge `ensure_healed` on every start), the rival displaces the
/// extended commit, or the rival is dropped. A unit test: a rival manifest
/// cannot be built from signed cozes, and `store_blobs_and_manifest` is the
/// only way to write both past ingest.
#[tokio::test]
async fn rebuild_keeps_a_rival_manifest_at_one_position_as_a_branch() {
    let engine = test_engine();
    for (seq, now) in [(0u64, 1), (1, 2), (2, 3)] {
        let blob = format!("{{\"pay\":{{\"now\":{now}}}}}");
        engine
            .store_blobs_and_manifest(
                &singles(&[blob.as_bytes()]),
                make_meta("alice", seq, now),
                None,
            )
            .await
            .unwrap();
    }
    let mut rival = make_meta("alice", 1, 9);
    rival.commit_ids = vec!["SHA-256:commit-alice-rival".to_string()];
    rival.prs = vec!["SHA-256:pr-alice-rival".to_string()];
    engine
        .store_blobs_and_manifest(&singles(&[b"{\"pay\":{\"now\":9}}"]), rival, None)
        .await
        .unwrap();

    let report = engine
        .rebuild_index_with_report()
        .await
        .expect("a rival manifest must not fail the rebuild");
    assert_eq!(report.quarantined, [], "{report:?}");
    let chain = engine
        .indexer()
        .get_commit_chain("alice", None, None)
        .await
        .unwrap();
    let ids: Vec<&str> = chain.iter().map(|c| c.commit_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "SHA-256:commit-alice-0",
            "SHA-256:commit-alice-1",
            "SHA-256:commit-alice-2"
        ]
    );
    let held = engine.branches.lock().unwrap().get("alice").cloned();
    let rivals: Vec<String> = held.into_iter().flatten().map(|r| r.tip.tip).collect();
    assert_eq!(rivals, ["SHA-256:commit-alice-rival"]);
}

/// A store of alice's commits 0, 1 and 2 plus `rivals` at position 1, its
/// rebuild report, and the commit ids it serves.
async fn rebuild_with_rivals(rivals: Vec<IndexableCommit>) -> (super::RebuildReport, Vec<String>) {
    let engine = test_engine();
    for (seq, now) in [(0u64, 1), (1, 2), (2, 3)] {
        let blob = format!("{{\"pay\":{{\"now\":{now}}}}}");
        engine
            .store_blobs_and_manifest(
                &singles(&[blob.as_bytes()]),
                make_meta("alice", seq, now),
                None,
            )
            .await
            .unwrap();
    }
    for rival in rivals {
        let blob = format!("{{\"pay\":{{\"now\":{}}}}}", rival.timestamp);
        engine
            .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), rival, None)
            .await
            .unwrap();
    }
    let report = engine.rebuild_index_with_report().await.expect("rebuild");
    let chain = engine
        .indexer()
        .get_commit_chain("alice", None, None)
        .await
        .unwrap();
    (report, chain.into_iter().map(|c| c.commit_id).collect())
}

/// A rival commit manifest at position 1 named `n`, extending commit 0.
fn rival(n: i64) -> IndexableCommit {
    let mut r = make_meta("alice", 1, 10 + n);
    r.commit_ids = vec![format!("SHA-256:commit-alice-rival-{n}")];
    r.prs = vec![format!("SHA-256:pr-alice-rival-{n}")];
    r
}

/// The quarantine reasons of a rebuild report.
fn reasons(report: &super::RebuildReport) -> Vec<&super::QuarantineReason> {
    report.quarantined.iter().map(|q| &q.reason).collect()
}

const ALICE_CHAIN: [&str; 3] = [
    "SHA-256:commit-alice-0",
    "SHA-256:commit-alice-1",
    "SHA-256:commit-alice-2",
];

/// Claim: a valid commit manifest whose `pre` is a held commit but which
/// lost the canonical walk and finds no retention slot (its key has kept
/// [`super::BRANCH_PER_KEY`] rivals) is quarantined as fork evidence, the
/// kind a verification pass exempts. Turns red if it is reported as any
/// other kind (a verification failure). A unit test: rival manifests
/// cannot be built from signed cozes, and `store_blobs_and_manifest` is the
/// only way to write them past ingest.
#[tokio::test]
async fn rebuild_reports_a_rival_past_its_slots_as_fork() {
    use super::QuarantineReason;
    let (report, chain) = rebuild_with_rivals((0..3).map(rival).collect()).await;
    assert_eq!(chain, ALICE_CHAIN);
    assert!(
        matches!(reasons(&report)[..], [QuarantineReason::Fork(_)]),
        "{report:?}"
    );
}

/// Claim: a commit manifest whose `pre` names no held commit is
/// quarantined as orphaned. Turns red if it is reported as a fork (an
/// exempt kind) or kept. Unit, for the reason above.
#[tokio::test]
async fn rebuild_reports_a_rival_with_no_predecessor_as_orphaned() {
    use super::QuarantineReason;
    let mut orphan = rival(0);
    orphan.pre = Some("SHA-256:pr-nowhere".to_string());
    let (report, chain) = rebuild_with_rivals(vec![orphan]).await;
    assert_eq!(chain, ALICE_CHAIN);
    assert!(
        matches!(reasons(&report)[..], [QuarantineReason::Orphaned(_)]),
        "{report:?}"
    );
}

/// Claim: a second manifest of the canonical commit at its own position
/// (same commit, different record) is quarantined as a conflict, never
/// kept as a branch of itself. Turns red if it is kept, or reported as a
/// fork. Unit, for the reason above.
#[tokio::test]
async fn rebuild_reports_a_second_record_of_the_canonical_commit_as_conflict() {
    use super::QuarantineReason;
    let (report, chain) = rebuild_with_rivals(vec![make_meta("alice", 1, 99)]).await;
    assert_eq!(chain, ALICE_CHAIN);
    assert!(
        matches!(reasons(&report)[..], [QuarantineReason::Conflict(_)]),
        "{report:?}"
    );
}

fn pool_for_keys() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).unwrap()
}

/// A signed-looking coz of `typ` by pool key `signer` naming pool key `who`
/// by its `id`, with `sidecar` as an unsigned `key` member on the coz
/// (absent when `None`). `canonical_bundle` never checks the signature, so
/// a placeholder is enough.
fn coz_naming(typ: &str, signer: &str, who: &str, sidecar: Option<serde_json::Value>) -> Vec<u8> {
    let pool = pool_for_keys();
    let s = pool.get(signer).unwrap();
    let mut coz = serde_json::json!({
        "pay": {"alg": s.alg, "id": pool.get(who).unwrap().compute_tmb_b64().unwrap(),
                "now": 1, "tmb": s.compute_tmb_b64().unwrap(), "typ": typ},
        "sig": "AAAA",
    });
    if let Some(k) = sidecar {
        coz["key"] = k;
    }
    serde_json::to_vec(&coz).unwrap()
}

fn key_json_of(who: &str) -> serde_json::Value {
    let pool = pool_for_keys();
    let k = pool.get(who).unwrap();
    serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.compute_tmb_b64().unwrap()})
}

/// A one-transaction bundle of `coz` whose `keys` are `keys` (JSON, read
/// through the wire's own parse, so unsigned members a sender adds to an
/// entry are exercised).
fn bundle_with_keys(coz: Vec<u8>, keys: &[serde_json::Value]) -> WireBundle {
    let mut bundle: WireBundle =
        serde_json::from_value(serde_json::json!({ "keys": keys })).expect("keys parse");
    bundle.txs = vec![vec![coz]];
    bundle
}

/// Claim: of a pushed bundle's `keys` (SPEC 4.6.2), canonicalization keeps
/// exactly the entries a key-introducing coz names, judged by the protocol
/// predicate (the typ's authority-qualified suffix), never by substring,
/// and no coz keeps a `key` member of its own. A `commit/create` introduces
/// no key (a genesis is read only from its commit's `key/create`s, SPEC
/// 5.1), and an application typ that merely contains `/commit/create` is an
/// ordinary coz: neither keeps the entry its `id` names, and two bundles
/// differing only in that entry, or in a `key` member on the coz, store as
/// the same bundle. A unit test: the engine's action classifier is
/// substring-based, so such a typ cannot be pushed end to end. Turns red if
/// an entry is kept for either, or a coz keeps a `key` member.
#[test]
fn canonical_key_is_kept_only_on_a_key_introducing_coz() {
    let kept = |typ: &str, who: &str| {
        let pushed = bundle_with_keys(
            coz_naming(typ, "alice", who, Some(key_json_of(who))),
            &[key_json_of(who)],
        );
        let canonical = canonical_bundle(&pushed).expect("canonical");
        let coz: serde_json::Value = serde_json::from_slice(&canonical.txs[0][0]).unwrap();
        assert!(coz.get("key").is_none(), "{typ}: a coz kept a key member");
        !canonical.keys.is_empty()
    };
    assert!(
        !kept("cyphr.me/cyphr/commit/create", "bob"),
        "a commit/create introduces no key, so keeps none"
    );
    assert!(
        kept("cyphr.me/cyphr/key/create", "golden"),
        "a key-introducing coz keeps the key it names"
    );
    assert!(
        !kept("example.com/repo/commit/create", "bob"),
        "an application typ is not a carrier"
    );
    let app = |who: &str| {
        canonical_bundle(&bundle_with_keys(
            coz_naming(
                "example.com/repo/commit/create",
                "alice",
                "bob",
                Some(key_json_of(who)),
            ),
            &[key_json_of(who)],
        ))
        .unwrap()
    };
    assert_eq!(
        app("alice"),
        app("golden"),
        "two copies differing only in key material must be one bundle",
    );
}

/// No regression file: tests must not write to the tree. 16 cases: the
/// input space is a few unsigned-member shapes, and each case signs several
/// bundles (256 cases cost ~160 s in a debug build).
fn no_regression_file() -> proptest::prelude::ProptestConfig {
    proptest::prelude::ProptestConfig {
        cases: 16,
        failure_persistence: None,
        ..proptest::prelude::ProptestConfig::default()
    }
}

proptest::proptest! {
    #![proptest_config(no_regression_file())]
    /// Property: whatever unsigned members a replayer or relayer attaches to
    /// a bundle's `keys` entry (a `tag`, a `now`, any extra member, any
    /// member order), `canonical_bundle` returns the same bundle, for every
    /// coz kind that introduces the key (key/create, key/replace). For kinds
    /// that introduce none (an action, key/delete, commit/create), the
    /// output equals the output with no key at all. One czd, one blob, one
    /// stored key. Turns red if any unsigned entry member, or a key for a
    /// kind that introduces none, survives.
    #[test]
    fn canonical_coz_is_independent_of_the_unsigned_sidecar(
        tag in proptest::option::of("[ -~]{0,12}"),
        now in proptest::option::of(proptest::prelude::any::<i64>()),
        extra in proptest::option::of("[a-z]{1,8}"),
        reversed in proptest::prelude::any::<bool>(),
    ) {
        let vary = |base: serde_json::Value| {
            let mut m = serde_json::Map::new();
            let mut entries: Vec<(String, serde_json::Value)> =
                base.as_object().unwrap().clone().into_iter().collect();
            if let Some(t) = &tag { entries.push(("tag".into(), t.clone().into())); }
            if let Some(n) = now { entries.push(("now".into(), n.into())); }
            if let Some(x) = &extra { entries.push((format!("x-{x}"), x.clone().into())); }
            if reversed { entries.reverse(); }
            for (k, v) in entries { m.insert(k, v); }
            serde_json::Value::Object(m)
        };
        // Kinds that keep the key: the key is the introduced one.
        for (typ, signer, shown) in [
            ("cyphr.me/cyphr/key/create", "alice", "golden"),
            ("cyphr.me/cyphr/key/replace", "alice", "golden"),
        ] {
            let coz = || coz_naming(typ, signer, shown, None);
            let plain =
                canonical_bundle(&bundle_with_keys(coz(), &[key_json_of(shown)])).unwrap();
            let varied =
                canonical_bundle(&bundle_with_keys(coz(), &[vary(key_json_of(shown))])).unwrap();
            proptest::prop_assert_eq!(&plain, &varied, "{} key entry changed the bundle", typ);
            proptest::prop_assert_eq!(plain.keys.len(), 1);
        }
        // Kinds that keep no key.
        for (typ, signer) in [
            ("cyphr.me/action", "alice"),
            ("cyphr.me/cyphr/key/delete", "alice"),
            ("cyphr.me/cyphr/commit/create", "alice"),
        ] {
            let coz = || coz_naming(typ, signer, "bob", None);
            let none = canonical_bundle(&bundle_with_keys(coz(), &[])).unwrap();
            let foreign =
                canonical_bundle(&bundle_with_keys(coz(), &[vary(key_json_of("bob"))])).unwrap();
            proptest::prop_assert_eq!(&none, &foreign, "{} kept a foreign key", typ);
        }
    }
}
mod pgk;

/// Claim: a rival whose parent is a disqualified rival is itself no
/// participant, so two children of a rival signed by a revoked key do not
/// put the principal in Error. Turns red if the participant parent check is
/// dropped (both children then count as a fork over one `pre`). A unit test
/// on the pure fork rule: the scenario needs a revoked key's rival and two
/// children of it, which no honest write path stores.
#[test]
fn children_of_a_disqualified_rival_are_not_a_fork() {
    let held = |sequence: u64, id: &str, pre: Option<&str>, signer: &str, canonical: bool| Held {
        sequence,
        id: id.into(),
        pre: pre.map(Into::into),
        pr: format!("pr-{id}"),
        signed: vec![signer.into()],
        canonical,
        removes: Vec::new(),
    };
    let commits = [
        held(0, "c0", None, "ok", true),
        held(1, "c1", Some("pr-c0"), "ok", true),
        held(1, "r1", Some("pr-c0"), "revoked", false),
        held(2, "r2a", Some("pr-r1"), "ok", false),
        held(2, "r2b", Some("pr-r1"), "ok", false),
    ];
    let revoked: Revoked = [(
        "revoked".to_string(),
        Death {
            now: 0,
            record: [0; 32],
        },
    )]
    .into_iter()
    .collect();
    assert!(
        !in_error(&commits, &revoked),
        "two children of a disqualified rival counted as a fork"
    );
    // Control: with the key not revoked, r1 participates and so do its
    // children, which fork over one pre.
    assert!(in_error(&commits, &Revoked::new()));
}
