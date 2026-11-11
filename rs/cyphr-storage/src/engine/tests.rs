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
        crate::Genesis::Explicit(keys)
    }
}

/// Ingest a golden fixture's commits into the engine through the raw index
/// path: each commit line's bundle (SPEC 4.6.2) as stored, its keys as the
/// commit's index keys.
async fn ingest_fixture(
    engine: &StorageEngine<MemoryBlobStore, MemoryIndexer>,
    principal_id: &str,
    commits: &[serde_json::Value],
) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    for (seq, commit) in commits.iter().enumerate() {
        let bundle = build_bundle(commit);
        let mut cozies = Vec::new();
        let mut last_now = 0;

        for blob in bundle.cozies() {
            let coz: serde_json::Value = serde_json::from_slice(blob).unwrap();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("").to_string();
            let pay = coz.get("pay").unwrap();
            let sig_b64 = coz.get("sig").unwrap().as_str().unwrap();
            let sig = Base64UrlUnpadded::decode_vec(sig_b64).unwrap();

            let mut pay_val = pay.clone();
            crate::import::canonicalize_value(&mut pay_val);
            let pay_json = serde_json::to_vec(&pay_val).unwrap();
            let alg = pay.get("alg").unwrap().as_str().unwrap().to_string();

            let cad = coz::canonical_hash_for_alg(&pay_json, &alg, None).unwrap();
            let czd_bytes = coz::czd_for_alg(&cad, &sig, &alg).unwrap();

            let source_alg =
                cyphr::state::hash_alg_from_str(&alg).expect("pool alg is in the table");
            let tagged = cyphr::state::TaggedCzd::new(&czd_bytes, source_alg);
            let converted = tagged.convert_to(source_alg);
            let czd = format!(
                "{source_alg}:{}",
                Base64UrlUnpadded::encode_string(&converted)
            );

            let tmb = pay
                .get("tmb")
                .unwrap_or(&serde_json::Value::Null)
                .as_str()
                .unwrap_or("")
                .to_string();
            let now = pay.get("now").unwrap().as_i64().unwrap();
            last_now = now;
            let payload = Some(serde_json::to_string(&pay_val).unwrap());

            cozies.push(IndexableCoz {
                blob_hash: crate::blob::Blake3Hash::from_bytes([0; 32]),
                czd,
                typ,
                tmb,
                alg,
                now,
                payload,
            });
        }
        let extracted_keys = bundle
            .keys
            .iter()
            .map(|k| crate::index::PublicKeyInfo {
                thumbprint: k.tmb.clone(),
                algorithm: k.alg.clone(),
                public_key: k.pub_key.clone(),
            })
            .collect();

        let pre = if seq == 0 {
            None
        } else {
            Some(commits[seq - 1]["pr"].as_str().unwrap_or("").to_string())
        };

        let meta = IndexableCommit {
            pg: Vec::new(),
            principal_id: principal_id.to_string(),
            commit_ids: vec![
                commit["commit_id"]
                    .as_str()
                    .unwrap_or(&format!("commit-{seq}"))
                    .to_string(),
            ],
            sequence: seq as u64,
            pre,
            prs: vec![commit["pr"].as_str().unwrap_or("").to_string()],
            srs: vec![commit["sr"].as_str().unwrap_or("").to_string()],
            ars: vec![commit["ar"].as_str().unwrap_or("").to_string()],
            // Golden fixtures predate CR tracking; ingest_fixture is a raw
            // index-population helper, not a source of truth for CR.
            crs: Vec::new(),
            blob_hashes: Vec::new(),
            cozies,
            timestamp: last_now,
            keys: extracted_keys,
        };

        engine
            .ingest_metadata(&bundle, meta)
            .await
            .unwrap_or_else(|e| panic!("ingest commit {seq} failed: {e}"));
    }
}

/// Backs replay of a stored chain into the same principal state (SPEC
/// be0663f section 2.3.2, state derives from the commit chain): a multi-commit
/// fixture ingested then loaded has the fixture's key count.
#[tokio::test]
async fn load_principal_multi_commit_replay() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = "seq-principal";

    ingest_fixture(&engine, principal_id, commits).await;

    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch after multi-commit replay"
        );
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

/// F36: `submit_commit`'s action-only branch (a bundle with no
/// transaction-typed cozy, only actions) must report `manifest_hash: None`
/// -- no commit was formed, so there is genuinely no manifest to name, not
/// a zero-hash sentinel in a field whose type otherwise implies a real
/// content address.
#[tokio::test]
async fn submit_commit_action_only_bundle_has_no_manifest_hash() {
    let fixture = load_golden("actions", "action_alone_leaves_pr");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    assert_eq!(
        commits.len(),
        1,
        "fixture must be a single action-only bundle"
    );

    let engine = test_engine();
    let genesis = make_genesis(genesis_keys);
    let principal_id = genesis_principal_id(&genesis).unwrap();
    let principal_id = principal_id.as_str();

    let bundle = build_bundle(&commits[0]);
    assert!(bundle.txs.is_empty(), "premise: an action-only line");

    let result = engine
        .submit_commit(principal_id, Some(genesis), &bundle)
        .await
        .expect("submit_commit failed for action-only bundle");

    assert_eq!(
        result.manifest_hash, None,
        "action-only bundle forms no commit, so it must report no manifest hash"
    );
    assert_eq!(result.blob_hashes.len(), 1);

    // No commit was indexed -- an action-only bundle never advances tip.
    assert!(
        engine.get_tip(principal_id).await.unwrap().is_none(),
        "action-only bundle must not create an indexed commit"
    );
}

/// F29: a submitted blob whose pay is missing `typ` must be rejected
/// outright, not silently misclassified. Before the fix, engine/mod.rs's
/// hand-rolled extraction defaulted a missing `typ` to `""`, and
/// a transaction check on `""` is false -- so a coz that was actually a
/// mutation (e.g. a corrupted `key/create`) could be silently routed down
/// the action-only path instead of being rejected as malformed.
#[tokio::test]
async fn submit_commit_rejects_blob_missing_typ() {
    let fixture = load_golden("actions", "action_alone_leaves_pr");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let genesis = make_genesis(genesis_keys);

    let malformed = serde_json::json!({
        "pay": {
            "alg": "ES256",
            "tmb": genesis_keys[0]["tmb"],
            "now": 1000
            // "typ" deliberately omitted
        },
        "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });
    let bytes = serde_json::to_vec(&malformed).unwrap();

    let engine = test_engine();
    let principal_id = genesis_principal_id(&genesis).unwrap();
    let result = engine
        .submit_commit(
            &principal_id,
            Some(genesis),
            &WireBundle::actions(vec![bytes]),
        )
        .await;

    assert!(
        matches!(result, Err(EngineError::MalformedBlob(_))),
        "a blob missing 'typ' must be rejected as malformed, not silently misclassified as an \
         action, got {result:?}"
    );
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

/// Backs the engine's validated write path end to end: every commit of a
/// replay fixture submitted through `submit_commit` is counted in the tip and
/// loads back to the fixture's key count.
#[tokio::test]
async fn submit_then_load_round_trip() {
    let fixture = load_golden("mutations", "transaction_sequence_replay");
    let genesis_keys = fixture["genesis_keys"].as_array().unwrap();
    let commits = fixture["commits"].as_array().unwrap();
    let expected = &fixture["expected"];

    let engine = test_engine();
    let principal_id = genesis_principal_id(&make_genesis(genesis_keys)).unwrap();
    let principal_id = principal_id.as_str();

    // Submit all commits.
    for commit in commits {
        let genesis = make_genesis(genesis_keys);

        engine
            .submit_commit(principal_id, Some(genesis), &build_bundle(commit))
            .await
            .expect("submit_commit failed");
    }

    // Load and verify.
    let genesis = make_genesis(genesis_keys);
    let principal = engine
        .load_principal(principal_id, genesis)
        .await
        .expect("load_principal failed");

    if let Some(kc) = expected["key_count"].as_u64() {
        assert_eq!(
            principal.active_key_count(),
            kc as usize,
            "key_count mismatch in round-trip"
        );
    }

    // Verify sequence count.
    let tip = engine
        .get_tip(principal_id)
        .await
        .expect("get_tip failed")
        .expect("tip should exist");
    assert_eq!(tip.commit_count, commits.len() as u64);
}

// ========================================================================
// Durable ingest: crash-window closure + order retention
// ========================================================================

/// Crash simulated between `store_blobs_and_manifest`'s manifest write and
/// `ingest_commit`'s subsequent index write: the blobs and the durable
/// commit-manifest are stored, but the index was never written -- exactly
/// what a process crash after `ingest_commit`'s manifest `put` but before
/// its `indexer.index_commit` call would leave behind.
///
/// The commit must not be silently lost: `rebuild_index_from_manifests`
/// (called here in place of "the next engine open") must recover it in
/// full from the manifest alone, with no index entry ever pointing at a
/// missing blob in the meantime.
#[tokio::test]
async fn crash_between_manifest_and_index_write_is_recoverable() {
    let engine = test_engine();
    let blob = b"{\"pay\":{\"now\":1000}}";
    let meta = make_meta("alice", 0, 1000);

    let (commit, manifest_hash) = engine
        .store_blobs_and_manifest(&singles(&[blob.as_slice()]), meta)
        .await
        .expect("store_blobs_and_manifest failed");

    // Before recovery: no index entry exists at all -- not a partial one,
    // not one pointing at a missing blob. Full absence. Probed via the
    // raw indexer accessor, not `engine.get_tip()`: since this node
    // (S3-ingest-crash-recovery) wired an automatic heal into every
    // index-touching public method, `get_tip()` itself would now heal
    // this exact manifest on first call -- the raw accessor is the
    // documented escape hatch outside that guarantee, letting this test
    // still observe the genuinely pre-heal state.
    assert!(
        engine.indexer().get_tip("alice").await.unwrap().is_none(),
        "index must not have been written yet"
    );

    // The manifest itself is durably present in the blob store.
    assert!(
        engine
            .blob_store()
            .get(&manifest_hash)
            .await
            .unwrap()
            .is_some(),
        "commit manifest must be durably stored before the index write"
    );

    // "Reopen": scan the blob store for manifests and complete indexing.
    let recovered = engine
        .rebuild_index_from_manifests()
        .await
        .expect("rebuild_index_from_manifests failed");
    assert_eq!(recovered, 1, "exactly one manifest should be found");

    // After recovery: full presence, matching what a normal ingest_commit
    // call would have produced.
    let tip = engine
        .get_tip("alice")
        .await
        .unwrap()
        .expect("tip must exist after manifest-based recovery");
    assert_eq!(tip.commit_count, 1);
    assert_eq!(tip.pr, commit.prs[0]);

    // Idempotent: calling recovery again must not double-index.
    let recovered_again = engine.rebuild_index_from_manifests().await.unwrap();
    assert_eq!(
        recovered_again, 1,
        "manifest is still found, but re-indexing is a no-op"
    );
    let tip_again = engine.get_tip("alice").await.unwrap().unwrap();
    assert_eq!(
        tip_again.commit_count, 1,
        "re-running recovery must not duplicate the commit"
    );
}

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

/// Backs the crash-window rule (I1): a crash before the manifest write leaves
/// the commit fully absent from the index, never half indexed.
#[tokio::test]
async fn crash_before_manifest_write_leaves_commit_fully_absent() {
    let engine = test_engine();

    let orphan_hash = engine.blob_store().put(b"orphan-coz-blob").await.unwrap();

    let recovered = engine
        .rebuild_index_from_manifests()
        .await
        .expect("rebuild_index_from_manifests failed");
    assert_eq!(
        recovered, 0,
        "no manifest exists, so nothing should be indexed"
    );

    assert!(engine.get_tip("alice").await.unwrap().is_none());
    // The orphan blob is still retrievable (harmless leftover content) but
    // never claims to be part of any indexed commit.
    assert!(
        engine
            .blob_store()
            .get(&orphan_hash)
            .await
            .unwrap()
            .is_some()
    );
}

/// The commit's intra-commit transaction order must be readable directly
/// from its durable manifest, and must match the exact order `ingest_commit` was called with.
#[tokio::test]
async fn manifest_retains_ingest_order_without_search() {
    let engine = test_engine();
    let blob_a = b"tx-a-first";
    let blob_b = b"tx-b-second";
    let blob_c = b"tx-c-third";

    let mut meta = make_meta("alice", 0, 1000);
    // Three cozies, matching the three blobs positionally (make_meta only
    // seeds one; extend to match blobs.len()).
    meta.cozies = vec![
        meta.cozies[0].clone(),
        meta.cozies[0].clone(),
        meta.cozies[0].clone(),
    ];

    let result = engine
        .ingest_metadata(
            &singles(&[blob_a.as_slice(), blob_b.as_slice(), blob_c.as_slice()]),
            meta,
        )
        .await
        .expect("ingest failed");

    let expected_order = vec![
        blake3::hash(blob_a).as_bytes().to_vec(),
        blake3::hash(blob_b).as_bytes().to_vec(),
        blake3::hash(blob_c).as_bytes().to_vec(),
    ];

    // Read the manifest back directly from the blob store -- the same
    // mechanism `rebuild_index_from_manifests` uses.
    let manifest_bytes = engine
        .blob_store()
        .get(
            &result
                .manifest_hash
                .expect("ingest_commit always forms a manifest"),
        )
        .await
        .unwrap()
        .expect("manifest must be present in the blob store");
    let manifest: super::CommitManifest = serde_json::from_slice(
        manifest_bytes
            .strip_prefix(super::COMMIT_MANIFEST_PREFIX)
            .expect("a stored manifest carries the manifest keyspace prefix"),
    )
    .expect("manifest must deserialize");

    assert_eq!(manifest.kind, super::COMMIT_MANIFEST_KIND);
    let retained_order: Vec<Vec<u8>> = manifest
        .commit
        .blob_hashes
        .iter()
        .map(|h| h.as_bytes().to_vec())
        .collect();
    assert_eq!(
        retained_order, expected_order,
        "retained manifest order must match the exact ingest-time transaction sequence"
    );

    // The manifest also carries the commit's derived Auth Root -- the
    // arrow the retained order is verified against -- so a reader never
    // needs to re-derive it via search.
    let tip = engine.get_tip("alice").await.unwrap().unwrap();
    assert_eq!(manifest.commit.ars, tip.ar.into_iter().collect::<Vec<_>>());
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

/// The `"key"` JSON object a raw blob embeds for a key-introducing coz,
/// matching `key_value_to_entry`'s expected shape.
fn pool_key_json(pk: &test_fixtures::PoolKey) -> serde_json::Value {
    serde_json::json!({
        "alg": pk.alg,
        "pub": pk.pub_key,
        "tmb": pk.compute_tmb_b64().expect("pool tmb b64"),
    })
}

/// Sign an arbitrary (already-complete-except-for-signature) pay object
/// under `pk`, returning the canonical pay bytes and raw signature.
fn sign_pay(pk: &test_fixtures::PoolKey, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut pay = pay;
    pay.as_object_mut().expect("pay object").sort_keys();
    let pay_vec = serde_json::to_vec(&pay).expect("serialize pay");

    let prv_bytes = Base64UrlUnpadded::decode_vec(
        pk.prv
            .as_ref()
            .unwrap_or_else(|| panic!("pool key '{}' has no private key material", pk.name)),
    )
    .expect("pool prv base64");
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub base64");

    let (sig, _cad) = coz::sign_json(&pay_vec, &pk.alg, &prv_bytes, &pub_bytes).expect("sign_json");
    (pay_vec, sig)
}

/// Build a raw `{pay, sig}` blob (optionally embedding `"key"`) from
/// already-signed pay bytes and a raw signature.
fn raw_blob(pay_bytes: &[u8], sig: &[u8], key: Option<serde_json::Value>) -> Vec<u8> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pay_val: serde_json::Value = serde_json::from_slice(pay_bytes).expect("pay json");
    let mut obj = serde_json::Map::new();
    obj.insert("pay".to_string(), pay_val);
    obj.insert(
        "sig".to_string(),
        serde_json::json!(Base64UrlUnpadded::encode_string(sig)),
    );
    if let Some(k) = key {
        obj.insert("key".to_string(), k);
    }
    serde_json::to_vec(&serde_json::Value::Object(obj)).expect("serialize blob")
}

/// Extract the raw `{pay, sig}` bytes `submit_commit` expects for the
/// `n`th coz of `commit`'s commit-tx (the transaction half — mutations
/// plus the terminal `commit/create`), as actually signed.
fn commit_tx_raw_blob(commit: &cyphr::commit::Commit, n: usize) -> Vec<u8> {
    let vtx = &commit.commit_tx().0[n];
    let raw = vtx.raw();
    serde_json::to_vec(raw).expect("serialize raw coz json")
}

/// F40 regression: a genuinely fresh explicit multi-key genesis (2+ keys,
/// zero prior commits) must accept a second, ordinary commit signed on top
/// of it, through the real production path — `StorageEngine::submit_commit`,
/// which reconstructs the principal via a full replay (`load_principal`) on
/// *every* call rather than reusing one live in-memory instance. Every raw
/// blob submitted here is produced by a correctly-computing client
/// (`CommitScope::finalize_with_software` on its own independently-maintained
/// principal), so any failure below is a genuine server-side asymmetry, not
/// a malformed test fixture. No existing golden fixture or test exercises
/// an *established* (`principal/create`-finalized) multi-key genesis
/// through `submit_commit` a second time.
#[tokio::test]
async fn submit_commit_explicit_multi_key_genesis_second_commit_succeeds() {
    let pool = load_pool();
    let key_a = pool.get("golden").expect("pool key golden");
    let key_b = pool.get("alice").expect("pool key alice");
    let key_c = pool.get("bob").expect("pool key bob");

    let now = 1_700_000_000i64;
    let a_tmb_b64 = key_a.compute_tmb_b64().expect("golden tmb b64");
    let tmb_a = key_a.compute_tmb().expect("golden tmb");

    let genesis_domain_keys = vec![pool_key_to_domain(key_a), pool_key_to_domain(key_b)];
    let genesis = crate::Genesis::Explicit(genesis_domain_keys.clone());

    // Client-side principal: the sole source of truth for what a correctly
    // behaving signer computes as `pre`/arrow at each step. Never reloaded
    // via replay — mirrors a long-lived client session.
    let mut client = cyphr::Principal::implicit(genesis_domain_keys[0].clone())
        .await
        .expect("client genesis");
    let mut scope1 = client.begin_commit();
    use coz::base64ct::Encoding as _;
    let genesis_creates: Vec<Vec<u8>> = scope1
        .create_genesis_keys(
            &cyphr::signer::SoftwareSigner::new(
                &key_a.alg,
                &coz::base64ct::Base64UrlUnpadded::decode_vec(
                    key_a.prv.as_ref().expect("golden has prv"),
                )
                .expect("golden prv base64"),
                &coz::base64ct::Base64UrlUnpadded::decode_vec(&key_a.pub_key)
                    .expect("golden pub base64"),
                &tmb_a,
            ),
            &genesis_domain_keys[1..],
            now,
            "cyphr.me",
        )
        .await
        .expect("genesis key/creates (SPEC 7.7 Example 1)")
        .iter()
        .map(|c| serde_json::to_vec(c).expect("key/create blob"))
        .collect();
    // The future SR after every genesis key/create: the PG-to-be that
    // `principal/create`'s `id` carries (SPEC 5.1 step 3).
    let id_tagged = scope1.genesis_id().expect("genesis id");

    // ---- Commit #1: principal/create + commit/create, establishing PG. ----
    let pc_pay = serde_json::json!({
        "alg": key_a.alg,
        "id": &id_tagged,
        "now": now,
        "tmb": a_tmb_b64,
        "typ": "cyphr.me/cyphr/principal/create",
    });
    let (pc_pay_bytes, pc_sig) = sign_pay(key_a, pc_pay);
    let pc_blob = raw_blob(&pc_pay_bytes, &pc_sig, None);

    let pc_czd = {
        let cad = coz::canonical_hash_for_alg(&pc_pay_bytes, &key_a.alg, None).expect("cad");
        coz::czd_for_alg(&cad, &pc_sig, &key_a.alg).expect("czd")
    };
    scope1
        .verify_and_apply(&pc_pay_bytes, &pc_sig, pc_czd, None)
        .expect("principal/create should apply to a fresh multi-key genesis (client side)");

    let prv_a = {
        use coz::base64ct::Encoding;
        coz::base64ct::Base64UrlUnpadded::decode_vec(key_a.prv.as_ref().expect("golden has prv"))
            .expect("golden prv base64")
    };
    let pub_a = {
        use coz::base64ct::Encoding;
        coz::base64ct::Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("golden pub base64")
    };

    let commit1 = scope1
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&key_a.alg, &prv_a, &pub_a, &tmb_a),
            now + 1,
            "cyphr.me",
        )
        .await
        .expect("genesis commit should finalize (client side)");
    assert_eq!(
        commit1.len(),
        genesis_creates.len() + 2,
        "key/create per genesis key + principal/create + commit/create"
    );
    let cc1_blob = commit_tx_raw_blob(commit1, 0);

    assert!(
        client.pg().is_some(),
        "PG must be established after the genesis commit (client side)"
    );

    let engine = test_engine();
    // A genesis commit keys its principal by PG (SPEC 5.1).
    let principal_id = id_tagged.as_str();

    engine
        .submit_commit(
            principal_id,
            Some(genesis.clone()),
            &WireBundle {
                txs: genesis_creates
                    .iter()
                    .chain([&pc_blob, &cc1_blob])
                    .map(|b| vec![b.clone()])
                    .collect(),
                keys: genesis_domain_keys
                    .iter()
                    .map(crate::KeyEntry::of)
                    .collect(),
                ..WireBundle::default()
            },
        )
        .await
        .expect("genesis commit should submit through the real StorageEngine write path");

    // ---- Commit #2: an ordinary mutation signed on top of the Established genesis. ----
    let kc_pay = serde_json::json!({
        "alg": key_a.alg,
        "id": key_c.compute_tmb_b64().expect("bob tmb b64"),
        "now": now + 2,
        "tmb": a_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let (kc_pay_bytes, kc_sig) = sign_pay(key_a, kc_pay);
    let kc_blob = raw_blob(&kc_pay_bytes, &kc_sig, None);
    let kc_czd = {
        let cad = coz::canonical_hash_for_alg(&kc_pay_bytes, &key_a.alg, None).expect("cad");
        coz::czd_for_alg(&cad, &kc_sig, &key_a.alg).expect("czd")
    };

    let mut scope2 = client.begin_commit();
    scope2
        .verify_and_apply(
            &kc_pay_bytes,
            &kc_sig,
            kc_czd,
            Some(pool_key_to_domain(key_c)),
        )
        .expect("key/create mutation should apply to the second commit (client side)");
    let commit2 = scope2
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&key_a.alg, &prv_a, &pub_a, &tmb_a),
            now + 3,
            "cyphr.me",
        )
        .await
        .expect("second commit should finalize (client side)");
    let cc2_blob = commit_tx_raw_blob(commit2, 0);

    engine
        .submit_commit(
            principal_id,
            Some(genesis),
            &WireBundle {
                txs: vec![vec![kc_blob], vec![cc2_blob]],
                keys: vec![serde_json::from_value(pool_key_json(key_c)).expect("key entry")],
                ..WireBundle::default()
            },
        )
        .await
        .expect(
            "a second commit signed on top of a fresh multi-key established genesis must submit \
             without a state-root mismatch (F40)",
        );
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
                .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), meta)
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
            .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), make_meta("alice", seq, now))
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
            .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), make_meta("alice", seq, now))
            .await
            .unwrap();
    }
    let mut rival = make_meta("alice", 1, 9);
    rival.commit_ids = vec!["SHA-256:commit-alice-rival".to_string()];
    rival.prs = vec!["SHA-256:pr-alice-rival".to_string()];
    engine
        .store_blobs_and_manifest(&singles(&[b"{\"pay\":{\"now\":9}}"]), rival)
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
            .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), make_meta("alice", seq, now))
            .await
            .unwrap();
    }
    for rival in rivals {
        let blob = format!("{{\"pay\":{{\"now\":{}}}}}", rival.timestamp);
        engine
            .store_blobs_and_manifest(&singles(&[blob.as_bytes()]), rival)
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

/// No regression file: tests must not write to the tree.
fn no_regression_file() -> proptest::prelude::ProptestConfig {
    proptest::prelude::ProptestConfig {
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
