//! Engine-level manifest confusion (finding H1): the storage engine's own
//! contract, independent of the HTTP layer.
//!
//! Claim: `StorageEngine::submit_commit` stores caller-supplied coz blobs
//! raw in the blob store that also holds the engine's `CommitManifest`
//! blobs, and `rebuild_index_from_manifests` must never index a
//! caller-supplied blob as if it were a manifest. A coz's signature covers
//! only `pay`, so a validly signed coz can carry top-level `kind` and
//! `commit` members shaped like a manifest.
//!
//! Every ingest path that stores a caller blob raw is covered:
//! - the transaction path (`ingest_commit`'s blobs). The server's witness sync (`sync.rs`) calls
//!   this same `submit_commit`, so this test is also its test; a separate witness-sync test would
//!   re-run the identical engine code.
//! - the action-only path (`engine/mod.rs`, "Action-only bundle"), which stores blobs raw with no
//!   manifest at all.
//!
//! Fix-agnostic: each red test accepts `Ok` or `Err` from the crafted
//! submit and runs the rebuild and the index assertions either way, so it
//! turns green under "reject at ingest" and under "store but never
//! interpret as a manifest". Red tests are `#[ignore = "RED(H1F)"]` and
//! fail on an index assertion with `--ignored`.
//!
//! Run: `cargo test -p cyphr-storage --test manifest_confusion --
//! --include-ignored`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, MemoryBlobStore};
use cyphr_storage::engine::{StorageEngine, genesis_principal_id};
use cyphr_storage::index::{IndexableCommit, IndexableCoz, Indexer, MemoryIndexer};

const MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

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

fn genesis_of(fixture: &serde_json::Value) -> (Genesis, String) {
    let gk = &fixture["genesis_keys"][0];
    let key = cyphr::Key::new(
        gk["alg"].as_str().unwrap().to_string(),
        coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(gk["tmb"].as_str().unwrap()).unwrap()),
        Base64UrlUnpadded::decode_vec(gk["pub"].as_str().unwrap()).unwrap(),
    )
    .expect("key binds its tmb");
    let g = Genesis::Implicit(key);
    let id = genesis_principal_id(&g).expect("genesis id");
    (g, id)
}

/// Wire blobs of a fixture commit, key material embedded as a client would.
fn raw_blobs(commit: &serde_json::Value) -> Vec<serde_json::Value> {
    let keys = commit["keys"].as_array();
    let mut key_idx = 0;
    commit["txs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let mut coz = c.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) {
                if let Some(k) = keys.and_then(|ks| ks.get(key_idx)) {
                    coz.as_object_mut().unwrap().insert("key".into(), k.clone());
                    key_idx += 1;
                }
            }
            coz
        })
        .collect()
}

fn fake_digest(tag: u8) -> String {
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[tag; 32]))
}

/// A forged commit naming `principal_id`, at `sequence`.
fn forged(principal_id: &str, sequence: u64, tag: u8) -> IndexableCommit {
    let hash = Blake3Hash::from_bytes([tag; 32]);
    IndexableCommit {
        pg: Vec::new(),
        principal_id: principal_id.to_string(),
        commit_ids: vec![fake_digest(tag)],
        sequence,
        pre: None,
        prs: vec![fake_digest(tag ^ 1)],
        srs: vec![fake_digest(tag ^ 2)],
        ars: vec![fake_digest(tag ^ 3)],
        crs: vec![fake_digest(tag ^ 4)],
        blob_hashes: vec![hash],
        cozies: vec![IndexableCoz {
            blob_hash: hash,
            czd: fake_digest(tag ^ 5),
            typ: "cyphr.me/cyphr/key/create".to_string(),
            tmb: "forged".to_string(),
            alg: "Ed25519".to_string(),
            now: 1,
            payload: None,
        }],
        timestamp: 1,
        keys: Vec::new(),
    }
}

/// Add manifest-shaped top-level members to the LAST blob (outside `pay`,
/// so its signature still verifies).
fn craft(mut blobs: Vec<serde_json::Value>, commit: &IndexableCommit) -> Vec<Vec<u8>> {
    let o = blobs.last_mut().unwrap().as_object_mut().unwrap();
    o.insert("kind".into(), MANIFEST_KIND.into());
    o.insert("commit".into(), serde_json::to_value(commit).unwrap());
    blobs.iter().map(|b| serde_json::to_vec(b).unwrap()).collect()
}

async fn submit(
    engine: &Engine,
    id: &str,
    genesis: &Genesis,
    blobs: &[Vec<u8>],
) -> Result<(), cyphr_storage::engine::EngineError> {
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(id, Some(genesis.clone()), &refs)
        .await
        .map(|_| ())
}

async fn submit_honest(engine: &Engine, fixture: &serde_json::Value) -> (Genesis, String) {
    let (g, id) = genesis_of(fixture);
    for c in fixture["commits"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = raw_blobs(c).iter().map(|b| serde_json::to_vec(b).unwrap()).collect();
        submit(engine, &id, &g, &blobs).await.expect("honest commit");
    }
    (g, id)
}

async fn principals(engine: &Engine) -> Vec<(String, String, u64)> {
    let mut p: Vec<_> = engine
        .indexer()
        .list_principals()
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.principal_id, s.pr, s.commit_count))
        .collect();
    p.sort();
    p
}

fn engine() -> Engine {
    StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
}

/// RED(H1F), engine-level scenario, transaction path (also witness sync's
/// path). Attacker principal A's validly signed commit carries a forged
/// manifest naming the honest principal B. Mutant caught: today's
/// rebuild, and any fix that keys trust on `kind` alone.
#[tokio::test]
#[ignore = "RED(H1F): rebuild_index_from_manifests trusts caller blobs shaped like a manifest"]
async fn crafted_transaction_blob_cannot_rewrite_another_principals_tip() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let before = e.get_tip(&victim).await.unwrap().unwrap();
    let before_others = principals(&e).await;

    let attacker_fx = load_golden("mutations", "transaction_sequence_replay");
    let (ag, aid) = genesis_of(&attacker_fx);
    let first = &attacker_fx["commits"][0];
    let blobs = craft(raw_blobs(first), &forged(&before.principal_id, 2, 0x10));
    let _accepted_or_refused = submit(&e, &aid, &ag, &blobs).await;

    e.rebuild_index_from_manifests().await.unwrap();

    assert_eq!(e.get_tip(&victim).await.unwrap().unwrap(), before, "victim tip untouched");
    let others: Vec<_> = principals(&e).await.into_iter().filter(|p| !p.0.ends_with(aid.split(':').next_back().unwrap())).collect();
    assert_eq!(others, before_others);
}

/// RED(H1F), engine-level scenario, action-only path. An action-only
/// bundle is stored raw with no manifest of its own, yet its blob lands in
/// the manifest-scanned store. A forged manifest in a signed action must
/// not invent a principal. Mutant caught: a fix that guards only the
/// transaction path, and the "only unindexed principals" non-fix (the
/// phantom is unindexed).
#[tokio::test]
#[ignore = "RED(H1F): rebuild_index_from_manifests trusts caller blobs shaped like a manifest"]
async fn crafted_action_blob_cannot_invent_a_principal() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let before = e.get_tip(&victim).await.unwrap().unwrap();
    let phantom = fake_digest(0x20);

    let fx = load_golden("actions", "action_changes_ps");
    let (ag, aid) = genesis_of(&fx);
    let blobs = craft(raw_blobs(&fx["commits"][0]), &forged(&phantom, 0, 0x21));
    let _accepted_or_refused = submit(&e, &aid, &ag, &blobs).await;

    e.rebuild_index_from_manifests().await.unwrap();

    assert!(e.get_tip(&phantom).await.unwrap().is_none(), "phantom principal must have no tip");
    assert!(principals(&e).await.iter().all(|p| p.0 != phantom));
    assert_eq!(e.get_tip(&victim).await.unwrap().unwrap(), before);

    // Scratch variant: after `clear`, nothing is indexed, so a
    // "trust only unindexed principals" non-fix would accept the phantom.
    e.rebuild_index_from_scratch().await.unwrap();
    assert!(e.get_tip(&phantom).await.unwrap().is_none(), "phantom survives a scratch rebuild");
}

/// Green control. Claim: rebuild recovers EXACTLY the engine's own
/// manifests (one per honest commit, 3 + 2 here) and a scratch rebuild
/// restores byte-equal tips and principal list. Mutants caught: a rebuild
/// blinded to manifests (count 0 / tips lost after clear), over- or
/// under-counting, and a rebuild that perturbs honest state.
#[tokio::test]
async fn rebuild_recovers_exactly_the_honest_manifests() {
    let e = engine();
    let (_, a) = submit_honest(&e, &load_golden("mutations", "transaction_sequence_replay")).await;
    let (_, b) = submit_honest(&e, &load_golden("edge_cases", "transaction_replay_order")).await;
    let (ta, tb, listed) = (
        e.get_tip(&a).await.unwrap().unwrap(),
        e.get_tip(&b).await.unwrap().unwrap(),
        principals(&e).await,
    );
    assert_eq!((ta.commit_count, tb.commit_count), (3, 2));

    assert_eq!(e.rebuild_index_from_manifests().await.unwrap(), 5);
    assert_eq!(e.rebuild_index_from_scratch().await.unwrap(), 5);
    assert_eq!(e.get_tip(&a).await.unwrap().unwrap(), ta);
    assert_eq!(e.get_tip(&b).await.unwrap().unwrap(), tb);
    assert_eq!(principals(&e).await, listed);
}
