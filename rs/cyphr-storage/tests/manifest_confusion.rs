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

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, MemoryBlobStore};
use cyphr_storage::engine::{EngineError, StorageEngine, genesis_principal_id};
use cyphr_storage::index::{
    CommitRef, DeriveToken, EntityRef, IndexableCommit, IndexableCoz, Indexer, IndexerError,
    IndexerWrite, MemoryIndexer, PrincipalSummary, PublicKeyInfo, TipState,
};
use proptest::prelude::*;

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
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(gk["tmb"].as_str().unwrap()).unwrap(),
        ),
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
    blobs
        .iter()
        .map(|b| serde_json::to_vec(b).unwrap())
        .collect()
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
        let blobs: Vec<Vec<u8>> = raw_blobs(c)
            .iter()
            .map(|b| serde_json::to_vec(b).unwrap())
            .collect();
        submit(engine, &id, &g, &blobs)
            .await
            .expect("honest commit");
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

    assert_eq!(
        e.get_tip(&victim).await.unwrap().unwrap(),
        before,
        "victim tip untouched"
    );
    let others: Vec<_> = principals(&e)
        .await
        .into_iter()
        .filter(|p| !p.0.ends_with(aid.split(':').next_back().unwrap()))
        .collect();
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

    assert!(
        e.get_tip(&phantom).await.unwrap().is_none(),
        "phantom principal must have no tip"
    );
    assert!(principals(&e).await.iter().all(|p| p.0 != phantom));
    assert_eq!(e.get_tip(&victim).await.unwrap().unwrap(), before);

    // Scratch variant: after `clear`, nothing is indexed, so a
    // "trust only unindexed principals" non-fix would accept the phantom.
    e.rebuild_index_from_scratch().await.unwrap();
    assert!(
        e.get_tip(&phantom).await.unwrap().is_none(),
        "phantom survives a scratch rebuild"
    );
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

// ---------------------------------------------------------------------------
// H1F acceptance. Every test names the claim it backs and the defect that
// turns it red.
// ---------------------------------------------------------------------------

/// Submit with no caller genesis, the call shape of the server's witness
/// sync (`sync.rs`): genesis comes from storage or from the blobs.
async fn submit_as_witness(
    engine: &Engine,
    id: &str,
    blobs: &[Vec<u8>],
) -> Result<(), EngineError> {
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    engine.submit_commit(id, None, &refs).await.map(|_| ())
}

/// Wire blobs of a fixture commit with the fixture's genesis key disclosed
/// on every coz that carries no key, as a witness-synced bundle does: with
/// no caller genesis the engine finds the genesis key in the blobs.
fn raw_blobs_disclosing_genesis(
    fixture: &serde_json::Value,
    commit: &serde_json::Value,
) -> Vec<serde_json::Value> {
    let gk = fixture["genesis_keys"][0].clone();
    let key = serde_json::json!({"alg": gk["alg"], "pub": gk["pub"], "tmb": gk["tmb"]});
    raw_blobs(commit)
        .into_iter()
        .map(|mut b| {
            b.as_object_mut()
                .unwrap()
                .entry("key")
                .or_insert_with(|| key.clone());
            b
        })
        .collect()
}

/// RED(H1F), engine-level scenario, witness-sync call shape. Claim: a
/// manifest-shaped member on a coz the witness replicates from an
/// authority cannot move any tip on rebuild: not the victim's, not the
/// replicating principal's own. Turns red if: rebuild trusts the member.
#[tokio::test]
#[ignore = "RED(H1F): rebuild_index_from_manifests trusts caller blobs shaped like a manifest"]
async fn via_witness_sync_crafted_blob_cannot_move_any_tip() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let attacker_fx = load_golden("mutations", "transaction_sequence_replay");
    let (_, aid) = genesis_of(&attacker_fx);
    let first: Vec<Vec<u8>> =
        raw_blobs_disclosing_genesis(&attacker_fx, &attacker_fx["commits"][0])
            .iter()
            .map(|b| serde_json::to_vec(b).unwrap())
            .collect();
    submit_as_witness(&e, &aid, &first).await.expect("commit 0");
    let (victim_tip, own_tip) = (
        e.get_tip(&victim).await.unwrap().unwrap(),
        e.get_tip(&aid).await.unwrap().unwrap(),
    );

    // Commit 1 arrives by witness sync, forging a rewind of its own
    // principal and a rewrite of the victim.
    for target in [&victim, &aid] {
        let blobs = craft(
            raw_blobs_disclosing_genesis(&attacker_fx, &attacker_fx["commits"][1]),
            &forged(target, 0, 0x30),
        );
        let _accepted_or_refused = submit_as_witness(&e, &aid, &blobs).await;
    }
    let own_after_ingest = e.get_tip(&aid).await.unwrap().unwrap();

    e.rebuild_index_from_manifests().await.unwrap();
    e.rebuild_index_from_scratch().await.unwrap();

    assert_eq!(e.get_tip(&victim).await.unwrap().unwrap(), victim_tip);
    assert_eq!(
        e.get_tip(&aid).await.unwrap().unwrap(),
        own_after_ingest,
        "own tip must be what ingest computed, not a forged value"
    );
    assert!(own_after_ingest.commit_count >= own_tip.commit_count);
}

/// RED(H1F), engine-level scenario, action-only call shape with no caller
/// genesis. Claim: a manifest-shaped action blob cannot plant a PG alias
/// that resolves to the victim, nor a digest, on rebuild. Turns red if:
/// rebuild indexes the forged `pg` or digests.
#[tokio::test]
#[ignore = "RED(H1F): rebuild_index_from_manifests trusts caller blobs shaped like a manifest"]
async fn via_action_only_bundle_cannot_plant_aliases_or_digests() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let before = principals(&e).await;

    let fx = load_golden("actions", "action_changes_ps");
    let (_, aid) = genesis_of(&fx);
    let mut hostile = forged(&aid, 0, 0x40);
    hostile.pg = vec![victim.clone(), fake_digest(0x41)];
    let blobs = craft(
        raw_blobs_disclosing_genesis(&fx, &fx["commits"][0]),
        &hostile,
    );
    let _accepted_or_refused = submit_as_witness(&e, &aid, &blobs).await;

    e.rebuild_index_from_scratch().await.unwrap();

    assert!(e.get_tip(&fake_digest(0x41)).await.unwrap().is_none());
    assert_eq!(
        e.get_tip(&victim).await.unwrap().unwrap().principal_id,
        victim,
        "the victim id must still name the victim"
    );
    assert!(e.get_tip(&aid).await.unwrap().is_none());
    assert_eq!(principals(&e).await, before);
    for tag in [0x40u8, 0x41, 0x42, 0x43, 0x44, 0x45] {
        let d: cyphr::state::TaggedDigest = fake_digest(tag).parse().unwrap();
        assert!(e.indexer().resolve_digest(&d).await.unwrap().is_none());
    }
}

/// The stored bytes of every blob a submit reports.
async fn stored_blobs(e: &Engine, hashes: &[Blake3Hash]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for h in hashes {
        let bytes = cyphr_storage::blob::BlobStore::get(e.blob_store(), h)
            .await
            .unwrap()
            .expect("reported blob is stored");
        out.push(serde_json::from_slice(&bytes).expect("stored blob is JSON"));
    }
    out
}

/// The first honest commit of the attacker fixture, with `extra` members
/// added to every coz.
fn with_extras(extra: &[(&str, serde_json::Value)]) -> Vec<Vec<u8>> {
    let fx = load_golden("mutations", "transaction_sequence_replay");
    raw_blobs(&fx["commits"][0])
        .into_iter()
        .map(|mut b| {
            for (k, v) in extra {
                b.as_object_mut().unwrap().insert((*k).into(), v.clone());
            }
            serde_json::to_vec(&b).unwrap()
        })
        .collect()
}

async fn submit_reporting(e: &Engine, blobs: &[Vec<u8>]) -> Result<Vec<Blake3Hash>, EngineError> {
    let fx = load_golden("mutations", "transaction_sequence_replay");
    let (g, id) = genesis_of(&fx);
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    e.submit_commit(&id, Some(g), &refs)
        .await
        .map(|r| r.blob_hashes)
}

/// RED(H1F). Claim: the store holds the canonical coz the signature
/// covers: unsigned extra top-level members (here `kind`, `commit`, and a
/// harmless `typ`) are not stored, while `pay`, `sig` and the disclosed
/// `key` are. Turns red if: any unsigned extra is persisted.
#[tokio::test]
#[ignore = "RED(H1F): extras are stored verbatim"]
async fn canonical_unsigned_extras_are_not_stored() {
    let e = engine();
    let blobs = with_extras(&[
        ("kind", MANIFEST_KIND.into()),
        (
            "commit",
            serde_json::to_value(forged("x", 0, 0x50)).unwrap(),
        ),
        ("typ", "cyphr.me/cyphr/key/create".into()),
    ]);
    let hashes = submit_reporting(&e, &blobs)
        .await
        .expect("extras tolerated");
    for stored in stored_blobs(&e, &hashes).await {
        let members: Vec<_> = stored.as_object().unwrap().keys().cloned().collect();
        assert!(
            members
                .iter()
                .all(|m| ["pay", "sig", "key"].contains(&m.as_str())),
            "stored members: {members:?}"
        );
        assert!(stored.get("pay").is_some() && stored.get("sig").is_some());
    }
}

/// RED(H1F). Claim: one signed coz has one blob address, whatever
/// unsigned members or pay member order the submitter used. Turns red if:
/// two spellings of one signed coz hash differently.
#[tokio::test]
#[ignore = "RED(H1F): extras are stored verbatim"]
async fn canonical_one_address_per_signed_coz() {
    let plain = submit_reporting(&engine(), &with_extras(&[]))
        .await
        .unwrap();
    let noisy = submit_reporting(
        &engine(),
        &with_extras(&[("typ", "x".into()), ("zzz", serde_json::json!([1, 2]))]),
    )
    .await
    .unwrap();
    assert_eq!(plain, noisy, "extras changed the blob address");
}

/// RED(H1F). Claim: a present `czd` or `cad` is recomputed and a mismatch
/// is refused (Coz: recalculatable members), while a correct one is
/// accepted and not stored. Turns red if: a wrong value is accepted, or a
/// correct one is stored.
#[tokio::test]
#[ignore = "RED(H1F): a present czd/cad is never recomputed"]
async fn canonical_mismatched_cad_or_czd_is_refused() {
    let fx = load_golden("mutations", "transaction_sequence_replay");
    let coz = &raw_blobs(&fx["commits"][0])[0];
    let mut pay = coz["pay"].clone();
    // Sorted member order is the canonical pay (what the engine signs
    // over); serde_json's map is ordered.
    pay.as_object_mut().unwrap().sort_keys();
    let pay_bytes = serde_json::to_vec(&pay).unwrap();
    let alg = pay["alg"].as_str().unwrap();
    let sig = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().unwrap()).unwrap();
    let cad = coz::canonical_hash_for_alg(&pay_bytes, alg, None).unwrap();
    let czd = coz::czd_for_alg(&cad, &sig, alg).unwrap();
    let wrong = Base64UrlUnpadded::encode_string(&[7u8; 32]);

    for (name, bad) in [("czd", &wrong), ("cad", &wrong)] {
        let e = engine();
        let r = submit_reporting(&e, &with_extras(&[(name, bad.clone().into())])).await;
        assert!(r.is_err(), "wrong {name} accepted");
        assert!(principals(&e).await.is_empty(), "wrong {name} left state");
    }

    let e = engine();
    let hashes = submit_reporting(
        &e,
        &with_extras(&[("czd", czd.to_b64().into()), ("cad", cad.to_b64().into())]),
    )
    .await
    .expect("correct recalculatable members are accepted");
    for stored in stored_blobs(&e, &hashes).await {
        assert!(stored.get("czd").is_none() && stored.get("cad").is_none());
    }
}

/// A [`BlobStore`] that notes when anything was stored after being armed.
#[derive(Clone)]
struct ArmedBlobs {
    inner: MemoryBlobStore,
    armed: Arc<AtomicBool>,
    stored: Arc<AtomicBool>,
}

impl cyphr_storage::blob::BlobStore for ArmedBlobs {
    fn put(
        &self,
        data: &[u8],
    ) -> impl Future<Output = Result<Blake3Hash, cyphr_storage::blob::BlobStoreError>> + Send {
        let (inner, armed, stored) = (self.inner.clone(), self.armed.clone(), self.stored.clone());
        let data = data.to_vec();
        async move {
            let hash = cyphr_storage::blob::BlobStore::put(&inner, &data).await?;
            if armed.load(Ordering::SeqCst) {
                stored.store(true, Ordering::SeqCst);
            }
            Ok(hash)
        }
    }

    fn get(
        &self,
        hash: &Blake3Hash,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, cyphr_storage::blob::BlobStoreError>> + Send
    {
        cyphr_storage::blob::BlobStore::get(&self.inner, hash)
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl Future<Output = Result<bool, cyphr_storage::blob::BlobStoreError>> + Send {
        cyphr_storage::blob::BlobStore::exists(&self.inner, hash)
    }

    fn iter(
        &self,
    ) -> impl Future<
        Output = Result<
            Box<
                dyn Iterator<Item = Result<Blake3Hash, cyphr_storage::blob::BlobStoreError>> + Send,
            >,
            cyphr_storage::blob::BlobStoreError,
        >,
    > + Send {
        cyphr_storage::blob::BlobStore::iter(&self.inner)
    }
}

/// An [`Indexer`] whose `get_tip` fails once the blob store has stored
/// something while armed: the "index read fails after the bytes are
/// durable" fault.
struct TipFailsAfterStore {
    inner: MemoryIndexer,
    stored: Arc<AtomicBool>,
}

impl Indexer for TipFailsAfterStore {
    fn get_tip(
        &self,
        principal_id: &str,
    ) -> impl Future<Output = Result<Option<TipState>, IndexerError>> + Send {
        let fail = self.stored.load(Ordering::SeqCst);
        let inner = self.inner.get_tip(principal_id);
        async move {
            if fail {
                return Err(IndexerError::Backend("injected get_tip fault".into()));
            }
            inner.await
        }
    }

    fn is_pg_established(
        &self,
        principal_id: &str,
    ) -> impl Future<Output = Result<bool, IndexerError>> + Send {
        self.inner.is_pg_established(principal_id)
    }

    fn get_commit_chain(
        &self,
        principal_id: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> impl Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send {
        self.inner.get_commit_chain(principal_id, from, to)
    }

    fn resolve_digest(
        &self,
        digest: &cyphr::state::TaggedDigest,
    ) -> impl Future<Output = Result<Option<EntityRef>, IndexerError>> + Send {
        self.inner.resolve_digest(digest)
    }

    fn list_principals(
        &self,
    ) -> impl Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send {
        self.inner.list_principals()
    }

    fn is_blob_indexed(
        &self,
        hash: &Blake3Hash,
    ) -> impl Future<Output = Result<bool, IndexerError>> + Send {
        self.inner.is_blob_indexed(hash)
    }

    fn get_key(
        &self,
        thumbprint: &str,
    ) -> impl Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send {
        self.inner.get_key(thumbprint)
    }
}

impl IndexerWrite for TipFailsAfterStore {
    fn index_commit(
        &self,
        commit: &IndexableCommit,
        token: &DeriveToken,
    ) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.index_commit(commit, token)
    }

    fn clear(&self, token: &DeriveToken) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.clear(token)
    }
}

/// RED(H1F), engine-level scenario. Claim: once an action-only bundle's
/// blobs are durable, the submit cannot report an error, extending the
/// no-error-after-commit guarantee from commits to actions. The index
/// read that fails is the one after the blob write. Turns red if: the
/// response is built from a fallible read after the store.
#[tokio::test]
#[ignore = "RED(H1F): action-only response reads the tip after the blobs are stored"]
async fn action_only_no_error_after_store() {
    let (armed, stored) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let e = StorageEngine::new(
        ArmedBlobs {
            inner: MemoryBlobStore::new(),
            armed: armed.clone(),
            stored: stored.clone(),
        },
        TipFailsAfterStore {
            inner: MemoryIndexer::new(),
            stored: stored.clone(),
        },
    );
    let fx = load_golden("actions", "action_changes_ps");
    let (g, id) = genesis_of(&fx);
    let blobs: Vec<Vec<u8>> = raw_blobs(&fx["commits"][0])
        .iter()
        .map(|b| serde_json::to_vec(b).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();

    armed.store(true, Ordering::SeqCst);
    let result = e.submit_commit(&id, Some(g), &refs).await;

    assert!(
        stored.load(Ordering::SeqCst),
        "control: the bundle's blobs were stored"
    );
    let result = result.expect("a stored action-only bundle must be reported as stored");
    assert_eq!(result.blob_hashes.len(), refs.len());
    assert!(result.manifest_hash.is_none());
}

/// RED(H1F), c-i1. Claim: a manifest-shaped blob in the wire store (an old
/// shared-store manifest, or a forged coz stored by an old engine) is
/// never silently indexed: rebuild refuses with a typed error and indexes
/// nothing. Turns red if: rebuild indexes it or ignores it without error.
#[tokio::test]
#[ignore = "RED(H1F): legacy manifest-shaped wire blobs are indexed"]
async fn rebuild_refuses_legacy_manifest_shaped_wire_blobs() {
    let e = engine();
    let legacy = serde_json::to_vec(&serde_json::json!({
        "kind": MANIFEST_KIND,
        "commit": forged(&fake_digest(0x60), 0, 0x61),
    }))
    .unwrap();
    cyphr_storage::blob::BlobStore::put(e.blob_store(), &legacy)
        .await
        .unwrap();

    let err = e.rebuild_index_from_manifests().await.expect_err("refused");
    assert!(matches!(err, EngineError::LegacyManifest { .. }), "{err:?}");
    assert!(principals(&e).await.is_empty());
    assert!(
        e.indexer()
            .get_tip(&fake_digest(0x60))
            .await
            .unwrap()
            .is_none()
    );
}

/// The index state a hostile blob could try to move.
async fn snapshot(e: &Engine, probes: &[String]) -> String {
    let mut lines = Vec::new();
    for p in principals(e).await {
        let tip = e.indexer().get_tip(&p.0).await.unwrap();
        let chain = e
            .indexer()
            .get_commit_chain(&p.0, None, None)
            .await
            .unwrap();
        lines.push(format!("{p:?} {tip:?} {chain:?}"));
    }
    for d in probes {
        let alias = e.indexer().get_tip(d).await.unwrap();
        let entity = match d.parse::<cyphr::state::TaggedDigest>() {
            Ok(t) => e.indexer().resolve_digest(&t).await.unwrap(),
            Err(_) => None,
        };
        lines.push(format!("{d} {alias:?} {entity:?}"));
    }
    lines.join("\n")
}

#[derive(Debug, Clone)]
struct Hostile {
    target: usize,
    sequence: u64,
    tag: u8,
    pg_victim: bool,
    escaped_key: bool,
}

fn hostile() -> impl Strategy<Value = Option<Hostile>> {
    proptest::option::of(
        (0usize..3, 0u64..4, 0u8..8, any::<bool>(), any::<bool>()).prop_map(
            |(target, sequence, tag, pg_victim, escaped_key)| Hostile {
                target,
                sequence,
                tag,
                pg_victim,
                escaped_key,
            },
        ),
    )
}

/// Serialize `blobs` with the manifest members; optionally spell the
/// `kind` key with a JSON escape so no byte-string match can find it.
fn craft_with(blobs: Vec<serde_json::Value>, h: &Hostile, victim: &str, own: &str) -> Vec<Vec<u8>> {
    let target = [victim.to_string(), own.to_string(), fake_digest(0x70)][h.target].clone();
    let mut commit = forged(&target, h.sequence, h.tag);
    if h.pg_victim {
        commit.pg = vec![victim.to_string(), fake_digest(h.tag ^ 9)];
    }
    let mut bytes = craft(blobs, &commit);
    if h.escaped_key {
        let last = bytes.last_mut().unwrap();
        let text = String::from_utf8(std::mem::take(last)).unwrap();
        *last = text.replacen("\"kind\"", "\"\\u006bind\"", 1).into_bytes();
    }
    bytes
}

/// Run honest victim history plus the attacker's three commits, each
/// optionally carrying a hostile manifest-shaped blob.
async fn run(plan: &[Option<Hostile>], hostile_on: bool) -> (Engine, String, Vec<String>) {
    let e = engine();
    let (_, victim) =
        submit_honest(&e, &load_golden("edge_cases", "transaction_replay_order")).await;
    let fx = load_golden("mutations", "transaction_sequence_replay");
    let (g, aid) = genesis_of(&fx);
    for (i, c) in fx["commits"].as_array().unwrap().iter().enumerate() {
        let honest = raw_blobs(c);
        let blobs = match plan.get(i).cloned().flatten() {
            Some(h) if hostile_on => craft_with(honest, &h, &victim, &aid),
            _ => honest
                .iter()
                .map(|b| serde_json::to_vec(b).unwrap())
                .collect(),
        };
        let _ = submit(&e, &aid, &g, &blobs).await;
    }
    let probes = (0u8..16).map(fake_digest).chain([victim.clone()]).collect();
    (e, victim, probes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// RED(H1F), property. Claim: rebuild trusts only what the blobs
    /// support. For random hostile manifest-shaped members on random
    /// commits of an honest history (random target principal, sequence,
    /// forged PG alias, escaped member spelling): the index after ingest
    /// equals the index of the same history without hostile members, and
    /// equals the index after a scratch rebuild; no probed forged digest or
    /// alias resolves. Turns red if: any hostile member moves a tip, alias
    /// or digest, at ingest or on rebuild.
    #[test]
    #[ignore = "RED(H1F): rebuild trusts manifest-shaped caller blobs"]
    fn rebuild_ignores_hostile_manifest_shaped_blobs(
        plan in proptest::collection::vec(hostile(), 3),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let (attacked, _, probes) = run(&plan, true).await;
            let (clean, _, _) = run(&plan, false).await;
            let ingest = snapshot(&attacked, &probes).await;
            prop_assert_eq!(&ingest, &snapshot(&clean, &probes).await);

            attacked.rebuild_index_from_manifests().await.unwrap();
            prop_assert_eq!(&ingest, &snapshot(&attacked, &probes).await);
            attacked.rebuild_index_from_scratch().await.unwrap();
            prop_assert_eq!(&ingest, &snapshot(&attacked, &probes).await);
            Ok(())
        })?;
    }
}
