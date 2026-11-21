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
//! interpret as a manifest". Each failed on an index assertion before the
//! manifest keyspace separated manifests from wire blobs.
//!
//! Run: `cargo test -p cyphr-storage --test manifest_confusion --
//! --include-ignored`.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::Genesis;
use cyphr_storage::blob::{Blake3Hash, MemoryBlobStore};
use cyphr_storage::engine::{EngineError, QuarantineReason, StorageEngine, genesis_principal_id};
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
    // A line's data actions come first: they are recorded before its
    // transactions (SPEC 4.6.2).
    commit["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            commit["txs"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|tx| tx.as_array().unwrap()),
        )
        .map(|c| {
            let mut coz = c.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ)
                && let Some(k) = keys.and_then(|ks| ks.get(key_idx))
            {
                coz.as_object_mut().unwrap().insert("key".into(), k.clone());
                key_idx += 1;
            }
            coz
        })
        .collect()
}

/// The wire bundle (SPEC 4.6.2) a client pushes for the cozies `blobs`,
/// in order: data actions first (recorded before the transactions), each
/// transaction coz a transaction of its own, and every disclosed `key`
/// member moved to the bundle's `keys`. A coz with no `key` member keeps
/// its exact bytes, so the unsigned members a test adds reach the engine.
pub fn wire(blobs: &[Vec<u8>]) -> cyphr::replay::WireBundle {
    let mut bundle = cyphr::replay::WireBundle::default();
    for blob in blobs {
        let mut bytes = blob.clone();
        let mut value: serde_json::Value = serde_json::from_slice(blob).unwrap_or_default();
        if let Some(entry) = value
            .get("key")
            .and_then(|k| serde_json::from_value::<cyphr_storage::KeyEntry>(k.clone()).ok())
        {
            value.as_object_mut().unwrap().remove("key");
            bytes = serde_json::to_vec(&value).unwrap();
            if !bundle.keys.iter().any(|k| k.tmb == entry.tmb) {
                bundle.keys.push(entry);
            }
        }
        let is_action = value["pay"]["typ"]
            .as_str()
            .is_some_and(|t| !cyphr::parsed_coz::typ::is_transaction(t));
        if is_action {
            bundle.actions.push(bytes);
        } else {
            bundle.txs.push(vec![bytes]);
        }
    }
    bundle
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
    engine
        .submit_commit(id, Some(genesis.clone()), &wire(blobs))
        .await
        .map(|_| ())
}

/// Push `fixture`'s genesis commit (`commits[0]`) alone, so its later
/// lines meet an established principal (a data action needs one).
async fn push_genesis(engine: &Engine, fixture: &serde_json::Value) -> (Genesis, String) {
    let (g, id) = genesis_of(fixture);
    let blobs: Vec<Vec<u8>> = raw_blobs(&fixture["commits"][0])
        .iter()
        .map(|b| serde_json::to_vec(b).unwrap())
        .collect();
    submit(engine, &id, &g, &blobs)
        .await
        .expect("genesis commit");
    (g, id)
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

/// engine-level scenario, transaction path (also witness sync's
/// path). Attacker principal A's validly signed commit carries a forged
/// manifest naming the honest principal B. Mutant caught: today's
/// rebuild, and any fix that keys trust on `kind` alone.
#[tokio::test]
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

/// engine-level scenario, action-only path. An action-only
/// bundle is stored raw with no manifest of its own, yet its blob lands in
/// the manifest-scanned store. A forged manifest in a signed action must
/// not invent a principal. Mutant caught: a fix that guards only the
/// transaction path, and the "only unindexed principals" non-fix (the
/// phantom is unindexed).
#[tokio::test]
async fn crafted_action_blob_cannot_invent_a_principal() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let before = e.get_tip(&victim).await.unwrap().unwrap();
    let phantom = fake_digest(0x20);

    let fx = load_golden("actions", "action_alone_leaves_pr");
    let (ag, aid) = push_genesis(&e, &fx).await;
    let blobs = craft(raw_blobs(&fx["commits"][1]), &forged(&phantom, 0, 0x21));
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
/// manifests (one per honest commit, 4 + 3 here, each chain's genesis
/// commit included) and a scratch rebuild
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
    assert_eq!((ta.commit_count, tb.commit_count), (4, 3));

    assert_eq!(e.rebuild_index_from_manifests().await.unwrap(), 7);
    assert_eq!(e.rebuild_index_from_scratch().await.unwrap(), 7);
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
    engine
        .submit_commit(id, None, &wire(blobs))
        .await
        .map(|_| ())
}

/// Wire blobs of a fixture commit with the fixture's genesis key attached
/// to every coz that carries no key. With no caller genesis the engine
/// reads a genesis only from a genesis commit's `key/create`s (SPEC 5.1),
/// so the extra `key` members are dropped as unsigned noise: a bundle can
/// carry them, but they never disclose (or bootstrap) a genesis.
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

/// engine-level scenario, witness-sync call shape. Claim: a
/// manifest-shaped member on a coz the witness replicates from an
/// authority cannot move any tip on rebuild: not the victim's, not the
/// replicating principal's own. Turns red if: rebuild trusts the member.
#[tokio::test]
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

/// engine-level scenario, action-only call shape with no caller
/// genesis. Claim: a manifest-shaped action blob cannot plant a PG alias
/// that resolves to the victim, nor a digest, on rebuild. Turns red if:
/// rebuild indexes the forged `pg` or digests.
#[tokio::test]
async fn via_action_only_bundle_cannot_plant_aliases_or_digests() {
    let e = engine();
    let victim_fx = load_golden("edge_cases", "transaction_replay_order");
    let (_, victim) = submit_honest(&e, &victim_fx).await;
    let fx = load_golden("actions", "action_alone_leaves_pr");
    let (_, aid) = push_genesis(&e, &fx).await;
    let own = e.get_tip(&aid).await.unwrap();
    let before = principals(&e).await;

    let mut hostile = forged(&aid, 0, 0x40);
    hostile.pg = vec![victim.clone(), fake_digest(0x41)];
    let blobs = craft(
        raw_blobs_disclosing_genesis(&fx, &fx["commits"][1]),
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
    assert_eq!(
        e.get_tip(&aid).await.unwrap(),
        own,
        "an action moves no tip of its own principal"
    );
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
    with_extras_on(usize::MAX, extra)
}

/// [`with_extras`] on the first `n` cozes only (a coz's own `cad`/`czd`
/// cannot be reused on another coz).
fn with_extras_on(n: usize, extra: &[(&str, serde_json::Value)]) -> Vec<Vec<u8>> {
    let fx = load_golden("mutations", "transaction_sequence_replay");
    raw_blobs(&fx["commits"][0])
        .into_iter()
        .enumerate()
        .map(|(i, mut b)| {
            for (k, v) in extra.iter().filter(|_| i < n) {
                b.as_object_mut().unwrap().insert((*k).into(), v.clone());
            }
            serde_json::to_vec(&b).unwrap()
        })
        .collect()
}

async fn submit_reporting(e: &Engine, blobs: &[Vec<u8>]) -> Result<Vec<Blake3Hash>, EngineError> {
    let fx = load_golden("mutations", "transaction_sequence_replay");
    let (g, id) = genesis_of(&fx);
    e.submit_commit(&id, Some(g), &wire(blobs))
        .await
        .map(|r| r.blob_hashes)
}

/// Claim: the store holds the canonical coz the signature
/// covers: unsigned extra top-level members (here `kind`, `commit`, and a
/// harmless `typ`) are not stored, while `pay` and `sig` are (key material
/// travels in the bundle's `keys`, never on a coz). Turns red if: any
/// unsigned extra is persisted.
#[tokio::test]
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
            members.iter().all(|m| ["pay", "sig"].contains(&m.as_str())),
            "stored members: {members:?}"
        );
        assert!(stored.get("pay").is_some() && stored.get("sig").is_some());
    }
}

/// Claim: one signed coz has one blob address, whatever
/// unsigned members or pay member order the submitter used. Turns red if:
/// two spellings of one signed coz hash differently.
#[tokio::test]
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

/// Claim: a present `czd` or `cad` is recomputed and a mismatch
/// is refused (Coz: recalculatable members), while a correct one is
/// accepted and not stored. Turns red if: a wrong value is accepted, or a
/// correct one is stored.
#[tokio::test]
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
        let r = submit_reporting(&e, &with_extras_on(1, &[(name, bad.clone().into())])).await;
        assert!(r.is_err(), "wrong {name} accepted");
        assert!(principals(&e).await.is_empty(), "wrong {name} left state");
    }

    let e = engine();
    let hashes = submit_reporting(
        &e,
        &with_extras_on(
            1,
            &[("czd", czd.to_b64().into()), ("cad", cad.to_b64().into())],
        ),
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
    async fn persist(&self) -> Result<(), cyphr_storage::blob::BlobStoreError> {
        self.inner.persist().await
    }

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
    fn check_commit(
        &self,
        commit: &IndexableCommit,
        token: &DeriveToken,
    ) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.check_commit(commit, token)
    }

    fn index_commit(
        &self,
        commit: &IndexableCommit,
        token: &DeriveToken,
    ) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.index_commit(commit, token)
    }

    fn replace_chain_from(
        &self,
        principal_id: &str,
        sequence: u64,
        commits: &[IndexableCommit],
        token: &DeriveToken,
    ) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner
            .replace_chain_from(principal_id, sequence, commits, token)
    }

    fn clear(&self, token: &DeriveToken) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.clear(token)
    }

    fn set_quarantined(
        &self,
        manifests: &[(Blake3Hash, String)],
        token: &DeriveToken,
    ) -> impl Future<Output = Result<(), IndexerError>> + Send {
        self.inner.set_quarantined(manifests, token)
    }

    fn quarantined(
        &self,
    ) -> impl Future<Output = Result<Vec<(Blake3Hash, String)>, IndexerError>> + Send {
        self.inner.quarantined()
    }
}

/// engine-level scenario. Claim: once an action-only bundle's
/// blobs are durable, the submit cannot report an error, extending the
/// no-error-after-commit guarantee from commits to actions. The index
/// read that fails is the one after the blob write. Turns red if: the
/// response is built from a fallible read after the store.
#[tokio::test]
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
    // The vector's first line is its genesis commit; its last is one data
    // action on its own, which only a principal with a genesis commit takes.
    let fx = load_golden("actions", "single_action_promotes_ds");
    let (g, id) = genesis_of(&fx);
    let line = |i: usize| -> Vec<Vec<u8>> {
        raw_blobs(&fx["commits"][i])
            .iter()
            .map(|b| serde_json::to_vec(b).unwrap())
            .collect()
    };
    e.submit_commit(&id, Some(g.clone()), &wire(&line(0)))
        .await
        .expect("genesis commit");
    let blobs = line(2);

    armed.store(true, Ordering::SeqCst);
    let result = e.submit_commit(&id, Some(g), &wire(&blobs)).await;

    assert!(
        stored.load(Ordering::SeqCst),
        "control: the bundle's blobs were stored"
    );
    let result = result.expect("a stored action-only bundle must be reported as stored");
    assert_eq!(result.blob_hashes.len(), blobs.len());
    assert!(result.manifest_hash.is_none());
}

/// c-i1. Claim: a manifest-shaped blob in the wire store (an old
/// shared-store manifest, or a forged coz stored by an old engine) is
/// never silently indexed: rebuild refuses with a typed error and indexes
/// nothing. Turns red if: rebuild indexes it or ignores it without error.
#[tokio::test]
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

/// No regression file: this node's tests must not write to the tree.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 24,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Claim: rebuild trusts only what the blobs
    /// support. For random hostile manifest-shaped members on random
    /// commits of an honest history (random target principal, sequence,
    /// forged PG alias, escaped member spelling): the index after ingest
    /// equals the index of the same history without hostile members, and
    /// equals the index after a scratch rebuild; no probed forged digest or
    /// alias resolves. Turns red if: any hostile member moves a tip, alias
    /// or digest, at ingest or on rebuild.
    #[test]
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

/// Store `commit` as an engine-format manifest (prefix plus JSON), the way
/// the engine's own writer does, bypassing the engine to model a corrupt
/// or foreign manifest that reached the blob store.
async fn plant_manifest(e: &Engine, commit: &IndexableCommit) {
    let mut bytes = cyphr_storage::engine::COMMIT_MANIFEST_PREFIX.to_vec();
    serde_json::to_writer(
        &mut bytes,
        &serde_json::json!({
            "kind": MANIFEST_KIND,
            "commit": commit,
            // One coz per transaction, as the honest writer records it.
            "shape": {"actions": 0, "txs": vec![1; commit.blob_hashes.len()]},
        }),
    )
    .unwrap();
    cyphr_storage::blob::BlobStore::put(e.blob_store(), &bytes)
        .await
        .unwrap();
}

/// Claim: rebuild binds each principal's manifests to the blobs they name:
/// a prefixed manifest whose principal id is not the genesis-derived id of
/// its sequence-0 blobs is quarantined with a typed reason and indexes nothing, while the rest of
/// the store rebuilds. Turns red if: a manifest naming real blobs re-points a principal (here
/// a phantom id) without any replay.
#[tokio::test]
async fn rebuild_quarantines_manifest_not_bound_to_its_blobs() {
    let e = engine();
    submit_honest(&e, &load_golden("edge_cases", "transaction_replay_order")).await;
    let fx = load_golden("mutations", "transaction_sequence_replay");
    // Genuine coz blobs that no manifest owns, so only the binding check
    // (not the index's digest-conflict check) can refuse the manifest.
    // They are a genesis commit's `key/create` and `principal/create`,
    // which disclose a genesis (SPEC 5.1), so the binding check derives
    // the key they bind and refuses the phantom id.
    let mut genuine = Vec::new();
    for b in raw_blobs(&fx["commits"][0]).iter().take(2) {
        let bytes = serde_json::to_vec(b).unwrap();
        genuine.push(
            cyphr_storage::blob::BlobStore::put(e.blob_store(), &bytes)
                .await
                .unwrap(),
        );
    }
    let phantom = fake_digest(0x70);
    let mut foreign = forged(&phantom, 0, 0x71);
    let mut second = foreign.cozies[0].clone();
    second.czd = fake_digest(0x72);
    foreign.cozies.push(second);
    for (coz, hash) in foreign.cozies.iter_mut().zip(&genuine) {
        coz.blob_hash = *hash;
    }
    foreign.blob_hashes = genuine;
    plant_manifest(&e, &foreign).await;

    let report = e
        .rebuild_index_with_report()
        .await
        .expect("rebuild survives");
    assert_eq!(report.quarantined.len(), 1, "{report:?}");
    assert!(
        matches!(report.quarantined[0].reason, QuarantineReason::Unbound(_)),
        "{report:?}"
    );
    assert_eq!(
        report.quarantined[0].principal_id.as_deref(),
        Some(phantom.as_str())
    );
    assert!(
        principals(&e).await.iter().any(|p| p.0 != phantom),
        "the honest principal still rebuilt"
    );
    assert!(e.indexer().get_tip(&phantom).await.unwrap().is_none());
    assert!(principals(&e).await.iter().all(|p| p.0 != phantom));
}

/// Hostile-input shapes for the single-writer property: arbitrary bytes,
/// and bytes that open with the manifest prefix or a manifest-shaped JSON.
fn hostile_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..64),
        proptest::collection::vec(any::<u8>(), 0..32).prop_map(|mut tail| {
            let mut v = cyphr_storage::engine::COMMIT_MANIFEST_PREFIX.to_vec();
            v.append(&mut tail);
            v
        }),
        Just(format!(r#"{{"kind":"{MANIFEST_KIND}","commit":{{}}}}"#).into_bytes()),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// Claim: only the engine's manifest writer ever stores a blob that
    /// starts with the manifest prefix. Over honest commits plus arbitrary
    /// hostile submissions on every path that stores caller bytes (a
    /// transaction bundle and an action-only bundle, each with hostile
    /// bytes in any slot), the stored prefixed blobs are exactly one per
    /// accepted commit and every other stored blob is a canonical coz
    /// (a JSON object of pay, sig and key only). Import and export take no
    /// blob store, so by type they cannot write one. Turns red if: any
    /// path stores caller bytes verbatim or writes a prefixed blob.
    #[test]
    fn rebuild_prefixed_blobs_only_from_the_manifest_writer(
        junk in proptest::collection::vec(hostile_bytes(), 1..4),
        slot in 0usize..3,
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let e = engine();
            let mut accepted = 0usize;
            let tx = load_golden("edge_cases", "transaction_replay_order");
            let (g, id) = genesis_of(&tx);
            for c in tx["commits"].as_array().unwrap() {
                let mut blobs: Vec<Vec<u8>> = raw_blobs(c)
                    .iter()
                    .map(|b| serde_json::to_vec(b).unwrap())
                    .collect();
                for (i, j) in junk.iter().enumerate() {
                    let at = (slot + i) % (blobs.len() + 1);
                    blobs.insert(at, j.clone());
                }
                if submit(&e, &id, &g, &blobs).await.is_ok() {
                    accepted += 1;
                }
                let clean: Vec<Vec<u8>> = raw_blobs(c)
                    .iter()
                    .map(|b| serde_json::to_vec(b).unwrap())
                    .collect();
                if submit(&e, &id, &g, &clean).await.is_ok() {
                    accepted += 1;
                }
            }
            let act = load_golden("actions", "action_alone_leaves_pr");
            let (ag, aid) = push_genesis(&e, &act).await;
            accepted += 1;
            let mut blobs: Vec<Vec<u8>> = raw_blobs(&act["commits"][1])
                .iter()
                .map(|b| serde_json::to_vec(b).unwrap())
                .collect();
            blobs.extend(junk.iter().cloned());
            let _ = submit(&e, &aid, &ag, &blobs).await;
            let clean: Vec<Vec<u8>> = raw_blobs(&act["commits"][1])
                .iter()
                .map(|b| serde_json::to_vec(b).unwrap())
                .collect();
            let _ = submit(&e, &aid, &ag, &clean).await;

            let store = e.blob_store();
            let hashes: Vec<Blake3Hash> = cyphr_storage::blob::BlobStore::iter(store)
                .await
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let (mut prefixed, mut wire) = (0usize, 0usize);
            for h in hashes {
                let data = cyphr_storage::blob::BlobStore::get(store, &h)
                    .await
                    .unwrap()
                    .unwrap();
                if data.starts_with(cyphr_storage::engine::COMMIT_MANIFEST_PREFIX) {
                    prefixed += 1;
                } else if data.starts_with(cyphr_storage::engine::ACTION_MANIFEST_PREFIX) {
                    // An accepted action-only bundle's record; not a commit.
                } else {
                    wire += 1;
                    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
                    prop_assert_eq!(data[0], 0x7b);
                    for k in v.as_object().unwrap().keys() {
                        prop_assert!(["pay", "sig", "key"].contains(&k.as_str()), "member {}", k);
                    }
                }
            }
            prop_assert_eq!(prefixed, accepted);
            prop_assert!(wire > 0);
            Ok(())
        })?;
    }
}

// ---------------------------------------------------------------------------
// Replayed cozes (hacker-seat findings F-A, F-B, F-C). SPEC be0663f 7.6 lets
// principals that share keys reuse a coz, and `key/create` needs no proof of
// possession, so any principal can add another's public key and replay that
// principal's signed cozes. Nothing replayed may block, misattribute or brick.
// ---------------------------------------------------------------------------
mod replay {
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr_storage::Genesis;
    use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError, MemoryBlobStore};
    use cyphr_storage::engine::{EngineError, IngestResult, StorageEngine, genesis_principal_id};
    use cyphr_storage::index::{Indexer, IndexerWrite, MemoryIndexer};

    pub const T: i64 = 1_700_000_000;

    pub fn pool() -> test_fixtures::Pool {
        let p =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
        test_fixtures::Pool::load(&p).unwrap()
    }
    pub fn dk(pk: &test_fixtures::PoolKey) -> cyphr::Key {
        cyphr::Key::new(
            pk.alg.clone(),
            pk.compute_tmb().unwrap(),
            Base64UrlUnpadded::decode_vec(&pk.pub_key).unwrap(),
        )
        .unwrap()
    }
    pub fn kj(pk: &test_fixtures::PoolKey) -> serde_json::Value {
        serde_json::json!({"alg": pk.alg, "pub": pk.pub_key, "tmb": pk.compute_tmb_b64().unwrap()})
    }
    pub fn sign(
        pk: &test_fixtures::PoolKey,
        mut pay: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        pay.as_object_mut().unwrap().sort_keys();
        let pb = serde_json::to_vec(&pay).unwrap();
        let prv = Base64UrlUnpadded::decode_vec(pk.prv.as_ref().unwrap()).unwrap();
        let pubk = Base64UrlUnpadded::decode_vec(&pk.pub_key).unwrap();
        let (sig, cad) = coz::sign_json(&pb, &pk.alg, &prv, &pubk).unwrap();
        let czd = coz::czd_for_alg(&cad, &sig, &pk.alg).unwrap();
        (pb, sig, czd)
    }
    pub fn blob(pb: &[u8], sig: &[u8], key: Option<serde_json::Value>) -> Vec<u8> {
        let mut o = serde_json::Map::new();
        o.insert("pay".into(), serde_json::from_slice(pb).unwrap());
        o.insert("sig".into(), Base64UrlUnpadded::encode_string(sig).into());
        if let Some(k) = key {
            o.insert("key".into(), k);
        }
        serde_json::to_vec(&o).unwrap()
    }
    pub fn signer(pk: &test_fixtures::PoolKey) -> cyphr::signer::SoftwareSigner {
        cyphr::signer::SoftwareSigner::new(
            &pk.alg,
            &Base64UrlUnpadded::decode_vec(pk.prv.as_ref().unwrap()).unwrap(),
            &Base64UrlUnpadded::decode_vec(&pk.pub_key).unwrap(),
            &pk.compute_tmb().unwrap(),
        )
    }
    /// The commit/create blob of `c`.
    pub fn cc_blob(c: &cyphr::commit::Commit) -> Vec<u8> {
        serde_json::to_vec(c.commit_tx().0.last().unwrap().raw()).unwrap()
    }
    pub async fn push<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
        id: &str,
        blobs: &[Vec<u8>],
    ) -> Result<IngestResult, EngineError> {
        e.submit_commit(id, None, &super::wire(blobs)).await
    }

    /// Push `pk`'s genesis commit at `T` (SPEC 5.1: `pk` creates itself,
    /// then the principal), as a server push with no caller genesis does.
    /// Returns the principal's id (its PG) and its client state.
    pub async fn established<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
        pk: &test_fixtures::PoolKey,
    ) -> (String, cyphr::Principal) {
        let id = genesis_principal_id(&Genesis::Implicit(dk(pk))).unwrap();
        let mut client = cyphr::Principal::implicit(dk(pk)).await.unwrap();
        let blobs = test_fixtures::bundle::genesis_bundle(&mut client, pk, &[], T)
            .await
            .unwrap();
        e.submit_commit(&id, None, &blobs)
            .await
            .expect("genesis commit");
        (id, client)
    }

    /// The attacker principal (bob) adds the victim's (alice) public key.
    pub async fn attacker_with_victim_key<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
    ) -> (String, cyphr::Principal) {
        let p = pool();
        let (bob, alice) = (p.get("bob").unwrap(), p.get("alice").unwrap());
        let (aid, mut client) = established(e, bob).await;
        let (pb, sig, czd) = sign(
            bob,
            serde_json::json!({
                "alg": bob.alg, "id": alice.compute_tmb_b64().unwrap(), "now": T + 1,
                "tmb": bob.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
        );
        let kc = blob(&pb, &sig, Some(kj(alice)));
        let mut s = client.begin_commit();
        s.verify_and_apply(&pb, &sig, czd, Some(dk(alice))).unwrap();
        let c = s
            .finalize_with_software(&signer(bob), T + 2, "cyphr.me")
            .await
            .unwrap();
        let cc = cc_blob(c);
        push(e, &aid, &[kc, cc])
            .await
            .expect("attacker adds the victim's public key");
        (aid, client)
    }

    /// What a scenario leaves behind.
    pub struct Outcome {
        pub vid: String,
        pub aid: String,
        /// The replayed coz's czd.
        pub czd: cyphr::state::TaggedDigest,
        /// The victim's own push, made after the attacker replayed first.
        pub victim_push: Result<IngestResult, EngineError>,
    }

    fn tagged(czd: &coz::Czd) -> cyphr::state::TaggedDigest {
        format!(
            "SHA-256:{}",
            Base64UrlUnpadded::encode_string(czd.as_bytes())
        )
        .parse()
        .unwrap()
    }

    /// F-A: the attacker replays the victim's signed `key/create(golden)`
    /// in its own commit first; the victim then pushes the same coz in its
    /// own commit.
    pub async fn replay_transaction<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
    ) -> Outcome {
        let p = pool();
        let (alice, golden, bob) = (
            p.get("alice").unwrap(),
            p.get("golden").unwrap(),
            p.get("bob").unwrap(),
        );
        let (vid, mut vclient) = established(e, alice).await;
        let (vpb, vsig, vczd) = sign(
            alice,
            serde_json::json!({
                "alg": alice.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 10,
                "tmb": alice.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
        );
        let vkc = blob(&vpb, &vsig, Some(kj(golden)));
        let mut vs = vclient.begin_commit();
        vs.verify_and_apply(&vpb, &vsig, vczd.clone(), Some(dk(golden)))
            .unwrap();
        let vc = vs
            .finalize_with_software(&signer(alice), T + 11, "cyphr.me")
            .await
            .unwrap();
        let vcc = cc_blob(vc);

        let (aid, mut aclient) = attacker_with_victim_key(e).await;
        let mut s = aclient.begin_commit();
        s.verify_and_apply(&vpb, &vsig, vczd.clone(), Some(dk(golden)))
            .unwrap();
        let c = s
            .finalize_with_software(&signer(bob), T + 12, "cyphr.me")
            .await
            .unwrap();
        push(e, &aid, &[vkc.clone(), cc_blob(c)])
            .await
            .expect("the attacker's replay is accepted");
        let victim_push = push(e, &vid, &[vkc, vcc]).await;
        Outcome {
            vid,
            aid,
            czd: tagged(&vczd),
            victim_push,
        }
    }

    /// F-B: the victim commits a signed action; the attacker replays the
    /// same action in its own commit.
    pub async fn replay_action<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
    ) -> Outcome {
        replay_action_ordered(e, false, "alice", "cyphr.me/action").await
    }

    /// [`replay_action`] with the pushes in either order and the attacker
    /// disclosing the pool key `attacker_discloses` in the unsigned `key`
    /// member of its copy of the action (the victim discloses its own).
    pub async fn replay_action_ordered<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
        attacker_first: bool,
        attacker_discloses: &str,
        typ: &str,
    ) -> Outcome {
        let p = pool();
        let (alice, golden, bob) = (
            p.get("alice").unwrap(),
            p.get("golden").unwrap(),
            p.get("bob").unwrap(),
        );
        let (vid, mut vclient) = established(e, alice).await;
        let (apb, asig, aczd) = sign(
            alice,
            serde_json::json!({
                "alg": alice.alg, "msg": "victim says hi", "now": T + 20,
                "tmb": alice.compute_tmb_b64().unwrap(), "typ": typ}),
        );
        let act = blob(&apb, &asig, Some(kj(alice)));
        let act_a = blob(&apb, &asig, Some(kj(p.get(attacker_discloses).unwrap())));
        let (vkpb, vksig, vkczd) = sign(
            alice,
            serde_json::json!({
                "alg": alice.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 21,
                "tmb": alice.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
        );
        let vkc = blob(&vkpb, &vksig, Some(kj(golden)));
        vclient
            .verify_and_record_action(&apb, &asig, aczd.clone())
            .unwrap();
        let mut vs = vclient.begin_commit();
        vs.verify_and_apply(&vkpb, &vksig, vkczd, Some(dk(golden)))
            .unwrap();
        let vc = vs
            .finalize_with_software(&signer(alice), T + 22, "cyphr.me")
            .await
            .unwrap();
        let vbundle = vec![act, vkc, cc_blob(vc)];

        let (aid, mut aclient) = attacker_with_victim_key(e).await;
        let (kpb, ksig, kczd) = sign(
            bob,
            serde_json::json!({
                "alg": bob.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 23,
                "tmb": bob.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
        );
        let kc = blob(&kpb, &ksig, Some(kj(golden)));
        aclient
            .verify_and_record_action(&apb, &asig, aczd.clone())
            .unwrap();
        let mut s = aclient.begin_commit();
        s.verify_and_apply(&kpb, &ksig, kczd, Some(dk(golden)))
            .unwrap();
        let c = s
            .finalize_with_software(&signer(bob), T + 24, "cyphr.me")
            .await
            .unwrap();
        let abundle = vec![act_a, kc, cc_blob(c)];

        let victim_push = if attacker_first {
            push(e, &aid, &abundle)
                .await
                .expect("the attacker's replay of the action is accepted");
            push(e, &vid, &vbundle).await
        } else {
            let r = push(e, &vid, &vbundle).await;
            push(e, &aid, &abundle)
                .await
                .expect("the attacker's replay of the action is accepted");
            r
        };
        Outcome {
            vid,
            aid,
            czd: tagged(&aczd),
            victim_push,
        }
    }

    pub async fn holder_ids<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
        d: &cyphr::state::TaggedDigest,
    ) -> Vec<String> {
        e.indexer()
            .resolve_digest_holders(d)
            .await
            .unwrap()
            .into_iter()
            .filter_map(|h| h.principal_id)
            .collect()
    }

    pub fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    type Fjall = StorageEngine<cyphr_blob_fjall::FjallBlobStore, cyphr_index_fjall::FjallIndexer>;

    pub fn fjall_engine(dir: &std::path::Path) -> Fjall {
        StorageEngine::new(
            cyphr_blob_fjall::FjallBlobStore::open(&dir.join("blobs")).unwrap(),
            cyphr_index_fjall::FjallIndexer::open(&dir.join("index")).unwrap(),
        )
    }

    type Mem = StorageEngine<MemoryBlobStore, MemoryIndexer>;

    pub fn mem_engine() -> Mem {
        StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
    }

    /// F-A claim: a coz someone else replayed first does not block the
    /// victim, and the replayed coz resolves to both principals.
    pub async fn assert_victim_not_blocked<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
    ) {
        let o = replay_transaction(e).await;
        assert!(o.victim_push.is_ok(), "victim refused: {:?}", o.victim_push);
        assert_eq!(
            sorted(holder_ids(e, &o.czd).await),
            sorted(vec![o.vid, o.aid])
        );
    }

    /// F-B claim: a replayed action resolves to every principal that
    /// committed it, never to the replayer alone.
    pub async fn assert_action_resolves_to_both<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
    ) {
        let o = replay_action(e).await;
        assert!(o.victim_push.is_ok(), "victim refused: {:?}", o.victim_push);
        assert_eq!(
            sorted(holder_ids(e, &o.czd).await),
            sorted(vec![o.vid, o.aid])
        );
    }

    /// Backs F-A (see `assert_victim_not_blocked`) on the durable backend, the
    /// only backend the server runs.
    #[tokio::test]
    async fn replay_victim_transaction_does_not_block_victim_fjall() {
        let dir = tempfile::tempdir().unwrap();
        assert_victim_not_blocked(&fjall_engine(dir.path())).await;
    }

    /// Backs F-B (see `assert_action_resolves_to_both`) on the durable backend.
    #[tokio::test]
    async fn replay_victim_action_resolves_to_both_principals_fjall() {
        let dir = tempfile::tempdir().unwrap();
        assert_action_resolves_to_both(&fjall_engine(dir.path())).await;
    }

    /// F-C claim: a store holding one coz under two principals restarts and
    /// rebuilds; every principal is served afterwards.
    pub async fn assert_restart_survives<B: BlobStore, I: Indexer + IndexerWrite>(
        first: StorageEngine<B, I>,
        reopen: impl FnOnce(StorageEngine<B, I>) -> StorageEngine<B, I>,
    ) {
        let o = replay_transaction(&first).await;
        let tips = (
            first.get_tip(&o.aid).await.unwrap().map(|t| t.commit_count),
            first.get_tip(&o.vid).await.unwrap().map(|t| t.commit_count),
        );
        let e = reopen(first);
        let after = (
            e.get_tip(&o.aid)
                .await
                .expect("attacker served after restart")
                .map(|t| t.commit_count),
            e.get_tip(&o.vid)
                .await
                .expect("victim served after restart")
                .map(|t| t.commit_count),
        );
        assert_eq!(after, tips, "restart changed what is served");
        e.rebuild_index_from_scratch()
            .await
            .expect("scratch rebuild");
        assert_eq!(
            e.get_tip(&o.vid).await.unwrap().map(|t| t.commit_count),
            tips.1
        );
        assert_eq!(
            sorted(holder_ids(&e, &o.czd).await),
            sorted(vec![o.vid, o.aid])
        );
    }

    /// Backs F-C (see `assert_restart_survives`): a real close and reopen of the
    /// durable stores.
    #[tokio::test]
    async fn replay_store_with_one_coz_under_two_principals_restarts_fjall() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        assert_restart_survives(fjall_engine(&path), |old| {
            drop(old);
            fjall_engine(&path)
        })
        .await;
    }

    /// A blob store whose `iter` order is a seeded permutation of the
    /// stored blobs, to show that a rebuild does not depend on it.
    #[derive(Clone)]
    pub struct ShuffledBlobs {
        pub inner: MemoryBlobStore,
        pub seed: Arc<AtomicU64>,
    }

    impl BlobStore for ShuffledBlobs {
        async fn persist(&self) -> Result<(), BlobStoreError> {
            self.inner.persist().await
        }

        fn put(
            &self,
            data: &[u8],
        ) -> impl Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
            self.inner.put(data)
        }

        fn get(
            &self,
            hash: &Blake3Hash,
        ) -> impl Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send {
            self.inner.get(hash)
        }

        fn exists(
            &self,
            hash: &Blake3Hash,
        ) -> impl Future<Output = Result<bool, BlobStoreError>> + Send {
            self.inner.exists(hash)
        }

        fn iter(
            &self,
        ) -> impl Future<
            Output = Result<
                Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>,
                BlobStoreError,
            >,
        > + Send {
            let inner = self.inner.clone();
            let seed = self.seed.load(Ordering::SeqCst);
            async move {
                let mut hashes: Vec<Blake3Hash> = inner.iter().await?.collect::<Result<_, _>>()?;
                hashes.sort_by_key(|h| {
                    let mut k = seed.to_le_bytes().to_vec();
                    k.extend_from_slice(h.as_bytes());
                    *blake3::hash(&k).as_bytes()
                });
                let it: Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send> =
                    Box::new(hashes.into_iter().map(Ok));
                Ok(it)
            }
        }
    }

    async fn snapshot<B: BlobStore, I: Indexer + IndexerWrite>(
        e: &StorageEngine<B, I>,
        czd: &cyphr::state::TaggedDigest,
    ) -> String {
        let mut out = Vec::new();
        let mut probes = vec![czd.clone()];
        let mut principals = e.indexer().list_principals().await.unwrap();
        principals.sort_by(|a, b| a.principal_id.cmp(&b.principal_id));
        for p in &principals {
            out.push(format!(
                "{p:?} {:?}",
                e.indexer().get_tip(&p.principal_id).await.unwrap()
            ));
            for c in e
                .indexer()
                .get_commit_chain(&p.principal_id, None, None)
                .await
                .unwrap()
            {
                out.push(format!("{c:?}"));
                for d in [
                    Some(&c.commit_id),
                    Some(&c.pr),
                    c.sr.as_ref(),
                    c.ar.as_ref(),
                    Some(&c.cr),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(t) = d.parse::<cyphr::state::TaggedDigest>() {
                        probes.push(t);
                    }
                }
            }
        }
        probes.sort_by_key(|d| d.to_string());
        probes.dedup();
        for d in &probes {
            out.push(format!(
                "{d} {:?}",
                e.indexer().resolve_digest_holders(d).await.unwrap()
            ));
        }
        out.join("\n")
    }

    /// Property: whatever order the blob store lists its blobs in, a scratch
    /// rebuild gives the same index (tips, chains, and the holders of every
    /// digest, including the coz stored under two principals), on both
    /// index backends. Turns red if the index depends on manifest order.
    #[test]
    fn order_independent_rebuild_of_a_store_with_a_replayed_coz() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let blobs = MemoryBlobStore::new();
        let czd = rt.block_on(async {
            let e = StorageEngine::new(blobs.clone(), MemoryIndexer::new());
            replay_transaction(&e).await.czd
        });
        let seed = Arc::new(AtomicU64::new(0));
        let shuffled = ShuffledBlobs {
            inner: blobs,
            seed: seed.clone(),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut runner = proptest::test_runner::TestRunner::new(super::config());
        runner
            .run(&proptest::prelude::any::<u64>(), |s| {
                rt.block_on(async {
                    let mut seen = Vec::new();
                    for backend in 0..2 {
                        seed.store(s, Ordering::SeqCst);
                        let snap = if backend == 0 {
                            let e = StorageEngine::new(shuffled.clone(), MemoryIndexer::new());
                            e.rebuild_index_from_scratch()
                                .await
                                .expect("memory rebuild");
                            snapshot(&e, &czd).await
                        } else {
                            let sub = dir.path().join(format!("{s}"));
                            let e = StorageEngine::new(
                                shuffled.clone(),
                                cyphr_index_fjall::FjallIndexer::open(&sub).unwrap(),
                            );
                            e.rebuild_index_from_scratch().await.expect("fjall rebuild");
                            snapshot(&e, &czd).await
                        };
                        seen.push(snap);
                    }
                    proptest::prop_assert_eq!(&seen[0], &seen[1]);
                    // The reference order: seed 0 on memory.
                    seed.store(0, Ordering::SeqCst);
                    let e = StorageEngine::new(shuffled.clone(), MemoryIndexer::new());
                    e.rebuild_index_from_scratch()
                        .await
                        .expect("reference rebuild");
                    proptest::prop_assert_eq!(&seen[0], &snapshot(&e, &czd).await);
                    Ok(())
                })
            })
            .unwrap();
    }
}

/// Claim: a manifest the rebuild cannot index is quarantined with a typed
/// reason; it never fails the rebuild or hides the honest manifests beside
/// it, and the report is the same on every run. Here a prefixed blob that is
/// not JSON, and a well-formed manifest naming a blob the store does not
/// hold. Turns red if either aborts the rebuild.
#[tokio::test]
async fn rebuild_quarantines_unindexable_manifests() {
    let e = engine();
    submit_honest(&e, &load_golden("edge_cases", "transaction_replay_order")).await;
    let honest = principals(&e).await;
    let mut garbage = cyphr_storage::engine::COMMIT_MANIFEST_PREFIX.to_vec();
    garbage.extend_from_slice(b"not json");
    cyphr_storage::blob::BlobStore::put(e.blob_store(), &garbage)
        .await
        .unwrap();
    let mut missing = forged(&fake_digest(0x80), 0, 0x81);
    missing.blob_hashes = vec![Blake3Hash::from_bytes([0x82; 32])];
    missing.cozies[0].blob_hash = Blake3Hash::from_bytes([0x82; 32]);
    plant_manifest(&e, &missing).await;

    let first = e
        .rebuild_index_with_report()
        .await
        .expect("rebuild survives");
    let again = e.rebuild_index_with_report().await.expect("and again");
    assert_eq!(first, again, "the report is deterministic");
    let reasons: Vec<_> = first.quarantined.iter().map(|q| &q.reason).collect();
    assert_eq!(reasons.len(), 2, "{first:?}");
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, QuarantineReason::Malformed(_)))
    );
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, QuarantineReason::Unsupported(_)))
    );
    assert_eq!(first.indexed, 3, "the honest commits are indexed");
    assert_eq!(principals(&e).await, honest);
}

/// Claim (`/e/{czd}` stays content-addressed): the unsigned `key` member
/// is kept only on a key-introducing coz, so two holders replaying one
/// action with different `key` members store exactly one blob, and the
/// bytes `/e/{czd}` serves are the same whichever holder arrived first
/// and carry no `key`. Turns red if a holder's copy keeps its own `key`
/// (then the served bytes are whatever the first or last replayer chose).
#[tokio::test]
async fn replay_key_member_does_not_split_a_czd_into_two_blobs() {
    let typ = "cyphr.me/action";
    let mut served = Vec::new();
    for attacker_first in [false, true] {
        let e = replay::mem_engine();
        let o = replay::replay_action_ordered(&e, attacker_first, "bob", typ).await;
        assert!(o.victim_push.is_ok(), "{:?}", o.victim_push);
        let holders = e.indexer().resolve_digest_holders(&o.czd).await.unwrap();
        assert_eq!(holders.len(), 2, "both principals hold the action");
        assert_eq!(
            holders[0].blob_hash, holders[1].blob_hash,
            "one czd, two blobs"
        );
        let bytes = e.get_entity(&o.czd).await.unwrap().expect("served");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v.get("key").is_none(), "an action keeps no key member");
        served.push(bytes);
    }
    assert_eq!(served[0], served[1], "/e/{{czd}} depends on arrival order");
}

/// Claim (SPEC 2.3.2, "data actions require DT commit inclusion"): a new
/// principal cannot be created by an action-only bundle. The action's
/// disclosed `key` is not kept (an action introduces no key), so with
/// no caller genesis and no `commit/create` in the bundle the push gets a
/// typed refusal and leaves no principal and no tip. Turns red if a
/// disclosed key on an action still bootstraps a principal.
#[tokio::test]
async fn action_only_bundle_cannot_create_a_principal() {
    let e = engine();
    let fx = load_golden("errors", "action_without_genesis_fails");
    let (_, aid) = genesis_of(&fx);
    let blobs: Vec<Vec<u8>> = raw_blobs_disclosing_genesis(&fx, &fx["commits"][0])
        .iter()
        .map(|b| serde_json::to_vec(b).unwrap())
        .collect();
    let err = submit_as_witness(&e, &aid, &blobs)
        .await
        .expect_err("refused");
    assert!(
        matches!(err, EngineError::Protocol(cyphr::Error::GenesisIncomplete)),
        "{err:?}"
    );
    assert!(e.get_tip(&aid).await.unwrap().is_none());
    assert!(principals(&e).await.is_empty());
}

/// F-E claim: whatever key material a replayer attaches to a replayed
/// key/create, one czd stores one blob. The attacker replays the victim's
/// signed key/create with a `keys` entry carrying a chosen `tag` and `now`
/// (neither is signed); the victim's blob and the attacker's are the same
/// blob, which holds no key, and the stored key keeps only `alg`, `pub`
/// and `tmb`. Turns red if any unsigned key member survives
/// canonicalization.
#[tokio::test]
async fn replayed_key_create_sidecar_cannot_split_the_czd() {
    use replay::*;
    let e = mem_engine();
    let p = pool();
    let (alice, golden, bob) = (
        p.get("alice").unwrap(),
        p.get("golden").unwrap(),
        p.get("bob").unwrap(),
    );
    let (vid, mut vclient) = established(&e, alice).await;
    let (xpb, xsig, xczd) = sign(
        alice,
        serde_json::json!({
            "alg": alice.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 10,
            "tmb": alice.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
    );
    let honest = blob(&xpb, &xsig, Some(kj(golden)));
    let mut sidecar = kj(golden);
    sidecar["tag"] = "ATTACKER-CHOSEN".into();
    sidecar["now"] = 1.into();
    let evil = blob(&xpb, &xsig, Some(sidecar));
    let mut vs = vclient.begin_commit();
    vs.verify_and_apply(&xpb, &xsig, xczd.clone(), Some(dk(golden)))
        .unwrap();
    let vc = vs
        .finalize_with_software(&signer(alice), T + 11, "cyphr.me")
        .await
        .unwrap();
    let victim = push(&e, &vid, &[honest, cc_blob(vc)]).await.unwrap();

    let (aid, mut aclient) = attacker_with_victim_key(&e).await;
    let mut s = aclient.begin_commit();
    s.verify_and_apply(&xpb, &xsig, xczd, Some(dk(golden)))
        .unwrap();
    let c = s
        .finalize_with_software(&signer(bob), T + 12, "cyphr.me")
        .await
        .unwrap();
    let attacker = push(&e, &aid, &[evil, cc_blob(c)]).await.unwrap();

    assert_eq!(
        victim.blob_hashes[0], attacker.blob_hashes[0],
        "one czd, two blobs"
    );
    let stored = cyphr_storage::blob::BlobStore::get(e.blob_store(), &victim.blob_hashes[0])
        .await
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert!(v.get("key").is_none(), "a stored coz holds no key: {v}");
    let served = e.get_patch(&aid, None, None).await.unwrap();
    let keys = &served.entries.last().unwrap().bundle.keys;
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert!(
        keys[0].tag.is_none() && keys[0].now.is_none(),
        "unsigned key members kept: {keys:?}"
    );
}

/// F-F claim: a `commit/create` keeps no `key` (it introduces none; a
/// genesis is read only from its commit's `key/create`s, SPEC 5.1). A
/// relayer attaches Bob's self-consistent key to the victim's signed
/// later `commit/create`; it must be stored without it. Turns red if a
/// foreign key survives on a commit/create.
#[tokio::test]
async fn relayed_commit_create_cannot_carry_a_foreign_key() {
    use replay::*;
    let e = mem_engine();
    let p = pool();
    let (alice, golden, bob) = (
        p.get("alice").unwrap(),
        p.get("golden").unwrap(),
        p.get("bob").unwrap(),
    );
    let (vid, mut vclient) = established(&e, alice).await;
    let (xpb, xsig, xczd) = sign(
        alice,
        serde_json::json!({
            "alg": alice.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 10,
            "tmb": alice.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/create"}),
    );
    let x = blob(&xpb, &xsig, Some(kj(golden)));
    let mut s = vclient.begin_commit();
    s.verify_and_apply(&xpb, &xsig, xczd, Some(dk(golden)))
        .unwrap();
    let c = s
        .finalize_with_software(&signer(alice), T + 11, "cyphr.me")
        .await
        .unwrap();
    push(&e, &vid, &[x, cc_blob(c)]).await.unwrap();

    let (dpb, dsig, dczd) = sign(
        alice,
        serde_json::json!({
            "alg": alice.alg, "id": golden.compute_tmb_b64().unwrap(), "now": T + 20,
            "tmb": alice.compute_tmb_b64().unwrap(), "typ": "cyphr.me/cyphr/key/delete"}),
    );
    let del = blob(&dpb, &dsig, None);
    let mut s = vclient.begin_commit();
    s.verify_and_apply(&dpb, &dsig, dczd, None).unwrap();
    let c = s
        .finalize_with_software(&signer(alice), T + 21, "cyphr.me")
        .await
        .unwrap();
    let mut relayed_cc: serde_json::Value = serde_json::from_slice(&cc_blob(c)).unwrap();
    relayed_cc["key"] = kj(bob);
    let relayed_cc = serde_json::to_vec(&relayed_cc).unwrap();
    let relayed = push(&e, &vid, &[del, relayed_cc]).await.unwrap();

    let stored = cyphr_storage::blob::BlobStore::get(e.blob_store(), &relayed.blob_hashes[1])
        .await
        .unwrap()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert!(v.get("key").is_none(), "a foreign key was kept: {v}");
    let served = e.get_patch(&vid, None, None).await.unwrap();
    let keys = &served.entries.last().unwrap().bundle.keys;
    assert!(
        keys.is_empty(),
        "a foreign key was kept for the commit: {keys:?}"
    );
}
