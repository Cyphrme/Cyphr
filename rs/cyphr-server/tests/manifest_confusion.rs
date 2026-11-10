//! Manifest confusion over `POST /push` (finding H1).
//!
//! Claim: bytes an untrusted client pushes can never be mistaken for the
//! engine's own commit manifest. `push` stores each blob raw in the blob
//! store that also holds the engine's `CommitManifest` blobs, and
//! `rebuild_index_from_manifests` (run on every `serve` start, and by
//! `rebuild_index_from_scratch`) treats ANY blob that deserializes as
//! `{kind, commit}` with the manifest `kind` as authoritative index
//! input. A coz envelope is `{pay, sig, key?}` and the signature covers
//! only `pay`, so an attacker can add top-level `kind` and `commit`
//! members to an otherwise valid, signed coz of their OWN principal.
//!
//! Fix-agnostic by construction: each red test accepts a 201 OR a 4xx on
//! the crafted push (a fix that rejects at ingest) and then runs the
//! rebuild and the index assertions either way, which hold for both
//! "reject at ingest" and "store but never interpret as a manifest".
//! Each of these failed on its index assertion, after the crafted push
//! was accepted, before the manifest keyspace separated manifests from
//! wire blobs.
//!
//! Each red test is an end-to-end scenario (push over HTTP, rebuild,
//! observe through the index and the served routes). Mutants named per
//! test below. The green controls rule out non-fixes: a rebuild blinded
//! to all manifests, and a rebuild that trusts manifests only for
//! principals not yet indexed (which a scratch rebuild defeats, since
//! after `clear` nothing is indexed).

use std::sync::Arc;

use axum::http::StatusCode;
use cyphr_server::{AppState, build_router};
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{IndexableCommit, IndexableCoz, Indexer, TipState};

mod common;

use common::{
    build_genesis_push_body, build_genesis_push_body_with, genesis_push_id, get_json,
    golden_principal_id, keyless_server, load_pool, post_json,
};
use coz::base64ct::{Base64UrlUnpadded, Encoding};

const MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// A well-formed (parseable) tagged digest, distinct per `tag`.
fn fake_digest(tag: u8) -> String {
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[tag; 32]))
}

/// What the attacker wants the rebuilt index to believe.
struct Forge {
    principal_id: String,
    sequence: u64,
    /// Primary commit id; may deliberately equal a victim's real digest.
    commit_id: String,
    pg: Vec<String>,
    /// Blob the forged entity should resolve to.
    blob_hash: Blake3Hash,
}

impl Forge {
    fn naming(principal_id: &str, tag: u8) -> Self {
        Forge {
            principal_id: principal_id.to_string(),
            sequence: 1,
            commit_id: fake_digest(tag),
            pg: Vec::new(),
            blob_hash: Blake3Hash::from_bytes([tag; 32]),
        }
    }

    fn commit(&self) -> IndexableCommit {
        let tag = fake_digest(0xF0);
        IndexableCommit {
            pg: self.pg.clone(),
            principal_id: self.principal_id.clone(),
            commit_ids: vec![self.commit_id.clone()],
            sequence: self.sequence,
            pre: None,
            prs: vec![fake_digest(0xF1)],
            srs: vec![fake_digest(0xF2)],
            ars: vec![fake_digest(0xF3)],
            crs: vec![fake_digest(0xF4)],
            blob_hashes: vec![self.blob_hash],
            cozies: vec![IndexableCoz {
                blob_hash: self.blob_hash,
                czd: tag,
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
}

/// Re-encode the push body with `kind` and `commit` added to the closing
/// coz's top level (outside `pay`, so the signature still verifies).
fn with_forged_manifest(body: &str, forge: &Forge) -> String {
    let mut v: serde_json::Value = serde_json::from_str(body).unwrap();
    let last = v["txs"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap()
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    let mut coz: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(last.as_str().unwrap()).unwrap())
            .unwrap();
    let obj = coz.as_object_mut().unwrap();
    obj.insert("kind".into(), MANIFEST_KIND.into());
    obj.insert(
        "commit".into(),
        serde_json::to_value(forge.commit()).unwrap(),
    );
    *last = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).unwrap()).into();
    v.to_string()
}

/// Principal summaries as comparable `(id, pr, commit_count)` triples.
async fn principals(state: &AppState) -> Vec<(String, String, u64)> {
    let mut p: Vec<_> = state
        .engine
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

/// A server with one honest victim (golden) pushed.
struct World {
    state: Arc<AppState>,
    app: axum::Router,
    pool: test_fixtures::Pool,
    victim: String,
    before: TipState,
    before_principals: Vec<(String, String, u64)>,
    _dir: tempfile::TempDir,
}

async fn world() -> World {
    let pool = load_pool();
    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    let victim = golden_principal_id(&pool).await;
    let (s, b) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &victim, 1_700_000_000).await,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "victim genesis push: {b:?}");
    let before = state.engine.get_tip(&victim).await.unwrap().unwrap();
    let before_principals = principals(&state).await;
    World {
        state,
        app,
        pool,
        victim,
        before,
        before_principals,
        _dir: dir,
    }
}

impl World {
    /// Index principals other than the attacker's own, which the crafted
    /// push legitimately creates when it is accepted.
    async fn others(&self) -> Vec<(String, String, u64)> {
        let attacker = genesis_push_id(&self.pool, "alice", "carol").await;
        let mut p = principals(&self.state).await;
        p.retain(|x| !x.0.ends_with(cyphr_storage::engine::bare_digest(&attacker)));
        p
    }

    /// The attacker (alice, an independent principal) pushes a validly
    /// signed genesis carrying `forge`. Returns the status; a fix may
    /// refuse (4xx) or accept (201), but never anything else.
    async fn push_forged(&self, forge: &Forge) -> StatusCode {
        let attacker = genesis_push_id(&self.pool, "alice", "carol").await;
        let honest =
            build_genesis_push_body_with(&self.pool, "alice", "carol", &attacker, 1_700_000_001)
                .await;
        let (s, b) = post_json(
            self.app.clone(),
            "/push",
            with_forged_manifest(&honest, forge),
        )
        .await;
        assert!(
            s == StatusCode::CREATED || s.is_client_error(),
            "crafted push must be accepted or refused, not fail: {s} {b:?}"
        );
        s
    }

    /// The victim's own first-blob hash helper for attacker-controlled
    /// content: the attacker's honest key/create blob (raw, as stored).
    async fn attacker_blob_hash(&self) -> Blake3Hash {
        let attacker = genesis_push_id(&self.pool, "alice", "carol").await;
        let body =
            build_genesis_push_body_with(&self.pool, "alice", "carol", &attacker, 1_700_000_001)
                .await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let raw = Base64UrlUnpadded::decode_vec(v["txs"][0][0].as_str().unwrap()).unwrap();
        Blake3Hash::from_bytes(*blake3::hash(&raw).as_bytes())
    }

    async fn assert_victim_intact(&self) {
        let after = self
            .state
            .engine
            .get_tip(&self.victim)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after, self.before, "victim tip must be untouched");
        let (s, tip) = get_json(self.app.clone(), &format!("/tip?pr={}", self.victim)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            common::envelope_payload(&tip)["commit_count"].as_u64(),
            Some(self.before.commit_count),
            "served commit_count must not grow"
        );
    }
}

/// E2E. Claim: another principal's pushed coz cannot rewrite a
/// victim's index entry on rebuild. Mutant caught: today's rebuild, and
/// any fix that still interprets a wire blob as a manifest (e.g. only
/// checking `kind`). Fails on tip equality / principal list / forged
/// commit id lookup, after the crafted push was accepted.
#[tokio::test]
async fn pushed_coz_cannot_rewrite_victim_index_on_rebuild() {
    let w = world().await;
    let forge = Forge::naming(&w.before.principal_id, 0xA1);
    w.push_forged(&forge).await;

    w.state.engine.rebuild_index_from_manifests().await.unwrap();

    w.assert_victim_intact().await;
    assert_eq!(w.others().await, w.before_principals);
    let forged: cyphr::state::TaggedDigest = forge.commit_id.parse().unwrap();
    assert!(
        w.state
            .engine
            .indexer()
            .resolve_digest(&forged)
            .await
            .unwrap()
            .is_none(),
        "the forged commit id must not be in the index"
    );
    assert!(w.state.engine.get_entity(&forged).await.unwrap().is_none());
}

/// E2E. Claim: a pushed coz cannot invent a principal that was
/// never pushed. Mutant caught: a fix that guards only already-indexed
/// principals (the phantom is unindexed, so it slips through).
#[tokio::test]
async fn pushed_coz_cannot_invent_a_principal_on_rebuild() {
    let w = world().await;
    let phantom = fake_digest(0xB0);
    w.push_forged(&Forge::naming(&phantom, 0xB1)).await;

    w.state.engine.rebuild_index_from_manifests().await.unwrap();

    assert!(
        w.state.engine.get_tip(&phantom).await.unwrap().is_none(),
        "a never-pushed principal must have no tip"
    );
    assert_eq!(w.others().await, w.before_principals);
}

/// E2E, scratch variant. Same claims after a FULL index wipe
/// (`rebuild_index_from_scratch`). Mutant caught: the non-fix "trust
/// manifests only for principals not yet indexed": after `clear` nothing
/// is indexed, so the phantom (and a tie-sequence forgery of the victim)
/// is trusted again.
#[tokio::test]
async fn pushed_coz_cannot_poison_a_scratch_rebuild() {
    let w = world().await;
    let phantom = fake_digest(0xC0);
    w.push_forged(&Forge::naming(&phantom, 0xC1)).await;

    w.state.engine.rebuild_index_from_scratch().await.unwrap();

    assert!(w.state.engine.get_tip(&phantom).await.unwrap().is_none());
    assert_eq!(w.others().await, w.before_principals);
    w.assert_victim_intact().await;
}

/// E2E. Claim: a pushed coz cannot plant a PG alias (aliases were
/// first-writer-wins in `index_commit`, so a forged first writer owned the
/// name for good). The forged commit claims a fresh digest as its own `pg`
/// variant. That digest resolves to nothing before the push (it is no
/// principal's id, PR or PG), so it must still resolve to nothing after the
/// push and a rebuild: any answer would come from the alias table.
/// Mutant caught: a fix that validates `principal_id` but leaves `pg`
/// unchecked.
#[tokio::test]
async fn pushed_coz_cannot_plant_a_pg_alias_on_rebuild() {
    let w = world().await;
    let planted = fake_digest(0xD2);
    assert!(
        w.state.engine.get_tip(&planted).await.unwrap().is_none(),
        "control: the probe digest resolves to nothing before the push"
    );

    let phantom = fake_digest(0xD0);
    let mut forge = Forge::naming(&phantom, 0xD1);
    forge.pg = vec![planted.clone()];
    w.push_forged(&forge).await;

    w.state.engine.rebuild_index_from_manifests().await.unwrap();

    assert!(
        w.state.engine.get_tip(&planted).await.unwrap().is_none(),
        "a forged pg must not create an alias: the probe digest resolves to nothing"
    );
    assert!(w.state.engine.get_tip(&phantom).await.unwrap().is_none());
    w.assert_victim_intact().await;
}

/// E2E. Claim: a pushed coz cannot redirect the digest index.
/// The forged commit (under a phantom principal) reuses the victim's real
/// commit id and points its blob at attacker bytes, so `GET /e/{digest}`
/// for the victim's commit would serve attacker content attributed to the
/// phantom. Mutant caught: a fix that only protects `tips`/`principals`
/// but leaves `digest_index` writable.
#[tokio::test]
async fn pushed_coz_cannot_redirect_victim_digest_on_rebuild() {
    let w = world().await;
    let digest: cyphr::state::TaggedDigest = w.before.commit_id.parse().unwrap();
    let entity_before = w
        .state
        .engine
        .indexer()
        .resolve_digest(&digest)
        .await
        .unwrap()
        .unwrap();
    let bytes_before = w.state.engine.get_entity(&digest).await.unwrap().unwrap();

    let mut forge = Forge::naming(&fake_digest(0xE0), 0xE1);
    forge.commit_id = w.before.commit_id.clone();
    forge.blob_hash = w.attacker_blob_hash().await;
    w.push_forged(&forge).await;

    w.state.engine.rebuild_index_from_manifests().await.unwrap();

    let entity_after = w
        .state
        .engine
        .indexer()
        .resolve_digest(&digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        entity_after, entity_before,
        "victim digest must resolve as before"
    );
    assert_eq!(
        w.state.engine.get_entity(&digest).await.unwrap().unwrap(),
        bytes_before,
        "victim digest must serve the victim's bytes"
    );
}

/// Green control, E2E. Claim: a rebuild over honest state recovers
/// exactly the engine's own manifests and nothing else, and a scratch
/// rebuild restores byte-equal tips with `commit_count` unchanged.
/// Mutants caught: a rebuild blinded to manifests (count 0, or tips lost
/// after clear), one that double-counts, one that perturbs honest state.
#[tokio::test]
async fn rebuild_recovers_exactly_the_honest_manifests() {
    let w = world().await;
    let other = genesis_push_id(&w.pool, "alice", "carol").await;
    let (s, b) = post_json(
        w.app.clone(),
        "/push",
        build_genesis_push_body_with(&w.pool, "alice", "carol", &other, 1_700_000_100).await,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "second honest principal: {b:?}");
    let tip = w.state.engine.get_tip(&w.victim).await.unwrap().unwrap();
    let other_tip = w.state.engine.get_tip(&other).await.unwrap().unwrap();
    let listed = principals(&w.state).await;

    let n = w.state.engine.rebuild_index_from_manifests().await.unwrap();
    assert_eq!(n, 2, "exactly one manifest per honest commit");
    assert_eq!(
        w.state.engine.get_tip(&w.victim).await.unwrap().unwrap(),
        tip
    );
    assert_eq!(
        w.state.engine.get_tip(&other).await.unwrap().unwrap(),
        other_tip
    );

    let n = w.state.engine.rebuild_index_from_scratch().await.unwrap();
    assert_eq!(n, 2, "scratch rebuild recovers every honest manifest");
    assert_eq!(
        w.state.engine.get_tip(&w.victim).await.unwrap().unwrap(),
        tip
    );
    assert_eq!(
        w.state.engine.get_tip(&other).await.unwrap().unwrap(),
        other_tip
    );
    assert_eq!(principals(&w.state).await, listed);
}
