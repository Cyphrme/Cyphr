//! Evidence (`docs/architecture/equivocation-detection.md`): a server
//! serves the principal forks it holds at `GET /evidence`, and a client
//! checks them offline from signatures and the chain alone.
//!
//! Every test runs over real servers and real signed commits; the client
//! side is `cyphr_client::evidence`, fed only what it fetched.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::evidence::{EvidenceFailure, verify_principal_fork};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::{AppState, build_router};
use tempfile::TempDir;

mod common;

use common::{
    envelope_payload, get_json, golden_principal_id, keyed_appstate, load_pool, post_json,
    write_signing_key,
};

const NOW: i64 = 1_700_100_000;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        prv: pk
            .prv
            .as_ref()
            .map(|p| Base64UrlUnpadded::decode_vec(p).expect("prv b64"))
            .unwrap_or_default(),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// Apply `pay` signed by `signer` (optionally introducing `sidecar`) and
/// finalize the commit with `finalizer`.
async fn apply(
    p: &mut cyphr::Principal,
    signer: &Kp,
    finalizer: &Kp,
    pay: serde_json::Value,
    sidecar: Option<cyphr::Key>,
    now: i64,
) {
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &finalizer.alg,
                &finalizer.prv,
                &finalizer.pubb,
                &finalizer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .await
        .expect("finalize");
}

/// `signer` creates `new` at `now` and finalizes the commit. Distinct
/// `new`/`now` give distinct commits at one position.
async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    });
    apply(p, signer, signer, pay, Some(key_of(new)), now).await;
}

/// A principal over the genesis `keys` (the first signs) after its genesis
/// commit (SPEC 5.1) at `now`.
async fn genesis_commit(keys: &[&Kp], now: i64) -> cyphr::Principal {
    let mut p = cyphr::Principal::implicit(key_of(keys[0]))
        .await
        .expect("genesis");
    let others: Vec<cyphr::Key> = keys[1..].iter().map(|k| key_of(k)).collect();
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(
            &keys[0].alg,
            &keys[0].prv,
            &keys[0].pubb,
            &keys[0].tmb,
        ),
        &others,
        now,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    p
}

/// Push body for line `i` of `p`'s export under `id`, in the wire form
/// (SPEC 4.6.2): its keys travel in the bundle's `keys`, so commit 0 (the
/// genesis) reads from its record alone.
fn wire(p: &cyphr::Principal, i: usize, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    common::push_body(id, &entries[i].bundle().expect("bundle"))
}

async fn push(app: &axum::Router, body: String) -> (StatusCode, serde_json::Value) {
    post_json(app.clone(), "/push", body).await
}

/// A keyed server (an attestor) with its signing key file kept: `key_from`
/// copies another server's key, so two servers sign as one peer.
async fn attestor(key_from: Option<&Path>) -> (AppState, Arc<ServerIdentity>, TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = match key_from {
        Some(src) => {
            let dst = dir.path().join("signing-key.json");
            std::fs::copy(src, &dst).expect("copy the signing key");
            dst
        },
        None => write_signing_key(dir.path()),
    };
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");
    let sp = ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(sp));
    (state, identity, dir, key_path)
}

/// What a client holds of a principal after fetching `/patch` from `app`.
async fn fetch_entries(app: &axum::Router, pr: &str) -> Vec<cyphr_client::PatchEntry> {
    let (status, body) = get_json(app.clone(), &format!("/patch?pg={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    cyphr_client::verify_patch_body(&serde_json::to_vec(&body).expect("json"), pr, None)
        .expect("patch decodes")
        .entries
}

/// The signed coz of a server's `GET /tip`.
async fn tip_of(app: &axum::Router, pr: &str) -> serde_json::Value {
    let (status, body) = get_json(app.clone(), &format!("/tip?pg={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["statement"]["kind"], "signed", "{body:?}");
    body["statement"]["coz"].clone()
}

/// The principal both servers hold, as its genesis commit (`golden` with
/// `key_a`) and the state after it.
struct Pr {
    g: Kp,
    a: Kp,
    id: String,
    base: cyphr::Principal,
}

async fn principal() -> Pr {
    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let base = genesis_commit(&[&g, &a], NOW).await;
    // The bare spelling of the PG, which names the evidence's `pg`.
    let id = golden_principal_id(&pool)
        .await
        .split_once(':')
        .expect("labelled PG")
        .1
        .to_string();
    Pr { id, g, a, base }
}

impl Pr {
    /// The principal before its genesis commit: what a client replays the
    /// fetched chain onto.
    async fn genesis(&self) -> cyphr::Principal {
        cyphr::Principal::implicit(key_of(&self.g))
            .await
            .expect("genesis")
    }

    /// Another genesis commit of the same principal (same genesis keys,
    /// same PG), made at `now`.
    async fn other_genesis(&self, now: i64) -> cyphr::Principal {
        genesis_commit(&[&self.g, &self.a], now).await
    }

    /// The principal after a second commit by `signer` creating `new`.
    async fn extend(&self, signer: &Kp, new: &str, now: i64) -> cyphr::Principal {
        let mut p = self.base.fork().await.expect("fork");
        create_key(&mut p, signer, &kp(&load_pool(), new), now).await;
        p
    }

    async fn push_commit(&self, app: &axum::Router, p: &cyphr::Principal, i: usize) -> StatusCode {
        push(app, wire(p, i, &self.id)).await.0
    }
}

async fn evidence_items(app: &axum::Router, pr: &str) -> Vec<serde_json::Value> {
    let (status, body) = get_json(app.clone(), &format!("/evidence?pg={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["items"]
        .as_array()
        .expect("items array")
        .clone()
}

/// Claim: a principal forked by one of its keys shows the fork at
/// `GET /evidence`, both branches kept; a client checks the item offline
/// by replaying each commit from the shared state, with no server
/// signature involved (a keyless server serves it). An item naming another
/// principal, a tampered rival, a wrong `pre` and a chain too short to
/// reach the fork are each refused; a principal never forked yields no
/// items; a malformed id is 400 and an unknown principal 404 (so the
/// route, not a missing one, answers the harness probe).
///
/// Turns red if: the fork is not served, the item verifies only with the
/// server's word, or any of the refused shapes is accepted.
/// End-to-end scenario: yes.
// @docket: arch-principal-fork-evidence :: scripts/docket-run arch-principal-fork-evidence
// @docket: arch-both-branches-kept :: scripts/docket-run arch-both-branches-kept
// @docket: arch-evidence-is-portable :: scripts/docket-run arch-evidence-is-portable
#[tokio::test]
async fn fork_evidence_is_served_and_verified_offline() {
    let pr = principal().await;
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let pool = load_pool();

    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);
    assert!(
        evidence_items(&app, &pr.id).await.is_empty(),
        "a principal never forked has no evidence"
    );

    let canonical = pr.extend(&pr.g, "key_b", NOW + 1).await;
    let rival = pr.extend(&pr.g, "alice", NOW + 2).await;
    assert_eq!(
        pr.push_commit(&app, &canonical, 1).await,
        StatusCode::CREATED
    );
    assert_eq!(
        pr.push_commit(&app, &rival, 1).await,
        StatusCode::CONFLICT,
        "the fork is refused as the tip"
    );

    let items = evidence_items(&app, &pr.id).await;
    assert_eq!(items.len(), 1, "{items:?}");
    let item = &items[0];
    let held = fetch_entries(&app, &pr.id).await;
    let genesis = async || pr.genesis().await;

    let proof = verify_principal_fork(item, &pr.id, genesis().await, &held)
        .await
        .expect("the client verifies the fork from the chain it fetched");
    assert_eq!((proof.pg.as_str(), proof.height), (pr.id.as_str(), 1));

    let refused = async |item: &serde_json::Value, pg: &str, held: &[cyphr_client::PatchEntry]| {
        verify_principal_fork(item, pg, genesis().await, held)
            .await
            .expect_err("must be refused")
    };
    let other = common::implicit_principal_id(&pool, "key_a");
    assert!(matches!(
        refused(item, &other, &held).await,
        EvidenceFailure::OtherPrincipal
    ));
    // A replay from a genesis that does not derive the principal proves
    // nothing about it.
    let wrong_genesis = cyphr::Principal::implicit(key_of(&kp(&pool, "key_a")))
        .await
        .expect("genesis");
    assert!(matches!(
        verify_principal_fork(item, &pr.id, wrong_genesis, &held).await,
        Err(EvidenceFailure::GenesisMismatch)
    ));
    let mut wrong_pre = item.clone();
    wrong_pre["pre"] = serde_json::json!("SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(matches!(
        refused(&wrong_pre, &pr.id, &held).await,
        EvidenceFailure::PreMismatch
    ));
    let mut tampered = item.clone();
    let blob = tampered["b"]["txs"][0][0]
        .as_str()
        .expect("blob")
        .to_owned();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(&blob).expect("b64")).expect("json");
    raw["pay"]["now"] = serde_json::json!(NOW + 99);
    tampered["b"]["txs"][0][0] = serde_json::json!(Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&raw).expect("blob"),
    ));
    assert!(matches!(
        refused(&tampered, &pr.id, &held).await,
        EvidenceFailure::CommitRefused { which: "b", .. }
    ));
    let mut twin = item.clone();
    twin["b"] = twin["a"].clone();
    assert!(matches!(
        refused(&twin, &pr.id, &held).await,
        EvidenceFailure::NotConflicting(_)
    ));
    assert!(matches!(
        refused(item, &pr.id, &[]).await,
        EvidenceFailure::ChainTooShort { .. }
    ));

    // Blob counts are bounded: none, or past the bound, is not an item.
    let mut empty = item.clone();
    empty["a"]["txs"] = serde_json::json!([]);
    assert!(matches!(
        refused(&empty, &pr.id, &held).await,
        EvidenceFailure::Malformed(_)
    ));
    let mut flood = item.clone();
    flood["a"]["txs"] = serde_json::json!(vec![item["a"]["txs"][0].clone(); 1025]);
    assert!(matches!(
        refused(&flood, &pr.id, &held).await,
        EvidenceFailure::Malformed(_)
    ));
    let mut one = item.clone();
    one["a"]["txs"] = serde_json::json!(vec![item["a"]["txs"][0].clone(); 1]);
    one["b"]["txs"] = serde_json::json!(vec![item["b"]["txs"][0].clone(); 1024]);
    assert!(
        !matches!(
            refused(&one, &pr.id, &held).await,
            EvidenceFailure::Malformed(_)
        ),
        "a commit at the bound is still an item (refused later, by replay)"
    );

    // The order of a pay's members on the wire is not signed: the signature
    // is over the canonical pay, so a re-ordered blob verifies the same.
    let mut reordered = item.clone();
    let reorder = |b: &serde_json::Value| {
        let v: serde_json::Value = serde_json::from_slice(
            &Base64UrlUnpadded::decode_vec(b.as_str().expect("blob")).expect("b64"),
        )
        .expect("json");
        let pay = v["pay"].as_object().expect("pay");
        let backwards: Vec<String> = pay
            .iter()
            .rev()
            .map(|(k, val)| format!("{}:{}", serde_json::json!(k), val))
            .collect();
        let text = format!(
            "{{\"pay\":{{{}}},\"sig\":{}{}}}",
            backwards.join(","),
            v["sig"],
            v.get("keys")
                .map_or(String::new(), |k| format!(",\"keys\":{k}"))
        );
        serde_json::json!(Base64UrlUnpadded::encode_string(text.as_bytes()))
    };
    let txs: Vec<serde_json::Value> = item["a"]["txs"]
        .as_array()
        .expect("txs")
        .iter()
        .map(|tx| tx.as_array().expect("tx").iter().map(reorder).collect())
        .collect();
    reordered["a"]["txs"] = serde_json::json!(txs);
    verify_principal_fork(&reordered, &pr.id, pr.genesis().await, &held)
        .await
        .expect("member order on the wire is not part of what is signed");

    let (status, _) = get_json(app.clone(), "/evidence?pg=probe").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a malformed id");
    let unknown = common::implicit_principal_id(&pool, "bob");
    let (status, _) = get_json(app, &format!("/evidence?pg={unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an unknown principal");
}

/// Claim (slot policy): one key that pushes more rivals than its quota
/// (`BRANCH_PER_KEY` = 2) is refused and does not stop a rival signed by
/// another key of the principal from being kept and served at `/evidence`,
/// where every served item verifies offline. The principal is already in
/// Error when the over-quota rivals arrive (three unextended siblings), so
/// the refusal is the Error answer, 423, and the quota is seen in what is
/// served (two of golden's), not in the status.
///
/// Turns red if: slots are first-come across keys (the second key's rival
/// is not served), the quota is absent (the flood is all served), an
/// over-quota rival is answered as anything but the Error refusal, or a
/// served item does not verify. End-to-end scenario: yes.
#[tokio::test]
async fn slots_one_key_cannot_crowd_out_another() {
    let pr = principal().await;
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);

    // golden: the first rival takes the position; two more are kept (and
    // leave the principal in Error); the rest are over its quota.
    let flood = ["key_b", "alice", "bob", "carol", "eve_ed25519"];
    for (n, new) in flood.iter().enumerate() {
        let rival = pr.extend(&pr.g, new, NOW + 1 + n as i64).await;
        let status = pr.push_commit(&app, &rival, 1).await;
        assert_eq!(
            status,
            match n {
                0 => StatusCode::CREATED,
                1 | 2 => StatusCode::CONFLICT,
                _ => StatusCode::LOCKED,
            },
            "rival {n}"
        );
    }
    assert_eq!(
        evidence_items(&app, &pr.id).await.len(),
        2,
        "golden keeps its two and no more"
    );

    // key_a, another key active at the same pre, still gets its slot: its
    // rival is retained, answered as the rival it is (409).
    let key_a = kp(&pool, "key_a");
    let theirs = pr.extend(&key_a, "diana_es384", NOW + 50).await;
    assert_eq!(pr.push_commit(&app, &theirs, 1).await, StatusCode::CONFLICT);
    let items = evidence_items(&app, &pr.id).await;
    assert_eq!(items.len(), 3, "the second key's rival is kept: {items:?}");

    let held = fetch_entries(&app, &pr.id).await;
    for item in &items {
        let genesis = pr.genesis().await;
        verify_principal_fork(item, &pr.id, genesis, &held)
            .await
            .expect("every served item verifies");
    }
}

/// Claim (`arch-signing-stays-stateless`): holding fork evidence changes
/// nothing about what a server signs. The tip report after a refused
/// fork is the same claim as before it (only the signed `now` may move)
/// and verifies under the server's key.
///
/// Turns red if: signing reads fork bookkeeping, so the claims differ once
/// evidence is held, or the statement stops verifying.
/// End-to-end scenario: yes.
// @docket: arch-signing-stays-stateless :: scripts/docket-run arch-signing-stays-stateless
#[tokio::test]
async fn signing_is_unchanged_by_held_evidence() {
    let pr = principal().await;
    let (state, identity, _dir, _) = attestor(None).await;
    let app = build_router(Arc::new(state));
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);
    let canonical = pr.extend(&pr.g, "key_b", NOW + 1).await;
    assert_eq!(
        pr.push_commit(&app, &canonical, 1).await,
        StatusCode::CREATED
    );

    // The chain is extended past the rival's position and the rival will
    // not be, so the principal stays Active: an unextended tie would be
    // Error, whose statement is a held one (SPEC 15.5, 13.6) and not this
    // tip report.
    let mut longer = canonical.fork().await.expect("fork");
    create_key(&mut longer, &pr.g, &kp(&load_pool(), "carol"), NOW + 2).await;
    assert_eq!(pr.push_commit(&app, &longer, 2).await, StatusCode::CREATED);

    let before = tip_of(&app, &pr.id).await;
    let rival = pr.extend(&pr.g, "alice", NOW + 3).await;
    assert_eq!(pr.push_commit(&app, &rival, 1).await, StatusCode::CONFLICT);
    assert_eq!(
        evidence_items(&app, &pr.id).await.len(),
        1,
        "evidence is held"
    );
    let after = tip_of(&app, &pr.id).await;

    let claim = |v: &serde_json::Value| {
        let mut pay = v["pay"].clone();
        pay.as_object_mut().expect("pay").remove("now");
        pay
    };
    assert_eq!(claim(&before), claim(&after), "evidence changed the claim");
    let sig = Base64UrlUnpadded::decode_vec(after["sig"].as_str().expect("sig")).expect("b64");
    assert_eq!(
        identity.verify(&serde_json::to_vec(&after["pay"]).expect("pay"), &sig),
        Some(true),
        "the statement verifies under the server key"
    );
}

/// Claim (`arch-principal-fork-evidence`, at the first position): two
/// different genesis commits of one principal are a fork with no ancestor;
/// the item has `height` 0 and a null `pre`, and the client checks it with
/// no held commit at all, refusing it from a foreign genesis.
///
/// Turns red if: a divergent commit 0 is not kept and served, an item at
/// height 0 is not accepted, or one is accepted (or refused as anything but
/// `GenesisMismatch`) from a genesis that does not derive the principal. End-to-end scenario: yes.
#[tokio::test]
async fn genesis_fork_is_evidence_at_height_zero() {
    let pr = principal().await;
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);

    let other = pr.other_genesis(NOW + 5).await;
    let status = push(&app, wire(&other, 0, &pr.id)).await;
    assert_eq!(status.0, StatusCode::CONFLICT, "{:?}", status.1);

    let items = evidence_items(&app, &pr.id).await;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["height"], 0);
    assert!(items[0]["pre"].is_null(), "no ancestor at height 0");
    verify_principal_fork(&items[0], &pr.id, pr.genesis().await, &[])
        .await
        .expect("a fork at the first position");
    // With no held commit, a genesis that is not this principal's is still
    // refused as such, not as a rival that fails to replay.
    let pool = load_pool();
    let wrong_genesis = cyphr::Principal::implicit(key_of(&kp(&pool, "key_a")))
        .await
        .expect("genesis");
    assert!(matches!(
        verify_principal_fork(&items[0], &pr.id, wrong_genesis, &[]).await,
        Err(EvidenceFailure::GenesisMismatch)
    ));
}

/// `g`'s principal whose genesis commit (SPEC 5.1) is `g`'s self
/// `key/create`, a KT-level `nonce/create` of `nonce`, the
/// `principal/create` and the `commit/create`, made at `now`; and its PG,
/// bare. Two nonces on one key give two principals with one genesis key
/// and different PGs (SPEC 5.1: "a nonce embedding for a unique PG").
async fn nonce_genesis(g: &Kp, nonce: u8, now: i64) -> (cyphr::Principal, String) {
    let signer = cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb);
    let mut p = cyphr::Principal::implicit(key_of(g))
        .await
        .expect("genesis");
    let mut scope = p.begin_commit();
    scope
        .create_genesis_keys(&signer, &[], now, "cyphr.me")
        .await
        .expect("genesis key/create");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": g.alg,
        "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[nonce; 32])),
        "now": now, "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &g.prv, &g.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("nonce/create");
    let pg = scope.genesis_id().expect("PG");
    scope
        .create_principal(&signer, now, "cyphr.me")
        .await
        .expect("principal/create");
    scope
        .finalize_with_software(&signer, now, "cyphr.me")
        .await
        .expect("genesis commit");
    let bare = pg.split_once(':').expect("labelled PG").1.to_string();
    (p, bare)
}

/// Claim (`arch-principal-fork-evidence`, SPEC 5.1 nonce siblings): a fork
/// of one principal is never evidence against another that shares its
/// genesis key. Two principals on key `golden` differ only by a genesis
/// nonce, so their PGs differ. The sibling's real fork, served by the
/// server, relabelled to name the other PG, is refused `GenesisMismatch`
/// by a client replaying from the shared genesis key: at height 1 (the
/// sibling's genesis commit held as the prefix) and at height 0 (two rival
/// genesis commits of the sibling).
///
/// Turns red if: the client accepts a fork whose replayed genesis commit,
/// or either height-0 rival, establishes a PG other than the one the item
/// names, which would be a false equivocation finding against an honest
/// principal. End-to-end scenario: yes.
#[tokio::test]
async fn a_nonce_siblings_fork_is_not_evidence_against_the_other() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let (_, honest_pg) = nonce_genesis(&g, 1, NOW).await;
    let genesis = async || {
        cyphr::Principal::implicit(key_of(&g))
            .await
            .expect("genesis")
    };
    let relabel = |item: &serde_json::Value| {
        let mut item = item.clone();
        item["pg"] = serde_json::json!(honest_pg);
        item
    };

    // Height 1: the sibling forks after its genesis commit.
    let (sibling, sibling_pg) = nonce_genesis(&g, 2, NOW).await;
    assert_ne!(sibling_pg, honest_pg, "premise: the nonces give two PGs");
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    assert_eq!(
        push(&app, wire(&sibling, 0, &sibling_pg)).await.0,
        StatusCode::CREATED
    );
    let mut canonical = sibling.fork().await.expect("fork");
    create_key(&mut canonical, &g, &kp(&pool, "key_b"), NOW + 1).await;
    let mut rival = sibling.fork().await.expect("fork");
    create_key(&mut rival, &g, &kp(&pool, "alice"), NOW + 2).await;
    assert_eq!(
        push(&app, wire(&canonical, 1, &sibling_pg)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        push(&app, wire(&rival, 1, &sibling_pg)).await.0,
        StatusCode::CONFLICT
    );
    let items = evidence_items(&app, &sibling_pg).await;
    assert_eq!(items.len(), 1, "{items:?}");
    let held = fetch_entries(&app, &sibling_pg).await;
    verify_principal_fork(&items[0], &sibling_pg, genesis().await, &held)
        .await
        .expect("control: the fork is evidence against the sibling");
    assert!(matches!(
        verify_principal_fork(&relabel(&items[0]), &honest_pg, genesis().await, &held).await,
        Err(EvidenceFailure::GenesisMismatch)
    ));

    // Height 0: two rival genesis commits of the sibling.
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let (first, _) = nonce_genesis(&g, 2, NOW).await;
    let (second, _) = nonce_genesis(&g, 2, NOW + 5).await;
    assert_eq!(
        push(&app, wire(&first, 0, &sibling_pg)).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        push(&app, wire(&second, 0, &sibling_pg)).await.0,
        StatusCode::CONFLICT
    );
    let items = evidence_items(&app, &sibling_pg).await;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["height"], 0);
    verify_principal_fork(&items[0], &sibling_pg, genesis().await, &[])
        .await
        .expect("control: the genesis fork is evidence against the sibling");
    assert!(matches!(
        verify_principal_fork(&relabel(&items[0]), &honest_pg, genesis().await, &[]).await,
        Err(EvidenceFailure::GenesisMismatch)
    ));
}
