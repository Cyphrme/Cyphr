//! Evidence (`docs/architecture/equivocation-detection.md`): a server
//! serves the principal forks it holds at `GET /evidence`, and a client
//! checks them, and a peer's equivocation, offline from signatures and the
//! chain alone.
//!
//! Every test runs over real servers and real signed commits; the client
//! side is `cyphr_client::evidence`, fed only what it fetched.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::evidence::{
    EvidenceFailure, replay_chain, verify_peer_equivocation, verify_principal_fork,
};
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
fn apply(
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
        .expect("finalize");
}

/// `signer` creates `new` at `now` and finalizes the commit. Distinct
/// `new`/`now` give distinct commits at one position.
fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    });
    apply(p, signer, signer, pay, Some(key_of(new)), now);
}

/// A principal over the genesis `keys` (the first signs) after its genesis
/// commit (SPEC 5.1) at `now`.
fn genesis_commit(keys: &[&Kp], now: i64) -> cyphr::Principal {
    let mut p = cyphr::Principal::implicit(key_of(keys[0])).expect("genesis");
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
    .expect("genesis commit");
    p
}

/// Push body for commit `i` of `p`; every key-introducing cozy discloses
/// its key, so commit 0 (the genesis) reads from its blobs alone.
fn wire(p: &cyphr::Principal, i: usize, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let entry = &entries[i];
    let mut key_idx = 0;
    let blobs: Vec<serde_json::Value> = entry
        .cozies
        .iter()
        .map(|c| {
            let mut c = c.clone();
            let typ = c["pay"]["typ"].as_str().unwrap_or("").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) && key_idx < entry.keys.len() {
                let k = &entry.keys[key_idx];
                c["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                key_idx += 1;
            }
            c
        })
        .collect();
    serde_json::json!({
        "principal_id": id,
        "blobs": blobs
            .iter()
            .map(|b| Base64UrlUnpadded::encode_string(&serde_json::to_vec(b).expect("blob")))
            .collect::<Vec<_>>(),
    })
    .to_string()
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
    let (status, body) = get_json(app.clone(), &format!("/patch?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    cyphr_client::verify_patch_body(&serde_json::to_vec(&body).expect("json"), pr, None)
        .expect("patch decodes")
        .entries
}

/// The peer's own principal chain, replayed by the client from the genesis
/// key the peer publishes at `/server` and the commits at `/patch`.
async fn peer_chain(
    app: &axum::Router,
) -> (
    cyphr::Principal<cyphr::eml::MemoryStorage>,
    cyphr_client::evidence::KeyHistory,
) {
    let (_, discovery) = get_json(app.clone(), "/server").await;
    let d = &discovery["payload"];
    let pg = d["pg"].as_str().expect("attestor pg").to_string();
    let g = &d["genesis"];
    let genesis_key = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb b64"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub b64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let base = cyphr::Principal::implicit(genesis_key.clone()).expect("peer genesis");
    let chain = replay_chain(base, &fetch_entries(app, &pg).await).expect("the peer chain replays");
    let history = cyphr_client::evidence::KeyHistory::of(&[genesis_key], &chain);
    (chain, history)
}

fn thumbprint(pr: &str) -> coz::Thumbprint {
    coz::Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(pr).expect("pr b64"))
}

/// The signed coz of a peer's `GET /view`.
async fn view_of(app: &axum::Router, pr: &str) -> serde_json::Value {
    let (status, body) = get_json(app.clone(), &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["statement"]["kind"], "signed", "{body:?}");
    body["statement"]["coz"].clone()
}

fn equivocation_item(pr: &str, a: &serde_json::Value, b: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"kind": "peer-equivocation", "pg": pr, "peer": "p1", "a": a, "b": b})
}

/// The principal both servers hold, as its genesis commit (`golden` with
/// `key_a`) and the state after it.
struct Pr {
    g: Kp,
    a: Kp,
    id: String,
    base: cyphr::Principal,
}

fn principal() -> Pr {
    let pool = load_pool();
    let (g, a) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let base = genesis_commit(&[&g, &a], NOW);
    // The bare spelling of the PG, which names the evidence's `pg`.
    let id = golden_principal_id(&pool)
        .split_once(':')
        .expect("labelled PG")
        .1
        .to_string();
    Pr { id, g, a, base }
}

impl Pr {
    /// The principal before its genesis commit: what a client replays the
    /// fetched chain onto.
    fn genesis(&self) -> cyphr::Principal {
        cyphr::Principal::implicit(key_of(&self.g)).expect("genesis")
    }

    /// Another genesis commit of the same principal (same genesis keys,
    /// same PG), made at `now`.
    fn other_genesis(&self, now: i64) -> cyphr::Principal {
        genesis_commit(&[&self.g, &self.a], now)
    }

    /// The principal after a second commit by `signer` creating `new`.
    fn extend(&self, signer: &Kp, new: &str, now: i64) -> cyphr::Principal {
        let mut p = self.base.clone();
        create_key(&mut p, signer, &kp(&load_pool(), new), now);
        p
    }

    async fn push_commit(&self, app: &axum::Router, p: &cyphr::Principal, i: usize) -> StatusCode {
        push(app, wire(p, i, &self.id)).await.0
    }
}

async fn evidence_items(app: &axum::Router, pr: &str) -> Vec<serde_json::Value> {
    let (status, body) = get_json(app.clone(), &format!("/evidence?pr={pr}")).await;
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
    let pr = principal();
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let pool = load_pool();

    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);
    assert!(
        evidence_items(&app, &pr.id).await.is_empty(),
        "a principal never forked has no evidence"
    );

    let canonical = pr.extend(&pr.g, "key_b", NOW + 1);
    let rival = pr.extend(&pr.g, "alice", NOW + 2);
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
    let genesis = || pr.genesis();

    let proof = verify_principal_fork(item, &pr.id, genesis(), &held)
        .expect("the client verifies the fork from the chain it fetched");
    assert_eq!((proof.pg.as_str(), proof.height), (pr.id.as_str(), 1));

    let refused = |item: &serde_json::Value, pg: &str, held: &[cyphr_client::PatchEntry]| {
        verify_principal_fork(item, pg, genesis(), held).expect_err("must be refused")
    };
    let other = common::implicit_principal_id(&pool, "key_a");
    assert!(matches!(
        refused(item, &other, &held),
        EvidenceFailure::OtherPrincipal
    ));
    // A replay from a genesis that does not derive the principal proves
    // nothing about it.
    let wrong_genesis = cyphr::Principal::implicit(key_of(&kp(&pool, "key_a"))).expect("genesis");
    assert!(matches!(
        verify_principal_fork(item, &pr.id, wrong_genesis, &held),
        Err(EvidenceFailure::GenesisMismatch)
    ));
    let mut wrong_pre = item.clone();
    wrong_pre["pre"] = serde_json::json!("SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(matches!(
        refused(&wrong_pre, &pr.id, &held),
        EvidenceFailure::PreMismatch
    ));
    let mut tampered = item.clone();
    let blob = tampered["b"]["blobs"][0].as_str().expect("blob").to_owned();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(&blob).expect("b64")).expect("json");
    raw["pay"]["now"] = serde_json::json!(NOW + 99);
    tampered["b"]["blobs"][0] = serde_json::json!(Base64UrlUnpadded::encode_string(
        &serde_json::to_vec(&raw).expect("blob"),
    ));
    assert!(matches!(
        refused(&tampered, &pr.id, &held),
        EvidenceFailure::CommitRefused { which: "b", .. }
    ));
    let mut twin = item.clone();
    twin["b"] = twin["a"].clone();
    assert!(matches!(
        refused(&twin, &pr.id, &held),
        EvidenceFailure::NotConflicting(_)
    ));
    assert!(matches!(
        refused(item, &pr.id, &[]),
        EvidenceFailure::ChainTooShort { .. }
    ));

    // Blob counts are bounded: none, or past the bound, is not an item.
    let mut empty = item.clone();
    empty["a"]["blobs"] = serde_json::json!([]);
    assert!(matches!(
        refused(&empty, &pr.id, &held),
        EvidenceFailure::Malformed(_)
    ));
    let mut flood = item.clone();
    flood["a"]["blobs"] = serde_json::json!(vec![item["a"]["blobs"][0].clone(); 1025]);
    assert!(matches!(
        refused(&flood, &pr.id, &held),
        EvidenceFailure::Malformed(_)
    ));
    let mut one = item.clone();
    one["a"]["blobs"] = serde_json::json!(vec![item["a"]["blobs"][0].clone(); 1]);
    one["b"]["blobs"] = serde_json::json!(vec![item["b"]["blobs"][0].clone(); 1024]);
    assert!(
        !matches!(refused(&one, &pr.id, &held), EvidenceFailure::Malformed(_)),
        "a commit at the bound is still an item (refused later, by replay)"
    );

    // The order of a pay's members on the wire is not signed: the signature
    // is over the canonical pay, so a re-ordered blob verifies the same.
    let mut reordered = item.clone();
    let blobs: Vec<serde_json::Value> = item["a"]["blobs"]
        .as_array()
        .expect("blobs")
        .iter()
        .map(|b| {
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
                v.get("key")
                    .map_or(String::new(), |k| format!(",\"key\":{k}"))
            );
            serde_json::json!(Base64UrlUnpadded::encode_string(text.as_bytes()))
        })
        .collect();
    reordered["a"]["blobs"] = serde_json::json!(blobs);
    verify_principal_fork(&reordered, &pr.id, pr.genesis(), &held)
        .expect("member order on the wire is not part of what is signed");

    let (status, _) = get_json(app.clone(), "/evidence?pr=probe").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a malformed id");
    let unknown = common::implicit_principal_id(&pool, "bob");
    let (status, _) = get_json(app, &format!("/evidence?pr={unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an unknown principal");
}

/// Claim (slot policy): one key that pushes more rivals than its quota
/// (`BRANCH_PER_KEY` = 2) is refused (409) and does not stop a rival signed
/// by another key of the principal from being kept and served at
/// `/evidence`, where every served item verifies offline.
///
/// Turns red if: slots are first-come across keys (the second key's rival
/// is not served), the quota is absent (the flood is all served), or a
/// served item does not verify. End-to-end scenario: yes.
#[tokio::test]
async fn slots_one_key_cannot_crowd_out_another() {
    let pr = principal();
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let pool = load_pool();
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);

    // golden: the first rival takes the position; two more are kept; the
    // rest are over its quota.
    let flood = ["key_b", "alice", "bob", "carol", "eve_ed25519"];
    for (n, new) in flood.iter().enumerate() {
        let rival = pr.extend(&pr.g, new, NOW + 1 + n as i64);
        let status = pr.push_commit(&app, &rival, 1).await;
        assert_eq!(
            status,
            if n == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::CONFLICT
            },
            "rival {n}"
        );
    }
    assert_eq!(
        evidence_items(&app, &pr.id).await.len(),
        2,
        "golden keeps its two and no more"
    );

    // key_a, another key active at the same pre, still gets its slot.
    let key_a = kp(&pool, "key_a");
    let theirs = pr.extend(&key_a, "diana_es384", NOW + 50);
    assert_eq!(pr.push_commit(&app, &theirs, 1).await, StatusCode::CONFLICT);
    let items = evidence_items(&app, &pr.id).await;
    assert_eq!(items.len(), 3, "the second key's rival is kept: {items:?}");

    let held = fetch_entries(&app, &pr.id).await;
    for item in &items {
        let genesis = pr.genesis();
        verify_principal_fork(item, &pr.id, genesis, &held).expect("every served item verifies");
    }
}

/// Claim (`arch-signing-stays-stateless`): holding fork evidence changes
/// nothing about what a server signs. The view statement after a refused
/// fork is the same claim as before it (only the signed `now` may move)
/// and verifies under the server's key.
///
/// Turns red if: signing reads fork bookkeeping, so the claims differ once
/// evidence is held, or the statement stops verifying.
/// End-to-end scenario: yes.
// @docket: arch-signing-stays-stateless :: scripts/docket-run arch-signing-stays-stateless
#[tokio::test]
async fn signing_is_unchanged_by_held_evidence() {
    let pr = principal();
    let (state, identity, _dir, _) = attestor(None).await;
    let app = build_router(Arc::new(state));
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);
    let canonical = pr.extend(&pr.g, "key_b", NOW + 1);
    assert_eq!(
        pr.push_commit(&app, &canonical, 1).await,
        StatusCode::CREATED
    );

    let before = view_of(&app, &pr.id).await;
    let rival = pr.extend(&pr.g, "alice", NOW + 2);
    assert_eq!(pr.push_commit(&app, &rival, 1).await, StatusCode::CONFLICT);
    assert_eq!(
        evidence_items(&app, &pr.id).await.len(),
        1,
        "evidence is held"
    );
    let after = view_of(&app, &pr.id).await;

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

/// Two servers that sign as one peer (one key file), each holding the
/// principal at a different state: the situation an equivocating peer
/// produces for two clients.
struct SplitPeer {
    a: axum::Router,
    b: axum::Router,
    /// The shared signing key file, for a further server of the same peer.
    key: PathBuf,
    _dirs: (TempDir, TempDir),
}

async fn split_peer(pr: &Pr) -> SplitPeer {
    let (sa, _, dir_a, key_a) = attestor(None).await;
    let (sb, _, dir_b, _) = attestor(Some(&key_a)).await;
    let (a, b) = (build_router(Arc::new(sa)), build_router(Arc::new(sb)));
    for app in [&a, &b] {
        assert_eq!(pr.push_commit(app, &pr.base, 0).await, StatusCode::CREATED);
    }
    SplitPeer {
        a,
        b,
        key: key_a,
        _dirs: (dir_a, dir_b),
    }
}

/// Claim (`arch-one-key-equivocation`): two views of one principal signed
/// under one peer's chain that disagree at one position are evidence the
/// client verifies against that peer's own chain; the same disagreement
/// between views signed by different servers is never evidence against
/// either.
///
/// Turns red if: a conflicting pair from one peer is not accepted, or a
/// pair from two servers is. End-to-end scenario: yes.
// @docket: arch-one-key-equivocation :: scripts/docket-run arch-one-key-equivocation
#[tokio::test]
async fn peer_equivocation_is_judged_against_one_peers_chain() {
    let pr = principal();
    let peer = split_peer(&pr).await;
    let (c1a, c1b) = (
        pr.extend(&pr.g, "key_b", NOW + 1),
        pr.extend(&pr.g, "alice", NOW + 2),
    );
    assert_eq!(pr.push_commit(&peer.a, &c1a, 1).await, StatusCode::CREATED);
    assert_eq!(pr.push_commit(&peer.b, &c1b, 1).await, StatusCode::CREATED);

    let (va, vb) = (
        view_of(&peer.a, &pr.id).await,
        view_of(&peer.b, &pr.id).await,
    );
    let (_, chain) = peer_chain(&peer.a).await;
    let pg = thumbprint(&pr.id);
    let item = equivocation_item(&pr.id, &va, &vb);
    let proof = verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&item, &pg, &chain, None)
        .expect("one peer, two disagreeing views at one position");
    assert_eq!(proof.signers[0], proof.signers[1], "one key signed both");

    // Tip reports are statements of the same kind: two signed under the one
    // peer chain that disagree at one position convict it too.
    let tip_of = |app: &axum::Router| {
        let app = app.clone();
        let id = pr.id.clone();
        async move {
            let (status, body) = get_json(app, &format!("/tip?pr={id}")).await;
            assert_eq!(status, StatusCode::OK, "{body:?}");
            assert_eq!(body["statement"]["kind"], "signed", "{body:?}");
            body["statement"]["coz"].clone()
        }
    };
    let tips = equivocation_item(&pr.id, &tip_of(&peer.a).await, &tip_of(&peer.b).await);
    verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&tips, &pg, &chain, None)
        .expect("two tip reports of one peer that disagree");

    let (stranger, _, _dir, _) = attestor(None).await;
    let stranger = build_router(Arc::new(stranger));
    assert_eq!(
        pr.push_commit(&stranger, &pr.base, 0).await,
        StatusCode::CREATED
    );
    assert_eq!(
        pr.push_commit(&stranger, &c1b, 1).await,
        StatusCode::CREATED
    );
    let theirs = view_of(&stranger, &pr.id).await;
    let framed = equivocation_item(&pr.id, &va, &theirs);
    let refused = verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&framed, &pg, &chain, None)
        .expect_err("two servers' views are never evidence against one");
    assert!(
        matches!(refused, EvidenceFailure::Statement { which: "b", .. }),
        "{refused:?}"
    );
}

/// Claim (`arch-behind-is-not-fork`): a peer that is merely behind is not
/// equivocating. An older view followed by a newer one of one chain is a
/// prefix: refused as evidence, and without the higher chain to compare
/// with, no verdict at all. A lower view that is NOT a prefix of the
/// higher one is evidence.
///
/// Turns red if: a stale prefix is accepted (a behind peer framed), a
/// check that could not complete is reported as a conflict, or a real
/// fork at different sizes is missed. End-to-end scenario: yes.
// @docket: arch-behind-is-not-fork :: scripts/docket-run arch-behind-is-not-fork
#[tokio::test]
async fn stale_prefix_is_not_evidence() {
    let pr = principal();
    let peer = split_peer(&pr).await;
    let pg = thumbprint(&pr.id);
    let (_, chain) = peer_chain(&peer.a).await;
    let old = view_of(&peer.a, &pr.id).await;

    let c1 = pr.extend(&pr.g, "key_b", NOW + 1);
    assert_eq!(pr.push_commit(&peer.a, &c1, 1).await, StatusCode::CREATED);
    let new = view_of(&peer.a, &pr.id).await;

    // The higher view's own principal chain, as the client fetched it.
    let higher = replay_chain(pr.genesis(), &fetch_entries(&peer.a, &pr.id).await)
        .expect("the principal chain replays");

    let item = equivocation_item(&pr.id, &old, &new);
    let stale = verify_peer_equivocation(&item, &pg, &chain, Some(&higher))
        .expect_err("an older tip then a newer one is not evidence");
    assert!(
        matches!(stale, EvidenceFailure::NotConflicting(_)),
        "{stale:?}"
    );
    let undecided = verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&item, &pg, &chain, None)
        .expect_err("different sizes need the higher chain");
    assert!(
        matches!(undecided, EvidenceFailure::NeedsChain),
        "{undecided:?}"
    );

    // A higher chain that does not hold the higher statement's commit
    // cannot settle the comparison: no verdict, never a conflict.
    let c1b = pr.extend(&pr.g, "alice", NOW + 2);
    assert_eq!(pr.push_commit(&peer.b, &c1b, 1).await, StatusCode::CREATED);
    let elsewhere = replay_chain(pr.genesis(), &fetch_entries(&peer.b, &pr.id).await)
        .expect("the other chain replays");
    let unbacked = verify_peer_equivocation(&item, &pg, &chain, Some(&elsewhere))
        .expect_err("the chain does not back the higher statement");
    assert!(
        matches!(unbacked, EvidenceFailure::NeedsChain),
        "{unbacked:?}"
    );

    // The same peer key, signing a one-commit chain whose commit is not
    // the higher chain's first: not a prefix, so evidence.
    let (third, _, _dir, _) = attestor(Some(&peer.key)).await;
    let third = build_router(Arc::new(third));
    let other = pr.other_genesis(NOW + 9);
    assert_eq!(pr.push_commit(&third, &other, 0).await, StatusCode::CREATED);
    let short = view_of(&third, &pr.id).await;
    let forked = equivocation_item(&pr.id, &short, &new);
    verify_peer_equivocation(&forked, &pg, &chain, Some(&higher))
        .expect("a lower view that is not a prefix of the higher is evidence");
}

/// Claim (historical form, `arch-finding-never-clears`): a view is
/// verified against the key the peer chain held at the view's own time, so
/// the peer's later rotation, which revokes that key, does not erase the
/// evidence; a statement signed after the revocation is refused; the
/// current-view verifier is unchanged and still refuses the retired key.
///
/// Turns red if: evidence stops verifying once the key is revoked, a
/// post-revocation statement is accepted, or `verify_view_statement` starts
/// accepting a retired key. End-to-end scenario: yes.
// @docket: arch-finding-never-clears :: scripts/docket-run arch-finding-never-clears
#[tokio::test]
async fn historical_view_survives_the_signing_keys_revocation() {
    let pr = principal();
    let (a, _, dir_a, key_a) = attestor(None).await;
    let (b, _, dir_b, _) = attestor(Some(&key_a)).await;
    let a = Arc::new(a);
    let (app_a, app_b) = (build_router(a.clone()), build_router(Arc::new(b)));
    for app in [&app_a, &app_b] {
        assert_eq!(pr.push_commit(app, &pr.base, 0).await, StatusCode::CREATED);
    }
    let c1a = pr.extend(&pr.g, "key_b", NOW + 1);
    let c1b = pr.extend(&pr.g, "alice", NOW + 2);
    assert_eq!(pr.push_commit(&app_a, &c1a, 1).await, StatusCode::CREATED);
    assert_eq!(pr.push_commit(&app_b, &c1b, 1).await, StatusCode::CREATED);
    let (va, vb) = (view_of(&app_a, &pr.id).await, view_of(&app_b, &pr.id).await);

    // The signed `now` has second resolution: let the rotation fall after it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    drop(app_a);
    let mut a = Arc::into_inner(a).expect("the router is gone, so the state is ours");
    a.rotate_signing_key(&coz::Alg::Ed25519.generate_keypair())
        .await
        .expect("rotate the signing key");
    let app_a = build_router(Arc::new(a));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let (chain, history) = peer_chain(&app_a).await;
    let pg = thumbprint(&pr.id);
    let retired = thumbprint(va["pay"]["tmb"].as_str().expect("tmb"));
    assert!(
        !chain.is_key_active(&retired),
        "premise: the key is retired"
    );

    let item = equivocation_item(&pr.id, &va, &vb);
    verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&item, &pg, &history, None)
        .expect("the revocation does not erase evidence signed before it");

    let envelope = serde_json::json!({"v": 1, "statement": {"kind": "signed", "coz": va}});
    assert!(
        cyphr_client::verify_view_statement(&envelope, &chain, &pr.id).is_err(),
        "the current-view verifier still refuses the retired key"
    );

    // The retired key keeps signing on the second server, now after the
    // revocation: that statement is not evidence.
    let late = view_of(&app_b, &pr.id).await;
    let late_item = equivocation_item(&pr.id, &va, &late);
    let refused =
        verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&late_item, &pg, &history, None)
            .expect_err("a statement signed after the revocation");
    assert!(
        matches!(refused, EvidenceFailure::Statement { which: "b", .. }),
        "{refused:?}"
    );
    drop((dir_a, dir_b));
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
    let pr = principal();
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    assert_eq!(pr.push_commit(&app, &pr.base, 0).await, StatusCode::CREATED);

    let other = pr.other_genesis(NOW + 5);
    let status = push(&app, wire(&other, 0, &pr.id)).await;
    assert_eq!(status.0, StatusCode::CONFLICT, "{:?}", status.1);

    let items = evidence_items(&app, &pr.id).await;
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["height"], 0);
    assert!(items[0]["pre"].is_null(), "no ancestor at height 0");
    verify_principal_fork(&items[0], &pr.id, pr.genesis(), &[])
        .expect("a fork at the first position");
    // With no held commit, a genesis that is not this principal's is still
    // refused as such, not as a rival that fails to replay.
    let pool = load_pool();
    let wrong_genesis = cyphr::Principal::implicit(key_of(&kp(&pool, "key_a"))).expect("genesis");
    assert!(matches!(
        verify_principal_fork(&items[0], &pr.id, wrong_genesis, &[]),
        Err(EvidenceFailure::GenesisMismatch)
    ));
}

/// `g`'s principal whose genesis commit (SPEC 5.1) is `g`'s self
/// `key/create`, a KT-level `nonce/create` of `nonce`, the
/// `principal/create` and the `commit/create`, made at `now`; and its PG,
/// bare. Two nonces on one key give two principals with one genesis key
/// and different PGs (SPEC 5.1: "a nonce embedding for a unique PG").
fn nonce_genesis(g: &Kp, nonce: u8, now: i64) -> (cyphr::Principal, String) {
    let signer = cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb);
    let mut p = cyphr::Principal::implicit(key_of(g)).expect("genesis");
    let mut scope = p.begin_commit();
    scope
        .create_genesis_keys(&signer, &[], now, "cyphr.me")
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
        .expect("principal/create");
    scope
        .finalize_with_software(&signer, now, "cyphr.me")
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
    let (_, honest_pg) = nonce_genesis(&g, 1, NOW);
    let genesis = || cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    let relabel = |item: &serde_json::Value| {
        let mut item = item.clone();
        item["pg"] = serde_json::json!(honest_pg);
        item
    };

    // Height 1: the sibling forks after its genesis commit.
    let (sibling, sibling_pg) = nonce_genesis(&g, 2, NOW);
    assert_ne!(sibling_pg, honest_pg, "premise: the nonces give two PGs");
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    assert_eq!(
        push(&app, wire(&sibling, 0, &sibling_pg)).await.0,
        StatusCode::CREATED
    );
    let mut canonical = sibling.clone();
    create_key(&mut canonical, &g, &kp(&pool, "key_b"), NOW + 1);
    let mut rival = sibling.clone();
    create_key(&mut rival, &g, &kp(&pool, "alice"), NOW + 2);
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
    verify_principal_fork(&items[0], &sibling_pg, genesis(), &held)
        .expect("control: the fork is evidence against the sibling");
    assert!(matches!(
        verify_principal_fork(&relabel(&items[0]), &honest_pg, genesis(), &held),
        Err(EvidenceFailure::GenesisMismatch)
    ));

    // Height 0: two rival genesis commits of the sibling.
    let (state, _dir) = common::keyless_server();
    let app = build_router(state);
    let (first, _) = nonce_genesis(&g, 2, NOW);
    let (second, _) = nonce_genesis(&g, 2, NOW + 5);
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
    verify_principal_fork(&items[0], &sibling_pg, genesis(), &[])
        .expect("control: the genesis fork is evidence against the sibling");
    assert!(matches!(
        verify_principal_fork(&relabel(&items[0]), &honest_pg, genesis(), &[]),
        Err(EvidenceFailure::GenesisMismatch)
    ));
}

/// A view statement signed by `signer`, claiming the principal `pr` at
/// `size` with commit id `id` and Principal Root `root`.
fn crafted_view(
    signer: &Kp,
    pr: &str,
    now: i64,
    size: u64,
    id: &str,
    root: &str,
) -> serde_json::Value {
    let pay = serde_json::json!({
        "alg": signer.alg, "commit_id": id, "index": size - 1, "now": now, "pr": pr,
        "roots": {"ar": null, "cr": null, "pr": root, "sr": null},
        "tmb": signer.tmb.to_b64(), "tree_size": size, "typ": "cyphr-server/view",
    });
    let (sig, _) = coz::sign_json(
        &serde_json::to_vec(&pay).expect("pay"),
        &signer.alg,
        &signer.prv,
        &signer.pubb,
    )
    .expect("sign");
    serde_json::json!({"pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig)})
}

/// Claim (historical form, `arch-finding-never-clears`, and the comparison
/// rules of `arch-behind-is-not-fork`): the peer's key history is bounded by
/// signed times, a key is judged at each statement's own time (introduced
/// by a coz, ended at its `rvk`, its delete, exclusive), and a statement is
/// evidence only when it verifies, is about the principal asked, and
/// disagrees in commit id or root. Unit-level on purpose: a running server
/// cannot be made to delete or self-revoke its own keys, and the exact
/// boundaries of a signed time need hand-made statements.
///
/// Turns red if: a key vouches outside its life (before it was introduced,
/// at or after its revoke or delete), a tampered statement or one about
/// another principal passes, agreeing statements convict, or a lower view
/// whose root differs from the chain's is taken for a prefix.
#[test]
fn key_history_bounds_a_key_by_its_signed_times() {
    const T: i64 = NOW;
    let pool = load_pool();
    let (g, a, bob) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "bob"));
    // The genesis commit creates golden and key_a at T.
    let mut peer = genesis_commit(&[&g, &a], T);
    create_key(&mut peer, &a, &bob, T + 10);
    apply(
        &mut peer,
        &a,
        &a,
        serde_json::json!({"alg": a.alg, "id": bob.tmb.to_b64(), "now": T + 20,
                           "tmb": a.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        T + 20,
    );
    // bob is added again after its delete: the later interval is its own.
    create_key(&mut peer, &a, &bob, T + 25);
    apply(
        &mut peer,
        &g,
        &a,
        serde_json::json!({"alg": g.alg, "now": T + 30, "rvk": T + 30,
                           "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"}),
        None,
        T + 30,
    );
    let history = cyphr_client::evidence::KeyHistory::of(&[key_of(&g), key_of(&a)], &peer);

    let pr = Base64UrlUnpadded::encode_string(&[9; 32]);
    let pg = thumbprint(&pr);
    let id = |n: u8| format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[n; 32]));
    let item = |x: &serde_json::Value, y: &serde_json::Value| equivocation_item(&pr, x, y);
    let check = |x: &serde_json::Value, y: &serde_json::Value| {
        verify_peer_equivocation::<cyphr::eml::MemoryStorage>(&item(x, y), &pg, &history, None)
    };
    let other = crafted_view(&a, &pr, T + 40, 2, &id(2), &id(2));
    let signs = |k: &Kp, now: i64| crafted_view(k, &pr, now, 2, &id(1), &id(1));

    check(&signs(&g, T + 29), &other).expect("golden vouches until its revoke");
    check(&signs(&g, T + 30), &other).expect_err("not at the instant of its revoke");
    check(&signs(&bob, T + 15), &other).expect("bob vouches while held");
    check(&signs(&bob, T + 20), &other).expect_err("not at the instant of its delete");
    check(&signs(&bob, T + 5), &other).expect_err("not before it was introduced");
    check(&signs(&bob, T + 22), &other).expect_err("not between the delete and the re-add");
    check(&signs(&bob, T + 27), &other).expect("a key added again vouches in its later interval");

    let mut tampered = signs(&a, T + 40);
    tampered["pay"]["tree_size"] = 3.into();
    tampered["pay"]["index"] = 2.into();
    assert!(matches!(
        check(&tampered, &other),
        Err(EvidenceFailure::Statement { which: "a", .. })
    ));
    let foreign = crafted_view(
        &a,
        &Base64UrlUnpadded::encode_string(&[8; 32]),
        T + 40,
        2,
        &id(1),
        &id(1),
    );
    assert!(matches!(
        check(&foreign, &other),
        Err(EvidenceFailure::OtherPrincipal)
    ));
    let stranger = kp(&pool, "alice");
    assert!(matches!(
        check(&signs(&stranger, T + 40), &other),
        Err(EvidenceFailure::Statement { which: "a", .. })
    ));

    // At one size: agreement is no conflict; either difference is one.
    let same = signs(&a, T + 41);
    assert!(matches!(
        check(&same, &signs(&a, T + 42)),
        Err(EvidenceFailure::NotConflicting(_))
    ));
    check(&same, &crafted_view(&a, &pr, T + 42, 2, &id(1), &id(7))).expect("same id, other root");
    check(&same, &crafted_view(&a, &pr, T + 42, 2, &id(7), &id(1))).expect("same root, other id");

    // At different sizes the lower is compared with the higher's own chain,
    // here the peer principal itself standing in for a principal chain.
    let tagged = |c: &cyphr::Commit| {
        let d = c.tr().0.get(cyphr::HashAlg::Sha256).expect("sha256 id");
        let r = c.pr().0.get(cyphr::HashAlg::Sha256).expect("sha256 pr");
        (
            cyphr::state::TaggedDigest::new(cyphr::HashAlg::Sha256, d.to_vec())
                .expect("id")
                .to_string(),
            cyphr::state::TaggedDigest::new(cyphr::HashAlg::Sha256, r.to_vec())
                .expect("pr")
                .to_string(),
        )
    };
    let commits: Vec<_> = peer.commits().map(tagged).collect();
    let run = |lo: &serde_json::Value, hi: &serde_json::Value, chain: Option<&cyphr::Principal>| {
        verify_peer_equivocation(&item(lo, hi), &pg, &history, chain)
    };
    let (hi_id, hi_root) = &commits[3];
    let hi = crafted_view(&a, &pr, T + 40, 4, hi_id, hi_root);
    let behind = crafted_view(&a, &pr, T + 40, 2, &commits[1].0, &commits[1].1);
    assert!(matches!(
        run(&behind, &hi, Some(&peer)),
        Err(EvidenceFailure::NotConflicting(_))
    ));
    let wrong_root = crafted_view(&a, &pr, T + 40, 2, &commits[1].0, &id(5));
    run(&wrong_root, &hi, Some(&peer)).expect("the chain's commit with another root is no prefix");
    let unbacked = crafted_view(&a, &pr, T + 40, 4, &id(6), &id(6));
    assert!(matches!(
        run(&behind, &unbacked, Some(&peer)),
        Err(EvidenceFailure::NeedsChain)
    ));
}
