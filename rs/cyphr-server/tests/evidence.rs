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

/// `signer` creates `new` at `now` and finalizes the commit. Distinct
/// `new`/`now` give distinct commits at one position.
fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &signer.prv,
                &signer.pubb,
                &signer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

/// Push body for commit `i` of `p`; commit 0 also embeds the genesis key on
/// its closing cozy, as the wire contract requires.
fn wire(p: &cyphr::Principal, i: usize, genesis: &Kp, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    let entry = &entries[i];
    let mut key_idx = 0;
    let mut blobs: Vec<serde_json::Value> = entry
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
    if i == 0 {
        let last = blobs.len() - 1;
        blobs[last]["key"] = serde_json::json!({
            "alg": genesis.alg,
            "pub": Base64UrlUnpadded::encode_string(&genesis.pubb),
            "tmb": genesis.tmb.to_b64(),
        });
    }
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

/// The principal both servers hold, as its first commit (key_a) and the
/// state after it.
struct Pr {
    g: Kp,
    id: String,
    base: cyphr::Principal,
}

fn principal() -> Pr {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let mut base = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    create_key(&mut base, &g, &kp(&pool, "key_a"), NOW);
    Pr {
        id: golden_principal_id(&pool),
        g,
        base,
    }
}

impl Pr {
    /// The principal after a second commit by `signer` creating `new`.
    fn extend(&self, signer: &Kp, new: &str, now: i64) -> cyphr::Principal {
        let mut p = self.base.clone();
        create_key(&mut p, signer, &kp(&load_pool(), new), now);
        p
    }

    async fn push_commit(&self, app: &axum::Router, p: &cyphr::Principal, i: usize) -> StatusCode {
        push(app, wire(p, i, &self.g, &self.id)).await.0
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
    let genesis = || cyphr::Principal::implicit(key_of(&pr.g)).expect("genesis");

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
        let genesis = cyphr::Principal::implicit(key_of(&pr.g)).expect("genesis");
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
    let higher = replay_chain(
        cyphr::Principal::implicit(key_of(&pr.g)).expect("genesis"),
        &fetch_entries(&peer.a, &pr.id).await,
    )
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

    // The same peer key, signing a one-commit chain whose commit is not
    // the higher chain's first: not a prefix, so evidence.
    let (third, _, _dir, _) = attestor(Some(&peer.key)).await;
    let third = build_router(Arc::new(third));
    let mut other = cyphr::Principal::implicit(key_of(&pr.g)).expect("genesis");
    create_key(&mut other, &pr.g, &kp(&load_pool(), "bob"), NOW + 9);
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
