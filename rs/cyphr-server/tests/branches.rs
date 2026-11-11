//! `GET /branches?pr=<id>` lists every retained branch of a principal (G1).
//!
//! A commit that forks a stored principal is still refused as its tip
//! (409), but is retained as a verified non-tip branch; the route reports
//! each branch's tip, its `pre`, its sequence and whether it is the
//! canonical chain.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_server::build_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

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
        // Keys that are only ever created (never sign) may be public-only.
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
async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
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
        .await
        .expect("finalize");
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// A principal over the genesis `keys` (the first signs) with its genesis
/// commit (SPEC 5.1) made at `now`, and its id: the PG, the principal
/// state over those keys.
async fn genesis(keys: &[&Kp], now: i64) -> (cyphr::Principal, String) {
    let mut p = cyphr::Principal::implicit(key_of(keys[0]))
        .await
        .expect("genesis");
    let others: Vec<cyphr::Key> = keys[1..].iter().map(|k| key_of(k)).collect();
    let blobs: Vec<Vec<u8>> = p
        .commit_genesis(&signer_of(keys[0]), &others, now, "cyphr.me")
        .await
        .expect("genesis commit")
        .iter()
        .map(|c| serde_json::to_vec(c).expect("coz"))
        .collect();
    let id = test_fixtures::bundle::genesis_id(&common::bundle_of(&blobs)).expect("PG");
    (p, id)
}

/// Push body for line `i` of `p`'s export under `id`, in the wire form
/// (SPEC 4.6.2): its keys travel in the bundle's `keys`, so commit 0 (the
/// genesis) reads from its record alone.
fn wire(p: &cyphr::Principal, i: usize, id: &str) -> String {
    let entries = cyphr_storage::export_commits(p).expect("export");
    common::push_body(id, &entries[i].bundle().expect("bundle"))
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A")
}

async fn tip_payload(app: axum::Router, id: &str) -> serde_json::Value {
    let (status, body) = get_json(app, &format!("/tip?pr={}", enc(id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let mut payload = envelope_payload(&body).clone();
    // `now` is the response's own clock, not principal state.
    payload.as_object_mut().expect("tip object").remove("now");
    payload
}

/// One principal with a PG, three PG hash variants (ES256, ES384, Ed25519
/// genesis keys), and a fork at its last position: two rival commits that
/// both verify at the same `pre`.
struct Forked {
    id: String,
    /// The shared prefix, pushed first.
    shared: cyphr::Principal,
    /// The commit that is pushed first at the fork position, and its rival.
    canonical: cyphr::Principal,
    rival: cyphr::Principal,
    /// Every spelling the PG answers to, the id among them.
    spellings: Vec<String>,
}

async fn forked() -> Forked {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let (shared, id) = genesis(
        &[&g, &kp(&pool, "diana_es384"), &kp(&pool, "eve_ed25519")],
        NOW + 2,
    )
    .await;

    let mut spellings = vec![id.clone()];
    let mh = shared.pg().expect("PG established").as_multihash();
    for alg in mh.algorithms() {
        let tagged = mh.tagged(alg).expect("variant").to_string();
        spellings.push(tagged.split_once(':').expect("tagged").1.to_string());
        spellings.push(tagged);
    }

    let mut canonical = shared.fork().await.expect("fork");
    create_key(&mut canonical, &g, &kp(&pool, "key_a"), NOW + 3).await;
    let mut rival = shared.fork().await.expect("fork");
    create_key(&mut rival, &g, &kp(&pool, "key_b"), NOW + 4).await;
    Forked {
        id,
        shared,
        canonical,
        rival,
        spellings,
    }
}

async fn branches(app: axum::Router, id: &str) -> (StatusCode, serde_json::Value) {
    let (status, body) = get_json(app, &format!("/branches?pr={}", enc(id))).await;
    let payload = if status == StatusCode::OK {
        envelope_payload(&body).clone()
    } else {
        body
    };
    (status, payload)
}

/// Backs a-red-route: a server holding a fork lists both branches, under
/// the genesis id and every PG spelling alike; and the push that forked it
/// is still refused (409) without moving the tip. Turns red if the fork is
/// dropped
/// (one branch listed), both or neither is canonical, or the listing
/// differs by spelling. End to end over `/push`, `/tip` and `/branches`:
/// yes.
#[tokio::test]
async fn fork_is_listed_under_every_pg_spelling() {
    let f = forked().await;
    let (state, _dir) = keyless_server();
    let app = build_router(state);

    let n = cyphr_storage::export_commits(&f.shared)
        .expect("export")
        .len();
    for i in 0..n {
        let (status, body) = post_json(app.clone(), "/push", wire(&f.shared, i, &f.id)).await;
        assert_eq!(status, StatusCode::CREATED, "shared commit {i}: {body:?}");
    }
    let (status, body) = post_json(app.clone(), "/push", wire(&f.canonical, n, &f.id)).await;
    assert_eq!(status, StatusCode::CREATED, "canonical commit: {body:?}");
    let tip_before = tip_payload(app.clone(), &f.id).await;

    let (status, body) = post_json(app.clone(), "/push", wire(&f.rival, n, &f.id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the fork must still be refused: {body:?}"
    );
    assert_eq!(
        tip_payload(app.clone(), &f.id).await,
        tip_before,
        "the fork moved the tip"
    );

    let pre_expected = f.shared.pr_tagged().expect("pr at the fork's parent");
    let mut seen = Vec::new();
    for spelling in &f.spellings {
        let (status, payload) = branches(app.clone(), spelling).await;
        assert_eq!(status, StatusCode::OK, "{spelling}: {payload:?}");
        let list = payload["branches"].as_array().expect("branches array");
        let at_fork: Vec<_> = list.iter().filter(|b| b["sequence"] == n as u64).collect();
        assert_eq!(
            at_fork.len(),
            2,
            "{spelling}: both rivals listed: {payload:?}"
        );
        assert!(
            at_fork
                .iter()
                .all(|b| b["pre"] == pre_expected && b["tip"].is_string()),
            "{spelling}: pre is the shared parent: {payload:?}"
        );
        assert_ne!(
            at_fork[0]["tip"], at_fork[1]["tip"],
            "{spelling}: distinct tips"
        );
        // The canonical branch is the chain `/tip` reports, in `/tip`'s
        // commit-id form; the rival is not.
        let canonical = at_fork
            .iter()
            .find(|b| b["canonical"] == true)
            .expect("one canonical");
        assert_eq!(
            canonical["tip"], tip_before["commit_id"],
            "{spelling}: the canonical tip is /tip's commit_id"
        );
        assert_eq!(
            at_fork.iter().filter(|b| b["canonical"] == true).count(),
            1,
            "{spelling}: exactly one canonical: {payload:?}"
        );
        seen.push(payload);
    }
    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "the listing differs by spelling: {seen:?}"
    );
}

/// Backs a-red-route: a principal that was never forked lists exactly its
/// canonical chain (one canonical branch per position, none other), and an
/// unknown principal is 404, not an empty listing. The unknown-id 404 is
/// asserted only after the known principal answers 200, so the absent
/// route (also 404) cannot satisfy it. Turns red if the route is absent or
/// lists a rival nothing forked. End to end: yes.
#[tokio::test]
async fn unforked_principal_lists_only_its_chain_and_unknown_is_404() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    // The genesis commit (`golden` with `key_a`), then one more commit.
    let (mut p, id) = genesis(&[&g, &kp(&pool, "key_a")], NOW).await;
    assert_eq!(id, common::golden_principal_id(&pool).await);
    create_key(&mut p, &g, &kp(&pool, "key_b"), NOW + 1).await;

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    for i in 0..2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&p, i, &id)).await;
        assert_eq!(status, StatusCode::CREATED, "commit {i}: {body:?}");
    }

    let (status, payload) = branches(app.clone(), &id).await;
    assert_eq!(status, StatusCode::OK, "{payload:?}");
    let list = payload["branches"].as_array().expect("branches array");
    assert!(
        !list.is_empty(),
        "a stored principal has a canonical chain: {payload:?}"
    );
    assert!(
        list.iter().all(|b| b["canonical"] == true),
        "no fork was pushed, so no non-canonical branch exists: {payload:?}"
    );
    let tip = tip_payload(app.clone(), &id).await;
    assert_eq!(list.len(), 1, "one head, the chain's tip: {payload:?}");
    assert_eq!(
        list[0]["tip"], tip["commit_id"],
        "the head is /tip's commit"
    );
    assert_eq!(list[0]["sequence"], 1, "the head is the second commit");
    assert!(list[0]["pre"].is_string(), "pre past sequence 0 is a PR");

    let unknown = common::implicit_principal_id(&pool, "key_a");
    let (status, body) = branches(app, &unknown).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body:?}");
}

/// `golden` signs `fields` plus its own `alg` and `tmb`: (pay, sig, czd).
fn golden_signs(
    pool: &test_fixtures::Pool,
    mut fields: serde_json::Value,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let g = pool.get("golden").expect("golden");
    fields["alg"] = g.alg.clone().into();
    fields["tmb"] = g.compute_tmb_b64().expect("tmb").into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&fields).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv b64");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub b64");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    (pay, sig, czd)
}

/// A data action then the `ds/create` that includes it, on `p`: the action's
/// wire coz and the commit's bundle (SPEC 4.8.2).
async fn data_commit(
    p: &mut cyphr::Principal,
    pool: &test_fixtures::Pool,
    msg: &str,
    now: i64,
) -> (Vec<u8>, cyphr::replay::WireBundle) {
    let g = pool.get("golden").expect("golden");
    let (pay, sig, czd) = golden_signs(
        pool,
        serde_json::json!({"msg": msg, "now": now, "typ": "cyphr.me/comment/create"}),
    );
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("action records");
    let wire_action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    let actions: Vec<&cyphr::Action> = p.actions().collect();
    let dr = cyphr::compute_dr(&actions, None, &[cyphr::state::HashAlg::Sha256])
        .expect("DR")
        .expect("DT holds an action");
    let dr = format!(
        "SHA-256:{}",
        Base64UrlUnpadded::encode_string(dr.0.get(cyphr::state::HashAlg::Sha256).expect("SHA-256"))
    );
    let (pay, sig, czd) = golden_signs(
        pool,
        serde_json::json!({"id": dr, "now": now + 1, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), now + 1, "cyphr.me")
        .await
        .expect("commit finalizes");
    let bundle = cyphr::replay::WireBundle::of_commit(p.commits().last().expect("a commit"))
        .expect("bundle");
    (wire_action, bundle)
}

/// Backs a-rival-data: a fork whose commits carry data actions is kept like
/// any other. The canonical branch holds its own action (pushed alone, so
/// stored at that position); the rival brings its OWN action inline. The
/// rival must replay from the fork point with its own actions, never the
/// stored branch's, and be listed at `/branches` and proven at `/evidence`.
///
/// Turns red if: the rival is dropped (one branch listed, no evidence), or
/// it is replayed over the stored branch's action (a state mismatch that
/// retains nothing). End to end over `/push`, `/branches`, `/evidence`.
#[tokio::test]
async fn rival_with_data() {
    let pool = load_pool();
    let f = forked().await;
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let n = cyphr_storage::export_commits(&f.shared)
        .expect("export")
        .len();
    for i in 0..n {
        let (status, body) = post_json(app.clone(), "/push", wire(&f.shared, i, &f.id)).await;
        assert_eq!(status, StatusCode::CREATED, "shared commit {i}: {body:?}");
    }

    let mut canonical = f.shared.fork().await.expect("fork");
    let (action, commit) = data_commit(&mut canonical, &pool, "canonical", NOW + 10).await;
    let (status, body) =
        post_json(app.clone(), "/push", common::push_blobs(&f.id, &[action])).await;
    assert!(status.is_success(), "canonical action: {status} {body:?}");
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&f.id, &commit)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "canonical data commit: {body:?}"
    );

    let mut rival = f.shared.fork().await.expect("fork");
    let (action, mut commit) = data_commit(&mut rival, &pool, "rival", NOW + 20).await;
    commit.actions = vec![action];
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&f.id, &commit)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the fork is refused: {body:?}"
    );

    let (status, payload) = branches(app.clone(), &f.id).await;
    assert_eq!(status, StatusCode::OK, "{payload:?}");
    let at_fork = payload["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .filter(|b| b["sequence"] == n as u64)
        .count();
    assert_eq!(at_fork, 2, "both branches are listed: {payload:?}");

    let (status, body) = get_json(app, &format!("/evidence?pr={}", enc(&f.id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let items = envelope_payload(&body)["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the fork is proven: {body:?}");
}

/// Push the shared prefix, the canonical commit A and refuse its rival B;
/// then `C` extends B (SPEC 15.8, a new commit whose `pre` is the chosen
/// branch's tip).
struct Resolved {
    f: Forked,
    n: usize,
    /// B's commit extended by `carol`: the resolution commit.
    c: cyphr::Principal,
    /// A's commit extended by `bob`: a rival resolution.
    d: cyphr::Principal,
    app: axum::Router,
    state: std::sync::Arc<cyphr_server::AppState>,
    dir: tempfile::TempDir,
}

async fn forked_server() -> Resolved {
    let f = forked().await;
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    let n = cyphr_storage::export_commits(&f.shared)
        .expect("export")
        .len();
    for i in 0..n {
        let (status, body) = post_json(app.clone(), "/push", wire(&f.shared, i, &f.id)).await;
        assert_eq!(status, StatusCode::CREATED, "shared commit {i}: {body:?}");
    }
    let (status, body) = post_json(app.clone(), "/push", wire(&f.canonical, n, &f.id)).await;
    assert_eq!(status, StatusCode::CREATED, "A: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", wire(&f.rival, n, &f.id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "B is retained, refused: {body:?}"
    );
    let mut c = f.rival.fork().await.expect("fork");
    create_key(&mut c, &g, &kp(&pool, "carol"), NOW + 5).await;
    let mut d = f.canonical.fork().await.expect("fork");
    create_key(&mut d, &g, &kp(&pool, "bob"), NOW + 6).await;
    Resolved {
        f,
        n,
        c,
        d,
        app,
        state,
        dir,
    }
}

/// `/branches` entries as (sequence, canonical, tip).
async fn heads(app: &axum::Router, id: &str) -> Vec<(u64, bool, String)> {
    let (status, payload) = branches(app.clone(), id).await;
    assert_eq!(status, StatusCode::OK, "{payload:?}");
    payload["branches"]
        .as_array()
        .expect("branches array")
        .iter()
        .map(|b| {
            (
                b["sequence"].as_u64().expect("sequence"),
                b["canonical"] == true,
                b["tip"].as_str().expect("tip").to_string(),
            )
        })
        .collect()
}

async fn evidence_count(app: &axum::Router, id: &str) -> usize {
    let (status, body) = get_json(app.clone(), &format!("/evidence?pr={}", enc(id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let payload = envelope_payload(&body);
    payload["items"].as_array().expect("items").len()
}

/// Backs SPEC 15.8 (new commit): after A and its rival B, a commit C whose
/// `pre` is B's tip is accepted as the tip, B's branch becomes the canonical
/// chain, A stays listed as a retained branch, the evidence of the fork is
/// still served, and a restart serves the same tip. Turns red if C is
/// refused or retained as a rival, A is dropped, or the restart reverts the
/// tip. End to end over `/push`, `/tip`, `/branches`, `/evidence`: yes.
#[tokio::test]
async fn resolution() {
    let r = forked_server().await;
    let (app, id, n) = (&r.app, &r.f.id, r.n);
    let a_head = heads(app, id)
        .await
        .into_iter()
        .find(|h| h.1)
        .expect("canonical head")
        .2;

    let (status, body) = post_json(app.clone(), "/push", wire(&r.c, n + 1, id)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the resolution commit: {body:?}"
    );
    let tip = tip_payload(app.clone(), id).await;
    assert_eq!(tip["commit_count"], n as u64 + 2, "{tip:?}");

    let list = heads(app, id).await;
    let canonical: Vec<_> = list.iter().filter(|h| h.1).collect();
    assert_eq!(canonical.len(), 1, "one canonical head: {list:?}");
    assert!(
        canonical[0].0 == n as u64 + 1 && canonical[0].2 == tip["commit_id"],
        "C is /tip: {list:?}"
    );
    assert!(
        list.iter()
            .any(|h| !h.1 && h.0 == n as u64 && h.2 == a_head),
        "A is retained, not dropped: {list:?}"
    );
    assert_eq!(
        evidence_count(app, id).await,
        1,
        "the fork is still evidence"
    );

    drop((r.app, r.state));
    let state = std::sync::Arc::new(
        cyphr_server::AppState::new(cyphr_server::config::ServerConfig {
            data_dir: r.dir.path().to_path_buf(),
            ..Default::default()
        })
        .expect("reopen"),
    );
    let app = build_router(state);
    assert_eq!(
        tip_payload(app.clone(), id).await,
        tip,
        "the tip survives a restart"
    );
    assert_eq!(
        heads(&app, id).await,
        list,
        "the branches survive a restart"
    );
}

/// Backs the engine never picking between resolutions (SPEC 15.8, Q8 open):
/// after C resolves to B, D (extending A) is a new fork at the resolution
/// point: both kept, the canonical tip still C, and the principal in Error
/// (`/evidence` lists the fork at the resolution position). An ordinary
/// commit extending C then clears the Error. Turns red if D is accepted as
/// the tip, dropped, or C is displaced. End to end: yes.
#[tokio::test]
async fn second_resolution() {
    let r = forked_server().await;
    let (app, id, n) = (&r.app, &r.f.id, r.n);
    let (status, body) = post_json(app.clone(), "/push", wire(&r.c, n + 1, id)).await;
    assert_eq!(status, StatusCode::CREATED, "C: {body:?}");
    let tip = tip_payload(app.clone(), id).await;

    let (status, body) = post_json(app.clone(), "/push", wire(&r.d, n + 1, id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "D is a fork, not a tip: {body:?}"
    );
    assert_eq!(tip_payload(app.clone(), id).await, tip, "C stays the tip");
    let list = heads(app, id).await;
    assert_eq!(
        list.iter().filter(|h| h.0 == n as u64 + 1).count(),
        2,
        "C and D are both kept at the resolution point: {list:?}"
    );
    assert!(
        r.state.engine.is_errored(id).await.expect("verdict"),
        "two extended branches: Error"
    );

    let pool = load_pool();
    let mut e = r.c.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&e, n + 2, id)).await;
    assert_eq!(status, StatusCode::CREATED, "E extends C: {body:?}");
    assert!(
        !r.state.engine.is_errored(id).await.expect("verdict"),
        "extending one branch selects it: Active"
    );
}
