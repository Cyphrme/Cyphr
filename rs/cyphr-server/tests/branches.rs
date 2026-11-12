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

    assert!(
        !r.state.engine.is_errored(id).await.expect("verdict"),
        "only B's branch is extended: Active"
    );

    let Resolved {
        dir, app, state, ..
    } = r;
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
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
    assert!(
        !state.engine.is_errored(id).await.expect("verdict"),
        "Active survives a restart"
    );
}

/// Backs SPEC 15.8 (be0663f) and 15.7.1: after C resolves to B, D
/// (extending A) is a new fork at the resolution point: both kept, C still
/// the tip, and the principal is in Error. An extension E of C afterwards
/// does not resolve it, so it is refused (423), and the verdict, tip and
/// branch list are the same live and after a restart that rebuilds from
/// the blobs. Turns red if D is accepted as the tip or dropped, E is
/// accepted or clears Error, or a rebuild disagrees with the live engine.
/// End to end: yes.
#[tokio::test]
async fn second_resolution_then_extension() {
    let Resolved {
        f,
        n,
        c,
        d,
        app,
        state,
        dir,
    } = forked_server().await;
    let id = &f.id;
    let (status, body) = post_json(app.clone(), "/push", wire(&c, n + 1, id)).await;
    assert_eq!(status, StatusCode::CREATED, "C: {body:?}");
    let tip = tip_payload(app.clone(), id).await;

    let (status, body) = post_json(app.clone(), "/push", wire(&d, n + 1, id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "D is a fork, not a tip: {body:?}"
    );
    assert_eq!(tip_payload(app.clone(), id).await, tip, "C stays the tip");
    let list = heads(&app, id).await;
    assert_eq!(
        list.iter().filter(|h| h.0 == n as u64 + 1).count(),
        2,
        "C and D are both kept at the resolution point: {list:?}"
    );
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "two extended branches: Error"
    );

    // A restart rebuilds the verdict from the blobs alone (I1).
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(tip_payload(app.clone(), id).await, tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "a rebuild agrees: Error"
    );

    let (tip, list) = extend_c(&app, &c, n, id, ERRORED).await;
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "extending C does not clear Error, so it is refused"
    );
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(tip_payload(app.clone(), id).await, tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "Error survives a restart"
    );
}

/// The same verdict when E (extending C) arrives before D: D is then a
/// rival below the head, and the verdict, tip and branch list are the
/// same live and after a restart. Turns red if D's late arrival is
/// dropped, the verdict depends on arrival order, or a rebuild disagrees.
/// End to end: yes.
#[tokio::test]
async fn extension_then_second_resolution() {
    let Resolved {
        f,
        n,
        c,
        d: _,
        app,
        state,
        dir,
    } = forked_server().await;
    let id = &f.id;
    let (status, body) = post_json(app.clone(), "/push", wire(&c, n + 1, id)).await;
    assert_eq!(status, StatusCode::CREATED, "C: {body:?}");
    let _ = extend_c(&app, &c, n, id, StatusCode::CREATED).await;
    assert!(
        !state.engine.is_errored(id).await.expect("verdict"),
        "only B's branch is extended: Active"
    );

    // D is signed after E: a commit older than the tip's is refused
    // outright (SPEC 15.9), so only a later D can arrive late.
    let pool = load_pool();
    let mut d = f.canonical.fork().await.expect("fork");
    create_key(&mut d, &kp(&pool, "golden"), &kp(&pool, "bob"), NOW + 9).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&d, n + 1, id)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "D is kept, not a tip: {body:?}"
    );
    let tip = tip_payload(app.clone(), id).await;
    let list = heads(&app, id).await;
    assert!(
        list.iter().any(|h| !h.1 && h.0 == n as u64 + 1),
        "D is kept as a branch: {list:?}"
    );
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "D extends A and C extends B: Error"
    );

    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(tip_payload(app.clone(), id).await, tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "Error survives a restart"
    );
}

/// Push E, a commit extending C, expecting `status`, and return the tip
/// and branch list after.
async fn extend_c(
    app: &axum::Router,
    c: &cyphr::Principal,
    n: usize,
    id: &str,
    status: StatusCode,
) -> (serde_json::Value, Vec<(u64, bool, String)>) {
    let pool = load_pool();
    let mut e = c.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    let (got, body) = post_json(app.clone(), "/push", wire(&e, n + 2, id)).await;
    assert_eq!(got, status, "E extends C: {body:?}");
    (tip_payload(app.clone(), id).await, heads(app, id).await)
}

/// A restarted server over `dir`, its index rebuilt from the blobs.
async fn reopen(dir: &std::path::Path) -> (axum::Router, std::sync::Arc<cyphr_server::AppState>) {
    let state = std::sync::Arc::new(
        cyphr_server::AppState::new(cyphr_server::config::ServerConfig {
            data_dir: dir.to_path_buf(),
            ..Default::default()
        })
        .expect("reopen"),
    );
    state
        .engine
        .rebuild_index_from_scratch()
        .await
        .expect("rebuild");
    (build_router(state.clone()), state)
}

// ========================================================================
// ERR1: Error is entered on any unresolved fork, refuses what does not
// resolve it, and is left only by protocol (SPEC 15.5, 15.7.1, 15.8).
// ========================================================================

/// A refusal while the principal is in Error (SPEC 15.5: "No new
/// transactions or actions are processed until resolved").
const ERRORED: StatusCode = StatusCode::LOCKED;

/// A theft: genesis keys `golden`, `diana_es384`, `eve_ed25519`; the owner
/// (`golden`) signs A and D, the thief (`eve`) signs the rival B and its
/// extension C. A at NOW+3, B at NOW+4; of C and D, the one the thief
/// (`thief_first`) or the owner pushes first is at NOW+5, the other at
/// NOW+6 (a later push dated earlier than the tip is TIMESTAMP_PAST).
struct Theft {
    id: String,
    n: usize,
    shared: cyphr::Principal,
    a: cyphr::Principal,
    b: cyphr::Principal,
    c: cyphr::Principal,
    d: cyphr::Principal,
    /// C's `now`.
    c_now: i64,
}

async fn theft(thief_first: bool) -> Theft {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let mut a = shared.fork().await.expect("fork");
    create_key(&mut a, &g, &kp(&pool, "key_a"), NOW + 3).await;
    let mut b = shared.fork().await.expect("fork");
    create_key(&mut b, &e, &kp(&pool, "key_b"), NOW + 4).await;
    let (c_now, d_now) = if thief_first {
        (NOW + 5, NOW + 6)
    } else {
        (NOW + 6, NOW + 5)
    };
    let mut c = b.fork().await.expect("fork");
    create_key(&mut c, &e, &kp(&pool, "carol"), c_now).await;
    let mut d = a.fork().await.expect("fork");
    create_key(&mut d, &g, &kp(&pool, "bob"), d_now).await;
    Theft {
        id,
        n,
        shared,
        a,
        b,
        c,
        d,
        c_now,
    }
}

/// Push `p`'s commit at `i` and return the status.
async fn push(app: &axum::Router, p: &cyphr::Principal, i: usize, id: &str) -> StatusCode {
    post_json(app.clone(), "/push", wire(p, i, id)).await.0
}

/// A server holding `t`'s shared prefix and A.
async fn theft_server(
    t: &Theft,
) -> (
    axum::Router,
    std::sync::Arc<cyphr_server::AppState>,
    tempfile::TempDir,
) {
    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    for i in 0..t.n {
        assert_eq!(
            push(&app, &t.shared, i, &t.id).await,
            StatusCode::CREATED,
            "shared {i}"
        );
    }
    assert_eq!(push(&app, &t.a, t.n, &t.id).await, StatusCode::CREATED, "A");
    (app, state, dir)
}

/// `eve` self-revokes (SPEC 6.4) as of `rvk`, over `/revoke`.
async fn revoke_eve(app: &axum::Router, rvk: i64) {
    let pool = load_pool();
    let e = kp(&pool, "eve_ed25519");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": e.alg, "now": rvk, "rvk": rvk, "tmb": e.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &e.alg, &e.prv, &e.pubb).expect("sign");
    let body = serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": e.alg, "pub": Base64UrlUnpadded::encode_string(&e.pubb)},
    });
    let (status, body) = post_json(app.clone(), "/revoke", body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
}

async fn errored(state: &cyphr_server::AppState, id: &str) -> bool {
    state.engine.is_errored(id).await.expect("verdict")
}

/// Backs SPEC 15.6 ("Active -> Error: Fork detected") and 15.8 item 1: a
/// plain fork, neither branch extended, is Error at once, live and after a
/// rebuild; a commit extending exactly one tip (here the canonical head)
/// resolves it, and Active survives a rebuild. Turns red if an unextended
/// fork is Active, or the extension is refused or leaves Error. End to end.
#[tokio::test]
async fn plain_fork_is_error_until_extended() {
    let t = theft(true).await;
    let (app, state, dir) = theft_server(&t).await;
    assert_eq!(
        push(&app, &t.b, t.n, &t.id).await,
        StatusCode::CONFLICT,
        "B is a rival"
    );
    assert!(errored(&state, &t.id).await, "an unextended fork is Error");
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(errored(&state, &t.id).await, "a rebuild agrees: Error");

    assert_eq!(
        push(&app, &t.d, t.n + 1, &t.id).await,
        StatusCode::CREATED,
        "D resolves"
    );
    assert!(!errored(&state, &t.id).await, "one extended branch: Active");
    let tip = tip_payload(app.clone(), &t.id).await;
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(!errored(&state, &t.id).await, "Active survives a rebuild");
    assert_eq!(tip_payload(app, &t.id).await, tip);
}

/// The state both arrival orders reach: A, B, then `first` resolves the
/// plain fork and `second` extends the other branch, so both are extended.
async fn both_extended(
    t: &Theft,
    thief_first: bool,
) -> (
    axum::Router,
    std::sync::Arc<cyphr_server::AppState>,
    tempfile::TempDir,
) {
    // The fixture dates the first resolution earlier.
    debug_assert_eq!(thief_first, t.c_now == NOW + 5);
    let (app, state, dir) = theft_server(t).await;
    assert_eq!(
        push(&app, &t.b, t.n, &t.id).await,
        StatusCode::CONFLICT,
        "B"
    );
    let (first, second) = if thief_first {
        (&t.c, &t.d)
    } else {
        (&t.d, &t.c)
    };
    assert_eq!(
        push(&app, first, t.n + 1, &t.id).await,
        StatusCode::CREATED,
        "resolution"
    );
    assert_eq!(
        push(&app, second, t.n + 1, &t.id).await,
        StatusCode::CONFLICT,
        "the other branch's extension is retained"
    );
    assert!(
        errored(&state, &t.id).await,
        "both branches extended: Error"
    );
    (app, state, dir)
}

/// Backs SPEC 15.5 and 15.7.1 ("rejection of both branches until
/// resolved"): in Error, a commit that leaves Error standing (E, extending
/// the canonical head) and an action-only bundle are refused (423) without
/// moving the tip, and E is retained as evidence (listed at `/branches`),
/// live and after a rebuild. Turns red if either is accepted, the tip
/// moves, or E is dropped. End to end.
#[tokio::test]
async fn errored_refuses_and_retains() {
    let t = theft(false).await;
    let (app, state, dir) = both_extended(&t, false).await;
    let tip = tip_payload(app.clone(), &t.id).await;
    let pool = load_pool();
    let mut e = t.d.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    assert_eq!(
        push(&app, &e, t.n + 2, &t.id).await,
        ERRORED,
        "E does not resolve"
    );
    let (pay, sig, _) = golden_signs(
        &pool,
        serde_json::json!({"msg": "hi", "now": NOW + 8, "typ": "cyphr.me/comment/create"}),
    );
    let action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    let (status, body) =
        post_json(app.clone(), "/push", common::push_blobs(&t.id, &[action])).await;
    assert_eq!(
        status, ERRORED,
        "an action-only bundle is refused: {body:?}"
    );
    assert_eq!(
        tip_payload(app.clone(), &t.id).await,
        tip,
        "nothing moved the tip"
    );
    let list = heads(&app, &t.id).await;
    assert!(
        list.iter().any(|h| !h.1 && h.0 == t.n as u64 + 2),
        "E is retained as evidence: {list:?}"
    );
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(errored(&state, &t.id).await, "Error survives a rebuild");
    assert_eq!(tip_payload(app.clone(), &t.id).await, tip);
    assert_eq!(heads(&app, &t.id).await, list, "E survives a rebuild");
}

/// Backs the revoke resolution (SPEC 15.7.1 "revocation"; 6.4): with both
/// branches extended, the thief's self-revoke as of a time after its
/// commits changes nothing (a revoke is never retroactive); a revoke as of
/// C's `now` invalidates C (but not B, signed before it) and leaves exactly
/// the owner's branch extended: Active, D the tip, B and C kept as
/// evidence. The same holds whichever branch resolved first (so also when
/// the thief's branch was canonical and the chain must move), and survives
/// a rebuild. Turns red if a revoke is retroactive, does not resolve,
/// leaves the thief's branch served, or depends on arrival order. End to
/// end over `/push`, `/revoke`, `/tip`, `/branches`.
#[tokio::test]
async fn revoke_resolves_both_extended() {
    for thief_first in [true, false] {
        let t = theft(thief_first).await;
        let (app, state, dir) = both_extended(&t, thief_first).await;
        let d_id = d_commit_id(&t).await;
        revoke_eve(&app, NOW + 100).await;
        assert!(
            errored(&state, &t.id).await,
            "thief_first={thief_first}: a revoke after every thief commit changes nothing"
        );
        revoke_eve(&app, t.c_now).await;
        assert!(
            !errored(&state, &t.id).await,
            "thief_first={thief_first}: C is invalid, only D extends: Active"
        );
        let tip = tip_payload(app.clone(), &t.id).await;
        assert_eq!(
            tip["commit_id"], d_id,
            "thief_first={thief_first}: D is /tip"
        );
        let list = heads(&app, &t.id).await;
        let canonical: Vec<_> = list.iter().filter(|h| h.1).collect();
        assert_eq!(canonical.len(), 1, "{list:?}");
        assert_eq!(canonical[0].2, d_id, "D is the head: {list:?}");
        assert_eq!(list.len(), 3, "D, and B and C kept as evidence: {list:?}");
        drop((app, state));
        let (app, state) = reopen(dir.path()).await;
        assert!(!errored(&state, &t.id).await, "Active survives a rebuild");
        assert_eq!(tip_payload(app.clone(), &t.id).await, tip);
        assert_eq!(heads(&app, &t.id).await, list);
    }
}

/// D's commit id: listed at D's position, and not C's (which `eve` signed).
async fn d_commit_id(t: &Theft) -> String {
    // Read off a fresh server holding the shared prefix, A and D only.
    let (state, _dir) = keyless_server();
    let fresh = build_router(state);
    for i in 0..t.n {
        assert_eq!(push(&fresh, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    assert_eq!(push(&fresh, &t.a, t.n, &t.id).await, StatusCode::CREATED);
    assert_eq!(
        push(&fresh, &t.d, t.n + 1, &t.id).await,
        StatusCode::CREATED
    );
    tip_payload(fresh, &t.id).await["commit_id"]
        .as_str()
        .expect("commit_id")
        .to_string()
}

/// Backs a commit admitted after a revoke resolution: E, refused while in
/// Error, is accepted once the revoke leaves Error, and listed once. Turns
/// red if Error outlives its resolution or E is double-listed. End to end.
#[tokio::test]
async fn refused_commit_lands_after_resolution() {
    let t = theft(false).await;
    let (app, state, _dir) = both_extended(&t, false).await;
    let pool = load_pool();
    let mut e = t.d.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    assert_eq!(push(&app, &e, t.n + 2, &t.id).await, ERRORED);
    revoke_eve(&app, NOW + 5).await;
    assert!(!errored(&state, &t.id).await);
    assert_eq!(
        push(&app, &e, t.n + 2, &t.id).await,
        StatusCode::CREATED,
        "E lands"
    );
    let list = heads(&app, &t.id).await;
    assert_eq!(
        list.iter().filter(|h| h.0 == t.n as u64 + 2).count(),
        1,
        "E is listed once, canonical: {list:?}"
    );
}

/// Backs SPEC 15.9 for branch commits: a rival dated past the witness
/// clock's tolerance (TIMESTAMP_FUTURE) or before the principal's latest
/// known `now` (TIMESTAMP_PAST) is refused and never retained, so it can
/// neither fork the principal nor put it in Error. Turns red if such a
/// rival is listed or makes the principal Error. End to end.
#[tokio::test]
async fn branch_commits_obey_timestamps() {
    let t = theft(true).await;
    let pool = load_pool();
    let (app, state, _dir) = theft_server(&t).await;
    let mut ahead = t.a.fork().await.expect("fork");
    create_key(
        &mut ahead,
        &kp(&pool, "golden"),
        &kp(&pool, "alice"),
        NOW + 50,
    )
    .await;
    assert_eq!(
        push(&app, &ahead, t.n + 1, &t.id).await,
        StatusCode::CREATED
    );

    // B (NOW+4) is older than the latest known `now` (NOW+50).
    let (status, body) = post_json(app.clone(), "/push", wire(&t.b, t.n, &t.id)).await;
    assert!(
        status.is_client_error(),
        "a past-dated rival is refused: {body:?}"
    );

    let mut future = t.shared.fork().await.expect("fork");
    future.set_clock(|| i64::from(u32::MAX));
    let late = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
        + 3600;
    create_key(&mut future, &kp(&pool, "golden"), &kp(&pool, "bob"), late).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&future, t.n, &t.id)).await;
    assert!(
        status.is_client_error(),
        "a future-dated rival is refused: {body:?}"
    );

    let list = heads(&app, &t.id).await;
    assert!(
        list.iter().all(|h| h.1),
        "neither rival is retained: {list:?}"
    );
    assert!(!errored(&state, &t.id).await, "no fork, no Error");
}

/// Backs first-seen time (SPEC 15.9; #203 "I saw this at x time"): every
/// listed branch carries the time this server first stored it, and a
/// rebuild serves the same time. Turns red if `seen` is absent, outside
/// the push window, or changes across a rebuild. End to end.
#[tokio::test]
async fn first_seen_survives_rebuild() {
    let t = theft(true).await;
    let clock = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    };
    let before = clock();
    let (app, state, dir) = theft_server(&t).await;
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    let after = clock();
    let (_, payload) = branches(app.clone(), &t.id).await;
    let listed = payload["branches"].as_array().expect("branches").clone();
    assert_eq!(listed.len(), 2, "{payload:?}");
    for b in &listed {
        let seen = b["seen"].as_i64().expect("seen is served");
        assert!(
            (before..=after).contains(&seen),
            "{seen} outside {before}..={after}"
        );
    }
    drop((app, state));
    let (app, _state) = reopen(dir.path()).await;
    let (_, payload) = branches(app, &t.id).await;
    assert_eq!(payload["branches"].as_array().expect("branches"), &listed);
}

/// A viewer that takes the protocol's word.
struct Protocol;

impl cyphr_storage::engine::Recovery for Protocol {
    fn review(
        &self,
        _: &str,
        protocol: cyphr_storage::engine::Consensus,
        _: &[cyphr_storage::engine::BranchTip],
    ) -> cyphr_storage::engine::Consensus {
        protocol
    }
}

/// A viewer that distrusts every resolved fork: one stolen key may have
/// resolved it first, so it holds the principal in Error while any
/// abandoned branch exists.
struct DistrustResolutions;

impl cyphr_storage::engine::Recovery for DistrustResolutions {
    fn review(
        &self,
        _: &str,
        protocol: cyphr_storage::engine::Consensus,
        branches: &[cyphr_storage::engine::BranchTip],
    ) -> cyphr_storage::engine::Consensus {
        if branches.iter().any(|b| !b.canonical) {
            cyphr_storage::engine::Consensus::Error
        } else {
            protocol
        }
    }
}

/// Backs the recovery seam: the verdict layer consults the strategy it is
/// given, and the engine's admission does not. After the thief's C
/// resolves the fork, the protocol (and a viewer taking its word) says
/// Active, a viewer distrusting resolutions says Error, and a commit
/// extending C is still admitted, since no strategy is wired into the
/// engine. Turns red if the strategy is ignored, or a strategy changes
/// what the engine admits. End to end over `/push` and the engine.
#[tokio::test]
async fn recovery_is_a_seam_not_a_rule() {
    use cyphr_storage::engine::Consensus;

    let t = theft(true).await;
    let (app, state, _dir) = theft_server(&t).await;
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.c, t.n + 1, &t.id).await, StatusCode::CREATED);
    let verdict = |r: &'static dyn cyphr_storage::engine::Recovery| {
        let state = state.clone();
        let id = t.id.clone();
        async move { state.engine.verdict(&id, r).await.expect("verdict") }
    };
    assert_eq!(verdict(&Protocol).await, Consensus::Active);
    assert_eq!(verdict(&DistrustResolutions).await, Consensus::Error);

    let pool = load_pool();
    let mut next = t.c.fork().await.expect("fork");
    create_key(
        &mut next,
        &kp(&pool, "golden"),
        &kp(&pool, "alice"),
        NOW + 9,
    )
    .await;
    assert_eq!(
        push(&app, &next, t.n + 2, &t.id).await,
        StatusCode::CREATED,
        "the engine admits by the protocol alone"
    );
}
