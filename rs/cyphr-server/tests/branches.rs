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

/// The commit ids `/tip` names as tied heads while the principal is in
/// Error; panics on any other answer, which would name a single tip.
fn error_heads(payload: &serde_json::Value) -> Vec<String> {
    assert_eq!(
        payload["state"], "error",
        "not an Error answer: {payload:?}"
    );
    payload["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .map(|h| h["commit_id"].as_str().expect("commit_id").to_owned())
        .collect()
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
    let after = tip_payload(app.clone(), &f.id).await;
    assert!(
        error_heads(&after).contains(&tip_before["commit_id"].as_str().expect("id").to_owned()),
        "the refused fork dropped the canonical head: {after:?}"
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
/// (extending A) ties C at the resolution point: both kept, C still the
/// tip, and the principal is in Error. An extension E of C, a tied head,
/// out-extends D, so it is admitted and the principal is Active, and the
/// verdict, tip and branch list are the same live and after a restart that
/// rebuilds from the blobs. Turns red if D is accepted as the tip or
/// dropped, E is refused or leaves Error standing, or a rebuild disagrees
/// with the live engine. End to end: yes.
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
    let errored_tip = tip_payload(app.clone(), id).await;
    assert!(
        error_heads(&errored_tip).contains(&tip["commit_id"].as_str().expect("id").to_owned()),
        "C stays held as a tied head"
    );
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
    assert_eq!(tip_payload(app.clone(), id).await, errored_tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        state.engine.is_errored(id).await.expect("verdict"),
        "a rebuild agrees: Error"
    );

    let (tip, list) = extend_c(&app, &c, n, id, StatusCode::CREATED).await;
    assert!(
        !state.engine.is_errored(id).await.expect("verdict"),
        "E out-extends D: Active"
    );
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(tip_payload(app.clone(), id).await, tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        !state.engine.is_errored(id).await.expect("verdict"),
        "Active survives a restart"
    );
}

/// The same verdict when E (extending C) arrives before D: D is then a
/// rival below the head, shorter than E's branch, so it is kept and the
/// principal stays Active with E the tip, live and after a restart. Turns
/// red if D's late arrival is dropped, the verdict depends on arrival
/// order, or a rebuild disagrees. End to end: yes.
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
        !state.engine.is_errored(id).await.expect("verdict"),
        "E's branch is taller than D's: Active"
    );

    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(tip_payload(app.clone(), id).await, tip);
    assert_eq!(heads(&app, id).await, list);
    assert!(
        !state.engine.is_errored(id).await.expect("verdict"),
        "Active survives a restart"
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

/// `eve` self-revokes (SPEC 6.4), dated `now` and received by this node
/// at `now`: the engine's cutoff for `eve` is that receipt time, as if the
/// server's clock read `now` when the revoke arrived.
async fn revoke_eve(state: &cyphr_server::AppState, now: i64) {
    let pool = load_pool();
    let e = kp(&pool, "eve_ed25519");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": e.alg, "now": now, "rvk": 1, "tmb": e.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &e.alg, &e.prv, &e.pubb).expect("sign");
    let envelope = serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": e.alg, "pub": Base64UrlUnpadded::encode_string(&e.pubb)},
    });
    state
        .observations
        .record_seen(&e.tmb, envelope.clone())
        .await
        .expect("observed");
    state
        .engine
        .record_revoke(&envelope, now)
        .await
        .expect("the engine keeps the revoke");
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

/// Backs the Error gate (SPEC 15.5, 15.7.1 "rejection of both branches
/// until resolved"): with C and D tied, a commit that extends neither (E,
/// a third child of A, beside D) and an action-only bundle are refused
/// without moving the tip, and E, which verifies on a held branch, is
/// retained as evidence (listed at `/branches`), live and after a
/// rebuild. Turns red if either is accepted, the tip moves, or E is
/// dropped. End to end.
#[tokio::test]
async fn errored_refuses_and_retains() {
    let t = theft(false).await;
    let (app, state, dir) = both_extended(&t, false).await;
    let tip = tip_payload(app.clone(), &t.id).await;
    let pool = load_pool();
    let mut e = t.a.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    let status = push(&app, &e, t.n + 1, &t.id).await;
    assert!(status.is_client_error(), "E extends no tied head: {status}");
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
    // E is held as evidence and ties the greatest height too, so it joins
    // the tied heads; nothing else moved.
    let after = tip_payload(app.clone(), &t.id).await;
    assert_eq!(after["fork_point"], tip["fork_point"], "the fork point");
    let (before, now) = (error_heads(&tip), error_heads(&after));
    assert!(
        before.iter().all(|h| now.contains(h)) && now.len() == before.len() + 1,
        "C and D stay heads and E joins them: {before:?} -> {now:?}"
    );
    let list = heads(&app, &t.id).await;
    assert_eq!(
        list.iter()
            .filter(|h| !h.1 && h.0 == t.n as u64 + 1)
            .count(),
        2,
        "C and E are retained at n+1: {list:?}"
    );
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(errored(&state, &t.id).await, "Error survives a rebuild");
    assert_eq!(tip_payload(app.clone(), &t.id).await, after);
    assert_eq!(heads(&app, &t.id).await, list, "E survives a rebuild");
}

/// Backs a revoke as an admission gate only (SPEC 14.12; #203): with the
/// owner's D and the thief's C tied, in either arrival order of the
/// branches, a naked revoke of `eve` received before every thief commit
/// (NOW+4) or after them (NOW+100) re-judges no held commit. Error stands
/// with both heads, nothing moves or is dropped, and a rebuild agrees; the
/// owner resolves forward. Turns red if a revoke takes a held commit out
/// of the fork.
#[tokio::test]
async fn a_revoke_does_not_resolve_both_extended() {
    for thief_first in [true, false] {
        for received in [NOW + 4, NOW + 100] {
            let t = theft(thief_first).await;
            let (app, state, dir) = both_extended(&t, thief_first).await;
            let case = format!("thief_first={thief_first}, received {received}");
            let before = verdict(&app, &state, &t.id).await;
            let list = heads(&app, &t.id).await;
            assert!(before.0, "{case}: C and D tie");
            revoke_eve(&state, received).await;
            assert_eq!(verdict(&app, &state, &t.id).await, before, "{case}: live");
            assert_eq!(heads(&app, &t.id).await, list, "{case}: nothing is dropped");
            drop((app, state));
            let (app, state) = reopen(dir.path()).await;
            assert_eq!(
                verdict(&app, &state, &t.id).await,
                before,
                "{case}: a rebuild agrees"
            );
        }
    }
}

/// Backs SPEC 15.9 for branch commits: a rival dated past the witness
/// clock's tolerance (TIMESTAMP_FUTURE) is refused and never retained; one
/// dated before the principal's latest known `now` (TIMESTAMP_PAST) is
/// refused without moving the tip, and kept only as proof of error (SPEC
/// 15.7.1: a quick-succession fork is evidence of compromise). Turns red if
/// either moves the tip, the future-dated rival is kept, or the past-dated
/// one puts the extended chain in Error. End to end.
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

    let tip = tip_payload(app.clone(), &t.id).await;

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

    assert_eq!(
        tip_payload(app.clone(), &t.id).await,
        tip,
        "the tip did not move"
    );
    let list = heads(&app, &t.id).await;
    let kept: Vec<_> = list.iter().filter(|h| !h.1).collect();
    assert_eq!(kept.len(), 1, "only B is kept: {list:?}");
    assert_eq!(kept[0].0, t.n as u64, "B, at the fork position: {list:?}");
    assert!(
        !errored(&state, &t.id).await,
        "A is extended and B is not: Active"
    );
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

/// After the thief's C resolves the fork, a commit extending C is still
/// admitted: what the engine admits is the protocol alone, and no viewer
/// strategy is wired into it. Turns red if admission consults anything but
/// the protocol. End to end over `/push` and the engine.
#[tokio::test]
async fn a_commit_extending_the_resolution_is_admitted() {
    let t = theft(true).await;
    let (app, _state, _dir) = theft_server(&t).await;
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.c, t.n + 1, &t.id).await, StatusCode::CREATED);

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

// ========================================================================
// ERR1 attack review (at 180a221): each path as a failing test, ignored
// until the design ruling. Every test asserts the safe outcome, so it is
// red while the path is open.
// ========================================================================

/// `signer` signs a one-transaction commit of `pay` (its `alg`, `now`,
/// `tmb` filled in) on `p`, introducing `new` if given.
async fn sign_commit(
    p: &mut cyphr::Principal,
    signer: &Kp,
    mut pay: serde_json::Value,
    new: Option<&Kp>,
    now: i64,
) {
    pay["alg"] = signer.alg.clone().into();
    pay["now"] = now.into();
    pay["tmb"] = signer.tmb.to_b64().into();
    // The wire form is canonical (sorted) JSON; sign exactly that.
    if let Some(obj) = pay.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, new.map(key_of))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .expect("finalize");
}

/// The chain the A1/A3 attacks start from: genesis (`golden`, `diana`,
/// `eve`) at NOW+2, then A by `golden` at NOW+3, X by `eve` (K) at NOW+10,
/// Y by `golden` at NOW+11. The attacker holds `eve` and builds B over A,
/// dated A's `now` (NOW+3), and B' over B at NOW+3.
struct Rewrite {
    id: String,
    n: usize,
    chain: cyphr::Principal,
    b: cyphr::Principal,
    b2: cyphr::Principal,
}

async fn rewrite() -> Rewrite {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let mut a = shared.fork().await.expect("fork");
    create_key(&mut a, &g, &kp(&pool, "key_a"), NOW + 3).await;
    let mut chain = a.fork().await.expect("fork");
    create_key(&mut chain, &e, &kp(&pool, "alice"), NOW + 10).await;
    create_key(&mut chain, &g, &kp(&pool, "bob"), NOW + 11).await;
    let mut b = a.fork().await.expect("fork");
    create_key(&mut b, &e, &kp(&pool, "key_b"), NOW + 3).await;
    let mut b2 = b.fork().await.expect("fork");
    create_key(&mut b2, &e, &kp(&pool, "carol"), NOW + 3).await;
    Rewrite {
        id,
        n,
        chain,
        b,
        b2,
    }
}

/// A server holding the whole canonical chain of `r` (genesis .. Y).
async fn rewrite_server(
    r: &Rewrite,
) -> (
    axum::Router,
    std::sync::Arc<cyphr_server::AppState>,
    tempfile::TempDir,
) {
    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    for i in 0..r.n + 3 {
        assert_eq!(
            push(&app, &r.chain, i, &r.id).await,
            StatusCode::CREATED,
            "chain {i}"
        );
    }
    (app, state, dir)
}

/// A1, a revoke after a backdated rival line (SPEC 14.12: a revoke gates
/// arrivals and re-judges nothing held). The holder of K (`eve`, which
/// signed canonical X at n+1, NOW+10) pushes B at n+1 dated A's `now`,
/// then B' over B: B' ties Y, Error. K's revoke, received at NOW+4, takes
/// nothing out: X, Y, B and B' are all held, Error stands with Y served,
/// live and after a rebuild. The owner answers forward: a commit over Y
/// out-extends B', Active. Turns red if a revoke moves or uncounts a held
/// commit, or the owner's forward commit does not resolve the fork.
#[tokio::test]
async fn a1_a_revoke_rejudges_no_held_rival() {
    let r = rewrite().await;
    let (app, state, dir) = rewrite_server(&r).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&r.b, r.n + 1, &r.id)).await;
    assert!(status.is_client_error(), "B is refused: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", wire(&r.b2, r.n + 2, &r.id)).await;
    assert!(status.is_client_error(), "B' is refused: {body:?}");
    let before = verdict(&app, &state, &r.id).await;
    assert!(before.0, "B' ties Y: Error");
    revoke_eve(&state, NOW + 4).await;
    assert_eq!(verdict(&app, &state, &r.id).await, before, "live");
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert_eq!(
        verdict(&app, &state, &r.id).await,
        before,
        "after a restart"
    );
    let pool = load_pool();
    let mut next = r.chain.fork().await.expect("fork");
    create_key(
        &mut next,
        &kp(&pool, "golden"),
        &kp(&pool, "carol"),
        NOW + 12,
    )
    .await;
    assert_eq!(push(&app, &next, r.n + 3, &r.id).await, StatusCode::CREATED);
    assert!(
        !errored(&state, &r.id).await,
        "the owner's commit out-extends B'"
    );
}

/// A2: a deleted key's signatures from its active period stand (SPEC
/// 6.2). `eve` was active at position n and the owner has since deleted
/// it on-chain (A then D at n+1). Its holder pushes B at n and B' over B:
/// B' ties D, so the principal is in Error. The owner's next ordinary
/// commit extends D, a tied head, so it is admitted and resolves the fork
/// (SPEC 15.8 item 1): Active, live and after a rebuild. Turns red if the
/// deleted key's branch is not counted, or the owner's commit is refused.
#[tokio::test]
async fn a2_owner_resolves_a_deleted_keys_tie() {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let mut chain = shared.fork().await.expect("fork");
    create_key(&mut chain, &g, &kp(&pool, "key_a"), NOW + 3).await;
    sign_commit(
        &mut chain,
        &g,
        serde_json::json!({"id": e.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        NOW + 4,
    )
    .await;
    let mut b = shared.fork().await.expect("fork");
    create_key(&mut b, &e, &kp(&pool, "key_b"), NOW + 3).await;
    let mut b2 = b.fork().await.expect("fork");
    create_key(&mut b2, &e, &kp(&pool, "carol"), NOW + 3).await;

    let (state, dir) = keyless_server();
    let app = build_router(state.clone());
    for i in 0..n + 2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&chain, i, &id)).await;
        assert_eq!(status, StatusCode::CREATED, "chain {i}: {body:?}");
    }
    let (status, body) = post_json(app.clone(), "/push", wire(&b, n, &id)).await;
    assert!(status.is_client_error(), "B: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", wire(&b2, n + 1, &id)).await;
    assert!(status.is_client_error(), "B': {body:?}");
    assert!(errored(&state, &id).await, "B' ties the delete: Error");

    let mut next = chain.fork().await.expect("fork");
    create_key(&mut next, &g, &kp(&pool, "bob"), NOW + 5).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&next, n + 2, &id)).await;
    assert_eq!(status, StatusCode::CREATED, "the owner's commit: {body:?}");
    assert!(!errored(&state, &id).await, "it out-extends B': Active");
    let tip = tip_payload(app.clone(), &id).await;
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(!errored(&state, &id).await, "a rebuild agrees");
    assert_eq!(tip_payload(app, &id).await, tip);
}

/// A3: live and rebuilt state disagree. K (`eve`) is revoked first as of
/// NOW+5, which invalidates X and Y but leaves no alternative, so live
/// keeps Y. Then B and B' (dated NOW+3, below `rvk`) arrive by gossip
/// ingest (`submit_commit`, which the server's dead-key gate does not
/// front). Live never runs `settle` on ingest, so Y stays the tip; a
/// rebuild runs it and moves the chain to B'. Safe outcome: the rebuilt
/// tip equals the live tip.
#[tokio::test]
async fn a3_live_and_rebuild_disagree() {
    let r = rewrite().await;
    let (app, state, dir) = rewrite_server(&r).await;
    revoke_eve(&state, NOW + 5).await;
    for (p, at) in [(&r.b, r.n + 1), (&r.b2, r.n + 2)] {
        let bundle = cyphr_storage::export_commits(p).expect("export")[at]
            .bundle()
            .expect("bundle");
        let refused = state.engine.submit_commit(&r.id, None, &bundle).await;
        assert!(refused.is_err(), "a rival is refused as the tip");
    }
    let live = tip_payload(app.clone(), &r.id).await;
    drop((app, state));
    let (app, _state) = reopen(dir.path()).await;
    assert_eq!(
        tip_payload(app, &r.id).await["commit_id"],
        live["commit_id"],
        "a rebuild serves another tip than the live engine did"
    );
}

/// A4: re-signed revokes store nothing. The first revoke of a key this
/// node accepts stands (SPEC 6.4; the spec author on #203: the cutoff is
/// the witness's receipt time of it), so a later revoke of the key, whatever
/// its `now`, `rvk` or `msg`, and whenever it arrives, adds no blob. Turns
/// red if a revoke of a key already dead stores a record.
#[tokio::test]
async fn a4_resigned_revokes_store_nothing() {
    use cyphr_storage::blob::BlobStore;

    let t = theft(true).await;
    let (_app, state, _dir) = theft_server(&t).await;
    let blobs = || async {
        state
            .engine
            .blob_store()
            .iter()
            .await
            .expect("iter")
            .count()
    };
    let pool = load_pool();
    let e = kp(&pool, "eve_ed25519");
    let revoke = |msg: &'static str, now: i64| {
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": e.alg, "msg": msg, "now": now, "rvk": 1,
            "tmb": e.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/revoke"
        }))
        .expect("pay");
        let (sig, _) = coz::sign_json(&pay, &e.alg, &e.prv, &e.pubb).expect("sign");
        serde_json::json!({
            "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
            "sig": Base64UrlUnpadded::encode_string(&sig),
            "key": {"alg": e.alg, "pub": Base64UrlUnpadded::encode_string(&e.pubb)},
        })
    };
    state
        .engine
        .record_revoke(&revoke("first", NOW + 5), NOW + 5)
        .await
        .expect("first");
    // (msg, its own now, when this node receives it): whatever either says,
    // a key already dead stores nothing more.
    for (msg, now, wrt) in [
        ("first", NOW + 5, NOW + 6),
        ("second", NOW + 5, NOW + 6),
        ("later", NOW + 50, NOW + 50),
        ("earlier", NOW + 1, NOW + 7),
        ("received earlier", NOW + 1, NOW + 1),
    ] {
        let before = blobs().await;
        state
            .engine
            .record_revoke(&revoke(msg, now), wrt)
            .await
            .expect("a Coz-valid revoke is accepted");
        assert_eq!(
            blobs().await,
            before,
            "revoke `{msg}` (now {now}, received {wrt}) grew the store"
        );
    }
}

/// Backs fix 3 (SPEC 15.7.1, 15.8 item 1): a `key/delete` resolves a fork
/// only as an ordinary extending commit. In Error with C and D tied, the
/// owner's delete of `eve` extends D, a tied head, so it is admitted and
/// the principal is Active, live and after a rebuild. That the delete
/// takes nothing out of the fork is
/// [`a_deleted_keys_line_counts_and_can_out_extend`]. Turns red if the
/// delete is refused or Error stands.
#[tokio::test]
async fn key_delete_resolves_only_as_an_extension() {
    let pool = load_pool();
    let t = theft(false).await;
    let (app, state, dir) = both_extended(&t, false).await;
    let mut del = t.d.fork().await.expect("fork");
    sign_commit(
        &mut del,
        &kp(&pool, "golden"),
        serde_json::json!({
            "id": kp(&pool, "eve_ed25519").tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/delete"
        }),
        None,
        NOW + 7,
    )
    .await;
    let (status, body) = post_json(app.clone(), "/push", wire(&del, t.n + 2, &t.id)).await;
    assert_eq!(status, StatusCode::CREATED, "the delete resolves: {body:?}");
    assert!(!errored(&state, &t.id).await, "eve's rivals left the fork");
    let tip = tip_payload(app.clone(), &t.id).await;
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(!errored(&state, &t.id).await, "a rebuild agrees");
    assert_eq!(tip_payload(app, &t.id).await, tip);
}

/// The same at the peer whose canonical chain is the losing branch: the
/// thief resolved first here, so B and C are canonical and the owner's A
/// and D are retained. The owner's `key/delete` of `eve` extends D, so it
/// out-extends C and promotes the owner's branch as any extending commit
/// would (SPEC 15.8 item 1): Active with the delete as `/tip`, live and
/// after a rebuild, as at the peer where the owner was canonical. Turns
/// red if the delete is refused (423) or Error stands. End to end.
#[tokio::test]
async fn key_delete_promotes_at_the_losing_peer() {
    let pool = load_pool();
    let t = theft(true).await;
    let (app, state, dir) = both_extended(&t, true).await;
    let mut del = t.d.fork().await.expect("fork");
    sign_commit(
        &mut del,
        &kp(&pool, "golden"),
        serde_json::json!({
            "id": kp(&pool, "eve_ed25519").tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/delete"
        }),
        None,
        NOW + 7,
    )
    .await;
    let (status, body) = post_json(app.clone(), "/push", wire(&del, t.n + 2, &t.id)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the delete promotes D: {body:?}"
    );
    assert!(!errored(&state, &t.id).await, "the delete out-extends C");
    let tip = tip_payload(app.clone(), &t.id).await;
    assert_eq!(
        tip["commit_id"], body["payload"]["commit_id"],
        "the delete is /tip"
    );
    drop((app, state));
    let (app, state) = reopen(dir.path()).await;
    assert!(!errored(&state, &t.id).await, "a rebuild agrees");
    assert_eq!(tip_payload(app, &t.id).await, tip);
}

/// Backs SPEC 6.2 ("past signatures from previous active periods remain
/// valid") under the fork rule: the owner deletes K (`eve`) at the head
/// position d; K's holder then pushes R_{d-1} over the commit below the
/// owner's d-1, R_d over it, and R_{d+1} over R_d, all dated inside K's
/// active period. A removal demotes no earlier signature, so the line
/// counts: R_d ties the deletion (Error), and R_{d+1} out-extends it and is
/// admitted as the tip, Active. What undoes it is recovery (SPEC 14), not a
/// rule here. Turns red if the deleted key's line is not counted.
#[tokio::test]
async fn a_deleted_keys_line_counts_and_can_out_extend() {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let mut chain = shared.fork().await.expect("fork");
    create_key(&mut chain, &g, &kp(&pool, "key_a"), NOW + 3).await;
    sign_commit(
        &mut chain,
        &g,
        serde_json::json!({"id": e.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        NOW + 4,
    )
    .await;
    let mut r = shared.fork().await.expect("fork");
    create_key(&mut r, &e, &kp(&pool, "key_b"), NOW + 3).await;
    create_key(&mut r, &e, &kp(&pool, "carol"), NOW + 3).await;
    create_key(&mut r, &e, &kp(&pool, "bob"), NOW + 3).await;

    let (state, _dir) = keyless_server();
    let app = build_router(state.clone());
    for i in 0..n + 2 {
        let (status, body) = post_json(app.clone(), "/push", wire(&chain, i, &id)).await;
        assert_eq!(status, StatusCode::CREATED, "chain {i}: {body:?}");
    }
    let tip = tip_payload(app.clone(), &id).await;
    for i in [n, n + 1] {
        let (status, body) = post_json(app.clone(), "/push", wire(&r, i, &id)).await;
        assert!(status.is_client_error(), "R at {i}: {body:?}");
    }
    assert!(errored(&state, &id).await, "R_d ties the deletion: Error");
    assert!(
        error_heads(&tip_payload(app.clone(), &id).await)
            .contains(&tip["commit_id"].as_str().expect("id").to_owned()),
        "the chain stays held as a tied head"
    );
    let (status, body) = post_json(app.clone(), "/push", wire(&r, n + 2, &id)).await;
    assert_eq!(status, StatusCode::CREATED, "R_(d+1): {body:?}");
    assert_eq!(
        tip_payload(app, &id).await["commit_id"],
        commit_id_at(&r, n + 2),
        "R_(d+1) is the tip"
    );
    assert!(!errored(&state, &id).await, "the taller line: Active");
}

/// Backs the retention bound on promotion against a thief: the thief's B
/// and C are canonical here, the owner's A and D retained, and the thief
/// also retains one more `eve`-signed rival B2 at n. The owner's
/// `key/delete` of `eve` over D promotes the owner's line and displaces B
/// and C. Displaced commits are blobs already held, swapped one for one
/// with the line, so they never count against `eve`'s per-key quota: the
/// thief cannot arm that quota to refuse the owner's resolution. The
/// delete is admitted, the principal is Active and the delete is `/tip`.
/// Turns red if the resolution is refused.
#[tokio::test]
async fn a_thief_cannot_arm_the_quota_against_a_resolution() {
    let pool = load_pool();
    let t = theft(true).await;
    let (app, state, _dir) = both_extended(&t, true).await;
    let eve = kp(&pool, "eve_ed25519");
    let mut b2 = t.shared.fork().await.expect("fork");
    create_key(&mut b2, &eve, &kp(&pool, "bob"), NOW + 4).await;
    let (status, body) = post_json(app.clone(), "/push", wire(&b2, t.n, &t.id)).await;
    assert!(status.is_client_error(), "B2 is a rival: {body:?}");
    let retained =
        |b: &Vec<cyphr_storage::engine::BranchTip>| b.iter().filter(|b| !b.canonical).count();
    let before = state.engine.list_branches(&t.id).await.expect("branches");
    assert_eq!(retained(&before), 3, "A, D and B2 are retained");
    let mut del = t.d.fork().await.expect("fork");
    sign_commit(
        &mut del,
        &kp(&pool, "golden"),
        serde_json::json!({"id": eve.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        NOW + 7,
    )
    .await;
    let (status, body) = post_json(app.clone(), "/push", wire(&del, t.n + 2, &t.id)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the owner's resolution: {body:?}"
    );
    assert!(!errored(&state, &t.id).await, "eve's rivals left the fork");
    let tip = tip_payload(app, &t.id).await;
    assert_eq!(
        tip["commit_id"], body["payload"]["commit_id"],
        "the delete is /tip"
    );
    let after = state.engine.list_branches(&t.id).await.expect("branches");
    assert_eq!(
        retained(&after),
        3,
        "B, C and B2 retained in A and D's place"
    );
}

/// `old` replaces itself with `new` (SPEC 6.3) at `now`, the commit
/// finalized by `new`, the key it leaves active.
async fn replace_key(p: &mut cyphr::Principal, old: &Kp, new: &Kp, now: i64) {
    let mut pay = serde_json::json!({
        "alg": old.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": old.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/replace"
    });
    if let Some(obj) = pay.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &old.alg, &old.prv, &old.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &old.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(new), now, "cyphr.me")
        .await
        .expect("finalize");
}

/// Backs the narrowed rule 3 on S04's rotation shape: the owner and the
/// thief each `key/replace` the stolen key (`eve`) at the same position.
/// A contested commit is judged against the state before its position, so
/// neither replacement disqualifies its rival: every peer, whichever it
/// saw first, is in Error with no branch picked, live and after a
/// rebuild. Turns red if either peer reports Active. End to end.
#[tokio::test]
async fn rival_rotations_are_error_at_every_peer() {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let mut owner = shared.fork().await.expect("fork");
    replace_key(&mut owner, &e, &kp(&pool, "alice"), NOW + 3).await;
    let mut thief = shared.fork().await.expect("fork");
    replace_key(&mut thief, &e, &kp(&pool, "bob"), NOW + 4).await;

    for (first, second) in [(&owner, &thief), (&thief, &owner)] {
        let (state, dir) = keyless_server();
        let app = build_router(state.clone());
        for i in 0..n {
            assert_eq!(push(&app, &shared, i, &id).await, StatusCode::CREATED);
        }
        let (status, body) = post_json(app.clone(), "/push", wire(first, n, &id)).await;
        assert_eq!(status, StatusCode::CREATED, "first rotation: {body:?}");
        let (status, body) = post_json(app.clone(), "/push", wire(second, n, &id)).await;
        // Refused as the tip: the key it replaces is gone from the tip.
        assert!(status.is_client_error(), "second rotation: {body:?}");
        let list = heads(&app, &id).await;
        assert_eq!(list.len(), 2, "both rotations are held: {list:?}");
        assert!(errored(&state, &id).await, "rival rotations: Error");
        drop((app, state));
        let (_app, state) = reopen(dir.path()).await;
        assert!(errored(&state, &id).await, "a rebuild agrees: Error");
    }
}

/// Backs the S04 shape at the witness holding the thief's chain: the
/// thief's B is canonical and the owner's A is retained; the stolen key
/// (`eve`) is naked-revoked; the owner then pushes a commit extending A
/// that deletes `eve`. It extends a retained tip, so it promotes A's
/// branch (SPEC 15.8 item 1), and with `eve` revoked B is no rival: the
/// principal is Active, `/tip` answers with the owner's commit, live and
/// after a rebuild. Turns red if `/tip` stops answering, the commit is
/// refused, or Error stands. End to end.
#[tokio::test]
async fn owner_delete_promotes_over_revoked_thief_chain() {
    let pool = load_pool();
    let t = theft(true).await;
    // Keyed, as scenario peers are: `/tip` re-derives the roots it signs.
    let (state, _identity, dir) = common::attestor_server().await;
    let app = build_router(state.clone());
    for i in 0..t.n {
        assert_eq!(push(&app, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CREATED, "B");
    // A (NOW+3) is dated before B (NOW+4): refused, kept as the rival.
    assert!(push(&app, &t.a, t.n, &t.id).await.is_client_error(), "A");
    assert_eq!(heads(&app, &t.id).await.len(), 2, "A is retained");
    revoke_eve(&state, NOW + 100).await;

    let mut del = t.a.fork().await.expect("fork");
    sign_commit(
        &mut del,
        &kp(&pool, "golden"),
        serde_json::json!({
            "id": kp(&pool, "eve_ed25519").tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/delete"
        }),
        None,
        NOW + 7,
    )
    .await;
    let (status, body) = post_json(app.clone(), "/push", wire(&del, t.n + 1, &t.id)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the delete promotes A: {body:?}"
    );
    let (status, tip) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        get_json(app.clone(), &format!("/tip?pr={}", enc(&t.id))),
    )
    .await
    .expect("/tip answers in time after the promotion");
    assert_eq!(status, StatusCode::OK, "/tip answers: {tip:?}");
    let mut tip = tip["payload"].clone();
    tip.as_object_mut().expect("tip").remove("now");
    assert_eq!(
        tip["commit_id"], body["payload"]["commit_id"],
        "the delete is /tip"
    );
    assert!(!errored(&state, &t.id).await, "B is no rival: Active");
    drop((app, state));
    let (app, state) = reopen(&dir.path().join("data")).await;
    assert_eq!(tip_payload(app, &t.id).await, tip, "a rebuild agrees");
    assert!(!errored(&state, &t.id).await, "a rebuild agrees: Active");
}

/// `signer` signs `fields` plus its own `alg` and `tmb`: (pay, sig, czd).
fn signs(signer: &Kp, mut fields: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    fields["alg"] = signer.alg.clone().into();
    fields["tmb"] = signer.tmb.to_b64().into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&fields).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    (pay, sig, czd)
}

/// [`data_commit`] signed by `signer`: a data action at `now`, then the
/// `ds/create` including it at `now + 1`.
async fn data_commit_by(
    p: &mut cyphr::Principal,
    signer: &Kp,
    msg: &str,
    now: i64,
) -> (Vec<u8>, cyphr::replay::WireBundle) {
    let (pay, sig, czd) = signs(
        signer,
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
    let (pay, sig, czd) = signs(
        signer,
        serde_json::json!({"id": dr, "now": now + 1, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create applies");
    scope
        .finalize_with_software(&signer_of(signer), now + 1, "cyphr.me")
        .await
        .expect("commit finalizes");
    let bundle = cyphr::replay::WireBundle::of_commit(p.commits().last().expect("a commit"))
        .expect("bundle");
    (wire_action, bundle)
}

/// The S04 shape with data commits, as the scenario's clients make them:
/// at this keyed witness the thief's data commit is canonical (its action
/// pushed alone first, so stored at the fork position), and the owner's
/// data commit, carrying its own action inline, is retained. After the
/// stolen key's naked revoke, the owner's `key/delete` of it extends her
/// retained tip: it promotes her branch, `/tip` answers with it, and the
/// principal is Active, live and after a rebuild. Turns red if `/tip`
/// stops answering or Error stands. End to end.
#[tokio::test]
async fn owner_delete_promotes_over_thief_data_chain() {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let (state, _identity, dir) = common::attestor_server().await;
    let app = build_router(state.clone());
    for i in 0..n {
        assert_eq!(push(&app, &shared, i, &id).await, StatusCode::CREATED);
    }
    let mut thief = shared.fork().await.expect("fork");
    let (action, commit) = data_commit_by(&mut thief, &e, "thief", NOW + 10).await;
    let (status, body) = post_json(app.clone(), "/push", common::push_blobs(&id, &[action])).await;
    assert!(status.is_success(), "thief action: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "thief commit: {body:?}");

    let mut owner = shared.fork().await.expect("fork");
    let (action, mut commit) = data_commit_by(&mut owner, &g, "owner", NOW + 3).await;
    commit.actions = vec![action];
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &commit)).await;
    assert!(status.is_client_error(), "owner's rival: {body:?}");
    assert_eq!(
        heads(&app, &id).await.len(),
        2,
        "the owner's commit is retained"
    );
    revoke_eve(&state, NOW + 100).await;

    sign_commit(
        &mut owner,
        &g,
        serde_json::json!({"id": e.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        NOW + 12,
    )
    .await;
    let del = cyphr::replay::WireBundle::of_commit(owner.commits().last().expect("a commit"))
        .expect("bundle");
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &del)).await;
    assert_eq!(status, StatusCode::CREATED, "the delete promotes: {body:?}");
    let (status, tip) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        get_json(app.clone(), &format!("/tip?pr={}", enc(&id))),
    )
    .await
    .expect("/tip answers in time after the promotion");
    assert_eq!(status, StatusCode::OK, "/tip answers: {tip:?}");
    assert_eq!(tip["payload"]["commit_id"], body["payload"]["commit_id"]);
    assert!(!errored(&state, &id).await, "the thief is no rival: Active");
    let mut tip = tip["payload"].clone();
    tip.as_object_mut().expect("tip").remove("now");
    drop((app, state));
    let (app, state) = reopen(&dir.path().join("data")).await;
    assert_eq!(tip_payload(app, &id).await, tip, "a rebuild agrees");
    assert!(!errored(&state, &id).await, "a rebuild agrees: Active");
}

/// Backs `/patch` matching the server's own replay after a promotion over
/// a thief's data chain (SPEC 4.8.2, 15.8): the thief's action, pushed
/// alone at the fork position, is no part of the owner's promoted chain,
/// so `/patch` does not serve it and a fresh client that replays the
/// served chain from its genesis commit reaches the PR `/tip` publishes.
///
/// Turns red if: `/patch` serves the displaced action, which the fresh
/// client records ahead of the owner's older inline action
/// (`TimestampPast`) and so refuses the peer. End to end over `/push`,
/// `/patch` and the client's pull replay: yes.
#[tokio::test]
async fn fresh_client_replays_after_thief_data_promotion() {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    let (state, _dir) = keyless_server();
    let app = build_router(state.clone());
    for i in 0..n {
        assert_eq!(push(&app, &shared, i, &id).await, StatusCode::CREATED);
    }
    let mut thief = shared.fork().await.expect("fork");
    let (action, commit) = data_commit_by(&mut thief, &e, "thief", NOW + 10).await;
    let (status, body) = post_json(app.clone(), "/push", common::push_blobs(&id, &[action])).await;
    assert!(status.is_success(), "thief action: {body:?}");
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &commit)).await;
    assert_eq!(status, StatusCode::CREATED, "thief commit: {body:?}");
    let mut owner = shared.fork().await.expect("fork");
    let (action, mut commit) = data_commit_by(&mut owner, &g, "owner", NOW + 3).await;
    commit.actions = vec![action];
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &commit)).await;
    assert!(status.is_client_error(), "owner's rival: {body:?}");
    revoke_eve(&state, NOW + 100).await;
    sign_commit(
        &mut owner,
        &g,
        serde_json::json!({"id": e.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        NOW + 12,
    )
    .await;
    let del = cyphr::replay::WireBundle::of_commit(owner.commits().last().expect("a commit"))
        .expect("bundle");
    let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, &del)).await;
    assert_eq!(status, StatusCode::CREATED, "the delete promotes: {body:?}");

    let published = tip_payload(app.clone(), &id).await["pr"]
        .as_str()
        .expect("pr")
        .to_owned();
    let (status, served) = get_json(app.clone(), &format!("/patch?pr={}", enc(&id))).await;
    assert_eq!(status, StatusCode::OK, "{served:?}");
    let bytes = serde_json::to_vec(&served).expect("body");
    let patch = cyphr_client::verify_patch_body(&bytes, &id, None).expect("well-formed patch");
    let genesis_commit = envelope_payload(&served)["entries"][0]["commit_id"]
        .as_str()
        .expect("genesis commit id")
        .to_owned();
    let record = cyphr_client::Record::from_entries(
        &id,
        cyphr_client::Anchor::GenesisCommit(genesis_commit),
        cyphr::principal::system_clock,
        &patch.entries,
        &patch.actions,
    )
    .await
    .expect("a fresh client replays the served chain");
    assert_eq!(record.tip().expect("tip").pr, published);
    assert_eq!(owner.pr_tagged().expect("pr"), published);
}

// ========================================================================
// The fork rule (SPEC 15.8; nrd: "the commit resolves the fork. If that
// fails or it's done maliciously, then you have to fall back on
// recovery"), made deterministic: walk from genesis, at each fork follow
// the child whose subtree is tallest, and two equally tall subtrees are
// Error. The thief (holding `eve`) signs A, D, F and G; the owner
// (`golden`) signs B, C and E.
// ========================================================================

/// The commits of the fork-rule table, over one shared prefix of `n`.
struct Table {
    id: String,
    n: usize,
    shared: cyphr::Principal,
    /// The thief's line: A at n, D, F, G above it.
    thief: cyphr::Principal,
    /// The owner's line: B at n, C, E above it.
    owner: cyphr::Principal,
}

async fn table() -> Table {
    let pool = load_pool();
    let (g, e) = (kp(&pool, "golden"), kp(&pool, "eve_ed25519"));
    let (shared, id) = genesis(&[&g, &kp(&pool, "diana_es384"), &e], NOW + 2).await;
    let n = cyphr_storage::export_commits(&shared)
        .expect("export")
        .len();
    // The thief adds `alice` in D and signs F and G with it: each key
    // retains at most two rivals here (`BRANCH_PER_KEY`), so one stolen key
    // alone cannot hold a line of four. The owner's C adds `alice` too,
    // which the engine needs before it retains a commit `alice` signs: it
    // authenticates a rival's signer against the canonical chain's keys.
    let mut thief = shared.fork().await.expect("fork");
    let alice = kp(&pool, "alice");
    create_key(&mut thief, &e, &kp(&pool, "key_a"), NOW + 3).await;
    create_key(&mut thief, &e, &alice, NOW + 5).await;
    create_key(&mut thief, &alice, &kp(&pool, "bob"), NOW + 7).await;
    create_key(&mut thief, &alice, &kp(&pool, "carol"), NOW + 8).await;
    let mut owner = shared.fork().await.expect("fork");
    for (new, now) in [("key_b", 4), ("alice", 6), ("bob", 7)] {
        create_key(&mut owner, &g, &kp(&pool, new), NOW + now).await;
    }
    Table {
        id,
        n,
        shared,
        thief,
        owner,
    }
}

/// One row of the fork table: (who pushes, the position, admitted?,
/// Error?, `/tip`, the heads).
type Row<'a> = (
    &'a cyphr::Principal,
    usize,
    bool,
    bool,
    serde_json::Value,
    Vec<serde_json::Value>,
);

/// The verdict a peer holds: (Error?, `/tip` commit id, the heads). In Error
/// `/tip` names no single tip, so the commit id is null.
async fn verdict(
    app: &axum::Router,
    state: &cyphr_server::AppState,
    id: &str,
) -> (bool, serde_json::Value, Vec<String>) {
    let assessed = state.engine.assess(id).await.expect("assess");
    (
        assessed.consensus == cyphr_storage::engine::Consensus::Error,
        tip_payload(app.clone(), id).await["commit_id"].clone(),
        assessed.heads,
    )
}

/// The commit id of `p`'s commit at `i`.
fn commit_id_at(p: &cyphr::Principal, i: usize) -> serde_json::Value {
    let id = p.commits().nth(i).expect("commit").tr().0.tagged_first();
    serde_json::Value::String(id.expect("commit id").to_string())
}

/// Backs the five-row fork table end to end, each row's verdict checked
/// live and again after a restart that rebuilds from the blobs:
///
/// | Held                  | Result                |
/// | A, B at n             | Error                 |
/// | + C on B              | Active on B           |
/// | + D on A              | Error                 |
/// | + E on C              | Active on B's branch  |
/// | thief out-extends     | Active on the thief's |
///
/// Turns red if any row's verdict, `/tip` or heads differ, or a restart
/// changes them.
#[tokio::test]
async fn fork_table_tallest_subtree_wins_and_a_tie_is_error() {
    let t = table().await;
    let (state, dir) = keyless_server();
    let mut app = build_router(state.clone());
    let mut state = state;
    for i in 0..t.n {
        assert_eq!(push(&app, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    let (n, at) = (t.n, |p: &cyphr::Principal, i| commit_id_at(p, i));
    let a = || at(&t.thief, n);
    let rows: [Row<'_>; 7] = [
        (&t.thief, n, true, false, a(), vec![a()]),
        // Row 1: A and B at n.
        (&t.owner, n, false, true, a(), vec![a(), at(&t.owner, n)]),
        // Row 2: C on B.
        (
            &t.owner,
            n + 1,
            true,
            false,
            at(&t.owner, n + 1),
            vec![at(&t.owner, n + 1)],
        ),
        // Row 3: D on A.
        (
            &t.thief,
            n + 1,
            false,
            true,
            at(&t.owner, n + 1),
            vec![at(&t.owner, n + 1), at(&t.thief, n + 1)],
        ),
        // Row 4: E on C.
        (
            &t.owner,
            n + 2,
            true,
            false,
            at(&t.owner, n + 2),
            vec![at(&t.owner, n + 2)],
        ),
        // The thief catches up (F on D): a tie again.
        (
            &t.thief,
            n + 2,
            false,
            true,
            at(&t.owner, n + 2),
            vec![at(&t.owner, n + 2), at(&t.thief, n + 2)],
        ),
        // Row 5: the thief out-extends (G on F): Active on its branch,
        // which only recovery can undo.
        (
            &t.thief,
            n + 3,
            true,
            false,
            at(&t.thief, n + 3),
            vec![at(&t.thief, n + 3)],
        ),
    ];
    for (row, (p, i, admitted, error, tip, heads)) in rows.into_iter().enumerate() {
        let status = push(&app, p, i, &t.id).await;
        assert_eq!(
            status == StatusCode::CREATED,
            admitted,
            "row {row}: {status}"
        );
        let mut heads: Vec<String> = heads
            .iter()
            .map(|h| h.as_str().expect("id").to_owned())
            .collect();
        heads.sort();
        let tip = if error { serde_json::Value::Null } else { tip };
        let expected = (error, tip, heads);
        assert_eq!(
            verdict(&app, &state, &t.id).await,
            expected,
            "row {row}: live"
        );
        drop((app, state));
        let (reopened, rebuilt) = reopen(dir.path()).await;
        (app, state) = (reopened, rebuilt);
        assert_eq!(
            verdict(&app, &state, &t.id).await,
            expected,
            "row {row}: after a restart"
        );
    }
}

/// Backs fix 6 (SPEC 14.12: "interpret transaction based on current `now`
/// and not `rvk`"): `eve` is revoked by a revoke dated NOW+5 carrying
/// `rvk` 1. A commit `eve` signed at NOW+4 is still admitted, and one it
/// signed at NOW+5 is refused, so an `rvk` of 1 refuses no history and the
/// revoke's own `now` decides. Turns red if `rvk` decides, or a commit
/// dated at the revoke's `now` is admitted.
#[tokio::test]
async fn a_revoke_takes_effect_from_its_own_now() {
    let t = theft(true).await;
    let (app, state, _dir) = theft_server(&t).await;
    let pool = load_pool();
    let eve = kp(&pool, "eve_ed25519");
    let mut before = t.a.fork().await.expect("fork");
    create_key(&mut before, &eve, &kp(&pool, "bob"), NOW + 4).await;
    let mut at = before.fork().await.expect("fork");
    create_key(&mut at, &eve, &kp(&pool, "carol"), NOW + 5).await;
    revoke_eve(&state, NOW + 5).await;
    assert_eq!(
        push(&app, &before, t.n + 1, &t.id).await,
        StatusCode::CREATED,
        "dated before the revoke's now"
    );
    let (status, body) = post_json(app.clone(), "/push", wire(&at, t.n + 2, &t.id)).await;
    assert!(
        status.is_client_error(),
        "dated at the revoke's now: {body:?}"
    );
    assert_eq!(
        tip_payload(app, &t.id).await["commit_id"],
        commit_id_at(&before, t.n + 1)
    );
}

/// Backs what lands after a fork is resolved forward: with C (the thief's)
/// and D tied, the Error gate refuses everything but an extension of a
/// tied head (SPEC 15.5: "no new transactions or actions are processed
/// until resolved"), so the owner's action-only bundle is refused (423). A
/// naked revoke of `eve` received at NOW+5, after C's `now`, re-judges no
/// held commit (SPEC 14.12), so the bundle is still refused. The owner's
/// next commit extends D and out-extends C (SPEC 15.8 item 1): Active, and
/// the same bundle lands without moving the tip. Turns red if a revoke
/// resolves the fork, or the bundle stays refused after the resolution.
#[tokio::test]
async fn a_refused_action_lands_after_resolution() {
    let t = theft(false).await;
    let (app, state, _dir) = both_extended(&t, false).await;
    let pool = load_pool();
    let (pay, sig, _) = golden_signs(
        &pool,
        serde_json::json!({"msg": "hi", "now": NOW + 8, "typ": "cyphr.me/comment/create"}),
    );
    let action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    let body = common::push_blobs(&t.id, &[action]);
    let (status, refused) = post_json(app.clone(), "/push", body.clone()).await;
    assert_eq!(status, ERRORED, "refused in Error: {refused:?}");
    revoke_eve(&state, NOW + 5).await;
    assert!(errored(&state, &t.id).await, "a revoke resolves nothing");
    let (status, still) = post_json(app.clone(), "/push", body.clone()).await;
    assert_eq!(status, ERRORED, "still refused: {still:?}");
    let mut e = t.d.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    assert_eq!(push(&app, &e, t.n + 2, &t.id).await, StatusCode::CREATED);
    assert!(!errored(&state, &t.id).await, "E out-extends C: Active");
    let tip = tip_payload(app.clone(), &t.id).await;
    let (status, landed) = post_json(app.clone(), "/push", body).await;
    assert!(status.is_success(), "the bundle lands: {status} {landed:?}");
    assert_eq!(
        tip_payload(app, &t.id).await,
        tip,
        "an action-only bundle moves no tip"
    );
}

// ========================================================================
// ERRSERVE: the read surface says what the engine decided (SPEC 15.5-15.8,
// 13.6): in Error `/tip` reports the fork and its tied heads, never one
// tip; `/patch` serves the common chain, then each branch; a signed
// statement claims only what the server has held since.
// ========================================================================

/// The tied heads of `t`, C and D, as `(commit_id, sequence)`, sorted.
fn tied_heads(t: &Theft) -> Vec<(serde_json::Value, u64)> {
    let at = t.n + 1;
    let mut heads = vec![
        (commit_id_at(&t.c, at), at as u64),
        (commit_id_at(&t.d, at), at as u64),
    ];
    heads.sort_by_key(|h| h.0.to_string());
    heads
}

/// `GET /tip` as the served envelope body, minus the response's own clock.
async fn tip_body(app: &axum::Router, id: &str) -> serde_json::Value {
    let (status, mut body) = get_json(app.clone(), &format!("/tip?pr={}", enc(id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    body["payload"]
        .as_object_mut()
        .expect("payload object")
        .remove("now");
    body
}

async fn patch_body(app: &axum::Router, id: &str) -> serde_json::Value {
    let (status, body) = get_json(app.clone(), &format!("/patch?pr={}", enc(id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    body
}

/// Backs SPEC 15.5 (Error: no single tip) and 15.7.1 (both branches held)
/// on `GET /tip`: with C and D tied, the answer states Error, the fork
/// point (the position and the `pre` the branches share) and each tied
/// head with its position, and carries no single tip (`commit_id`, `pr`,
/// `commit_count`); a resolution restores the Active shape, which has no
/// `state`. Turns red if Error answers with one tip, omits a tied head or
/// the fork point, or the Active shape changes. End to end over `/push`
/// and `/tip`.
#[tokio::test]
async fn tip_in_error_reports_the_fork_and_the_tied_heads() {
    let t = theft(false).await;
    let (app, state, _dir) = both_extended(&t, false).await;
    let shared_tip = state
        .engine
        .assess(&t.id)
        .await
        .expect("assess")
        .fork_point
        .expect("Error has a fork point");
    let body = tip_body(&app, &t.id).await;
    let payload = &body["payload"];
    assert_eq!(payload["state"], "error", "{body:?}");
    for single in ["commit_id", "pr", "sr", "ar", "cr", "commit_count"] {
        assert!(
            payload.get(single).is_none(),
            "Error names no single tip, found `{single}`: {body:?}"
        );
    }
    assert_eq!(payload["fork_point"]["height"], t.n as u64, "{body:?}");
    assert_eq!(
        payload["fork_point"]["pre"],
        serde_json::json!(shared_tip.pre),
        "{body:?}"
    );
    let got: Vec<_> = payload["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .map(|h| (h["commit_id"].clone(), h["sequence"].as_u64().expect("seq")))
        .collect();
    assert_eq!(got, tied_heads(&t), "{body:?}");
}

/// Backs the Active shape staying as it was: a resolved fork answers `/tip`
/// with a single tip and no `state`. Turns red if the Active answer gains
/// the Error vocabulary or loses a field. End to end.
#[tokio::test]
async fn tip_after_resolution_keeps_the_active_shape() {
    let t = theft(true).await;
    let (app, _state, _dir) = theft_server(&t).await;
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.d, t.n + 1, &t.id).await, StatusCode::CREATED);
    let body = tip_body(&app, &t.id).await;
    let payload = body["payload"].as_object().expect("payload");
    assert!(!payload.contains_key("state"), "{body:?}");
    assert!(!payload.contains_key("heads"), "{body:?}");
    for field in [
        "principal_id",
        "pr",
        "sr",
        "ar",
        "cr",
        "commit_id",
        "commit_count",
        "last_updated",
    ] {
        assert!(payload.contains_key(field), "missing {field}: {body:?}");
    }
}

/// Backs the patch rule for Error: `/patch` serves the chain up to the
/// fork point (positions below the fork), then each tied branch from the
/// fork to its head, as `fork_point` and `branches`; every branch commit is
/// a bundle a client replays from the common chain. Turns red if a branch
/// is dropped, a branch repeats the common chain, or the common chain
/// reaches into either branch. End to end.
#[tokio::test]
async fn patch_in_error_serves_the_common_chain_then_each_branch() {
    let t = theft(false).await;
    let (app, _state, _dir) = both_extended(&t, false).await;
    let body = patch_body(&app, &t.id).await;
    let payload = &body["payload"];
    let seqs: Vec<u64> = payload["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["sequence"].as_u64().expect("sequence"))
        .collect();
    assert_eq!(
        seqs,
        (0..t.n as u64).collect::<Vec<_>>(),
        "the common chain ends below the fork: {body:?}"
    );
    assert_eq!(payload["fork_point"]["height"], t.n as u64, "{body:?}");
    let branches = payload["branches"].as_array().expect("branches");
    let mut served: Vec<(serde_json::Value, Vec<u64>)> = branches
        .iter()
        .map(|b| {
            (
                b["head"].clone(),
                b["entries"]
                    .as_array()
                    .expect("branch entries")
                    .iter()
                    .map(|e| e["sequence"].as_u64().expect("sequence"))
                    .collect(),
            )
        })
        .collect();
    served.sort_by_key(|b| b.0.to_string());
    let want: Vec<_> = tied_heads(&t)
        .into_iter()
        .map(|(id, _)| (id, vec![t.n as u64, t.n as u64 + 1]))
        .collect();
    assert_eq!(served, want, "{body:?}");
    assert_eq!(
        branches.iter().filter(|b| b["canonical"] == true).count(),
        1,
        "exactly one branch is the indexed chain: {body:?}"
    );
    // Each branch's last entry is its head, with the bundle served whole.
    for b in branches {
        let last = b["entries"]
            .as_array()
            .and_then(|e| e.last())
            .expect("entry");
        assert_eq!(last["commit_id"], b["head"], "{body:?}");
        assert!(last["txs"].is_array(), "a bundle, not a bare id: {body:?}");
    }
    // The Active shape has neither member.
    let (app2, _s2, _d2) = theft_server(&t).await;
    let active = patch_body(&app2, &t.id).await;
    assert!(active["payload"].get("branches").is_none(), "{active:?}");
    assert!(active["payload"].get("fork_point").is_none(), "{active:?}");
}

/// Backs I1 for the new answers: a restarted server rebuilt from the
/// blobs gives the same `/tip` and `/patch` bytes in Error as the live
/// one. Turns red if either answer depends on state a rebuild loses.
/// End to end.
#[tokio::test]
async fn error_reads_are_identical_after_a_rebuild() {
    let t = theft(true).await;
    let (app, state, dir) = both_extended(&t, true).await;
    let (tip, patch) = (tip_body(&app, &t.id).await, patch_body(&app, &t.id).await);
    assert_eq!(tip["payload"]["state"], "error", "{tip:?}");
    drop((app, state));
    let (app, _state) = reopen(dir.path()).await;
    assert_eq!(tip_body(&app, &t.id).await, tip, "/tip");
    assert_eq!(patch_body(&app, &t.id).await, patch, "/patch");
}

/// Backs SPEC 13.6 (a witness records what it has seen, since when): an
/// attestor in Error signs a `held` statement that names the fork point
/// and each tied head with `held_since`, and no canonical claim (`roots`,
/// `commit_id`, `commit_count`); `held_since` is when this server first
/// stored the head and survives a rebuild. Turns red if the statement is
/// a tip report, claims a canonical tip or roots, or `held_since` differs
/// after a rebuild. End to end through a keyed, bootstrapped server.
#[tokio::test]
async fn signed_statement_in_error_claims_only_held_since() {
    let t = theft(false).await;
    let (state, identity, dir) = common::attestor_server().await;
    let app = build_router(state);
    for i in 0..t.n {
        assert_eq!(push(&app, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    assert_eq!(push(&app, &t.a, t.n, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.d, t.n + 1, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.c, t.n + 1, &t.id).await, StatusCode::CONFLICT);

    let (status, body) = get_json(app.clone(), &format!("/tip?pr={}", enc(&t.id))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["statement"]["kind"], "signed", "{body:?}");
    let pay = &body["statement"]["coz"]["pay"];
    assert_eq!(pay["typ"], "cyphr-server/receipt/held", "{body:?}");
    let sig = Base64UrlUnpadded::decode_vec(body["statement"]["coz"]["sig"].as_str().expect("sig"))
        .expect("sig b64");
    assert_eq!(
        identity.verify(&serde_json::to_vec(pay).expect("pay"), &sig),
        Some(true),
        "signed by the server key"
    );
    for canonical in ["roots", "commit_id", "commit_count", "sequence"] {
        assert!(
            pay.get(canonical).is_none(),
            "`{canonical}` is canonical: {body:?}"
        );
    }
    assert_eq!(pay["fork_point"], body["payload"]["fork_point"], "{body:?}");
    let heads = pay["heads"].as_array().expect("heads");
    assert_eq!(heads.len(), 2, "{body:?}");
    for (signed, plain) in heads
        .iter()
        .zip(body["payload"]["heads"].as_array().unwrap())
    {
        assert_eq!(signed["commit_id"], plain["commit_id"]);
        assert_eq!(signed["sequence"], plain["sequence"]);
        assert!(signed["held_since"].is_i64(), "{signed:?}");
        assert_eq!(signed["held_since"], plain["held_since"]);
    }
    let since: Vec<_> = heads.iter().map(|h| h["held_since"].clone()).collect();

    drop(app);
    let (app, _state) = reopen(&dir.path().join("data")).await;
    let (_, again) = get_json(app, &format!("/tip?pr={}", enc(&t.id))).await;
    let again_since: Vec<_> = again["payload"]["heads"]
        .as_array()
        .expect("heads")
        .iter()
        .map(|h| h["held_since"].clone())
        .collect();
    assert_eq!(again_since, since, "held_since survives a rebuild");
}

/// Backs SPEC 15.8 (the abandoned branch stays served as proof of error)
/// for a witness: an authority in Error serves a signed `held` /patch, and
/// a witness configured with the authority's identity syncs the common
/// chain and every branch, ends in Error with both tied heads, and a second
/// poll of the still-Error authority is up to date, not a rejection. Turns
/// red if sync refuses the Error patch, skips the other branch, or reads
/// the held statement as a tip report. End to end: two servers over TCP.
#[tokio::test]
async fn witness_syncs_an_authority_in_error_and_holds_both_heads() {
    use cyphr_server::config::{AuthorityIdentity, ServerConfig, ServerMode};
    use cyphr_server::sync::{SyncOutcome, sync_from_authority};

    let t = theft(false).await;
    let (astate, identity, adir) = common::attestor_server().await;
    let app = cyphr_server::build_app_router(astate.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state: astate.clone(),
        identity: Some(identity.clone()),
        dir: adir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind");
    let url = instance.url().expect("url");
    for i in 0..t.n {
        assert_eq!(push(&app, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    assert_eq!(push(&app, &t.a, t.n, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.d, t.n + 1, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.c, t.n + 1, &t.id).await, StatusCode::CONFLICT);
    assert!(errored(&astate, &t.id).await, "the authority is in Error");

    let wdir = tempfile::tempdir().expect("witness dir");
    let witness = std::sync::Arc::new(
        cyphr_server::AppState::new(ServerConfig {
            mode: ServerMode::Witness,
            data_dir: wdir.path().join("data"),
            authority_url: Some(url),
            authority_identity: Some(AuthorityIdentity {
                alg: identity.alg().name().to_string(),
                pub_key: identity.pub_key().to_vec(),
            }),
            ..Default::default()
        })
        .expect("witness"),
    );
    let outcome = sync_from_authority(&witness, &t.id).await;
    assert!(
        matches!(outcome, SyncOutcome::Synced { .. }),
        "witness sync from an Error authority: {outcome:?}"
    );
    assert!(
        errored(&witness, &t.id).await,
        "the fork reached the witness"
    );
    let mut mine = witness.engine.assess(&t.id).await.expect("assess").heads;
    let mut theirs = astate.engine.assess(&t.id).await.expect("assess").heads;
    mine.sort();
    theirs.sort();
    assert_eq!(mine, theirs, "both tied heads are held");
    assert_eq!(mine.len(), 2);

    let again = sync_from_authority(&witness, &t.id).await;
    assert!(
        !matches!(again, SyncOutcome::Failed { .. }),
        "polling a still-Error authority is not a failure: {again:?}"
    );
}

/// Backs a witness that already moved past the fork: it holds a commit E
/// resolving over one tied head (so it is Active, ahead), and polls an
/// authority still in Error with heads C and D. Holding each attested
/// head, not merely having it as a current head, is what sync requires:
/// the poll is not a failure and the witness gains the branch it lacked
/// while staying Active on E. Turns red if sync demands the attested heads
/// be the witness's current heads (EntryCommitmentMismatch), or the seq
/// guard drops the branch the witness lacks. End to end over TCP.
#[tokio::test]
async fn witness_ahead_of_an_error_authority_holds_its_heads() {
    use cyphr_server::config::{AuthorityIdentity, ServerConfig, ServerMode};
    use cyphr_server::sync::{SyncOutcome, sync_from_authority};

    let t = theft(false).await;
    let (astate, identity, adir) = common::attestor_server().await;
    let app = cyphr_server::build_app_router(astate.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state: astate.clone(),
        identity: Some(identity.clone()),
        dir: adir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind");
    let url = instance.url().expect("url");
    for i in 0..t.n {
        assert_eq!(push(&app, &t.shared, i, &t.id).await, StatusCode::CREATED);
    }
    assert_eq!(push(&app, &t.a, t.n, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.b, t.n, &t.id).await, StatusCode::CONFLICT);
    assert_eq!(push(&app, &t.d, t.n + 1, &t.id).await, StatusCode::CREATED);
    assert_eq!(push(&app, &t.c, t.n + 1, &t.id).await, StatusCode::CONFLICT);
    assert!(errored(&astate, &t.id).await, "the authority is in Error");

    // The witness holds the owner's line and a resolving commit E over D.
    let pool = load_pool();
    let mut e = t.d.fork().await.expect("fork");
    create_key(&mut e, &kp(&pool, "golden"), &kp(&pool, "alice"), NOW + 7).await;
    let wdir = tempfile::tempdir().expect("witness dir");
    let wstate = std::sync::Arc::new(
        cyphr_server::AppState::new(ServerConfig {
            mode: ServerMode::Witness,
            data_dir: wdir.path().join("data"),
            authority_url: Some(url),
            authority_identity: Some(AuthorityIdentity {
                alg: identity.alg().name().to_string(),
                pub_key: identity.pub_key().to_vec(),
            }),
            ..Default::default()
        })
        .expect("witness"),
    );
    let hold = |p: &cyphr::Principal, i: usize| {
        let bundle = cyphr_storage::export_commits(p).expect("export")[i]
            .bundle()
            .expect("bundle");
        let (state, id) = (wstate.clone(), t.id.clone());
        async move { state.engine.submit_commit(&id, None, &bundle).await }
    };
    for i in 0..t.n {
        hold(&t.shared, i).await.expect("shared");
    }
    hold(&t.a, t.n).await.expect("A");
    hold(&t.d, t.n + 1).await.expect("D");
    hold(&e, t.n + 2).await.expect("E");
    assert!(!errored(&wstate, &t.id).await, "the witness is Active on E");

    let outcome = sync_from_authority(&wstate, &t.id).await;
    assert!(
        !matches!(outcome, SyncOutcome::Failed { .. }),
        "an Active witness ahead of the fork polls an Error authority: {outcome:?}"
    );
    let c_id = commit_id_at(&t.c, t.n + 1).as_str().expect("id").to_owned();
    assert!(
        wstate
            .engine
            .holds_commit(&t.id, &c_id)
            .await
            .expect("holds"),
        "the witness gained the branch it lacked"
    );
    assert!(!errored(&wstate, &t.id).await, "still Active on E");
}
