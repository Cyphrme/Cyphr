//! Gossip carries a fork resolution across a partition (SPEC 15.8).
//!
//! Two peers each hold one side of a principal fork as canonical and the
//! other as a retained branch, so both are in Error. The phone resolves on
//! P1 with a commit extending its own branch. One gossip round on P2
//! against P1 must take that resolution: P2 pulls the head it lacks, with
//! P1's chain from the common ancestor, and submits it through the same
//! admission path a push takes.

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_500_000;

/// `golden` signs `fields` plus its own `alg` and `tmb`: (pay, sig, czd).
fn golden_signs(fields: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut fields = fields;
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

/// One commit on `p` of `typ` naming `id` (and `key`, for a key/create),
/// signed and finalized by `golden` at `now`; its bundle.
async fn commit(
    p: &mut cyphr::Principal,
    typ: &str,
    id: &str,
    key: Option<cyphr::Key>,
    now: i64,
) -> WireBundle {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let (pay, sig, czd) = golden_signs(serde_json::json!({"id": id, "now": now, "typ": typ}));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, key)
        .expect("applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle")
}

async fn key_commit(p: &mut cyphr::Principal, name: &str, now: i64) -> WireBundle {
    let key = load_pool().get(name).expect("pool key").key().expect("key");
    let tmb = key.tmb().to_b64();
    commit(p, "cyphr.me/cyphr/key/create", &tmb, Some(key), now).await
}

/// A data action then the `ds/create` including it, on `p`: the action's
/// wire coz and the commit's bundle (SPEC 4.8.2).
async fn data_commit(p: &mut cyphr::Principal, msg: &str, now: i64) -> (Vec<u8>, WireBundle) {
    let (pay, sig, czd) =
        golden_signs(serde_json::json!({"msg": msg, "now": now, "typ": "cyphr.me/comment/create"}));
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("records");
    let action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("coz");
    let dr = p
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    let bundle = commit(p, "cyphr.me/cyphr/ds/create", &dr, None, now + 1).await;
    (action, bundle)
}

async fn push(app: &axum::Router, id: &str, bundle: &WireBundle) -> StatusCode {
    post_json(app.clone(), "/push", common::push_body(id, bundle))
        .await
        .0
}

async fn tip_pr(app: &axum::Router, id: &str) -> String {
    let (status, body) =
        get_json(app.clone(), &format!("/tip?pr={}", id.replace(':', "%3A"))).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    envelope_payload(&body)["pr"]
        .as_str()
        .expect("pr")
        .to_owned()
}

/// Serve `state` on an ephemeral local port; its base URL.
async fn serve(state: &Arc<AppState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

/// Backs the gossip follow-up: P1 holds the phone's data branch B
/// canonical and the laptop's A retained; P2 the reverse. The phone
/// resolves on P1 with C extending B. One round of P2's gossip against P1
/// moves P2's tip to C, B's branch canonical, with A kept as a branch,
/// and P2 leaves Error as P1 did.
///
/// Turns red if: P2 does not take the resolution in one round (its tip
/// stays A and it stays in Error), or takes it as anything but a verified
/// commit. End to end over two servers on real sockets and one gossip
/// round: yes.
#[tokio::test(flavor = "multi_thread")]
async fn one_round_takes_a_peers_resolution() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut shared, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");

    let mut laptop = shared.fork().await.expect("fork");
    let a = key_commit(&mut laptop, "key_a", T + 1).await;
    let mut phone = shared.fork().await.expect("fork");
    let (action, mut b) = data_commit(&mut phone, "phone", T + 2).await;
    let mut resolved = phone.fork().await.expect("fork");
    let c = key_commit(&mut resolved, "carol", T + 4).await;

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
    }
    // P1: B canonical (its action pushed alone first), A retained.
    let (s, body) = post_json(
        app1.clone(),
        "/push",
        common::push_blobs(&id, std::slice::from_ref(&action)),
    )
    .await;
    assert!(s.is_success(), "B's action: {s} {body:?}");
    assert_eq!(push(&app1, &id, &b).await, StatusCode::CREATED, "B on P1");
    // A rival is refused as the tip (409, or 422 when its `now` is older
    // than the tip's) and kept as a branch: the Error below shows it.
    assert!(push(&app1, &id, &a).await.is_client_error(), "A kept");
    // P2: A canonical, B retained with its action inline.
    assert_eq!(push(&app2, &id, &a).await, StatusCode::CREATED, "A on P2");
    b.actions = vec![action];
    assert!(push(&app2, &id, &b).await.is_client_error(), "B kept");
    for p in [&p1, &p2] {
        assert!(p.engine.is_errored(&id).await.expect("verdict"), "a fork");
    }

    assert_eq!(push(&app1, &id, &c).await, StatusCode::CREATED, "C on P1");
    let want = resolved.pr_tagged().expect("pr");
    assert_eq!(tip_pr(&app1, &id).await, want);
    assert!(!p1.engine.is_errored(&id).await.expect("verdict"));

    let url = serve(&p1).await;
    let connector =
        HttpConnector::with_client(p2.http_client.clone(), &url, true).expect("connector");
    cyphr_server::gossip::round(&p2, &[(url, connector)]).await;

    assert_eq!(tip_pr(&app2, &id).await, want, "P2 took C in one round");
    assert!(
        !p2.engine.is_errored(&id).await.expect("verdict"),
        "P2 left Error"
    );
    let branches = p2.engine.list_branches(&id).await.expect("branches");
    assert_eq!(branches.len(), 2, "A is kept: {branches:?}");
}

/// [`dead_key_fixture_at`] dated from `T`, long before any receipt clock:
/// a revoke received now leaves its commits as history.
async fn dead_key_fixture() -> (
    WireBundle,
    String,
    cyphr::Principal,
    WireBundle,
    WireBundle,
    WireBundle,
    cyphr::Principal,
) {
    dead_key_fixture_at(T).await
}

/// [`dead_key_fixture_at`] dated a minute ahead of the wall clock (inside
/// the push window, SPEC 15.9): a revoke this node receives now, its
/// cutoff, kills `eve`'s commits.
async fn dead_key_fixture_ahead() -> (
    WireBundle,
    String,
    cyphr::Principal,
    WireBundle,
    WireBundle,
    WireBundle,
    cyphr::Principal,
) {
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    dead_key_fixture_at(clock + 60).await
}

/// A shared genesis (`golden`, `eve`) at `t0`, the owner's X at 1
/// (`golden`), and `eve`'s line R at 1, B at 2: `(genesis, id, owner after
/// X, X, R, B, thief after B)`.
async fn dead_key_fixture_at(
    t0: i64,
) -> (
    WireBundle,
    String,
    cyphr::Principal,
    WireBundle,
    WireBundle,
    WireBundle,
    cyphr::Principal,
) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let eve = pool.get("eve_ed25519").expect("eve");
    let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis =
        test_fixtures::bundle::genesis_bundle(&mut shared, g, &[eve.key().expect("eve")], t0)
            .await
            .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let mut owner = shared.fork().await.expect("fork");
    let x = common::key_commit_by(&mut owner, "golden", "key_a", t0 + 1).await;
    let mut thief = shared.fork().await.expect("fork");
    let r = common::key_commit_by(&mut thief, "eve_ed25519", "key_b", t0 + 1).await;
    let b = common::key_commit_by(&mut thief, "eve_ed25519", "carol", t0 + 2).await;
    (genesis, id, owner, x, r, b, thief)
}

async fn one_round(from: &Arc<AppState>, to: &Arc<AppState>) {
    let url = serve(to).await;
    let connector =
        HttpConnector::with_client(from.http_client.clone(), &url, true).expect("connector");
    cyphr_server::gossip::round(from, &[(url, connector)]).await;
}

/// Backs key death at admission (SPEC 6.4) on the gossip path: P1 holds X
/// canonical, P2 serves `eve`'s line R, B over X's position, dated a
/// minute ahead, and `eve` is naked-revoked now, so each receipt time
/// precedes both (#203: the cutoff is the receipt). One round of P1's gossip must
/// not promote R's line: X stays P1's tip and P1 stays Active. Pinned
/// with the revoke posted to P1 beforehand, and with it posted only to P2,
/// so P1 learns it in the very round that serves the line: verified
/// revokes are recorded before any bundle is submitted. Turns red if
/// either round moves P1's tip.
#[tokio::test(flavor = "multi_thread")]
async fn gossip_never_promotes_a_dead_keys_rival() {
    for on_p1 in [true, false] {
        let (genesis, id, owner, x, r, b, _) = dead_key_fixture_ahead().await;
        let (p1, _d1) = keyless_server();
        let (p2, _d2) = keyless_server();
        let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
        for app in [&app1, &app2] {
            assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
        }
        assert_eq!(push(&app1, &id, &x).await, StatusCode::CREATED, "X on P1");
        assert_eq!(push(&app2, &id, &r).await, StatusCode::CREATED, "R on P2");
        assert_eq!(push(&app2, &id, &b).await, StatusCode::CREATED, "B on P2");
        let to = if on_p1 { &app1 } else { &app2 };
        let (status, body) =
            post_json(to.clone(), "/revoke", common::eve_revoke(T + 1).to_string()).await;
        assert_eq!(status, StatusCode::OK, "revoke: {body:?}");
        let want = owner.pr_tagged().expect("pr");

        one_round(&p1, &p2).await;

        assert_eq!(
            tip_pr(&app1, &id).await,
            want,
            "revoke on P1={on_p1}: P1 promoted a dead key's rival"
        );
        assert!(
            !p1.engine.is_errored(&id).await.expect("verdict"),
            "revoke on P1={on_p1}: a dead key's rival is evidence only"
        );
    }
}

/// Backs gossip feeding the engine's revocations (SPEC 6.4, 15.7.1): P1
/// holds X canonical and `eve`'s rival R at X's position, a plain fork in
/// Error, R dated a minute ahead. P2 holds X and `eve`'s naked revoke.
/// One round of P1's gossip records the revoke, received now and so
/// before R's `now`, where the engine judges forks, so R leaves the fork
/// and P1 is Active, as P2 would be. Turns red if a revoke learned by
/// gossip leaves P1 in Error.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_learned_by_gossip_settles_the_fork() {
    let (genesis, id, owner, x, r, ..) = dead_key_fixture_ahead().await;
    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
        assert_eq!(push(app, &id, &x).await, StatusCode::CREATED, "X");
    }
    assert!(push(&app1, &id, &r).await.is_client_error(), "R is a rival");
    assert!(
        p1.engine.is_errored(&id).await.expect("verdict"),
        "a plain fork"
    );
    let (status, body) = post_json(
        app2.clone(),
        "/revoke",
        common::eve_revoke(T + 1).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");

    one_round(&p1, &p2).await;

    assert!(
        !p1.engine.is_errored(&id).await.expect("verdict"),
        "a revoke learned by gossip takes R out of the fork"
    );
    assert_eq!(tip_pr(&app1, &id).await, owner.pr_tagged().expect("pr"));
}

/// Backs the rule that key death is not retroactive (SPEC 6.4; nrd: "You
/// cant make all sigs retroactively invalid"): P1 holds only the genesis
/// and already knows `eve` is revoked as of T+5; P2 serves the chain, in
/// which `eve` signed R and B before that, and `golden` C after them. One
/// round of P1's gossip catches P1 up to P2's tip. Turns red if a node that
/// knows a revoke refuses the key's commits dated before it.
#[tokio::test(flavor = "multi_thread")]
async fn a_lagging_peer_catches_up_through_pre_revoke_commits() {
    let (genesis, id, _, _, r, b, mut thief) = dead_key_fixture().await;
    let c = common::key_commit_by(&mut thief, "golden", "key_a", T + 3).await;
    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
    }
    assert_eq!(push(&app2, &id, &r).await, StatusCode::CREATED, "R on P2");
    assert_eq!(push(&app2, &id, &b).await, StatusCode::CREATED, "B on P2");
    assert_eq!(push(&app2, &id, &c).await, StatusCode::CREATED, "C on P2");
    let (status, body) = post_json(
        app1.clone(),
        "/revoke",
        common::eve_revoke(T + 5).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");

    one_round(&p1, &p2).await;

    assert_eq!(
        tip_pr(&app1, &id).await,
        tip_pr(&app2, &id).await,
        "P1 caught up through eve's commits made before its death"
    );
}

/// Backs honest rotation under a later revoke (SPEC 6.4, not
/// retroactive): `eve` adds `alice`, and `alice` commits; later `eve` is
/// revoked. P1 learns the revoke first, then syncs from P2 and catches up
/// through the whole history, the commit `eve` signed and the one
/// `alice` signed. Turns red if a revoke learned first blocks honest
/// history signed before it.
#[tokio::test(flavor = "multi_thread")]
async fn honest_rotation_syncs_after_a_later_revoke() {
    let (genesis, id, ..) = dead_key_fixture().await;
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let eve = pool.get("eve_ed25519").expect("eve");
    let mut p = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let again = test_fixtures::bundle::genesis_bundle(&mut p, g, &[eve.key().expect("eve")], T)
        .await
        .expect("genesis");
    assert_eq!(again, genesis, "one genesis");
    let added = common::key_commit_by(&mut p, "eve_ed25519", "alice", T + 1).await;
    let rotated = common::key_commit_by(&mut p, "alice", "carol", T + 2).await;

    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
    }
    assert_eq!(
        push(&app2, &id, &added).await,
        StatusCode::CREATED,
        "eve adds alice"
    );
    assert_eq!(
        push(&app2, &id, &rotated).await,
        StatusCode::CREATED,
        "alice commits"
    );
    let (status, body) = post_json(
        app1.clone(),
        "/revoke",
        common::eve_revoke(T + 5).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body:?}");

    one_round(&p1, &p2).await;

    assert_eq!(
        tip_pr(&app1, &id).await,
        p.pr_tagged().expect("pr"),
        "P1 synced the honest rotation signed before the revoke"
    );
}

/// Backs "Coz valid revokes are always accepted" (spec author, #203) for
/// a relayed revoke: P2 serves `eve`'s naked revoke dated an hour ahead.
/// It is Coz-valid, so one round of P1's gossip accepts and keeps it, and
/// P1 serves it at `/revoked`. A far-future `now` is harmless: the key's
/// cutoff is P1's own receipt time. Turns red if a Coz-valid relayed
/// revoke is refused or not served on.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_future_revoke_is_accepted_and_kept() {
    let (genesis, id, ..) = dead_key_fixture().await;
    let (p1, _d1) = keyless_server();
    let (p2, _d2) = keyless_server();
    let (app1, app2) = (build_router(p1.clone()), build_router(p2.clone()));
    for app in [&app1, &app2] {
        assert_eq!(push(app, &id, &genesis).await, StatusCode::CREATED);
    }
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let future = common::eve_revoke(clock + 3600);
    let eve = load_pool()
        .get("eve_ed25519")
        .expect("eve")
        .compute_tmb()
        .expect("tmb");
    p2.observations
        .record_seen(&eve, future.clone())
        .await
        .expect("P2 serves it");

    one_round(&p1, &p2).await;

    let (status, body) = get_json(app1.clone(), &format!("/revoked?tmbs={}", eve.to_b64())).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        envelope_payload(&body)["revoked"],
        serde_json::json!([future]),
        "P1 serves the relayed revoke on"
    );
}
