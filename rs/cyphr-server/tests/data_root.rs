//! SPEC 4.8.2 "Data Tree Inclusion" through the server push path: a data
//! action is recorded in DT, but DR enters the Principal Tree only by a
//! signed `cyphr/ds/create` whose `id` is the computed DR = MR(DT).
//!
//! Every bundle carries its data actions ahead of its transactions, the
//! order the replay rule records them in (`cyphr::replay`): an action-only
//! bundle forms no commit and is not replayed when the server reloads the
//! principal, so the actions a `ds/create` covers travel with a commit.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr::signer::SoftwareSigner;
use cyphr::state::HashAlg;
use cyphr_server::build_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

/// The genesis `now`; every later coz is a little after it.
const T: i64 = 1_700_000_000;

/// One coz signed by `golden`: its signed pay bytes, signature and digest,
/// plus the key a `key/create` discloses.
struct Signed {
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
    key: Option<cyphr::Key>,
}

impl Signed {
    /// The wire blob `{pay, sig}` the push body carries; a key it
    /// introduces travels in the bundle's `keys`.
    fn wire(&self) -> Vec<u8> {
        let coz = serde_json::json!({
            "pay": serde_json::from_slice::<serde_json::Value>(&self.pay).expect("pay"),
            "sig": Base64UrlUnpadded::encode_string(&self.sig),
        });
        serde_json::to_vec(&coz).expect("coz")
    }
}

/// `golden` signs `fields` plus its own `alg` and `tmb`.
fn golden_signs(pool: &test_fixtures::Pool, mut fields: serde_json::Value) -> Signed {
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
    Signed {
        pay,
        sig,
        czd,
        key: None,
    }
}

fn action(pool: &test_fixtures::Pool, now: i64, msg: &str) -> Signed {
    golden_signs(
        pool,
        serde_json::json!({"msg": msg, "now": now, "typ": "cyphr.me/comment/create"}),
    )
}

fn ds_create(pool: &test_fixtures::Pool, id: &str, now: i64) -> Signed {
    golden_signs(
        pool,
        serde_json::json!({"id": id, "now": now, "typ": "cyphr.me/cyphr/ds/create"}),
    )
}

fn key_create(pool: &test_fixtures::Pool, target: &str, now: i64) -> Signed {
    let t = pool.get(target).expect("target");
    let mut tx = golden_signs(
        pool,
        serde_json::json!({
            "id": t.compute_tmb_b64().expect("tmb"),
            "now": now,
            "typ": "cyphr.me/cyphr/key/create",
        }),
    );
    tx.key = Some(t.key().expect("pool key").with_first_seen(now));
    tx
}

/// DR = MR(DT) over every action `p` holds (SPEC 4.8.1, 4.8.2), computed
/// here from the actions themselves, tagged `alg:digest`.
fn data_tree_id(p: &Principal) -> String {
    let actions: Vec<&cyphr::Action> = p.actions().collect();
    let dr = cyphr::compute_dr(&actions, None, &[HashAlg::Sha256])
        .expect("DR")
        .expect("DT holds an action");
    let bytes = dr.0.get(HashAlg::Sha256).expect("SHA-256 variant");
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(bytes))
}

/// Record `actions` on `p`, apply `txs` as one commit signed by `golden`,
/// and return the bundle: the actions, then the commit's cozies.
async fn bundle(
    p: &mut Principal,
    pool: &test_fixtures::Pool,
    actions: &[Signed],
    txs: impl Fn(&Principal) -> Vec<Signed>,
    now: i64,
) -> WireBundle {
    for a in actions {
        p.verify_and_record_action(&a.pay, &a.sig, a.czd.clone())
            .expect("action records");
    }
    let txs = txs(p);
    let g = pool.get("golden").expect("golden");
    let mut scope = p.begin_commit();
    for tx in &txs {
        scope
            .verify_and_apply(&tx.pay, &tx.sig, tx.czd.clone(), tx.key.clone())
            .expect("transaction applies");
    }
    let signer = g.software_signer().expect("signer");
    finalize(scope, &signer, now).await;

    let commit = WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle");
    WireBundle {
        actions: actions.iter().map(Signed::wire).collect(),
        ..commit
    }
}

async fn finalize(scope: cyphr::CommitScope<'_>, signer: &SoftwareSigner, now: i64) {
    scope
        .finalize_with_software(signer, now, "cyphr.me")
        .await
        .expect("commit finalizes");
}

fn body(principal_id: &str, bundle: &WireBundle) -> String {
    common::push_body(principal_id, bundle)
}

/// Backs SPEC 4.8.2: "Like all nodes, DT/DR is first set to empty, causing
/// AR to be implicitly promoted to PR. To explicitly include DR into PR, a
/// DR transaction is signed, which updates the value of DR in the PR tree"
/// (`cyphr.me/cyphr/ds/create`, `id` = computed DR = MR(DT)).
///
/// Scenario, end to end over HTTP, one implicit principal (`golden`):
/// 1. a commit carrying a data action and a `key/create` is accepted, and the tip's SR is still the
///    AR: the action is in DT, but DR is not in PR;
/// 2. a `ds/create` naming a DR no set of the pending bundles reaches (it covers an action the
///    server never received) is refused with the typed `StateMismatch` (409, as for any `id` naming
///    a state the principal is not in), and the tip does not move;
/// 3. a `ds/create` naming MR(DT) over both actions is accepted: the tip's PR is the one the client
///    computed, and its SR now differs from AR, so DR is in PR.
///
/// Turns red if a data action moves PR on its own (step 1), if `ds/create`
/// is unknown or its `id` is not checked against DT (steps 2, 3), or if the
/// server and the core disagree on the included DR (step 3). End to end: yes.
#[tokio::test]
async fn data_root_enters_pr_only_by_a_signed_ds_create() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(g.key().expect("golden key"))
        .await
        .expect("implicit genesis");
    let id = p.pr_tagged().expect("PG");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut p, g, &[], T)
        .await
        .expect("genesis");

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let tip_uri = format!("/tip?pr={id}");

    let (s, b) = post_json(app.clone(), "/push", body(&id, &genesis)).await;
    assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");

    // 1. A data action alone does not put DR into PR.
    let first = bundle(
        &mut p,
        &pool,
        &[action(&pool, T + 1, "one")],
        |_| vec![key_create(&pool, "key_a", T + 2)],
        T + 2,
    )
    .await;
    let (s, b) = post_json(app.clone(), "/push", body(&id, &first)).await;
    assert_eq!(s, StatusCode::CREATED, "action + key/create push: {b:?}");
    let (_, tip) = get_json(app.clone(), &tip_uri).await;
    let tip = envelope_payload(&tip).clone();
    assert_eq!(
        tip["sr"], tip["ar"],
        "a data action without ds/create must leave DR out of PR (SR is AR): {tip:?}"
    );

    // 2. A ds/create whose id no pending bundles reach is refused. A DR
    // over a strict subset of them would be a legitimate choice (the
    // `ds/create` includes the bundles it names, SPEC 4.8.2), so this one
    // covers an action the server never received.
    let mut elsewhere = p.fork().await.expect("fork");
    let unseen = action(&pool, T + 3, "never pushed");
    elsewhere
        .verify_and_record_action(&unseen.pay, &unseen.sig, unseen.czd.clone())
        .expect("records");
    let stale = data_tree_id(&elsewhere);
    let refused = WireBundle {
        actions: vec![action(&pool, T + 3, "two").wire()],
        txs: vec![vec![ds_create(&pool, &stale, T + 4).wire()]],
        ..WireBundle::default()
    };
    let (s, b) = post_json(app.clone(), "/push", body(&id, &refused)).await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "a ds/create naming a stale DR must be a typed refusal: {b:?}"
    );
    let msg = envelope_payload(&b)["error"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    assert!(
        msg.contains("state mismatch"),
        "the refusal must be the core's StateMismatch, got {msg:?}"
    );
    let (_, after) = get_json(app.clone(), &tip_uri).await;
    assert_eq!(
        envelope_payload(&after)["pr"],
        tip["pr"],
        "a refused ds/create must not move the tip"
    );

    // 3. A ds/create naming MR(DT) includes DR into PR.
    let included = bundle(
        &mut p,
        &pool,
        &[action(&pool, T + 3, "two")],
        |p| vec![ds_create(&pool, &data_tree_id(p), T + 4)],
        T + 4,
    )
    .await;
    let (s, b) = post_json(app.clone(), "/push", body(&id, &included)).await;
    assert_eq!(s, StatusCode::CREATED, "ds/create push: {b:?}");
    let (_, tip) = get_json(app.clone(), &tip_uri).await;
    let tip = envelope_payload(&tip);
    assert_eq!(
        tip["pr"].as_str(),
        Some(p.pr_tagged().expect("PR").as_str()),
        "server and client agree on the PR that includes DR"
    );
    assert_ne!(
        tip["sr"], tip["ar"],
        "after ds/create, DR is in PR, so SR is no longer AR alone: {tip:?}"
    );
}

/// Backs SPEC 4.8.1 and 4.8.2 for actions pushed on their own: an action is
/// recorded in DT whether or not a commit carries it, so a later
/// `ds/create` naming MR(DT) over it is accepted, and one naming a
/// different DR is refused with `StateMismatch`.
///
/// Scenario, end to end over HTTP: after its genesis, `golden` pushes a
/// data action as an action-only bundle, then a commit whose `ds/create`
/// names a DR over no action of DT (refused, 409) and one whose
/// `ds/create` names MR(DT) over that action (accepted, the server's PR
/// equals the client's). Turns red while the engine does not replay
/// action-only bundles: the server's DT is then empty and the correct
/// `ds/create` is refused as a state mismatch. End to end: yes.
#[tokio::test]
async fn ds_create_includes_actions_pushed_alone() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(g.key().expect("golden key"))
        .await
        .expect("implicit genesis");
    let id = p.pr_tagged().expect("PG");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut p, g, &[], T)
        .await
        .expect("genesis");

    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let tip_uri = format!("/tip?pr={id}");
    let (s, b) = post_json(app.clone(), "/push", body(&id, &genesis)).await;
    assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");

    // The action travels alone; the client records it too.
    let a1 = action(&pool, T + 1, "alone");
    let (s, b) = post_json(
        app.clone(),
        "/push",
        body(&id, &WireBundle::actions(vec![a1.wire()])),
    )
    .await;
    assert!(s.is_success(), "action-only push: {s} {b:?}");
    p.verify_and_record_action(&a1.pay, &a1.sig, a1.czd.clone())
        .expect("action records");

    // A ds/create naming a DR that is not MR(DT) is refused.
    let other = action(&pool, T + 1, "never pushed");
    let mut q = Principal::implicit(g.key().expect("golden key"))
        .await
        .expect("implicit genesis");
    q.verify_and_record_action(&other.pay, &other.sig, other.czd.clone())
        .expect("action records");
    let wrong = WireBundle {
        txs: vec![vec![ds_create(&pool, &data_tree_id(&q), T + 2).wire()]],
        ..WireBundle::default()
    };
    let (s, b) = post_json(app.clone(), "/push", body(&id, &wrong)).await;
    assert_eq!(s, StatusCode::CONFLICT, "a foreign DR is refused: {b:?}");
    let (_, before) = get_json(app.clone(), &tip_uri).await;

    // A ds/create naming MR(DT) over the action pushed alone is accepted.
    let included = bundle(
        &mut p,
        &pool,
        &[],
        |p| vec![ds_create(&pool, &data_tree_id(p), T + 2)],
        T + 2,
    )
    .await;
    let (s, b) = post_json(app.clone(), "/push", body(&id, &included)).await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "ds/create over an action pushed alone: {b:?}"
    );
    let (_, tip) = get_json(app.clone(), &tip_uri).await;
    let tip = envelope_payload(&tip);
    assert_ne!(tip["pr"], envelope_payload(&before)["pr"]);
    assert_eq!(
        tip["pr"].as_str(),
        Some(p.pr_tagged().expect("PR").as_str()),
        "server and client agree on the PR that includes DR"
    );
}
