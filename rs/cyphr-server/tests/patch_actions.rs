//! SPEC 4.8.1, 4.8.2 for a client that was not there: `GET /patch` carries
//! the data actions a `ds/create` includes, so a fresh client replays the
//! served chain to the PR the server published.
//!
//! Without them the client's DT is empty and replaying the `ds/create`
//! fails as a state mismatch (the wire carried no actions, #202). The
//! carriage is DS2's export lines: an action-only line before the commit
//! that follows it, here the patch's `actions` member with `after` = the
//! number of commits the principal had when the bundle was accepted.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr_server::build_router;
use cyphr_storage::{CommitEntry, Genesis, load_principal_from_commits};

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_000_000;

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

fn wire(pay: &[u8], sig: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(sig),
    }))
    .expect("coz")
}

fn push_body(id: &str, blobs: &[Vec<u8>]) -> String {
    common::push_blobs(id, blobs)
}

fn blobs_of(entry: &serde_json::Value) -> Vec<Vec<u8>> {
    entry["blobs"]
        .as_array()
        .expect("blobs")
        .iter()
        .map(|b| Base64UrlUnpadded::decode_vec(b.as_str().expect("b64")).expect("decode"))
        .collect()
}

/// The bundle line of a served action-only bundle: its actions.
fn action_line(blobs: &[Vec<u8>]) -> CommitEntry {
    CommitEntry::from_bundle(&WireBundle::actions(blobs.to_vec())).expect("action line")
}

/// The bundle line of a served commit entry (SPEC 4.6.2 `txs`, `keys`).
fn entry_line(entry: &serde_json::Value) -> CommitEntry {
    let bundle: WireBundle = serde_json::from_value(entry.clone()).expect("entry bundle");
    CommitEntry::from_bundle(&bundle).expect("entry line")
}

/// Backs SPEC 4.8.2 across the wire: a data action pushed alone, then a
/// `ds/create` commit including it, are both served by `GET /patch`, and a
/// fresh client that replays the served chain (actions ahead of the commit
/// that follows them) reaches the PR the server's tip names.
///
/// Turns red if `/patch` omits the actions: the replay then refuses the
/// `ds/create` (empty DT) or reaches a different PR. End to end: yes.
#[tokio::test]
async fn fresh_client_replays_a_chain_holding_a_ds_create() {
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
    let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &genesis)).await;
    assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");

    // The action travels alone; the client records it too.
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"msg": "one", "now": T + 1, "typ": "cyphr.me/comment/create"}),
    );
    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &[wire(&pay, &sig)])).await;
    assert!(s.is_success(), "action-only push: {s} {b:?}");
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("action records");

    // The ds/create commit including it.
    let actions: Vec<&cyphr::Action> = p.actions().collect();
    let dr = cyphr::compute_dr(&actions, None, &[cyphr::state::HashAlg::Sha256])
        .expect("DR")
        .expect("DT holds an action");
    let dr = format!(
        "SHA-256:{}",
        Base64UrlUnpadded::encode_string(dr.0.get(cyphr::state::HashAlg::Sha256).expect("SHA-256"))
    );
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"id": dr, "now": T + 2, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), T + 2, "cyphr.me")
        .await
        .expect("commit finalizes");
    let bundle = WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle");
    let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &bundle)).await;
    assert_eq!(s, StatusCode::CREATED, "ds/create push: {b:?}");

    // A fresh client reads the patch and replays it.
    let (_, tip) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    let published = envelope_payload(&tip)["pr"]
        .as_str()
        .expect("pr")
        .to_owned();
    let (s, patch) = get_json(app.clone(), &format!("/patch?pr={id}")).await;
    assert_eq!(s, StatusCode::OK, "{patch:?}");
    let payload = envelope_payload(&patch);
    let mut lines = Vec::new();
    let held: Vec<&serde_json::Value> = payload["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .collect();
    for entry in payload["entries"].as_array().expect("entries") {
        let seq = entry["sequence"].as_u64().expect("sequence");
        for a in held.iter().filter(|a| a["after"].as_u64() == Some(seq)) {
            lines.push(action_line(&blobs_of(a)));
        }
        lines.push(entry_line(entry));
    }
    let key = g.key().expect("golden key");
    let fresh = load_principal_from_commits(Genesis::Implicit(key), &lines)
        .await
        .expect("a fresh client replays the served chain");
    assert_eq!(
        fresh.pr_tagged().expect("PR"),
        published,
        "the replayed PR is the one the server published"
    );
}

/// A principal with its genesis commit, `golden` over the keyless server,
/// and its id; the genesis is pushed when `push_genesis` is set.
async fn principal_on_server(
    push_genesis: bool,
) -> (axum::Router, Principal, String, test_fixtures::Pool) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut p = Principal::implicit(g.key().expect("golden key"))
        .await
        .expect("implicit genesis");
    let id = p.pr_tagged().expect("PG");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut p, g, &[], T)
        .await
        .expect("genesis");
    let (state, dir) = keyless_server();
    // The data directory must outlive the router for the whole test.
    std::mem::forget(dir);
    let app = build_router(state);
    if push_genesis {
        let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &genesis)).await;
        assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");
    }
    (app, p, id, pool)
}

/// Claim (architect DS2 note, be0663f 2.3.2: principal genesis is required
/// for commits): an action-only push for a principal that has no genesis
/// commit is refused as `GenesisIncomplete` (422), not recorded under a key
/// no chain will ever include. Nothing is stored: the principal stays
/// unknown.
///
/// Turns red if: the push is accepted (orphaned action), or refused as
/// anything but the protocol's `GenesisIncomplete`. End to end: yes.
#[tokio::test]
async fn action_only_push_before_genesis_is_refused() {
    let (app, _p, id, pool) = principal_on_server(false).await;
    let (pay, sig, _) = golden_signs(
        &pool,
        serde_json::json!({"msg": "early", "now": T + 1, "typ": "cyphr.me/comment/create"}),
    );
    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &[wire(&pay, &sig)])).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b:?}");
    let message = envelope_payload(&b)["error"].to_string().to_lowercase();
    assert!(
        message.contains("genesis"),
        "the refusal names the missing genesis: {b:?}"
    );
    let (s, _) = get_json(app, &format!("/patch?pr={id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "nothing was recorded");
}

/// Claim (architect ruling: action-only push idempotency): an action-only
/// bundle whose every action the server already records is accepted and
/// stores nothing, so a client that re-sends a trailing action after the
/// chain has moved on (it cannot tell which the peer holds) adds no second
/// action manifest. Scenario: an action is pushed alone, a `ds/create`
/// commit includes it, and the action is pushed alone again; `/patch`
/// still lists exactly one action bundle holding it.
///
/// Turns red if: the repeat records a second manifest at the new position
/// (two action bundles), or is refused. End to end: yes.
#[tokio::test]
async fn action_only_push_of_recorded_actions_stores_nothing() {
    let (app, mut p, id, pool) = principal_on_server(true).await;
    let g = pool.get("golden").expect("golden");
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"msg": "once", "now": T + 1, "typ": "cyphr.me/comment/create"}),
    );
    let blob = wire(&pay, &sig);
    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &[blob.clone()])).await;
    assert!(s.is_success(), "first action-only push: {s} {b:?}");
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("action records");

    let actions: Vec<&cyphr::Action> = p.actions().collect();
    let dr = cyphr::compute_dr(&actions, None, &[cyphr::state::HashAlg::Sha256])
        .expect("DR")
        .expect("DT holds an action");
    let dr = format!(
        "SHA-256:{}",
        Base64UrlUnpadded::encode_string(dr.0.get(cyphr::state::HashAlg::Sha256).expect("SHA-256"))
    );
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"id": dr, "now": T + 2, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), T + 2, "cyphr.me")
        .await
        .expect("commit finalizes");
    let bundle = WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle");
    let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &bundle)).await;
    assert_eq!(s, StatusCode::CREATED, "ds/create push: {b:?}");

    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &[blob])).await;
    assert!(s.is_success(), "the repeated action-only push: {s} {b:?}");

    let (s, patch) = get_json(app, &format!("/patch?pr={id}")).await;
    assert_eq!(s, StatusCode::OK, "{patch:?}");
    let held = envelope_payload(&patch)["actions"]
        .as_array()
        .expect("actions")
        .len();
    assert_eq!(
        held, 1,
        "the repeat stored a second action bundle: {patch:?}"
    );
}
