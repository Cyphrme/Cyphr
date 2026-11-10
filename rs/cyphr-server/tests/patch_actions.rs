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
    serde_json::json!({
        "principal_id": id,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

fn blobs_of(entry: &serde_json::Value) -> Vec<Vec<u8>> {
    entry["blobs"]
        .as_array()
        .expect("blobs")
        .iter()
        .map(|b| Base64UrlUnpadded::decode_vec(b.as_str().expect("b64")).expect("decode"))
        .collect()
}

fn line(blobs: &[Vec<u8>]) -> CommitEntry {
    let cozies: Vec<serde_json::Value> = blobs
        .iter()
        .map(|b| serde_json::from_slice(b).expect("coz"))
        .collect();
    // A key a `key/create` discloses rides on the line, as a bundle writes it.
    let keys = cozies
        .iter()
        .filter_map(|c| c.get("key"))
        .map(|k| serde_json::from_value(k.clone()).expect("key entry"))
        .collect();
    CommitEntry::new(cozies, keys, String::new(), None, None, String::new())
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
    let mut p = Principal::implicit(g.key().expect("golden key")).expect("implicit genesis");
    let id = p.pr_tagged().expect("PG");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut p, g, &[], T).expect("genesis");
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &genesis)).await;
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
        .expect("commit finalizes");
    let commit = cyphr_storage::export_commits(&p).expect("export");
    let commit_create = commit
        .last()
        .expect("a commit")
        .cozies
        .last()
        .expect("seal");
    let blobs = [
        wire(&pay, &sig),
        serde_json::to_vec(commit_create).expect("coz"),
    ];
    let (s, b) = post_json(app.clone(), "/push", push_body(&id, &blobs)).await;
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
            lines.push(line(&blobs_of(a)));
        }
        lines.push(line(&blobs_of(entry)));
    }
    let key = g.key().expect("golden key");
    let fresh = load_principal_from_commits(Genesis::Implicit(key), &lines)
        .expect("a fresh client replays the served chain");
    assert_eq!(
        fresh.pr_tagged().expect("PR"),
        published,
        "the replayed PR is the one the server published"
    );
}
