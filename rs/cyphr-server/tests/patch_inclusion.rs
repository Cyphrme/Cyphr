//! SPEC 4.8.2 across `/patch`: the patch carries the action bundles the
//! chain included (and those still pending), and a puller never takes that
//! list on trust. It replays the chain and selects, at each `ds/create`,
//! the pending bundles whose root is the signed `id`, exactly as the
//! source did.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::WireBundle;
use cyphr_client::{Anchor, Record, verify_patch_body};
use cyphr_server::build_router;

mod common;

use common::{envelope_payload, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_400_000;

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

/// A puller's replay of a `/patch` body: the record it opens from the
/// served chain, anchored at the served genesis commit.
async fn pull(id: &str, body: &serde_json::Value) -> Result<Record, cyphr_client::PeerFailure> {
    let bytes = serde_json::to_vec(body).expect("body");
    let patch = verify_patch_body(&bytes, id, None).expect("well-formed patch");
    let genesis = envelope_payload(body)["entries"][0]["commit_id"]
        .as_str()
        .expect("genesis commit id")
        .to_owned();
    Record::from_entries(
        id,
        Anchor::GenesisCommit(genesis),
        cyphr::principal::system_clock,
        &patch.entries,
        &patch.actions,
    )
    .await
}

/// Backs rule 4: the laptop pushes an action at the position the phone
/// then commits at; the phone's `ds/create` includes only its own. The
/// served `/patch` carries the phone's bundle alone, and a puller that
/// replays it reaches the published PR. A forged patch that adds the
/// laptop's bundle back as included is replayed to the same PR with that
/// bundle left out, and one that drops the phone's bundle is refused.
///
/// Turns red if: a puller adopts a forged included set (its replay
/// includes the laptop's bundle or reaches another PR), or accepts a
/// chain missing a bundle its `ds/create` signed for. End to end over
/// `/push`, `/patch` and the client's pull replay: yes.
#[tokio::test]
async fn puller_reselects_the_included_set() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut phone = Principal::implicit(g.key().expect("golden key"))
        .await
        .expect("implicit genesis");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut phone, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let (state, _dir) = keyless_server();
    let app = build_router(state);
    let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &genesis)).await;
    assert_eq!(s, StatusCode::CREATED, "genesis push: {b:?}");

    let (pay, sig, _) = golden_signs(
        &pool,
        serde_json::json!({"msg": "laptop", "now": T + 1, "typ": "cyphr.me/comment/create"}),
    );
    let laptop = wire(&pay, &sig);
    let (s, b) = post_json(
        app.clone(),
        "/push",
        common::push_blobs(&id, std::slice::from_ref(&laptop)),
    )
    .await;
    assert!(s.is_success(), "laptop action: {s} {b:?}");
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"msg": "phone", "now": T + 2, "typ": "cyphr.me/comment/create"}),
    );
    let mine = wire(&pay, &sig);
    phone
        .verify_and_record_action(&pay, &sig, czd)
        .expect("records");
    let (s, b) = post_json(
        app.clone(),
        "/push",
        common::push_blobs(&id, std::slice::from_ref(&mine)),
    )
    .await;
    assert!(s.is_success(), "phone action: {s} {b:?}");
    let dr = phone
        .begin_commit()
        .data_tree_id()
        .expect("DR")
        .expect("DT holds an action");
    let (pay, sig, czd) = golden_signs(
        &pool,
        serde_json::json!({"id": dr, "now": T + 3, "typ": "cyphr.me/cyphr/ds/create"}),
    );
    let mut scope = phone.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), T + 3, "cyphr.me")
        .await
        .expect("commit finalizes");
    let commit = WireBundle::of_commit(phone.commits().last().expect("a commit")).expect("bundle");
    let (s, b) = post_json(app.clone(), "/push", common::push_body(&id, &commit)).await;
    assert_eq!(s, StatusCode::CREATED, "ds/create push: {b:?}");
    let published = phone.pr_tagged().expect("PR");

    let (s, served) = get_json(app.clone(), &format!("/patch?pr={id}")).await;
    assert_eq!(s, StatusCode::OK, "{served:?}");
    let b64 = |blob: &[u8]| serde_json::Value::from(Base64UrlUnpadded::encode_string(blob));
    let carried = envelope_payload(&served)["actions"].clone();
    assert_eq!(
        carried,
        serde_json::json!([{"after": 1, "blobs": [b64(&mine)]}]),
        "the served patch carries the included bundle only"
    );
    let honest = pull(&id, &served).await.expect("the served chain replays");
    assert_eq!(honest.tip().expect("tip").pr, published);

    // Forged: the laptop's bundle claimed as included too.
    let mut forged = served.clone();
    forged["payload"]["actions"] = serde_json::json!([
        {"after": 1, "blobs": [b64(&laptop)]},
        {"after": 1, "blobs": [b64(&mine)]},
    ]);
    let record = pull(&id, &forged).await.expect("the forged set replays");
    assert_eq!(record.tip().expect("tip").pr, published, "same DR, same PR");
    let left_out: Vec<bool> = record
        .principal()
        .expect("held")
        .actions()
        .map(cyphr::Action::is_not_included)
        .collect();
    assert_eq!(left_out, [true, false], "the laptop's bundle is left out");

    // Forged: the phone's bundle withheld.
    let mut withheld = served.clone();
    withheld["payload"]["actions"] = serde_json::json!([]);
    assert!(
        pull(&id, &withheld).await.is_err(),
        "a chain missing a bundle its ds/create signed for is refused"
    );
}
