//! SPEC 4.8.2 "Data Tree Inclusion" through the server push path: a data
//! action is recorded in DT, but DR enters the Principal Tree only by a
//! signed `cyphr/ds/create`, as its `id`. DT is a point-in-time snapshot
//! (SPEC 2.3.3): the `id` is the signer's commitment, never checked against
//! the actions a holder has.
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

/// The digest bytes of a tagged `SHA-256:<b64>` root.
fn sha256_bytes(tagged: &str) -> Vec<u8> {
    let b64 = tagged.strip_prefix("SHA-256:").expect("a SHA-256 root");
    Base64UrlUnpadded::decode_vec(b64).expect("b64")
}

/// SR over `ar` and DR = `id` (SPEC 3.7, 4.8.2), derived here from the two
/// roots rather than from any principal's actions.
fn sr_over(ar: &str, id: &str) -> Vec<u8> {
    let root = |t: &str| {
        cyphr::multihash::MultihashDigest::from_single(HashAlg::Sha256, sha256_bytes(t))
            .expect("digest")
    };
    let sr = cyphr::semantic_tree::StateTree::build(
        &cyphr::state::AuthRoot(root(ar)),
        Some(&cyphr::state::DataRoot(root(id))),
        &[HashAlg::Sha256],
    )
    .expect("SR");
    sr.0.get(HashAlg::Sha256).expect("SHA-256 variant").to_vec()
}

/// Record `actions` on `p`, apply `txs` as one commit signed by `golden`,
/// and return the bundle: the actions, then the commit's cozies.
async fn bundle(
    p: &mut Principal,
    pool: &test_fixtures::Pool,
    actions: &[Signed],
    txs: impl FnOnce(&Principal) -> Vec<Signed>,
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
/// 2. a `ds/create` whose `id` is a DR over an action neither the server nor the client ever
///    received is accepted, and the tip's SR is the SR over its AR and that `id`: DR is the signed
///    `id`, not a root over the actions held;
/// 3. a `ds/create` naming MR(DT) over the held actions is accepted: the tip's PR is the one the
///    client computed, and its SR is the SR over AR and that `id`.
///
/// Turns red if a data action moves PR on its own (step 1), if `ds/create`
/// is unknown or refused, or if DR is recomputed from held actions instead
/// of taken from the signed `id` (steps 2, 3). End to end: yes.
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
    let tip_uri = format!("/tip?pg={id}");

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

    // 2. A ds/create over an action nobody here received sets DR to its id.
    let mut elsewhere = p.fork().await.expect("fork");
    let unseen = action(&pool, T + 3, "never pushed");
    elsewhere
        .verify_and_record_action(&unseen.pay, &unseen.sig, unseen.czd.clone())
        .expect("records");
    let foreign = data_tree_id(&elsewhere);
    let signed = bundle(
        &mut p,
        &pool,
        &[],
        |_| vec![ds_create(&pool, &foreign, T + 3)],
        T + 3,
    )
    .await;
    let (s, b) = post_json(app.clone(), "/push", body(&id, &signed)).await;
    assert_eq!(s, StatusCode::CREATED, "a ds/create over any DR: {b:?}");
    let (_, tip) = get_json(app.clone(), &tip_uri).await;
    let tip = envelope_payload(&tip).clone();
    assert_eq!(
        sha256_bytes(tip["sr"].as_str().expect("sr")),
        sr_over(tip["ar"].as_str().expect("ar"), &foreign),
        "DR is the signed id: {tip:?}"
    );
    assert_eq!(
        tip["pr"].as_str(),
        Some(p.pr_tagged().expect("PR").as_str()),
        "server and client agree on the PR"
    );

    // 3. A ds/create naming MR(DT) over the held actions sets DR to it.
    let mut own = String::new();
    let included = bundle(
        &mut p,
        &pool,
        &[action(&pool, T + 4, "two")],
        |p| {
            own = data_tree_id(p);
            vec![ds_create(&pool, &own, T + 5)]
        },
        T + 5,
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
    assert_eq!(
        sha256_bytes(tip["sr"].as_str().expect("sr")),
        sr_over(tip["ar"].as_str().expect("ar"), &own),
        "DR is the signed id: {tip:?}"
    );
}
