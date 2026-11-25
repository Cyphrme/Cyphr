//! A server that follows the fork rule signs two tip reports at one
//! position when a fork is resolved under it: the first names the commit the
//! resolution then abandoned (SPEC 15.8: "the abandoned branch's
//! transactions become permanently invalid"; the spec author: "Once a fork
//! is resolved, it's no longer a fork"). Two reports at one position that
//! differ prove equivocation only if no valid resolution explains the
//! difference. These tests check [`check_equivocation`] over the forks a
//! witness holds, as the engine reads them.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_server::build_router;
use cyphr_server::receipt::{self, EquivocationVerdict};

mod common;
use common::{attestor_server, get_json, load_pool, post_json};

const T: i64 = 1_700_700_000;

fn signs(name: &str, fields: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pool = load_pool();
    let g = pool.get(name).expect("pool key");
    let mut fields = fields;
    fields["alg"] = g.alg.clone().into();
    fields["tmb"] = g.compute_tmb_b64().expect("tmb").into();
    if let Some(obj) = fields.as_object_mut() {
        obj.sort_keys();
    }
    let pay = serde_json::to_vec(&fields).expect("pay");
    let prv = Base64UrlUnpadded::decode_vec(g.prv.as_ref().expect("prv")).expect("prv");
    let pubb = Base64UrlUnpadded::decode_vec(&g.pub_key).expect("pub");
    let (sig, cad) = coz::sign_json(&pay, &g.alg, &prv, &pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    (pay, sig, czd)
}

async fn commit(
    p: &mut cyphr::Principal,
    signer: &str,
    fields: serde_json::Value,
    new_key: Option<&str>,
    now: i64,
) -> WireBundle {
    let pool = load_pool();
    let (pay, sig, czd) = signs(signer, fields);
    let key = new_key.map(|n| pool.get(n).expect("key").key().expect("key"));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, key)
        .expect("applies");
    scope
        .finalize_with_software(
            &pool
                .get(signer)
                .expect("signer")
                .software_signer()
                .expect("signer"),
            now,
            "cyphr.me",
        )
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
}

fn tmb(name: &str) -> String {
    load_pool()
        .get(name)
        .expect("key")
        .compute_tmb_b64()
        .expect("tmb")
}

/// A principal whose server reports the owner's c2 and then, after the
/// owner's retired key `key_a` resolves a fork below it with a resync proof
/// (SPEC 15.8 item 2), the resolving line. The tip reports before and after,
/// the principal id, and the engine's read of its forks.
struct Resolved {
    first: serde_json::Value,
    second: serde_json::Value,
    forks: Vec<cyphr::fork::Contest>,
    identity: std::sync::Arc<cyphr_server::auth::ServerIdentity>,
    _dir: tempfile::TempDir,
}

async fn resolved_fork() -> Resolved {
    let (state, identity, dir) = attestor_server().await;
    let app = build_router(state.clone());
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut chain = cyphr::Principal::implicit(g.key().expect("key"))
        .await
        .expect("principal");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut chain, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("id");
    let enc = id.replace(':', "%3A");
    let push = |b: WireBundle| {
        let app = app.clone();
        let id = id.clone();
        async move { post_json(app, "/push", common::push_body(&id, &b)).await.0 }
    };
    push(genesis).await;
    let c1 = commit(
        &mut chain,
        "golden",
        serde_json::json!({"id": tmb("key_a"), "now": T + 1, "typ": "cyphr.me/cyphr/key/create"}),
        Some("key_a"),
        T + 1,
    )
    .await;
    let after_c1 = chain.fork().await.expect("fork");
    push(c1).await;
    let c2 = commit(
        &mut chain,
        "golden",
        serde_json::json!({"id": tmb("key_a"), "now": T + 2, "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        T + 2,
    )
    .await;
    push(c2).await;
    let (_, first) = get_json(app.clone(), &format!("/tip?pg={enc}")).await;

    // `key_a`, retired at c2, signs a line over c1 and a proof of it.
    let now = T + 10_000;
    let mut line = after_c1.fork().await.expect("fork");
    let e1 = commit(
        &mut line,
        "key_a",
        serde_json::json!({"id": tmb("golden"), "now": now, "typ": "cyphr.me/cyphr/key/delete"}),
        None,
        now,
    )
    .await;
    let (pay, sig, _) = signs(
        "key_a",
        serde_json::json!({
            "id": line.pr_tagged().expect("pr"), "now": now + 1,
            "typ": "cyphr.me/cyphr/resync/create"}),
    );
    let pop = serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig)});
    let body = serde_json::json!({"principal_id": id, "coz": pop,
        "line": [serde_json::to_value(&e1).expect("line")]})
    .to_string();
    let (st, resp) = post_json(app.clone(), "/resync", body).await;
    assert!(st.is_success(), "the resolution is accepted: {st} {resp}");
    let (_, second) = get_json(app.clone(), &format!("/tip?pg={enc}")).await;
    let forks = state.engine.assess(&id).await.expect("assess").forks;
    Resolved {
        first,
        second,
        forks,
        identity,
        _dir: dir,
    }
}

fn report(v: &serde_json::Value) -> coz::CozJson {
    serde_json::from_value(v["statement"]["coz"].clone()).expect("signed report")
}

/// SPEC 15.8: the first report names the commit the resolution abandoned,
/// so the pair is a server following the fork rule, not equivocation.
#[tokio::test]
async fn a_report_superseded_by_a_valid_resolution_is_not_equivocation() {
    let r = resolved_fork().await;
    let (a, b) = (report(&r.first), report(&r.second));
    assert_ne!(
        a.pay["commit_id"], b.pay["commit_id"],
        "premise: they differ"
    );
    assert_eq!(
        a.pay["sequence"], b.pay["sequence"],
        "premise: one position"
    );

    let verdict =
        receipt::check_equivocation(&a, r.identity.pub_key(), &b, r.identity.pub_key(), &r.forks);

    assert_eq!(verdict, EquivocationVerdict::Resolved);
}

/// Without the resolution the same pair is the conflict it looks like: the
/// verdict is read from what the witness holds, never from the pair alone.
#[tokio::test]
async fn the_same_pair_without_the_resolution_is_proven() {
    let r = resolved_fork().await;
    let (a, b) = (report(&r.first), report(&r.second));

    let verdict =
        receipt::check_equivocation(&a, r.identity.pub_key(), &b, r.identity.pub_key(), &[]);

    assert_eq!(verdict, EquivocationVerdict::Proven);
}
