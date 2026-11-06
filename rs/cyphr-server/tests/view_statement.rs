//! The signed view statement: a peer's own claim "I hold P at this size and
//! index" (GOSSIP.md section 3, `View statement`), served so a client can
//! verify it against the peer's chain.
//!
//! Pinned here (the minimum a black-box test cannot avoid): the route
//! `GET /view?pr=<P>` and a signed server statement whose `typ` is its own
//! under `cyphr-server/`. The field layout inside `pay` is the implementer's
//! (C2SP checkpoint shape); these tests locate the tree size and index by
//! VALUE, not by name, so any layout that signs them passes.

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::build_router;

mod common;

use common::{attestor_server, get_json, golden_principal_id, load_pool, post_json};

/// Typs the server already stamps; a view statement must not reuse one, or
/// a receipt could be replayed as a view (and the reverse).
const OTHER_TYPS: [&str; 3] = [
    "cyphr-server/receipt/commit",
    "cyphr-server/receipt/tip",
    "cyphr-server/auth/token",
];

/// Push bodies for two successive commits of the `golden` principal, each a
/// `key/create` signed by `golden` and authored on ONE local principal so the
/// second commit's `pre` is the first's state. The genesis key rides on the
/// first commit's closing cozy, as `/push` requires.
fn two_commit_bodies(pool: &test_fixtures::Pool, pr: &str) -> (String, String) {
    let golden = pool.get("golden").expect("golden in pool");
    let prv = Base64UrlUnpadded::decode_vec(golden.prv.as_ref().expect("golden prv"))
        .expect("golden prv b64");
    let pub_key = Base64UrlUnpadded::decode_vec(&golden.pub_key).expect("golden pub b64");
    let tmb = golden.compute_tmb().expect("golden tmb");
    let key = cyphr::Key::new(golden.alg.clone(), tmb.clone(), pub_key.clone())
        .expect("key binds its tmb");
    let mut principal = cyphr::Principal::implicit(key).expect("implicit genesis");

    let mut commit = |new_key: &str, now: i64, genesis: bool| -> String {
        let nk = pool.get(new_key).expect("new key in pool");
        let nk_tmb = nk.compute_tmb().expect("new key tmb");
        let nk_pub = Base64UrlUnpadded::decode_vec(&nk.pub_key).expect("new key pub b64");
        // Alphabetical field order: the server re-canonicalizes before
        // verifying, so the signed bytes must already be in that order.
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": golden.alg,
            "id": nk_tmb.to_b64(),
            "now": now,
            "tmb": tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/create",
        }))
        .expect("pay json");
        let (sig, cad) = coz::sign_json(&pay, &golden.alg, &prv, &pub_key).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &golden.alg).expect("czd");
        let new_key = cyphr::Key::new(nk.alg.clone(), nk_tmb, nk_pub)
            .expect("key binds its tmb")
            .with_first_seen(now);

        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, Some(new_key))
            .expect("key/create applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(&golden.alg, &prv, &pub_key, &tmb),
                now,
                "cyphr.me",
            )
            .expect("commit finalizes");

        let entries = cyphr_storage::export_commits(&principal).expect("export commits");
        let entry = entries.last().expect("a commit after finalize");
        let mut key_idx = 0;
        let mut blobs: Vec<serde_json::Value> = entry
            .cozies
            .iter()
            .map(|v| {
                let mut coz = v.clone();
                let typ = coz["pay"]["typ"].as_str().unwrap_or("");
                if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < entry.keys.len() {
                    let k = &entry.keys[key_idx];
                    coz["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                    key_idx += 1;
                }
                coz
            })
            .collect();
        if genesis {
            let closing = blobs.last_mut().expect("closing cozy");
            closing["key"] = serde_json::json!({
                "alg": golden.alg,
                "pub": golden.pub_key,
                "tmb": tmb.to_b64(),
            });
        }
        serde_json::json!({
            "principal_id": pr,
            "blobs": blobs
                .iter()
                .map(|b| Base64UrlUnpadded::encode_string(&serde_json::to_vec(b).expect("json")))
                .collect::<Vec<_>>(),
        })
        .to_string()
    };

    let first = commit("key_a", 1_700_000_000, true);
    let second = commit("key_b", 1_700_000_100, false);
    (first, second)
}

fn verifies(identity: &ServerIdentity, pay: &serde_json::Value, sig: &[u8]) -> bool {
    let pay_json = serde_json::to_vec(pay).expect("pay serializes");
    identity.verify(&pay_json, sig) == Some(true)
}

/// Names of the top-level `pay` fields holding exactly the integer `n`.
fn fields_equal(pay: &serde_json::Value, n: u64) -> Vec<String> {
    pay.as_object()
        .expect("pay is an object")
        .iter()
        .filter(|(_, v)| v.as_u64() == Some(n))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Claim: a peer's view statement signs the tree size AND the index of the
/// principal's log, so a client holding the peer's key can tell a genuine
/// "P has N commits, tip at index N-1" from a forged one. Two commits make
/// size (2) and index (1) distinct values, so each is located by value.
///
/// Turns red if: `/view` is absent or unsigned; the size or index sits
/// outside the signed `pay` (an attacker rewrites it undetected); a forged
/// size or index still verifies; or the statement reuses another typ.
/// End-to-end scenario: yes (attestor, two pushes over HTTP, signature
/// checked with the peer's key).
#[tokio::test]
async fn view_statement_signs_tree_size_and_index_end_to_end() {
    let (state, identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let pr = golden_principal_id(&pool);

    let (first, second) = two_commit_bodies(&pool, &pr);
    for body in [first, second] {
        let (status, resp) = post_json(app.clone(), "/push", body).await;
        assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    }

    let (status, view) = get_json(app, &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "GET /view must serve: {view:?}");
    assert_eq!(
        view["statement"]["kind"],
        serde_json::json!("signed"),
        "the view statement is the peer's signed claim: {view:?}"
    );

    let coz = &view["statement"]["coz"];
    let pay = coz["pay"].clone();
    let sig = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().expect("sig is a string"))
        .expect("sig is base64url");

    let typ = pay["typ"].as_str().expect("typ is a string");
    assert!(
        typ.starts_with("cyphr-server/") && !OTHER_TYPS.contains(&typ),
        "a view statement needs its own typ: {typ}"
    );
    assert!(
        verifies(&identity, &pay, &sig),
        "the statement must verify against the peer's key: {pay:?}"
    );

    // Tree size 2, index 1: both must be signed claims.
    let size = fields_equal(&pay, 2);
    let index = fields_equal(&pay, 1);
    assert!(
        !size.is_empty(),
        "no signed field carries tree size 2: {pay:?}"
    );
    assert!(
        !index.is_empty(),
        "no signed field carries index 1: {pay:?}"
    );

    // A forged size or index must not verify. Every field carrying either
    // value is perturbed on its own.
    for field in size.iter().chain(index.iter()) {
        let mut forged = pay.clone();
        let original = forged[field].as_u64().expect("integer field");
        forged[field] = serde_json::json!(original + 1);
        assert!(
            !verifies(&identity, &forged, &sig),
            "forging `{field}` ({original} -> {}) still verifies",
            original + 1
        );
    }
}

/// Claim: the statement tracks the log, so a view served after one commit
/// cannot be passed off as the view after two: size and index advance with
/// the chain and the signature changes with them.
///
/// Turns red if: `/view` is absent; the size or index is stale or fixed
/// across commits; or the two statements carry the same signature.
/// End-to-end scenario: yes.
#[tokio::test]
async fn view_statement_advances_with_the_log() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let pr = golden_principal_id(&pool);

    let (first_body, second_body) = two_commit_bodies(&pool, &pr);
    let (status, body) = post_json(app.clone(), "/push", first_body).await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    let (status, first) = get_json(app.clone(), &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "GET /view must serve: {first:?}");

    let (status, body) = post_json(app.clone(), "/push", second_body).await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    let (status, second) = get_json(app, &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "GET /view must serve: {second:?}");

    // After one commit the log has size 1 and index 0; after two, size 2
    // and index 1. Size 1 and index 1 coincide in the first view, so only
    // the second view is checked for both values by name-free lookup.
    let first_pay = &first["statement"]["coz"]["pay"];
    let second_pay = &second["statement"]["coz"]["pay"];
    assert!(
        !fields_equal(first_pay, 1).is_empty(),
        "first view must sign size 1: {first_pay:?}"
    );
    assert!(
        !fields_equal(second_pay, 2).is_empty() && !fields_equal(second_pay, 1).is_empty(),
        "second view must sign size 2 and index 1: {second_pay:?}"
    );
    assert_ne!(
        first["statement"]["coz"]["sig"], second["statement"]["coz"]["sig"],
        "a view after another commit is a different statement"
    );
}

/// Claim: a client accepts a peer's view statement only through a verifier
/// that takes the key ACTIVE in the peer principal chain the client holds,
/// never the server's own say-so. Genuine statement: accepted. Forged tree
/// size or index: refused. Statement signed by a key not active in that
/// chain: refused, even though its own signature is valid.
///
/// The verifier shape pinned here: the response envelope, the peer principal
/// chain the client replayed, and the principal id, giving `Ok(_)` or
/// `Err(_)`.
///
/// Turns red if: a forged size or index is accepted; a statement signed by
/// an inactive key is accepted; or the genuine statement is refused.
/// End-to-end scenario: yes (peer over HTTP, chain replayed into a second,
/// independent engine as in `receipts.rs`).
#[tokio::test]
async fn client_verifies_view_statement_against_the_active_peer_chain() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let pr = golden_principal_id(&pool);
    let (first, second) = two_commit_bodies(&pool, &pr);
    for body in [first, second] {
        let (status, resp) = post_json(app.clone(), "/push", body).await;
        assert_eq!(status, StatusCode::CREATED, "{resp:?}");
    }

    // The client's view of the peer's own chain: pin the PG from discovery,
    // re-derive it from the published genesis key, replay /patch locally.
    let (_, discovery) = get_json(app.clone(), "/server").await;
    let d = &discovery["payload"];
    let pg = d["pg"].as_str().expect("attestor pg").to_string();
    let g = &d["genesis"];
    let genesis_key = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb b64"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub b64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let (_, patch) = get_json(app.clone(), &format!("/patch?pr={pg}")).await;
    let local = cyphr_storage::engine::StorageEngine::new(
        cyphr_storage::blob::MemoryBlobStore::new(),
        cyphr_storage::index::MemoryIndexer::new(),
    );
    for entry in patch["payload"]["entries"].as_array().expect("entries") {
        let blobs: Vec<Vec<u8>> = entry["blobs"]
            .as_array()
            .expect("blobs")
            .iter()
            .map(|b| Base64UrlUnpadded::decode_vec(b.as_str().expect("blob")).expect("blob b64"))
            .collect();
        let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        local
            .submit_commit(
                &pg,
                Some(cyphr_storage::Genesis::Explicit(vec![genesis_key.clone()])),
                &refs,
            )
            .await
            .expect("replay a peer-chain commit");
    }
    let chain = local
        .load_principal(&pg, cyphr_storage::Genesis::Explicit(vec![genesis_key]))
        .await
        .expect("load the replayed peer chain");

    let (status, view) = get_json(app, &format!("/view?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "{view:?}");

    assert!(
        cyphr_client::verify_view_statement(&view, &chain, &pr).is_ok(),
        "the genuine statement must verify against the peer chain"
    );

    // Forged size or index: perturb each signed integer field in turn.
    let pay = view["statement"]["coz"]["pay"].clone();
    for field in fields_equal(&pay, 2)
        .iter()
        .chain(fields_equal(&pay, 1).iter())
    {
        let mut forged = view.clone();
        let original = pay[field].as_u64().expect("integer field");
        forged["statement"]["coz"]["pay"][field] = serde_json::json!(original + 1);
        assert!(
            cyphr_client::verify_view_statement(&forged, &chain, &pr).is_err(),
            "forged `{field}` was accepted"
        );
    }

    // A validly signed statement from a key the peer chain does not hold.
    let outsider = coz::Alg::Ed25519.generate_keypair();
    let mut foreign_pay = pay.clone();
    foreign_pay["alg"] = serde_json::json!("Ed25519");
    foreign_pay["tmb"] = serde_json::json!(Base64UrlUnpadded::encode_string(
        outsider
            .alg
            .compute_thumbprint(&outsider.pub_bytes)
            .expect("thumbprint")
            .as_bytes()
    ));
    let (sig, _cad) = coz::sign_json(
        &serde_json::to_vec(&foreign_pay).expect("pay json"),
        "Ed25519",
        &outsider.prv_bytes,
        &outsider.pub_bytes,
    )
    .expect("outsider signs");
    let mut foreign = view.clone();
    foreign["statement"]["coz"]["pay"] = foreign_pay;
    foreign["statement"]["coz"]["sig"] = serde_json::json!(Base64UrlUnpadded::encode_string(&sig));
    assert!(
        cyphr_client::verify_view_statement(&foreign, &chain, &pr).is_err(),
        "a statement signed by a key not active in the peer chain was accepted"
    );
}
