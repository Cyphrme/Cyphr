//! The HTTP shapes of heads and proofs: `GET /tip` carries the head as
//! `root: {size, pr}`; `GET /proof?pr&size&claim=member:<i>|extends:<from>`
//! answers `{certificate}` (and the commit's `bundle` for `member:`), with
//! no default to the tip; an unknown claim is a 400, a claim the log cannot
//! answer a 422 (an index or size it lacks, a log whose last commit left no
//! State Root); and `/head`, `/inclusion` and `/consistency` are gone. Every certificate verifies
//! against an anchor the asker built itself. Bodies sit in the server's envelope
//! `payload`, as every other answer does.

use axum::http::StatusCode;
use cyphr::proof::{Anchor, Certificate, Claim, Root, verify};
use cyphr::replay::WireBundle;
use cyphr_server::build_router;

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, key_commit_by, load_pool, post_json,
    push_body,
};

const NOW: i64 = 1_700_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn tip_root_and_proof_answers_have_the_shapes_and_verify() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let id = common::golden_principal_id(&pool).await;
    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, NOW).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "genesis push: {body:?}");

    let golden = pool.get("golden").expect("golden");
    let mut p = cyphr::Principal::implicit(golden.key().expect("key"))
        .await
        .expect("genesis");
    test_fixtures::bundle::genesis_bundle(
        &mut p,
        golden,
        &[pool.get("key_a").expect("key_a").key().expect("key")],
        NOW,
    )
    .await
    .expect("genesis commit");
    let holder = p.fork().await.expect("fork"); // the one commit a holder has
    for (i, name) in ["key_b", "alice"].into_iter().enumerate() {
        let bundle = key_commit_by(&mut p, "golden", name, NOW + 1 + i as i64).await;
        let (status, body) = post_json(app.clone(), "/push", push_body(&id, &bundle)).await;
        assert_eq!(status, StatusCode::CREATED, "push {name}: {body:?}");
    }
    let size = p.commit_count() as u64;

    // /tip carries the head: the Root of the last commit.
    let (status, body) = get_json(app.clone(), &format!("/tip?pg={id}")).await;
    assert_eq!(status, StatusCode::OK, "/tip: {body:?}");
    let head: Root = serde_json::from_value(body["payload"]["root"].clone())
        .unwrap_or_else(|e| panic!("/tip has no root: {e}: {body:?}"));
    assert_eq!(
        Some(&head),
        p.root_at(size).as_ref(),
        "the head is PR at the tip"
    );
    assert_eq!(head.size, size);
    for gone in ["/head", "/inclusion", "/consistency"] {
        let (status, _) = get_json(app.clone(), &format!("{gone}?pg={id}&size={size}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{gone} is gone");
    }

    // member: {certificate, bundle}, and the size is asked for.
    let proof = |query: &str| get_json(app.clone(), format!("/proof?pg={id}&{query}").leak());
    let (status, _) = proof("claim=member:1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no default to the tip");
    let (status, body) = proof(&format!("size={size}&claim=member:1")).await;
    assert_eq!(status, StatusCode::OK, "member: {body:?}");
    let mut keys: Vec<_> = body["payload"]
        .as_object()
        .expect("an object")
        .keys()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["bundle", "certificate"],
        "nothing echoed beside them"
    );
    let cert: Certificate =
        serde_json::from_value(body["payload"]["certificate"].clone()).expect("a certificate");
    let bundle: WireBundle =
        serde_json::from_value(body["payload"]["bundle"].clone()).expect("a bundle");
    assert_eq!(
        bundle,
        WireBundle::of_commit(p.commit_at(1).expect("commit")).expect("bundle"),
        "the bundle served is the commit's own"
    );
    let claim = Claim::Member {
        index: 1,
        commit: bundle,
    };
    assert_eq!(
        verify(&Anchor::of_chain(p.state()), &cert, size, &claim),
        Ok(())
    );
    assert_eq!(
        verify(&Anchor::pin(head.clone()), &cert, size, &claim),
        Ok(())
    );

    // extends: {certificate} only, the size is the head's.
    let (status, body) = proof(&format!("size={size}&claim=extends:1")).await;
    assert_eq!(status, StatusCode::OK, "extends: {body:?}");
    assert_eq!(
        body["payload"]
            .as_object()
            .expect("an object")
            .keys()
            .collect::<Vec<_>>(),
        ["certificate"]
    );
    let cert: Certificate =
        serde_json::from_value(body["payload"]["certificate"].clone()).expect("a certificate");
    let claim = Claim::Extends {
        from: 1,
        head: head.pr.clone(),
    };
    assert_eq!(
        verify(&Anchor::of_chain(holder.state()), &cert, size, &claim),
        Ok(())
    );

    // What the log cannot answer is a 4xx; a claim that is no claim is a 400.
    let (status, _) = proof(&format!("size={size}&claim=bogus")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unknown claim");
    let (status, _) = proof(&format!("size={size}&claim=member:{size}")).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "an index at the size"
    );
    let (status, _) = proof(&format!("size={}&claim=member:1", size + 1)).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a size past the log"
    );
    let (status, _) = proof(&format!("size={size}&claim=key:{}", "A".repeat(43))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no such kind of claim");
}
