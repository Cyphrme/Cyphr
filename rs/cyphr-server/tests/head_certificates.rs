//! The HTTP shapes of heads and certificates: `GET /head?pr` is a `Root`,
//! `GET /inclusion?pr&index&size` and `GET /consistency?pr&from&to` are
//! `{certificate}` and nothing else (no echoed fields, no default to the
//! tip), and every certificate verifies against an anchor the asker built
//! itself. Bodies sit in the server's envelope `payload`, as every other
//! answer does. Red until the routes exist: today `/head` is a 404 and
//! the other two answer the old payloads.

use axum::http::StatusCode;
use cyphr::proof::{Anchor, Certificate, Root, verify_extension, verify_membership};
use cyphr_server::build_router;

mod common;

use common::{
    attestor_server, build_genesis_push_body, get_json, key_commit_by, load_pool, post_json,
    push_body,
};

const NOW: i64 = 1_700_000_000;

#[tokio::test(flavor = "multi_thread")]
async fn head_and_certificate_answers_are_bare_and_verify() {
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

    // /head is the Root of the last commit.
    let (status, body) = get_json(app.clone(), &format!("/head?pr={id}")).await;
    assert_eq!(status, StatusCode::OK, "/head: {body:?}");
    let head: Root = serde_json::from_value(body["payload"].clone()).expect("a Root");
    assert_eq!(
        Some(&head),
        p.root_at(size).as_ref(),
        "the head is PR at the tip"
    );
    assert_eq!(head.size, size);

    // /inclusion: {certificate} only, and the size is asked for.
    let (status, _) = get_json(app.clone(), &format!("/inclusion?pr={id}&index=1")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no default to the tip");
    let (status, body) = get_json(
        app.clone(),
        &format!("/inclusion?pr={id}&index=1&size={size}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "/inclusion: {body:?}");
    let payload = body["payload"].as_object().expect("an object payload");
    assert_eq!(
        payload.keys().collect::<Vec<_>>(),
        ["certificate"],
        "nothing echoed beside the certificate"
    );
    let cert: Certificate =
        serde_json::from_value(body["payload"]["certificate"].clone()).expect("a certificate");
    let bundle =
        cyphr::replay::WireBundle::of_commit(p.commit_at(1).expect("commit")).expect("bundle");
    assert_eq!(
        verify_membership(&Anchor::of_chain(p.state()), &cert, size, 1, &bundle),
        Ok(())
    );
    assert_eq!(
        verify_membership(&Anchor::pin(head.clone()), &cert, size, 1, &bundle),
        Ok(())
    );

    // /consistency: {certificate} only, from and to both asked for.
    let (status, _) = get_json(app.clone(), &format!("/consistency?pr={id}&from=1")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no default to the tip");
    let (status, body) = get_json(
        app.clone(),
        &format!("/consistency?pr={id}&from=1&to={size}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "/consistency: {body:?}");
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
    assert_eq!(
        verify_extension(&Anchor::of_chain(holder.state()), &cert, 1, &head),
        Ok(())
    );
}
