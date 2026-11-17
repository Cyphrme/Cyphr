//! A read of `GET /tip` while the principal's chain is growing is answered
//! with a signed attestation of the commit it names, never a 500
//! (NETSIM-2 D2; U3).
//!
//! The write path makes a commit durable (manifest) before it indexes it,
//! so a read racing a push can see the blob store ahead of the index
//! without any corruption. The attestation derives the roots of the commit
//! the tip names (the engine knows them from admitting it, or replays up to
//! that commit alone), so there is nothing to wait out and no retry budget:
//! every read is a 200 whose roots are those the push of that commit
//! answered. End to end through the router: the unit that fails is the
//! `attestation roots disagree` 500.

use axum::http::StatusCode;
use cyphr_server::build_router;

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

const GENESIS_NOW: i64 = 1_700_000_000;
const COMMITS: usize = 30;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tip_read_during_pushes_never_500s() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let pool = load_pool();
    let id = common::golden_principal_id(&pool).await;

    let (status, body) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &id, GENESIS_NOW).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "genesis push: {body:?}");

    // The whole chain is built up front, so the pushes below land as fast
    // as the server takes them.
    let mut p = cyphr::Principal::implicit(pool.get("golden").expect("golden").key().expect("key"))
        .await
        .expect("genesis");
    test_fixtures::bundle::genesis_bundle(
        &mut p,
        pool.get("golden").expect("golden"),
        &[pool.get("key_a").expect("key_a").key().expect("key")],
        GENESIS_NOW,
    )
    .await
    .expect("genesis commit");
    let mut bodies = Vec::new();
    for n in 0..COMMITS {
        let bundle = common::sign_key_create_commit(
            p.fork().await.expect("fork"),
            &pool,
            "golden",
            &format!("#{n}"),
            GENESIS_NOW + 1 + n as i64,
        )
        .await;
        cyphr::replay::replay_bundle(&mut p, &bundle.decode().expect("wire bundle"))
            .await
            .expect("commit replays");
        bodies.push(common::push_body(&id, &bundle));
    }

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let readers: Vec<_> = (0..3)
        .map(|_| {
            let (app, id, stop) = (app.clone(), id.clone(), stop.clone());
            tokio::spawn(async move {
                let mut bad = Vec::new();
                let mut seen = Vec::new();
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let (status, body) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
                    if status != StatusCode::OK {
                        bad.push((status, body));
                        continue;
                    }
                    let payload = &body["payload"];
                    seen.push((
                        payload["commit_id"].as_str().expect("commit_id").to_owned(),
                        payload["pr"].as_str().expect("pr").to_owned(),
                    ));
                }
                (seen, bad)
            })
        })
        .collect();

    // The roots each push answered, by the commit it admitted.
    let mut admitted = std::collections::HashMap::new();
    let (_, genesis) = get_json(app.clone(), &format!("/tip?pr={id}")).await;
    let genesis = &genesis["payload"];
    admitted.insert(
        genesis["commit_id"].as_str().expect("commit_id").to_owned(),
        genesis["pr"].as_str().expect("pr").to_owned(),
    );
    for body in bodies {
        let (status, res) = post_json(app.clone(), "/push", body).await;
        assert!(status.is_success(), "push: {status} {res:?}");
        let pushed = &res["payload"];
        admitted.insert(
            pushed["commit_id"].as_str().expect("commit_id").to_owned(),
            pushed["roots"]["pr"].as_str().expect("pr").to_owned(),
        );
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);

    let mut reads = 0;
    for r in readers {
        let (seen, bad) = r.await.expect("reader");
        assert!(bad.is_empty(), "GET /tip during pushes: {bad:?}");
        for (commit_id, pr) in &seen {
            assert_eq!(
                admitted.get(commit_id),
                Some(pr),
                "a tip read named commit {commit_id} with roots its push did not answer"
            );
        }
        reads += seen.len();
    }
    assert!(reads > 0);

    let (status, tip) = get_json(app, &format!("/tip?pr={id}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");
    assert_eq!(tip["statement"]["kind"], "signed", "{tip:?}");
}
