//! Adversarial sweep (AS1) of the server routes: attacks reproduced end to
//! end over TCP, each a red test owned by the node that fixes it.

mod common;

use std::sync::{Arc, Mutex};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_server::config::{AuthorityIdentity, ServerConfig, ServerMode};
use cyphr_server::sync::{SyncOutcome, sync_from_authority};

fn unix_now() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    i64::try_from(secs).expect("secs")
}

/// `statement` (`{pay, sig}`) re-signed by the authority's own key with its
/// `now` moved to `now`: the statement the authority signed at `now`.
fn signed_at(statement: &mut serde_json::Value, key_file: &std::path::Path, now: i64) {
    let key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(key_file).expect("key file")).expect("key json");
    let alg = key["alg"].as_str().expect("alg").to_owned();
    let prv = Base64UrlUnpadded::decode_vec(key["prv_key"].as_str().expect("prv")).expect("prv");
    let pubb = Base64UrlUnpadded::decode_vec(key["pub_key"].as_str().expect("pub")).expect("pub");
    statement["pay"]["now"] = now.into();
    let pay = serde_json::to_vec(&statement["pay"]).expect("pay");
    let (sig, _) = coz::sign_json(&pay, &alg, &prv, &pubb).expect("sign");
    statement["sig"] = Base64UrlUnpadded::encode_string(&sig).into();
}

/// A stand-in for the network between a witness and its authority: it
/// answers every request with the body it is told to replay.
async fn replayer(body: Arc<Mutex<serde_json::Value>>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().fallback(move || {
        let body = body.lock().expect("body").clone();
        async move { axum::Json(body) }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (url, handle)
}

async fn push(app: &axum::Router, id: &str, bundle: &WireBundle) -> axum::http::StatusCode {
    common::post_json(app.clone(), "/push", common::push_body(id, bundle))
        .await
        .0
}

/// Claim (docs/specs/receipts.md: the tip report "is the freshness
/// attestation over that chain"): a witness refuses a signed tip report
/// the authority made long ago as the authority's current word. The report
/// signs its `now`, but nothing binds it to the request or to a time the
/// witness checks, so whoever carries the link can replay an old genuine
/// `/patch` and withhold every commit made since: the witness answers
/// `UpToDate` while the authority holds a commit it lacks.
///
/// Here the authority signed the replayed report an hour before the sync.
/// Turns red while the witness accepts it as current (anything but
/// `Failed`).
/// End to end: yes (an attestor over TCP, the witness's real sync, a relay
/// replaying the authority's genuine signed body).
#[tokio::test]
#[ignore = "RED(DEBT3)"]
async fn witness_refuses_an_hour_old_tip_report() {
    let (astate, _identity, adir) = common::attestor_server().await;
    let app = cyphr_server::build_app_router(astate.clone()).expect("authority router");
    let pool = common::load_pool();
    let now = unix_now();
    let id = common::genesis_push_id(&pool, "golden", "key_a").await;
    let mut p = common::genesis_pushed_principal(&pool, "golden", "key_a", now).await;
    let genesis = WireBundle::of_commit(p.commits().next().expect("genesis")).expect("bundle");
    let first = common::key_commit_by(&mut p, "golden", "key_b", now + 1).await;
    for b in [&genesis, &first] {
        assert!(push(&app, &id, b).await.is_success(), "authority takes it");
    }
    let (_, fresh) = common::get_json(app.clone(), &format!("/patch?pr={id}")).await;
    let body = Arc::new(Mutex::new(fresh.clone()));
    let (url, relay) = replayer(body.clone()).await;

    let identity = astate.identity.clone().expect("identity");
    let wdir = tempfile::tempdir().expect("witness dir");
    let witness = Arc::new(
        cyphr_server::AppState::new(ServerConfig {
            mode: ServerMode::Witness,
            data_dir: wdir.path().join("data"),
            authority_url: Some(url),
            authority_identity: Some(AuthorityIdentity {
                alg: identity.alg().name().to_string(),
                pub_key: identity.pub_key().to_vec(),
            }),
            ..Default::default()
        })
        .expect("witness"),
    );
    let synced = sync_from_authority(&witness, &id).await;
    assert!(
        matches!(synced, SyncOutcome::Synced { .. }),
        "the relayed genuine body syncs: {synced:?}"
    );

    // The authority moves on; the relay replays its hour-old word.
    let second = common::key_commit_by(&mut p, "golden", "alice", now + 2).await;
    assert!(push(&app, &id, &second).await.is_success());
    let mut stale = fresh;
    signed_at(
        &mut stale["statement"],
        &adir.path().join("signing-key.json"),
        now - 3600,
    );
    *body.lock().expect("body") = stale;
    let replayed = sync_from_authority(&witness, &id).await;
    relay.abort();
    let held = witness
        .engine
        .get_tip(&id)
        .await
        .expect("tip")
        .expect("held");
    println!(
        "replayed: {replayed:?}; witness holds {} commits",
        held.commit_count
    );
    assert!(
        matches!(replayed, SyncOutcome::Failed { .. }),
        "an hour-old report was taken as current: {replayed:?}, witness at {} of 3 commits",
        held.commit_count
    );
}
