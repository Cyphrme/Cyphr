//! A gossip hand-off that carries two refused line roots together with their
//! extensions (frame 11.1: every carrier re-offers a refused entry with its
//! own extension).
//!
//! A holder whose key quota is full refuses each rival root alone, so each
//! root must travel with its extension. `branch_bundles` hands a round's
//! rivals first and the peers' later commits after them, so with two rivals
//! the extension of the first root is not the next bundle: pairing a refused
//! root with whatever follows it offers the wrong commit, and the real
//! extension then arrives alone and is refused.

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::gossip::Peer;
use cyphr_server::{AppState, build_router};

mod common;

use common::{keyless_server, load_pool, post_json};

const T: i64 = 1_700_600_000;

/// `golden` signs `fields` plus its own `alg` and `tmb`: (pay, sig, czd).
fn golden_signs(fields: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut fields = fields;
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

/// `golden` creates the pool key `name` over `p` at `now`; the commit's
/// bundle. Every commit here is signed by that one key.
async fn key_commit(p: &mut cyphr::Principal, name: &str, now: i64) -> WireBundle {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let key = pool.get(name).expect("pool key").key().expect("key");
    let (pay, sig, czd) = golden_signs(serde_json::json!({
        "id": key.tmb().to_b64(), "now": now, "typ": "cyphr.me/cyphr/key/create"
    }));
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key))
        .expect("applies");
    scope
        .finalize_with_software(&g.software_signer().expect("signer"), now, "cyphr.me")
        .await
        .expect("finalizes");
    WireBundle::of_commit(p.commits().last().expect("a commit")).expect("bundle")
}

/// A line over `base`: one commit per name, each extending the last.
async fn line(base: &cyphr::Principal, names: &[&str], now: i64) -> Vec<WireBundle> {
    let mut p = base.fork().await.expect("fork");
    let mut out = Vec::new();
    for (i, name) in names.iter().enumerate() {
        out.push(key_commit(&mut p, name, now + i as i64).await);
    }
    out
}

async fn push(app: &axum::Router, id: &str, bundle: &WireBundle) -> StatusCode {
    post_json(app.clone(), "/push", common::push_body(id, bundle))
        .await
        .0
}

/// Serve `state` on an ephemeral local port; its base URL.
async fn serve(state: &Arc<AppState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    format!("http://{addr}")
}

/// (is Error, fork point (height, pre)).
async fn verdict(state: &Arc<AppState>, id: &str) -> (bool, Option<(u64, Option<String>)>) {
    let a = state.engine.assess(id).await.expect("assess");
    (
        a.consensus == cyphr_storage::engine::Consensus::Error,
        a.fork_point.map(|f| (f.height, f.pre)),
    )
}

/// Catches pairing a refused root with the next bundle of the hand-off: the
/// holder (chain C_0..C_2, the thief's J_3, J_4 canonical, the key's quota
/// full of junk X, Y) is offered, by one round against two peers, the
/// owner's line O_3, O_4 and a second line Q_3, Q_4. The hand-off is
/// [O_3, Q_3, O_4, Q_4], so O_3's next bundle is Q_3, not its extension. The
/// holder must end where a holder fed the same lines directly ends: Error at
/// the contest over C_2.
#[tokio::test(flavor = "multi_thread")]
async fn two_refused_roots_each_travel_with_their_own_extension() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut chain = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut chain, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let c1 = key_commit(&mut chain, "key_a", T + 1).await;
    let before_c2 = chain.fork().await.expect("fork");
    let c2 = key_commit(&mut chain, "key_b", T + 2).await;
    let prefix = [genesis, c1, c2];

    let j = line(&chain, &["alice", "bob"], T + 100).await;
    let x = line(&before_c2, &["carol"], T + 110).await;
    let y = line(&before_c2, &["diana_es384"], T + 111).await;
    let o = line(&chain, &["alice", "bob"], T + 200).await;
    let q = line(&chain, &["carol", "diana_es384"], T + 300).await;

    // Peers P1 and P2 each hold the chain and one line, canonical.
    let mut urls = Vec::new();
    let mut keep = Vec::new();
    for owned in [&o, &q] {
        let (state, dir) = keyless_server();
        let app = build_router(state.clone());
        for b in prefix.iter().chain(owned) {
            assert_eq!(push(&app, &id, b).await, StatusCode::CREATED);
        }
        urls.push(serve(&state).await);
        keep.push((state, dir));
    }

    // A holder: the thief's line canonical, the key's quota full.
    let make_holder = async || {
        let (holder, dir) = keyless_server();
        let happ = build_router(holder.clone());
        for b in prefix.iter().chain(&j) {
            assert_eq!(push(&happ, &id, b).await, StatusCode::CREATED);
        }
        for junk in [&x[0], &y[0]] {
            assert!(push(&happ, &id, junk).await.is_client_error(), "junk kept");
        }
        assert!(!verdict(&holder, &id).await.0, "premise: Active on J");
        (holder, dir)
    };
    let (holder, _hdir) = make_holder().await;
    let (control, _cdir) = make_holder().await;

    // The reference: a holder fed the lines directly.
    let (reference, _rdir) = keyless_server();
    let rapp = build_router(reference.clone());
    for b in prefix.iter().chain(&o).chain(&j).chain(&q) {
        let _ = push(&rapp, &id, b).await;
    }
    let want = verdict(&reference, &id).await;
    assert!(want.0, "premise: the lines make both branches extended");

    let dial = |state: &Arc<AppState>, urls: &[String]| -> Vec<Peer> {
        urls.iter()
            .map(|url| {
                let connector = HttpConnector::with_client(state.http_client.clone(), url, true)
                    .expect("connector");
                Peer::new(url.clone(), connector)
            })
            .collect()
    };
    // Control: one peer hands over [O_3, O_4], adjacent, and a refused root
    // pairs with its extension.
    cyphr_server::gossip::Gossip::default()
        .round(&control, &dial(&control, &urls[..1]))
        .await;
    assert!(
        verdict(&control, &id).await.0,
        "control: one rival's root and extension are adjacent and land"
    );

    cyphr_server::gossip::Gossip::default()
        .round(&holder, &dial(&holder, &urls))
        .await;
    assert_eq!(
        verdict(&holder, &id).await,
        want,
        "the holder reads what a holder fed the same commits reads"
    );
}
