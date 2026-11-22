//! `POST /resync` and `GET /resync?pr=` (frame section 12.3, SPEC 15.8 item
//! 2): a proof of possession over one branch's tip selects it at a fork
//! both of whose branches are extended, which no commit can. The chosen
//! tip admits writes, the abandoned branch stays served as evidence, and
//! the holders that read the fork as Error (a gossiping peer, a witness)
//! reach Active on the same tip once they carry the PoP.

use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_client::HttpConnector;
use cyphr_server::{AppState, build_router};

mod common;

use common::{attestor_server, get_json, keyless_server, load_pool, post_json};

const T: i64 = 1_700_700_000;

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

/// `golden` creates the pool key `name` over `p` at `now`; the commit's bundle.
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

/// A line over `base`: the bundles, and the state after each commit.
async fn line(
    base: &cyphr::Principal,
    names: &[&str],
    now: i64,
) -> (Vec<WireBundle>, Vec<cyphr::Principal>) {
    let mut p = base.fork().await.expect("fork");
    let (mut bundles, mut states) = (Vec::new(), Vec::new());
    for (i, name) in names.iter().enumerate() {
        bundles.push(key_commit(&mut p, name, now + i as i64).await);
        states.push(p.fork().await.expect("fork"));
    }
    (bundles, states)
}

fn commit_id(p: &cyphr::Principal) -> String {
    p.commits()
        .last()
        .expect("commit")
        .tr()
        .0
        .tagged_first()
        .expect("commit id")
        .to_string()
}

/// A resync PoP by `golden` asserting the tip `tip`, as `/resync` takes it.
fn pop(tip: &cyphr::Principal, now: i64) -> serde_json::Value {
    let (pay, sig, _) = golden_signs(serde_json::json!({
        "id": tip.pr_tagged().expect("pr"), "now": now, "typ": "cyphr.me/cyphr/resync/create"
    }));
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    })
}

fn resync_body(id: &str, coz: &serde_json::Value, line: &[WireBundle]) -> String {
    serde_json::json!({
        "principal_id": id, "coz": coz,
        "line": line.iter().map(|b| serde_json::to_value(b).expect("bundle")).collect::<Vec<_>>(),
    })
    .to_string()
}

async fn push(app: &axum::Router, id: &str, b: &WireBundle) -> StatusCode {
    post_json(app.clone(), "/push", common::push_body(id, b))
        .await
        .0
}

fn enc(id: &str) -> String {
    id.replace(':', "%3A")
}

/// The fork of section 12: the chain C_0..C_2, the line L of four commits
/// over it (L_5 and L_6 are offered after the PoP is asserted or held),
/// and R of two over it; L_3, L_4 and R_3, R_4 are the contest's two
/// extended branches.
struct Fork {
    id: String,
    prefix: Vec<WireBundle>,
    l: Vec<WireBundle>,
    l_states: Vec<cyphr::Principal>,
    r: Vec<WireBundle>,
    r_states: Vec<cyphr::Principal>,
}

async fn fork() -> Fork {
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
    let c2 = key_commit(&mut chain, "key_b", T + 2).await;
    let (l, l_states) = line(&chain, &["alice", "bob", "carol", "eve_ed25519"], T + 100).await;
    let (r, r_states) = line(&chain, &["carol", "diana_es384"], T + 200).await;
    Fork {
        id,
        prefix: vec![genesis, c1, c2],
        l,
        l_states,
        r,
        r_states,
    }
}

impl Fork {
    /// A server holding both branches: Error at position 3.
    async fn error_server(&self) -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
        let (state, dir) = keyless_server();
        let app = build_router(state.clone());
        for b in self.prefix.iter().chain(&self.l[..2]) {
            assert_eq!(push(&app, &self.id, b).await, StatusCode::CREATED);
        }
        for b in &self.r {
            assert!(
                push(&app, &self.id, b).await.is_client_error(),
                "a rival is retained"
            );
        }
        assert!(
            state.engine.is_errored(&self.id).await.expect("verdict"),
            "premise: Error"
        );
        (state, app, dir)
    }

    fn pop_l(&self) -> serde_json::Value {
        pop(&self.l_states[1], T + 900)
    }
}

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

/// Catches an exit that does not exist: with both branches extended, a
/// commit on a head is refused (423), `/resync` over L_4 is accepted,
/// the principal is Active on the chosen branch's held leaf L_5, a write on it is admitted and one
/// on the abandoned branch is not, the abandoned branch is still served as
/// evidence, and `GET /resync` lists the PoP.
#[tokio::test]
async fn a_pop_resolves_a_both_extended_fork_and_keeps_the_other_branch() {
    let f = fork().await;
    let (state, app, _dir) = f.error_server().await;
    assert_eq!(
        push(&app, &f.id, &f.l[2]).await,
        StatusCode::LOCKED,
        "no commit leaves Error"
    );

    let coz = f.pop_l();
    let (status, body) = post_json(app.clone(), "/resync", resync_body(&f.id, &coz, &[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    // The walk ends at the held leaf of the chosen branch (frame 12.2:
    // heads are leaves, "assertions decide where the walk stops"): L_5,
    // which was held as evidence while in Error, not the asserted L_4.
    let want = commit_id(&f.l_states[2]);
    assert_eq!(
        state.engine.assess(&f.id).await.expect("assess").heads,
        vec![want.clone()]
    );
    assert!(
        !state.engine.is_errored(&f.id).await.expect("verdict"),
        "Active on the asserted tip"
    );

    assert_eq!(
        push(&app, &f.id, &f.l[3]).await,
        StatusCode::CREATED,
        "a write on the chosen head"
    );
    let (_, branches) = get_json(app.clone(), &format!("/branches?pr={}", enc(&f.id))).await;
    assert!(
        branches.to_string().contains(&commit_id(&f.r_states[1])),
        "the abandoned branch is evidence: {branches:?}"
    );
    let (status, held) = get_json(app.clone(), &format!("/resync?pr={}", enc(&f.id))).await;
    assert_eq!(status, StatusCode::OK, "{held:?}");
    assert_eq!(
        held.to_string()
            .matches(&coz["sig"].as_str().expect("sig").to_owned())
            .count(),
        1
    );
}

/// Catches a PoP that reaches only the server it was sent to: a gossiping
/// peer in Error fetches the PoP with the heads and reaches Active on the
/// same tip.
#[tokio::test(flavor = "multi_thread")]
async fn a_gossiping_peer_in_error_reaches_active_on_the_asserted_tip() {
    let f = fork().await;
    let (a, a_app, _ad) = f.error_server().await;
    let (b, _b_app, _bd) = f.error_server().await;
    let (status, body) = post_json(a_app, "/resync", resync_body(&f.id, &f.pop_l(), &[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let url = serve(&a).await;
    let peer = HttpConnector::with_client(b.http_client.clone(), &url, true).expect("connector");
    cyphr_server::gossip::Gossip::default()
        .round(&b, &[(url, peer)])
        .await;
    assert_eq!(
        b.engine.assess(&f.id).await.expect("assess").heads,
        vec![commit_id(&f.l_states[1])],
        "the peer is Active on the asserted tip"
    );
}

/// Catches a witness that stays in Error behind an authority that resolved:
/// it syncs the Error, the authority takes the PoP, and the next sync
/// leaves the witness Active on the authority's tip.
#[tokio::test(flavor = "multi_thread")]
async fn a_witness_in_error_reaches_active_on_the_asserted_tip() {
    use cyphr_server::config::{AuthorityIdentity, ServerConfig, ServerMode};
    use cyphr_server::sync::{SyncOutcome, sync_from_authority};

    let f = fork().await;
    let (astate, identity, adir) = attestor_server().await;
    let app = cyphr_server::build_app_router(astate.clone()).expect("authority router");
    let mut instance = common::multi::Instance {
        name: "authority".to_string(),
        state: astate.clone(),
        identity: Some(identity.clone()),
        dir: adir,
        router: app.clone(),
        listener_addr: None,
        tcp_handle: None,
    };
    instance.bind_tcp().await.expect("bind");
    for b in f.prefix.iter().chain(&f.l[..2]) {
        assert_eq!(push(&app, &f.id, b).await, StatusCode::CREATED);
    }
    for b in &f.r {
        let _ = push(&app, &f.id, b).await;
    }
    assert!(
        astate.engine.is_errored(&f.id).await.expect("verdict"),
        "premise: Error"
    );
    let wdir = tempfile::tempdir().expect("witness dir");
    let witness = Arc::new(
        AppState::new(ServerConfig {
            mode: ServerMode::Witness,
            data_dir: wdir.path().join("data"),
            authority_url: Some(instance.url().expect("url")),
            authority_identity: Some(AuthorityIdentity {
                alg: identity.alg().name().to_string(),
                pub_key: identity.pub_key().to_vec(),
            }),
            ..Default::default()
        })
        .expect("witness"),
    );
    let first = sync_from_authority(&witness, &f.id).await;
    assert!(matches!(first, SyncOutcome::Synced { .. }), "{first:?}");
    assert!(
        witness.engine.is_errored(&f.id).await.expect("verdict"),
        "premise: Error"
    );

    let (status, body) = post_json(app, "/resync", resync_body(&f.id, &f.pop_l(), &[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let second = sync_from_authority(&witness, &f.id).await;
    assert!(!matches!(second, SyncOutcome::Failed { .. }), "{second:?}");
    assert_eq!(
        witness.engine.assess(&f.id).await.expect("assess").heads,
        vec![commit_id(&f.l_states[1])],
        "the witness is Active on the asserted tip"
    );
}
