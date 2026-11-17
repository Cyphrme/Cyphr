//! `GET /consistency` and the proof-gated pull (SPEC 4.4: clients obtain
//! consistency proofs over the commit log). A follower that holds a tip A
//! and is offered a tip B asks the peer for the proof that B extends A
//! before it fetches a single commit: a fork shows as a failed extension
//! with nothing transferred, an honest extension still moves only the new
//! commits.
//!
//! End to end over a real server on a real socket; the only stand-in is a
//! connector that counts what the follower asks for and can corrupt one
//! answer, so "zero commits fetched" is a count and a lying peer is a
//! byte flipped.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use cyphr::replay::WireBundle;
use cyphr_client::{
    Anchor, ChannelBinding, ConnectError, Connector, HttpConnector, PatchEntry, PeerFailure,
    PeerStanding, PullPeer, Record, Request, pull,
};
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, key_commit_by, keyless_server, load_pool, post_json};

const T: i64 = 1_700_500_000;

fn clock() -> i64 {
    T + 10_000
}

/// What the follower asked the peer, and an optional edit of the
/// `/consistency` answer.
struct Watched {
    inner: HttpConnector,
    asked: Mutex<Vec<String>>,
    lie: Option<fn(&mut serde_json::Value)>,
}

impl Watched {
    fn new(inner: HttpConnector) -> Self {
        Self {
            inner,
            asked: Mutex::default(),
            lie: None,
        }
    }

    fn asked(&self, route: &str) -> usize {
        let asked = self.asked.lock().expect("asked");
        asked.iter().filter(|t| t.starts_with(route)).count()
    }
}

impl Connector for Watched {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        self.inner.channel_binding()
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        self.asked
            .lock()
            .expect("asked")
            .push(request.target.clone());
        let body = self.inner.exchange(request).await?;
        let (true, Some(lie)) = (request.target.starts_with("/consistency"), self.lie) else {
            return Ok(body);
        };
        let mut json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        lie(&mut json["payload"]);
        Ok(serde_json::to_vec(&json).expect("json"))
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

/// `grow` keys created, each by `golden`, on a fork of `shared`: the
/// principal after the last commit and the commit bundles.
async fn line(
    shared: &cyphr::Principal,
    grow: &[&str],
    t0: i64,
) -> (cyphr::Principal, Vec<WireBundle>) {
    let mut p = shared.fork().await.expect("fork");
    let mut bundles = Vec::new();
    for (i, name) in grow.iter().enumerate() {
        bundles.push(key_commit_by(&mut p, "golden", name, t0 + i as i64).await);
    }
    (p, bundles)
}

async fn follower(id: &str, entries: &[&WireBundle]) -> Record {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let entries: Vec<PatchEntry> = entries
        .iter()
        .enumerate()
        .map(|(i, b)| PatchEntry {
            sequence: i as u64,
            bundle: Ok((*b).clone()),
        })
        .collect();
    Record::from_entries(
        id,
        Anchor::GenesisKey(g.key().expect("key")),
        clock,
        &entries,
        &[],
    )
    .await
    .expect("record")
    .with_extension_proofs()
}

struct World {
    id: String,
    peer: Arc<AppState>,
    url: String,
    _dir: tempfile::TempDir,
    genesis: WireBundle,
    shared: cyphr::Principal,
}

/// A server holding the genesis and `peer_line`'s commits.
async fn world(peer_line: &[&str]) -> (World, Vec<WireBundle>) {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut shared, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let (peer, dir) = keyless_server();
    let app = build_router(peer.clone());
    let (_, bundles) = line(&shared, peer_line, T + 1).await;
    for b in std::iter::once(&genesis).chain(&bundles) {
        let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, b)).await;
        assert_eq!(status, StatusCode::CREATED, "{body:?}");
    }
    let url = serve(&peer).await;
    (
        World {
            id,
            peer,
            url,
            _dir: dir,
            genesis,
            shared,
        },
        bundles,
    )
}

fn connector(w: &World) -> Watched {
    Watched::new(
        HttpConnector::with_client(w.peer.http_client.clone(), &w.url, true).expect("connector"),
    )
}

fn only_standing(report: &cyphr_client::PullReport) -> &PeerStanding {
    &report.peers.first().expect("one peer").standing
}

/// Backs: a peer whose tip does not extend the follower's is refused on the
/// proof, and not one commit is fetched to find out. The follower holds A
/// (a commit on its own branch); the peer's B forks from the shared
/// genesis.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_is_refused_on_the_proof_with_no_commits_fetched() {
    let (w, _) = world(&["key_a", "carol", "key_b"]).await;
    let (_, mine) = line(&w.shared, &["key_b"], T + 1).await;
    let mut record = follower(&w.id, &[&w.genesis, &mine[0]]).await;
    let held = record.tip().expect("tip");

    let c = connector(&w);
    let report = pull(&mut record, &[PullPeer { name: "b", connector: &c }]).await;

    assert!(
        matches!(only_standing(&report), PeerStanding::Diverged),
        "{:?}",
        only_standing(&report)
    );
    assert_eq!(c.asked("/consistency"), 1, "the proof was asked for");
    assert_eq!(c.asked("/patch"), 0, "no commit was fetched");
    assert_eq!(record.tip().expect("tip"), held, "the record did not move");
}

/// Backs: an honest extension still pulls exactly the new commits, after
/// one proof.
#[tokio::test(flavor = "multi_thread")]
async fn an_honest_extension_pulls_only_the_new_commits() {
    let (w, bundles) = world(&["key_a", "carol", "key_b"]).await;
    let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;

    let c = connector(&w);
    let report = pull(&mut record, &[PullPeer { name: "b", connector: &c }]).await;

    assert!(
        matches!(only_standing(&report), PeerStanding::Extended { added: 2 }),
        "{:?}",
        only_standing(&report)
    );
    assert_eq!(c.asked("/consistency"), 1);
    assert_eq!(c.asked("/patch"), 1);
    assert_eq!(record.tip().expect("tip").commits, 4);
}

/// Backs: a lying proof fails closed. A flipped byte in the proof, and a
/// root or size the peer states that the proof was not made over, are each
/// a refusal with no commit fetched; a payload that is not the wire shape
/// fails the peer, not the record.
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_proof_fails_closed() {
    let flip = |v: &mut serde_json::Value| {
        let h = v["proof"]["boundary_hash"].as_str().expect("hash").to_owned();
        let first = if h.starts_with('A') { 'B' } else { 'A' };
        v["proof"]["boundary_hash"] = format!("{first}{}", &h[1..]).into();
    };
    let wrong_size = |v: &mut serde_json::Value| {
        let size = v["size"].as_u64().expect("size");
        v["size"] = (size + 1).into();
    };
    let wrong_root = |v: &mut serde_json::Value| {
        let cr = v["cr"].as_str().expect("cr").to_owned();
        let last = if cr.ends_with('A') { 'B' } else { 'A' };
        v["cr"] = format!("{}{last}", &cr[..cr.len() - 1]).into();
    };
    for (what, lie) in [
        ("a flipped proof byte", flip as fn(&mut serde_json::Value)),
        ("a stated size", wrong_size),
        ("a stated root", wrong_root),
    ] {
        let (w, bundles) = world(&["key_a", "carol", "key_b"]).await;
        let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;
        let mut c = connector(&w);
        c.lie = Some(lie);
        let report = pull(&mut record, &[PullPeer { name: "b", connector: &c }]).await;
        assert!(
            matches!(only_standing(&report), PeerStanding::Diverged),
            "{what}: {:?}",
            only_standing(&report)
        );
        assert_eq!(c.asked("/patch"), 0, "{what}: nothing fetched");
        assert_eq!(record.tip().expect("tip").commits, 2, "{what}");
    }

    let (w, bundles) = world(&["key_a", "carol"]).await;
    let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;
    let mut c = connector(&w);
    c.lie = Some(|v| *v = serde_json::json!({"size": "many"}));
    let report = pull(&mut record, &[PullPeer { name: "b", connector: &c }]).await;
    assert!(
        matches!(
            only_standing(&report),
            PeerStanding::Failed(PeerFailure::Extension(_))
        ),
        "{:?}",
        only_standing(&report)
    );
    assert_eq!(c.asked("/patch"), 0);
}

/// Backs: the request is bounded. `from` must name a log the peer's log
/// extends, strictly shorter than it, and be a number; an unknown principal
/// is a 404, as `/tip`'s is.
#[tokio::test(flavor = "multi_thread")]
async fn the_proof_request_is_bounded() {
    let (w, _) = world(&["key_a", "carol"]).await;
    let app = build_router(w.peer.clone());
    let id = w.id.replace(':', "%3A");
    for (from, want) in [
        ("1", StatusCode::OK),
        ("2", StatusCode::BAD_REQUEST),
        ("0", StatusCode::BAD_REQUEST),
        ("18446744073709551615", StatusCode::BAD_REQUEST),
        ("-1", StatusCode::BAD_REQUEST),
        ("x", StatusCode::BAD_REQUEST),
    ] {
        let (status, body) = get_json(app.clone(), &format!("/consistency?pr={id}&from={from}")).await;
        assert_eq!(status, want, "from={from}: {body:?}");
    }
    let (status, _) = get_json(app.clone(), "/consistency?pr=nobody&from=1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, body) = get_json(app, &format!("/consistency?pr={id}&from=1")).await;
    let payload = envelope_payload(&body);
    assert_eq!(payload["size"], 2, "{body:?}");
}
