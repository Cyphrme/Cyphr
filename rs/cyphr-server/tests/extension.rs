//! `GET /proof` and the proof-gated pull (SPEC 4.4: clients obtain
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
    Anchor, ChannelBinding, ConnectError, Connector, HttpConnector, PatchEntry, PeerStanding,
    PullPeer, Record, Request, pull,
};
use cyphr_server::{AppState, build_router};

mod common;

use common::{envelope_payload, get_json, key_commit_by, keyless_server, load_pool, post_json};

const T: i64 = 1_700_500_000;

fn clock() -> i64 {
    T + 10_000
}

/// What the follower asked the peer, and an optional edit of the
/// `/proof` answer.
struct Watched {
    inner: HttpConnector,
    asked: Mutex<Vec<String>>,
    /// Commits the peer's `/patch` answers carried.
    fetched: Mutex<usize>,
    lie: Option<fn(&mut serde_json::Value)>,
    /// An edit of the head `/tip` reports (its `root`).
    head_lie: Option<fn(&mut serde_json::Value)>,
    /// An edit of the `/proof` answers after the first: those the
    /// search for where a fork parts is made of.
    search_lie: Option<fn(&mut serde_json::Value)>,
    /// Entries appended to a whole-chain `/patch` answer, each a copy of
    /// its last at the next position: a peer claiming a longer chain.
    padding: usize,
}

impl Watched {
    fn new(inner: HttpConnector) -> Self {
        Self {
            inner,
            asked: Mutex::default(),
            fetched: Mutex::default(),
            lie: None,
            head_lie: None,
            search_lie: None,
            padding: 0,
        }
    }

    fn fetched(&self) -> usize {
        *self.fetched.lock().expect("fetched")
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
        let mut body = self.inner.exchange(request).await?;
        if self.padding > 0
            && request.target.starts_with("/patch")
            && !request.target.contains("&from=")
        {
            let mut json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let entries = json["payload"]["entries"].as_array_mut().expect("entries");
            let last = entries.last().expect("an entry").clone();
            let at = last["sequence"].as_u64().expect("sequence");
            for k in 1..=self.padding as u64 {
                let mut junk = last.clone();
                junk["sequence"] = (at + k).into();
                entries.push(junk);
            }
            body = serde_json::to_vec(&json).expect("json");
        }
        if request.target.starts_with("/patch") {
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            let entries = json["payload"]["entries"].as_array().map_or(0, Vec::len);
            *self.fetched.lock().expect("fetched") += entries;
        }
        let lie = if request.target.starts_with("/tip") {
            self.head_lie
        } else if request.target.starts_with("/proof") {
            if self.asked("/proof") > 1 {
                self.search_lie
            } else {
                self.lie
            }
        } else {
            None
        };
        let Some(lie) = lie else {
            return Ok(body);
        };
        let mut json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        if request.target.starts_with("/tip") {
            lie(&mut json["payload"]["root"]);
        } else {
            lie(&mut json["payload"]);
        }
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
/// proof and the fork is found without its chain. The follower holds A (four
/// keys past the genesis, then a fifth of its own); the peer's B shares the
/// first four and then goes its own way. The follower asks for the proof,
/// then for O(log n) positions to find where the logs part, and fetches the
/// one commit the peer holds there: the fork finding is the one the whole
/// chain gave, proved by signatures.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_is_found_with_one_commit_fetched() {
    let shared = ["key_a", "key_b", "alice", "bob"];
    let (w, _) = world(&["key_a", "key_b", "alice", "bob", "carol", "eve_ed25519"]).await;
    let (_, mine) = line(
        &w.shared,
        &[shared[0], shared[1], shared[2], shared[3], "diana_es384"],
        T + 1,
    )
    .await;
    let held: Vec<&WireBundle> = std::iter::once(&w.genesis).chain(&mine).collect();
    let mut record = follower(&w.id, &held).await;
    let before = record.tip().expect("tip");

    let c = connector(&w);
    let report = pull(
        &mut record,
        &[PullPeer {
            name: "b",
            connector: &c,
        }],
    )
    .await;

    assert!(
        matches!(only_standing(&report), PeerStanding::Forked),
        "{:?}",
        only_standing(&report)
    );
    let fork = report.forks.first().expect("a fork finding");
    assert_eq!(fork.height, 5, "the logs part after genesis and four keys");
    assert_ne!(fork.commits[0], fork.commits[1]);
    // One ask for the pull itself, then a binary search over the six
    // commits the record holds: at most ceil(log2 7) + 1 more.
    assert!(
        c.asked("/proof") <= 1 + 4,
        "O(log n) asks: {}",
        c.asked("/proof")
    );
    assert_eq!(c.fetched(), 1, "one commit, not the chain");
    assert_eq!(
        record.tip().expect("tip"),
        before,
        "the record did not move"
    );
}

/// Backs: what a forked peer makes the holder do is bounded by the
/// holder's own chain. The peer's branch can change the holder's canonical
/// chain only by extending past the fork where the holder's own branch is
/// not extended, so no more of it is handed on than that takes; the rest arrives as an ordinary
/// extension once the branch is taken. A peer that has proved one fork and then serves any
/// number of entries past it gets the same bounded hand-off, where each
/// entry would otherwise be one submission to the engine.
#[tokio::test(flavor = "multi_thread")]
async fn a_forked_peers_branch_is_handed_on_no_longer_than_ours() {
    let (w, _) = world(&["key_a", "key_b", "alice", "bob"]).await;
    let (_, mine) = line(&w.shared, &["key_a", "key_b", "carol"], T + 1).await;
    let held: Vec<&WireBundle> = std::iter::once(&w.genesis).chain(&mine).collect();
    let mut handed = Vec::new();
    for padding in [0, 500] {
        let mut record = follower(&w.id, &held).await;
        let mut c = connector(&w);
        c.padding = padding;
        let peers = [PullPeer {
            name: "b",
            connector: &c,
        }];
        let report = pull(&mut record, &peers).await;
        assert!(
            matches!(only_standing(&report), PeerStanding::Forked),
            "{:?}",
            only_standing(&report)
        );
        assert_eq!(report.forks.first().expect("a fork").height, 3);
        handed.push(
            cyphr_client::branch_bundles(&record, &report, &peers)
                .await
                .len(),
        );
    }
    // The fork is at position 3 and the holder has one commit there: the
    // rival, and the one commit past it that extends it.
    assert_eq!(handed, [2, 2], "bundles handed on, unpadded and padded");
}

/// Backs: serving `/tip` and `/proof`, and admitting a
/// push, read a number of commit records from the index that does not grow
/// with the principal's history. Each asks whether the principal is in
/// Error first; answered by walking the whole chain, a proof of logarithmic
/// size costs a linear read, on every request, to anyone who asks.
///
/// Counted at the engine's one chain read, on a history of 2 commits and
/// one of 6: the answers are the same either way, so only the count shows
/// a walk, and the replay count sees no signature checked.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_reads_no_more_of_the_index_as_history_grows() {
    let mut rows = Vec::new();
    for peer_line in [
        &["key_a"][..],
        &["key_a", "key_b", "alice", "bob", "carol"][..],
    ] {
        let (w, bundles) = world(peer_line).await;
        let mut tip = w.shared.fork().await.expect("fork");
        for b in &bundles {
            cyphr::replay::replay_held(&mut tip, &b.decode().expect("decodes"))
                .await
                .expect("replays");
        }
        let next = key_commit_by(&mut tip, "golden", "eve_ed25519", T + 50).await;
        let app = build_router(w.peer.clone());
        let id = w.id.replace(':', "%3A");
        let before = w.peer.engine.chain_rows_read();
        for route in [
            format!("/tip?pr={id}"),
            format!("/proof?pr={id}&size={}&claim=extends:1", bundles.len() + 1),
            format!("/proof?pr={id}&size={}&claim=member:0", bundles.len() + 1),
        ] {
            let (status, body) = get_json(app.clone(), &route).await;
            assert_eq!(status, StatusCode::OK, "{route}: {body:?}");
        }
        let (status, body) = post_json(app, "/push", common::push_body(&w.id, &next)).await;
        assert_eq!(status, StatusCode::CREATED, "{body:?}");
        rows.push(w.peer.engine.chain_rows_read() - before);
    }
    assert_eq!(
        rows[0], rows[1],
        "index commit records read over a history of 2 commits and of 6"
    );
}

/// Backs: an honest extension still pulls exactly the new commits, after
/// one proof.
#[tokio::test(flavor = "multi_thread")]
async fn an_honest_extension_pulls_only_the_new_commits() {
    let (w, bundles) = world(&["key_a", "carol", "key_b"]).await;
    let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;

    let c = connector(&w);
    let report = pull(
        &mut record,
        &[PullPeer {
            name: "b",
            connector: &c,
        }],
    )
    .await;

    assert!(
        matches!(only_standing(&report), PeerStanding::Extended { added: 2 }),
        "{:?}",
        only_standing(&report)
    );
    assert_eq!(c.asked("/proof"), 1);
    assert_eq!(c.asked("/patch"), 1);
    assert_eq!(c.fetched(), 2, "only the new commits");
    assert_eq!(record.tip().expect("tip").commits, 4);
}

/// Backs: what a peer says about its tree decides what is fetched and never
/// what is believed. A flipped proof byte, a stated root other than the
/// log's, and a payload that is not the wire shape each leave the pull to
/// the no-proof path, which replays every commit it takes; a size the proof
/// cannot tell from the true one (a Commit Root does not commit to its
/// size) is held to the replay before the record takes the commits, so the
/// record does not move and the peer fails.
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_proof_never_changes_what_is_believed() {
    let flip = |v: &mut serde_json::Value| {
        let h = v["certificate"]["terminal"]["boundary_hash"]
            .as_str()
            .expect("hash")
            .to_owned();
        let first = if h.starts_with('A') { 'B' } else { 'A' };
        v["certificate"]["terminal"]["boundary_hash"] = format!("{first}{}", &h[1..]).into();
    };
    let wrong_root = |v: &mut serde_json::Value| {
        let sha = v["pr"].as_object_mut().expect("pr");
        let (_, d) = sha.iter_mut().next().expect("a variant");
        let s = d.as_str().expect("digest").to_owned();
        let first = if s.starts_with('A') { 'B' } else { 'A' };
        *d = format!("{first}{}", &s[1..]).into();
    };
    // (what, an edit of the certificate answer, an edit of the head answer)
    type Lie = Option<fn(&mut serde_json::Value)>;
    for (what, lie, head_lie) in [
        (
            "a flipped proof byte",
            Some(flip as fn(&mut serde_json::Value)),
            None,
        ),
        (
            "a stated root",
            None,
            Some(wrong_root as fn(&mut serde_json::Value)),
        ),
        (
            "a payload of no shape",
            Some((|v| *v = serde_json::json!({"size": "many"})) as fn(&mut serde_json::Value)),
            None,
        ),
    ] as [(&str, Lie, Lie); 3]
    {
        let (w, bundles) = world(&["key_a", "carol", "key_b"]).await;
        let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;
        let mut c = connector(&w);
        c.lie = lie;
        c.head_lie = head_lie;
        let report = pull(
            &mut record,
            &[PullPeer {
                name: "b",
                connector: &c,
            }],
        )
        .await;
        let standing = only_standing(&report);
        assert!(
            matches!(standing, PeerStanding::Extended { added: 2 }),
            "{what}: {standing:?}"
        );
        assert_eq!(c.fetched(), 2, "{what}: only the new commits");
        assert_eq!(record.tip().expect("tip").commits, 4, "{what}");
    }

    // A head stating more commits than the log holds: the server refuses
    // the certificate for it, so the pull goes on without one, and every
    // commit it takes is replayed.
    let (w, bundles) = world(&["key_a", "carol", "key_b", "alice"]).await;
    let mut record = follower(&w.id, &[&w.genesis, &bundles[0]]).await;
    let mut c = connector(&w);
    c.head_lie = Some(|v| v["size"] = (v["size"].as_u64().expect("size") + 1).into());
    let report = pull(
        &mut record,
        &[PullPeer {
            name: "b",
            connector: &c,
        }],
    )
    .await;
    assert!(
        matches!(only_standing(&report), PeerStanding::Extended { added: 3 }),
        "a stated size: {:?}",
        only_standing(&report)
    );
    assert_eq!(record.tip().expect("tip").commits, 5);
}

/// Backs: a peer on a fork cannot hide it by lying about its tree. Its
/// proof is fabricated (a one-leaf log, or a root nothing contradicts
/// cheaply), so no fork can be located from its answers; the pull then
/// compares the whole chain, as before proofs, and still finds the fork.
#[tokio::test(flavor = "multi_thread")]
async fn a_forked_peer_cannot_hide_behind_a_fabricated_proof() {
    for lie in [
        (|v: &mut serde_json::Value| v["size"] = 1.into()) as fn(&mut serde_json::Value),
        |v| v["size"] = 99.into(),
    ] {
        let (w, _) = world(&["key_a", "key_b", "alice", "bob", "carol", "eve_ed25519"]).await;
        let (_, mine) = line(
            &w.shared,
            &["key_a", "key_b", "alice", "bob", "diana_es384"],
            T + 1,
        )
        .await;
        let held: Vec<&WireBundle> = std::iter::once(&w.genesis).chain(&mine).collect();
        let mut record = follower(&w.id, &held).await;
        let mut c = connector(&w);
        c.head_lie = Some(lie);
        let report = pull(
            &mut record,
            &[PullPeer {
                name: "b",
                connector: &c,
            }],
        )
        .await;
        assert!(
            matches!(only_standing(&report), PeerStanding::Forked),
            "{:?}",
            only_standing(&report)
        );
        assert_eq!(report.forks.len(), 1);
        assert_eq!(report.forks[0].height, 5);
    }
}

/// Backs: a principal whose state the engine does not keep (after a restart)
/// is replayed once for the first proof asked of it and kept: asking over
/// and over, which any peer can, replays nothing more, and a follower pulls
/// with a proof as from any other principal.
#[tokio::test(flavor = "multi_thread")]
async fn an_unkept_principal_is_replayed_once_for_its_proofs() {
    let pool = load_pool();
    let g = pool.get("golden").expect("golden");
    let mut shared = cyphr::Principal::implicit(g.key().expect("golden"))
        .await
        .expect("implicit");
    let genesis = test_fixtures::bundle::genesis_bundle(&mut shared, g, &[], T)
        .await
        .expect("genesis");
    let id = test_fixtures::bundle::genesis_id(&genesis).expect("genesis id");
    let (_, bundles) = line(&shared, &["key_a", "carol", "key_b"], T + 1).await;
    let (first, dir) = keyless_server();
    let app = build_router(first.clone());
    for b in std::iter::once(&genesis).chain(&bundles) {
        let (status, body) = post_json(app.clone(), "/push", common::push_body(&id, b)).await;
        assert_eq!(status, StatusCode::CREATED, "{body:?}");
    }
    drop(app);
    drop(first);
    let config = cyphr_server::config::ServerConfig {
        data_dir: dir.path().to_path_buf(),
        ..Default::default()
    };
    let again = Arc::new(AppState::new(config).expect("reopens"));
    let app = build_router(again.clone());
    let q = id.replace(':', "%3A");
    let before = again.engine.commits_replayed();
    for _ in 0..3 {
        for route in [
            format!("/proof?pr={q}&size=4&claim=extends:2"),
            format!("/proof?pr={q}&size=4&claim=member:1"),
        ] {
            let (status, body) = get_json(app.clone(), &route).await;
            assert_eq!(status, StatusCode::OK, "{route}: {body:?}");
        }
    }
    assert_eq!(
        again.engine.commits_replayed() - before,
        4,
        "the chain of 4 commits replayed once for six proofs"
    );

    let url = serve(&again).await;
    let c = Watched::new(
        HttpConnector::with_client(again.http_client.clone(), &url, true).expect("connector"),
    );
    let mut record = follower(&id, &[&genesis, &bundles[0]]).await;
    let report = pull(
        &mut record,
        &[PullPeer {
            name: "b",
            connector: &c,
        }],
    )
    .await;
    assert!(
        matches!(only_standing(&report), PeerStanding::Extended { added: 2 }),
        "{:?}",
        only_standing(&report)
    );
}

/// Backs: the request is bounded. `from` must name a log the peer's log
/// extends, strictly shorter than it, and be a number; an unknown principal
/// is a 404, as `/tip`'s is.
#[tokio::test(flavor = "multi_thread")]
async fn the_proof_request_is_bounded() {
    let (w, _) = world(&["key_a", "carol"]).await; // three commits
    let app = build_router(w.peer.clone());
    let id = w.id.replace(':', "%3A");
    for (claim, size, want) in [
        ("extends:1", "3", StatusCode::OK),
        ("extends:2", "3", StatusCode::OK),
        ("extends:3", "3", StatusCode::OK),
        ("extends:1", "2", StatusCode::OK),
        ("extends:4", "3", StatusCode::UNPROCESSABLE_ENTITY),
        ("extends:0", "3", StatusCode::UNPROCESSABLE_ENTITY),
        ("extends:1", "4", StatusCode::UNPROCESSABLE_ENTITY),
        (
            "extends:1",
            "18446744073709551615",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("extends:-1", "3", StatusCode::BAD_REQUEST),
        ("extends:x", "3", StatusCode::BAD_REQUEST),
        ("extends:1", "x", StatusCode::BAD_REQUEST),
        ("member:0", "3", StatusCode::OK),
        ("member:2", "3", StatusCode::OK),
        ("member:0", "1", StatusCode::OK),
        ("member:3", "3", StatusCode::UNPROCESSABLE_ENTITY),
        ("member:0", "4", StatusCode::UNPROCESSABLE_ENTITY),
        ("member:0", "0", StatusCode::UNPROCESSABLE_ENTITY),
        ("member:-1", "3", StatusCode::BAD_REQUEST),
        ("member:x", "3", StatusCode::BAD_REQUEST),
        ("bogus", "3", StatusCode::BAD_REQUEST),
    ] {
        let (status, body) = get_json(
            app.clone(),
            &format!("/proof?pr={id}&size={size}&claim={claim}"),
        )
        .await;
        assert_eq!(status, want, "claim={claim} size={size}: {body:?}");
    }
    let (status, _) = get_json(app.clone(), "/proof?pr=nobody&size=1&claim=member:0").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, body) = get_json(app, &format!("/tip?pr={id}")).await;
    let payload = envelope_payload(&body);
    assert_eq!(payload["root"]["size"], 3, "{body:?}");
}

/// Backs: a proof request on a principal whose state the engine keeps
/// replays no commit: the proof is read from the engine's own log.
#[tokio::test(flavor = "multi_thread")]
async fn a_proof_from_a_kept_principal_replays_nothing() {
    let (w, _) = world(&["key_a", "carol", "key_b"]).await;
    let app = build_router(w.peer.clone());
    let id = w.id.replace(':', "%3A");
    let before = w.peer.engine.commits_replayed();
    let (status, _) = get_json(
        app.clone(),
        &format!("/proof?pr={id}&size=4&claim=extends:2"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get_json(app, &format!("/proof?pr={id}&size=4&claim=member:1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(w.peer.engine.commits_replayed(), before);
}

/// Backs: the search for where a fork parts is steered by the peer's
/// answers and decided by none of them. An answer that is no certificate, or
/// whose proof does not hold, cannot end in a fork the record did not
/// verify: the pull compares the whole chain and finds the same fork, at the
/// price of fetching it.
#[tokio::test(flavor = "multi_thread")]
async fn an_inconsistent_search_answer_ends_the_search() {
    type Lie = fn(&mut serde_json::Value);
    let lies: [(&str, Lie); 2] = [
        ("an answer that is no certificate", |v| {
            *v = serde_json::json!({"size": "many"});
        }),
        ("a proof that does not hold", |v| {
            let h = v["certificate"]["terminal"]["boundary_hash"]
                .as_str()
                .expect("hash")
                .to_owned();
            let first = if h.starts_with('A') { 'B' } else { 'A' };
            v["certificate"]["terminal"]["boundary_hash"] = format!("{first}{}", &h[1..]).into();
        }),
    ];
    for (what, lie) in lies {
        let (w, _) = world(&["key_a", "key_b", "alice", "bob", "carol", "eve_ed25519"]).await;
        let (_, mine) = line(
            &w.shared,
            &["key_a", "key_b", "alice", "bob", "diana_es384"],
            T + 1,
        )
        .await;
        let held: Vec<&WireBundle> = std::iter::once(&w.genesis).chain(&mine).collect();
        let mut record = follower(&w.id, &held).await;
        let mut c = connector(&w);
        c.search_lie = Some(lie);
        let report = pull(
            &mut record,
            &[PullPeer {
                name: "b",
                connector: &c,
            }],
        )
        .await;
        assert!(
            matches!(only_standing(&report), PeerStanding::Forked),
            "{what}: {:?}",
            only_standing(&report)
        );
        assert!(c.fetched() > 1, "{what}: the whole chain was compared");
    }
}
