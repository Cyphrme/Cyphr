//! Claims about the harness itself. Each backs a promise the scenarios
//! rely on: if one fails, a red scenario could be red for the wrong reason.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use cyphr_scenarios::Harness;
use cyphr_scenarios::capability::{Capability, Probe};
use cyphr_scenarios::carrier::{Carrier, UdpCarrier};
use cyphr_scenarios::faults::{Link, Schedule};

async fn get_server(
    h: &Harness,
    addr: std::net::SocketAddr,
) -> Result<reqwest::StatusCode, reqwest::Error> {
    Ok(h.http
        .get(format!("http://{addr}/server"))
        .send()
        .await?
        .status())
}

// Claim: a scenario's peers are real, independent processes.
#[tokio::test(flavor = "multi_thread")]
async fn harness_three_peers_start_independently() {
    let h = Harness::start(&["p1", "p2", "p3"])
        .await
        .expect("start peers");
    let ports: HashSet<_> = h.peers.iter().map(|p| p.addr.port()).collect();
    let dirs: HashSet<_> = h.peers.iter().map(|p| p.data_dir.clone()).collect();
    let ids: HashSet<_> = h.peers.iter().map(|p| p.id.clone()).collect();
    assert_eq!((ports.len(), dirs.len(), ids.len()), (3, 3, 3));
    for p in &h.peers {
        assert_eq!(
            get_server(&h, p.addr).await.expect("GET /server"),
            reqwest::StatusCode::OK
        );
    }
}

// Claim: partition and heal gate traffic through the proxy, both on a new
// request and for a client that already used the route.
#[tokio::test(flavor = "multi_thread")]
async fn harness_partition_blocks_and_heal_restores() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let via = h.route("bob", "p1").await;
    assert!(get_server(&h, via).await.is_ok(), "healthy route must work");
    h.proxy.partition("bob", "p1");
    assert!(
        get_server(&h, via).await.is_err(),
        "partitioned route must fail"
    );
    h.proxy.heal("p1", "bob"); // link order must not matter
    assert!(get_server(&h, via).await.is_ok(), "healed route must work");
}

// Claim: an offline node cannot be reached by anyone, and returns on online.
#[tokio::test(flavor = "multi_thread")]
async fn harness_offline_node_refuses_connections() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let via = h.route("bob", "p1").await;
    h.proxy.offline("p1");
    assert!(get_server(&h, via).await.is_err());
    h.proxy.online("p1");
    assert!(get_server(&h, via).await.is_ok());
}

// Claim: delay and drop shape traffic, so scenarios can model slow and lossy links.
#[tokio::test(flavor = "multi_thread")]
async fn harness_delay_and_drop_shape_traffic() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let via = h.route("bob", "p1").await;
    let link = Link::new("bob", "p1");
    h.proxy.delay(&link, Duration::from_millis(300));
    let t = Instant::now();
    assert!(get_server(&h, via).await.is_ok());
    assert!(
        t.elapsed() >= Duration::from_millis(300),
        "delay not applied: {:?}",
        t.elapsed()
    );
    h.proxy.delay(&link, Duration::ZERO);
    h.proxy.drop(&link, 1.0);
    assert!(get_server(&h, via).await.is_err(), "drop=1.0 must drop");
}

// Claim: a schedule is a pure function of its seed and always injects a fault.
// (Pure logic: no scenario reaches this cheaply, and it is the replay guarantee.)
#[test]
fn harness_schedule_is_seeded_and_nonempty() {
    let nodes = ["p1", "p2", "bob"];
    for seed in 0..64u64 {
        let s = Schedule::generate(seed, &nodes, 8);
        // Compare events, not whole schedules: `Schedule` carries its seed, so
        // comparing it would make different seeds differ by construction.
        assert_eq!(
            s.events,
            Schedule::generate(seed, &nodes, 8).events,
            "seed {seed} not reproducible"
        );
        assert_ne!(
            s.events,
            Schedule::generate(seed + 1, &nodes, 8).events,
            "seeds {seed},{} yield the same events",
            seed + 1
        );
        assert!(
            !Schedule::generate(seed, &nodes, 0).events.is_empty(),
            "no fault event"
        );
    }
}

// Claim: replaying a schedule through the live proxy lands in the state the
// schedule says it should.
#[tokio::test(flavor = "multi_thread")]
async fn harness_schedule_play_reaches_its_final_world() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let s = Schedule::generate(7, &["p1", "bob", "carol"], 12);
    h.proxy.play(&s).await;
    assert_eq!(h.proxy.snapshot(), s.final_world());
}

// Claim: the Udp slot of the seam reports Unsupported, never a silent TCP fallback.
#[tokio::test]
async fn harness_udp_carrier_is_unsupported() {
    let err = UdpCarrier.bind().await.err().expect("bind must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

// Claim: every probe in the capability table can be evaluated against the
// shipped binaries today. A probe that errors would make a scenario red for
// the wrong reason. Outcomes are not asserted: they flip as capabilities land.
#[tokio::test(flavor = "multi_thread")]
async fn harness_every_probe_evaluates() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    for (cap, res) in h.probe_all().await {
        eprintln!("probe {:<16} -> {res:?}", cap.name());
        assert!(res.is_ok(), "{}: {res:?}", cap.name());
    }
}

// Claim: each probe kind can say "present". Without a positive control, a
// probe that always reports absent would make every scenario red for the
// wrong reason. Each control probes something that exists today.
#[tokio::test(flavor = "multi_thread")]
async fn harness_each_probe_kind_can_report_present() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let cap = Capability::Transport; // the name is used only in error text
    let controls = [
        ("Cli", Probe::Cli(&["init", "--help"], Some("--"))),
        ("Server", Probe::Server(&["serve", "--help"])),
        ("Route", Probe::Route("/server")),
        ("Banner", Probe::Banner("listening on ")),
        ("WorkspacePath", Probe::WorkspacePath(&["Cargo.toml"])),
    ];
    for (kind, probe) in controls {
        assert!(
            probe.eval(&h, cap).await.expect("probe runs"),
            "{kind} control reported absent"
        );
    }
    assert!(
        !Probe::Pending("none")
            .eval(&h, cap)
            .await
            .expect("probe runs")
    );
}

// Claim: a partition cuts a connection that is already open, not only new
// ones. S2 and S3 partition peers mid-conversation, so a held connection that
// kept flowing would hide the partition from the client.
#[tokio::test(flavor = "multi_thread")]
async fn harness_partition_cuts_an_open_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const REQ: &[u8] = b"GET /server HTTP/1.1\r\nHost: p1\r\nConnection: keep-alive\r\n\r\n";
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let via = h.route("bob", "p1").await;
    let mut conn = tokio::net::TcpStream::connect(via).await.expect("connect");
    let mut buf = vec![0u8; 8192];

    conn.write_all(REQ).await.expect("first request");
    let n = conn.read(&mut buf).await.expect("first response");
    assert!(
        buf[..n].starts_with(b"HTTP/1.1 200"),
        "healthy connection must answer"
    );

    h.proxy.partition("bob", "p1");
    let _ = conn.write_all(REQ).await; // may fail outright once cut
    let cut = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf)).await;
    assert!(
        matches!(cut, Ok(Ok(0) | Err(_))),
        "an open connection must be cut by a partition, got {cut:?}"
    );
}

// Claim: an action that is not implemented ends the scenario as RED for the
// capability it names, even when that capability's probe reads present. A
// scenario can therefore neither pass nor fail as a behaviour failure by
// running an empty step.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "RED(cli-network) after-setup peers=1 ids=")]
async fn harness_unsupported_action_ends_red() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    h.ok(h.client("alice").create_principal().await);
}

// Claim: the observer parses a peer's `GET /tip` envelope and reports `None`
// for a principal the peer does not hold. (The server's own principal cannot
// serve as a live positive control: its `/tip` currently answers 500, so the
// parse is pinned against the documented response shape instead.)
#[tokio::test(flavor = "multi_thread")]
async fn harness_peer_view_reads_the_peer_itself() {
    use cyphr_scenarios::actions::{PeerTip, Principal, Tip};

    let h = Harness::start(&["p1"]).await.expect("start peer");
    assert_eq!(
        h.peer_view("p1", &Principal("SHA-512:AAAA".into())).await,
        None
    );

    let envelope = serde_json::json!({"v": 1, "payload": {
        "principal_id": "x", "pr": "PR", "sr": "SR", "ar": "AR", "cr": "CR",
        "commit_id": "C2", "commit_count": 2, "last_updated": 5, "now": 9}});
    assert_eq!(
        PeerTip::parse(&envelope),
        Some(PeerTip {
            principal_id: "x".into(),
            tip: Tip("C2".into()),
            height: 2,
            pr: "PR".into(),
            ar: "AR".into()
        })
    );
}

// Claim: a principal handle compares in one spelling. Peers report a bare
// digest while handles may carry an algorithm tag, and a mismatch there
// would make every "the peer holds Alice's principal" assertion fail or,
// worse, pass on the wrong string.
// (Pure logic: no scenario reaches the spelling cases cheaply.)
#[test]
fn harness_principal_handles_compare_by_bare_digest() {
    use cyphr_scenarios::actions::Principal;

    let tagged = Principal("SHA-512:abcDEF_-123".into());
    assert_eq!(tagged.bare(), "abcDEF_-123");
    assert!(tagged.same_as("abcDEF_-123"));
    assert!(tagged.same_as("SHA-512:abcDEF_-123"));
    assert!(!tagged.same_as("abcDEF_-124"));
}

// Claim: a partition cuts a peer-to-peer link, not only client traffic. A
// witness pulls from its authority over a proxy route; with the link
// partitioned its pull attempt is counted as blocked and nothing is
// forwarded, and healed it is forwarded. S02 and S03 use the same counters
// to prove their partition was exercised by real traffic.
#[tokio::test(flavor = "multi_thread")]
async fn harness_partition_cuts_a_peer_to_peer_link() {
    use cyphr_scenarios::actions::Principal;

    let h = Harness::start(&["p1"]).await.expect("start authority");
    h.start_witness("w1", "p1").await.expect("start witness");
    let asked = Principal("SHA-512:AAAA".into()); // any pr makes the witness pull

    h.proxy.partition("w1", "p1");
    let before = h.proxy.stats("w1", "p1");
    h.peer_view("w1", &asked).await;
    let cut = h.proxy.stats("w1", "p1");
    assert_eq!(
        cut.forwarded, before.forwarded,
        "a partitioned pull must not be forwarded"
    );
    assert!(
        cut.blocked > before.blocked,
        "the pull must reach the proxy and be blocked"
    );

    h.proxy.heal("w1", "p1");
    h.peer_view("w1", &asked).await;
    assert!(
        h.proxy.stats("w1", "p1").forwarded > cut.forwarded,
        "a healed pull is forwarded"
    );
}
