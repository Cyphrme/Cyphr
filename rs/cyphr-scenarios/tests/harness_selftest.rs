//! Claims about the harness itself. Each backs a promise the scenarios
//! rely on: if one fails, a red scenario could be red for the wrong reason.

use std::time::{Duration, Instant};

use cyphr_scenarios::Harness;
use cyphr_scenarios::capability::{Capability, Probe};
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

// Claim: the observer reads what a peer itself holds. Positive control: a
// principal pushed to two peers over HTTP is reported by each with the same
// tip, and by neither under a principal it never saw.
#[tokio::test(flavor = "multi_thread")]
async fn harness_peer_view_reads_the_peer_itself() {
    use cyphr_scenarios::actions::{PeerTip, Principal, Tip};

    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    let pr = h
        .seed_principal(&["p1", "p2"])
        .await
        .expect("seed a principal");
    let (v1, v2) = (h.peer_view("p1", &pr).await, h.peer_view("p2", &pr).await);
    assert!(v1.is_some(), "p1 must report the seeded principal");
    assert_eq!(v1, v2, "both peers took the same commit");
    assert_eq!(
        h.peer_view("p1", &Principal("SHA-512:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into())).await,
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
    assert!(
        !tagged.same_as("SHA-256:abcDEF_-123"),
        "the same text under another algorithm is another digest"
    );
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
    let asked = Principal("SHA-512:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()); // any pr makes the witness pull

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

fn oracle_verdict(
    tip: &str,
    standing: cyphr_scenarios::actions::Standing,
) -> cyphr_scenarios::actions::Verdict {
    use cyphr_scenarios::actions::*;

    Verdict {
        standing,
        freshness: Freshness {
            age: Duration::ZERO,
            peer_reported_newer: false,
        },
        tip: Tip(tip.into()),
        anchor: Anchor {
            source: AnchorSource::TrustedGenesis,
            id: "AAAA".into(),
        },
        peers: vec!["p1".into()],
        branches: vec![Tip(tip.into())],
        evidence: vec![],
        resolved_by: None,
    }
}

// Claim: the oracle rejects a verdict that names the wrong peers.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "verdict peers differ from the chosen set")]
async fn harness_oracle_rejects_the_wrong_peer_set() {
    use cyphr_scenarios::actions::{Principal, Standing};
    use cyphr_scenarios::oracle::Expect;

    let h = Harness::start(&["p1", "p2"]).await.expect("start peers");
    let v = oracle_verdict("T", Standing::Active);
    h.check_verdict(&v, &Principal("AAAA".into()), &Expect::new(&["p2"], "AAAA"))
        .await;
}

// Claim: a chosen peer that does not answer is never skipped silently: the
// oracle fails unless the scenario declares that peer down.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "peer `p1` did not report a tip for the principal")]
async fn harness_oracle_requires_every_live_peer_to_answer() {
    use cyphr_scenarios::actions::{Principal, Standing};
    use cyphr_scenarios::oracle::Expect;

    let h = Harness::start(&["p1"]).await.expect("start peer");
    let v = oracle_verdict("T", Standing::Active);
    h.check_verdict(&v, &Principal("AAAA".into()), &Expect::new(&["p1"], "AAAA"))
        .await;
}

// Claim: the verdict's branches must equal the peers' observed head, not
// merely contain it. A peer holds exactly one head for the seeded principal.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "verdict branches differ from the peers' observed head")]
async fn harness_oracle_rejects_branches_that_are_not_the_peers_head() {
    use cyphr_scenarios::actions::{Standing, Tip};
    use cyphr_scenarios::oracle::Expect;

    let h = Harness::start(&["p1"]).await.expect("start peer");
    let pr = h.seed_principal(&["p1"]).await.expect("seed a principal");
    let head = h.peer_view("p1", &pr).await.expect("seeded").tip;
    let mut v = oracle_verdict(&head.0, Standing::Active);
    v.anchor.id = pr.0.clone();
    v.branches.push(Tip("EXTRA".into()));
    h.check_verdict(&v, &pr, &Expect::new(&["p1"], &pr.0)).await;
}

// Claim: with the evidence route present, a verdict that agrees with the
// peers on everything they can answer passes, and "no evidence" is confirmed
// from the route's own 2xx answer, not assumed. (End to end: a real peer.)
#[tokio::test(flavor = "multi_thread")]
async fn harness_oracle_confirms_no_evidence_from_the_real_route() {
    use cyphr_scenarios::actions::Standing;
    use cyphr_scenarios::oracle::Expect;

    let h = Harness::start(&["p1"]).await.expect("start peer");
    let pr = h.seed_principal(&["p1"]).await.expect("seed a principal");
    let view = h.peer_view("p1", &pr).await.expect("seeded");
    let age = h.peer_age("p1", &pr).await.expect("age");
    let mut v = oracle_verdict(&view.tip.0, Standing::Active);
    v.anchor.id = pr.0.clone();
    v.freshness.age = Duration::from_secs(age.max(0) as u64);
    h.check_verdict(&v, &pr, &Expect::new(&["p1"], &pr.0)).await;
}

// Claim: an evidence response is only "no evidence" when it is a 2xx with the
// expected shape. A 500, a malformed body or a missing items array fails.
// (Pure logic: the evidence route does not exist yet, so no peer can serve
// these cases.)
#[test]
fn harness_evidence_reads_must_be_2xx_with_items() {
    use cyphr_scenarios::signed::evidence_items;

    assert_eq!(
        evidence_items(200, br#"{"payload":{"items":[]}}"#),
        Ok(vec![])
    );
    assert_eq!(
        evidence_items(200, br#"{"payload":{"items":[{"k":1}]}}"#).map(|v| v.len()),
        Ok(1)
    );
    assert!(evidence_items(500, br#"{"payload":{"items":[]}}"#).is_err());
    assert!(evidence_items(404, b"{}").is_err());
    assert!(evidence_items(200, b"not json").is_err());
    assert!(evidence_items(200, br#"{"payload":{}}"#).is_err());
}

fn keyed() -> (String, String, String, Vec<u8>) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    (
        kp.alg.name().to_owned(),
        Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        Base64UrlUnpadded::encode_string(tmb.as_bytes()),
        kp.prv_bytes.clone(),
    )
}

fn signed_coz(alg: &str, pub_b64: &str, prv: &[u8], pay: serde_json::Value) -> serde_json::Value {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64).expect("pub");
    let json = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(&json, alg, prv, &pub_bytes).expect("sign");
    serde_json::json!({"pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig)})
}

// Claim: statement and evidence verification is offline and discriminating.
// A correctly signed statement passes; a tampered payload, a different
// signer and a wrong expected tmb each fail. (Pure crypto: no scenario
// reaches a forged object cheaply.)
#[test]
fn harness_statement_verification_catches_forgery() {
    use cyphr_scenarios::signed::verify_statement;

    let (alg, pub_b64, tmb, prv) = keyed();
    let good = signed_coz(
        &alg,
        &pub_b64,
        &prv,
        serde_json::json!({"alg": alg, "tmb": tmb, "now": 1}),
    );
    let bytes = serde_json::to_vec(&good).unwrap();
    assert_eq!(verify_statement(&bytes, &alg, &pub_b64, &tmb), Ok(()));

    let mut tampered = good.clone();
    tampered["pay"]["now"] = 2.into();
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert!(
        verify_statement(&tampered, &alg, &pub_b64, &tmb).is_err(),
        "tampered payload"
    );

    let (_, other_pub, other_tmb, _) = keyed();
    assert!(
        verify_statement(&bytes, &alg, &other_pub, &tmb).is_err(),
        "another key"
    );
    assert!(
        verify_statement(&bytes, &alg, &pub_b64, &other_tmb).is_err(),
        "another tmb"
    );
}

// Claim: the resolution signer is chosen by `typ`, not position, and its
// signature must verify against the chain's keys.
#[test]
fn harness_commit_signer_is_chosen_by_typ_and_verified() {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr_scenarios::signed::commit_signer_from_patch;

    let (alg, pub_b64, tmb, prv) = keyed();
    let key = serde_json::json!({"alg": alg, "pub": pub_b64, "tmb": tmb});
    let blob =
        |c: &serde_json::Value| Base64UrlUnpadded::encode_string(&serde_json::to_vec(c).unwrap());
    let mut commit = signed_coz(
        &alg,
        &pub_b64,
        &prv,
        serde_json::json!({"alg": alg, "tmb": tmb, "typ": "x/cyphr/commit/create"}),
    );
    commit["key"] = key.clone();
    // A later, non-commit coz must not be mistaken for the commit.
    let action = signed_coz(
        &alg,
        &pub_b64,
        &prv,
        serde_json::json!({"alg": alg, "tmb": "OTHER", "typ": "x/action"}),
    );
    let patch =
        |blobs: Vec<String>| serde_json::json!({"payload": {"entries": [{"blobs": blobs}]}});

    assert_eq!(
        commit_signer_from_patch(&patch(vec![blob(&commit), blob(&action)])),
        Ok(tmb.clone())
    );
    let mut forged = commit.clone();
    forged["pay"]["now"] = 9.into();
    assert!(
        commit_signer_from_patch(&patch(vec![blob(&forged)])).is_err(),
        "mis-signed commit"
    );
    assert!(
        commit_signer_from_patch(&patch(vec![blob(&action)])).is_err(),
        "no commit/create"
    );
}

// Claim: a served evidence item is believed only when it verifies offline.
// A fork needs two distinct commits closing in a commit/create, signed by
// keys the principal's chain introduced (never the serving peer's own key),
// at a height on the chain whose pre is the chain's root before it, naming
// the requested principal. Peer equivocation needs two statements signed by
// the accused peer that conflict; a lower statement on the same chain as the
// higher is a stale prefix and no evidence. (Pure crypto and logic: no
// scenario reaches a forged item cheaply.)
#[test]
fn harness_evidence_items_are_verified_offline() {
    use std::collections::BTreeMap;

    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr_scenarios::signed::{ChainView, Keys, Proven, verify_evidence};
    use serde_json::{Value, json};

    let (alg, pub_b64, tmb, prv) = keyed();
    let (_, peer_pub, peer_tmb, peer_prv) = keyed();
    let mut keys = Keys::new();
    keys.insert(tmb.clone(), (alg.clone(), pub_b64.clone()));
    keys.insert(peer_tmb.clone(), (alg.clone(), peer_pub.clone()));
    let peers = BTreeMap::from([("PEER".to_owned(), peer_tmb.clone())]);
    let chain = ChainView {
        prs: vec!["PR0".into(), "PR1".into(), "PR2".into()],
        commit_ids: vec!["C0".into(), "C1".into(), "C2".into()],
    };

    let blob = |c: &Value| {
        json!(Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(c).expect("coz")
        ))
    };
    let commit = |typ: &str, signer: (&str, &str, &[u8]), n: u64| {
        let c = signed_coz(
            &alg,
            signer.1,
            signer.2,
            json!({"alg": alg, "tmb": signer.0, "typ": typ, "n": n}),
        );
        json!({"blobs": [blob(&c)]})
    };
    let own = (tmb.as_str(), pub_b64.as_str(), prv.as_slice());
    let fork = |a: Value, b: Value, height: u64, pre: Value, pg: &str| json!({"kind": "principal-fork", "pg": pg, "height": height, "pre": pre, "a": a, "b": b});
    let create = "cyphr.me/cyphr/commit/create";
    let ok = |item: &Value| verify_evidence(item, "PG", &keys, &peers, &chain);

    let (a, b) = (commit(create, own, 1), commit(create, own, 2));
    assert_eq!(
        ok(&fork(a.clone(), b.clone(), 2, json!("PR1"), "PG")),
        Ok(Proven::PrincipalFork { pg: "PG".into() })
    );
    assert_eq!(
        ok(&fork(a.clone(), b.clone(), 0, Value::Null, "PG")),
        Ok(Proven::PrincipalFork { pg: "PG".into() }),
        "a fork at the first position has no ancestor"
    );
    assert!(
        ok(&fork(a.clone(), a.clone(), 2, json!("PR1"), "PG")).is_err(),
        "identical commits"
    );
    assert!(
        ok(&fork(a.clone(), b.clone(), 2, json!("PR1"), "OTHER")).is_err(),
        "another principal"
    );
    assert!(
        ok(&fork(a.clone(), b.clone(), 2, json!("PR0"), "PG")).is_err(),
        "wrong ancestor"
    );
    assert!(
        ok(&fork(a.clone(), b.clone(), 9, json!("PR1"), "PG")).is_err(),
        "height off the chain"
    );
    let wrong_typ = commit("cyphr.me/cyphr/key/create", own, 3);
    assert!(
        ok(&fork(a.clone(), wrong_typ, 2, json!("PR1"), "PG")).is_err(),
        "no commit/create"
    );
    let by_peer = commit(create, (&peer_tmb, &peer_pub, &peer_prv), 4);
    assert!(
        ok(&fork(a.clone(), by_peer, 2, json!("PR1"), "PG")).is_err(),
        "the serving peer's key cannot vouch for a fork"
    );
    let mut forged = b.clone();
    let mut raw: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(forged["blobs"][0].as_str().expect("blob")).expect("b64"),
    )
    .expect("json");
    raw["pay"]["n"] = 7.into();
    forged["blobs"][0] = blob(&raw);
    assert!(
        ok(&fork(a, forged, 2, json!("PR1"), "PG")).is_err(),
        "mis-signed commit"
    );

    let view = |size: u64, id: &str, signer: (&str, &str, &[u8])| {
        signed_coz(
            &alg,
            signer.1,
            signer.2,
            json!({"alg": alg, "tmb": signer.0, "typ": "cyphr-server/view", "tree_size": size,
                   "commit_id": id, "roots": {"pr": id}}),
        )
    };
    let peer = (peer_tmb.as_str(), peer_pub.as_str(), peer_prv.as_slice());
    let equiv = |a: Value, b: Value| json!({"kind": "peer-equivocation", "pg": "PG", "peer": "PEER", "a": a, "b": b});
    let proven = Ok(Proven::PeerEquivocation {
        pg: "PG".into(),
        peer: "PEER".into(),
    });
    assert_eq!(
        ok(&equiv(view(2, "C1", peer), view(2, "X1", peer))),
        proven,
        "one size, two ids"
    );
    assert_eq!(
        ok(&equiv(view(1, "X0", peer), view(3, "C2", peer))),
        proven,
        "lower is off the chain"
    );
    assert!(
        ok(&equiv(view(2, "C1", peer), view(2, "C1", peer))).is_err(),
        "agreeing statements"
    );
    assert!(
        ok(&equiv(view(1, "C0", peer), view(3, "C2", peer))).is_err(),
        "a stale prefix"
    );
    assert!(
        ok(&equiv(view(1, "X0", peer), view(3, "X2", peer))).is_err(),
        "higher is not on the chain read"
    );
    assert!(
        ok(&equiv(view(2, "C1", own), view(2, "X1", peer))).is_err(),
        "not the accused peer"
    );
    let mut other = equiv(view(2, "C1", peer), view(2, "X1", peer));
    other["peer"] = "NOBODY".into();
    assert!(ok(&other).is_err(), "unknown peer");
}
