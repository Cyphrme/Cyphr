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
    (*h.proxy).drop(&link, 1.0);
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
    // The cut is event-driven, so the read ends the moment the proxy acts;
    // the bound only ends a test whose cut never comes, and is long enough
    // that a starved machine cannot trip it first.
    let cut = tokio::time::timeout(Duration::from_secs(20), conn.read(&mut buf)).await;
    assert!(
        matches!(cut, Ok(Ok(0) | Err(_))),
        "an open connection must be cut by a partition, got {cut:?}"
    );
}

// Claim: the observer reads what a peer itself holds. Positive control: a
// principal pushed to two peers over HTTP is reported by each with the same
// tip, and by neither under a principal it never saw.
#[tokio::test(flavor = "multi_thread")]
async fn harness_peer_view_reads_the_peer_itself() {
    use cyphr_scenarios::actions::{PeerTip, Principal, Standing, Tip};

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
            heads: vec![Tip("C2".into())],
            standing: Standing::Active,
            height: 2,
            pr: "PR".into(),
            ar: "AR".into()
        })
    );

    // An Error answer names no single tip: every tied head is a head, and
    // there is no root to read.
    let error = serde_json::json!({"v": 1, "payload": {
        "state": "error", "principal_id": "x", "now": 9,
        "fork_point": {"height": 1, "pre": "PRE"},
        "heads": [
            {"commit_id": "C3", "sequence": 2, "held_since": 5},
            {"commit_id": "D3", "sequence": 2, "held_since": 6}]}});
    assert_eq!(
        PeerTip::parse(&error),
        Some(PeerTip {
            principal_id: "x".into(),
            tip: Tip("C3".into()),
            heads: vec![Tip("C3".into()), Tip("D3".into())],
            standing: Standing::Error,
            height: 3,
            pr: String::new(),
            ar: String::new()
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
        observed_at: std::time::Instant::now(),
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
        abandoned: vec![],
        evidence: vec![],
        resolved_by: None,
        unreachable: vec![],
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

// Claim: a served peer-equivocation item is believed only when it verifies
// offline: two statements signed by the accused peer that conflict; a lower
// statement on the same chain as the higher is a stale prefix and no
// evidence. A fork item is never believed without a replayable chain: it is
// checked by the client's own verifier, so an empty chain or another
// principal's item is refused (the accepted-fork path is the end-to-end test
// below). Pure crypto and logic: no scenario reaches a forged statement
// cheaply.
#[tokio::test]
async fn harness_evidence_items_are_verified_offline() {
    use std::collections::BTreeMap;

    use cyphr_scenarios::signed::{ChainView, Keys, Proven, verify_evidence};
    use serde_json::{Value, json};

    let (alg, _, tmb, _) = keyed();
    let (_, peer_pub, peer_tmb, peer_prv) = keyed();
    let mut keys = Keys::new();
    keys.insert(peer_tmb.clone(), (alg.clone(), peer_pub.clone()));
    let peers = BTreeMap::from([("PEER".to_owned(), peer_tmb.clone())]);
    let chain = ChainView {
        commit_ids: vec!["C0".into(), "C1".into(), "C2".into()],
        ..ChainView::default()
    };
    let ok = async |item: &Value| verify_evidence(item, "PG", &keys, &peers, &chain).await;

    let fork = json!({"kind": "principal-fork", "pg": "PG", "height": 0, "pre": null,
                      "a": {"txs": [["AA"]]}, "b": {"txs": [["BB"]]}});
    assert!(ok(&fork).await.is_err(), "no chain to replay a fork from");
    let mut other = fork.clone();
    other["pg"] = "OTHER".into();
    assert!(ok(&other).await.is_err(), "another principal's item");

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
        ok(&equiv(view(2, "C1", peer), view(2, "X1", peer))).await,
        proven,
        "one size, two ids"
    );
    assert_eq!(
        ok(&equiv(view(1, "X0", peer), view(3, "C2", peer))).await,
        proven,
        "lower is off the chain"
    );
    assert!(
        ok(&equiv(view(2, "C1", peer), view(2, "C1", peer)))
            .await
            .is_err(),
        "agreeing statements"
    );
    assert!(
        ok(&equiv(view(1, "C0", peer), view(3, "C2", peer)))
            .await
            .is_err(),
        "a stale prefix"
    );
    assert!(
        ok(&equiv(view(1, "X0", peer), view(3, "X2", peer)))
            .await
            .is_err(),
        "higher is not on the chain read"
    );
    let stranger = (tmb.as_str(), peer_pub.as_str(), peer_prv.as_slice());
    assert!(
        ok(&equiv(view(2, "C1", stranger), view(2, "X1", peer)))
            .await
            .is_err(),
        "not the accused peer"
    );
    let mut unknown = equiv(view(2, "C1", peer), view(2, "X1", peer));
    unknown["peer"] = "NOBODY".into();
    assert!(ok(&unknown).await.is_err(), "unknown peer");
}

/// A signing key outside any pool.
struct Signer {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn signer() -> Signer {
    let g = coz::Alg::Ed25519.generate_keypair();
    Signer {
        alg: g.alg.name().to_owned(),
        prv: g.prv_bytes.clone(),
        pubb: g.pub_bytes.clone(),
        tmb: g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb"),
    }
}

fn key_of(k: &Signer) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// `by` creates `new` at `now` and finalizes the commit.
async fn create_key(p: &mut cyphr::Principal, by: &Signer, new: &Signer, now: i64) {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": by.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": by.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&by.alg, &by.prv, &by.pubb, &by.tmb),
            now,
            "cyphr.me",
        )
        .await
        .expect("finalize");
}

/// The `POST /push` body of commit `i` of `p` in the wire form (SPEC
/// 4.6.2): the keys its `key/create`s name travel in `keys` (in the genesis
/// commit, the genesis key's own).
fn push_body(p: &cyphr::Principal, i: usize, id: &str) -> serde_json::Value {
    let commit = p.commits().nth(i).expect("commit");
    let mut body =
        serde_json::to_value(cyphr::replay::WireBundle::of_commit(commit).expect("bundle"))
            .expect("bundle json");
    body["principal_id"] = id.into();
    body
}

// Claim: the oracle verifies a real fork end to end. A principal's key signs
// two different commits at one position; the peer takes the first, refuses
// the second as the tip (409) and keeps it; the oracle reads the peer's
// chain, replays it, fetches `/evidence`, and verifies the served fork with
// the client's own verifier. A verdict that names that fork as evidence
// passes. Turns red if the served item does not verify against the replayed
// chain or the oracle does not see it.
#[tokio::test(flavor = "multi_thread")]
async fn harness_oracle_verifies_a_served_fork_end_to_end() {
    use cyphr_scenarios::actions::{Evidence, Principal, Standing};
    use cyphr_scenarios::oracle::Expect;

    let h = Harness::start(&["p1"]).await.expect("start peer");
    let (g, k1, k2, k3) = (signer(), signer(), signer(), signer());
    let mut base = cyphr::Principal::implicit(key_of(&g))
        .await
        .expect("genesis");
    // A single-key genesis: the PG is the genesis key's thumbprint.
    let id = g.tmb.to_b64();
    base.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb),
        &[],
        1_700_099_999,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    create_key(&mut base, &g, &k1, 1_700_100_000).await;
    let (mut first, mut rival) = (
        base.fork().await.expect("fork"),
        base.fork().await.expect("fork"),
    );
    create_key(&mut first, &g, &k2, 1_700_100_001).await;
    create_key(&mut rival, &g, &k3, 1_700_100_002).await;

    let addr = h.peer("p1").addr();
    let push = |p: &cyphr::Principal, i: usize| {
        let body = push_body(p, i, &id);
        let http = h.http.clone();
        async move {
            http.post(format!("http://{addr}/push"))
                .json(&body)
                .send()
                .await
                .expect("push")
                .status()
        }
    };
    assert!(push(&base, 0).await.is_success(), "the genesis commit");
    assert!(push(&base, 1).await.is_success());
    assert!(push(&first, 2).await.is_success());
    assert_eq!(
        push(&rival, 2).await,
        reqwest::StatusCode::CONFLICT,
        "the second commit at the position is refused as the tip"
    );

    let pr = Principal(id);
    let view = h.peer_view("p1", &pr).await.expect("held");
    assert_eq!(view.heads.len(), 2, "the tied heads, not one tip");
    let mut v = oracle_verdict(&view.tip.0, Standing::Error);
    v.branches = view.heads.clone();
    v.anchor.id = pr.0.clone();
    v.evidence = vec![Evidence::PrincipalFork(pr.clone())];
    h.check_verdict(&v, &pr, &Expect::new(&["p1"], &pr.0)).await;
}

// Claim: a peer whose port is taken while it is down still restarts: it comes
// back on a fresh port, and a route opened before the restart follows it.
// Red if a restart insists on the old port (EarlyExit) or leaves routes
// pointing at it.
#[tokio::test(flavor = "multi_thread")]
async fn harness_restart_survives_a_lost_port() {
    let h = Harness::start(&["p1"]).await.expect("start peer");
    let via = h.route("bob", "p1").await;
    let old = h.peer("p1").addr();
    h.peer("p1").stop().await.expect("stop");
    // The thief: a listener that holds the old port for the whole test.
    let thief = std::net::TcpListener::bind(old).expect("take the freed port");
    h.peer("p1").restart(h.bins).await.expect("restart");
    assert_ne!(
        h.peer("p1").addr(),
        old,
        "the port was held; the peer moved"
    );
    assert!(
        get_server(&h, via).await.is_ok(),
        "a route opened before the restart must follow the peer"
    );
    drop(thief);
}

// Claim: a failing scenario keeps each peer's server log, copied out of the
// peer's temp dir (deleted on drop) to a path under $TMPDIR named in the
// failure output, so a one-in-fifty failure can be diagnosed after the fact.
#[test]
fn harness_failing_scenario_keeps_peer_logs() {
    let (tx, rx) = std::sync::mpsc::channel();
    let run = std::thread::Builder::new()
        .name("keeps-logs".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async {
                let h = Harness::start(&["p1"]).await.expect("start peer");
                tx.send(h.seed).expect("send seed");
                // A request, so the server has logged something to keep.
                assert!(get_server(&h, h.peer("p1").addr()).await.is_ok());
                panic!("scenario failed on purpose");
            });
        })
        .expect("spawn")
        .join();
    assert!(run.is_err(), "the scenario must have failed");
    let seed = rx.recv().expect("the scenario reported its seed");
    // The directory is private and randomly named; find it by its prefix.
    let prefix = format!("cyphr-scenario-logs-keeps-logs-seed-{seed}-");
    let dir = std::fs::read_dir(std::env::temp_dir())
        .expect("read temp dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
        })
        .expect("a kept log directory");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir)
            .expect("dir metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "kept logs must be owner-only");
    }
    let kept = dir.join("p1.server.log");
    let text = std::fs::read_to_string(&kept)
        .unwrap_or_else(|e| panic!("no kept log at {}: {e}", kept.display()));
    assert!(!text.is_empty(), "the kept log is empty");
    let _ = std::fs::remove_dir_all(&dir);
}
