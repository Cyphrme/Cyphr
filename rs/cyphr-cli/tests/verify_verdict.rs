//! The verify verdict: what the pull step decided and why, persisted and
//! printed (anchor, peers and when they answered, freshness, evidence).
//! `watch` is `verify` on a timer.

mod common;

use common::{Server, User, accepted};
use serde_json::Value;

/// Claim: the verdict names its anchor, each peer and whether and when it
/// answered (the verifier's own clock), the principal's last-signed `now`,
/// and freshness as two ages the verifier computes itself; a peer that is
/// behind or down never moves the record to a lower tip. Defect that turns
/// it red: a missing field, a peer-reported age, or a lower peer tip that
/// regresses the tip. End-to-end: yes (a lagging server and a dead port).
#[test]
fn verdict_names_peers_ages_and_never_regresses_to_a_lagging_peer() {
    let (lagging, ahead) = (Server::start(), Server::start());
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &lagging.url), "push to the lagging peer");
    a.add_key(&id);
    accepted(&a.push(&id, &ahead.url), "push the newer tip to the other");
    let tip = a.setup(&["inspect", &format!("--identity={id}")])["commit_count"].clone();

    let dead = "http://127.0.0.1:1".to_owned();
    let args = [
        "verify".to_owned(),
        format!("--identity={id}"),
        format!("--peer={}", lagging.url),
        format!("--peer={dead}"),
    ];
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let v = a.setup(&args);
    assert_eq!(v["verdict"], "Active", "{v}");
    let peers = v["peers"]
        .as_array()
        .unwrap_or_else(|| panic!("no peers: {v}"));
    let by = |url: &str| {
        peers
            .iter()
            .find(|p| p["peer"] == url)
            .unwrap_or_else(|| panic!("peer {url} not listed: {v}"))
    };
    assert_eq!(by(&lagging.url)["standing"], "behind", "{v}");
    assert!(
        by(&lagging.url)["answered_at"].is_i64(),
        "when it answered: {v}"
    );
    assert_eq!(by(&dead)["standing"], "failed", "{v}");
    assert!(
        by(&dead)["answered_at"].is_null(),
        "a dead peer never answered: {v}"
    );
    assert!(v["principal_now"].is_i64(), "the principal's last now: {v}");
    assert!(
        v["freshness"]["pull_age_secs"].is_u64()
            && v["freshness"]["principal_now_age_secs"].is_u64(),
        "freshness is two ages the verifier computes: {v}"
    );
    assert_eq!(
        a.setup(&["inspect", &format!("--identity={id}")])["commit_count"],
        tip,
        "a peer that is behind must not move the record"
    );
    // A second run with only the lagging peer still reports the same tip.
    let again = a.setup(&[
        "verify",
        &format!("--identity={id}"),
        &format!("--peer={}", lagging.url),
    ]);
    assert_eq!(
        again["tip"], v["tip"],
        "the record never regresses: {again}"
    );
}

/// Claim: `watch` is `verify` on a timer: each round prints the verdict
/// `verify` prints for the same inputs. Defect that turns it red: a watch
/// that computes its own verdict (different tip or standing from verify).
/// End-to-end: yes.
#[test]
fn watch_prints_the_verify_verdict_each_round() {
    let s = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &s.url), "push");
    let peer = format!("--peer={}", s.url);
    let verified = a.setup(&["verify", &format!("--identity={id}"), &peer]);

    let r = a.run(&[
        "watch",
        &format!("--identity={id}"),
        &peer,
        "--interval-secs=1",
        "--rounds=2",
    ]);
    assert!(r.ok, "watch: {}", r.stderr);
    let rounds: Vec<Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l}")))
        .collect();
    assert_eq!(rounds.len(), 2, "two rounds: {}", r.stdout);
    for round in &rounds {
        assert_eq!(round["tip"], verified["tip"]);
        assert_eq!(round["verdict"], verified["verdict"]);
    }
}

/// Claim (SPEC 4.5, GOSSIP-MIN anchor rule): the anchor is the genesis key
/// or the genesis commit id, never the PG alone, because one key set
/// under different openers derives one PG; a PG-only anchor is refused with
/// a message naming the rule. Defect that turns it red: a PG anchor
/// accepted. End-to-end: yes.
#[test]
fn anchor_that_is_only_the_pg_is_refused() {
    let s = Server::start();
    let a = User::new();
    // A two-key principal: its PG names the key set, which no single key's
    // thumbprint equals (a one-key PG is that key's thumbprint).
    let tmb = |algo: &str| {
        a.setup(&["key", "generate", "--algo", algo])["tmb"]
            .as_str()
            .expect("tmb")
            .to_owned()
    };
    let (key, second) = (tmb("ES256"), tmb("Ed25519"));
    let init = a.setup(&[
        "init",
        &format!("--keys={key},{second}"),
        "--genesis-commit",
    ]);
    let pg = init["pr"].as_str().expect("pr").to_owned();
    accepted(&a.push(&pg, &s.url), "push");
    let ident = format!("--identity={pg}");
    let peer = format!("--peer={}", s.url);

    let r = a.run(&["verify", &ident, &peer, &format!("--anchor={pg}")]);
    assert!(!r.ok, "a PG-only anchor is refused: {}", r.stdout);
    assert!(
        r.stderr.contains("genesis key or the genesis commit id"),
        "the message names the rule: {}",
        r.stderr
    );
    let ok = a.setup(&["verify", &ident, &peer, &format!("--anchor={key}")]);
    assert_eq!(ok["anchor"]["source"], "pinned", "{ok}");
}

/// Claim (SPEC 15.8; arch-principal-resolves): once the principal signs a
/// commit on one branch, a verifier's verdict follows that branch, names the
/// key that signed the resolution, and keeps the abandoned branch as proof of
/// error; the fork persists across runs until then. Defect that turns it
/// red: a verdict that stays Error after the resolution, picks a branch
/// before it, names no key, or forgets the abandoned branch. End-to-end: yes
/// (two servers, two devices, three verify runs).
// @docket: arch-principal-resolves :: scripts/docket-run arch-principal-resolves
#[test]
fn verdict_follows_the_branch_the_principal_resolves_to() {
    let (s1, s2) = (Server::start(), Server::start());
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity(&id);
    a.add_key(&id);
    b.add_key(&id);
    let at = a.push(&id, &s1.url);
    accepted(&at, "A's branch to peer 1");
    accepted(&b.push(&id, &s2.url), "B's competing branch to peer 2");
    let (p1, p2) = (format!("--peer={}", s1.url), format!("--peer={}", s2.url));
    let ident = format!("--identity={id}");

    let forked = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(
        forked["verdict"], "Error",
        "two branches, none resolved: {forked}"
    );
    assert!(
        forked["resolved_by"].is_null(),
        "no branch is picked for the principal"
    );
    // The fork is held from the run that found it, not recomputed from peers.
    let alone = a.setup(&["verify", &ident, &p1]);
    assert_eq!(alone["verdict"], "Error", "the fork persists: {alone}");

    // B resolves: a new commit on its branch (SPEC 15.8, act 1).
    b.add_key(&id);
    let resolved = b.push(&id, &s2.url);
    accepted(&resolved, "B's resolution to peer 2");
    let after = a.setup(&["verify", &ident, &p2]);
    assert_eq!(after["verdict"], "Active", "{after}");
    assert_eq!(
        after["tip"],
        resolved.json()["tip"],
        "follows the chosen branch: {after}"
    );
    assert_eq!(
        after["resolved_by"],
        id.as_str(),
        "names the resolving key: {after}"
    );
    let kept = after["branches"].as_array().expect("branches");
    assert!(
        kept.iter().any(|b| *b == at.json()["tip"]),
        "the abandoned branch is kept: {after}"
    );
}
