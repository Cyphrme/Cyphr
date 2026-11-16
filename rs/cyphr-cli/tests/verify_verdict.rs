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
    // The abandoned branch is retained as proof of error (SPEC 15.8) in the
    // resolved forks, and is no live head.
    let kept = after["resolved_forks"].as_array().expect("resolved_forks");
    assert!(
        kept.iter().any(|f| f["abandoned"] == at.json()["tip"]),
        "the abandoned branch is kept: {after}"
    );
    assert_eq!(
        after["branches"].as_array().map(Vec::len),
        Some(1),
        "one live head: {after}"
    );
    // The resolved fork stays reported as evidence, held by the verifier
    // rather than by what one round's peers happen to serve.
    let evidence = after["evidence"].as_array().expect("evidence");
    assert!(
        evidence
            .iter()
            .any(|e| e["kind"] == "principal_fork" && e["resolved"] == true),
        "the resolved fork is still evidence: {after}"
    );
}

/// Claim (SPEC 4.8.2, 15.8, 15.9): a fork of data commits made after a
/// rebase (whose re-signed actions put the rebased history's actions at
/// several heights) is still evidence a verifier can replay: the peer that
/// retains the rival serves an item that verifies, so a verifier asking only
/// that peer reports Error. Defect that turns it red: evidence for the
/// rival that does not verify at its `pre` (the verifier then sees no fork
/// and says Active). End-to-end: yes (two servers, two devices, a rebase).
#[test]
fn data_fork_after_a_rebase_is_evidence_the_verifier_replays() {
    let s2 = Server::start();
    // Peer 1 pulls from peer 2, so it comes to hold B's branch as a rival.
    let s1 = Server::start_gossiping(&[&s2.url]);
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &s1.url), "base to peer 1");
    accepted(&a.push(&id, &s2.url), "base to peer 2");
    let b = a.clone_identity(&id);
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    let data = |u: &User, msg: &str| {
        u.setup(&["data", "action", &ident, &signer, &format!("--msg={msg}")]);
        u.setup(&["data", "commit", &ident, &signer]);
    };

    // B commits data offline; A moves peer 1 on; B rebases onto it.
    data(&b, "offline");
    data(&a, "online");
    accepted(&a.push(&id, &s1.url), "A's data commit to peer 1");
    std::thread::sleep(std::time::Duration::from_millis(1100));
    b.setup(&["rebase", &ident, &format!("--peer={}", s1.url)]);
    accepted(&b.push(&id, &s1.url), "B's rebased history to peer 1");
    accepted(&b.push(&id, &s2.url), "B's rebased history to peer 2");
    accepted(
        &a.run(&["fetch", &ident, &format!("--peer={}", s1.url)]),
        "A catches up",
    );

    // Both sides commit data over one tip, to different peers (peer 1
    // learns B's branch by gossip).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    data(&a, "a branch");
    data(&b, "b branch");
    accepted(&a.push(&id, &s1.url), "A's branch to peer 1");
    accepted(&b.push(&id, &s2.url), "B's branch to peer 2");
    let peer = format!("--peer={}", s1.url);
    let mut v = a.setup(&["verify", &ident, &peer]);
    for _ in 0..30 {
        if v["verdict"] == "Error" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        v = a.setup(&["verify", &ident, &peer]);
    }
    assert_eq!(
        v["verdict"], "Error",
        "the retained rival's evidence verifies: {v}"
    );
}

/// Claim (SPEC 14; human recovery is a last resort): a viewer may choose,
/// locally, which branch head to trust for a principal in Error. A new
/// choice replaces the old, clearing returns to "no branch chosen", the
/// verdict stays Error throughout, and the choice (reason included) is in no
/// request a peer sees and in no stored commit. Defect that turns it red: a
/// verdict of Active, a stale or lingering choice, an unknown head accepted,
/// or the reason leaking into a request or the store. End-to-end: yes (two
/// servers, a fork, a recording peer, the export bundle and the store files).
#[test]
fn human_recovery_is_a_local_revisable_choice_that_leaves_the_verdict_error() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let (s1, s2) = (Server::start(), Server::start());
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity(&id);
    a.add_key(&id);
    b.add_key(&id);
    accepted(&a.push(&id, &s1.url), "A's branch");
    accepted(&b.push(&id, &s2.url), "B's branch");
    let ident = format!("--identity={id}");
    let (p1, p2) = (format!("--peer={}", s1.url), format!("--peer={}", s2.url));
    let forked = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(forked["verdict"], "Error", "{forked}");
    assert_eq!(forked["recovery"]["note"], "no branch chosen", "{forked}");
    let heads: Vec<String> = forked["branches"]
        .as_array()
        .expect("branches")
        .iter()
        .map(|h| h.as_str().expect("head").to_owned())
        .collect();
    assert_eq!(heads.len(), 2, "{forked}");

    // A head that is not a held branch is refused.
    assert!(!a.run(&["recover", &ident, "--head=nope"]).ok);

    const WHY: &str = "zz-recovery-reason-probe";
    let chose = a.setup(&[
        "recover",
        &ident,
        &format!("--head={}", heads[0]),
        &format!("--reason={WHY}"),
    ]);
    assert_eq!(chose["recovery"]["head"], heads[0].as_str(), "{chose}");
    let v = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(
        v["verdict"], "Error",
        "the choice never changes the verdict: {v}"
    );
    assert_eq!(
        v["recovery"]["note"],
        format!(
            "human recovery: trusting {} by local choice ({WHY})",
            heads[0]
        ),
        "{v}"
    );
    assert!(v["recovery"]["chosen_at"].is_i64(), "{v}");

    // A new choice replaces the old; no reason, no parenthetical.
    a.setup(&["recover", &ident, &format!("--head={}", heads[1])]);
    let v = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(v["verdict"], "Error", "{v}");
    assert_eq!(
        v["recovery"]["note"],
        format!("human recovery: trusting {} by local choice", heads[1]),
        "{v}"
    );

    // The reason appears in no request a peer sees: a recording peer that
    // never answers still receives what the verifier sends.
    a.setup(&[
        "recover",
        &ident,
        &format!("--head={}", heads[0]),
        &format!("--reason={WHY}"),
    ]);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind recorder");
    let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
    let recorder = format!("http://{}", listener.local_addr().expect("addr"));
    let sink = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 8192];
            if let Ok(n) = stream.read(&mut buf) {
                sink.lock().expect("sink").extend_from_slice(&buf[..n]);
            }
        }
    });
    let _ = a.run(&["verify", &ident, &format!("--peer={recorder}")]);
    let seen = String::from_utf8_lossy(&seen.lock().expect("sink")).into_owned();
    assert!(!seen.is_empty(), "the recorder saw no request");
    assert!(
        !seen.contains(WHY) && !seen.to_lowercase().contains("recover"),
        "the choice reached a peer: {seen}"
    );

    // Nor is it in the stored commits: the export bundle or the store files.
    let file = a.dir.path().join("bundle.json");
    a.setup(&[
        "gossip",
        "export",
        &ident,
        &format!("--file={}", file.display()),
    ]);
    assert!(
        !std::fs::read_to_string(&file)
            .expect("bundle")
            .contains(WHY)
    );
    fn walk(dir: &std::path::Path, hit: &mut bool) {
        for e in std::fs::read_dir(dir).expect("dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, hit);
            } else if std::fs::read(&p)
                .is_ok_and(|b| b.windows(WHY.len()).any(|w| w == WHY.as_bytes()))
            {
                *hit = true;
            }
        }
    }
    let mut hit = false;
    walk(&a.dir.path().join("data"), &mut hit);
    assert!(!hit, "the choice reached the store");

    // Clearing returns to no branch chosen.
    let cleared = a.setup(&["recover", &ident, "--clear"]);
    assert!(cleared["recovery"].is_null(), "{cleared}");
    let v = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(v["verdict"], "Error", "{v}");
    assert_eq!(v["recovery"]["note"], "no branch chosen", "{v}");

    // A fork the protocol resolved: the abandoned head can still be chosen
    // (the resolution may have been fraudulent), the consensus is the
    // protocol's Active, and the kept head is not an alternative.
    let (s3, s4) = (Server::start(), Server::start());
    let c = User::new();
    let id2 = c.new_identity();
    let d = c.clone_identity(&id2);
    c.add_key(&id2);
    d.add_key(&id2);
    let abandoned = c.push(&id2, &s3.url);
    accepted(&abandoned, "C's branch");
    let kept_fork = d.push(&id2, &s4.url);
    accepted(&kept_fork, "D's branch");
    let ident2 = format!("--identity={id2}");
    let (q3, q4) = (format!("--peer={}", s3.url), format!("--peer={}", s4.url));
    assert_eq!(c.setup(&["verify", &ident2, &q3, &q4])["verdict"], "Error");
    d.add_key(&id2);
    accepted(&d.push(&id2, &s4.url), "D resolves");
    let v = c.setup(&["verify", &ident2, &q4]);
    assert_eq!(v["verdict"], "Active", "{v}");
    assert!(v.get("recovery").is_none(), "no choice, no note: {v}");
    let lost = abandoned.json()["tip"].as_str().expect("tip").to_owned();
    // The fork's kept head is D's first tip, not the resolving commit above it.
    let won = kept_fork.json()["tip"].as_str().expect("tip").to_owned();
    assert!(
        !c.run(&["recover", &ident2, &format!("--head={won}")]).ok,
        "the kept head is the protocol's own answer, not a choice"
    );
    c.setup(&[
        "recover",
        &ident2,
        &format!("--head={lost}"),
        "--reason=stolen key",
    ]);
    let v = c.setup(&["verify", &ident2, &q4]);
    assert_eq!(v["verdict"], "Active", "the protocol verdict stands: {v}");
    assert_eq!(
        v["recovery"]["note"],
        format!("human recovery: trusting {lost} by local choice (stolen key)"),
        "{v}"
    );
}

/// Claim (NETSIM-2): a rebase whose backup name is already taken (two
/// rebases in one second name the backup by the second) keeps the existing
/// backup and writes its own, instead of failing to rename onto it. The
/// names for every second the rebase can finish in are taken beforehand, so
/// the collision does not depend on timing. Defect that turns it red: the
/// backup named by the second alone, so the rebase dies with `Directory not
/// empty`. End-to-end: yes (a server, two devices, a rebase).
#[test]
fn rebase_keeps_an_existing_backup_of_the_same_second() {
    let s1 = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &s1.url), "base to peer");
    let b = a.clone_identity(&id);
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    let data = |u: &User, msg: &str| {
        u.setup(&["data", "action", &ident, &signer, &format!("--msg={msg}")]);
        u.setup(&["data", "commit", &ident, &signer]);
    };
    data(&a, "online");
    accepted(&a.push(&id, &s1.url), "A's data commit to peer");
    data(&b, "offline");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let taken: Vec<_> = (now - 1..now + 120)
        .map(|t| b.dir.path().join(format!("data.pre-rebase-{t}")))
        .collect();
    for dir in &taken {
        std::fs::create_dir(dir).expect("taken backup");
        std::fs::write(dir.join("earlier"), b"an earlier backup").expect("earlier backup");
    }

    let r = b.run(&["rebase", &ident, &format!("--peer={}", s1.url)]);
    accepted(&r, "rebase with this second's backup name taken");
    for dir in &taken {
        assert!(dir.join("earlier").exists(), "{} was overwritten", dir.display());
    }
}
