//! Client-to-client exchange with no peer: `cyphr gossip export` writes a
//! bundle file, `cyphr gossip import` replays it into another client's
//! store through the same pull step a peer's answer passes.

mod common;

use common::{Server, User, accepted};
use serde_json::Value;

/// Claim (scenario S01, Carol hears of Alice only from Bob): a client
/// exports what it verified (commits with their data actions, and the
/// other branch of a fork it holds); a second client with no peer and no
/// keystore imports the file and reaches the same tip and the same two
/// branch heads. Defect that turns it red: a bundle that does not
/// round-trip (a missing action, a dropped branch), or an import that
/// stores less than it reports. End-to-end: yes (real servers, two CLI
/// stores, one file).
#[test]
fn bundle_carries_commits_actions_and_both_fork_branches_between_clients() {
    let (s1, s2) = (Server::start(), Server::start());
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity(&id);
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    a.setup(&["data", "action", &ident, &signer, "--msg=carried"]);
    a.setup(&["data", "commit", &ident, &signer]);
    b.add_key(&id);
    accepted(&a.push(&id, &s1.url), "A's branch (with its action) to peer 1");
    accepted(&b.push(&id, &s2.url), "B's competing branch to peer 2");
    // A learns of the fork by pulling from both, as a verifier does.
    let (p1, p2) = (format!("--peer={}", s1.url), format!("--peer={}", s2.url));
    let verdict = a.setup(&["verify", &ident, &p1, &p2]);
    assert_eq!(verdict["verdict"], "Error", "the fork is held: {verdict}");

    let file = a.dir.path().join("alice.bundle.json");
    a.setup(&["gossip", "export", &ident, &format!("--file={}", file.display())]);

    // Carol: no keystore entry, no peer, no network.
    let carol = User::new();
    let got = carol.setup(&["gossip", "import", &ident, &format!("--file={}", file.display())]);
    let tip = a.setup(&["inspect", &ident])["commit_count"].clone();
    assert_eq!(
        carol.setup(&["inspect", &ident])["commit_count"],
        tip,
        "Carol must hold every commit Alice's store holds: {got}"
    );
    assert_eq!(
        got["tip"], verdict["tip"],
        "same verified tip as the exporter's record"
    );
    let heads = |v: &Value| -> Vec<String> {
        let mut h: Vec<String> = v["branches"]
            .as_array()
            .unwrap_or_else(|| panic!("no branches: {v}"))
            .iter()
            .map(|x| x.as_str().expect("head").to_owned())
            .collect();
        h.sort();
        h
    };
    assert_eq!(heads(&got), heads(&verdict), "both branch heads cross the file");
    assert_eq!(got["anchor"]["source"], "hint", "Carol only has a hint");
}

/// Claim: an import is replay, never trust: a bundle whose commit was
/// altered is refused and nothing of it is stored. Defect that turns it
/// red: an import that stores a bundle's commits without replaying them
/// (Carol would then hold a commit no key signed). End-to-end: yes.
#[test]
fn import_of_an_altered_bundle_is_refused_and_stores_nothing() {
    let s = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &s.url), "push");
    let ident = format!("--identity={id}");
    let file = a.dir.path().join("alice.bundle.json");
    a.setup(&["gossip", "export", &ident, &format!("--file={}", file.display())]);

    let mut doc: Value = serde_json::from_slice(&std::fs::read(&file).expect("read")).expect("json");
    // Flip a character inside the last commit's signed bytes.
    let coz = doc["chains"][0]["commits"][1]["txs"][0][0]
        .as_str()
        .expect("coz")
        .to_owned();
    let mut bytes = coz.into_bytes();
    let at = bytes.len() / 2;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    doc["chains"][0]["commits"][1]["txs"][0][0] = String::from_utf8(bytes).expect("utf8").into();
    std::fs::write(&file, serde_json::to_vec(&doc).expect("ser")).expect("write");

    let carol = User::new();
    let r = carol.run(&["gossip", "import", &ident, &format!("--file={}", file.display())]);
    assert!(!r.ok, "an altered bundle must be refused: {}", r.stdout);
    let held = carol.run(&["inspect", &ident]);
    assert!(
        !held.ok || held.json()["commit_count"] == 0,
        "nothing of a refused bundle is stored: {}",
        held.stdout
    );
}
