//! A Level 1 identity (no genesis commit, SPEC 5.1) is moved up only by the
//! user: `cyphr upgrade`, or a command's `--upgrade`. Nothing else signs its
//! genesis commit.

mod common;

use common::User;

fn level_one(u: &User) -> String {
    let g = u.setup(&["key", "generate", "--algo", "ES256"]);
    g["tmb"].as_str().expect("tmb").to_owned()
}

fn commits(u: &User, id: &str) -> u64 {
    u.commit_count(id)
}

/// Claim: on a Level 1 identity, `key add` and `data action` without
/// `--upgrade` refuse naming the way up and sign nothing; `upgrade` then
/// makes the genesis commit (and refuses a second time); and `key add
/// --upgrade` on a fresh Level 1 identity makes one commit that carries the
/// new key. End-to-end: yes (CLI processes).
/// Turns red on: a command that commits the genesis on its own, an `upgrade`
/// that accepts a committed identity, or an `--upgrade` that adds a second
/// commit for the key.
#[test]
fn level_one_moves_up_only_when_the_user_says_so() {
    let u = User::new();
    let id = level_one(&u);
    let ident = format!("--identity={id}");
    let signer = format!("--signer={id}");

    for args in [
        vec!["key", "add", &ident, &signer],
        vec!["data", "action", &ident, &signer, "--msg=m"],
        vec!["data", "commit", &ident, &signer],
    ] {
        let r = u.run(&args);
        assert!(!r.ok, "{args:?} must refuse a Level 1 identity");
        assert!(
            r.stderr.contains("cyphr upgrade") && r.stderr.contains("--upgrade"),
            "the refusal names the way up: {}",
            r.stderr
        );
        assert_eq!(commits(&u, &id), 0, "{args:?} signed nothing");
    }

    u.setup(&["upgrade", &ident]);
    assert_eq!(commits(&u, &id), 1, "the genesis commit");
    let again = u.run(&["upgrade", &ident]);
    assert!(!again.ok, "a committed identity is not upgraded again");
    assert!(
        again.stderr.contains("already has a genesis commit"),
        "{}",
        again.stderr
    );

    let v = User::new();
    let vid = level_one(&v);
    let added = v.setup(&[
        "key",
        "add",
        &format!("--identity={vid}"),
        &format!("--signer={vid}"),
        "--upgrade",
    ]);
    // Two keys in one genesis commit: the identity is their PG now.
    let pg = added["identity"].as_str().expect("identity").to_owned();
    assert_ne!(pg, vid, "the identity names the key set: {added}");
    assert_eq!(commits(&v, &pg), 1, "one genesis commit carries the key");
    let seen = v.setup(&["inspect", &format!("--identity={pg}")]);
    assert_eq!(
        seen["active_keys"].as_array().map(Vec::len),
        Some(2),
        "the genesis key and the added one: {seen}"
    );
}
