//! Network commands of the CLI (`push`, `fetch`, `verify`) and its
//! typed refusals, end to end against real `cyphr-server` processes.
//!
//! Contract these tests pin (the implementation is free to add to it):
//!
//! - `cyphr push --identity <pr> --peer <url>`: exit 0 if the peer accepted. A refusal is a
//!   non-zero exit and, under `--output json`, one JSON object on stderr whose `error.kind` names
//!   the typed cause (`"stale"` for a peer holding a newer tip).
//! - `cyphr fetch --identity <pr> --peer <url> [--trust-remote]`: pulls and verifies the peer's
//!   commits into the local store. A local history that differs from the peer's is refused with
//!   nothing changed; `--trust-remote` discards only the local commits after the parting point.
//! - `cyphr push --assert-local`: sends local commits that differ from the peer's as a fork.
//! - `cyphr verify --identity <pr> [--peer <url>]... [--anchor <pr>] [--choices <file>]`: prints
//!   (JSON) `tip`, `view_age_secs`, `added`, `peers_queried` (never 0), `freshness_secs`,
//!   `anchor.{value,source}` with source one of `pinned`, `trusted-genesis`, `hint`, and a
//!   `verdict` that is a standing: `"Active"`, or `"Error"` with a non-empty top-level `evidence`
//!   for an unresolved fork. Never `current`, `verified`, `ok` or `valid`.
//! - A choices file is TOML: `anchor = "<pr>"`, `peers = ["<url>", ...]`, `freshness_secs = <n>`;
//!   an unknown key is refused with error kind `malformed`.
//! - Error kinds are the scenario harness's `RefusalKind` names, lowercased.
//!
//! Server-based tests need the `cyphr-server` binary: `CYPHR_SERVER_BIN`, else
//! one `cargo build -p cyphr-server` (as the scenario harness does).

mod common;

use std::path::Path;

use clap::Parser;
use common::{Server, User, accepted};
use cyphr_cli::{Cli, Error, commands, keystore};
use serde_json::Value;
use tempfile::TempDir;

// ------------------------------------------------------------------- push

/// Claim: a push to a peer that already holds a different tip is refused as
/// stale with a typed error and the peer's history is not overwritten; a
/// fetch with no flag refuses the divergence and changes nothing; after
/// `fetch --trust-remote` and a redone commit the same user's push is
/// accepted. End-to-end: yes (two devices, one real server).
/// Turns red on: a CLI that overwrites or forks a different peer tip (the
/// stale push exits 0), a refusal that is only text (`error.kind` absent or
/// not `stale`), a fetch that changes the store without the flag, or an
/// adoption that does not produce an acceptable push.
#[test]
fn push_stale_is_refused_then_trusting_the_remote_is_accepted() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &server.url), "first push of a new identity");

    // Device B takes the identity, advances it, and pushes first.
    let b = a.clone_identity(&id);
    b.add_key(&id);
    accepted(&b.push(&id, &server.url), "B's push of the newer commit");

    // Device A, unaware, makes a competing commit on the old tip.
    a.add_key(&id);
    let stale = a.push(&id, &server.url);
    assert!(!stale.ok, "a push on a stale tip must be refused");
    let err: Value = serde_json::from_str(stale.stderr.lines().last().unwrap_or(""))
        .unwrap_or_else(|e| panic!("refusal must be a JSON error ({e}): {}", stale.stderr));
    assert_eq!(
        err["error"]["kind"], "stale",
        "refusal must be the typed `stale` kind: {err}"
    );

    // Fetch without a flag refuses the divergence and changes nothing.
    let peer = format!("--peer={}", server.url);
    let refused = a.run(&["fetch", &format!("--identity={id}"), &peer]);
    assert!(!refused.ok, "a diverged fetch must be refused");
    assert!(
        refused.stderr.contains("--trust-remote"),
        "the refusal names the choice: {}",
        refused.stderr
    );
    assert_eq!(a.commit_count(&id), 3, "nothing was discarded");

    // A trusts the peer, redoes its commit, and lands.
    let r = a.run(&[
        "fetch",
        &format!("--identity={id}"),
        &peer,
        "--trust-remote",
    ]);
    assert!(r.ok, "trusting the remote must succeed: {}", r.stderr);
    a.add_key(&id);
    accepted(&a.push(&id, &server.url), "push after adopting the remote");

    // B sees both devices' commits: nothing was overwritten.
    let f = b.run(&["fetch", &format!("--identity={id}"), &peer]);
    assert!(f.ok, "fetch must succeed: {}", f.stderr);
    assert_eq!(
        b.commit_count(&id),
        4,
        "genesis commit + setup add + B's + A's redone"
    );
}

/// Claim: the CLI accepts an identity whose genesis key is not ES256. The
/// identity digest is the key's thumbprint under that key's own hash
/// (SHA-384 for ES384, SHA-512 for Ed25519), so it is not 32 bytes, and
/// push must read it at the width the core reads it (SPEC 2.2.1).
/// End-to-end: yes (CLI process, real server).
/// Turns red on: an identity parser that assumes SHA-256, which refuses
/// Ed25519 and ES384 with "digest length mismatch" before any request.
/// Red on base: ed25519 and ES384 pushes fail with that error.
#[test]
fn push_accepts_ed25519_and_other_key_algorithms() {
    let server = Server::start();
    for algo in ["ES256", "ES384", "Ed25519"] {
        let u = User::new();
        let id = u.new_identity_alg(algo);
        accepted(&u.push(&id, &server.url), &format!("{algo} identity push"));
        assert_eq!(
            u.commit_count(&id),
            2,
            "{algo}: the genesis commit + the setup key add"
        );
    }
}

/// Claim (SPEC 5.1/5.2, zami be0663f): a single-key principal is
/// published by its genesis commit alone, with no second key: the genesis
/// key signs principal/create (id = the future SR) and commit/create. The
/// server accepts it, and a reader fetching it holds exactly one key and a
/// PG equal to the identity.
/// End-to-end: yes (init, push to a real server, fetch by a second user).
/// Turns red on: an init with no genesis commit (nothing to push), a
/// genesis commit that also adds a key (two active keys), or a
/// principal/create whose id is not the SR (the server refuses the push,
/// or the fetched PG differs from the identity).
/// Red on base: `init` has no `--genesis-commit`, so the setup fails.
#[test]
fn genesis_only_principal_is_published_with_one_key() {
    let server = Server::start();
    let a = User::new();
    let init = a.setup(&["init", "--algo", "Ed25519", "--genesis-commit"]);
    let id = init["keys"][0].as_str().expect("genesis key").to_owned();
    accepted(&a.push(&id, &server.url), "genesis-only push");

    let reader = User::new();
    let f = reader.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "fetch of the genesis-only principal: {}", f.stderr);
    let seen = reader.setup(&["inspect", &format!("--identity={id}")]);
    assert_eq!(seen["commit_count"], 1, "genesis commit only: {seen}");
    assert_eq!(
        seen["active_keys"].as_array().map(Vec::len),
        Some(1),
        "no extra key: {seen}"
    );
    assert!(
        seen["pg"].to_string().contains(&id),
        "PG is the SR principal/create names, i.e. the identity {id}: {}",
        seen["pg"]
    );
}

/// Claim (SPEC 5.1 step 1, 7.7 Example 1; zami be0663f 5.2): the single-key
/// genesis commit is three transactions, key/create of the genesis key,
/// principal/create, commit/create, and a second client fetching it sees
/// all three in the genesis bundle with PG equal to the identity.
/// End-to-end: yes (init, push to a real server, fetch and export by a
/// second client).
/// Turns red on: a genesis bundle without the key/create (the key is only
/// implicit in the principal), or a PG that is not the identity.
/// Red on base 6c9f48a: the bundle held only principal/create and
/// commit/create (the core refused to re-add the genesis key).
#[test]
fn genesis_bundle_carries_key_create_principal_create_commit_create() {
    let server = Server::start();
    let a = User::new();
    let init = a.setup(&["init", "--algo", "Ed25519", "--genesis-commit"]);
    let id = init["keys"][0].as_str().expect("genesis key").to_owned();
    accepted(&a.push(&id, &server.url), "genesis push");

    let reader = User::new();
    let f = reader.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "fetch: {}", f.stderr);
    let seen = reader.setup(&["inspect", &format!("--identity={id}")]);
    assert!(
        seen["pg"].to_string().contains(&id),
        "PG is the identity {id}: {}",
        seen["pg"]
    );

    let out = reader.dir.path().join("bundle.jsonl");
    reader.setup(&[
        "export",
        &format!("--identity={id}"),
        &format!("--output={}", out.display()),
    ]);
    let first = std::fs::read_to_string(&out).expect("bundle");
    let first: Value =
        serde_json::from_str(first.lines().next().expect("genesis line")).expect("bundle JSON");
    // `txs` is the bundle's ordered transaction list; a transaction may be
    // wrapped in a one-element array (SPEC 5.2 wire format).
    let typs: Vec<String> = first["txs"]
        .as_array()
        .expect("txs")
        .iter()
        .map(|c| {
            let c = c.as_array().and_then(|a| a.first()).unwrap_or(c);
            c["pay"]["typ"].as_str().unwrap_or("").to_owned()
        })
        .collect();
    let suffixes: Vec<&str> = typs
        .iter()
        .filter_map(|t| t.rsplit_once("cyphr/"))
        .map(|(_, s)| s)
        .collect();
    assert_eq!(
        suffixes,
        ["key/create", "principal/create", "commit/create"],
        "genesis commit transactions: {typs:?}"
    );
}

/// Claim (SPEC 5.3, 7.7 Example 1, zami be0663f): `init --keys a,b
/// --genesis-commit` publishes a two-key explicit genesis, the genesis key
/// creating itself and the second key before principal/create, and a
/// second client fetching it holds both keys under a PG equal to the
/// identity.
/// End-to-end: yes (init, push to a real server, fetch by a second user).
/// Turns red on: a multi-key genesis the CLI refuses to commit, one whose
/// bundle lacks a key's key/create (the server refuses it), or a server
/// that cannot read a multi-key genesis from its blobs.
/// Red on base 6c9f48a: `--genesis-commit` conflicted with `--keys`.
#[test]
fn multi_key_genesis_is_published_with_every_key_created() {
    let server = Server::start();
    let a = User::new();
    let k0 = a.setup(&["key", "generate", "--algo", "ES256"])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let k1 = a.setup(&["key", "generate", "--algo", "Ed25519"])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let init = a.setup(&["init", &format!("--keys={k0},{k1}"), "--genesis-commit"]);
    let id = init["pr"].as_str().expect("identity").to_owned();
    accepted(&a.push(&id, &server.url), "multi-key genesis push");

    let reader = User::new();
    let f = reader.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "fetch of the multi-key genesis: {}", f.stderr);
    let seen = reader.setup(&["inspect", &format!("--identity={id}")]);
    assert_eq!(seen["commit_count"], 1, "genesis commit only: {seen}");
    assert_eq!(
        seen["active_keys"].as_array().map(Vec::len),
        Some(2),
        "both genesis keys: {seen}"
    );
    assert!(
        seen["pg"].to_string().contains(&id),
        "PG is the identity {id}: {}",
        seen["pg"]
    );
}

/// Claim: a device paired into a multi-key principal can trust the remote.
/// The identity is the principal genesis, not a thumbprint in the device's
/// keystore, so the adoption must read the genesis from the stored history.
/// End-to-end: yes (two devices, one real server).
/// Turns red on: an adoption that resolves genesis only from the keystore,
/// failing with "cannot resolve genesis ... no stored commits or keystore
/// key".
#[test]
fn paired_device_of_multi_key_principal_trusts_the_remote() {
    let server = Server::start();
    let a = User::new();
    let k0 = a.setup(&["key", "generate", "--algo", "ES256"])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let k1 = a.setup(&["key", "generate", "--algo", "Ed25519"])["tmb"]
        .as_str()
        .expect("tmb")
        .to_owned();
    let init = a.setup(&["init", &format!("--keys={k0},{k1}"), "--genesis-commit"]);
    let id = init["pr"].as_str().expect("identity").to_owned();
    accepted(&a.push(&id, &server.url), "publish");

    // The phone enrolls its own key; the identity is not a phone key.
    let phone = User::new();
    let request = a.dir.path().join("request.json");
    let req = phone.setup(&[
        "key",
        "request",
        &format!("--identity={id}"),
        &format!("--file={}", request.display()),
    ]);
    let phone_tmb = req["tmb"].as_str().expect("tmb").to_owned();
    a.setup(&[
        "key",
        "accept",
        &format!("--identity={id}"),
        &format!("--signer={k0}"),
        &format!("--file={}", request.display()),
    ]);
    accepted(&a.push(&id, &server.url), "pairing");
    let f = phone.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "phone fetch: {}", f.stderr);

    // The owner moves on; the phone commits on the old tip.
    a.setup(&[
        "key",
        "add",
        &format!("--identity={id}"),
        &format!("--signer={k0}"),
    ]);
    accepted(&a.push(&id, &server.url), "owner's commit");
    phone.setup(&[
        "key",
        "add",
        &format!("--identity={id}"),
        &format!("--signer={phone_tmb}"),
    ]);
    assert!(
        !phone.push(&id, &server.url).ok,
        "the phone is stale before it adopts the remote"
    );

    let r = phone.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
        "--trust-remote",
    ]);
    assert!(r.ok, "adoption by a multi-key principal: {}", r.stderr);
    phone.setup(&[
        "key",
        "add",
        &format!("--identity={id}"),
        &format!("--signer={phone_tmb}"),
    ]);
    accepted(&phone.push(&id, &server.url), "push after adoption");
}

/// Claim: fetch brings a peer's verified commits into an empty local store.
/// End-to-end: yes. Turns red on: a fetch that exits 0 without storing, or
/// stores unverified/partial history (commit count differs from the peer's).
#[test]
fn push_fetch_pulls_peer_history() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    a.add_key(&id);
    accepted(&a.push(&id, &server.url), "push of two commits");

    let reader = User::new();
    let f = reader.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "fetch into an empty store must succeed: {}", f.stderr);
    assert_eq!(reader.commit_count(&id), a.commit_count(&id));
}

// ------------------------------------------------------------------- data

/// Claim (SPEC 4.8.1, 4.8.2): a data action the CLI records and pushes enters
/// the peer's Data Tree, and DR joins PR only by a signed `ds/create`. A
/// `ds/create` a device signed over a DT that lacks an action the peer holds
/// includes exactly the actions it names: the peer accepts it, its tip moves
/// to that commit, and the action the device never saw is left out.
/// End-to-end: yes (two devices of one principal, one real server).
/// Turns red on: a CLI with no data command (every `data` call fails), a push
/// that omits the recorded actions (the server's DT is then empty and the
/// `ds/create` is refused), a `data commit` that names a DR other than
/// MR(DT), or a peer that counts the unseen action in DT (it then refuses
/// the `ds/create`).
/// A fresh client fetches the chain and `verify` reaches the published tip;
/// red while `/patch` carries no actions (the replay of the `ds/create`
/// finds an empty DT: state mismatch, #202), or carries the left-out action
/// as included.
/// Red on base: `data` is an unknown subcommand, so the first `data action`
/// fails.
#[test]
fn data_commit_includes_only_the_actions_it_names() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &server.url), "push of the genesis history");
    let signer = format!("--signer={id}");
    let ident = format!("--identity={id}");
    // `push` reports `up_to_date` only when the peer's tip is this device's
    // last commit, and fails stale when the peer holds any other tip, so it
    // reads the peer's tip without `verify`, which replays the peer's chain
    // and cannot yet (the wire carries no actions, #202) for a `ds/create`.
    let peer_tip = |u: &User| {
        let v = u.setup(&["push", &ident, &format!("--peer={}", server.url)]);
        assert_eq!(v["status"], "up_to_date", "the peer must hold the tip: {v}");
        v["tip"].as_str().expect("tip").to_owned()
    };
    let base_tip = peer_tip(&a);

    // A records an action and pushes it alone: DR is not yet in PR, so the
    // peer's tip stays where it was.
    a.setup(&["data", "action", &ident, &signer, "--msg=one"]);
    accepted(&a.push(&id, &server.url), "push of a recorded action");
    assert_eq!(peer_tip(&a), base_tip, "an action alone moves no tip");

    // The devices part here: B is a copy of A that never learns A's second
    // action, which A pushes alone.
    let b = a.clone_identity(&id);
    a.setup(&["data", "action", &ident, &signer, "--msg=two"]);
    accepted(&a.push(&id, &server.url), "push of A's second action");

    // B's ds/create names MR(DT) over its one action; the peer's DT holds
    // two. It includes the one it names and leaves A's second out.
    let made = b.setup(&["data", "commit", &ident, &signer]);
    accepted(&b.push(&id, &server.url), "push of B's data commit");
    assert_eq!(
        peer_tip(&b),
        made["commit_id"].as_str().expect("commit_id"),
        "the peer's tip is the commit B made"
    );

    // A fresh client was not there: it fetches the chain holding the
    // ds/create with the actions it includes, and verify reaches that tip.
    let reader = User::new();
    let fetched = reader.run(&["fetch", &ident, &format!("--peer={}", server.url)]);
    assert!(fetched.ok, "fetch of a data chain: {}", fetched.stderr);
    assert_eq!(reader.commit_count(&id), b.commit_count(&id));
    let verified = reader.setup(&["verify", &ident, &format!("--peer={}", server.url)]);
    assert_eq!(verified["verdict"], "Active");
    assert_eq!(verified["tip"], made["commit_id"], "verify reaches the tip");
}

/// Claim (SPEC 4.8.2): a `ds/create` includes exactly the actions recorded
/// before it, so one push of a history recorded offline (two actions, then
/// `data commit`, no push between) must send each action ahead of the commit
/// that follows it. The peer then accepts, and its tip is the data commit.
/// End-to-end: yes (a fresh real server).
/// Turns red if push sends a commit before the actions recorded before it
/// (`after < i` for `after <= i`): the server meets the `ds/create` with an
/// empty DT and refuses it as a state mismatch.
#[test]
fn data_push_sends_actions_ahead_of_their_ds_create() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    a.setup(&["data", "action", &ident, &signer, "--msg=one"]);
    a.setup(&["data", "action", &ident, &signer, "--msg=two"]);
    let made = a.setup(&["data", "commit", &ident, &signer]);

    let pushed = a.push(&id, &server.url);
    accepted(&pushed, "one push of actions and their ds/create");
    assert_eq!(
        pushed.json()["tip"],
        made["commit_id"],
        "the peer's tip is the data commit"
    );
}

/// Claim (SPEC 4.8.1, 4.8.2, I1): `fetch --trust-remote` discards only the
/// local commits after the parting point and loses no data action recorded
/// locally. The shared prefix stays, the discarded commit is named, and the
/// action stays in the device's DT, so a following `ds/create` includes it,
/// the peer accepts it, and a fresh client verifies the result.
/// End-to-end: yes (two devices of one principal, one real server).
/// Turns red if the adoption rebuilds the store from commits alone: the
/// action is gone, `data commit` has no DR to include and fails; if it
/// discards the shared prefix or more than the diverged commit; or if it
/// drops an action the adopted history still authorizes at its own `now`, or
/// re-signs one (a duplicate under a new digest, SPEC 6.5); an action it
/// cannot keep is named under `dropped_actions`.
#[test]
fn trust_remote_discards_only_diverged_commits_and_keeps_actions() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &server.url), "base push");
    let b = a.clone_identity(&id);
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));

    // B records an action and a commit it does not push; A moves the peer on.
    b.setup(&["data", "action", &ident, &signer, "--msg=mine"]);
    b.add_key(&id);
    let diverged = b.setup(&["inspect", &ident])["commit_count"].as_u64();
    a.add_key(&id);
    accepted(&a.push(&id, &server.url), "A's newer commit");
    assert!(!b.push(&id, &server.url).ok, "B is stale");

    let adopted = b.setup(&[
        "fetch",
        &ident,
        &format!("--peer={}", server.url),
        "--trust-remote",
    ]);
    assert_eq!(
        adopted["discarded"].as_array().map(Vec::len),
        Some(1),
        "only B's own commit goes: {adopted}"
    );
    assert_eq!(adopted["fetched"], 1, "A's commit comes: {adopted}");
    assert_eq!(
        b.commit_count(&id),
        diverged.expect("count"),
        "the shared prefix stays and the peer's commit replaces B's"
    );
    let dropped = adopted["dropped_actions"].as_array().expect("dropped");
    assert!(
        dropped.is_empty(),
        "an action B's key still authorizes is kept as signed, not dropped: {adopted}"
    );
    assert!(
        adopted.get("resigned_actions").is_none(),
        "nothing is re-signed: {adopted}"
    );
    let made = b.setup(&["data", "commit", &ident, &signer]);
    let pushed = b.push(&id, &server.url);
    accepted(&pushed, "push of the adopted history with its ds/create");
    assert_eq!(pushed.json()["tip"], made["commit_id"]);

    let reader = User::new();
    let fetched = reader.run(&["fetch", &ident, &format!("--peer={}", server.url)]);
    assert!(fetched.ok, "fetch: {}", fetched.stderr);
    let v = reader.setup(&["verify", &ident, &format!("--peer={}", server.url)]);
    assert_eq!(v["verdict"], "Active");
    assert_eq!(v["tip"], made["commit_id"]);
}

/// Claim: `push --assert-local` sends local commits that differ from the
/// peer's as a fork, and without the flag the same push is refused with
/// nothing sent. A single diverged commit is sent too, and the answer is the
/// peer's: it refuses a lone fork root with 409, which the CLI reports as
/// `stale` (the CLI sets no minimum of its own). End-to-end: yes (two
/// devices, one real server).
/// Turns red on: a push that sends the fork with no flag, or one that refuses
/// two diverged commits with the flag. The lone-commit case does not tell the
/// CLI's refusal from the peer's: both read `stale`.
#[test]
fn assert_local_pushes_the_fork() {
    for diverged in [2, 1] {
        let server = Server::start();
        let a = User::new();
        let id = a.new_identity();
        accepted(&a.push(&id, &server.url), "base push");
        let b = a.clone_identity(&id);
        b.add_key(&id);
        accepted(&b.push(&id, &server.url), "B's commit");

        // A holds `diverged` commits over the base, a branch against B's.
        for _ in 0..diverged {
            a.add_key(&id);
        }
        let refused = a.push(&id, &server.url);
        assert!(!refused.ok, "a fork needs the explicit choice");
        let sent = a.run(&[
            "push",
            &format!("--identity={id}"),
            &format!("--peer={}", server.url),
            "--assert-local",
        ]);
        if diverged == 1 {
            assert!(
                !sent.ok,
                "the peer refuses a lone fork root: {}",
                sent.stdout
            );
            assert!(
                sent.stderr.contains(r#""kind":"stale""#),
                "the peer's 409 is reported as stale: {}",
                sent.stderr
            );
            continue;
        }
        assert!(sent.ok, "the asserted fork is sent: {}", sent.stderr);
        assert_eq!(sent.json()["pushed"], diverged, "{}", sent.stdout);
    }
}

/// Claim: a held data action whose signer a peer later reports naked-revoked
/// does not stop the principal from saving again. Every save re-sends the
/// store's trailing action-only lines; the revoke is recorded before the
/// action's `now`, so the store refuses the action as `key revoked`, and
/// that refusal must not fail the save. End-to-end: yes (CLI processes, one
/// real server). Turns red on: a save that propagates the refusal, exiting
/// non-zero with "key revoked".
#[test]
fn a_save_survives_a_held_action_whose_signer_was_revoked() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let k1 = a.setup(&[
        "key",
        "add",
        &format!("--identity={id}"),
        &format!("--signer={id}"),
    ])["added_key"]
        .as_str()
        .expect("added_key")
        .to_owned();
    accepted(&a.push(&id, &server.url), "publish");

    // The store judges a revoke by the clock of the verifier that records it,
    // and admits an action up to 360 s ahead of that clock. An action dated a
    // minute ahead is therefore always at or after the revoke's recording
    // time, however slowly the steps below run, so the re-send is refused.
    let ahead = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
        + 60;
    a.setup(&[
        "data",
        "action",
        &format!("--identity={id}"),
        &format!("--signer={k1}"),
        "--msg=held",
        &format!("--now={ahead}"),
    ]);
    a.setup(&[
        "key",
        "naked-revoke",
        &format!("--key={k1}"),
        &format!("--peer={}", server.url),
    ]);
    // The pull step records the peer's revoke in the local store.
    let v = a.run(&verify_args(
        &format!("--identity={id}"),
        &[&format!("--peer={}", server.url)],
    ));
    assert!(v.ok, "verify must record the revoke: {}", v.stderr);

    let r = a.run(&[
        "data",
        "action",
        &format!("--identity={id}"),
        &format!("--signer={id}"),
        "--msg=next",
    ]);
    assert!(
        r.ok,
        "a save after the signer's revoke must not fail on the held action: {}",
        r.stderr
    );
}

/// A peer URL nothing listens on: the port of a server that has exited.
fn dead_peer() -> String {
    Server::start().url.clone()
}

/// Claim (SPEC 6.4): a naked revoke is sent to every named peer, and an
/// unreachable one does not abort it. It succeeds when at least one peer
/// accepted, reports each failure on stderr, and fails when none did.
/// End-to-end: yes (CLI processes, one real server and one dead URL).
/// Turns red on: a command that stops at the first unreachable peer, so
/// the live peer after it never hears the revoke.
#[test]
fn naked_revoke_is_sent_past_an_unreachable_peer() {
    let live = Server::start();
    let dead = dead_peer();
    let a = User::new();
    let id = a.new_identity();
    let key = a.setup(&[
        "key",
        "add",
        &format!("--identity={id}"),
        &format!("--signer={id}"),
    ])["added_key"]
        .as_str()
        .expect("added_key")
        .to_owned();

    let revoke = |peers: &[&str]| {
        let mut args = vec!["key".to_owned(), "naked-revoke".to_owned()];
        args.push(format!("--key={key}"));
        args.extend(peers.iter().map(|p| format!("--peer={p}")));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        a.run(&args)
    };

    let none = revoke(&[&dead]);
    assert!(!none.ok, "no peer accepted: the revoke must fail");

    let r = revoke(&[&dead, &live.url]);
    assert!(r.ok, "one peer accepted: the revoke succeeds: {}", r.stderr);
    assert!(
        r.stderr.contains(&dead),
        "the unreachable peer is reported on stderr: {}",
        r.stderr
    );
    assert_eq!(
        r.json()["peers"],
        serde_json::json!([live.url]),
        "the output names the peers that accepted: {}",
        r.stdout
    );
}

// ----------------------------------------------------------------- verify

fn verify_args<'a>(id: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut v = vec!["verify", id];
    v.extend_from_slice(extra);
    v
}

/// The verdict fields every answer must carry, whatever the inputs.
fn assert_answer_shape(v: &Value) {
    assert!(
        v["tip"].as_str().is_some_and(|s| !s.is_empty()),
        "answer must name the tip: {v}"
    );
    assert!(
        v["view_age_secs"].is_u64(),
        "answer must state the view age: {v}"
    );
    assert!(
        v["added"].is_u64(),
        "answer must say how many commits the pull added: {v}"
    );
    assert!(
        v["anchor"]["value"].as_str().is_some_and(|s| !s.is_empty())
            && v["anchor"]["source"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "answer must state the anchor and how it was obtained: {v}"
    );
    assert!(
        v["peers_queried"].as_u64().is_some_and(|n| n > 0),
        "peers_queried must be present and never 0: {v}"
    );
    assert!(
        matches!(
            v["anchor"]["source"].as_str(),
            Some("pinned" | "trusted-genesis" | "hint")
        ),
        "anchor source must be pinned, trusted-genesis or hint: {v}"
    );
    assert!(
        matches!(v["verdict"].as_str(), Some("Active" | "Error")),
        "verdict must be a standing (Active or Error), never current/verified: {v}"
    );
}

/// Claim: the verdict says how old its view is and what it rests on: tip,
/// view age, whether the queried peer reported a newer tip, anchor and its
/// provenance, and never a bare "current". End-to-end: yes (real peer).
/// Turns red on: a verify that prints "current"/"verified" with no age,
/// anchor or provenance.
#[test]
fn verify_answer_states_age_anchor_and_basis() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &server.url), "push");

    let peer = format!("--peer={}", server.url);
    let r = a.run(&verify_args(&format!("--identity={id}"), &[&peer]));
    assert!(
        r.ok,
        "verify against a healthy peer must succeed: {}",
        r.stderr
    );
    let v = r.json();
    assert_answer_shape(&v);
    assert_eq!(v["verdict"], "Active", "honest principal is Active: {v}");
    assert_eq!(v["added"], 0, "peer is at our tip: {v}");
}

/// Claim: when a queried peer holds a newer tip than the local view, verify
/// pulls and replays it, adopts it, and says how many commits that added
/// rather than vouching for the stale tip. End-to-end: yes (two peers, one
/// lagging). Turns red on: a verify that ignores a peer's longer chain
/// (`added` 0, the stale tip reported) or that answers "current" from the
/// local view.
#[test]
fn verify_adopts_the_newer_tip_a_peer_holds() {
    let lagging = Server::start();
    let ahead = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &lagging.url), "push to lagging");
    accepted(&a.push(&id, &ahead.url), "push to ahead");
    a.add_key(&id);
    let newest = a.push(&id, &ahead.url);
    accepted(&newest, "push newer commit to ahead only");

    // A reader whose view came from the lagging peer queries both.
    let reader = User::new();
    let f = reader.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", lagging.url),
    ]);
    assert!(f.ok, "fetch from lagging peer: {}", f.stderr);
    let p1 = format!("--peer={}", lagging.url);
    let p2 = format!("--peer={}", ahead.url);
    let r = reader.run(&verify_args(&format!("--identity={id}"), &[&p1, &p2]));
    assert!(r.ok, "verify must answer, not fail: {}", r.stderr);
    let v = r.json();
    assert_answer_shape(&v);
    assert_eq!(
        v["added"], 1,
        "the ahead peer's newer commit is adopted: {v}"
    );
    assert_eq!(
        v["tip"],
        newest.json()["tip"],
        "the newest verified tip: {v}"
    );
}

/// Claim: a choices file sets the anchor, the peers and the freshness
/// window; with no flags the verdict reflects exactly those. End-to-end: yes.
/// Turns red on: a choices file that is ignored (no peer queried, anchor not
/// the configured one, freshness not echoed).
#[test]
fn verify_choices_file_sets_anchor_peers_freshness() {
    let server = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &server.url), "push");

    let choices = a.dir.path().join("choices.toml");
    std::fs::write(
        &choices,
        format!(
            "anchor = \"{id}\"\npeers = [\"{}\"]\nfreshness_secs = 7\n",
            server.url
        ),
    )
    .expect("write choices");
    let c = format!("--choices={}", choices.display());
    let r = a.run(&verify_args(&format!("--identity={id}"), &[&c]));
    assert!(
        r.ok,
        "verify driven by a choices file must succeed: {}",
        r.stderr
    );
    let v = r.json();
    assert_answer_shape(&v);
    assert_eq!(v["anchor"]["value"], id.as_str(), "anchor from file: {v}");
    assert_eq!(v["peers_queried"], 1, "peer from file was queried: {v}");
    assert_eq!(v["freshness_secs"], 7, "freshness from file: {v}");
}

/// Claim: a principal with an unresolved fork (two devices advanced the same
/// tip, each pushed to a different peer) gets standing `Error` with evidence,
/// not `Active` (SPEC section 15, zami branch). End-to-end: yes.
/// Turns red on: a verify that vouches `Active` from whichever peer it
/// reached first, or reports `Error` with no evidence.
#[test]
fn verify_forked_principal_is_error_with_evidence() {
    let s1 = Server::start();
    let s2 = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity(&id);
    a.add_key(&id);
    b.add_key(&id);
    accepted(&a.push(&id, &s1.url), "A's branch to peer 1");
    accepted(&b.push(&id, &s2.url), "B's competing branch to peer 2");

    let p1 = format!("--peer={}", s1.url);
    let p2 = format!("--peer={}", s2.url);
    let r = a.run(&verify_args(&format!("--identity={id}"), &[&p1, &p2]));
    assert!(
        r.ok,
        "a fork is an answer (standing Error), not a failure: {}",
        r.stderr
    );
    let v = r.json();
    assert_eq!(v["verdict"], "Error", "an unresolved fork is Error: {v}");
    assert!(
        !v["evidence"].is_null() && v["evidence"] != "" && v["evidence"] != serde_json::json!([]),
        "Error must carry evidence: {v}"
    );
}

/// Claim: `fetch` from a peer whose chain diverged from the local one
/// refuses with the typed `forked` error (SPEC 15.8) and exits, rather than
/// crashing while it replays the peer's chain. End-to-end: yes (two devices,
/// two servers). Turns red on: a fetch whose divergence path nests a second
/// runtime inside the first (the process panics, no typed error).
#[test]
fn fetch_from_a_diverged_peer_is_a_typed_fork() {
    let s1 = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity(&id);
    a.add_key(&id);
    b.add_key(&id);
    accepted(&a.push(&id, &s1.url), "A's branch to peer 1");

    let r = b.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", s1.url),
    ]);
    assert!(!r.ok, "a diverged peer must be refused, got: {}", r.stdout);
    let err: Value = serde_json::from_str(r.stderr.lines().last().unwrap_or(""))
        .unwrap_or_else(|e| panic!("no typed error on stderr ({e}): {}", r.stderr));
    assert_eq!(err["error"]["kind"], "forked", "{err}");
}

/// Claim: a choices file with an unknown (misspelled) key is refused with a
/// typed `malformed` error and never silently falls back to defaults.
/// End-to-end: yes (CLI process). Turns red on: a parser that ignores
/// unknown keys (here `peerz` would leave no peers, silently).
#[test]
fn verify_choices_unknown_key_is_refused() {
    let a = User::new();
    let id = a.new_identity();
    let choices = a.dir.path().join("choices.toml");
    std::fs::write(
        &choices,
        format!("anchor = \"{id}\"\npeerz = [\"http://127.0.0.1:1\"]\nfreshness_secs = 7\n"),
    )
    .expect("write choices");
    let c = format!("--choices={}", choices.display());
    let r = a.run(&verify_args(&format!("--identity={id}"), &[&c]));
    assert!(!r.ok, "an unknown choices key must be refused");
    let err: Value = serde_json::from_str(r.stderr.lines().last().unwrap_or(""))
        .unwrap_or_else(|e| panic!("refusal must be a JSON error ({e}): {}", r.stderr));
    assert_eq!(err["error"]["kind"], "malformed", "typed refusal: {err}");
}

// ----------------------------------------------------------- typed errors

fn lib_cli(user_dir: &Path, extra: &[&str]) -> Cli {
    let store = format!("file:{}", user_dir.join("data").display());
    let ks = user_dir.join("keys.json");
    let mut argv = vec![
        "cyphr".to_owned(),
        "--store".into(),
        store,
        "--keystore".into(),
        ks.display().to_string(),
    ];
    argv.extend(extra.iter().map(|s| (*s).to_owned()));
    Cli::try_parse_from(argv).expect("cli parses")
}

/// Claim: importing a bundle whose line states an unknown version yields a
/// typed CLI error, not a flattened message. The assertion is negative
/// (`matches!` against the variants that flatten today) because the typed
/// variant does not exist yet and naming it would not compile; the
/// implementation brief should replace it with a positive `matches!` on the
/// new variant. A unit-level test: the claim is about the library error type
/// and no scenario reaches it cheaper.
/// Turns red on: `import` mapping a bundle refusal into `Error::Storage`,
/// `Error::Json` or `Error::Io` text.
#[test]
fn typed_error_import_unknown_bundle_version() {
    let a = User::new();
    let id = a.new_identity();
    let bundle = a.dir.path().join("bundle.jsonl");
    a.setup(&[
        "export",
        &format!("--identity={id}"),
        &format!("--output={}", bundle.display()),
    ]);
    let text = std::fs::read_to_string(&bundle).expect("read bundle");
    let mut line: Value = serde_json::from_str(text.lines().next().expect("a line")).unwrap();
    line["v"] = 99.into();
    std::fs::write(&bundle, format!("{line}\n")).expect("write bundle");

    let other = TempDir::new().unwrap();
    std::fs::copy(a.keystore(), other.path().join("keys.json")).unwrap();
    let cli = lib_cli(other.path(), &["import", "--input", "x"]);
    let err = commands::io::import(&cli, &bundle).expect_err("v=99 must be refused");
    assert!(
        matches!(
            err,
            Error::Bundle {
                source: cyphr_storage::BundleError::UnsupportedVersion { found: 99, .. },
                ..
            }
        ),
        "unknown bundle version must be Error::Bundle(UnsupportedVersion): {err:?}"
    );
}

/// Claim: opening a store whose index states a future schema yields a typed
/// CLI error, not `Error::Storage` text. Negative `matches!` for the same
/// reason as above. A unit-level test: `parse_store` is the CLI's only door
/// to the store. Turns red on: `parse_store` flattening the cause to
/// `Error::Storage(String)`.
#[test]
fn typed_error_store_unknown_index_version() {
    let dir = TempDir::new().unwrap();
    let index = dir.path().join("data").join("index");
    drop(cyphr_index_fjall::FjallIndexer::open(&index).unwrap());
    let db = fjall::Database::builder(&index).open().unwrap();
    let meta = db
        .keyspace("index_meta", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    let rec = serde_json::json!({"version": 99, "partitions": []});
    meta.insert(b"index-meta", serde_json::to_vec(&rec).unwrap())
        .unwrap();
    db.persist(fjall::PersistMode::SyncAll).unwrap();
    drop((meta, db));

    let cli = lib_cli(dir.path(), &["import", "--input", "x"]);
    let err = commands::common::parse_store(&cli)
        .err()
        .expect("v=99 refused");
    assert!(
        matches!(
            err,
            Error::Index(cyphr_storage::index::IndexerError::UnsupportedVersion { found: 99, .. })
        ),
        "unknown index version must be Error::Index(UnsupportedVersion): {err:?}"
    );
}

/// Claim (characterization, must survive): a keystore stating an unknown
/// version surfaces through the CLI as the typed
/// `Error::Keystore(UnsupportedVersion)`, matched structurally, before any
/// key is read. Turns red on: a CLI layer that flattens the keystore refusal.
#[test]
fn typed_error_keystore_unknown_version_stays_typed() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("keys.json"), r#"{"v":99}"#).unwrap();
    let cli = lib_cli(dir.path(), &["import", "--input", "x"]);
    let err = commands::io::import(&cli, Path::new("absent.jsonl")).expect_err("refused");
    assert!(
        matches!(
            err,
            Error::Keystore(keystore::Error::UnsupportedVersion { found: 99, .. })
        ),
        "keystore v=99 must be Error::Keystore(UnsupportedVersion): {err:?}"
    );
}
