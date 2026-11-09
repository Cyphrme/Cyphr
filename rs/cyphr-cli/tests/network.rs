//! Network commands of the CLI (`push`, `rebase`, `fetch`, `verify`) and its
//! typed refusals, end to end against real `cyphr-server` processes.
//!
//! Contract these tests pin (the implementation is free to add to it):
//!
//! - `cyphr push --identity <pr> --peer <url>`: exit 0 if the peer accepted. A refusal is a
//!   non-zero exit and, under `--output json`, one JSON object on stderr whose `error.kind` names
//!   the typed cause (`"stale"` for a peer holding a newer tip).
//! - `cyphr rebase --identity <pr> --peer <url>`: replays local, unpushed commits onto the peer's
//!   tip, so a following `push` is accepted.
//! - `cyphr fetch --identity <pr> --peer <url>`: pulls and verifies the peer's commits into the
//!   local store.
//! - `cyphr verify --identity <pr> [--peer <url>]... [--anchor <pr>] [--choices <file>]`: prints
//!   (JSON) `tip`, `view_age_secs`, `newer_tip_reported`, `peers_queried` (never 0),
//!   `freshness_secs`, `anchor.{value,source}` with source one of `pinned`, `trusted-genesis`,
//!   `hint`, and a `verdict` that is a standing: `"Active"`, or `"Error"` with a non-empty
//!   top-level `evidence` for an unresolved fork. Never `current`, `verified`, `ok` or `valid`.
//! - A choices file is TOML: `anchor = "<pr>"`, `peers = ["<url>", ...]`, `freshness_secs = <n>`;
//!   an unknown key is refused with error kind `malformed`.
//! - Error kinds are the scenario harness's `RefusalKind` names, lowercased.
//!
//! Server-based tests need the `cyphr-server` binary: `CYPHR_SERVER_BIN`, else
//! one `cargo build -p cyphr-server` (as the scenario harness does).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use clap::Parser;
use cyphr_cli::{Cli, Error, commands, keystore};
use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------- harness

fn server_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("CYPHR_SERVER_BIN") {
            return PathBuf::from(p);
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(cargo)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "build",
                "--locked",
                "--quiet",
                "--message-format=json-render-diagnostics",
                "-p",
                "cyphr-server",
            ])
            .output()
            .expect("spawning cargo to build cyphr-server");
        assert!(
            out.status.success(),
            "building cyphr-server failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == "cyphr-server")
            .find_map(|v| v["executable"].as_str().map(PathBuf::from))
            .expect("cargo reported no cyphr-server executable")
    })
}

/// A running `cyphr-server`, killed on drop.
struct Server {
    child: Child,
    url: String,
    _dir: TempDir,
}

impl Server {
    fn start() -> Self {
        let dir = TempDir::new().expect("server tempdir");
        let mut child = Command::new(server_bin())
            .arg("--config")
            .arg(dir.path().join("absent.toml"))
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(dir.path().join("data"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning cyphr-server");
        let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
        let addr = loop {
            let line = lines
                .next()
                .expect("cyphr-server exited before announcing its address")
                .expect("reading server stdout");
            if let Some(a) = line.strip_prefix("listening on ") {
                break a.trim().to_owned();
            }
        };
        // Drain stdout so the server never blocks on a full pipe.
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            url: format!("http://{addr}"),
            _dir: dir,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One user's CLI environment: its own keystore and store.
struct User {
    dir: TempDir,
}

struct Ran {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }
}

impl User {
    fn new() -> Self {
        Self {
            dir: TempDir::new().expect("user tempdir"),
        }
    }

    fn keystore(&self) -> PathBuf {
        self.dir.path().join("keys.json")
    }

    fn store_uri(&self) -> String {
        format!("file:{}", self.dir.path().join("data").display())
    }

    fn run(&self, args: &[&str]) -> Ran {
        let out = Command::new(env!("CARGO_BIN_EXE_cyphr"))
            .arg("--keystore")
            .arg(self.keystore())
            .arg("--store")
            .arg(self.store_uri())
            .args(["--output", "json"])
            .args(args)
            .output()
            .expect("running cyphr");
        Ran {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run a command that exists today; failure is a setup bug.
    fn setup(&self, args: &[&str]) -> Value {
        let r = self.run(args);
        assert!(r.ok, "setup `{args:?}` failed: {}", r.stderr);
        r.json()
    }

    /// Create an identity: returns its genesis thumbprint (the identity arg).
    fn new_identity(&self) -> String {
        self.new_identity_alg("ES256")
    }

    fn new_identity_alg(&self, algo: &str) -> String {
        let g = self.setup(&["key", "generate", "--algo", algo]);
        let tmb = g["tmb"].as_str().expect("tmb").to_owned();
        self.add_key(&tmb);
        tmb
    }

    /// Commit one key addition, signed by the identity's genesis key.
    fn add_key(&self, identity: &str) {
        let id = format!("--identity={identity}");
        let signer = format!("--signer={identity}");
        self.setup(&["key", "add", &id, &signer]);
    }

    /// Seed a second device directly: copy this user's keystore and store
    /// directory (all its processes have exited, so the files are quiescent).
    /// Deliberately not export/import, whose roundtrip is quarantined (#111).
    fn clone_identity(&self, _identity: &str) -> Self {
        let other = Self::new();
        std::fs::copy(self.keystore(), other.keystore()).expect("copy keystore");
        copy_dir(
            &self.dir.path().join("data"),
            &other.dir.path().join("data"),
        );
        other
    }

    fn push(&self, id: &str, peer: &str) -> Ran {
        self.run(&[
            "push",
            &format!("--identity={id}"),
            &format!("--peer={peer}"),
        ])
    }

    fn commit_count(&self, id: &str) -> u64 {
        self.setup(&["inspect", &format!("--identity={id}")])["commit_count"]
            .as_u64()
            .expect("commit_count")
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).expect("copy file");
        }
    }
}

fn accepted(r: &Ran, what: &str) {
    assert!(r.ok, "{what} must be accepted, got: {}", r.stderr);
}

// ------------------------------------------------------------------- push

/// Claim: a push to a peer that already holds a newer tip is refused as
/// stale with a typed error, the peer's history is not overwritten, and after
/// a rebase onto the peer's tip the same user's push is accepted.
/// End-to-end: yes (two devices, one real server).
/// Turns red on: a CLI that overwrites or forks a newer peer tip (the stale
/// push exits 0), a refusal that is only text (`error.kind` absent or not
/// `stale`), or a rebase that does not produce an acceptable push.
/// Red on base: the first `push` is an unknown subcommand, so the first
/// assertion (`push` accepted) fails at runtime; the stale/rebase assertions
/// are reached once `push` exists.
#[test]
fn push_stale_is_refused_then_rebased_is_accepted() {
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

    // The refused push left the peer's history alone: A rebases and lands.
    let r = a.run(&[
        "rebase",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(
        r.ok,
        "rebase onto the peer's tip must succeed: {}",
        r.stderr
    );
    accepted(&a.push(&id, &server.url), "push after rebase");

    // B sees both devices' commits: nothing was overwritten.
    let f = b.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", server.url),
    ]);
    assert!(f.ok, "fetch must succeed: {}", f.stderr);
    assert_eq!(b.commit_count(&id), 3, "genesis commit + B's + rebased A's");
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
        assert_eq!(u.commit_count(&id), 1, "{algo}: one genesis commit");
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
        v["newer_tip_reported"].is_boolean(),
        "answer must say whether a peer reported a newer tip: {v}"
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
    assert_eq!(v["newer_tip_reported"], false, "peer is at our tip: {v}");
}

/// Claim: when a queried peer holds a newer tip than the local view, verify
/// reports that fact rather than vouching for the stale tip. End-to-end: yes
/// (two peers, one lagging). Turns red on: a verify that ignores peer tips
/// (`newer_tip_reported` false) or that answers "current" from the local view.
#[test]
fn verify_reports_newer_tip_from_a_peer() {
    let lagging = Server::start();
    let ahead = Server::start();
    let a = User::new();
    let id = a.new_identity();
    accepted(&a.push(&id, &lagging.url), "push to lagging");
    accepted(&a.push(&id, &ahead.url), "push to ahead");
    a.add_key(&id);
    accepted(&a.push(&id, &ahead.url), "push newer commit to ahead only");

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
        v["newer_tip_reported"], true,
        "the ahead peer's newer tip must be reported: {v}"
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
