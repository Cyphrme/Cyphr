//! The network commands against hostile or faulty peers: the cases an
//! honest-peer suite cannot reach. Every test is an end-to-end scenario
//! (the real `cyphr` binary against real `cyphr-server` processes and/or a
//! scripted peer on a loopback socket).
//!
//! Server-based tests need `cyphr-server`: `CYPHR_SERVER_BIN`, else one
//! `cargo build -p cyphr-server`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
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
    addr: String,
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
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            url: format!("http://{addr}"),
            addr,
            _dir: dir,
        }
    }

    /// The server's whole history for `id`: one bundle per commit (SPEC
    /// 4.6.2).
    fn chain(&self, id: &str) -> Vec<WireBundle> {
        let mut s = TcpStream::connect(&self.addr).expect("connect");
        write!(
            s,
            "GET /patch?pr={id} HTTP/1.1\r\nhost: x\r\nconnection: close\r\naccept: \
             application/json\r\n\r\n"
        )
        .expect("send");
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).expect("read");
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("http response");
        let doc: Value = serde_json::from_slice(&raw[split + 4..]).expect("patch json");
        doc["payload"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|e| serde_json::from_value(e.clone()).expect("entry bundle"))
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What a scripted peer answers to a request.
enum Reply {
    Body(Vec<u8>),
    /// Accept the connection and never answer.
    Hang,
    Redirect(String),
    /// Stream this many bytes of body with no length, then close.
    Flood(usize),
}

/// A scripted peer on a loopback socket. It records every request target.
struct Hostile {
    url: String,
    hits: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Hostile {
    fn start(reply: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let reply = Arc::new(reply);
        let (h, st) = (hits.clone(), stop.clone());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let (h, st, reply) = (h.clone(), st.clone(), reply.clone());
                std::thread::spawn(move || serve(conn, &*reply, &h, &st));
            }
        });
        Self { url, hits, stop }
    }

    fn hits(&self) -> Vec<String> {
        self.hits.lock().expect("hits").clone()
    }
}

impl Drop for Hostile {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(
    conn: TcpStream,
    reply: &dyn Fn(&str) -> Reply,
    hits: &Mutex<Vec<String>>,
    stop: &AtomicBool,
) {
    let mut reader = BufReader::new(conn.try_clone().expect("clone"));
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    let target = first.split_whitespace().nth(1).unwrap_or("").to_owned();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }
    hits.lock().expect("hits").push(target.clone());
    let mut out = conn;
    match reply(&target) {
        Reply::Body(b) => {
            let _ = write!(
                out,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                 {}\r\nconnection: close\r\n\r\n",
                b.len()
            );
            let _ = out.write_all(&b);
        },
        Reply::Hang => {
            let until = Instant::now() + Duration::from_secs(120);
            while !stop.load(Ordering::Relaxed) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(100));
            }
        },
        Reply::Redirect(to) => {
            let _ = write!(
                out,
                "HTTP/1.1 302 Found\r\nlocation: {to}\r\ncontent-length: 0\r\nconnection: \
                 close\r\n\r\n"
            );
        },
        Reply::Flood(n) => {
            let _ = write!(out, "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n");
            let chunk = vec![b' '; 1 << 20];
            let mut sent = 0;
            while sent < n && out.write_all(&chunk).is_ok() {
                sent += chunk.len();
            }
        },
    }
}

/// A patch envelope serving `chain`, with every blob re-serialized the way
/// a different but honest JSON writer would: pretty-printed, members in
/// reverse order. Signatures and digests are untouched, so a canonical
/// reader sees exactly the victim's history.
fn reserialized_patch(chain: &[WireBundle]) -> Vec<u8> {
    patch_with(chain, false)
}

/// As [`reserialized_patch`]; with `unsigned_extras`, each blob also gains
/// an unsigned top-level member and each `keys` entry a different `tag` and
/// `now`, none of which a signature binds.
fn patch_with(chain: &[WireBundle], unsigned_extras: bool) -> Vec<u8> {
    let rewrite = |b: &Vec<u8>| {
        let Value::Object(mut m) = serde_json::from_slice::<Value>(b).expect("json") else {
            panic!("blob is not an object")
        };
        if unsigned_extras {
            m.insert("lm_extra".into(), 1.into());
        }
        let reversed: serde_json::Map<String, Value> = m.into_iter().rev().collect();
        Base64UrlUnpadded::encode_string(
            &serde_json::to_vec_pretty(&Value::Object(reversed)).expect("pretty"),
        )
    };
    let entries: Vec<Value> = chain
        .iter()
        .enumerate()
        .map(|(i, bundle)| {
            let txs: Vec<Vec<String>> = bundle
                .txs
                .iter()
                .map(|tx| tx.iter().map(rewrite).collect())
                .collect();
            let actions: Vec<String> = bundle.actions.iter().map(rewrite).collect();
            let keys: Vec<Value> = bundle
                .keys
                .iter()
                .map(|k| {
                    let mut k = serde_json::to_value(k).expect("key");
                    if unsigned_extras {
                        k["tag"] = "relabelled".into();
                        k["now"] = 7.into();
                    }
                    k
                })
                .collect();
            serde_json::json!({"commit_id": format!("c{i}"), "sequence": i, "pr": "p",
                "txs": txs, "actions": actions, "keys": keys})
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "payload": {"principal_id": "x", "entries": entries},
        "statement": {"kind": "unsigned"},
    }))
    .expect("serialize")
}

fn empty_patch() -> Vec<u8> {
    reserialized_patch(&[])
}

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
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}): {:?} / {}",
                self.stdout, self.stderr
            )
        })
    }

    fn error_kind(&self) -> String {
        let last = self.stderr.lines().last().unwrap_or("");
        let v: Value = serde_json::from_str(last)
            .unwrap_or_else(|e| panic!("stderr is not a JSON error ({e}): {}", self.stderr));
        v["error"]["kind"].as_str().unwrap_or("").to_owned()
    }
}

impl User {
    fn new() -> Self {
        Self {
            dir: TempDir::new().expect("user tempdir"),
        }
    }

    fn store(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn run(&self, args: &[&str]) -> Ran {
        let out = Command::new(env!("CARGO_BIN_EXE_cyphr"))
            .arg("--keystore")
            .arg(self.dir.path().join("keys.json"))
            .arg("--store")
            .arg(format!("file:{}", self.store().display()))
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

    fn setup(&self, args: &[&str]) -> Value {
        let r = self.run(args);
        assert!(r.ok, "setup `{args:?}` failed: {}", r.stderr);
        r.json()
    }

    /// A fresh identity with two commits: the genesis commit the CLI makes
    /// before its first key add, then that key add.
    fn new_identity(&self) -> String {
        let g = self.setup(&["key", "generate", "--algo", "ES256"]);
        let tmb = g["tmb"].as_str().expect("tmb").to_owned();
        self.add_key(&tmb);
        tmb
    }

    fn add_key(&self, id: &str) {
        self.setup(&[
            "key",
            "add",
            &format!("--identity={id}"),
            &format!("--signer={id}"),
        ]);
    }

    fn clone_identity(&self) -> Self {
        let other = Self::new();
        std::fs::copy(
            self.dir.path().join("keys.json"),
            other.dir.path().join("keys.json"),
        )
        .expect("copy keystore");
        copy_dir(&self.store(), &other.store());
        other
    }

    fn peer_cmd(&self, cmd: &str, id: &str, peer: &str) -> Ran {
        self.run(&[cmd, &format!("--identity={id}"), &format!("--peer={peer}")])
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
        let entry = entry.expect("entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).expect("copy");
        }
    }
}

fn siblings(store: &Path, prefix: &str) -> Vec<String> {
    std::fs::read_dir(store.parent().expect("parent"))
        .expect("read parent")
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefix))
        .collect()
}

// ------------------------------------------------- 1. canonical identity

/// A victim's own chain, re-served byte-different but signature-equal.
/// Returns (user, id, hostile peer serving the re-serialized chain).
fn reserialized_world() -> (User, String, Hostile, Server) {
    world(false)
}

fn world(unsigned_extras: bool) -> (User, String, Hostile, Server) {
    world_serving(|chain| patch_with(chain, unsigned_extras))
}

/// A user pushed to a real server, and a hostile peer that serves the
/// user's own chain as `patch` builds it.
fn world_serving(patch: impl FnOnce(&[WireBundle]) -> Vec<u8>) -> (User, String, Hostile, Server) {
    let real = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let pushed = a.peer_cmd("push", &id, &real.url);
    assert!(pushed.ok, "setup push: {}", pushed.stderr);
    let chain = real.chain(&id);
    let body = patch(&chain);
    // The pull step reads heads and revokes before the patch; a head names
    // a tip the verifier does not hold, so it reads the patch itself.
    let branches = serde_json::to_vec(&serde_json::json!({"v": 1, "payload": {"branches": [
        {"tip": "unknown", "sequence": chain.len() - 1, "canonical": true}]}}))
    .expect("branches");
    let revoked = br#"{"v":1,"payload":{"revoked":[]}}"#.to_vec();
    let nothing_after = empty_patch();
    let peer = Hostile::start(move |target| {
        Reply::Body(match target.split('?').next().unwrap_or_default() {
            "/branches" => branches.clone(),
            "/revoked" => revoked.clone(),
            // From the verifier's tip the peer holds nothing more.
            "/patch" if target.contains("&from=") => nothing_after.clone(),
            _ => body.clone(),
        })
    });
    (a, id, peer, real)
}

/// Claim: a peer that re-serves the victim's own history with different
/// whitespace and member order is the same history, not a fork: verify
/// reports Active with no evidence. Turns red on a byte comparison of blobs
/// (verify reports `principal_fork` at height 0). End-to-end: yes.
#[test]
fn reserialized_chain_is_not_a_fork_in_verify() {
    let (a, id, peer, _real) = reserialized_world();
    let r = a.run(&[
        "verify",
        &format!("--identity={id}"),
        &format!("--peer={}", peer.url),
    ]);
    assert!(r.ok, "verify must answer: {}", r.stderr);
    let v = r.json();
    assert_eq!(
        v["verdict"], "Active",
        "same history under another encoding: {v}"
    );
    assert!(v.get("evidence").is_none(), "no evidence of a fork: {v}");
    // The default anchor is the identity itself, so the answer must say its
    // anchor check is trivially satisfied.
    assert_eq!(v["anchor"]["is_identity"], true, "anchor provenance: {v}");
}

/// Claim (SPEC 6.2, 14.12): a peer that serves an action signed by a key the
/// principal never held gets a refusal from fetch, not a silent drop: only
/// an action whose signer the principal once held is ignored when its
/// history voids it. Turns red if fetch skips the stranger's action and
/// reports success (the shape of a refusal for an inactive signer is the
/// same either way; only the signer's history tells them apart).
#[test]
fn fetch_refuses_an_action_by_a_never_held_key() {
    let stranger = coz::Alg::ES256.generate_keypair();
    let tmb = coz::Alg::ES256
        .compute_thumbprint(&stranger.pub_bytes)
        .expect("tmb");
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": "ES256", "msg": "from nobody", "now": 1_700_000_000,
        "tmb": tmb.to_b64(), "typ": "cyphr.me/comment/create",
    }))
    .expect("pay");
    let (sig, _cad) =
        coz::sign_json(&pay, "ES256", &stranger.prv_bytes, &stranger.pub_bytes).expect("sign");
    let action = serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<Value>(&pay).expect("pay json"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("action");
    let (a, id, peer, _real) = world_serving(|chain| {
        let mut body: Value = serde_json::from_slice(&patch_with(chain, false)).expect("patch");
        body["payload"]["actions"] =
            serde_json::json!([{"blobs": [Base64UrlUnpadded::encode_string(&action)]}]);
        serde_json::to_vec(&body).expect("body")
    });
    a.add_key(&id);
    let r = a.peer_cmd("fetch", &id, &peer.url);
    assert!(
        !r.ok,
        "an action by a key the principal never held must be refused: {}",
        r.stdout
    );
}

/// Claim: fetch from a peer that re-serializes our own history stores
/// nothing and fails nothing. Turns red on "diverges at commit 0".
#[test]
fn reserialized_chain_is_not_a_fork_in_fetch() {
    let (a, id, peer, _real) = reserialized_world();
    a.add_key(&id);
    let r = a.peer_cmd("fetch", &id, &peer.url);
    assert!(
        r.ok,
        "fetch of an equal-by-signature prefix must succeed: {}",
        r.stderr
    );
    assert_eq!(r.json()["fetched"], 0);
}

/// Claim: what a signature does not bind (an extra top-level member, the
/// `tag` and `now` of a key sidecar) does not make a different commit, so a
/// peer adding them is serving the same history in verify and fetch.
/// Turns red on a comparison of the whole blob (false fork at height 0,
/// `forked`). End-to-end: yes.
#[test]
fn unsigned_additions_are_not_a_fork_in_verify() {
    let (a, id, peer, _real) = world(true);
    let r = a.run(&[
        "verify",
        &format!("--identity={id}"),
        &format!("--peer={}", peer.url),
    ]);
    assert!(r.ok, "verify must answer: {}", r.stderr);
    let v = r.json();
    assert_eq!(v["verdict"], "Active", "same signed history: {v}");
    assert!(v.get("evidence").is_none(), "no evidence of a fork: {v}");
}

#[test]
fn unsigned_additions_are_not_a_fork_in_fetch() {
    let (a, id, peer, _real) = world(true);
    a.add_key(&id);
    let r = a.peer_cmd("fetch", &id, &peer.url);
    assert!(
        r.ok,
        "fetch of the same signed prefix must succeed: {}",
        r.stderr
    );
    assert_eq!(r.json()["fetched"], 0);
}

// ------------------------------------------------- 2. failed adoption scratch

/// Claim: an adoption (`fetch --trust-remote`) that fails while building the
/// new store leaves no scratch directory behind, so the next one is not
/// refused for it, and the original store is intact. Turns red on a leftover
/// `data.adopt`.
#[test]
fn failed_adoption_cleans_up_its_scratch_store() {
    let real = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity();
    b.add_key(&id);
    assert!(b.peer_cmd("push", &id, &real.url).ok, "B pushes");
    a.add_key(&id);

    // The peer serves B's chain with the last commit's signature damaged.
    let mut chain = real.chain(&id);
    let last = chain
        .last_mut()
        .and_then(|c| c.txs.last_mut())
        .and_then(|tx| tx.last_mut())
        .expect("a blob");
    let mut v: Value = serde_json::from_slice(last).expect("json");
    let sig = v["sig"].as_str().expect("sig").to_owned();
    let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
    v["sig"] = format!("{flipped}{}", &sig[1..]).into();
    *last = serde_json::to_vec(&v).expect("json");
    let body = reserialized_patch(&chain);
    let peer = Hostile::start(move |_| Reply::Body(body.clone()));

    let first = a.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", peer.url),
        "--trust-remote",
    ]);
    assert!(!first.ok, "a damaged peer chain must fail the adoption");
    assert!(
        siblings(&a.store(), "data.").is_empty(),
        "scratch left: {:?}",
        siblings(&a.store(), "data.")
    );
    let second = a.run(&[
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", peer.url),
        "--trust-remote",
    ]);
    assert!(
        !second.stderr.contains("swap workspace"),
        "the retry must fail for the real cause, not the leftover: {}",
        second.stderr
    );
    assert_eq!(
        a.commit_count(&id),
        3,
        "the original store is intact: genesis, setup add, our add"
    );
}

// ------------------------------------------------- 3. interrupted swap

/// Claim: a store that has gone missing next to a swap backup (the
/// process died between the two renames) is refused with an error naming
/// the backup, never silently replaced by a new empty store. Turns red on
/// a CLI that creates `data` afresh.
#[test]
fn interrupted_swap_is_refused_not_emptied() {
    let a = User::new();
    let id = a.new_identity();
    let backup = a.dir.path().join("data.pre-adopt-1700000000");
    std::fs::rename(a.store(), &backup).expect("simulate the first rename");

    let r = a.run(&["inspect", &format!("--identity={id}")]);
    assert!(!r.ok, "must refuse to open a store that is missing");
    let msg = r.stderr.lines().last().unwrap_or("");
    assert!(
        msg.contains("data.pre-adopt-1700000000"),
        "names the backup: {msg}"
    );
    assert!(
        !a.store().exists(),
        "no empty store may be created in its place"
    );
}

// ------------------------------------------------- 4. bounded peer I/O

/// Claim: a peer that accepts and never answers fails the command with the
/// typed `unreachable` kind within the timeout, instead of hanging.
#[test]
fn silent_peer_times_out() {
    let a = User::new();
    let id = a.new_identity();
    let peer = Hostile::start(|_| Reply::Hang);
    let start = Instant::now();
    let r = a.run(&[
        "--peer-timeout-secs=1",
        "fetch",
        &format!("--identity={id}"),
        &format!("--peer={}", peer.url),
    ]);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "returned in {:?}",
        start.elapsed()
    );
    assert!(!r.ok);
    assert_eq!(r.error_kind(), "unreachable", "{}", r.stderr);
}

/// Claim: an oversized response body is refused with the typed `toolarge`
/// kind rather than buffered whole. Turns red on an unbounded read (the
/// 66 MiB body is read and then fails as `malformed`).
#[test]
fn oversized_response_is_refused() {
    let a = User::new();
    let id = a.new_identity();
    let peer = Hostile::start(|_| Reply::Flood(66 << 20));
    let r = a.peer_cmd("fetch", &id, &peer.url);
    assert!(!r.ok);
    assert_eq!(r.error_kind(), "toolarge", "{}", r.stderr);
}

/// Claim: a redirect is not followed (it could leave the peer the user
/// chose, including to a plaintext host). Turns red when the second host is
/// contacted.
#[test]
fn redirect_is_not_followed() {
    let a = User::new();
    let id = a.new_identity();
    let elsewhere = Hostile::start(|_| Reply::Body(empty_patch()));
    let to = elsewhere.url.clone();
    let peer = Hostile::start(move |_| Reply::Redirect(format!("{to}/patch")));
    let r = a.peer_cmd("fetch", &id, &peer.url);
    assert!(!r.ok, "a redirect is a refusal, not an answer");
    assert!(
        elsewhere.hits().is_empty(),
        "the redirect target was contacted: {:?}",
        elsewhere.hits()
    );
}
