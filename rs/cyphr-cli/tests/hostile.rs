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

    /// The server's whole history for `id`: one blob list per commit.
    fn chain(&self, id: &str) -> Vec<Vec<Vec<u8>>> {
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
            .map(|e| {
                e["blobs"]
                    .as_array()
                    .expect("blobs")
                    .iter()
                    .map(|b| Base64UrlUnpadded::decode_vec(b.as_str().expect("str")).expect("b64"))
                    .collect()
            })
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
fn reserialized_patch(chain: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let entries: Vec<Value> = chain
        .iter()
        .enumerate()
        .map(|(i, blobs)| {
            let blobs: Vec<String> = blobs
                .iter()
                .map(|b| {
                    let Value::Object(m) = serde_json::from_slice::<Value>(b).expect("json") else {
                        panic!("blob is not an object")
                    };
                    let reversed: serde_json::Map<String, Value> = m.into_iter().rev().collect();
                    Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec_pretty(&Value::Object(reversed)).expect("pretty"),
                    )
                })
                .collect();
            serde_json::json!({"commit_id": format!("c{i}"), "sequence": i, "pr": "p", "blobs": blobs})
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
    let real = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let pushed = a.peer_cmd("push", &id, &real.url);
    assert!(pushed.ok, "setup push: {}", pushed.stderr);
    let body = reserialized_patch(&real.chain(&id));
    let peer = Hostile::start(move |_| Reply::Body(body.clone()));
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

/// Claim: rebase against a peer that re-serializes the shared prefix finds
/// nothing to move and leaves the store alone. Turns red on a "duplicate
/// key" failure from replaying onto a mis-detected empty common prefix.
#[test]
fn reserialized_chain_does_not_break_rebase() {
    let (a, id, peer, _real) = reserialized_world();
    a.add_key(&id);
    let r = a.peer_cmd("rebase", &id, &peer.url);
    assert!(
        r.ok,
        "rebase over an equal prefix must succeed: {}",
        r.stderr
    );
    assert_eq!(r.json()["rebased"], 0);
    assert_eq!(a.commit_count(&id), 2, "local history untouched");
    assert!(
        siblings(&a.store(), "data.").is_empty(),
        "no scratch or backup left"
    );
}

// ------------------------------------------------- 2. failed rebase scratch

/// Claim: a rebase that fails while building the new store leaves no
/// scratch directory behind, so the next rebase is not refused for it, and
/// the original store is intact. Turns red on a leftover `data.rebase`.
#[test]
fn failed_rebase_cleans_up_its_scratch_store() {
    let real = Server::start();
    let a = User::new();
    let id = a.new_identity();
    let b = a.clone_identity();
    b.add_key(&id);
    assert!(b.peer_cmd("push", &id, &real.url).ok, "B pushes");
    a.add_key(&id);

    // The peer serves B's chain with the last commit's signature damaged.
    let mut chain = real.chain(&id);
    let last = chain.last_mut().and_then(|c| c.last_mut()).expect("a blob");
    let mut v: Value = serde_json::from_slice(last).expect("json");
    let sig = v["sig"].as_str().expect("sig").to_owned();
    let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
    v["sig"] = format!("{flipped}{}", &sig[1..]).into();
    *last = serde_json::to_vec(&v).expect("json");
    let body = reserialized_patch(&chain);
    let peer = Hostile::start(move |_| Reply::Body(body.clone()));

    let first = a.peer_cmd("rebase", &id, &peer.url);
    assert!(!first.ok, "a damaged peer chain must fail the rebase");
    assert!(
        siblings(&a.store(), "data.").is_empty(),
        "scratch left: {:?}",
        siblings(&a.store(), "data.")
    );
    let second = a.peer_cmd("rebase", &id, &peer.url);
    assert!(
        !second.stderr.contains("rebase workspace"),
        "the retry must fail for the real cause, not the leftover: {}",
        second.stderr
    );
    assert_eq!(a.commit_count(&id), 2, "the original store is intact");
}

// ------------------------------------------------- 3. interrupted swap

/// Claim: a store that has gone missing next to a rebase backup (the
/// process died between the two renames) is refused with an error naming
/// the backup, never silently replaced by a new empty store. Turns red on
/// a CLI that creates `data` afresh.
#[test]
fn interrupted_rebase_swap_is_refused_not_emptied() {
    let a = User::new();
    let id = a.new_identity();
    let backup = a.dir.path().join("data.pre-rebase-1700000000");
    std::fs::rename(a.store(), &backup).expect("simulate the first rename");

    let r = a.run(&["inspect", &format!("--identity={id}")]);
    assert!(!r.ok, "must refuse to open a store that is missing");
    let msg = r.stderr.lines().last().unwrap_or("");
    assert!(
        msg.contains("data.pre-rebase-1700000000"),
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
#[ignore = "RED(N16): peer requests have no timeout"]
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
#[ignore = "RED(N16): peer response bodies are unbounded"]
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
#[ignore = "RED(N16): peer requests follow redirects"]
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
