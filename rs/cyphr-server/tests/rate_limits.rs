//! Acceptance suite for the server-side resource fences: per-IP / per-operation
//! RATE limits, a request-SIZE cap over ALL routes, and a per-principal
//! commit-COUNT quota. There is deliberately NO per-principal RATE limit: it
//! keyed on the unverified, attacker-nameable `principal_id` peeked from a raw
//! `/push` body, so an unauthenticated attacker could throttle a victim's own
//! pushes merely by naming them (see `anti_griefing_...` below). The write path
//! is bounded instead by the per-IP rate (the real, un-nameable TCP peer) and
//! the durable per-principal count quota (which reads uninflatable stored
//! state).
//!
//! Like the admission fence, these are composed ONLY in `serve()`, never in
//! `build_router` (they are orthogonal to the protocol; `build_router` stays
//! the standing strip test and never sees a limiter). The whole in-process
//! harness drives `build_router` via `oneshot`, so it structurally CANNOT
//! exercise a fence that only exists on the running binary. This suite
//! therefore boots the real `cyphr-server` binary as a subprocess on an
//! ephemeral port and drives it over HTTP -- the same seam `tests/admission.rs`
//! uses, and the only seam where the `serve()`-composed layers are live. Per-IP
//! keying in particular is meaningful only over a real socket: the limiter keys
//! on the peer address the kernel reports (`ConnectInfo<SocketAddr>`), which
//! `oneshot` cannot supply.
//!
//! The fences are configured through a `[limits]` TOML table on `ServerConfig`
//! (additive to `[admission]`, mirroring its structured-config pattern).
//!
//! ## The `[limits]` schema this suite pins
//!
//! Each rate bucket is a `{ per_second, burst }` pair: `per_second` is the
//! sustained replenish rate (requests/sec) and `burst` the bucket capacity.
//! ```toml
//! [limits]
//! max_body_bytes = 2097152                       # request size cap (bytes), ALL routes
//! count_quota    = 1000000                        # per-principal hard commit cap
//! per_ip        = { per_second = N, burst = N }   # keyed on peer address
//! read          = { per_second = N, burst = N }   # per-op: reads (generous)
//! push          = { per_second = N, burst = N }   # per-op: push  (tightest)
//! login         = { per_second = N, burst = N }   # per-op: login/challenge
//! revoke        = { per_second = N, burst = N }   # per-op: /revoke (ORDINARY)
//! ```
//! The implementation owns `config.rs`; if the architect reshapes this table,
//! these tests move in lockstep within the node.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use socket2::{Domain, Socket, Type};
use tempfile::TempDir;

// A distinct, deterministic `now` per principal keeps genesis blob bytes (and
// therefore blob hashes) disjoint across principals, so two resident principals
// never collide in the content-addressed blob store.
const NOW_BASE: i64 = 1_700_000_000;

// A small tripping bucket: capacity 2, replenishing 1/sec. A tight burst well
// past the capacity exhausts it deterministically (replenish over the burst's
// sub-second window is negligible), so at least one request 429s once the fence
// exists; today none do.
const TRIP_PER_SECOND: u64 = 1;
const TRIP_BURST: u32 = 2;
// Requests fired in a tripping burst -- far past `TRIP_BURST` so the 429 does
// not hinge on exact timing.
const BURST: usize = 25;
// A modest burst at capacity: never trips a correctly-sized bucket.
const MODEST: usize = 2;

// ========================================================================
// `[limits]` config builder
// ========================================================================

/// Renders a `[limits]` table. `generous()` sets every bucket high enough that
/// no test-scale burst trips it and the quota/size are effectively unbounded;
/// each test lowers ONLY the fence under test, so a 429/413/quota-refusal is
/// unambiguously attributable to that fence and not an unrelated one.
struct Limits {
    max_body_bytes: u64,
    count_quota: u64,
    per_ip: (u64, u32),
    read: (u64, u32),
    push: (u64, u32),
    login: (u64, u32),
    revoke: (u64, u32),
}

impl Limits {
    fn generous() -> Self {
        let wide = (100_000, 100_000);
        Limits {
            max_body_bytes: 2 * 1024 * 1024,
            count_quota: 1_000_000,
            per_ip: wide,
            read: wide,
            push: wide,
            login: wide,
            revoke: wide,
        }
    }

    fn render(&self) -> String {
        let bucket = |b: (u64, u32)| format!("{{ per_second = {}, burst = {} }}", b.0, b.1);
        format!(
            "[limits]\nmax_body_bytes = {}\ncount_quota = {}\nper_ip = {}\nread = {}\npush = \
             {}\nlogin = {}\nrevoke = {}\n",
            self.max_body_bytes,
            self.count_quota,
            bucket(self.per_ip),
            bucket(self.read),
            bucket(self.push),
            bucket(self.login),
            bucket(self.revoke),
        )
    }
}

// ========================================================================
// Subprocess server harness (mirrors tests/admission.rs)
// ========================================================================

/// Path to the compiled `cyphr-server` binary, resolved beside this test binary
/// (`<target>/debug/deps/..` -> `<target>/debug/cyphr-server`).
fn server_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("deps dir")
        .parent()
        .expect("profile dir")
        .join("cyphr-server")
}

/// Read the server's resolved bind port from its stdout: it binds the ephemeral
/// port itself (`:0`) and prints exactly one `listening on <addr>` line once
/// bound. Reading the real bound port removes the free-then-rebind window a
/// test-side reservation would open.
fn read_reported_port(child: &mut Child) -> u16 {
    use std::io::BufRead;
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    let read = reader.read_line(&mut line).expect("read server stdout");
    assert_ne!(
        read, 0,
        "server stdout closed before reporting bind address"
    );
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected first server stdout line: {line:?}"));
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("unparseable server bind address: {addr:?}"))
}

/// A running `cyphr-server` subprocess plus the temp dir backing its store.
/// Dropping it kills the child and removes the store.
struct TestServer {
    child: Child,
    port: u16,
    _tmp: TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestServer {
    /// Boot with the given `[limits]` table and no admission policy.
    fn with_limits(limits: &Limits) -> TestServer {
        Self::boot(tempfile::tempdir().expect("tempdir"), &limits.render())
    }

    /// Boot a server whose config carries `extra` (raw TOML appended after the
    /// base `listen`/`data_dir`), and wait until it accepts connections.
    fn boot(tmp: TempDir, extra: &str) -> TestServer {
        let data_dir = tmp.path().join("data");
        let config_path = tmp.path().join("cyphr-server.toml");
        let config = format!(
            "listen = \"127.0.0.1:0\"\ndata_dir = {data:?}\n\n{extra}",
            data = data_dir,
        );
        std::fs::write(&config_path, config).expect("write config");

        let mut child = Command::new(server_binary())
            .arg("--config")
            .arg(&config_path)
            .arg("serve")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn cyphr-server");

        let port = read_reported_port(&mut child);
        let server = TestServer {
            child,
            port,
            _tmp: tmp,
        };
        server.wait_ready();
        server
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("server did not become ready on port {}", self.port);
    }

    fn get(&self, path: &str) -> HttpResponse {
        self.request("GET", path, None, "127.0.0.1")
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        self.request("POST", path, Some(body), "127.0.0.1")
    }

    /// Issue one request over a fresh connection bound to `source_ip` (loopback
    /// alias). The server sees `source_ip` as the peer address, so per-IP
    /// keying can be exercised with distinct synthesized clients. `Connection:
    /// close` -> the server closes after the response, so read-to-EOF yields
    /// the whole message.
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        source_ip: &str,
    ) -> HttpResponse {
        let mut stream = connect_from(source_ip, self.port);
        let body = body.unwrap_or("");
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if !body.is_empty() || method == "POST" {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .expect("write request head");
        stream
            .write_all(body.as_bytes())
            .expect("write request body");
        stream.flush().expect("flush");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read response");
        HttpResponse::parse(&raw)
    }

    /// Issue one POST whose body is sent with `Transfer-Encoding: chunked` and
    /// NO `Content-Length` header, so the request carries no declared length.
    /// This is the case the merged size fence's `Content-Length` check cannot
    /// see: a non-push route with a chunked over-cap body slips the header
    /// check and falls back to axum's 2 MiB default extractor limit rather than
    /// `max_body_bytes`. A single chunk carries the whole body.
    fn post_chunked(&self, path: &str, body: &str) -> HttpResponse {
        let mut stream = connect_from("127.0.0.1", self.port);
        let mut req = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: \
             application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        // One chunk: `<hex-len>\r\n<bytes>\r\n`, then the terminating `0` chunk.
        req.push_str(&format!("{:x}\r\n", body.len()));
        req.push_str(body);
        req.push_str("\r\n0\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .expect("write chunked request");
        stream.flush().expect("flush");

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read response");
        HttpResponse::parse(&raw)
    }

    /// Fire `n` identical requests as fast as possible from `source_ip` and
    /// return every status. Fresh connection per request (the harness default).
    fn burst(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        source_ip: &str,
        n: usize,
    ) -> Vec<u16> {
        (0..n)
            .map(|_| self.request(method, path, body, source_ip).status)
            .collect()
    }
}

/// Open a TCP connection to the server from an explicit loopback `source_ip`.
///
/// On Linux the whole `127.0.0.0/8` block is loopback, so binding the client
/// socket to e.g. `127.0.0.2` and connecting to `127.0.0.1` makes the server's
/// `accept()` report `127.0.0.2` as the peer -- the only way to present the
/// per-IP fence with genuinely distinct clients over loopback.
fn connect_from(source_ip: &str, port: u16) -> TcpStream {
    let src: SocketAddr = format!("{source_ip}:0").parse().expect("source addr");
    let dst = SocketAddr::from(([127, 0, 0, 1], port));
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).expect("socket");
    sock.bind(&src.into())
        .unwrap_or_else(|e| panic!("bind source {source_ip}: {e}"));
    sock.connect(&dst.into()).expect("connect");
    let stream: TcpStream = sock.into();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    stream
}

/// A parsed HTTP response: status code plus the raw body string.
struct HttpResponse {
    status: u16,
    body: String,
}

impl HttpResponse {
    fn parse(raw: &[u8]) -> HttpResponse {
        let text = String::from_utf8_lossy(raw);
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("no status line in response: {text:?}"));
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        HttpResponse { status, body }
    }
}

fn some_429(statuses: &[u16]) -> bool {
    statuses.contains(&429)
}

// ========================================================================
// Push bodies
// ========================================================================

/// A brand-new principal's genesis push body (golden key adds `key_a`).
fn genesis_body(principal_id: &str, now: i64) -> String {
    let pool = common::load_pool();
    common::build_genesis_push_body(&pool, principal_id, now)
}

/// A push body's blob list, base64url-encoded, wrapped with `principal_id`.
fn push_body(pid: &str, blobs: &[Vec<u8>]) -> String {
    serde_json::json!({
        "principal_id": pid,
        "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
    })
    .to_string()
}

/// The genesis `cyphr::Key` for pool key `name` (`first_seen` 0, like a fixture
/// genesis).
fn genesis_key(pool: &test_fixtures::Pool, name: &str) -> cyphr::Key {
    let k = pool.get(name).expect("genesis key in pool");
    cyphr::Key {
        alg: k.alg.clone(),
        tmb: k.compute_tmb().expect("genesis tmb"),
        pub_key: Base64UrlUnpadded::decode_vec(&k.pub_key).expect("genesis pub b64"),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Append a fresh "add `new_key_name`" commit onto `principal`, signed by
/// `signer_name`, and return the new commit's raw coz blobs, wire-ready. Takes
/// `&mut principal` so a caller can build a genesis and a valid follow-on onto
/// the SAME principal in sequence (a fresh `Principal::clone()` would share the
/// durable log rather than deep-copy, colliding two "next commits" on one leaf).
/// The key-introducing cozy carries its new key embedded, as the wire path
/// expects.
fn append_key_create(
    principal: &mut cyphr::Principal,
    pool: &test_fixtures::Pool,
    signer_name: &str,
    new_key_name: &str,
    now: i64,
) -> Vec<Vec<u8>> {
    let signer = pool.get(signer_name).expect("signer key in pool");
    let new_key = pool.get(new_key_name).expect("new key in pool");

    let signer_tmb_b64 = signer.compute_tmb_b64().expect("signer tmb");
    let new_tmb_b64 = new_key.compute_tmb_b64().expect("new key tmb");

    // Alphabetical field order matches the server's `canonicalize_value`
    // `sort_keys()`, which it re-derives before verifying; any other order
    // would make the signature mismatch what the server recomputes.
    let pay_value = serde_json::json!({
        "alg": signer.alg,
        "id": new_tmb_b64,
        "now": now,
        "tmb": signer_tmb_b64,
        "typ": "cyphr.me/cyphr/key/create",
    });
    let pay_vec = serde_json::to_vec(&pay_value).unwrap();

    let signer_prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("signer prv"))
        .expect("valid signer prv base64");
    let signer_pub =
        Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("valid signer pub base64");
    let (sig_bytes, cad) = coz::sign_json(&pay_vec, &signer.alg, &signer_prv, &signer_pub)
        .expect("signing supported for this algorithm");
    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer.alg).expect("czd for this algorithm");

    let new_cyphr_key = cyphr::Key {
        alg: new_key.alg.clone(),
        tmb: coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(&new_tmb_b64).expect("valid new key tmb base64"),
        ),
        pub_key: Base64UrlUnpadded::decode_vec(&new_key.pub_key).expect("valid new key pub base64"),
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let mut scope = principal.begin_commit();
    scope
        .verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_cyphr_key))
        .expect("key/create should verify against the current principal state");

    let signer_tmb = coz::Thumbprint::from_bytes(
        Base64UrlUnpadded::decode_vec(&signer_tmb_b64).expect("valid signer tmb base64"),
    );
    scope
        .finalize_with_arrow(
            &signer.alg,
            &signer_prv,
            &signer_pub,
            &signer_tmb,
            now,
            "cyphr.me",
        )
        .expect("commit should finalize");

    let entries = cyphr_storage::export_commits(principal).expect("export the new commit");
    let new_commit = entries.last().expect("at least one commit after finalize");

    // The wire format expects the introduced key embedded directly on the
    // key-introducing cozy; `export_commits` carries it separately.
    let mut key_idx = 0;
    new_commit
        .cozies
        .iter()
        .map(|v| {
            let mut coz = v.clone();
            let typ = coz["pay"]["typ"].as_str().unwrap_or("");
            if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < new_commit.keys.len() {
                let key = &new_commit.keys[key_idx];
                coz.as_object_mut().unwrap().insert(
                    "key".to_string(),
                    serde_json::json!({ "alg": key.alg, "pub": key.pub_key, "tmb": key.tmb }),
                );
                key_idx += 1;
            }
            serde_json::to_vec(&coz).expect("cozy serializes")
        })
        .collect()
}

/// Build a genesis push body AND a valid follow-on push body for the SAME
/// principal, sharing one principal instance so the follow-on legitimately
/// chains onto the genesis. The follow-on is a genesis-less "add key_b" commit
/// the protocol accepts once the principal is resident -- so the ONLY thing that
/// can refuse it is the count quota.
fn genesis_and_followon(pid: &str, now: i64) -> (String, String) {
    let pool = common::load_pool();
    let gkey = genesis_key(&pool, "golden");
    let mut principal = cyphr::Principal::implicit(gkey.clone()).expect("implicit genesis");

    // Genesis commit: golden adds key_a.
    let mut g_blobs = append_key_create(&mut principal, &pool, "golden", "key_a", now);
    // The closing cozy of a never-before-seen genesis carries the embedded
    // genesis key `resolve_genesis` re-derives the principal from.
    let closing = g_blobs.len() - 1;
    let mut c: serde_json::Value = serde_json::from_slice(&g_blobs[closing]).unwrap();
    c.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!({
            "alg": gkey.alg,
            "pub": pool.get("golden").unwrap().pub_key,
            "tmb": Base64UrlUnpadded::encode_string(gkey.tmb.as_bytes()),
        }),
    );
    g_blobs[closing] = serde_json::to_vec(&c).unwrap();

    // Follow-on commit: golden (still active) adds key_b onto the same chain.
    let f_blobs = append_key_create(&mut principal, &pool, "golden", "key_b", now + 1);

    (push_body(pid, &g_blobs), push_body(pid, &f_blobs))
}

// ========================================================================
// Per-IP rate limit: keyed on peer address (ConnectInfo wired)
// ========================================================================

/// RED today: with a small per-IP bucket (everything else generous) a burst
/// from ONE synthesized client eventually 429s, while a DISTINCT client IP
/// buckets independently. Today no limiter exists, so no request ever 429s and
/// the "some 429" assertion fails behaviorally. Green once the per-IP
/// `GovernorLayer` is composed AND `serve()` wires `ConnectInfo<SocketAddr>`
/// (without it the peer-key extractor cannot key and the burst never 429s).
#[test]
fn per_ip_rate_limit_burst_429s_and_isolates_by_ip() {
    let mut limits = Limits::generous();
    limits.per_ip = (TRIP_PER_SECOND, TRIP_BURST);
    let server = TestServer::with_limits(&limits);

    let from_a = server.burst("GET", "/tip?pr=nobody", None, "127.0.0.1", BURST);
    assert!(
        some_429(&from_a),
        "a per-IP burst past the bucket must yield at least one 429: {from_a:?}"
    );

    // A distinct source IP is a distinct bucket: a modest burst from it, after
    // the first client is throttled, must NOT be collateral-throttled.
    let from_b = server.burst("GET", "/tip?pr=nobody", None, "127.0.0.2", MODEST);
    assert!(
        !some_429(&from_b),
        "a distinct client IP must bucket independently (no shared/global limiter): {from_b:?}"
    );
}

// ========================================================================
// Per-operation limits: independent buckets; reads survive a
// push flood; /revoke takes ORDINARY limits, no exemption
// ========================================================================

/// RED today: with a small PUSH bucket but a generous per-IP and READ bucket, a
/// push flood eventually 429s while a read on the same connection-IP still
/// succeeds -- proving the per-operation buckets are independent, not one shared
/// pool. Distinct `principal_id` per push keeps the (generous) per-principal
/// fence out of the picture, isolating the per-op push bucket. Today the push
/// flood never 429s.
#[test]
fn per_operation_push_bucket_limits_reads_independent() {
    let mut limits = Limits::generous();
    limits.push = (TRIP_PER_SECOND, TRIP_BURST);
    let server = TestServer::with_limits(&limits);

    let pushes: Vec<u16> = (0..BURST)
        .map(|i| {
            server
                .post(
                    "/push",
                    &genesis_body(&format!("perop-{i}"), NOW_BASE + i as i64),
                )
                .status
        })
        .collect();
    assert!(
        some_429(&pushes),
        "a push flood past the push bucket must yield at least one 429: {pushes:?}"
    );

    // Reads have their OWN (generous) bucket; the push flood must not have
    // drained them, and per-IP is generous so nothing collateral-throttles.
    let read = server.get("/tip?pr=nobody").status;
    assert_ne!(
        read, 429,
        "reads must bucket independently of pushes -- a push flood must not throttle a read: \
         {read}"
    );
}

/// RED today: `/revoke` takes ORDINARY per-op limits -- NO exemption. A modest
/// revoke burst passes; an abusive burst 429s. Today `/revoke` is never rate
/// limited, so the abusive burst never 429s.
#[test]
fn revoke_takes_ordinary_limits_no_exemption() {
    let mut limits = Limits::generous();
    limits.revoke = (TRIP_PER_SECOND, TRIP_BURST);
    let server = TestServer::with_limits(&limits);

    let modest = server.burst("POST", "/revoke", Some("{}"), "127.0.0.1", MODEST);
    assert!(
        !some_429(&modest),
        "a modest /revoke burst must pass -- ordinary limits, not a stricter fence: {modest:?}"
    );

    let abusive = server.burst("POST", "/revoke", Some("{}"), "127.0.0.1", BURST);
    assert!(
        some_429(&abusive),
        "an abusive /revoke burst must 429 -- /revoke is NOT exempt from rate limits: {abusive:?}"
    );
}

// ========================================================================
// Anti-griefing: a dropped per-principal RATE limit cannot be
// weaponized to throttle a victim by naming its principal_id
// ========================================================================

/// GREEN once the server drops the per-principal RATE limit entirely. Keying
/// a write-path rate bucket on the `principal_id` peeked from the raw `/push`
/// body is unsafe -- that value is any unauthenticated client's to name. So an
/// attacker, from a DISTINCT source IP, bursts garbage `/push` bodies naming a
/// resident VICTIM's `principal_id`; if the rate key is the principal (not
/// the peer IP), the attacker's flood drains the VICTIM's shared bucket across
/// the IP boundary, and the victim's own next legitimate push is 429'd -- a
/// zero-cost targeted DoS. With no per-principal rate limit the victim's push
/// is no longer throttled by traffic it did not send: per-IP rate (keyed on
/// the real, un-nameable peer) and the durable count quota cover the write
/// path without this cross-principal coupling.
///
/// Everything except the per-principal bucket configured below is generous,
/// so the ONLY thing that can 429 the victim is a per-principal rate fence
/// drained by the attacker -- the failure is unambiguously that fence. With
/// the field dropped from `LimitsConfig`, the `per_principal` line below is
/// an unknown `[limits]` key the server ignores, so the victim's follow-on
/// push reaches the handler and commits (2xx).
#[test]
fn anti_griefing_attacker_naming_victim_cannot_throttle_victim() {
    // Generous everywhere, then append a per-principal rate bucket as raw
    // `[limits]` TOML, tight enough that the attacker's burst drains it. This
    // key no longer exists in `LimitsConfig`, so the server ignores this line
    // (it does not deny unknown fields), which is exactly what lets the
    // victim through.
    let limits = Limits::generous();
    let extra = format!(
        "{}per_principal = {{ per_second = {}, burst = {} }}\n",
        limits.render(),
        TRIP_PER_SECOND,
        TRIP_BURST,
    );
    let server = TestServer::boot(tempfile::tempdir().expect("tempdir"), &extra);

    // The victim establishes residency with an active key via its genesis push
    // (from its own IP). Under generous per-op/per-IP limits this succeeds.
    let (genesis, followon) = genesis_and_followon("griefing-victim", NOW_BASE + 700);
    let g = server.request("POST", "/push", Some(&genesis), "127.0.0.1");
    assert_eq!(
        g.status, 201,
        "the victim's genesis push must establish residency: {} {}",
        g.status, g.body
    );

    // The attacker, from a DISTINCT IP, bursts garbage bodies naming the
    // VICTIM's principal_id. Garbage blobs never commit (the handler rejects
    // them), so the victim's chain is untouched -- but a per-principal rate
    // fence keyed on the named principal would drain the victim's bucket.
    let garbage = push_body("griefing-victim", &[b"not a valid commit".to_vec()]);
    let _ = server.burst("POST", "/push", Some(&garbage), "127.0.0.3", BURST);

    // The victim's OWN legitimate follow-on push, from its own IP, must NOT be
    // throttled by the attacker's traffic: with no per-principal rate limit,
    // the follow-on commits.
    let f = server.request("POST", "/push", Some(&followon), "127.0.0.1");
    assert!(
        (200..300).contains(&f.status),
        "a victim's own push must succeed despite an attacker naming its principal_id in a \
         garbage flood -- it must not be 429'd by traffic it did not send: {} {}",
        f.status,
        f.body
    );
}

// ========================================================================
// Request-size cap
// ========================================================================

/// GUARD (green today and after): on the PUSH path an over-cap body is refused
/// 413 before handler work; an under-cap body passes. The cap here (64 KiB) is
/// well below axum's 2 MiB default extractor limit, and the oversized body
/// (256 KiB) sits between the two. The merged fence already caps the push path,
/// so this stays green across the rework; the RED driver for the size fence is
/// the NON-push case below, which the merged fence does not cover.
#[test]
fn request_size_cap_rejects_oversized_body() {
    let mut limits = Limits::generous();
    limits.max_body_bytes = 64 * 1024;
    let server = TestServer::with_limits(&limits);

    // A well-formed push envelope whose single blob is 256 KiB of filler: over
    // the 64 KiB cap, under axum's 2 MiB default.
    let filler = "A".repeat(256 * 1024);
    let oversized = serde_json::json!({ "principal_id": "too-big", "blobs": [filler] }).to_string();
    let over = server.post("/push", &oversized);
    assert_eq!(
        over.status, 413,
        "an over-cap body must be refused 413 (payload too large): {} {}",
        over.status, over.body
    );

    // A normal genesis body is far under the cap and must still be admitted.
    let under = server.post("/push", &genesis_body("size-ok", NOW_BASE + 5));
    assert_ne!(
        under.status, 413,
        "an under-cap body must not be size-refused: {} {}",
        under.status, under.body
    );
}

/// GREEN once `max_body_bytes` is authoritative over ALL routes. The
/// rate-limit fence alone caps only the push path's actual bytes; every other
/// route would otherwise fall back to axum's 2 MiB default extractor limit.
/// Its one all-routes check is on the declared `Content-Length`, which a
/// chunked body carries no value for -- so a NON-push route (`/revoke`) fed a
/// chunked body over `max_body_bytes` but under 2 MiB would slip the header
/// check and be processed by the handler (a non-413 rejection of the junk)
/// instead of being 413'd. A `serve()`-composed body-limit layer applying
/// `max_body_bytes` to every route closes that gap: the oversized chunked
/// body is refused 413 regardless of framing.
#[test]
fn non_push_route_size_cap_rejects_oversized_body() {
    let mut limits = Limits::generous();
    limits.max_body_bytes = 1024; // 1 KiB cap
    let server = TestServer::with_limits(&limits);

    // 100 KiB: over the 1 KiB cap, well under axum's 2 MiB default. Sent
    // chunked (no Content-Length), so the fence's declared-length check -- its
    // only all-routes size check today -- has nothing to test.
    let oversized = "A".repeat(100 * 1024);
    let over = server.post_chunked("/revoke", &oversized);
    assert_eq!(
        over.status, 413,
        "an over-cap chunked body on a non-push route must be refused 413, not processed by the \
         handler (max_body_bytes must bind every route, not just push): {} {}",
        over.status, over.body
    );

    // A small body on the same route must still be served (413 is a size
    // verdict, not a blanket refusal of the route).
    let under = server.post_chunked("/revoke", "{}");
    assert_ne!(
        under.status, 413,
        "an under-cap body on a non-push route must not be size-refused: {} {}",
        under.status, under.body
    );
}

// ========================================================================
// Per-principal HARD count quota (refuse on exceed)
// ========================================================================

/// RED today: a principal at the configured commit-count cap is REFUSED a
/// further otherwise-valid push (a distinct quota 4xx -- neither 429 rate nor
/// 403 admission), not merely logged. With `count_quota = 1`, a genesis push
/// (bringing the principal to one commit) succeeds, and a valid follow-on
/// commit -- one the protocol would accept absent the quota -- is refused.
/// Today no quota exists, so the follow-on succeeds (2xx) where it must be
/// refused.
#[test]
fn per_principal_count_quota_refuses_over_cap() {
    let mut limits = Limits::generous();
    limits.count_quota = 1;
    let server = TestServer::with_limits(&limits);

    let (genesis, followon) = genesis_and_followon("quota-p", NOW_BASE + 100);

    let g = server.post("/push", &genesis);
    assert_eq!(
        g.status, 201,
        "the first (genesis) commit is under the quota and must succeed: {} {}",
        g.status, g.body
    );

    let f = server.post("/push", &followon);
    assert!(
        (400..500).contains(&f.status) && f.status != 429 && f.status != 403,
        "a principal at the count quota must be REFUSED the next commit with a distinct quota 4xx \
         (not 2xx, not 429 rate, not 403 admission): {} {}",
        f.status,
        f.body
    );
    assert!(
        !f.body.trim().is_empty(),
        "a quota refusal must carry a machine-readable body naming the limit: {}",
        f.body
    );
}

// ========================================================================
// Coexistence: both fences compose in serve() without interfering
// ========================================================================

/// RED today (limits half): with BOTH a `[limits]` table (small READ bucket)
/// and an `[admission]` invite policy installed, a no-token genesis push is
/// still admission-denied 403 (green today) AND a read flood -- a route
/// admission never gates -- 429s on the rate fence (RED today). Proves the two
/// orthogonal fences compose in `serve()` and neither swallows the other. The
/// flood targets reads deliberately: `serve()` composes the rate fence OUTER
/// and admission INNER, so a push flood under invite would 429 at the rate
/// layer before ever reaching admission, and valid-token pushes cannot repeat
/// (single-use), so reads are the only route that isolates the rate fence
/// while admission is armed.
#[test]
fn both_fences_compose_in_serve() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let tokens = tmp.path().join("invite-tokens.txt");
    // A real sha256(token) hex so the invite policy loads and arms cleanly (the
    // token itself is never presented -- the push below is denied for lacking
    // one). Value copied from tests/admission.rs's VALID_TOKEN_SHA256.
    std::fs::write(
        &tokens,
        "1d3ff7848551415ad2947246fb017ed8d4a3a2fee20bad4cc4e4affcad861705\n",
    )
    .expect("write tokens");
    let mut limits = Limits::generous();
    limits.read = (TRIP_PER_SECOND, TRIP_BURST);
    let extra = format!(
        "{limits}\n[admission]\npolicy = \"invite\"\ntokens_path = {tokens:?}\n",
        limits = limits.render(),
        tokens = tokens,
    );
    let server = TestServer::boot(tmp, &extra);

    // Admission still fires: a no-token genesis under invite is 403.
    let denied = server.post("/push", &genesis_body("coexist-admission", NOW_BASE + 200));
    assert_eq!(
        denied.status, 403,
        "admission must still deny a no-token genesis under invite: {} {}",
        denied.status, denied.body
    );

    // Rate fence still fires alongside admission, on a route admission does not
    // gate: a read flood past the read bucket must 429.
    let flood = server.burst("GET", "/tip?pr=nobody", None, "127.0.0.1", BURST);
    assert!(
        some_429(&flood),
        "the rate fence must fire alongside admission -- a read flood must 429: {flood:?}"
    );
}

// ========================================================================
// Strip test / bare-server defaults (guard: green today & after)
// ========================================================================

/// GUARD (not a RED driver): a server booted with NO `[limits]` table applies
/// sane defaults and self-bootstraps -- it boots, serves `/server`, and admits
/// a genesis push. Green today (no fence) and green after (default fences let
/// normal traffic through). Together with the whole in-process suite over
/// `build_router` staying green, this is the standing strip test that the
/// fences never leak into `build_router`.
#[test]
fn bare_server_boots_and_self_bootstraps() {
    let server = TestServer::boot(tempfile::tempdir().expect("tempdir"), "");
    assert_eq!(
        server.get("/server").status,
        200,
        "a bare (no-[limits]) server must boot and serve /server"
    );
    assert_eq!(
        server
            .post("/push", &genesis_body("bare-genesis", NOW_BASE + 400))
            .status,
        201,
        "a bare server must admit a normal genesis push under default limits"
    );
}

// ========================================================================
// Bounded limiter state (self-DoS guard)
//
// A liveness guard, NOT a RED driver. The bounded-state guarantee (idle
// buckets are evicted / the key map cannot grow without bound) is not
// observable as a deterministic black-box HTTP behavior within a test's
// timescale; it is verified at the source level by
// `rate_limit::tests::keyed_limiter_map_is_bounded_by_key_ceiling` (a
// size-ceiling backstop over `governor`'s own time-based sweep -- see
// `rate_limit`'s module doc). What IS black-box checkable here is the
// SYMPTOM's absence: driving many distinct limiter keys must not wedge or
// crash the server. Green today and after -- it exists to catch a gross
// regression; the real bounded-state proof lives in the source-level test.
// ========================================================================

/// GUARD: many distinct principals and many distinct per-IP keys keep the
/// server responsive.
#[test]
fn many_distinct_keys_keep_server_responsive() {
    let server = TestServer::with_limits(&Limits::generous());

    // Many distinct principals, all from the same source IP -- this loop
    // exercises storage/count-quota state growth, not the rate limiter's key
    // map: `rate_limit` is deliberately IP-keyed only (no per-principal RATE
    // bucket; see the `rate_limit` module doc), so these pushes never grow a
    // limiter key map by themselves ...
    for i in 0..64 {
        let _ = server.post(
            "/push",
            &genesis_body(&format!("bounded-{i}"), NOW_BASE + 500 + i),
        );
    }
    // Many distinct source IPs (distinct per-IP keys) ...
    for i in 2..32u8 {
        let _ = server.request("GET", "/tip?pr=nobody", None, &format!("127.0.0.{i}"));
    }
    // The server is still live and serving after churning the key space.
    assert_eq!(
        server.get("/server").status,
        200,
        "the server must stay responsive after many distinct limiter keys (no unbounded-state \
         wedge)"
    );
}
