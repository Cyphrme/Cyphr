//! Acceptance suite for the server-side admission fence.
//!
//! Admission is composed only in `serve()`, never in `build_router` (the
//! fence is orthogonal to the protocol; `build_router` stays admission-free
//! by design). The whole existing integration harness drives `build_router`
//! in-process via `oneshot`, so it structurally cannot exercise admission:
//! the only surface that composes the layer is the running binary reading its
//! resolved config. This suite therefore boots the real `cyphr-server`
//! binary as a subprocess on an ephemeral port and drives it over HTTP.
//!
//! Admission is configured through the `[admission]` TOML table. The current
//! (no-admission) server has no such config field, and `ServerConfig` does
//! not deny unknown fields, so today the table is silently ignored and every
//! request is admitted -- which is exactly why the gating assertions below
//! are RED for a *behavioral* reason (a genesis push with no token is
//! admitted with 201 where admission must answer 403), not a compile
//! artifact. Once the fence exists the same assertions turn green.

mod common;

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use tempfile::TempDir;

// ========================================================================
// Invite token fixtures
//
// Precomputed offline so the suite needs no hashing dependency. Only
// `sha256(VALID)` is written into a deployment tokens file; the two WRONG
// tokens are never in any file. VALID and WRONG_SAME_LEN are the same byte
// length on purpose -- the constant-time-intent test presents both a
// same-length and a different-length wrong token and demands an identical
// 403, so an implementation cannot shortcut on a length check or a
// short-circuiting `==` over the secret.
// ========================================================================

const VALID_TOKEN: &str = "valid-invite-token-aaaaaaaaaaaaaaaaaaaa";
const VALID_TOKEN_SHA256: &str = "1d3ff7848551415ad2947246fb017ed8d4a3a2fee20bad4cc4e4affcad861705";
const WRONG_TOKEN_SAME_LEN: &str = "wrong-invite-token-bbbbbbbbbbbbbbbbbbbb";
const WRONG_TOKEN_DIFF_LEN: &str = "short-wrong";

const INVITE_HEADER: &str = "X-Cyphr-Invite";

// A distinct, deterministic `now` per principal keeps genesis blob bytes
// (and therefore blob hashes) disjoint across principals, so two resident
// principals never collide in the content-addressed blob store.
const NOW_BASE: i64 = 1_700_000_000;

// ========================================================================
// Subprocess server harness
// ========================================================================

/// Path to the compiled `cyphr-server` binary, resolved beside this test
/// binary (`<target>/debug/deps/..` -> `<target>/debug/cyphr-server`), the
/// same discovery `tests/cli.rs` uses.
fn server_binary() -> PathBuf {
    std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("deps dir")
        .parent()
        .expect("profile dir")
        .join("cyphr-server")
}

/// Read the server's resolved bind port from its stdout. The server binds the
/// ephemeral port itself (config `:0`) and prints exactly one `listening on
/// <addr>` line once bound -- all logs go to stderr, so stdout carries only
/// that line. Reading the port from the REAL bound socket removes the
/// free-then-rebind window a test-side port reservation would open.
fn read_reported_port(child: &mut Child) -> u16 {
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    let read = reader.read_line(&mut line).expect("read server stdout");
    assert_ne!(
        read, 0,
        "server stdout closed before reporting its bind address"
    );
    let addr = line
        .trim()
        .strip_prefix("listening on ")
        .unwrap_or_else(|| panic!("unexpected first server stdout line: {line:?}"));
    addr.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("unparseable server bind address: {addr:?}"))
}

/// A running `cyphr-server` subprocess plus the temp dir backing its data and
/// config. Dropping it kills the child and removes the store.
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
    /// Default Open policy: no `[admission]` table at all.
    fn start_open() -> TestServer {
        Self::boot(tempfile::tempdir().expect("tempdir"), "")
    }

    /// Single-use invite policy: writes a tokens file holding
    /// `sha256(VALID_TOKEN)` and points the `[admission]` table at it.
    fn start_invite() -> TestServer {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tokens_path = tmp.path().join("invite-tokens.txt");
        std::fs::write(&tokens_path, format!("{VALID_TOKEN_SHA256}\n")).expect("write tokens file");
        let table = format!(
            "[admission]\npolicy = \"invite\"\ntokens_path = {tokens:?}\n",
            tokens = tokens_path,
        );
        Self::boot(tmp, &table)
    }

    /// Boot a server over `tmp` whose config carries `admission_table` (a raw
    /// TOML snippet, or empty for the default Open policy), and wait until it
    /// accepts connections.
    fn boot(tmp: TempDir, admission_table: &str) -> TestServer {
        let data_dir = tmp.path().join("data");
        let config_path = tmp.path().join("cyphr-server.toml");
        // Bind the ephemeral port at the SERVER (`:0`); it reports the port the
        // OS assigned on stdout. The test never chooses a port, so there is no
        // free-then-rebind race between reservation and the server's bind.
        let config = format!(
            "listen = \"127.0.0.1:0\"\ndata_dir = {data:?}\n\n{admission_table}",
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

    fn post(&self, path: &str, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        self.request("POST", path, Some(body), headers)
    }

    fn get(&self, path: &str) -> HttpResponse {
        self.request("GET", path, None, &[])
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> HttpResponse {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set read timeout");

        let body = body.unwrap_or("");
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if !body.is_empty() || method == "POST" {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
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
        // `Connection: close` -> the server closes after the response, so
        // read-to-EOF yields the whole message.
        stream.read_to_end(&mut raw).expect("read response");
        HttpResponse::parse(&raw)
    }
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

// ========================================================================
// Bodies
// ========================================================================

/// A brand-new principal's genesis push body, wire-ready. `principal_id` is
/// only a storage label; genesis is resolved from the golden-key blobs, so
/// distinct labels (with distinct `now`) are distinct new-principal
/// residency facts.
fn genesis_body(principal_id: &str, now: i64) -> String {
    let pool = common::load_pool();
    common::build_genesis_push_body(&pool, principal_id, now)
}

/// Assert an admission denial: HTTP 403 (never 401) whose JSON body names the
/// active policy -- the machine-readable denial contract.
fn assert_denied(resp: &HttpResponse, expected_policy: &str) {
    assert_eq!(
        resp.status, 403,
        "admission denial must be 403 (never 401 -- this is not an authentication failure), got \
         {}: {}",
        resp.status, resp.body
    );
    let json: serde_json::Value = serde_json::from_str(&resp.body)
        .unwrap_or_else(|e| panic!("denial body must be JSON, got {:?}: {e}", resp.body));
    assert_eq!(
        json["policy"], expected_policy,
        "denial JSON must name the active policy: {}",
        resp.body
    );
    assert!(
        json.get("error").and_then(|e| e.as_str()).is_some(),
        "denial JSON must carry a machine-readable `error`: {}",
        resp.body
    );
}

// ========================================================================
// Open policy -- permissionless out of the box (strip-test parity guard)
// ========================================================================

/// Default config (no `[admission]` table): a brand-new genesis
/// push succeeds with no token. A bare server is permissionless, and the
/// Open policy is the *absence* of the layer, not an always-pass middleware.
#[test]
fn open_policy_admits_new_principal_without_token() {
    let server = TestServer::start_open();
    let r = server.post("/push", &genesis_body("open-genesis", NOW_BASE + 10), &[]);
    assert_eq!(r.status, 201, "open genesis push must succeed: {}", r.body);
}

// ========================================================================
// Invite policy -- gates new-principal residency
// ========================================================================

/// Invite-policy denial. RED today: under Invite, a new-principal genesis push
/// with NO invite header must be refused 403; today the ignored table admits
/// it (201).
#[test]
fn invite_missing_token_is_denied() {
    let server = TestServer::start_invite();
    let r = server.post("/push", &genesis_body("invite-notoken", NOW_BASE + 20), &[]);
    assert_denied(&r, "invite");
}

/// Invite-policy denial (wrong token). RED today: a present-but-wrong token is refused
/// exactly like a missing one.
#[test]
fn invite_wrong_token_is_denied() {
    let server = TestServer::start_invite();
    let r = server.post(
        "/push",
        &genesis_body("invite-wrong", NOW_BASE + 21),
        &[(INVITE_HEADER, WRONG_TOKEN_SAME_LEN)],
    );
    assert_denied(&r, "invite");
}

/// Invite-policy admission: a valid token admits the new principal.
#[test]
fn invite_valid_token_admits_new_principal() {
    let server = TestServer::start_invite();
    let r = server.post(
        "/push",
        &genesis_body("invite-valid", NOW_BASE + 22),
        &[(INVITE_HEADER, VALID_TOKEN)],
    );
    assert_eq!(
        r.status, 201,
        "a valid invite token must admit a new principal: {}",
        r.body
    );
}

/// Constant-time comparison intent. RED today: a wrong token
/// of the SAME length as a valid one and a wrong token of a DIFFERENT length
/// must both be refused with an identical 403 response -- so the
/// implementation cannot branch on length or short-circuit a byte compare
/// over the secret. (This pins behavioral intent at the black-box level; the
/// comparison itself is implemented with `subtle::ConstantTimeEq` in
/// `rs/cyphr-server/src/admission.rs`.)
#[test]
fn invite_wrong_tokens_are_denied_identically() {
    let server = TestServer::start_invite();
    let same_len = server.post(
        "/push",
        &genesis_body("ct-same", NOW_BASE + 23),
        &[(INVITE_HEADER, WRONG_TOKEN_SAME_LEN)],
    );
    let diff_len = server.post(
        "/push",
        &genesis_body("ct-diff", NOW_BASE + 24),
        &[(INVITE_HEADER, WRONG_TOKEN_DIFF_LEN)],
    );
    assert_denied(&same_len, "invite");
    assert_denied(&diff_len, "invite");
    assert_eq!(
        same_len.body, diff_len.body,
        "a same-length and a different-length wrong token must be refused identically (no \
         length-dependent behavior)"
    );
}

/// Single-use token. RED today: a valid token admits ONCE; presenting
/// the same token for a second, distinct new principal is refused as spent.
#[test]
fn invite_token_is_single_use() {
    let server = TestServer::start_invite();
    let first = server.post(
        "/push",
        &genesis_body("single-p1", NOW_BASE + 30),
        &[(INVITE_HEADER, VALID_TOKEN)],
    );
    assert_eq!(
        first.status, 201,
        "first use of a valid token must admit: {}",
        first.body
    );
    let second = server.post(
        "/push",
        &genesis_body("single-p2", NOW_BASE + 31),
        &[(INVITE_HEADER, VALID_TOKEN)],
    );
    assert_denied(&second, "invite");
}

/// Consume-on-2xx. Guard: a token presented on a genesis the
/// PROTOCOL rejects (non-2xx) is NOT consumed, and remains usable for a later
/// valid genesis. Guards against an implementation that spends on reservation
/// rather than on an observed 2xx.
#[test]
fn invite_token_not_consumed_on_protocol_rejection() {
    let server = TestServer::start_invite();
    // A parseable principal_id (so admission fires and reserves the token)
    // but an empty commit bundle the handler rejects (400) -> non-2xx.
    let bad = server.post(
        "/push",
        "{\"principal_id\":\"refund-bad\",\"blobs\":[]}",
        &[(INVITE_HEADER, VALID_TOKEN)],
    );
    assert!(
        !(200..300).contains(&bad.status),
        "the empty-bundle genesis must be protocol-rejected (non-2xx): {} {}",
        bad.status,
        bad.body
    );
    // The token must survive that rejection and admit a clean genesis.
    let good = server.post(
        "/push",
        &genesis_body("refund-good", NOW_BASE + 40),
        &[(INVITE_HEADER, VALID_TOKEN)],
    );
    assert_eq!(
        good.status, 201,
        "a token must not be consumed by a protocol-rejected genesis: {}",
        good.body
    );
}

/// Existing-principal bypass. Guard: once a principal is
/// resident, admission never fires for it -- a subsequent push with no token
/// is never a 403 (residency is a protocol fact, not an admission event).
#[test]
fn invite_resident_principal_bypasses_admission() {
    let server = TestServer::start_invite();
    let body = genesis_body("resident", NOW_BASE + 50);
    let seed = server.post("/push", &body, &[(INVITE_HEADER, VALID_TOKEN)]);
    assert_eq!(
        seed.status, 201,
        "seed the resident principal: {}",
        seed.body
    );
    // Re-push to the now-resident principal with NO token: admission must not
    // fire. The protocol may reject the replay, but never with a 403 denial.
    let again = server.post("/push", &body, &[]);
    assert_ne!(
        again.status, 403,
        "a resident principal must bypass admission (no 403 without a token): {} {}",
        again.status, again.body
    );
}

/// Non-/push pass-through. Guard: reads and other endpoints are
/// never gated by admission.
#[test]
fn non_push_requests_are_never_gated() {
    let server = TestServer::start_invite();
    let identity = server.get("/server");
    assert_eq!(
        identity.status, 200,
        "GET /server must never be gated: {}",
        identity.body
    );
    let tip = server.get("/tip?pr=nobody");
    assert_ne!(
        tip.status, 403,
        "GET /tip must never be gated by admission: {} {}",
        tip.status, tip.body
    );
}

/// Malformed-body pass-through. Guard: a `POST /push` whose body has
/// no parseable `principal_id` fails open -- admission cannot fire (nothing to
/// gate), and the handler's own parse rejects it. Never a 403.
#[test]
fn push_without_principal_id_passes_through_to_handler() {
    let server = TestServer::start_invite();
    let r = server.post("/push", "{\"blobs\":[\"QUFBQQ\"]}", &[]);
    assert_ne!(
        r.status, 403,
        "a body with no parseable principal_id must fail open, not be gated: {} {}",
        r.status, r.body
    );
    assert!(
        r.status >= 400,
        "the handler's own parse must still reject the malformed body: {} {}",
        r.status,
        r.body
    );
}

/// End-to-end boot check. Guard: `serve()` BOOTS with the
/// admission module present and installed -- not merely that `build_router`
/// compiles. `TestServer::start` panics if the server never accepts
/// connections, so a successful `/server` read proves the composed server is
/// live.
#[test]
fn serve_boots_with_admission_installed() {
    let server = TestServer::start_invite();
    let r = server.get("/server");
    assert_eq!(
        r.status, 200,
        "server with admission installed must boot and serve: {}",
        r.body
    );
}

// ========================================================================
// Cross-cutting: admission's own body cap vs. the deployer's configured cap
// ========================================================================

/// RED: admission buffers every `/push` body through its own private,
/// hardcoded 2 MiB constant BEFORE it ever consults the configured
/// `[limits] max_body_bytes` or its resident short-circuit. A deployer who
/// raises `max_body_bytes` above 2 MiB gets no relief on `/push` under any
/// active (non-`Open`) admission policy: a body past 2 MiB but under the
/// configured cap is still refused `413 {"error":"push body too large"}` by
/// admission itself, silently defeating the config knob. This test boots an
/// Invite server with `max_body_bytes` raised to 4 MiB and sends a ~3 MiB
/// genesis push with a valid token -- a body that clears both the deployer's
/// configured cap and admission's own invite policy -- and asserts admission's
/// size refusal does NOT fire.
#[test]
fn configured_body_cap_governs_push_under_active_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let tokens_path = tmp.path().join("invite-tokens.txt");
    std::fs::write(&tokens_path, format!("{VALID_TOKEN_SHA256}\n")).expect("write tokens file");
    let table = format!(
        "[admission]\npolicy = \"invite\"\ntokens_path = {tokens:?}\n\n[limits]\nmax_body_bytes = {cap}\n",
        tokens = tokens_path,
        cap = 4 * 1024 * 1024,
    );
    let server = TestServer::boot(tmp, &table);

    // A real genesis push (valid principal_id + blobs), padded with an
    // unknown, ignored field so the body crosses 2 MiB but stays under the
    // configured 4 MiB cap. The padding never disturbs `principal_id` or
    // `blobs`, so nothing about this request is rejectable by admission's
    // invite policy or the handler's own parse for any reason OTHER than
    // size.
    let mut body: serde_json::Value = serde_json::from_str(&genesis_body("n-body-cap", NOW_BASE + 60))
        .expect("genesis body parses as JSON");
    body.as_object_mut()
        .expect("genesis body is a JSON object")
        .insert(
            "padding".to_string(),
            serde_json::Value::String("a".repeat(3 * 1024 * 1024)),
        );
    let body = serde_json::to_string(&body).expect("padded body serializes");
    assert!(
        body.len() > 2 * 1024 * 1024,
        "test body must exceed admission's hardcoded 2 MiB cap to exercise the bug: {} bytes",
        body.len()
    );
    assert!(
        body.len() < 4 * 1024 * 1024,
        "test body must stay under the configured 4 MiB cap: {} bytes",
        body.len()
    );

    let r = server.post("/push", &body, &[(INVITE_HEADER, VALID_TOKEN)]);

    let is_admission_size_refusal = r.status == 413 && r.body.contains("push body too large");
    assert!(
        !is_admission_size_refusal,
        "a {}-byte push under a configured 4 MiB max_body_bytes must not be refused by \
         admission's own 2 MiB size cap (413 \"push body too large\"); admission must defer to \
         the deployer's configured limit, not its private hardcoded constant. Got {}: {}",
        body.len(),
        r.status,
        r.body
    );
}
