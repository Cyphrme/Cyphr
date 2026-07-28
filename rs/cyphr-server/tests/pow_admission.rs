//! Acceptance suite for the stateless proof-of-work admission arm.
//!
//! Proof-of-work is the second admission policy: it prices Sybil registration
//! by demanding a brand-new principal's genesis push carry a hashcash proof
//! bound to *its own identity and the current time window*, or be refused 403.
//! Like the invite arm it gates only new-principal residency, refuses only
//! (never admits or mutates protocol state), and is composed solely in
//! `serve()` -- so this suite boots the real `cyphr-server` binary as a
//! subprocess and drives it over HTTP, exactly as the invite suite does.
//!
//! # Why these tests are RED today
//!
//! `resolve_config` currently *rejects* `policy = "pow"`
//! (`ConfigError::PowUnimplemented`), so a pow-configured server refuses to
//! boot. Every test that boots a pow server therefore fails for a behavioral
//! reason -- the server exits before reporting its port, so the harness panics
//! ("server stdout closed before reporting its bind address") -- not a compile
//! artifact. `pow_policy_resolves_at_config` pins that upstream cause directly
//! and in-process: it asserts `resolve_config` *accepts* pow, which is the
//! `Err` -> `Ok` flip the implementation makes. Once the arm exists, the same
//! assertions turn green.
//!
//! # The PoW verification contract (PINNED HERE)
//!
//! The proof is `blake3(preimage)` meeting `difficulty` leading zero **bits**,
//! where the preimage binds the target `principal_id` and the coarse UTC-hour
//! window. This suite pins the exact byte-encoding in one place --
//! [`pow_digest`] -- because a valid-nonce acceptance test cannot exist without
//! a concrete preimage to solve against. The implementation MUST hash exactly
//! the bytes [`pow_digest`] produces, or the acceptances below cannot go green.
//!
//! The encoding is INJECTIVE, not merely delimited. `principal_id` is arbitrary
//! attacker-supplied bytes at the admission check point -- unvalidated, and a
//! real principal id already carries a `:` (e.g. `SHA-256:U5XU...`) -- so a
//! `:`-delimited *string* preimage would be non-injective: an attacker reframes
//! the field boundaries so one solved hash satisfies several `(principal,
//! window)` tuples, amortizing a single solve across many Sybil registrations.
//! [`pow_digest`] instead uses a fixed-length domain tag, the `principal_id`
//! LENGTH-PREFIXED, and `utc_hour`/`nonce` as fixed-width little-endian `u64`s,
//! so no field's content can cross a boundary for ANY `principal_id`. The
//! `X-Cyphr-Pow` header value parses to that `u64` nonce.
//! `pow_colon_injection_cannot_reframe_a_solution` pins the property directly.

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::TempDir;

/// Header carrying the client's hashcash nonce.
const POW_HEADER: &str = "X-Cyphr-Pow";

// A distinct, deterministic `now` per principal keeps genesis blob bytes (and
// therefore blob hashes) disjoint across principals, so two resident principals
// never collide in the content-addressed blob store. Mirrors the invite suite.
const NOW_BASE: i64 = 1_700_000_000;

// ========================================================================
// The PoW verification contract (single source of truth)
//
// The implementation under test MUST agree with these three functions
// byte-for-byte and bit-for-bit; they ARE the acceptance contract.
// ========================================================================

/// The pinned hashcash preimage: `blake3` over an INJECTIVE byte encoding --
/// a fixed-length domain tag, the `principal_id` length-prefixed, then the
/// `utc_hour` and `nonce` as fixed-width little-endian `u64`s. The length
/// prefix and fixed-width integers guarantee that distinct `(principal_id,
/// utc_hour, nonce)` triples never share a preimage for ANY `principal_id`, so
/// a solution provably binds to exactly one principal and one window -- the
/// anti-amortization property. A naive `:`-delimited string preimage lacks
/// this (see `pow_colon_injection_cannot_reframe_a_solution`).
fn pow_digest(principal_id: &str, utc_hour: u64, nonce: u64) -> [u8; 32] {
    let pid = principal_id.as_bytes();
    let mut preimage = Vec::with_capacity(10 + 8 + pid.len() + 8 + 8);
    preimage.extend_from_slice(b"cyphr-pow\x01");
    preimage.extend_from_slice(&(pid.len() as u64).to_le_bytes());
    preimage.extend_from_slice(pid);
    preimage.extend_from_slice(&utc_hour.to_le_bytes());
    preimage.extend_from_slice(&nonce.to_le_bytes());
    *blake3::hash(&preimage).as_bytes()
}

/// Leading zero **bits** of a 32-byte digest read big-endian (byte 0 most
/// significant) -- the difficulty metric. Not bytes: the whole point of the
/// bit granularity is that a difficulty need not be a multiple of 8.
fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &byte in digest {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// The current coarse time window: integer UTC hour since the epoch.
fn current_utc_hour() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_secs();
    secs / 3600
}

/// Brute-force a nonce whose digest for `(principal_id, utc_hour)` has at least
/// `min_bits` leading zero bits. Legitimate client-side work; kept to small
/// difficulties so the suite solves in well under a second.
fn solve_pow(principal_id: &str, utc_hour: u64, min_bits: u32) -> u64 {
    for nonce in 0u64.. {
        if leading_zero_bits(&pow_digest(principal_id, utc_hour, nonce)) >= min_bits {
            return nonce;
        }
    }
    unreachable!("64-bit nonce space cannot be exhausted for a small difficulty");
}

/// Brute-force a nonce whose digest lands in `[lo_bits, hi_bits)` leading zero
/// bits -- used to pin the exact difficulty boundary (a nonce that clears N-1
/// bits but not N).
fn solve_pow_in_range(principal_id: &str, utc_hour: u64, lo_bits: u32, hi_bits: u32) -> u64 {
    for nonce in 0u64.. {
        let bits = leading_zero_bits(&pow_digest(principal_id, utc_hour, nonce));
        if bits >= lo_bits && bits < hi_bits {
            return nonce;
        }
    }
    unreachable!("64-bit nonce space cannot be exhausted for a small difficulty");
}

// ========================================================================
// Subprocess server harness (mirrors tests/admission.rs)
// ========================================================================

/// A test server wrapping an in-process `common::multi::Instance`.
struct TestServer {
    instance: common::multi::Instance,
}

impl TestServer {
    /// Proof-of-work policy at `difficulty` leading zero bits.
    async fn start_pow(difficulty: u32) -> TestServer {
        let table = format!("[admission]\npolicy = \"pow\"\ndifficulty = {difficulty}\n");
        Self::boot(tempfile::tempdir().expect("tempdir"), &table).await
    }

    /// Boot a server over `tmp` whose config carries `admission_table`.
    async fn boot(tmp: TempDir, admission_table: &str) -> TestServer {
        let data_dir = tmp.path().join("data");
        let config_path = tmp.path().join("cyphr-server.toml");
        let config = format!(
            "listen = \"127.0.0.1:0\"\ndata_dir = {data:?}\n\n{admission_table}",
            data = data_dir,
        );
        std::fs::write(&config_path, config).expect("write config");

        let instance = common::multi::Instance::from_config_file(&config_path, tmp).await;
        TestServer { instance }
    }

    async fn post(&self, path: &str, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        let resp = self
            .instance
            .request("POST", path, Some(body.to_string()), headers, None)
            .await;
        HttpResponse {
            status: resp.status.as_u16(),
            body: resp.body,
        }
    }

    async fn get(&self, path: &str) -> HttpResponse {
        let resp = self.instance.request("GET", path, None, &[], None).await;
        HttpResponse {
            status: resp.status.as_u16(),
            body: resp.body,
        }
    }
}

/// A parsed HTTP response: status code plus the raw body string.
struct HttpResponse {
    status: u16,
    body: String,
}

// ========================================================================
// Bodies and assertions
// ========================================================================

/// A brand-new principal's genesis push body, wire-ready. The wire
/// `principal_id` field carried here is exactly the string admission peeks and
/// the string the PoW proof must bind to, so every test passes the same
/// `principal_id` to this and to [`pow_digest`].
fn genesis_body(principal_id: &str, now: i64) -> String {
    let pool = common::load_pool();
    common::build_genesis_push_body(&pool, principal_id, now)
}

/// Assert a proof-of-work admission denial: HTTP 403 (never 401) whose JSON
/// body names the pow policy AND echoes the challenge parameters a client
/// needs to solve -- the machine-readable denial contract.
fn assert_denied_pow(resp: &HttpResponse, expected_difficulty: u64) {
    assert_eq!(
        resp.status, 403,
        "pow denial must be 403 (never 401 -- this is not an authentication failure), got {}: {}",
        resp.status, resp.body
    );
    let json: serde_json::Value = serde_json::from_str(&resp.body)
        .unwrap_or_else(|e| panic!("denial body must be JSON, got {:?}: {e}", resp.body));
    let payload = common::envelope_payload(&json);
    assert_eq!(
        payload["policy"], "pow",
        "denial JSON must name the pow policy: {}",
        resp.body
    );
    assert!(
        payload.get("error").and_then(|e| e.as_str()).is_some(),
        "denial JSON must carry a machine-readable `error`: {}",
        resp.body
    );
    assert_eq!(
        payload["difficulty"].as_u64(),
        Some(expected_difficulty),
        "denial must echo the configured difficulty so a client can size its work: {}",
        resp.body
    );
    assert!(
        payload.get("window").and_then(|w| w.as_str()).is_some(),
        "denial must name the time window (e.g. \"utc-hour\") so a client knows the binding: {}",
        resp.body
    );
}

// ========================================================================
// pow resolves at config (the Err -> Ok flip)
// ========================================================================

/// RED today: `policy = "pow"` currently returns `Err(PowUnimplemented)` from
/// `resolve_config`; it must instead resolve to an `AdmissionConfig::Pow`
/// carrying the configured difficulty. Driven in-process -- the one pow
/// behavior today's server exposes without the layer -- and the exact `Err`
/// -> `Ok` inversion of the invite suite's `pow_policy_rejected_at_config`.
#[test]
fn pow_policy_resolves_at_config() {
    use cyphr_server::config::{AdmissionConfig, Cli, Command, ServeArgs, resolve_config};

    let tmp = tempfile::tempdir().expect("tempdir");
    let config_path = tmp.path().join("cyphr-server.toml");
    std::fs::write(
        &config_path,
        "data_dir = \"./data\"\n\n[admission]\npolicy = \"pow\"\ndifficulty = 18\n",
    )
    .expect("write config");

    let cli = Cli {
        config: config_path,
        command: Command::Serve(ServeArgs {
            listen: None,
            data_dir: None,
            log_format: None,
            mode: None,
            signing_key_path: None,
            audience: None,
        }),
    };

    let config = resolve_config(&cli)
        .expect("policy = \"pow\" must now resolve, not be rejected at config resolution");
    assert!(
        matches!(config.admission, AdmissionConfig::Pow { difficulty } if difficulty == 18),
        "pow must resolve to AdmissionConfig::Pow carrying the configured difficulty, got: {:?}",
        config.admission
    );
}

// ========================================================================
// pow required + admits
// ========================================================================

/// RED today (server won't boot): under pow, a new-principal genesis push with
/// NO nonce header is refused 403 naming the pow policy and its parameters.
#[tokio::test]
async fn pow_missing_nonce_is_denied() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let r = server
        .post("/push", &genesis_body("pow-missing", NOW_BASE + 10), &[])
        .await;
    assert_denied_pow(&r, difficulty as u64);
}

/// RED today: a present-but-insufficient nonce (fewer than `difficulty` leading
/// zero bits) is refused exactly like a missing one. The test proves the
/// presented nonce is genuinely insufficient before sending it.
#[tokio::test]
async fn pow_insufficient_nonce_is_denied() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let pid = "pow-insufficient";
    let hour = current_utc_hour();
    // A nonce that clears only a handful of bits -- provably below difficulty.
    let weak = solve_pow_in_range(pid, hour, 4, 8);
    assert!(
        leading_zero_bits(&pow_digest(pid, hour, weak)) < difficulty,
        "test setup: the weak nonce must be below difficulty"
    );
    let r = server
        .post(
            "/push",
            &genesis_body(pid, NOW_BASE + 11),
            &[(POW_HEADER, &weak.to_string())],
        )
        .await;
    assert_denied_pow(&r, difficulty as u64);
}

/// RED today: a valid nonce (meets difficulty, bound to this principal and the
/// current window) ADMITS the genesis push. The server runs keyless (no signing
/// identity), so this also confirms pow works with no server signing key.
#[tokio::test]
async fn pow_valid_nonce_admits_keyless() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let pid = "pow-valid";
    let hour = current_utc_hour();
    let nonce = solve_pow(pid, hour, difficulty);
    let r = server
        .post(
            "/push",
            &genesis_body(pid, NOW_BASE + 12),
            &[(POW_HEADER, &nonce.to_string())],
        )
        .await;
    assert_eq!(
        r.status, 201,
        "a valid pow nonce must admit a new principal (keyless): {}",
        r.body
    );
}

// ========================================================================
// anti-amortization (LOAD-BEARING)
// ========================================================================

/// RED today: a nonce solved for principal A does NOT admit principal B. The
/// test first proves, in-process, that A's nonce is genuinely insufficient for
/// B's preimage -- so a 403 is the ONLY correct behavior and the assertion
/// genuinely exercises the principal binding rather than passing by luck.
#[tokio::test]
async fn pow_nonce_does_not_transfer_across_principals() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let hour = current_utc_hour();

    let principal_a = "pow-amortize-a";
    let principal_b = "pow-amortize-b";
    let nonce_a = solve_pow(principal_a, hour, difficulty);

    // The heart of the guard: A's solution is worthless for B.
    assert!(
        leading_zero_bits(&pow_digest(principal_a, hour, nonce_a)) >= difficulty,
        "test setup: A's nonce must be valid for A"
    );
    assert!(
        leading_zero_bits(&pow_digest(principal_b, hour, nonce_a)) < difficulty,
        "test setup: A's nonce must NOT clear difficulty for B (the binding under test)"
    );

    let r = server
        .post(
            "/push",
            &genesis_body(principal_b, NOW_BASE + 20),
            &[(POW_HEADER, &nonce_a.to_string())],
        )
        .await;
    assert_denied_pow(&r, difficulty as u64);
}

/// The OLD, REJECTED `:`-delimited framing, reproduced here ONLY to witness the
/// reframe it admits. Both `principal_id` and `nonce` are attacker-controlled
/// strings that may contain the `:` delimiter, so distinct `(principal_id,
/// utc_hour, nonce)` triples map to the SAME preimage -- the non-injectivity the
/// injective [`pow_digest`] exists to defeat. Never used to drive the server;
/// it exists so the reframe below is a proven premise, not an assumed one.
fn naive_colon_preimage(principal_id: &str, utc_hour: u64, nonce: &str) -> String {
    format!("cyphr-pow:{principal_id}:{utc_hour}:{nonce}")
}

/// RED today (server won't boot): an attacker who solves the PoW for one
/// principal cannot reuse that work to admit a DIFFERENT, colon-bearing
/// principal constructed to COLLIDE the old `:`-delimited framing. This pins
/// that the preimage is injective, not merely delimited -- a property
/// `pow_nonce_does_not_transfer_across_principals` cannot see, because its two
/// principals share no delimiter structure to exploit.
///
/// The reframe is real, and this test proves it rather than assuming it: under
/// the old `cyphr-pow:{pid}:{hour}:{nonce}` framing, principal `A` with the
/// nonce string `"{hour}:{n}"` and the DISTINCT principal `"A:{hour}"` with the
/// nonce string `"{n}"` produce byte-identical preimages -- so any hash that
/// solves one solves the other, admitting two principals for a single unit of
/// work (Sybil amortization). The length-prefixed injective encoding gives the
/// two principals unrelated digests, so the nonce that admits `A` is refused
/// for the reframed twin.
#[tokio::test]
async fn pow_colon_injection_cannot_reframe_a_solution() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let hour = current_utc_hour();

    let principal_a = "sybil";
    // The colon-bearing reframe twin: a DISTINCT principal built from A's own
    // identity and window -- exactly the shape the old delimiter framing folds
    // together with A.
    let principal_b = format!("{principal_a}:{hour}");

    // Witness the old framing's non-injectivity directly. The shared preimage
    // is independent of whether it clears difficulty: identical preimage bytes
    // means identical digest, so ONE solved hash would admit BOTH principals.
    // If this equality ever broke, the reframe would be imaginary.
    let n = 7u64;
    assert_eq!(
        naive_colon_preimage(principal_a, hour, &format!("{hour}:{n}")),
        naive_colon_preimage(&principal_b, hour, &n.to_string()),
        "test premise: the old `:`-delimited framing IS non-injective across a colon-bearing \
         principal -- one preimage, two distinct principals"
    );

    // The injective server, in contrast, binds a solution to exactly one
    // principal. Solve A's genuine proof and prove in-process that it is
    // worthless for the reframed twin across every window the server may check
    // (the current hour, its in-grace predecessor, and a boundary-roll
    // successor), so a 403 for B is the only correct outcome.
    let nonce_a = solve_pow(principal_a, hour, difficulty);
    assert!(
        leading_zero_bits(&pow_digest(principal_a, hour, nonce_a)) >= difficulty,
        "test setup: A's nonce must be valid for A under the injective encoding"
    );
    for h in [hour - 1, hour, hour + 1] {
        assert!(
            leading_zero_bits(&pow_digest(&principal_b, h, nonce_a)) < difficulty,
            "test setup: A's nonce must NOT clear difficulty for the reframed twin in window {h} \
             (the injective binding under test)"
        );
    }

    // A's genuine nonce admits A ...
    let admit_a = server
        .post(
            "/push",
            &genesis_body(principal_a, NOW_BASE + 60),
            &[(POW_HEADER, &nonce_a.to_string())],
        )
        .await;
    assert_eq!(
        admit_a.status, 201,
        "A's own valid nonce must admit A: {}",
        admit_a.body
    );

    // ... but is refused for the colon-reframed twin: the injective encoding
    // defeats the delimiter injection the naive framing above would have
    // admitted for free.
    let deny_b = server
        .post(
            "/push",
            &genesis_body(&principal_b, NOW_BASE + 61),
            &[(POW_HEADER, &nonce_a.to_string())],
        )
        .await;
    assert_denied_pow(&deny_b, difficulty as u64);
}

/// RED today: a nonce solved for a PAST window (well beyond the grace) is stale
/// and rejected in the current window -- no stockpiling / precomputation
/// market. The test proves the stale nonce clears difficulty for its own old
/// window but not for the current window nor the immediately-previous one (the
/// grace boundary), so rejection is the only correct behavior.
#[tokio::test]
async fn pow_stale_window_nonce_is_rejected() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let pid = "pow-stale";
    let now_hour = current_utc_hour();
    let stale_hour = now_hour - 5; // far outside any reasonable grace window
    let nonce = solve_pow(pid, stale_hour, difficulty);

    assert!(
        leading_zero_bits(&pow_digest(pid, stale_hour, nonce)) >= difficulty,
        "test setup: the nonce must be valid for its own (stale) window"
    );
    assert!(
        leading_zero_bits(&pow_digest(pid, now_hour, nonce)) < difficulty,
        "test setup: the stale nonce must NOT clear difficulty for the current window"
    );
    assert!(
        leading_zero_bits(&pow_digest(pid, now_hour - 1, nonce)) < difficulty,
        "test setup: the stale nonce must NOT clear difficulty for the previous (in-grace) window"
    );

    let r = server
        .post(
            "/push",
            &genesis_body(pid, NOW_BASE + 21),
            &[(POW_HEADER, &nonce.to_string())],
        )
        .await;
    assert_denied_pow(&r, difficulty as u64);
}

// ========================================================================
// difficulty is BITS, not BYTES
// ========================================================================

/// RED today: with difficulty = 10 (not a multiple of 8), a nonce clearing
/// exactly 9 leading zero bits is REJECTED and a nonce clearing 10+ is
/// ACCEPTED. The 9-bit rejection is the sharp guard: an implementation that
/// mis-reads difficulty as *bytes* (or otherwise thresholds on a byte
/// boundary) would accept the 9-bit nonce -- so this pins the bit boundary and
/// catches the off-by-a-byte misread in both directions.
#[tokio::test]
async fn pow_difficulty_is_bits_not_bytes() {
    let difficulty = 10;
    let server = TestServer::start_pow(difficulty).await;
    let hour = current_utc_hour();

    let below_pid = "pow-bits-below";
    let below = solve_pow_in_range(below_pid, hour, difficulty - 1, difficulty); // exactly 9 bits
    assert_eq!(
        leading_zero_bits(&pow_digest(below_pid, hour, below)),
        difficulty - 1,
        "test setup: the below nonce must clear exactly difficulty-1 bits"
    );
    let rejected = server
        .post(
            "/push",
            &genesis_body(below_pid, NOW_BASE + 30),
            &[(POW_HEADER, &below.to_string())],
        )
        .await;
    assert_denied_pow(&rejected, difficulty as u64);

    let above_pid = "pow-bits-above";
    let above = solve_pow(above_pid, hour, difficulty); // >= 10 bits
    let admitted = server
        .post(
            "/push",
            &genesis_body(above_pid, NOW_BASE + 31),
            &[(POW_HEADER, &above.to_string())],
        )
        .await;
    assert_eq!(
        admitted.status, 201,
        "a nonce clearing difficulty in BITS must admit: {}",
        admitted.body
    );
}

// ========================================================================
// existing-principal bypass
// ========================================================================

/// RED today: once a principal is resident, admission never fires for it -- a
/// later push with NO nonce is never a 403 (residency is a protocol fact, not
/// an admission event). Seeds residency with a valid nonce, then re-pushes with
/// no header.
#[tokio::test]
async fn pow_resident_principal_bypasses_admission() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let pid = "pow-resident";
    let hour = current_utc_hour();
    let nonce = solve_pow(pid, hour, difficulty);
    let body = genesis_body(pid, NOW_BASE + 40);

    let seed = server
        .post("/push", &body, &[(POW_HEADER, &nonce.to_string())])
        .await;
    assert_eq!(
        seed.status, 201,
        "seed the resident principal with a valid nonce: {}",
        seed.body
    );

    // Re-push to the now-resident principal with NO nonce: admission must not
    // fire. The protocol may reject the replay, but never with a 403 denial.
    let again = server.post("/push", &body, &[]).await;
    assert_ne!(
        again.status, 403,
        "a resident principal must bypass admission (no 403 without a nonce): {} {}",
        again.status, again.body
    );
}

// ========================================================================
// non-/push pass-through
// ========================================================================

/// RED today: reads and other endpoints are never gated by pow admission.
#[tokio::test]
async fn pow_non_push_requests_are_never_gated() {
    let server = TestServer::start_pow(16).await;
    let identity = server.get("/server").await;
    assert_eq!(
        identity.status, 200,
        "GET /server must never be gated by pow: {}",
        identity.body
    );
    let tip = server.get("/tip?pr=nobody").await;
    assert_ne!(
        tip.status, 403,
        "GET /tip must never be gated by pow: {} {}",
        tip.status, tip.body
    );
}

// ========================================================================
// orthogonality (runtime half; the source-import guard is a source check)
// ========================================================================

/// RED today: `serve()` BOOTS with the pow arm installed and serves reads --
/// not merely that `build_router` compiles. `start_pow` panics if the server
/// never accepts connections, so a successful `/server` read proves the
/// composed pow server is live. (The source-level guard -- `admission.rs`
/// imports no `cyphr`/`coz` type -- is verified by source review, not here.)
#[tokio::test]
async fn pow_serve_boots_and_serves_reads() {
    let server = TestServer::start_pow(20).await;
    let r = server.get("/server").await;
    assert_eq!(
        r.status, 200,
        "server with the pow arm installed must boot and serve reads: {}",
        r.body
    );
}

// ========================================================================
// time-window grace
// ========================================================================

/// RED today: a nonce solved for the immediately-previous UTC hour is accepted
/// within the grace window (a solution found near an hour boundary must still
/// verify). Distinct from the stale-window rejection, which uses a window far
/// outside the grace.
#[tokio::test]
async fn pow_previous_window_nonce_accepted_within_grace() {
    let difficulty = 16;
    let server = TestServer::start_pow(difficulty).await;
    let pid = "pow-grace";
    let previous_hour = current_utc_hour() - 1;
    let nonce = solve_pow(pid, previous_hour, difficulty);
    assert!(
        leading_zero_bits(&pow_digest(pid, previous_hour, nonce)) >= difficulty,
        "test setup: the nonce must be valid for the previous window"
    );
    let r = server
        .post(
            "/push",
            &genesis_body(pid, NOW_BASE + 50),
            &[(POW_HEADER, &nonce.to_string())],
        )
        .await;
    assert_eq!(
        r.status, 201,
        "a nonce for the previous UTC hour must be accepted within grace: {}",
        r.body
    );
}
