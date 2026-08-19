//! Ops-hardening acceptance tests for `cyphr-server` (issues #172, #175).
//!
//! ## Shutdown signal handling (#172)
//!
//! `serve`'s own doc comment (`rs/cyphr-server/src/lib.rs`) claims the
//! server "blocks until SIGTERM/SIGINT", but `shutdown_signal()` awaits
//! only `tokio::signal::ctrl_c()` (SIGINT). SIGTERM -- what systemd,
//! Docker, Kubernetes, and a bare `kill` all send by default -- falls
//! through to the OS default disposition, which terminates the process
//! immediately: no drain, no "server stopped" log line, and an exit status
//! that reports death-by-signal rather than a clean return from `main`.
//!
//! These tests drive the compiled binary as a real OS process (a signal
//! handler can only be exercised by an actual signal delivery, not an
//! in-process call) and assert the SAME shutdown contract for both
//! signals: a zero exit status, both graceful-shutdown log lines, and an
//! intact store on the next boot. `sigint_*` is the positive control --
//! it already holds today -- proving the harness distinguishes a real
//! graceful path from one that merely happens to exit for an unrelated
//! reason before `sigterm_*`, which currently fails it, is trusted.
//!
//! ## Sidecar recovery (#175)
//!
//! Losing `server-principal.json` while the blob store and index stay
//! intact currently bricks a keyed boot with a raw engine diagnostic --
//! see `missing_sidecar_after_established_principal_names_file_and_guide`
//! below.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::AppState;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;

/// Locate the compiled `cyphr-server` binary. `CARGO_BIN_EXE_<name>` is set
/// by cargo itself for integration tests whose package builds that binary
/// target -- correct under any `target-dir` layout, unlike deriving it from
/// `current_exe()`'s parent (`tests/cli.rs`'s approach, which assumes a
/// `target/<profile>/deps/` layout this workspace's shared target-dir does
/// not use).
fn server_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cyphr-server"))
}

/// Write a fresh Ed25519 signing key file, matching the on-disk shape
/// `auth::ServerIdentity::load_from_path` expects.
fn write_signing_key(dir: &Path) -> PathBuf {
    let path = dir.join("signing-key.json");
    let kp = coz::Alg::Ed25519.generate_keypair();
    let file = serde_json::json!({
        "alg": kp.alg.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
        "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    path
}

/// A spawned `cyphr-server serve` process, plus a background-drained feed
/// of its stderr (where `tracing` logs land -- see `logging.rs`).
struct Server {
    child: Child,
    stderr_lines: Receiver<String>,
}

/// Spawn `cyphr-server serve` against a keyed, ephemeral data directory and
/// block until it reports its bound port on stdout. `--config` names a
/// file that is never created, so resolution falls through to compiled
/// defaults regardless of the test runner's working directory.
fn spawn_server(data_dir: &Path, key_path: &Path) -> Server {
    let mut child = Command::new(server_binary())
        .args([
            "--config",
            data_dir.join("unused.toml").to_str().unwrap(),
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--signing-key-path",
            key_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cyphr-server");

    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line).expect("read stdout");
        assert!(
            n != 0,
            "server exited before reporting a listen address (check stderr for a boot failure)"
        );
        if line.trim_end().starts_with("listening on ") {
            break;
        }
    }
    // Drain the rest of stdout in the background so the child never blocks
    // writing to a full pipe once this thread stops reading it.
    std::thread::spawn(move || {
        let mut sink = String::new();
        let _ = std::io::Read::read_to_string(&mut stdout, &mut sink);
    });

    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    Server {
        child,
        stderr_lines: rx,
    }
}

/// Send `kill -s <signal> <pid>` to a live process, via the real `kill(1)`
/// so the delivery mechanism is the same one an operator's process
/// supervisor uses -- no signal crate stands between the test and the OS.
fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .args(["-s", signal, &pid.to_string()])
        .status()
        .expect("invoke kill(1)");
    assert!(status.success(), "kill -s {signal} {pid} failed to send");
}

/// Poll `try_wait` until the child exits or `timeout` elapses.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        if start.elapsed() > timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Every line the background reader has delivered so far. Called only
/// after the child has exited and a brief settle, so the reader thread has
/// had the chance to drain its buffered final lines from the closed pipe.
fn collect_stderr(rx: &Receiver<String>) -> String {
    std::thread::sleep(Duration::from_millis(200));
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines.join("\n")
}

/// Boot a fresh `cyphr-server` against `data_dir`/`key_path` and confirm it
/// reaches a listening state -- i.e. the store a prior process left behind
/// is intact and loadable, not corrupted. Kills the reboot once confirmed;
/// this is a liveness check, not a place to run further assertions.
fn assert_store_survives_reboot(data_dir: &Path, key_path: &Path) {
    let mut reboot = spawn_server(data_dir, key_path);
    send_signal(reboot.child.id(), "KILL");
    wait_with_timeout(&mut reboot.child, Duration::from_secs(5));
}

/// Drive one full signal-to-shutdown cycle and assert the graceful-path
/// contract: a clean exit status, both `shutdown_signal`/`serve` log
/// lines, and a store the next boot can still open.
fn assert_graceful_shutdown_on(signal: &str) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let key_path = write_signing_key(dir.path());

    let mut server = spawn_server(&data_dir, &key_path);
    let pid = server.child.id();

    send_signal(pid, signal);
    let status = wait_with_timeout(&mut server.child, Duration::from_secs(10))
        .unwrap_or_else(|| panic!("server did not exit within 10s of receiving SIG{signal}"));
    let stderr = collect_stderr(&server.stderr_lines);

    assert!(
        status.success(),
        "SIG{signal} must produce the same clean exit as a graceful shutdown (main returning Ok), \
         got {status:?}\ncaptured stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("shutdown signal received"),
        "SIG{signal} must run the same drain path ctrl_c takes -- expected shutdown_signal()'s \
         log line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("server stopped"),
        "SIG{signal} must reach serve()'s post-shutdown log line, got:\n{stderr}"
    );

    assert_store_survives_reboot(&data_dir, &key_path);
}

/// Positive control: SIGINT (`ctrl_c()`) already triggers the documented
/// drain path today. If this test itself were red, the harness would be
/// broken, not the server -- it pins that the assertions above are
/// satisfiable at all before `sigterm_*` is trusted to mean something.
#[test]
fn sigint_triggers_graceful_shutdown() {
    assert_graceful_shutdown_on("INT");
}

/// `c-sigterm-test`: SIGTERM must trigger the identical graceful path.
/// Currently red -- `shutdown_signal()` awaits only `ctrl_c()`, so SIGTERM
/// falls through to the OS default disposition (immediate termination):
/// no log lines, and an exit status that reports death-by-signal rather
/// than `main`'s `Ok(())` return. Mutation that turns this green: handling
/// `tokio::signal::unix::signal(SignalKind::terminate())` alongside
/// `ctrl_c()` in `shutdown_signal()` (`rs/cyphr-server/src/lib.rs:394`).
#[test]
fn sigterm_triggers_graceful_shutdown() {
    assert_graceful_shutdown_on("TERM");
}

// ========================================================================
// Sidecar recovery (#175)
// ========================================================================

/// Build a keyed, `Arc`-wrapped `AppState` over a fresh data directory --
/// the in-process construction `serve` performs before it bootstraps the
/// principal, which `ServerPrincipal::bootstrap` is driven through
/// directly below (no live process needed: this is a library-level
/// contract, not a signal-delivery one).
fn keyed_state(data_dir: &Path, key_path: &Path) -> Arc<AppState> {
    let config = ServerConfig {
        data_dir: data_dir.to_path_buf(),
        signing_key_path: Some(key_path.to_path_buf()),
        ..Default::default()
    };
    Arc::new(AppState::new(config).expect("keyed AppState opens"))
}

/// Losing the sidecar recording file (`server-principal.json`) -- backup
/// restore that missed one file, disk hiccup, operator error -- while the
/// blob store and index (the actual chain data) stay intact must not brick
/// the server with a raw, unexplained engine diagnostic (issue #175).
///
/// `bootstrap()` currently treats "no sidecar" as "no principal yet" with
/// no check for whether the engine already carries a chain at that PG. It
/// re-attempts genesis, `principal/create` re-applies to an
/// already-established principal, and the resulting protocol error
/// surfaces verbatim as `"server principal storage: protocol: state
/// mismatch"` -- naming neither the missing file nor the fact that the
/// condition is recoverable. An operator reading that message concludes
/// the STORE is corrupt and reaches for a backup restore, when what they
/// actually lost is one small, reconstructible file (`ac-sidecar`,
/// `c-named-error`).
#[tokio::test]
async fn missing_sidecar_after_established_principal_names_file_and_guide() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let data_dir = dir.path().join("data");
    let state = keyed_state(&data_dir, &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");

    ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("first keyed boot establishes the principal and writes the sidecar");

    let sidecar = data_dir.join("server-principal.json");
    assert!(
        sidecar.exists(),
        "the sidecar must exist after a first keyed boot"
    );
    std::fs::remove_file(&sidecar).expect("remove the sidecar to simulate its loss");

    // A real restart always spans a wall-clock second boundary; without
    // this, the retried genesis attempt's `now` (second-granularity, see
    // `auth::server_now`) can tie the first attempt's and fail a
    // timestamp-ordering check before ever reaching the state-mismatch this
    // scenario is actually about -- masking the defect behind a different,
    // timing-dependent symptom instead of the one #175 reports.
    std::thread::sleep(Duration::from_millis(1100));

    let result =
        ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &state.config.data_dir)
            .await;
    let message = match result {
        Ok(_) => {
            panic!("a missing sidecar over an already-established chain must not silently succeed")
        },
        Err(e) => e.to_string(),
    };

    assert!(
        message.contains("server-principal.json"),
        "the error must name the missing sidecar file, got: {message}"
    );
    assert!(
        message.contains("docs/guides/operating-a-server.md"),
        "the error must point at the documented recovery procedure, got: {message}"
    );
    assert!(
        !message.contains("state mismatch"),
        "the error must not surface the raw internal engine diagnostic verbatim -- to an operator \
         it reads as store corruption, not a missing, reconstructible file, got: {message}"
    );
}
