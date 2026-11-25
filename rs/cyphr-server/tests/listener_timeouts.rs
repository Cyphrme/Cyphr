//! The HTTP listener drops a client that stalls: one that never finishes
//! its request head, and one that sits idle. Each case boots the real
//! binary, because the timeouts belong to the accept loop `serve` runs.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running `cyphr-server serve` and the address it reported.
struct Server {
    child: Child,
    addr: String,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(limits: &str) -> Server {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("server.toml");
    std::fs::write(&config, format!("[limits]\n{limits}\n")).expect("config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cyphr-server"))
        .args(["--config", config.to_str().expect("utf-8")])
        .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
        .arg(dir.path().join("data"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn cyphr-server");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    let addr = loop {
        line.clear();
        assert!(
            stdout.read_line(&mut line).expect("stdout") != 0,
            "server exited"
        );
        if let Some(addr) = line.trim_end().strip_prefix("listening on ") {
            break addr.to_owned();
        }
    };
    Server {
        child,
        addr,
        _dir: dir,
    }
}

/// Whether the server closed `stream` within `within`: a read that ends in
/// EOF or a reset, not one that is still waiting.
fn closed_within(stream: &mut TcpStream, within: Duration) -> Option<Duration> {
    stream.set_read_timeout(Some(within)).expect("read timeout");
    let started = Instant::now();
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) if started.elapsed() < within => Some(started.elapsed()),
        Ok(0) => Some(started.elapsed()),
        Ok(_) | Err(_) => None,
    }
}

/// Claim: a client that starts a request and never finishes its head is
/// dropped at the header-read timeout, while a complete request on a fresh
/// connection is answered. Turns red if the listener waits for ever on a
/// stalled head (the `axum::serve` behaviour).
/// End-to-end scenario: yes (the real binary over a socket).
#[test]
fn a_stalled_header_read_is_dropped() {
    let server = start("header_read_timeout_secs = 1");

    let mut stalled = TcpStream::connect(&server.addr).expect("connect");
    stalled
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
        .expect("partial head");
    let after = closed_within(&mut stalled, Duration::from_secs(8))
        .expect("the stalled connection must be closed");
    assert!(
        after >= Duration::from_millis(900),
        "closed early: {after:?}"
    );

    let mut whole = TcpStream::connect(&server.addr).expect("connect");
    whole
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .expect("request");
    let mut answer = String::new();
    whole.read_to_string(&mut answer).expect("answer");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
}

/// Claim: a connection with no traffic is closed at the idle timeout, and
/// one that has been answered is closed after its keep-alive sits idle.
/// Turns red if an idle connection is held open.
/// End-to-end scenario: yes (the real binary over a socket).
#[test]
fn an_idle_connection_is_closed() {
    let server = start("idle_timeout_secs = 1");

    let mut silent = TcpStream::connect(&server.addr).expect("connect");
    closed_within(&mut silent, Duration::from_secs(8)).expect("a silent connection is closed");

    let mut kept = TcpStream::connect(&server.addr).expect("connect");
    kept.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .expect("request");
    kept.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut buf = [0u8; 1024];
    let n = kept.read(&mut buf).expect("answer");
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    closed_within(&mut kept, Duration::from_secs(8)).expect("the idle keep-alive is closed");
}
