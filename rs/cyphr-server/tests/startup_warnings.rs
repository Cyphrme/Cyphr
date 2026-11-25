//! A server that starts but cannot do its job says so at start, in its log.
//!
//! Each case boots the real binary (the warning is a start-up log line, so
//! only a started process shows it) and reads what it logged.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

mod common;

/// Boot `cyphr-server serve <extra>` over `dir`, wait for it to listen, stop
/// it, and return everything it logged.
fn boot_and_read_log(dir: &Path, extra: &[&str]) -> String {
    std::fs::create_dir_all(dir).expect("dir");
    let config = dir.join("empty.toml");
    std::fs::write(&config, "").expect("empty config");
    let log_path = dir.join("server.log");
    let log = std::fs::File::create(&log_path).expect("log file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_cyphr-server"))
        .args(["--config", config.to_str().expect("utf-8")])
        .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
        .arg(dir.join("data"))
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn cyphr-server");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        let n = stdout.read_line(&mut line).expect("read stdout");
        assert!(n != 0, "server exited before listening");
        if line.starts_with("listening on ") {
            break;
        }
    }
    child.kill().expect("kill");
    child.wait().expect("wait");
    std::fs::read_to_string(log_path).expect("read log")
}

/// Claim: witness mode with no upstream, an audience with no signing key and
/// a signing key other users can read each start with a warning; a server
/// with none of them logs none. Turns red if any is silent, or if the
/// warnings fire on a sound configuration.
/// End-to-end scenario: yes (the real binary and its log).
#[test]
fn a_server_that_cannot_do_its_job_warns_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");

    let witness = boot_and_read_log(&dir.path().join("a"), &["--mode", "witness"]);
    assert!(witness.contains("no upstream"), "{witness}");

    let audience = boot_and_read_log(&dir.path().join("b"), &["--audience", "cyphr.me"]);
    assert!(audience.contains("no signing key"), "{audience}");

    let keydir = dir.path().join("c");
    std::fs::create_dir_all(&keydir).expect("dir");
    let key = common::write_signing_key(&keydir);
    let key_arg = key.to_str().expect("utf-8");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let wide = boot_and_read_log(&keydir, &["--signing-key-path", key_arg]);
        assert!(wide.contains("accessible to other users"), "{wide}");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let sound = boot_and_read_log(&keydir.join("again"), &["--signing-key-path", key_arg]);
    assert!(
        !sound.contains("accessible to other users") && !sound.contains("no upstream"),
        "a sound configuration warns of nothing: {sound}"
    );
}
