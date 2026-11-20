//! A CLI commit is durable before the command reports success.
//!
//! A client that releases a commit it can lose to a power cut can sign
//! again on the same `pre`, an implicit fork (SPEC 2.3.2). The engine
//! syncs the record once per accepted commit, before it returns, and the
//! CLI prints only after the engine returns. Before this the store was
//! made durable only by fjall's `Journal::drop` at process exit, after the
//! output, where a failed sync is logged and swallowed.
//!
//! Counting syncs means tracing syscalls, so the command runs under
//! `strace`: the engine's sync is the one `fdatasync` on the blob journal
//! (the exit-time sync is an `fsync`, a different call), and the output is
//! the first write to stdout.

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use common::User;

/// One syscall of the traced command, by its place in the trace.
struct Call {
    line: usize,
    text: String,
}

/// Run `cyphr args...` under strace for `fsync`, `fdatasync` and `write`,
/// with file descriptors decoded to paths, and return the trace.
fn traced(user: &User, args: &[&str]) -> Vec<Call> {
    let out = user.dir.path().join("trace.txt");
    let status = Command::new("strace")
        .args(["-f", "-y", "-e", "trace=fsync,fdatasync,write", "-o"])
        .arg(&out)
        .arg(env!("CARGO_BIN_EXE_cyphr"))
        .arg("--keystore")
        .arg(user.keystore())
        .arg("--store")
        .arg(user.store_uri())
        .args(["--output", "json"])
        .args(args)
        .stdout(std::process::Stdio::piped())
        .status()
        .expect("running strace: this test needs it on PATH (nix-shell provides it)");
    assert!(status.success(), "traced command failed: {status}");
    std::fs::read_to_string(out)
        .expect("trace")
        .lines()
        .enumerate()
        .map(|(line, text)| Call {
            line,
            text: text.to_owned(),
        })
        .collect()
}

/// Behaviour: a commit made through the CLI causes exactly one data sync
/// of the blob journal, and it happens before anything is written to
/// stdout. Turns red if the engine does not sync (the only sync is then the
/// exit-time `fsync` after the output), syncs more than once, or the CLI
/// reports before the engine returns.
#[test]
fn a_cli_commit_is_synced_once_before_it_reports() {
    let user = User::new();
    let id = user.new_identity();
    let (ident, signer) = (format!("--identity={id}"), format!("--signer={id}"));
    user.setup(&["data", "action", &ident, &signer, "--msg=m"]);

    let trace = traced(&user, &["data", "commit", &ident, &signer]);

    let syncs: Vec<&Call> = trace
        .iter()
        .filter(|c| c.text.contains("fdatasync(") && c.text.contains("/blobs/"))
        .collect();
    assert_eq!(
        syncs.len(),
        1,
        "one data sync of the blob journal per commit: {:#?}",
        trace.iter().map(|c| &c.text).collect::<Vec<_>>()
    );
    let reported = trace
        .iter()
        .find(|c| c.text.contains("write(1<"))
        .expect("the command wrote its result to stdout");
    assert!(
        syncs[0].line < reported.line,
        "the commit was reported (line {}) before it was synced (line {})",
        reported.line,
        syncs[0].line
    );
}
