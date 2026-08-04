//! Tests for `cyphr-server`'s CLI subcommand dispatch (`src/main.rs`).
//!
//! Exercises the compiled binary directly via subprocess, since dispatch
//! lives in `fn main() -> ExitCode`, not a library function.

use std::process::Command;

fn server_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("parent")
        .parent()
        .expect("parent")
        .join("cyphr-server")
}

#[test]
fn test_export_subcommand_fails_loudly_not_yet_implemented() {
    // Regression test: the `export` subcommand used to log a warning
    // (easily missed or filtered out depending on log level) and then
    // exit 0, as if an export had actually happened. It must instead
    // fail with a non-zero exit code until the feature is implemented.
    let output = Command::new(server_binary())
        .args(["export", "some-identity"])
        .output()
        .expect("failed to execute cyphr-server binary");

    assert!(
        !output.status.success(),
        "export must not report success (exit 0) while not implemented"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not yet implemented"),
        "stderr should honestly state the feature isn't implemented, got: {stderr}"
    );
}
