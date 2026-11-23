//! Locating the shipped binaries.
//!
//! `CARGO_BIN_EXE_<name>` is only set for a package's own binaries, and
//! these binaries belong to other packages. Deriving the path from the
//! test executable's directory depth breaks as soon as the target dir
//! moves (forge #189), so the harness asks cargo itself: one
//! `cargo build --message-format=json` reports each artifact's real
//! path. `CYPHR_SERVER_BIN` / `CYPHR_CLI_BIN` override it, for CI that
//! prebuilds.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Bins {
    pub server: PathBuf,
    pub cli: PathBuf,
}

impl Bins {
    /// Resolve once per process; panics with the cause if the binaries
    /// cannot be located, since no scenario can run without them.
    pub fn get() -> &'static Bins {
        static BINS: OnceLock<Bins> = OnceLock::new();
        BINS.get_or_init(|| {
            Self::locate().unwrap_or_else(|e| panic!("cannot locate cyphr binaries: {e}"))
        })
    }

    fn locate() -> Result<Bins, String> {
        let over = |k: &str| std::env::var_os(k).map(PathBuf::from);
        if let (Some(server), Some(cli)) = (over("CYPHR_SERVER_BIN"), over("CYPHR_CLI_BIN")) {
            return Ok(Bins { server, cli });
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut build = Command::new(cargo);
        build.current_dir(env!("CARGO_MANIFEST_DIR")).args([
            "build",
            "--quiet",
            "--message-format=json-render-diagnostics",
            "-p",
            "cyphr-server",
            "-p",
            "cyphr-cli",
        ]);
        // A release harness drives release servers: debug servers are slow
        // enough to distort timing-sensitive scenarios.
        if !cfg!(debug_assertions) {
            build.arg("--release");
        }
        let out = build.output().map_err(|e| format!("spawning cargo: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "cargo build failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let exe = |name: &str| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == name)
                .find_map(|v| v["executable"].as_str().map(PathBuf::from))
                .ok_or_else(|| format!("cargo reported no executable for `{name}`"))
        };
        Ok(Bins {
            server: exe("cyphr-server")?,
            cli: exe("cyphr")?,
        })
    }
}
