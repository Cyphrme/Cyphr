//! A running `cyphr-server` process: its own port, its own data dir, its
//! own freshly generated signing key.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

use crate::bins::Bins;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer `{name}`: {what}: {source}")]
    Io {
        name: String,
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("peer `{name}` exited before announcing a listen address (see {log})")]
    EarlyExit { name: String, log: PathBuf },
    #[error("peer `{name}` GET /server: {reason}")]
    Identity { name: String, reason: String },
}

/// What a started server is.
#[derive(Clone, Copy, Debug)]
pub enum Role {
    /// A keyed attestor with its own identity.
    Attestor,
    /// A witness that pulls from the authority at this address. Give it the
    /// address of a proxy route, so the pull rides a link the proxy can cut.
    Witness { authority: SocketAddr },
}

/// Server settings a scenario may pin explicitly instead of inheriting a
/// default that could change underneath it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    /// `[limits] max_body_bytes`.
    pub max_body_bytes: Option<u64>,
}

pub struct Peer {
    pub name: String,
    /// The server's real address; clients should dial a proxy route instead.
    pub addr: SocketAddr,
    /// The identity digest the peer reported from `GET /server`.
    pub id: String,
    pub data_dir: PathBuf,
    stdout: Arc<Mutex<Vec<String>>>,
    // `kill_on_drop` reaps the process if a scenario panics.
    _child: Child,
    _dir: TempDir,
}

impl Peer {
    pub async fn start(
        bins: &Bins,
        name: &str,
        http: &reqwest::Client,
        role: Role,
        limits: Limits,
    ) -> Result<Peer, PeerError> {
        let io_err = |what| {
            let name = name.to_owned();
            move |source| PeerError::Io { name, what, source }
        };
        let dir = tempfile::tempdir().map_err(io_err("creating tempdir"))?;
        let data_dir = dir.path().join("data");
        let key_path = dir.path().join("signing-key.json");
        let log = dir.path().join("server.log");

        // A fresh key per start: scenario identities must never repeat.
        let kp = coz::Alg::Ed25519.generate_keypair();
        let key = serde_json::json!({
            "alg": kp.alg.name(),
            "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
            "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
        });
        std::fs::write(&key_path, key.to_string()).map_err(io_err("writing signing key"))?;

        // Without pinned limits the file is never created: compiled defaults.
        let config_path = dir.path().join("server.toml");
        if let Some(n) = limits.max_body_bytes {
            std::fs::write(&config_path, format!("[limits]\nmax_body_bytes = {n}\n"))
                .map_err(io_err("writing config"))?;
        }
        let mut cmd = Command::new(&bins.server);
        cmd.arg("--config")
            .arg(&config_path)
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(&data_dir);
        match role {
            Role::Attestor => {
                cmd.arg("--signing-key-path")
                    .arg(&key_path)
                    // Keyed peers also carry the Noise transport, so a
                    // scenario can reach them as principals.
                    .args(["--transport-listen", "127.0.0.1:0"]);
            },
            Role::Witness { authority } => {
                cmd.args(["--mode", "witness", "--authority-url"])
                    .arg(format!("http://{authority}"));
            },
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&log).map_err(io_err("creating log"))?)
            .kill_on_drop(true)
            .spawn()
            .map_err(io_err("spawning cyphr-server"))?;

        let mut lines = BufReader::new(child.stdout.take().expect("stdout was piped")).lines();
        let mut seen = Vec::new();
        let addr = loop {
            match lines.next_line().await.map_err(io_err("reading stdout"))? {
                None => {
                    return Err(PeerError::EarlyExit {
                        name: name.to_owned(),
                        log,
                    });
                },
                Some(l) => {
                    let parsed = l
                        .strip_prefix("listening on ")
                        .and_then(|a| a.trim().parse().ok());
                    seen.push(l);
                    if let Some(addr) = parsed {
                        break addr;
                    }
                },
            }
        };
        let stdout = Arc::new(Mutex::new(seen));
        let sink = Arc::clone(&stdout);
        // Keep draining so the child never blocks on a full pipe.
        tokio::spawn(async move {
            while let Ok(Some(l)) = lines.next_line().await {
                sink.lock().expect("peer stdout").push(l);
            }
        });

        // A witness holds no identity of its own, so its id is synthetic.
        let id = match role {
            Role::Attestor => fetch_id(http, name, addr).await?,
            Role::Witness { .. } => format!("witness-{name}-{}", addr.port()),
        };
        Ok(Peer {
            name: name.to_owned(),
            addr,
            id,
            data_dir,
            stdout,
            _child: child,
            _dir: dir,
        })
    }

    /// The Noise transport address the peer announced on stdout, waiting
    /// briefly for the line, which follows the HTTP one. `None` for a peer
    /// that runs no transport (a witness) or never announced one.
    pub async fn transport_addr(&self) -> Option<SocketAddr> {
        for _ in 0..50 {
            let found = self.stdout_lines().iter().find_map(|l| {
                l.strip_prefix("transport listening on ")
                    .and_then(|a| a.trim().parse().ok())
            });
            if found.is_some() {
                return found;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }

    pub fn stdout_lines(&self) -> Vec<String> {
        self.stdout.lock().expect("peer stdout").clone()
    }
}

async fn fetch_id(
    http: &reqwest::Client,
    name: &str,
    addr: SocketAddr,
) -> Result<String, PeerError> {
    let fail = |reason: String| PeerError::Identity {
        name: name.to_owned(),
        reason,
    };
    let body: serde_json::Value = http
        .get(format!("http://{addr}/server"))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| fail(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| fail(e.to_string()))
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| fail(e.to_string())))?;
    body["payload"]["pg"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("no `payload.pg` in {body}")))
}
