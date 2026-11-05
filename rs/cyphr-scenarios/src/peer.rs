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
    pub async fn start(bins: &Bins, name: &str, http: &reqwest::Client) -> Result<Peer, PeerError> {
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

        let mut child = Command::new(&bins.server)
            .arg("--config")
            .arg(dir.path().join("absent.toml")) // never created: compiled defaults
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(&data_dir)
            .arg("--signing-key-path")
            .arg(&key_path)
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

        let id = fetch_id(http, name, addr).await?;
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
