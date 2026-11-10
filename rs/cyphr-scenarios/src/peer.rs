//! A running `cyphr-server` process: its own port, its own data dir, its
//! own freshly generated signing key.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    #[error("peer `{name}`: {what} failed: {reason}")]
    Command {
        name: String,
        what: &'static str,
        reason: String,
    },
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
    /// A restart binds the same address, so routes stay valid across it.
    pub addr: SocketAddr,
    /// The identity digest the peer reported from `GET /server`.
    pub id: String,
    pub data_dir: PathBuf,
    launch: Launch,
    stdout: Arc<Mutex<Vec<String>>>,
    backups: AtomicUsize,
    // `kill_on_drop` reaps the process if a scenario panics. `None` while
    // the peer is stopped.
    child: tokio::sync::Mutex<Option<Child>>,
    _dir: TempDir,
}

/// What a peer needs to start again with the same identity and data.
struct Launch {
    config: PathBuf,
    key: PathBuf,
    log: PathBuf,
    role: Role,
}

impl Launch {
    /// Spawn `cyphr-server serve` on `listen`, wait for its listen line, and
    /// keep draining its stdout into `sink`.
    async fn spawn(
        &self,
        bins: &Bins,
        name: &str,
        listen: &str,
        data_dir: &Path,
        sink: &Arc<Mutex<Vec<String>>>,
    ) -> Result<(Child, SocketAddr), PeerError> {
        let io_err = |what| {
            let name = name.to_owned();
            move |source| PeerError::Io { name, what, source }
        };
        let mut cmd = Command::new(&bins.server);
        cmd.arg("--config")
            .arg(&self.config)
            .args(["serve", "--listen", listen, "--data-dir"])
            .arg(data_dir);
        match self.role {
            Role::Attestor => {
                cmd.arg("--signing-key-path")
                    .arg(&self.key)
                    // Keyed peers also carry the Noise transport, so a
                    // scenario can reach them as principals.
                    .args(["--transport-listen", "127.0.0.1:0"]);
            },
            Role::Witness { authority } => {
                cmd.args(["--mode", "witness", "--authority-url"])
                    .arg(format!("http://{authority}"));
            },
        }
        // Appending keeps the log of a run before a restart.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .map_err(io_err("opening log"))?;
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(log)
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
                        log: self.log.clone(),
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
        *sink.lock().expect("peer stdout") = seen;
        let sink = Arc::clone(sink);
        // Keep draining so the child never blocks on a full pipe.
        tokio::spawn(async move {
            while let Ok(Some(l)) = lines.next_line().await {
                sink.lock().expect("peer stdout").push(l);
            }
        });
        Ok((child, addr))
    }
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
        let launch = Launch {
            config: config_path,
            key: key_path,
            log: dir.path().join("server.log"),
            role,
        };
        let stdout = Arc::new(Mutex::new(Vec::new()));
        let (child, addr) = launch
            .spawn(bins, name, "127.0.0.1:0", &data_dir, &stdout)
            .await?;

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
            launch,
            stdout,
            backups: AtomicUsize::new(0),
            child: tokio::sync::Mutex::new(Some(child)),
            _dir: dir,
        })
    }

    /// Stop the server process and wait for it to exit. Stopping a stopped
    /// peer is a no-op.
    pub async fn stop(&self) -> Result<(), PeerError> {
        if let Some(mut child) = self.child.lock().await.take() {
            child.kill().await.map_err(|source| PeerError::Io {
                name: self.name.clone(),
                what: "stopping cyphr-server",
                source,
            })?;
        }
        Ok(())
    }

    /// Start a stopped peer again on its old address, with the same data
    /// directory and key file.
    pub async fn restart(&self, bins: &Bins) -> Result<(), PeerError> {
        let mut slot = self.child.lock().await;
        if slot.is_some() {
            return Ok(());
        }
        let listen = self.addr.to_string();
        let (child, addr) = self
            .launch
            .spawn(bins, &self.name, &listen, &self.data_dir, &self.stdout)
            .await?;
        if addr != self.addr {
            // Clients' routes point at the old address; a peer that moved
            // would silently drop out of the scenario.
            return Err(PeerError::Command {
                name: self.name.clone(),
                what: "restart",
                reason: format!("came back on {addr}, not {}", self.addr),
            });
        }
        *slot = Some(child);
        Ok(())
    }

    /// Configure the peer to gossip with `peers` every `interval_secs` and
    /// start it again (a peer's own address is only known once it runs, so
    /// the list cannot be given at first start). `peers` are the proxy
    /// routes by which this peer dials the others, so the proxy carries,
    /// and can cut, the gossip link.
    pub async fn enable_gossip(
        &self,
        bins: &Bins,
        peers: &[SocketAddr],
        interval_secs: u64,
    ) -> Result<(), PeerError> {
        let io_err = |what| {
            let name = self.name.clone();
            move |source| PeerError::Io { name, what, source }
        };
        let mut config = match std::fs::read_to_string(&self.launch.config) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io_err("reading config")(e)),
        };
        let list = peers
            .iter()
            .map(|a| format!("\"http://{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        config.push_str(&format!(
            "\n[gossip]\npeers = [{list}]\ninterval_secs = {interval_secs}\n"
        ));
        std::fs::write(&self.launch.config, config).map_err(io_err("writing config"))?;
        self.stop().await?;
        self.restart(bins).await
    }

    /// Rotate the peer's signing key with the shipped offline command
    /// (`cyphr-server rotate-key`), which needs the peer stopped, then
    /// start it again. Returns the rotated-in key's thumbprint.
    pub async fn rotate_key(&self, bins: &Bins) -> Result<String, PeerError> {
        let fail = |reason: String| PeerError::Command {
            name: self.name.clone(),
            what: "rotate-key",
            reason,
        };
        self.stop().await?;
        let out = Command::new(&bins.server)
            .arg("--config")
            .arg(&self.launch.config)
            .args(["rotate-key", "--data-dir"])
            .arg(&self.data_dir)
            .arg("--signing-key-path")
            .arg(&self.launch.key)
            .output()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr).into_owned()));
        }
        // The command reports `rotated <pg> to key <tmb>`.
        let report = String::from_utf8_lossy(&out.stdout);
        let tmb = report
            .split_whitespace()
            .last()
            .ok_or_else(|| fail(format!("no key in the report {report:?}")))?
            .to_owned();
        self.restart(bins).await?;
        Ok(tmb)
    }

    /// Stop the peer, run one offline `cyphr-server` operator command on
    /// its data (never given the signing key), and start it again.
    async fn offline(
        &self,
        bins: &Bins,
        what: &'static str,
        args: &[&std::ffi::OsStr],
    ) -> Result<String, PeerError> {
        let fail = |reason: String| PeerError::Command {
            name: self.name.clone(),
            what,
            reason,
        };
        self.stop().await?;
        let out = Command::new(&bins.server)
            .arg("--config")
            .arg(&self.launch.config)
            .arg(what)
            .args(args)
            .arg("--data-dir")
            .arg(&self.data_dir)
            .output()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if !out.status.success() {
            return Err(fail(String::from_utf8_lossy(&out.stderr).into_owned()));
        }
        self.restart(bins).await?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Snapshot the peer's data with `cyphr-server backup`; returns the
    /// backup's path.
    pub async fn backup(&self, bins: &Bins) -> Result<PathBuf, PeerError> {
        // Beside the data directory, in the peer's own temp dir.
        let dest = self.data_dir.with_file_name(format!(
            "backup-{}",
            self.backups.fetch_add(1, Ordering::Relaxed)
        ));
        self.offline(bins, "backup", &[dest.as_os_str()]).await?;
        Ok(dest)
    }

    /// Put a backup back with `cyphr-server restore`; returns the command's
    /// report, which states the window the restore lost.
    pub async fn restore(&self, bins: &Bins, from: &Path) -> Result<String, PeerError> {
        self.offline(bins, "restore", &[from.as_os_str()]).await
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
