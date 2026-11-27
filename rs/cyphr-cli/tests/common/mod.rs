//! Shared end-to-end helpers: real `cyphr-server` processes and one user's
//! CLI environment (own keystore and store).
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

use serde_json::Value;
use tempfile::TempDir;

// ---------------------------------------------------------------- harness

pub fn server_bin() -> &'static Path {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        if let Some(p) = std::env::var_os("CYPHR_SERVER_BIN") {
            return PathBuf::from(p);
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(cargo)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "build",
                "--locked",
                "--quiet",
                "--message-format=json-render-diagnostics",
                "-p",
                "cyphr-server",
            ])
            .output()
            .expect("spawning cargo to build cyphr-server");
        assert!(
            out.status.success(),
            "building cyphr-server failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == "cyphr-server")
            .find_map(|v| v["executable"].as_str().map(PathBuf::from))
            .expect("cargo reported no cyphr-server executable")
    })
}

/// A running `cyphr-server`, killed on drop.
pub struct Server {
    child: Child,
    pub url: String,
    _dir: TempDir,
}

impl Server {
    pub fn start() -> Self {
        Self::start_gossiping(&[])
    }

    /// A server that pulls from `peers` every second (the server's own
    /// gossip timer), so a branch a peer holds reaches it without a push.
    pub fn start_gossiping(peers: &[&str]) -> Self {
        Self::start_with(peers, None)
    }

    /// A server that signs bearer tokens and answers logins for `audience`.
    pub fn start_keyed(audience: &str) -> Self {
        Self::start_with(&[], Some(audience))
    }

    fn start_with(peers: &[&str], audience: Option<&str>) -> Self {
        let dir = TempDir::new().expect("server tempdir");
        let config = dir.path().join("server.toml");
        std::fs::write(&config, "").expect("empty config");
        if !peers.is_empty() {
            let list = peers
                .iter()
                .map(|p| format!("\"{p}\""))
                .collect::<Vec<_>>()
                .join(", ");
            std::fs::write(
                &config,
                format!("[gossip]\npeers = [{list}]\ninterval_secs = 1\n"),
            )
            .expect("gossip config");
        }
        let mut serve = Command::new(server_bin());
        serve
            .arg("--config")
            .arg(&config)
            .args(["serve", "--listen", "127.0.0.1:0", "--data-dir"])
            .arg(dir.path().join("data"));
        if let Some(audience) = audience {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let kp = coz::Alg::Ed25519.generate_keypair();
            let key = dir.path().join("signing-key.json");
            std::fs::write(
                &key,
                serde_json::json!({
                    "alg": kp.alg.name(),
                    "pub_key": Base64UrlUnpadded::encode_string(&kp.pub_bytes),
                    "v": 1,
                    "prv_key": Base64UrlUnpadded::encode_string(&kp.prv_bytes),
                })
                .to_string(),
            )
            .expect("signing key");
            serve
                .arg("--signing-key-path")
                .arg(&key)
                .args(["--audience", audience]);
        }
        let mut child = serve
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning cyphr-server");
        let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
        let addr = loop {
            let line = lines
                .next()
                .expect("cyphr-server exited before announcing its address")
                .expect("reading server stdout");
            if let Some(a) = line.strip_prefix("listening on ") {
                break a.trim().to_owned();
            }
        };
        // Drain stdout so the server never blocks on a full pipe.
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            url: format!("http://{addr}"),
            _dir: dir,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One user's CLI environment: its own keystore and store.
pub struct User {
    pub dir: TempDir,
}

pub struct Ran {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Ran {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }
}

impl User {
    pub fn new() -> Self {
        Self {
            dir: TempDir::new().expect("user tempdir"),
        }
    }

    pub fn keystore(&self) -> PathBuf {
        self.dir.path().join("keys.json")
    }

    pub fn store_uri(&self) -> String {
        format!("file:{}", self.dir.path().join("data").display())
    }

    pub fn run(&self, args: &[&str]) -> Ran {
        let out = Command::new(env!("CARGO_BIN_EXE_cyphr"))
            .arg("--keystore")
            .arg(self.keystore())
            .arg("--store")
            .arg(self.store_uri())
            .args(["--format", "json"])
            .args(args)
            .output()
            .expect("running cyphr");
        Ran {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run a command that exists today; failure is a setup bug.
    pub fn setup(&self, args: &[&str]) -> Value {
        let r = self.run(args);
        assert!(r.ok, "setup `{args:?}` failed: {}", r.stderr);
        r.json()
    }

    /// Create an identity: returns its labelled id (the identity arg).
    /// `--signer` takes the genesis thumbprint: use [`tmb`].
    pub fn new_identity(&self) -> String {
        self.new_identity_alg("ES256")
    }

    /// A fresh identity with two commits: the genesis commit `upgrade` makes
    /// for a Level 1 identity, then a key add.
    pub fn new_identity_alg(&self, algo: &str) -> String {
        let g = self.setup(&["key", "generate", "--algo", algo]);
        let tmb = g["tmb"].as_str().expect("tmb").to_owned();
        let id = labelled(algo, &tmb);
        self.setup(&["upgrade", &format!("--identity={id}")]);
        self.add_key(&id);
        id
    }

    /// Commit one key addition, signed by the identity's genesis key.
    pub fn add_key(&self, identity: &str) {
        let id = format!("--identity={identity}");
        let signer = format!("--signer={}", tmb(identity));
        self.setup(&["key", "add", &id, &signer]);
    }

    /// Seed a second device directly: copy this user's keystore and store
    /// directory (all its processes have exited, so the files are quiescent).
    /// Deliberately not export/import, whose roundtrip is quarantined (#111).
    pub fn clone_identity(&self, _identity: &str) -> Self {
        let other = Self::new();
        std::fs::copy(self.keystore(), other.keystore()).expect("copy keystore");
        copy_dir(
            &self.dir.path().join("data"),
            &other.dir.path().join("data"),
        );
        other
    }

    pub fn push(&self, id: &str, peer: &str) -> Ran {
        self.run(&[
            "push",
            &format!("--identity={id}"),
            &format!("--peer={peer}"),
        ])
    }

    pub fn commit_count(&self, id: &str) -> u64 {
        self.setup(&["inspect", &format!("--identity={id}")])["commit_count"]
            .as_u64()
            .expect("commit_count")
    }
}

/// The hash an identity's genesis key of `algo` is digested under.
fn hash_name(algo: &str) -> &'static str {
    match algo {
        "ES256" => "SHA-256",
        "ES384" => "SHA-384",
        "Ed25519" => "SHA-512",
        other => panic!("no hash named for algo {other}"),
    }
}

/// The labelled principal id (`ALG:digest`) of the implicit principal on a
/// genesis key of `algo` with thumbprint `tmb`.
pub fn labelled(algo: &str, tmb: &str) -> String {
    format!("{}:{tmb}", hash_name(algo))
}

/// The bare digest of a labelled id: the genesis key's thumbprint, which
/// is what `--signer` and the keystore take.
pub fn tmb(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, digest)| digest)
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).expect("copy file");
        }
    }
}

pub fn accepted(r: &Ran, what: &str) {
    assert!(r.ok, "{what} must be accepted, got: {}", r.stderr);
}
