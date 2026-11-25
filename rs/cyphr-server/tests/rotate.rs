//! Offline server key rotation (`cyphr-server rotate-key`), end to end
//! against the real binary and a client following the server's chain.
//!
//! No key storage is involved: the existing file at `signing_key_path` is
//! replaced in place, through `AppState::rotate_signing_key`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{ConnectError, Connector, PeerChain, PeerFailure, Request};
use cyphr_server::AppState;
use cyphr_server::auth::principal::{RotationStep, ServerPrincipal};
use cyphr_server::auth::{ServerIdentity, next_key_path};
use cyphr_server::config::ServerConfig;

mod common;

use common::write_signing_key;

fn server_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cyphr-server"))
}

/// `cyphr-server <sub> ...` with a config file that never exists, so only
/// the flags decide the data directory and key path.
fn server_cmd(data_dir: &Path, sub: &str, key_path: &Path) -> Command {
    let mut cmd = Command::new(server_binary());
    cmd.args([
        "--config",
        data_dir.join("unused.toml").to_str().unwrap(),
        sub,
    ]);
    if sub == "serve" {
        cmd.args(["--listen", "127.0.0.1:0"]);
    }
    cmd.args([
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--signing-key-path",
        key_path.to_str().unwrap(),
    ]);
    cmd
}

/// A running `cyphr-server serve`, killed on drop so a failed assertion
/// never leaks a process holding the data directory lock.
struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot the real server and wait for its bound address. Panics with the
/// server's stderr if it exits first (a boot refusal).
fn boot(data_dir: &Path, key_path: &Path) -> Server {
    let child = server_cmd(data_dir, "serve", key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cyphr-server");
    // Owned by a `Server` from the start so every path reaps the child.
    let mut server = Server {
        child,
        addr: String::new(),
    };
    let mut stdout = BufReader::new(server.child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        if stdout.read_line(&mut line).expect("read stdout") == 0 {
            let _ = server.child.wait();
            let mut stderr = String::new();
            if let Some(mut pipe) = server.child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
            }
            panic!("server exited before listening: {stderr}");
        }
        if let Some(addr) = line.trim_end().strip_prefix("listening on ") {
            server.addr = addr.to_string();
            std::thread::spawn(move || {
                let mut sink = String::new();
                let _ = std::io::Read::read_to_string(&mut stdout, &mut sink);
            });
            return server;
        }
    }
}

/// The carrier over real HTTP.
struct Http {
    base: String,
    client: reqwest::Client,
}

impl Http {
    fn new(server: &Server) -> Self {
        Self {
            base: format!("http://{}", server.addr),
            client: reqwest::Client::new(),
        }
    }

    async fn get_json(&self, target: &str) -> serde_json::Value {
        serde_json::from_slice(
            &self
                .exchange(&Request::get(target))
                .await
                .expect("GET succeeds"),
        )
        .expect("json body")
    }
}

impl Connector for Http {
    fn channel_binding(&self) -> Option<&cyphr_client::ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let resp = self
            .client
            .get(format!("{}{}", self.base, request.target))
            .send()
            .await
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(ConnectError::NonSuccess(resp.status().as_u16()));
        }
        Ok(resp
            .bytes()
            .await
            .map_err(|e| ConnectError::Unreachable(e.to_string()))?
            .to_vec())
    }
}

/// Pin the server's PG and genesis key from `/server`, like a first-contact
/// client. Returns the pinned chain (not yet followed) and the PG.
async fn pin(http: &Http) -> (PeerChain, String) {
    let discovery = http.get_json("/server").await;
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let genesis = cyphr::Key::new(
        g["alg"].as_str().expect("alg").to_string(),
        coz::Thumbprint::from_bytes(
            Base64UrlUnpadded::decode_vec(g["tmb"].as_str().expect("tmb")).expect("tmb b64"),
        ),
        Base64UrlUnpadded::decode_vec(g["pub"].as_str().expect("pub")).expect("pub b64"),
    )
    .expect("key binds its tmb")
    .with_first_seen(g["first_seen"].as_i64().expect("first_seen"));
    let pg = d["pg"].as_str().expect("pg").to_string();
    (PeerChain::pin(&pg, genesis).await, pg)
}

/// The server's signed `/tip` for its own chain.
async fn own_tip(http: &Http, pg: &str) -> serde_json::Value {
    http.get_json(&format!("/tip?pg={pg}")).await
}

fn key_file_pub(path: &Path) -> Vec<u8> {
    ServerIdentity::load_from_path(path)
        .expect("the key file loads")
        .pub_key()
        .to_vec()
}

/// A data dir whose server principal exists (one real boot), with the key
/// file it was established under. Returns the guard, dir, key path.
fn established() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let key_path = write_signing_key(dir.path());
    drop(boot(&data_dir, &key_path));
    (dir, data_dir, key_path)
}

/// Claim: `rotate-key` on a stopped server extends its principal with
/// key/replace and replaces the key file; the restarted server signs with
/// the new key, and a client following its chain accepts a tip signed by
/// the new key and refuses one signed by the retired key. `rotate-key
/// --help` exits 0 (the PeerRollover probe).
///
/// Turns red if: the subcommand is missing; the key file keeps the retired
/// key; the restarted server signs with the retired key; the client
/// accepts the retired key after following.
/// End-to-end scenario: yes (real binary, restart, PeerChain over HTTP).
#[tokio::test]
async fn rotate_key_then_restart_signs_with_the_new_key() {
    let help = Command::new(server_binary())
        .args(["rotate-key", "--help"])
        .output()
        .expect("run rotate-key --help");
    assert!(help.status.success(), "rotate-key --help must exit 0");

    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let key_path = write_signing_key(dir.path());
    let retired_pub = key_file_pub(&key_path);

    let before = boot(&data_dir, &key_path);
    let http = Http::new(&before);
    let (mut held, pg) = pin(&http).await;
    held.follow(&http).await.expect("follow before rotation");
    let old_tip = own_tip(&http, &pg).await;
    held.verify_tip(&old_tip, &pg)
        .expect("the genesis key's tip verifies before rotation");
    drop(before); // offline command: the server must be stopped

    let out = server_cmd(&data_dir, "rotate-key", &key_path)
        .output()
        .expect("run rotate-key");
    assert!(
        out.status.success(),
        "rotate-key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(key_file_pub(&key_path), retired_pub, "key file replaced");
    assert!(!next_key_path(&key_path).exists(), "no staged file remains");

    let after = boot(&data_dir, &key_path);
    let http = Http::new(&after);
    let new_tip = own_tip(&http, &pg).await;
    assert!(
        matches!(
            held.verify_tip(&new_tip, &pg),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "the stale chain does not know the rotated-in key"
    );
    held.verify_tip_following(&http, &new_tip, &pg)
        .await
        .expect("a client following the chain accepts the new key");
    assert!(
        matches!(
            held.verify_tip(&old_tip, &pg),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "the followed chain refuses the retired key"
    );
}

/// Claim: a crash after any step of a rotation (new key staged; key/replace
/// committed; key file renamed) leaves a server that boots with the key its
/// chain has active, and no `.next` remains afterwards: a staged key the
/// chain does not know is discarded, one it has active is adopted.
///
/// Turns red if: the boot refuses (record mismatch on a committed-but-not-
/// renamed rotation); the unknown staged key is adopted or left behind; or
/// the booted server signs with a key the chain has retired.
/// End-to-end scenario: yes (real binary boot after each interruption).
/// The interruption itself uses `rotate_through`: a real crash cannot be
/// scheduled between two statements of one call.
#[tokio::test]
async fn crash_after_each_rotation_step_boots_with_the_chains_active_key() {
    for (stop, rotated) in [
        (RotationStep::Staged, false),
        (RotationStep::Committed, true),
        (RotationStep::Promoted, true),
    ] {
        let (_guard, data_dir, key_path) = established();
        let retired_pub = key_file_pub(&key_path);

        let new_kp = coz::Alg::Ed25519.generate_keypair();
        {
            let state = AppState::new(ServerConfig {
                data_dir: data_dir.clone(),
                signing_key_path: Some(key_path.clone()),
                ..Default::default()
            })
            .expect("open the stopped server's store");
            let identity = state.identity.clone().expect("keyed");
            let principal =
                ServerPrincipal::bootstrap(&state.engine, identity, &key_path, &data_dir)
                    .await
                    .expect("load the server principal");
            principal
                .rotate_through(&state.engine, &new_kp, stop)
                .await
                .expect("rotation interrupted");
        } // state dropped: the store is free for the real boot

        let server = boot(&data_dir, &key_path);
        let http = Http::new(&server);
        let (mut held, pg) = pin(&http).await;
        let tip = own_tip(&http, &pg).await;
        held.verify_tip_following(&http, &tip, &pg)
            .await
            .unwrap_or_else(|e| panic!("{stop:?}: the boot signs with an inactive key: {e:?}"));
        let expect_pub = if rotated {
            new_kp.pub_bytes.clone()
        } else {
            retired_pub
        };
        assert_eq!(key_file_pub(&key_path), expect_pub, "{stop:?}: key file");
        assert!(
            !next_key_path(&key_path).exists(),
            "{stop:?}: a staged file survived the boot"
        );
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

/// Claim: a rotation leaves the key file owner-only (0600) even when the
/// operator's was wider, because the staged `<key>.next` is created 0600
/// and the rename carries that mode.
///
/// Turns red if: the rotated key file keeps or gains a wider mode.
/// End-to-end scenario: yes (real binary rotation).
#[cfg(unix)]
#[test]
fn rotation_leaves_the_key_file_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (_guard, data_dir, key_path) = established();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
        .expect("widen the operator's key file");
    let out = server_cmd(&data_dir, "rotate-key", &key_path)
        .output()
        .expect("run rotate-key");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(mode(&key_path), 0o600, "rotated key file mode");
}

/// Claim: `rotate-key` on a data directory that never had a keyed boot
/// refuses with an error telling the operator to start the server once,
/// and creates no chain (rotating there would mint a genesis as a side
/// effect of an offline command).
///
/// Turns red if: it succeeds, or refuses without the instruction, or
/// leaves a server principal record behind.
/// End-to-end scenario: yes (real binary).
#[tokio::test]
async fn rotate_key_refuses_a_never_booted_data_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let key_path = write_signing_key(dir.path());
    let before = key_file_pub(&key_path);

    let out = server_cmd(&data_dir, "rotate-key", &key_path)
        .output()
        .expect("run rotate-key");
    assert!(!out.status.success(), "must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("start the server once"), "stderr: {stderr}");
    assert_eq!(key_file_pub(&key_path), before, "key file untouched");
    assert!(
        !data_dir
            .join(cyphr_server::config::RECORD_DIR_NAME)
            .join("server-principal.json")
            .exists(),
        "no server chain may be minted"
    );
}
