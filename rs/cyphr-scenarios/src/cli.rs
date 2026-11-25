//! One device's `cyphr` CLI: its own store and keystore, driven as a
//! subprocess with `--format json`.
//!
//! The CLI's machine contract is a JSON document on stdout on success, and
//! on failure a non-zero exit whose last stderr line is
//! `{"error":{"kind","message"}}`, `kind` being a [`RefusalKind`] lowercased
//! or `other`. A refusal is a verdict the scenario may assert on; `other`
//! is a failure of the step itself.

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use serde_json::{Map, Value};
use tempfile::TempDir;

use crate::actions::{ActionError, ActionResult, Refusal, RefusalKind};
use crate::bins::Bins;

/// How long a `cyphr` call waits on a peer, in seconds. A loaded host (the
/// large network scenario runs ten servers and eight clients at once) needs
/// longer than the scenarios' usual bound before a slow peer is a dead one.
static PEER_TIMEOUT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(5);

pub fn set_peer_timeout_secs(secs: u64) {
    PEER_TIMEOUT_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

pub struct Device {
    pub store: PathBuf,
    pub keystore: PathBuf,
    dir: TempDir,
}

impl Device {
    /// Write `contents` to a file in this device's directory, as a file a
    /// person would have saved, and return its path.
    pub fn save(&self, name: &str, contents: &[u8]) -> std::io::Result<PathBuf> {
        let path = self.dir.path().join(name);
        std::fs::write(&path, contents)?;
        Ok(path)
    }

    pub fn new() -> std::io::Result<Device> {
        let dir = tempfile::tempdir()?;
        Ok(Device {
            store: dir.path().join("store"),
            keystore: dir.path().join("keys.json"),
            dir,
        })
    }

    /// A scratch path inside the device (exports, choices files).
    pub fn scratch(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Run `cyphr <args>` against this device.
    pub async fn run(&self, bins: &Bins, args: &[&str]) -> ActionResult<Value> {
        let peer_wait = PEER_TIMEOUT_SECS.load(std::sync::atomic::Ordering::Relaxed);
        let mut cmd = tokio::process::Command::new(&bins.cli);
        cmd.arg("--store")
            .arg(format!("file:{}", self.store.display()))
            .arg("--keystore")
            .arg(&self.keystore)
            .args(["--format", "json", "--peer-timeout-secs"])
            .arg(peer_wait.to_string())
            .args(bind_values(args));
        // The CLI bounds its own peer calls; a call that outlives them many
        // times over has hung (a deadlocked process was seen once at the large
        // size), which must end the run with a name, not stall it for ever.
        let hung = Duration::from_secs(peer_wait * 6 + 60);
        let out = run_bounded(cmd, hung).await.map_err(|e| match e {
            Bounded::Spawn(e) => ActionError::Failed(format!("spawning cyphr: {e}")),
            Bounded::Hung(dump) => ActionError::Failed(format!(
                "cyphr {args:?} hung for over {hung:?}; {}",
                dump.describe()
            )),
        })?;
        if out.status.success() {
            return serde_json::from_slice(&out.stdout).map_err(|e| {
                ActionError::Failed(format!(
                    "cyphr {args:?} printed no JSON ({e}): {}",
                    String::from_utf8_lossy(&out.stdout)
                ))
            });
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let err = stderr
            .lines()
            .last()
            .and_then(|l| serde_json::from_str::<Value>(l).ok());
        let kind = err.as_ref().and_then(|e| e["error"]["kind"].as_str());
        let detail = err
            .as_ref()
            .and_then(|e| e["error"]["message"].as_str())
            .unwrap_or(&stderr)
            .to_owned();
        match kind.and_then(|k| refusal_kind(k, &detail)) {
            Some(kind) => Err(ActionError::Refused(Refusal { kind, detail })),
            None => Err(ActionError::Failed(format!("cyphr {args:?}: {detail}"))),
        }
    }
}

/// Thread dumps taken of hung children, for the harness to keep beside the
/// peer logs of a failing run.
static HANG_DUMPS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// The thread dumps taken so far in this process.
pub fn hang_dumps() -> Vec<PathBuf> {
    HANG_DUMPS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// What was learned of a child that outlived its bound.
pub struct Dump {
    /// Where the dump was saved, or why it could not be taken.
    pub outcome: Result<PathBuf, String>,
}

impl Dump {
    fn describe(&self) -> String {
        match &self.outcome {
            Ok(path) => format!("thread dump at {}", path.display()),
            Err(why) => format!("no thread dump: {why}"),
        }
    }
}

enum Bounded {
    Spawn(std::io::Error),
    Hung(Dump),
}

/// Run `cmd` to completion, but no longer than `hung`. A child still
/// running at the bound has its threads dumped before it is killed: a
/// deadlock leaves nothing else to read.
async fn run_bounded(mut cmd: tokio::process::Command, hung: Duration) -> Result<Output, Bounded> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    allow_tracing(&mut cmd);
    let mut child = cmd.spawn().map_err(Bounded::Spawn)?;
    let out_task = drain(child.stdout.take().expect("stdout was piped"));
    let err_task = drain(child.stderr.take().expect("stderr was piped"));
    match tokio::time::timeout(hung, child.wait()).await {
        Ok(status) => {
            let status = status.map_err(Bounded::Spawn)?;
            Ok(Output {
                status,
                stdout: out_task.await.unwrap_or_default(),
                stderr: err_task.await.unwrap_or_default(),
            })
        },
        Err(_) => {
            let dump = match child.id() {
                Some(pid) => thread_dump(pid).await,
                None => Dump {
                    outcome: Err("the child had already exited".into()),
                },
            };
            let _ = child.kill().await;
            Err(Bounded::Hung(dump))
        },
    }
}

fn drain<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut pipe: R,
) -> tokio::task::JoinHandle<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf).await;
        buf
    })
}

/// Let any process attach a debugger to the child (the Yama restriction
/// otherwise confines `ptrace` to a debugger's own descendants). The
/// setting survives `exec`.
fn allow_tracing(cmd: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        const PR_SET_PTRACER: libc::c_int = 0x5961_6d61;
        // SAFETY: `prctl` is async-signal-safe and touches only the
        // calling (child) process, between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(PR_SET_PTRACER, libc::c_ulong::MAX, 0, 0, 0);
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

/// Save every thread's backtrace of process `pid` to a file, with `gdb`
/// when it is on the path, else through `nix shell nixpkgs#gdb`.
pub async fn thread_dump(pid: u32) -> Dump {
    const GDB_ARGS: [&str; 4] = ["-batch", "-ex", "thread apply all bt", "-p"];
    let pid_s = pid.to_string();
    let mut attempts: Vec<Vec<&str>> = vec![vec!["gdb"]];
    attempts.push(vec!["nix", "shell", "nixpkgs#gdb", "-c", "gdb"]);
    let mut why = Vec::new();
    for argv in attempts {
        let mut cmd = tokio::process::Command::new(argv[0]);
        cmd.args(&argv[1..])
            .args(GDB_ARGS)
            .arg(&pid_s)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(180), cmd.output()).await {
            Ok(Ok(out)) if out.status.success() => return save_dump(pid, &out.stdout, &out.stderr),
            Ok(Ok(out)) => why.push(format!(
                "`{}` exited {}: {}",
                argv.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .last()
                    .unwrap_or_default()
            )),
            Ok(Err(e)) => why.push(format!("`{}`: {e}", argv[0])),
            Err(_) => why.push(format!("`{}` timed out", argv.join(" "))),
        }
    }
    Dump {
        outcome: Err(why.join("; ")),
    }
}

fn save_dump(pid: u32, stdout: &[u8], stderr: &[u8]) -> Dump {
    // A fresh 0700 directory, never a predictable path in a shared temp dir.
    let saved = tempfile::Builder::new()
        .prefix(&format!("cyphr-hang-{pid}-"))
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .map(tempfile::TempDir::keep)
        .and_then(|dir| {
            let path = dir.join("threads.txt");
            let mut text = stdout.to_vec();
            text.extend_from_slice(b"\n--- gdb stderr ---\n");
            text.extend_from_slice(stderr);
            std::fs::write(&path, text).map(|()| path)
        });
    match saved {
        Ok(path) => {
            HANG_DUMPS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(path.clone());
            Dump { outcome: Ok(path) }
        },
        Err(e) => Dump {
            outcome: Err(format!("saving the dump: {e}")),
        },
    }
}

/// `--flag value` as `--flag=value` for the flags whose values are
/// identifiers: a principal id is random base64url and one that starts with
/// `-` would otherwise be read as a flag.
fn bind_values(args: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        match (args[i], args.get(i + 1)) {
            (flag @ ("--identity" | "--signer" | "--key" | "--peer"), Some(value)) => {
                out.push(format!("{flag}={value}"));
                i += 2;
            },
            (arg, _) => {
                out.push(arg.to_owned());
                i += 1;
            },
        }
    }
    out
}

/// The CLI's `error.kind` names a [`RefusalKind`] lowercased.
///
/// A `protocol` refusal (HTTP 422) is read from the peer's own message.
fn refusal_kind(kind: &str, detail: &str) -> Option<RefusalKind> {
    use RefusalKind::*;
    Some(match kind {
        "protocol" => protocol_kind(detail),
        "stale" => Stale,
        "unauthorized" if detail.to_ascii_lowercase().contains("revoked") => Revoked,
        "unauthorized" => Unauthorized,
        "revoked" => Revoked,
        "keynotactive" => KeyNotActive,
        "cozreuse" => CozReuse,
        "malformed" => Malformed,
        "forked" => Forked,
        "unreachable" => Unreachable,
        "rollback" => Rollback,
        "toolarge" => TooLarge,
        "unknownversion" => UnknownVersion,
        _ => return None,
    })
}

/// A field of a CLI answer that the contract says is a string.
pub fn field(v: &Value, name: &str) -> ActionResult<String> {
    v[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ActionError::Failed(format!("cyphr answered without `{name}`: {v}")))
}

// The keystore file is the CLI's own format (a flat map of thumbprint to
// `{alg, pub_key, prv_key, tag}` plus a version `v`). The harness edits it
// only to carry a PUBLIC key between devices, the step a pairing channel
// performs; a private key is copied only by
// `steal_key`, which is a theft on purpose.

fn read_keystore(path: &Path) -> ActionResult<Map<String, Value>> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| ActionError::Failed(format!("reading {}: {e}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|e| ActionError::Failed(format!("parsing {}: {e}", path.display())))
}

/// The keystore entry for `tmb`.
pub fn key_entry(keystore: &Path, tmb: &str) -> ActionResult<Value> {
    read_keystore(keystore)?
        .remove(tmb)
        .ok_or_else(|| ActionError::Failed(format!("no key {tmb} in {}", keystore.display())))
}

/// `entry` with its private half removed.
pub fn public_half(mut entry: Value) -> Value {
    entry["prv_key"] = Value::String(String::new());
    entry
}

/// Add `entry` under `tmb`, keeping every other entry.
pub fn put_key(keystore: &Path, tmb: &str, entry: Value) -> ActionResult<()> {
    let mut doc = read_keystore(keystore)?;
    doc.entry("v").or_insert(Value::from(1));
    doc.insert(tmb.to_owned(), entry);
    let text =
        serde_json::to_string_pretty(&doc).map_err(|e| ActionError::Failed(e.to_string()))?;
    std::fs::write(keystore, text)
        .map_err(|e| ActionError::Failed(format!("writing {}: {e}", keystore.display())))
}

/// Copy a whole directory tree: a device copied as a thief would.
pub fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), dest)?;
        }
    }
    Ok(())
}

/// What a peer's protocol refusal says went wrong.
pub(crate) fn protocol_kind(message: &str) -> RefusalKind {
    let m = message.to_ascii_lowercase();
    if m.contains("coz_reuse") {
        RefusalKind::CozReuse
    } else if m.contains("revoked") {
        RefusalKind::Revoked
    } else if m.contains("not active") || m.contains("unknown key") || m.contains("unknownkey") {
        RefusalKind::KeyNotActive
    } else {
        RefusalKind::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Claim: a child that outlives its bound has its threads dumped before
    // it is killed. Positive control: a deliberately hung `sleep` is dumped
    // (gdb attaches to it, and a thread's backtrace is in the file).
    // Negative control: a child that finishes in time yields its output and
    // no dump.
    // Turns red if: the bound kills the child without a dump, or the dump
    // is attached to the wrong process.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hung_child_is_dumped_before_it_is_killed() {
        let done = run_bounded(
            {
                let mut c = tokio::process::Command::new("echo");
                c.arg("fine");
                c
            },
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            done.ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()),
            Some("fine".to_owned())
        );

        let mut hung = tokio::process::Command::new("sleep");
        hung.arg("600");
        let Err(Bounded::Hung(dump)) = run_bounded(hung, Duration::from_secs(1)).await else {
            panic!("a child that sleeps for 600s must exceed a 1s bound");
        };
        match dump.outcome {
            Ok(path) => {
                let text = std::fs::read_to_string(&path).expect("read the dump");
                assert!(text.contains("Thread 1"), "no thread backtrace in {text}");
                assert!(
                    text.contains("nanosleep") || text.contains("clock_nanosleep"),
                    "{text}"
                );
            },
            // A host with neither gdb nor a reachable nix cannot take it;
            // the report must then say why.
            Err(why) => {
                eprintln!("no dump: {why}");
                assert!(!why.is_empty());
            },
        }
    }
}
