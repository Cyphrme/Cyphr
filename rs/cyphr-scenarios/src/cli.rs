//! One device's `cyphr` CLI: its own store and keystore, driven as a
//! subprocess with `--output json`.
//!
//! The CLI's machine contract is a JSON document on stdout on success, and
//! on failure a non-zero exit whose last stderr line is
//! `{"error":{"kind","message"}}`, `kind` being a [`RefusalKind`] lowercased
//! or `other`. A refusal is a verdict the scenario may assert on; `other`
//! is a failure of the step itself.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use tempfile::TempDir;

use std::time::Duration;

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
        cmd
            .arg("--store")
            .arg(format!("file:{}", self.store.display()))
            .arg("--keystore")
            .arg(&self.keystore)
            .args(["--output", "json", "--peer-timeout-secs"])
            .arg(peer_wait.to_string())
            .args(bind_values(args))
            .kill_on_drop(true);
        // The CLI bounds its own peer calls; a call that outlives them many
        // times over has hung (a deadlocked process was seen once at the large
        // size), which must end the run with a name, not stall it for ever.
        let hung = Duration::from_secs(peer_wait * 6 + 60);
        let out = tokio::time::timeout(hung, cmd.output())
            .await
            .map_err(|_| ActionError::Failed(format!("cyphr {args:?} hung for over {hung:?}")))?
            .map_err(|e| ActionError::Failed(format!("spawning cyphr: {e}")))?;
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
// performs (N22 will own that channel); a private key is copied only by
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
