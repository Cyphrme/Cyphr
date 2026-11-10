//! `backup` and `restore`: a copy of the `record/` tree and its return.
//!
//! **Consistency.** `record/` holds every fjall database the server was
//! told (blobs with the EML keyspaces, observations). Each is opened by
//! this command first, which takes fjall's exclusive lock (no server is
//! running) and replays its journal; the commit counts are taken, and the
//! stores are closed before the copy. The lock cannot be held across the
//! copy, so a server started mid-copy could tear it. The copy is therefore
//! checked: it must open and replay cleanly, and hold exactly the commit
//! counts taken before the copy, or the backup is refused and deleted.
//! The check detects a torn copy, it does not prevent one: a change that
//! leaves every commit count as it was would pass it: chain writes always
//! add a commit, but a write to the observation store (the key death-set)
//! does not, and is not detected. `index/` is derived (ADR-0002) and is neither copied nor trusted
//! back: a restore drops it and rebuilds from the restored blobs (I1).
//!
//! **Keys.** The copy is of `record/` only. The server's signing key
//! lives at `signing_key_path`; a backup refuses to run if that file sits
//! inside `record/`, so a backup never copies private key material.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::{OpsError, commit_counts, open};
use crate::config::ServerConfig;

/// Where a displaced `record/` goes on restore.
const DISPLACED: &str = "record.pre-restore";

/// A finished backup.
#[derive(Debug)]
pub struct BackupReport {
    pub dest: PathBuf,
    pub principals: usize,
    pub commits: u64,
}

impl fmt::Display for BackupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "backed up {} principal(s), {} commit(s) to {}",
            self.principals,
            self.commits,
            self.dest.display()
        )
    }
}

/// What a restore took away: per principal, the commits the live store
/// held and the restored one holds.
#[derive(Debug)]
pub struct RestoreReport {
    pub displaced: Option<PathBuf>,
    pub lost: Vec<Lost>,
}

/// A principal whose restored chain is shorter than the one it replaced.
#[derive(Debug, PartialEq, Eq)]
pub struct Lost {
    pub principal: String,
    pub had: u64,
    pub restored: u64,
}

impl fmt::Display for RestoreReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lost.is_empty() {
            write!(f, "restored; no commits lost")?;
        } else {
            let commits: u64 = self.lost.iter().map(|l| l.had - l.restored).sum();
            write!(
                f,
                "restored; lost window: {commits} commit(s) across {} principal(s); the \
                 principals re-push to fill it",
                self.lost.len()
            )?;
            for l in &self.lost {
                write!(
                    f,
                    "\nlost {}: had {}, restored {}",
                    l.principal, l.had, l.restored
                )?;
            }
        }
        if let Some(d) = &self.displaced {
            write!(f, "\nthe replaced record is kept at {}", d.display())?;
        }
        Ok(())
    }
}

fn refuse_key_in_record(config: &ServerConfig) -> Result<(), OpsError> {
    let Some(key) = &config.signing_key_path else {
        return Ok(());
    };
    let record = config.record_dir();
    // An absent path cannot be canonicalized; an absent key file is not in
    // the tree either.
    if let (Ok(key), Ok(record)) = (key.canonicalize(), record.canonicalize()) {
        if key.starts_with(&record) {
            return Err(OpsError::KeyInRecord { key, record });
        }
    }
    Ok(())
}

/// Copy `record/` of the stopped server at `config.data_dir` to `dest`
/// (which must not exist). The copy appears under `dest` only once whole
/// and verified against the commit counts taken before it.
pub async fn backup(config: &ServerConfig, dest: &Path) -> Result<BackupReport, OpsError> {
    backup_with(config, dest, std::future::ready(())).await
}

/// [`backup`], awaiting `between` after the counts are taken and the store
/// is closed, before the copy: the window in which a server could start.
/// Tests write into it.
pub async fn backup_with(
    config: &ServerConfig,
    dest: &Path,
    between: impl std::future::Future<Output = ()>,
) -> Result<BackupReport, OpsError> {
    refuse_key_in_record(config)?;
    if dest.exists() {
        return Err(OpsError::Refused(format!(
            "{} already exists",
            dest.display()
        )));
    }
    let counts = {
        let state = open(config)?;
        commit_counts(&state).await?
    };
    between.await;
    let mut partial = dest.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let _ = std::fs::remove_dir_all(&partial);
    let verified = verify_copy(config, &partial, &counts).await;
    if let Err(e) = verified {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(e);
    }
    std::fs::rename(&partial, dest).map_err(OpsError::io("publishing the backup at", dest))?;
    Ok(BackupReport {
        dest: dest.to_owned(),
        principals: counts.len(),
        commits: counts.values().sum(),
    })
}

/// Copy `record/` into `partial` and require the copy to open, replay and
/// hold exactly `expected`.
async fn verify_copy(
    config: &ServerConfig,
    partial: &Path,
    expected: &BTreeMap<String, u64>,
) -> Result<(), OpsError> {
    copy_tree(&config.record_dir(), &partial.join("record"))?;
    let mut probe = config.clone();
    probe.data_dir = partial.to_owned();
    let held = {
        let state = open(&probe)?;
        commit_counts(&state).await?
    };
    // Opening built a derived index inside the backup; it is not part of it.
    let _ = std::fs::remove_dir_all(probe.index_dir());
    if &held != expected {
        return Err(OpsError::Refused(
            "the store changed while it was copied (a server started on it?); the backup was \
             discarded"
                .into(),
        ));
    }
    Ok(())
}

/// Replace `record/` of the stopped server at `config.data_dir` with the
/// backup at `from`, keeping the replaced tree beside it, and report the
/// window the restored store lost relative to the replaced one.
pub async fn restore(config: &ServerConfig, from: &Path) -> Result<RestoreReport, OpsError> {
    refuse_key_in_record(config)?;
    let source = from.join("record");
    if !source.join("blobs").is_dir() {
        return Err(OpsError::Refused(format!(
            "{} is not a backup: no record/blobs",
            from.display()
        )));
    }
    let record = config.record_dir();
    let displaced = config.data_dir.join(DISPLACED);
    let (before, kept) = if record.exists() {
        if displaced.exists() {
            return Err(OpsError::Refused(format!(
                "{} exists from an earlier restore; remove it first",
                displaced.display()
            )));
        }
        let before = {
            let state = open(config)?;
            commit_counts(&state).await?
        };
        std::fs::rename(&record, &displaced).map_err(OpsError::io("setting aside", &record))?;
        (before, Some(displaced.clone()))
    } else {
        (BTreeMap::new(), None)
    };

    // A failed rollback is part of the error: the operator must know where
    // the displaced record is.
    let put_back = |why: OpsError| {
        let mut failed = Vec::new();
        if let Err(e) = std::fs::remove_dir_all(&record) {
            if e.kind() != std::io::ErrorKind::NotFound {
                failed.push(format!("removing the partial {}: {e}", record.display()));
            }
        }
        if kept.is_some() {
            if let Err(e) = std::fs::rename(&displaced, &record) {
                failed.push(format!("moving {} back: {e}", displaced.display()));
            }
        }
        if failed.is_empty() {
            why
        } else {
            OpsError::Refused(format!(
                "{why}; the rollback also failed ({}); the replaced record is at {}",
                failed.join("; "),
                displaced.display()
            ))
        }
    };
    if let Err(e) = copy_tree(&source, &record) {
        return Err(put_back(e));
    }
    // The index belongs to the replaced record; it is derived, so drop it
    // and let the restored blobs rebuild it.
    let index = config.index_dir();
    if index.exists() {
        if let Err(e) = std::fs::remove_dir_all(&index) {
            return Err(put_back(OpsError::io("dropping the stale index", &index)(
                e,
            )));
        }
    }
    let after = match open(config) {
        Ok(state) => commit_counts(&state).await,
        Err(e) => Err(e),
    }
    .map_err(put_back)?;

    let lost = before
        .into_iter()
        .filter_map(|(principal, had)| {
            let restored = after.get(&principal).copied().unwrap_or(0);
            (restored < had).then_some(Lost {
                principal,
                had,
                restored,
            })
        })
        .collect();
    Ok(RestoreReport {
        displaced: kept,
        lost,
    })
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), OpsError> {
    std::fs::create_dir_all(to).map_err(OpsError::io("creating", to))?;
    for entry in std::fs::read_dir(from).map_err(OpsError::io("reading", from))? {
        let entry = entry.map_err(OpsError::io("reading", from))?;
        let target = to.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(OpsError::io("inspecting", &entry.path()))?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).map_err(OpsError::io("copying", &entry.path()))?;
        }
        // Other kinds (a symlink) have no place in a fjall tree.
    }
    Ok(())
}
