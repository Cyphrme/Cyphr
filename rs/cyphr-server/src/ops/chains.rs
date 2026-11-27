//! `export` and `verify-all`: every stored chain, written out or replayed.
//!
//! **Export layout.** One file per principal, `<n>.jsonl`: a header line
//! `{"principal":"<id>"}`, then the chain as bundle lines (the push wire
//! shape, [`cyphr_storage::export_commits`]). [`import`] reads the files
//! back by submitting each line through the engine's admission path,
//! which re-verifies every signature, so an export is re-pushed rather
//! than trusted.

use std::fmt;
use std::path::Path;

use cyphr::PrincipalGenesis;
use cyphr_storage::CommitEntry;
use cyphr_storage::engine::QuarantineReason;

use super::{OpsError, commit_counts, open};
use crate::AppState;
use crate::config::ServerConfig;

/// Write every stored principal's chain under `out` (created if absent);
/// returns the principal ids written.
pub async fn export(config: &ServerConfig, out: &Path) -> Result<Vec<PrincipalGenesis>, OpsError> {
    let state = open(config)?;
    std::fs::create_dir_all(out).map_err(OpsError::io("creating", out))?;
    let mut written = Vec::new();
    for (n, id) in commit_counts(&state).await?.into_keys().enumerate() {
        let principal = state
            .engine
            .at_tip(&id)
            .await
            .map_err(OpsError::store("replaying a chain"))?
            .ok_or_else(|| OpsError::Refused(format!("principal {id} has no stored chain")))?;
        let mut body = serde_json::json!({ "principal": id }).to_string();
        for line in cyphr_storage::export_commits(&principal)
            .map_err(OpsError::store("exporting a chain"))?
        {
            body.push('\n');
            body.push_str(&line.to_json().map_err(OpsError::store("encoding a line"))?);
        }
        body.push('\n');
        let path = out.join(format!("{n}.jsonl"));
        std::fs::write(&path, body).map_err(OpsError::io("writing", &path))?;
        written.push(id);
    }
    Ok(written)
}

/// Submit every chain of an [`export`] directory to `state`; returns the
/// principal ids read.
pub async fn import(state: &AppState, dir: &Path) -> Result<Vec<PrincipalGenesis>, OpsError> {
    let mut read = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(OpsError::io("reading", dir))? {
        let path = entry.map_err(OpsError::io("reading", dir))?.path();
        let text = std::fs::read_to_string(&path).map_err(OpsError::io("reading", &path))?;
        let mut lines = text.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap_or_default())
            .map_err(OpsError::store("parsing an export header"))?;
        let id: PrincipalGenesis = header["principal"]
            .as_str()
            .ok_or_else(|| {
                OpsError::Refused(format!("{}: no principal in the header", path.display()))
            })?
            .parse()
            .map_err(|e| {
                OpsError::Refused(format!("{}: the header's principal: {e}", path.display()))
            })?;
        for line in lines {
            let bundle = CommitEntry::from_json(line)
                .map_err(OpsError::store("parsing a bundle line"))?
                .bundle()
                .map_err(OpsError::store("rebuilding a bundle"))?;
            state
                .engine
                .submit_commit(&id, None, &bundle)
                .await
                .map_err(OpsError::store("importing a bundle"))?;
        }
        read.push(id);
    }
    Ok(read)
}

/// A chain (or manifest) the replay could not reproduce.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    /// The principal it belongs to, when known.
    pub principal: Option<PrincipalGenesis>,
    pub why: String,
}

/// The outcome of [`verify_all`].
#[derive(Debug)]
pub struct VerifyReport {
    pub principals: usize,
    pub failures: Vec<Failure>,
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for x in &self.failures {
            writeln!(
                f,
                "FAIL {}: {}",
                x.principal
                    .as_ref()
                    .map_or_else(|| "(unknown principal)".to_owned(), ToString::to_string),
                x.why
            )?;
        }
        write!(
            f,
            "{} principal(s) replayed, {} failure(s)",
            self.principals,
            self.failures.len()
        )
    }
}

/// Replay every stored chain from the blob store: the index is rebuilt
/// from scratch through the admission path (every manifest's blobs
/// re-verified from genesis), then each principal is replayed onto its
/// commit log. A manifest kept out as fork evidence is retained evidence,
/// not damage, and is not a failure.
pub async fn verify_all(config: &ServerConfig) -> Result<VerifyReport, OpsError> {
    let state = open(config)?;
    let rebuild = state
        .engine
        .rebuild_index_from_scratch_with_report()
        .await
        .map_err(OpsError::store("replaying the blob store"))?;
    let mut failures: Vec<Failure> = rebuild
        .quarantined
        .into_iter()
        .filter(|q| !matches!(q.reason, QuarantineReason::Fork(_)))
        .map(|q| Failure {
            principal: q.principal_id,
            why: format!("manifest {:?} left out: {:?}", q.manifest, q.reason),
        })
        .collect();
    let counts = commit_counts(&state).await?;
    for id in counts.keys() {
        // The replay itself is what is being checked, so this asks for it
        // outright, where every other reader takes the kept state.
        let replayed = async {
            let genesis = state.engine.resolve_genesis(id, &[]).await?;
            state.engine.load_principal(id, genesis).await.map(drop)
        }
        .await;
        if let Err(e) = replayed {
            failures.push(Failure {
                principal: Some(id.clone()),
                why: e.to_string(),
            });
        }
    }
    Ok(VerifyReport {
        principals: counts.len(),
        failures,
    })
}
