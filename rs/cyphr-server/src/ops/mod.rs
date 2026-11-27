//! Offline operator commands over a stopped server's data directory:
//! `backup`, `restore` ([`snapshot`]) and `export`, `verify-all`
//! ([`chains`]).
//!
//! Peers are mirrors of principal-signed objects: a restored
//! peer holds an older prefix of every chain it lost and catches up by
//! re-push, and no signed statement of the server's names what it held.
//! These commands therefore keep no watermark and refuse nothing on
//! behalf of one.
//!
//! Every command opens the store itself, and fjall's exclusive directory
//! lock refuses the open while a server runs. That lock is the whole
//! "the server is stopped" check.

pub mod chains;
pub mod snapshot;

use std::collections::BTreeMap;
use std::path::PathBuf;

use cyphr::PrincipalGenesis;
use cyphr_storage::index::Indexer;

use crate::AppState;
use crate::config::ServerConfig;

/// Why an operator command could not complete.
#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    /// A filesystem operation failed.
    #[error("{what} {}: {source}", path.display())]
    Io {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The signing key file sits inside the tree a backup copies.
    #[error(
        "the signing key {} is inside {}, which the backup would copy; keep the key outside the \
         data directory's record/ tree (key storage is a separate decision)",
        key.display(), record.display()
    )]
    KeyInRecord { key: PathBuf, record: PathBuf },
    /// The command's precondition does not hold.
    #[error("{0}")]
    Refused(String),
    /// The store could not be opened (a running server holds its lock) or read.
    #[error("{what}: {source}")]
    Store {
        what: &'static str,
        source: Box<dyn std::error::Error>,
    },
}

impl OpsError {
    pub(crate) fn io(
        what: &'static str,
        path: &std::path::Path,
    ) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.to_owned();
        move |source| Self::Io { what, path, source }
    }

    pub(crate) fn store<E: std::error::Error + 'static>(
        what: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |e| Self::Store {
            what,
            source: Box::new(e),
        }
    }
}

/// Open the store of `config` for an offline command. The signing key is
/// never loaded: no operator command needs it, and not reading it keeps
/// private key material out of these commands entirely.
pub(crate) fn open(config: &ServerConfig) -> Result<AppState, OpsError> {
    let mut config = config.clone();
    config.signing_key_path = None;
    AppState::new(config).map_err(|e| OpsError::Store {
        what: "opening the data directory (is a server still running on it?)",
        source: e,
    })
}

/// Commit counts per stored principal, after healing the index from the
/// durable manifests (the index is a cache, I1).
pub(crate) async fn commit_counts(
    state: &AppState,
) -> Result<BTreeMap<PrincipalGenesis, u64>, OpsError> {
    state
        .engine
        .rebuild_index_from_manifests()
        .await
        .map_err(OpsError::store("healing the index"))?;
    let principals = state
        .engine
        .indexer()
        .list_principals()
        .await
        .map_err(OpsError::store("listing principals"))?;
    Ok(principals
        .into_iter()
        .map(|p| (p.principal_id, p.commit_count))
        .collect())
}
