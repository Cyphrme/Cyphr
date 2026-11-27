//! What a verifier keeps between runs besides the chain itself: which
//! peers answered and when, how far its record has reached, and the
//! viewer's own recovery choice.
//!
//! The chain, its forks and its naked revokes are the store's (the engine
//! keeps them, and the verifier reads them back); this file holds only what
//! the store has no place for. It
//! sits beside the store directory, so a store swap leaves it be.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// State file version this build writes and reads.
const VERSION: u64 = 1;

/// The state file of the store at `store`.
#[must_use]
pub fn path_for(store: &Path) -> PathBuf {
    let mut p = store.as_os_str().to_owned();
    p.push(".verifier.json");
    PathBuf::from(p)
}

/// The whole file: one entry per principal the verifier has judged.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierState {
    #[serde(default)]
    v: u64,
    /// By the principal's id.
    #[serde(default)]
    pub principals: BTreeMap<cyphr::PrincipalGenesis, PrincipalState>,
}

/// How one peer last stood, on the verifier's own clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSeen {
    /// When the verifier last got an answer from it; `None` if never.
    pub answered_at: Option<i64>,
    /// When the verifier last asked.
    pub asked_at: i64,
    /// `current`, `extended`, `behind`, `forked` or `failed`.
    pub standing: String,
    /// Why it failed, when it did.
    pub detail: Option<String>,
}

/// A viewer's own choice of branch head for a principal in Error. It is
/// local: never stored with commits, never sent to a peer, and it never
/// changes the protocol's verdict (human recovery, SPEC 14).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryChoice {
    /// The branch head trusted.
    pub head: String,
    /// Why, in the viewer's words.
    pub reason: Option<String>,
    /// When the choice was made (verifier clock, Unix seconds).
    pub chosen_at: i64,
}

/// Everything kept for one principal.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PrincipalState {
    /// By peer name, as the caller gave it.
    #[serde(default)]
    pub peers: BTreeMap<String, PeerSeen>,
    /// When the verifier last got any answer.
    #[serde(default)]
    pub last_pull_at: Option<i64>,
    /// The most commits the record has held: it never falls below it.
    #[serde(default)]
    pub commits_high: usize,
    /// The viewer's recovery choice, if any.
    #[serde(default)]
    pub recovery: Option<RecoveryChoice>,
}

impl VerifierState {
    /// Read the state at `path`; a missing file is an empty state.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is not a state file, or states a version
    /// this build does not read.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        let state: Self = serde_json::from_slice(&bytes)?;
        if state.v != VERSION {
            return Err(crate::Error::InvalidArgument(format!(
                "verifier state {} is version {}, not the supported {VERSION}",
                path.display(),
                state.v
            )));
        }
        Ok(state)
    }

    /// Write the state to `path` through a sibling file, so a crash leaves
    /// the old state or the new, never half.
    ///
    /// # Errors
    ///
    /// The write or the rename failed.
    pub fn save(&mut self, path: &Path) -> crate::Result<()> {
        self.v = VERSION;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
