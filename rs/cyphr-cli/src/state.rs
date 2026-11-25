//! What a verifier keeps between runs besides the chain itself: which
//! peers answered and when, the forks and naked revokes it holds, and how
//! far its record has reached.
//!
//! The chain is the store's (append-only, so a record built from it never
//! regresses); this file holds only what the store has no place for. It
//! sits beside the store directory, so a store swap leaves it be.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use cyphr::replay::WireBundle;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    /// By the principal's wire id (bare digest).
    #[serde(default)]
    pub principals: BTreeMap<String, PrincipalState>,
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

/// A naked revoke the verifier verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldRevoke {
    /// The revoked key.
    pub tmb: String,
    /// The `rvk` the revoke declared.
    pub rvk: i64,
    /// The first peer that served it.
    pub peer: String,
    /// The signed envelope, so the verifier can serve it on.
    pub envelope: Value,
}

/// How a fork ended (SPEC 15.8): a chain continued past one branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    /// The fork commit the chain kept.
    pub kept: String,
    /// The fork commit it abandoned.
    pub abandoned: String,
    /// The key that settled the fork: the signer of the commit extending
    /// the kept one, or of the commit that removed the rival's signer;
    /// `None` when no commit did (a naked revoke).
    pub by: Option<String>,
}

/// Two commits over one `pre`, with the other branch kept as evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldFork {
    /// The commit position both commits take.
    pub height: usize,
    /// The Principal Root both extend.
    pub pre: Option<String>,
    /// The two commit ids.
    pub commits: [String; 2],
    /// The commit the record does not follow.
    pub rival: WireBundle,
    /// When the verifier first saw the fork.
    pub first_seen: i64,
    /// Set once a chain continued past one branch.
    pub resolution: Option<Resolution>,
}

impl HeldFork {
    /// Whether `commits` are this fork's two commits, in either order.
    #[must_use]
    pub fn is(&self, commits: &[String; 2]) -> bool {
        let mut mine = self.commits.clone();
        let mut theirs = commits.clone();
        mine.sort();
        theirs.sort();
        mine == theirs
    }
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
    /// The naked revokes held.
    #[serde(default)]
    pub revoked: Vec<HeldRevoke>,
    /// The forks held, resolved or not.
    #[serde(default)]
    pub forks: Vec<HeldFork>,
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
