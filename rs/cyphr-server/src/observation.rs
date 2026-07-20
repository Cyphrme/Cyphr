//! Durable, server-local naked-revoke observations (SPEC.md §6.4).
//!
//! A witness that accepts an uncommitted `key/revoke` coz records the
//! observation *here*, deliberately not on the principal's chain and not in
//! the rebuildable index:
//!
//! - A naked revoke mutates no PR (SPEC §6.4): the principal's chain is
//!   untouched, so the chain is the wrong home.
//! - The index is a derived projection a reindex rebuilds from blobs (root
//!   `AGENTS.md` I1): an observation kept there would be silently wiped by
//!   the next reindex, which is exactly the durability the acceptance suite
//!   pins against.
//!
//! So this is independent, durable, server-local truth: its own fjall
//! database, opened beside the blob store and the index, keyed by
//! `(principal_id, revoked key, kind)`.

use std::path::Path;

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use fjall::{Database, Keyspace, KeyspaceCreateOptions};
use serde::{Deserialize, Serialize};

/// Whether a naked revoke was signed by the revoked key itself or by an
/// outsider.
///
/// The distinction is load-bearing: only a *self-signed* revoke refuses the
/// key at login (proof of possession by the key's own holder). A
/// *third-party* claim is recorded and surfaced but never blocks a login --
/// the anti-griefing posture pending the SPEC §6.4 clarification (forge
/// issue #106).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// The signature verifies under the revoked key itself.
    SelfRevoke,
    /// The signature verifies under a different, outsider-supplied key.
    ThirdParty,
}

impl ObservationKind {
    /// The one key byte separating the two kinds in the store, so a
    /// self-revoke and a third-party claim over the same `(principal, key)`
    /// occupy distinct slots and never overwrite one another.
    fn tag(self) -> u8 {
        match self {
            ObservationKind::SelfRevoke => 0,
            ObservationKind::ThirdParty => 1,
        }
    }
}

/// A recorded naked-revoke observation: the interpreted verdict plus the
/// exact coz that produced it, retained so the claim can be surfaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub kind: ObservationKind,
    pub principal_id: String,
    /// The revoked key's thumbprint, base64url.
    pub revoked_tmb: String,
    /// The revocation timestamp the coz declared.
    pub rvk: i64,
    /// The naked-revoke coz as received (`{pay, sig, key?}`), retained for
    /// surfacing the claim.
    pub coz: serde_json::Value,
}

/// Failures from the observation store. A store failure is server
/// infrastructure breaking, never a client error.
#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    /// The underlying fjall store failed.
    #[error("observation store backend: {0}")]
    Backend(String),
    /// A `spawn_blocking` task failed to join.
    #[error("observation store task join: {0}")]
    Join(String),
    /// Serializing an observation record failed.
    #[error("observation serialize: {0}")]
    Serialize(String),
}

fn backend(e: fjall::Error) -> ObservationError {
    ObservationError::Backend(e.to_string())
}

/// Encode an observation key: `principal_id` length + bytes, then the
/// thumbprint length + bytes, then the kind tag byte.
///
/// Both variable-length segments are length-prefixed so the encoding is
/// injective: without it, `(pr = "a", tmb = "bc")` and `(pr = "ab", tmb =
/// "c")` would collide on the concatenated bytes. This mirrors
/// `cyphr-index-fjall`'s `commit_key` rationale; here only point lookups
/// run, but injective keys are still required for correctness.
fn observation_key(principal_id: &str, tmb: &[u8], kind: ObservationKind) -> Vec<u8> {
    let pid = principal_id.as_bytes();
    let mut key = Vec::with_capacity(4 + pid.len() + 4 + tmb.len() + 1);
    key.extend_from_slice(&(pid.len() as u32).to_be_bytes());
    key.extend_from_slice(pid);
    key.extend_from_slice(&(tmb.len() as u32).to_be_bytes());
    key.extend_from_slice(tmb);
    key.push(kind.tag());
    key
}

/// A durable server-local store of naked-revoke observations, backed by a
/// dedicated fjall database.
pub struct ObservationStore {
    /// Held so the keyspace's backing database outlives it.
    _db: Database,
    observations: Keyspace,
}

impl ObservationStore {
    /// Open or create the observation store at `path`, owning a dedicated
    /// database (separate from the blob store and the index, so its
    /// failure domain is independent of theirs).
    pub fn open(path: &Path) -> Result<Self, ObservationError> {
        let db = Database::builder(path).open().map_err(backend)?;
        let observations = db
            .keyspace("observations", KeyspaceCreateOptions::default)
            .map_err(backend)?;
        Ok(Self {
            _db: db,
            observations,
        })
    }

    /// Record a naked-revoke observation over `(principal_id, tmb, kind)`.
    ///
    /// A later observation of the same kind over the same key supersedes an
    /// earlier one; the two kinds occupy distinct slots (see
    /// [`ObservationKind::tag`]), so a third-party claim can never displace
    /// a self-revoke.
    pub async fn record(
        &self,
        principal_id: &str,
        tmb: &Thumbprint,
        kind: ObservationKind,
        rvk: i64,
        coz: serde_json::Value,
    ) -> Result<(), ObservationError> {
        let record = Observation {
            kind,
            principal_id: principal_id.to_string(),
            revoked_tmb: Base64UrlUnpadded::encode_string(tmb.as_bytes()),
            rvk,
            coz,
        };
        let key = observation_key(principal_id, tmb.as_bytes(), kind);
        let value = serde_json::to_vec(&record)
            .map_err(|e| ObservationError::Serialize(e.to_string()))?;
        let observations = self.observations.clone();
        tokio::task::spawn_blocking(move || observations.insert(key, value).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))?
    }

    /// Whether `tmb` carries a self-signed naked-revoke observation under
    /// `principal_id`. This is the login gate: a true here refuses the key
    /// even though it is still active on-chain.
    pub async fn is_self_revoked(
        &self,
        principal_id: &str,
        tmb: &Thumbprint,
    ) -> Result<bool, ObservationError> {
        let key = observation_key(principal_id, tmb.as_bytes(), ObservationKind::SelfRevoke);
        let observations = self.observations.clone();
        tokio::task::spawn_blocking(move || observations.contains_key(&key).map_err(backend))
            .await
            .map_err(|e| ObservationError::Join(e.to_string()))?
    }
}
