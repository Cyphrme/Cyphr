//! Import utilities for loading Principals from stored commit bundles.
//!
//! This module reconstructs a `Principal` by replaying bundle lines from
//! genesis: one commit per line (SPEC §4.2.1, §7.3.1), or the data actions
//! recorded between two commits (an action-only line, SPEC 4.8.1).

use coz::Thumbprint;
use cyphr::{Key, Principal};

use crate::{CommitEntry, KeyEntry};

// ============================================================================
// Types
// ============================================================================

/// How the principal was created (genesis mode).
///
/// Per SPEC §5, principals can be created implicitly (single key, no coz)
/// or explicitly (multiple keys with genesis cozies).
#[derive(Debug, Clone)]
pub enum Genesis {
    /// Implicit genesis: single key, no coz required.
    ///
    /// Per SPEC §5.1: "Identity emerges from first key possession"
    /// - `PR = AR = KR = tmb` (PG is None at L1/L2)
    Implicit(Key),

    /// Explicit genesis: the genesis key first, then the keys its genesis
    /// commit creates.
    ///
    /// Per SPEC §5.1: the genesis key adds itself and every further key by
    /// `key/create`, and `principal/create` establishes PG. The principal
    /// is constructed from the genesis key alone; replaying the genesis
    /// commit adds the rest.
    Explicit(Vec<Key>),
}

impl Genesis {
    /// The genesis key, the one a principal is constructed from; `None`
    /// for an explicit genesis listing no key.
    #[must_use]
    pub fn key(&self) -> Option<&Key> {
        match self {
            Genesis::Implicit(key) => Some(key),
            Genesis::Explicit(keys) => keys.first(),
        }
    }
}

/// Errors that can occur during import.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// No keys provided for genesis.
    #[error("genesis requires at least one key")]
    NoGenesisKeys,

    /// Entry missing required pay.now field.
    #[error("entry missing pay.now field at index {index}")]
    MissingTimestamp { index: usize },

    /// Entry missing required signature.
    #[error("entry missing sig field at index {index}")]
    MissingSig { index: usize },

    /// Signature verification failed.
    #[error("invalid signature at index {index}: {message}")]
    InvalidSignature { index: usize, message: String },

    /// Unknown signer key.
    #[error("unknown signer at index {index}: {tmb}")]
    UnknownSigner { index: usize, tmb: String },

    /// Protocol error from cyphr.
    #[error("protocol error: {0}")]
    Protocol(#[from] cyphr::Error),

    /// JSON parsing error.
    #[error("JSON error at index {index}: {source}")]
    Json {
        index: usize,
        #[source]
        source: serde_json::Error,
    },

    /// Invalid key material (e.g., base64 decode failure).
    #[error("invalid key material: {field}: {message}")]
    InvalidKeyMaterial { field: String, message: String },
}

// ============================================================================
// Import Functions
// ============================================================================

/// Load a principal by replaying bundle lines from genesis, as
/// [`export_commits`](crate::export_commits) writes them: commit lines and
/// action-only lines, in recorded order.
///
/// # Arguments
///
/// * `genesis` - How the principal was created (implicit or explicit)
/// * `commits` - Commit bundles to replay
///
/// # Errors
///
/// Returns `LoadError` if:
/// - Signature verification fails
/// - Unknown signer key
///
/// # Example
///
/// ```ignore
/// // Ignored: requires file_store context not available in doc-test
/// let genesis = Genesis::Implicit(my_key);
/// let commits = file_store.get_commits(&pr)?;
/// let principal = load_principal_from_commits(genesis, &commits)?;
/// ```
pub fn load_principal_from_commits(
    genesis: Genesis,
    commits: &[CommitEntry],
) -> Result<Principal, LoadError> {
    let key = genesis.key().ok_or(LoadError::NoGenesisKeys)?;
    let mut principal = Principal::implicit(key.clone())?;

    // Replay commits
    replay_commits(&mut principal, commits)?;

    Ok(principal)
}

pub(crate) fn canonicalize_value(val: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = val {
        map.sort_keys();
        for (_, v) in map.iter_mut() {
            canonicalize_value(v);
        }
    } else if let serde_json::Value::Array(arr) = val {
        for v in arr {
            canonicalize_value(v);
        }
    }
}

pub(crate) fn replay_commits<S: cyphr::eml::Storage>(
    principal: &mut Principal<S>,
    commits: &[CommitEntry],
) -> Result<(), LoadError> {
    for (commit_idx, commit) in commits.iter().enumerate() {
        replay_commit(principal, commit, commit_idx)?;
    }
    Ok(())
}

/// Replay one bundle line, the `commit_idx`-th of its history (which only
/// numbers the cozies an error names).
pub(crate) fn replay_commit<S: cyphr::eml::Storage>(
    principal: &mut Principal<S>,
    commit: &CommitEntry,
    commit_idx: usize,
) -> Result<(), LoadError> {
    let cozies = stored_cozies(commit, commit_idx)?;
    cyphr::replay::replay_bundle(principal, &cozies).map_err(|e| {
        let Some(i) = e.coz else {
            return LoadError::Protocol(e.source);
        };
        let index = commit_idx * 1000 + i;
        match e.source {
            cyphr::Error::InvalidSignature => LoadError::InvalidSignature {
                index,
                message: "signature verification failed".into(),
            },
            cyphr::Error::UnknownKey => LoadError::UnknownSigner {
                index,
                tmb: cozies
                    .get(i)
                    .map(|c| c.header().tmb.to_b64())
                    .unwrap_or_default(),
            },
            other => LoadError::Protocol(other),
        }
    })?;
    Ok(())
}

/// A stored commit's cozies as the core replays them: each key-introducing
/// coz takes the next entry of the commit's key list, in order.
fn stored_cozies(
    commit: &CommitEntry,
    commit_idx: usize,
) -> Result<Vec<cyphr::replay::StoredCoz>, LoadError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphr::replay::{StoredCoz, WireError};

    let mut keys = commit.keys.iter();
    commit
        .cozies
        .iter()
        .enumerate()
        .map(|(tx_idx, value)| {
            let index = commit_idx * 1000 + tx_idx;
            let pay = value
                .get("pay")
                .ok_or(LoadError::MissingTimestamp { index })?;
            let sig_b64 = value
                .get("sig")
                .and_then(|s| s.as_str())
                .ok_or(LoadError::MissingSig { index })?;
            let sig = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| {
                LoadError::InvalidSignature {
                    index,
                    message: "invalid base64 signature".into(),
                }
            })?;
            let introduces = pay
                .get("typ")
                .and_then(|t| t.as_str())
                .is_some_and(is_key_introducing_typ);
            let key = if introduces {
                keys.next().map(key_entry_to_key).transpose()?
            } else {
                None
            };
            StoredCoz::new(pay, sig, key).map_err(|e| match e {
                WireError::Header(p) | WireError::Key(p) | WireError::Protocol(p) => {
                    LoadError::Protocol(p)
                },
                // `StoredCoz::new` raises only the variants above; the rest
                // describe wire framing this path does not read.
                _ => LoadError::Protocol(cyphr::Error::MalformedPayload),
            })
        })
        .collect()
}

/// Returns true if a coz type introduces new key material.
///
/// Canonical implementation lives in `cyphr::parsed_coz::typ` -- this is a
/// thin re-export so existing call sites don't need to change.
pub(crate) use cyphr::parsed_coz::typ::is_key_introducing as is_key_introducing_typ;

/// Convert a commit-level KeyEntry to a Principal Key.
pub(crate) fn key_entry_to_key(entry: &KeyEntry) -> Result<Key, LoadError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_key = Base64UrlUnpadded::decode_vec(&entry.pub_key).map_err(|e| {
        LoadError::InvalidKeyMaterial {
            field: "pub".into(),
            message: e.to_string(),
        }
    })?;
    let tmb_bytes =
        Base64UrlUnpadded::decode_vec(&entry.tmb).map_err(|e| LoadError::InvalidKeyMaterial {
            field: "tmb".into(),
            message: e.to_string(),
        })?;

    // The one place stored/wire key material becomes a `Key`: the
    // constructor rejects a tmb that is not the thumbprint of the pub.
    Ok(Key::new(
        entry.alg.clone(),
        Thumbprint::from_bytes(tmb_bytes),
        pub_key,
    )?
    .with_first_seen(entry.now.unwrap_or(0))
    .with_tag(entry.tag.clone()))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key(id: u8) -> Key {
        Key::from_pub_key("ES256", vec![id; 64])
            .expect("dummy key")
            .with_first_seen(1000)
    }

    /// Claim: a commit whose coz pay omits `typ` is rejected as malformed
    /// during replay, never silently routed to the action path (a missing
    /// `typ` is not a transaction type, so only `CozHeader::parse` stops it).
    /// Turns red if replay stops parsing the header strictly. Not an
    /// end-to-end scenario: it needs a malformed commit no honest write path
    /// produces, so only a direct replay reaches it.
    #[test]
    fn replay_rejects_commit_missing_typ() {
        let key = make_test_key(0xAA);
        let malformed = serde_json::json!({
            "pay": { "alg": "ES256", "tmb": key.tmb().to_b64(), "now": 1000 },
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        });
        let commit = CommitEntry::new(
            vec![malformed],
            vec![],
            "SHA-256:c".into(),
            Some("SHA-256:a".into()),
            Some("SHA-256:s".into()),
            "SHA-256:p".into(),
        );

        let result = load_principal_from_commits(Genesis::Implicit(key), &[commit]);
        assert!(
            matches!(
                result,
                Err(LoadError::Protocol(cyphr::Error::MalformedPayload))
            ),
            "a coz missing 'typ' must be rejected as malformed, got {result:?}"
        );
    }
}
