//! Import utilities for loading Principals from stored commit bundles.
//!
//! This module reconstructs a `Principal` by replaying commit bundles
//! (one commit per line, per SPEC §4.2.1, §7.3.1) from genesis.

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

    /// Explicit genesis: multiple keys established at creation.
    ///
    /// Per SPEC §5.1: "Multi-key accounts require explicit genesis"
    /// - PR is established by principal/create
    Explicit(Vec<Key>),
}

/// Errors that can occur during import.
#[derive(Debug, thiserror::Error)]
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

    /// Unsupported cryptographic algorithm.
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    /// Invalid key material (e.g., base64 decode failure).
    #[error("invalid key material: {field}: {message}")]
    InvalidKeyMaterial { field: String, message: String },
}

/// Determine if a typ string represents a transaction (not an action).
///
/// Every kind in the core kind table is a transaction; anything else is an
/// action. Matching goes through the core's `/`-boundary
/// `typ::has_suffix`, so storage cannot classify a typ the core would
/// refuse to parse as a kind (`xcyphr/key/create`) and cannot miss a kind
/// the core added.
pub(crate) fn is_transaction_typ(typ: &str) -> bool {
    use cyphr::parsed_coz::typ as k;
    [
        k::KEY_CREATE,
        k::KEY_DELETE,
        k::KEY_REPLACE,
        k::KEY_REVOKE,
        k::PRINCIPAL_CREATE,
        k::PRINCIPAL_DELETE,
        k::COMMIT_CREATE,
        k::MERGE,
        k::MERGE_ACK,
        k::FREEZE_CREATE,
        k::FREEZE_DELETE,
    ]
    .iter()
    .any(|suffix| k::has_suffix(typ, suffix))
        || k::nonce_path(typ).is_some()
}

// ============================================================================
// Import Functions
// ============================================================================

/// Load a principal by replaying commit bundles from genesis.
///
/// Storage holds one commit per line (per SPEC §4.2.1, §7.3.1).
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
    let mut principal = match genesis {
        Genesis::Implicit(key) => Principal::implicit(key)?,
        Genesis::Explicit(keys) => {
            if keys.is_empty() {
                return Err(LoadError::NoGenesisKeys);
            }
            Principal::explicit(keys)?
        },
    };

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
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    for (commit_idx, commit) in commits.iter().enumerate() {
        if commit.cozies.is_empty() {
            return Err(LoadError::Protocol(cyphr::Error::EmptyCommit));
        }

        // 1. Find the first transaction cozy index
        let mut first_tx_idx = None;
        for (tx_idx, tx_value) in commit.cozies.iter().enumerate() {
            let pay = tx_value.get("pay").ok_or(LoadError::MissingTimestamp {
                index: commit_idx * 1000 + tx_idx,
            })?;
            let header = cyphr::parsed_coz::CozHeader::parse(pay)?;
            if is_transaction_typ(&header.typ) {
                first_tx_idx = Some(tx_idx);
                break;
            }
        }

        let mut key_iter = commit.keys.iter();

        if let Some(idx) = first_tx_idx {
            // 2. Process pre-actions (before the first transaction)
            for (tx_idx, tx_value) in commit.cozies.iter().enumerate().take(idx) {
                let index = commit_idx * 1000 + tx_idx;

                let pay = tx_value
                    .get("pay")
                    .ok_or(LoadError::MissingTimestamp { index })?;

                let sig_b64 = tx_value
                    .get("sig")
                    .and_then(|s| s.as_str())
                    .ok_or(LoadError::MissingSig { index })?;

                let sig = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| {
                    LoadError::InvalidSignature {
                        index,
                        message: "invalid base64 signature".into(),
                    }
                })?;

                let mut pay_val = pay.clone();
                canonicalize_value(&mut pay_val);
                let pay_json = serde_json::to_vec(&pay_val)
                    .map_err(|e| LoadError::Json { index, source: e })?;

                let czd = compute_czd(&pay_json, &sig)?;

                principal
                    .verify_and_record_action(&pay_json, &sig, czd)
                    .map_err(|e| match e {
                        cyphr::Error::InvalidSignature => LoadError::InvalidSignature {
                            index,
                            message: "signature verification failed".into(),
                        },
                        other => LoadError::Protocol(other),
                    })?;
            }

            // 3. Open commit scope and process transactions and deferred actions
            let mut deferred_actions = Vec::new();
            let mut scope = principal.begin_commit();
            let mut applied_tx_count = 0;

            for (tx_idx, tx_value) in commit.cozies.iter().enumerate().skip(idx) {
                let index = commit_idx * 1000 + tx_idx;

                let pay = tx_value
                    .get("pay")
                    .ok_or(LoadError::MissingTimestamp { index })?;

                let sig_b64 = tx_value
                    .get("sig")
                    .and_then(|s| s.as_str())
                    .ok_or(LoadError::MissingSig { index })?;

                let sig = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| {
                    LoadError::InvalidSignature {
                        index,
                        message: "invalid base64 signature".into(),
                    }
                })?;

                let mut pay_val = pay.clone();
                canonicalize_value(&mut pay_val);
                let pay_json = serde_json::to_vec(&pay_val)
                    .map_err(|e| LoadError::Json { index, source: e })?;

                let header = cyphr::parsed_coz::CozHeader::parse(pay)?;

                if is_transaction_typ(&header.typ) {
                    let new_key = if is_key_introducing_typ(&header.typ) {
                        key_iter.next().map(key_entry_to_key).transpose()?
                    } else {
                        None
                    };

                    let alg = pay
                        .get("alg")
                        .and_then(|a| a.as_str())
                        .ok_or(LoadError::UnsupportedAlgorithm)?;
                    let czd = cyphr::compute_czd(&pay_json, &sig, alg)
                        .ok_or(LoadError::UnsupportedAlgorithm)?;

                    scope
                        .verify_and_apply(&pay_json, &sig, czd, new_key)
                        .map_err(|e| match e {
                            cyphr::Error::InvalidSignature => LoadError::InvalidSignature {
                                index,
                                message: "signature verification failed".into(),
                            },
                            cyphr::Error::UnknownKey => LoadError::UnknownSigner {
                                index,
                                tmb: header.tmb.to_b64(),
                            },
                            other => LoadError::Protocol(other),
                        })?;
                    applied_tx_count += 1;
                } else {
                    let tmb = header.tmb.to_b64();
                    deferred_actions.push((index, pay_json, sig, tmb));
                }
            }

            if applied_tx_count > 0 {
                scope.finalize().map_err(LoadError::Protocol)?;
            } else {
                drop(scope);
            }

            // 4. Replay deferred actions on the principal
            for (index, pay_json, sig, tmb) in deferred_actions {
                let czd = compute_czd(&pay_json, &sig)?;

                principal
                    .verify_and_record_action(&pay_json, &sig, czd)
                    .map_err(|e| match e {
                        cyphr::Error::InvalidSignature => LoadError::InvalidSignature {
                            index,
                            message: "signature verification failed".into(),
                        },
                        cyphr::Error::UnknownKey => LoadError::UnknownSigner { index, tmb },
                        other => LoadError::Protocol(other),
                    })?;
            }
        } else {
            // Action-only bundle
            for (tx_idx, tx_value) in commit.cozies.iter().enumerate() {
                let index = commit_idx * 1000 + tx_idx;

                let pay = tx_value
                    .get("pay")
                    .ok_or(LoadError::MissingTimestamp { index })?;

                let sig_b64 = tx_value
                    .get("sig")
                    .and_then(|s| s.as_str())
                    .ok_or(LoadError::MissingSig { index })?;

                let sig = Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| {
                    LoadError::InvalidSignature {
                        index,
                        message: "invalid base64 signature".into(),
                    }
                })?;

                let mut pay_val = pay.clone();
                canonicalize_value(&mut pay_val);
                let pay_json = serde_json::to_vec(&pay_val)
                    .map_err(|e| LoadError::Json { index, source: e })?;

                let czd = compute_czd(&pay_json, &sig)?;

                principal
                    .verify_and_record_action(&pay_json, &sig, czd)
                    .map_err(|e| match e {
                        cyphr::Error::InvalidSignature => LoadError::InvalidSignature {
                            index,
                            message: "signature verification failed".into(),
                        },
                        cyphr::Error::UnknownKey => LoadError::UnknownSigner {
                            index,
                            tmb: pay
                                .get("tmb")
                                .and_then(|t| t.as_str())
                                .unwrap_or("?")
                                .into(),
                        },
                        other => LoadError::Protocol(other),
                    })?;
            }
        }
    }

    Ok(())
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

/// Compute Coz digest for an entry.
///
/// Delegates to `cyphr::compute_czd` to ensure consistent hash computation
/// matching the signing path.
pub(crate) fn compute_czd(pay_json: &[u8], sig: &[u8]) -> Result<coz::Czd, LoadError> {
    let pay: serde_json::Value = serde_json::from_slice(pay_json).map_err(|e| LoadError::Json {
        index: 0,
        source: e,
    })?;
    let alg = pay
        .get("alg")
        .and_then(|a| a.as_str())
        .ok_or(LoadError::UnsupportedAlgorithm)?;

    cyphr::compute_czd(pay_json, sig, alg).ok_or(LoadError::UnsupportedAlgorithm)
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

    #[test]
    fn load_explicit_genesis_no_commits() {
        let key1 = make_test_key(0xAA);
        let key2 = make_test_key(0xBB);

        let principal =
            load_principal_from_commits(Genesis::Explicit(vec![key1.clone(), key2.clone()]), &[])
                .unwrap();

        // Explicit genesis: PG is None (needs principal/create)
        assert!(
            principal.pg().is_none(),
            "PG should be None before principal/create"
        );
        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(key1.tmb()));
        assert!(principal.is_key_active(key2.tmb()));
    }

    #[test]
    fn load_explicit_genesis_empty_keys_fails() {
        let result = load_principal_from_commits(Genesis::Explicit(vec![]), &[]);
        assert!(matches!(result, Err(LoadError::NoGenesisKeys)));
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

    #[test]
    fn is_key_introducing_typ_delegates_to_canonical_predicate() {
        assert!(is_key_introducing_typ("cyphr.me/cyphr/key/create"));
        assert!(is_key_introducing_typ("cyphr.me/cyphr/key/replace"));
        assert!(!is_key_introducing_typ("cyphr.me/cyphr/key/delete"));
        assert!(!is_key_introducing_typ("cyphr.me/cyphr/commit/create"));
    }

    /// F25: `is_transaction_typ` must recognize the three lifecycle
    /// transaction typs N03 added to the core protocol crate, or a signed
    /// lifecycle commit is silently misfiled as a deferred data action
    /// instead of being applied through `verify_and_apply`.
    #[test]
    fn is_transaction_typ_recognizes_lifecycle_typs() {
        assert!(is_transaction_typ("cyphr.me/cyphr/principal/delete"));
        assert!(is_transaction_typ("cyphr.me/cyphr/freeze/create"));
        assert!(is_transaction_typ("cyphr.me/cyphr/freeze/delete"));
    }
}
