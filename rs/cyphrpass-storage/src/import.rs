//! Import utilities for loading Principals from stored entries.
//!
//! This module provides functions to reconstruct a `Principal` from stored
//! entries, supporting both full replay from genesis and partial replay
//! from a trusted checkpoint.
//!
//! Supports both legacy flat format (one tx per line) and commit-based format
//! (one commit bundle per line).

use crate::{CommitEntry, Entry};
use coz::Thumbprint;
use cyphrpass::state::{AuthState, PrincipalRoot};
use cyphrpass::{Key, Principal};

// ============================================================================
// Types
// ============================================================================

/// How the principal was created (genesis mode).
///
/// Per SPEC §5, principals can be created implicitly (single key, no transaction)
/// or explicitly (multiple keys with genesis transactions).
#[derive(Debug, Clone)]
pub enum Genesis {
    /// Implicit genesis: single key, no transaction required.
    ///
    /// Per SPEC §5.1: "Identity emerges from first key possession"
    /// - `PS = AS = KS = tmb` (PR is None at L1/L2)
    Implicit(Key),

    /// Explicit genesis: multiple keys established at creation.
    ///
    /// Per SPEC §5.1: "Multi-key accounts require explicit genesis"
    /// - PR is established by principal/create
    Explicit(Vec<Key>),
}

/// Trusted checkpoint for partial replay.
///
/// Enables thin clients to verify only recent transactions without
/// replaying full history from genesis.
///
/// # Security
///
/// The caller must establish trust in this checkpoint before using it.
/// Per SPEC §6.3.3, checkpoint trust is established via signature by
/// a key the client trusts (self, service, or cross-attestation).
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The trusted Auth State at checkpoint.
    pub auth_state: AuthState,
    /// Active keys at checkpoint (needed to verify subsequent transactions).
    pub keys: Vec<Key>,
    /// Future: thumbprint of key that attested this checkpoint.
    ///
    /// Not currently verified; included for forward compatibility.
    pub attestor: Option<Thumbprint>,
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

    /// Transaction pre field doesn't match expected AS.
    #[error("broken chain at index {index}: pre mismatch")]
    BrokenChain { index: usize },

    /// Unknown signer key.
    #[error("unknown signer at index {index}: {tmb}")]
    UnknownSigner { index: usize, tmb: String },

    /// Protocol error from cyphrpass.
    #[error("protocol error: {0}")]
    Protocol(#[from] cyphrpass::Error),

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
}

/// Determine if a typ string represents a transaction (not an action).
///
/// Transactions are: key/*, principal/create
/// Everything else is an action.
fn is_transaction_typ(typ: &str) -> bool {
    typ.contains("/key/") || typ.contains("/principal/create")
}

// ============================================================================
// Import Functions
// ============================================================================

/// Load a principal by replaying entries from genesis.
///
/// This performs full verification of the entire transaction history.
///
/// # Arguments
///
/// * `genesis` - How the principal was created (implicit or explicit)
/// * `entries` - All transactions and actions to replay
///
/// # Errors
///
/// Returns `LoadError` if:
/// - Signature verification fails
/// - Transaction chain is broken (pre mismatch)
/// - Unknown signer key
///
/// # Example
///
/// ```ignore
/// // Ignored: requires store context and key material not available in doc-test
/// let genesis = Genesis::Implicit(my_key);
/// let entries = store.get_entries(&pr)?;
/// let principal = load_principal(genesis, &entries)?;
/// ```
pub fn load_principal(genesis: Genesis, entries: &[Entry]) -> Result<Principal, LoadError> {
    // Create principal from genesis
    let mut principal = match genesis {
        Genesis::Implicit(key) => Principal::implicit(key)?,
        Genesis::Explicit(keys) => {
            if keys.is_empty() {
                return Err(LoadError::NoGenesisKeys);
            }
            Principal::explicit(keys)?
        },
    };

    // Replay entries
    replay_entries(&mut principal, entries)?;

    Ok(principal)
}

/// Load a principal from a trusted checkpoint.
///
/// This allows verification of only the transaction suffix, enabling
/// efficient sync for thin clients or after long periods offline.
///
/// # Security
///
/// The `expected_pr` parameter is required to prevent identity confusion
/// attacks. The caller must know which principal they are loading.
///
/// # Arguments
///
/// * `expected_pr` - The expected Principal Root (for security validation)
/// * `checkpoint` - Trusted state to start from
/// * `entries` - Entries after the checkpoint to replay
///
/// # Example
///
/// ```ignore
/// let checkpoint = Checkpoint {
///     auth_state: trusted_as,
///     keys: current_keys,
///     attestor: Some(service_tmb),
/// };
/// let entries = store.get_entries_range(&pr, &QueryOpts { after: Some(cp_time), .. })?;
/// let principal = load_from_checkpoint(pr, checkpoint, &entries)?;
/// ```
pub fn load_from_checkpoint(
    expected_pr: Option<PrincipalRoot>,
    checkpoint: Checkpoint,
    entries: &[Entry],
) -> Result<Principal, LoadError> {
    if checkpoint.keys.is_empty() {
        return Err(LoadError::NoGenesisKeys);
    }

    // Construct principal at checkpoint state
    // We use the first key to determine hash algorithm, then add remaining keys
    let mut principal =
        Principal::from_checkpoint(expected_pr, checkpoint.auth_state, checkpoint.keys)?;

    // Replay entries from checkpoint
    replay_entries(&mut principal, entries)?;

    Ok(principal)
}

/// Load a principal by replaying commit bundles from genesis.
///
/// This is the commit-based equivalent of `load_principal`, used when
/// storage contains one commit per line (per SPEC §4.2.1, §7.3.1).
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
/// - Transaction chain is broken (pre mismatch)
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
    // Create principal from genesis
    let mut principal = load_principal(genesis, &[])?; // Load from genesis, no flat entries

    // Replay commits
    replay_commits(&mut principal, commits)?;

    Ok(principal)
}

/// Replay entries onto a principal (shared logic).
fn replay_entries(principal: &mut Principal, entries: &[Entry]) -> Result<(), LoadError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    for (index, entry) in entries.iter().enumerate() {
        // Parse entry for field access (NOT for czd computation)
        let raw = entry
            .as_value()
            .map_err(|_| LoadError::MissingTimestamp { index })?;

        let pay = raw
            .get("pay")
            .ok_or(LoadError::MissingTimestamp { index })?;

        let sig_b64 = raw
            .get("sig")
            .and_then(|s| s.as_str())
            .ok_or(LoadError::MissingSig { index })?;

        let sig =
            Base64UrlUnpadded::decode_vec(sig_b64).map_err(|_| LoadError::InvalidSignature {
                index,
                message: "invalid base64 signature".into(),
            })?;

        // CRITICAL: Use pay_bytes() for bit-perfect JSON, NOT re-serialization
        let pay_json = entry
            .pay_bytes()
            .map_err(|_| LoadError::MissingTimestamp { index })?;

        // Determine if this is a transaction or action by typ prefix
        let typ = pay.get("typ").and_then(|t| t.as_str()).unwrap_or("");

        if is_transaction_typ(typ) {
            // Transaction: extract key material if present
            let new_key = extract_key_from_entry(&raw);

            // Compute czd for this entry
            let czd = compute_czd(&pay_json, &sig, principal)?;

            // Apply transaction
            principal
                .verify_and_apply_transaction(&pay_json, &sig, czd, new_key)
                .map_err(|e| match e {
                    cyphrpass::Error::InvalidSignature => LoadError::InvalidSignature {
                        index,
                        message: "signature verification failed".into(),
                    },
                    cyphrpass::Error::InvalidPrior => LoadError::BrokenChain { index },
                    cyphrpass::Error::UnknownKey => LoadError::UnknownSigner {
                        index,
                        tmb: pay
                            .get("tmb")
                            .and_then(|t| t.as_str())
                            .unwrap_or("?")
                            .into(),
                    },
                    other => LoadError::Protocol(other),
                })?;
        } else {
            // Action: compute czd and record
            let czd = compute_czd(&pay_json, &sig, principal)?;

            principal
                .verify_and_record_action(&pay_json, &sig, czd)
                .map_err(|e| match e {
                    cyphrpass::Error::InvalidSignature => LoadError::InvalidSignature {
                        index,
                        message: "signature verification failed".into(),
                    },
                    cyphrpass::Error::UnknownKey => LoadError::UnknownSigner {
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

    Ok(())
}

/// Replay commit bundles onto a principal (commit-based format).
///
/// Each commit bundle contains multiple transactions that form an atomic unit.
/// Uses `CommitScope` to properly group transactions into commits.
fn replay_commits(principal: &mut Principal, commits: &[CommitEntry]) -> Result<(), LoadError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    for (commit_idx, commit) in commits.iter().enumerate() {
        // Collect actions to replay after the commit scope is finalized.
        // Actions don't participate in the commit lifecycle but may appear
        // in the same bundle.
        let mut deferred_actions: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();

        // Create a commit scope for this bundle's transactions
        let mut scope = principal.begin_commit();
        let mut applied_tx_count = 0;

        for (tx_idx, tx_value) in commit.txs.iter().enumerate() {
            let index = commit_idx * 1000 + tx_idx; // Composite index for error messages

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

            // Serialize pay for verification (bit-perfect for stored data)
            let pay_json =
                serde_json::to_vec(pay).map_err(|e| LoadError::Json { index, source: e })?;

            // Determine if this is a transaction or action by typ prefix
            let typ = pay.get("typ").and_then(|t| t.as_str()).unwrap_or("");

            if is_transaction_typ(typ) {
                // Transaction: extract key material if present
                let new_key = extract_key_from_entry(tx_value);

                // Compute czd via the scope's hash algorithm
                let alg = match scope.principal_hash_alg() {
                    cyphrpass::state::HashAlg::Sha256 => "ES256",
                    cyphrpass::state::HashAlg::Sha384 => "ES384",
                    cyphrpass::state::HashAlg::Sha512 => "ES512",
                };
                let cad = coz::canonical_hash_for_alg(&pay_json, alg, None)
                    .ok_or(LoadError::UnsupportedAlgorithm)?;
                let czd =
                    coz::czd_for_alg(&cad, &sig, alg).ok_or(LoadError::UnsupportedAlgorithm)?;

                // Verify and apply within the scope
                scope
                    .verify_and_apply(&pay_json, &sig, czd, new_key)
                    .map_err(|e| match e {
                        cyphrpass::Error::InvalidSignature => LoadError::InvalidSignature {
                            index,
                            message: "signature verification failed".into(),
                        },
                        cyphrpass::Error::InvalidPrior => LoadError::BrokenChain { index },
                        cyphrpass::Error::UnknownKey => LoadError::UnknownSigner {
                            index,
                            tmb: pay
                                .get("tmb")
                                .and_then(|t| t.as_str())
                                .unwrap_or("?")
                                .into(),
                        },
                        other => LoadError::Protocol(other),
                    })?;
                applied_tx_count += 1;
            } else {
                // Action: defer until after scope is finalized
                deferred_actions.push((index, pay_json, sig));
            }
        }

        if applied_tx_count > 0 {
            // Finalize the commit scope
            scope.finalize().map_err(LoadError::Protocol)?;
        } else {
            // Drop scope without finalize — no transactions were applied
            drop(scope);
        }

        // Replay deferred actions on the principal (outside the scope)
        for (index, pay_json, sig) in deferred_actions {
            let czd = compute_czd(&pay_json, &sig, principal)?;

            principal
                .verify_and_record_action(&pay_json, &sig, czd)
                .map_err(|e| match e {
                    cyphrpass::Error::InvalidSignature => LoadError::InvalidSignature {
                        index,
                        message: "signature verification failed".into(),
                    },
                    cyphrpass::Error::UnknownKey => LoadError::UnknownSigner {
                        index,
                        tmb: "?".into(),
                    },
                    other => LoadError::Protocol(other),
                })?;
        }
    }

    Ok(())
}

/// Extract key material from entry (for key/create, key/replace).
fn extract_key_from_entry(raw: &serde_json::Value) -> Option<Key> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let key_obj = raw.get("key")?;
    let alg = key_obj.get("alg")?.as_str()?;
    let pub_b64 = key_obj.get("pub")?.as_str()?;
    let tmb_b64 = key_obj.get("tmb")?.as_str()?;

    let pub_key = Base64UrlUnpadded::decode_vec(pub_b64).ok()?;
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64).ok()?;

    Some(Key {
        alg: alg.to_string(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key,
        first_seen: 0, // Will be set by apply_transaction
        last_used: None,
        revocation: None,
        tag: None,
    })
}

/// Compute Coz digest for an entry.
///
/// Uses coz library's canonical_hash_for_alg and czd_for_alg to ensure
/// consistent hash computation matching the signing path.
fn compute_czd(pay_json: &[u8], sig: &[u8], principal: &Principal) -> Result<coz::Czd, LoadError> {
    use cyphrpass::state::HashAlg;

    // Map principal's hash algorithm to coz algorithm name
    let alg = match principal.hash_alg() {
        HashAlg::Sha256 => "ES256",
        HashAlg::Sha384 => "ES384",
        HashAlg::Sha512 => "ES512",
    };

    // Compute cad using canonical hash (compacts JSON first)
    let cad =
        coz::canonical_hash_for_alg(pay_json, alg, None).ok_or(LoadError::UnsupportedAlgorithm)?;

    // Compute czd using canonical {"cad":"...","sig":"..."} format
    let czd = coz::czd_for_alg(&cad, sig, alg).ok_or(LoadError::UnsupportedAlgorithm)?;

    Ok(czd)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_key(id: u8) -> Key {
        Key {
            alg: "ES256".to_string(),
            tmb: Thumbprint::from_bytes(vec![id; 32]),
            pub_key: vec![id; 64],
            first_seen: 1000,
            last_used: None,
            revocation: None,
            tag: None,
        }
    }

    #[test]
    fn load_implicit_genesis_no_entries() {
        let key = make_test_key(0xAA);
        let _expected_tmb = key.tmb.clone();

        let principal = load_principal(Genesis::Implicit(key), &[]).unwrap();

        // Implicit genesis: PR is None at L1
        assert!(principal.pr().is_none(), "PR should be None at L1");
        assert_eq!(principal.active_key_count(), 1);
    }

    #[test]
    fn load_explicit_genesis_no_entries() {
        let key1 = make_test_key(0xAA);
        let key2 = make_test_key(0xBB);

        let principal =
            load_principal(Genesis::Explicit(vec![key1.clone(), key2.clone()]), &[]).unwrap();

        // Explicit genesis: PR is None (needs principal/create)
        assert!(
            principal.pr().is_none(),
            "PR should be None before principal/create"
        );
        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key1.tmb));
        assert!(principal.is_key_active(&key2.tmb));
    }

    #[test]
    fn load_explicit_genesis_empty_keys_fails() {
        let result = load_principal(Genesis::Explicit(vec![]), &[]);
        assert!(matches!(result, Err(LoadError::NoGenesisKeys)));
    }

    #[test]
    fn checkpoint_empty_keys_fails() {
        use cyphrpass::multihash::MultihashDigest;
        use cyphrpass::state::HashAlg;

        let pr = PrincipalRoot::from_bytes(vec![0xAA; 32]);
        let checkpoint = Checkpoint {
            auth_state: AuthState(MultihashDigest::from_single(
                HashAlg::Sha256,
                vec![0xBB; 32],
            )),
            keys: vec![],
            attestor: None,
        };

        let result = load_from_checkpoint(Some(pr), checkpoint, &[]);
        assert!(matches!(result, Err(LoadError::NoGenesisKeys)));
    }
}
