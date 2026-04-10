//! Export/import utilities for Principal storage.
//!
//! These functions bridge the `cyphrpass` Principal type with the storage layer,
//! enabling faithful round-trip serialization of identity state.

use crate::{CommitEntry, Entry, KeyEntry, Store};
use cyphrpass::Principal;

/// Errors that can occur during export.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// JSON serialization failed.
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    /// Entry construction failed.
    #[error("entry error: {0}")]
    Entry(#[from] crate::EntryError),

    /// State digest is empty (no algorithm variants).
    #[error("empty state digest: {0}")]
    EmptyDigest(#[from] cyphrpass::Error),
}

/// Export all entries from a Principal for storage (legacy flat format).
///
/// Returns a vector of `Entry` that can be persisted to any `Store`.
/// The order is: cozies first (in apply order), then actions.
///
/// For `key/create` and `key/replace` cozies, the associated key material
/// is included in the exported entry as a `key` field, matching SPEC §3.1 JSONL format.
///
/// **Note**: For commit-based storage, use `export_commits` instead.
///
/// # Errors
///
/// Returns `ExportError` if serialization or state digest access fails.
///
/// # Example
///
/// ```ignore
/// let entries = export_entries(&principal)?;
/// for entry in entries {
///     store.append_entry(principal.pg(), &entry)?;
/// }
/// ```
pub fn export_entries(principal: &Principal) -> Result<Vec<Entry>, ExportError> {
    let mut entries = Vec::new();

    for cz in principal.iter_all_cozies() {
        // Serialize complete CozJson {pay, sig} — no key embedding
        let raw = serde_json::to_value(cz.raw())?;

        // Note: from_value serializes, which is fine for export (creating new entries)
        entries.push(Entry::from_value(&raw)?);
    }

    for action in principal.actions() {
        let raw = serde_json::to_value(action.raw())?;
        entries.push(Entry::from_value(&raw)?);
    }

    Ok(entries)
}

/// Export commits from a Principal for commit-based storage.
///
/// Returns a vector of `CommitEntry` representing each finalized commit.
/// Each entry contains:
/// - `cozies`: Array of coz JSON values (with embedded key material)
/// - `commit_id`: Commit ID (Merkle root of coz czds, base64url)
/// - `as`: Auth State (base64url)
/// - `sr`: State Root (base64url)
/// - `ps`: Principal State (base64url)
///
/// **Note**: Actions are not included in commits; they are stored separately
/// or handled by the caller.
///
/// # Errors
///
/// Returns `ExportError` if serialization or state digest access fails.
///
/// # Example
///
/// ```ignore
/// // Ignored: requires initialized Principal with commits (external context)
/// let commits = export_commits(&principal)?;
/// for commit in commits {
///     file.write_line(&commit.to_json()?)?;
/// }
/// ```
pub fn export_commits(principal: &Principal) -> Result<Vec<CommitEntry>, ExportError> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut commit_entries = Vec::new();

    for commit in principal.commits() {
        let mut cozies = Vec::new();
        let mut keys = Vec::new();

        for cz in commit.iter_all_cozies() {
            // Serialize complete CozJson {pay, sig} — no key embedding
            let raw = serde_json::to_value(cz.raw())?;
            cozies.push(raw);

            // Collect key material at commit level
            if let Some(key) = cz.new_key() {
                keys.push(KeyEntry {
                    alg: key.alg.clone(),
                    pub_key: Base64UrlUnpadded::encode_string(&key.pub_key),
                    tmb: key.tmb.to_b64(),
                    tag: key.tag.clone(),
                    now: Some(key.first_seen),
                });
            }
        }

        // Get state digests as algorithm-prefixed strings (alg:digest format)
        // Use first_variant() for deterministic, fallible access
        let tr_bytes = commit.tr().0.first_variant()?;
        let tr_alg = commit
            .tr()
            .0
            .algorithms()
            .next()
            .ok_or(cyphrpass::Error::EmptyMultihash)?;
        let commit_id = format!("{}:{}", tr_alg, Base64UrlUnpadded::encode_string(tr_bytes));

        let as_bytes = commit.auth_root().as_multihash().first_variant()?;
        let as_alg = commit
            .auth_root()
            .as_multihash()
            .algorithms()
            .next()
            .ok_or(cyphrpass::Error::EmptyMultihash)?;
        let auth_root = format!("{}:{}", as_alg, Base64UrlUnpadded::encode_string(as_bytes));

        let sr_bytes = commit.sr().as_multihash().first_variant()?;
        let sr_alg = commit
            .sr()
            .as_multihash()
            .algorithms()
            .next()
            .ok_or(cyphrpass::Error::EmptyMultihash)?;
        let sr = format!("{}:{}", sr_alg, Base64UrlUnpadded::encode_string(sr_bytes));

        let ps_bytes = commit.pr().as_multihash().first_variant()?;
        let ps_alg = commit
            .pr()
            .as_multihash()
            .algorithms()
            .next()
            .ok_or(cyphrpass::Error::EmptyMultihash)?;
        let ps = format!("{}:{}", ps_alg, Base64UrlUnpadded::encode_string(ps_bytes));

        commit_entries.push(CommitEntry::new(cozies, keys, commit_id, auth_root, sr, ps));
    }

    Ok(commit_entries)
}

/// Export entries and persist them to storage.
///
/// This is a convenience function that combines export and storage.
///
/// # Errors
///
/// Returns `NoPrincipalGenesis` if the principal has no PR (Level 1/2).
pub fn persist_entries<S: Store>(
    store: &S,
    principal: &Principal,
) -> Result<usize, PersistError<S::Error>> {
    let entries = export_entries(principal).map_err(PersistError::Export)?;
    let pg = principal.pg().ok_or(PersistError::NoPrincipalGenesis)?;
    let count = entries.len();
    for entry in entries {
        store
            .append_entry(pg, &entry)
            .map_err(PersistError::Store)?;
    }
    Ok(count)
}

/// Errors from persist_entries (combines export and store errors).
#[derive(Debug, thiserror::Error)]
pub enum PersistError<E: std::error::Error> {
    /// Export failed.
    #[error("export: {0}")]
    Export(#[from] ExportError),
    /// Store operation failed.
    #[error("store: {0}")]
    Store(E),
    /// Principal has no PrincipalGenesis (Level 1/2 cannot be persisted).
    #[error("persist_entries requires a Level 3+ principal with PrincipalGenesis")]
    NoPrincipalGenesis,
}

#[cfg(test)]
mod tests {
    use super::*;
    use coz::Thumbprint;
    use cyphrpass::Key;
    use serde_json::json;

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
    fn export_implicit_genesis_no_entries() {
        // Implicit genesis has no cozies (identity emerges from key possession)
        let principal = Principal::implicit(make_test_key(0xAA)).unwrap();
        let entries = export_entries(&principal).unwrap();

        // No cozies for implicit genesis
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn entry_from_value_extracts_now() {
        use crate::Entry;

        let raw = json!({
            "pay": {"now": 12345, "typ": "test"},
            "sig": "AAAA"
        });

        let entry = Entry::from_value(&raw).unwrap();
        assert_eq!(entry.now, 12345);
    }

    #[test]
    fn exported_entry_has_pay_and_sig() {
        // We can't easily create a real coz without signature verification,
        // but we can verify the CozJson serialization format
        let coz_json = coz::CozJson {
            pay: json!({"typ": "test", "now": 1000}),
            sig: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let serialized = serde_json::to_value(&coz_json).unwrap();

        // Verify structure has both pay and sig
        assert!(serialized.get("pay").is_some(), "missing pay field");
        assert!(serialized.get("sig").is_some(), "missing sig field");

        // Verify sig is base64url encoded
        let sig_str = serialized["sig"].as_str().unwrap();
        assert!(!sig_str.is_empty(), "sig should not be empty");
    }
}
