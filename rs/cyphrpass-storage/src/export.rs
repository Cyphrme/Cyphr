//! Export/import utilities for Principal storage.
//!
//! These functions bridge the `cyphrpass` Principal type with the storage layer,
//! enabling faithful round-trip serialization of identity state.

use crate::{CommitEntry, Entry, Store};
use cyphrpass::Principal;
use serde_json::json;

/// Export all entries from a Principal for storage (legacy flat format).
///
/// Returns a vector of `Entry` that can be persisted to any `Store`.
/// The order is: transactions first (in apply order), then actions.
///
/// For `key/create` and `key/replace` transactions, the associated key material
/// is included in the exported entry as a `key` field, matching SPEC §3.1 JSONL format.
///
/// **Note**: For commit-based storage, use `export_commits` instead.
///
/// # Example
///
/// ```ignore
/// let entries = export_entries(&principal);
/// for entry in entries {
///     store.append_entry(principal.pr(), &entry)?;
/// }
/// ```
pub fn export_entries(principal: &Principal) -> Vec<Entry> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut entries = Vec::new();

    for tx in principal.transactions() {
        // Serialize complete CozJson {pay, sig}
        let mut raw = serde_json::to_value(tx.raw()).expect("CozJson serialization cannot fail");

        // For key/create and key/replace, include the key material from the transaction
        if let Some(key) = tx.new_key() {
            let key_json = json!({
                "alg": key.alg,
                "pub": Base64UrlUnpadded::encode_string(&key.pub_key),
                "tmb": key.tmb.to_b64()
            });
            raw.as_object_mut()
                .expect("CozJson is always an object")
                .insert("key".to_string(), key_json);
        }

        // Note: from_value serializes, which is fine for export (creating new entries)
        entries.push(Entry::from_value(&raw).expect("valid entry"));
    }

    for action in principal.actions() {
        let raw = serde_json::to_value(action.raw()).expect("CozJson serialization cannot fail");
        entries.push(Entry::from_value(&raw).expect("valid entry"));
    }

    entries
}

/// Export commits from a Principal for commit-based storage.
///
/// Returns a vector of `CommitEntry` representing each finalized commit.
/// Each entry contains:
/// - `txs`: Array of transaction JSON values (with embedded key material)
/// - `commit_id`: Commit ID (Merkle root of transaction czds, base64url)
/// - `as`: Auth State (base64url)
/// - `cs`: Commit State (MR(AS, Commit ID), base64url)
/// - `ps`: Principal State (base64url)
///
/// **Note**: Actions are not included in commits; they are stored separately
/// or handled by the caller.
///
/// # Example
///
/// ```ignore
/// // Ignored: requires initialized Principal with commits (external context)
/// let commits = export_commits(&principal);
/// for commit in commits {
///     file.write_line(&commit.to_json()?)?;
/// }
/// ```
pub fn export_commits(principal: &Principal) -> Vec<CommitEntry> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let mut commit_entries = Vec::new();

    for commit in principal.commits() {
        let mut txs = Vec::new();

        for tx in commit.transactions() {
            // Serialize complete CozJson {pay, sig}
            let mut raw =
                serde_json::to_value(tx.raw()).expect("CozJson serialization cannot fail");

            // For key/create and key/replace, include the key material
            if let Some(key) = tx.new_key() {
                let key_json = json!({
                    "alg": key.alg,
                    "pub": Base64UrlUnpadded::encode_string(&key.pub_key),
                    "tmb": key.tmb.to_b64()
                });
                raw.as_object_mut()
                    .expect("CozJson is always an object")
                    .insert("key".to_string(), key_json);
            }

            txs.push(raw);
        }

        // Get state digests as algorithm-prefixed strings (alg:digest format)
        // Use lexicographically first algorithm for deterministic ordering
        let cid_mh = commit.commit_id().as_multihash();
        let cid_alg = cid_mh
            .algorithms()
            .next()
            .expect("CommitID must have at least one variant");
        let commit_id = format!(
            "{}:{}",
            cid_alg,
            Base64UrlUnpadded::encode_string(cid_mh.get(cid_alg).unwrap())
        );

        let as_mh = commit.auth_state().as_multihash();
        let as_alg = as_mh
            .algorithms()
            .next()
            .expect("AuthState must have at least one variant");
        let auth_state = format!(
            "{}:{}",
            as_alg,
            Base64UrlUnpadded::encode_string(as_mh.get(as_alg).unwrap())
        );

        let cs_mh = commit.cs().as_multihash();
        let cs_alg = cs_mh
            .algorithms()
            .next()
            .expect("CommitState must have at least one variant");
        let cs = format!(
            "{}:{}",
            cs_alg,
            Base64UrlUnpadded::encode_string(cs_mh.get(cs_alg).unwrap())
        );

        let ps_mh = commit.ps().as_multihash();
        let ps_alg = ps_mh
            .algorithms()
            .next()
            .expect("PrincipalState must have at least one variant");
        let ps = format!(
            "{}:{}",
            ps_alg,
            Base64UrlUnpadded::encode_string(ps_mh.get(ps_alg).unwrap())
        );

        commit_entries.push(CommitEntry::new(txs, commit_id, auth_state, cs, ps));
    }

    commit_entries
}

/// Export entries and persist them to storage.
///
/// This is a convenience function that combines export and storage.
pub fn persist_entries<S: Store>(store: &S, principal: &Principal) -> Result<usize, S::Error> {
    let entries = export_entries(principal);
    let count = entries.len();
    for entry in entries {
        store.append_entry(principal.pr(), &entry)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use coz::Thumbprint;
    use cyphrpass::Key;

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
        // Implicit genesis has no transactions (identity emerges from key possession)
        let principal = Principal::implicit(make_test_key(0xAA)).unwrap();
        let entries = export_entries(&principal);

        // No transactions for implicit genesis
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
        // We can't easily create a real transaction without signature verification,
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
