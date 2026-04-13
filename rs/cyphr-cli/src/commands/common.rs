//! Shared helper functions for CLI commands.
//!
//! These were previously duplicated across multiple command modules.
//! Consolidated per C.2 audit finding.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphr::Key;
use cyphr_storage::{CommitEntry, FileStore, Genesis};

use crate::Error;
use crate::keystore::{JsonKeyStore, KeyStore, StoredKey};

/// Get Unix timestamp as i64 seconds.
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Load a cyphr Key from keystore by thumbprint.
pub fn load_key_from_keystore(keystore: &JsonKeyStore, tmb: &str) -> crate::Result<Key> {
    let stored = keystore.get(tmb)?;
    let now = current_timestamp();

    Ok(Key {
        alg: stored.alg.clone(),
        tmb: Thumbprint::from_bytes(decode_b64(tmb)?),
        pub_key: stored.pub_key.clone(),
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: stored.tag.clone(),
    })
}

/// Extract genesis from stored commits.
///
/// Strategy depends on whether a keystore is available:
///
/// **With keystore**: Look up the signer of the first coz by
/// thumbprint (`pay.tmb`). This is the correct approach for import,
/// where the genesis key (signer) may not be embedded in the commit
/// but the *new* key being added might be.
///
/// **Without keystore**: Scan the first commit's cozies for
/// embedded `key` objects. This works for inspect/verify/list where
/// all key material is in the commits themselves.
pub fn extract_genesis_from_commits(
    commits: &[CommitEntry],
    keystore: Option<&JsonKeyStore>,
) -> crate::Result<Genesis> {
    let first_commit = commits.first().ok_or(Error::MissingField("commits"))?;

    // When keystore is available, prefer signer-based lookup.
    // The signer of the first coz IS the genesis key.
    if let Some(ks) = keystore {
        if let Some(first_tx) = first_commit.cozies.first() {
            if let Some(signer_tmb) = first_tx
                .get("pay")
                .and_then(|p| p.get("tmb"))
                .and_then(|v| v.as_str())
            {
                // Try embedded key first (self-signed genesis)
                if let Some(key_obj) = first_tx.get("key") {
                    if key_obj.get("tmb").and_then(|v| v.as_str()) == Some(signer_tmb) {
                        return extract_key_from_obj(key_obj).map(Genesis::Implicit);
                    }
                }

                // Fallback to keystore
                if let Ok(key) = load_key_from_keystore(ks, signer_tmb) {
                    return Ok(Genesis::Implicit(key));
                }
            }
        }
    }

    // No keystore or signer lookup failed — scan for embedded keys.
    let mut genesis_keys = Vec::new();

    for tx_value in &first_commit.cozies {
        if let Some(key_obj) = tx_value.get("key") {
            genesis_keys.push(extract_key_from_obj(key_obj)?);
        }
    }

    if genesis_keys.is_empty() {
        return Err(Error::Storage(
            "cannot determine genesis keys from storage".into(),
        ));
    }

    if genesis_keys.len() == 1 {
        Ok(Genesis::Implicit(genesis_keys.remove(0)))
    } else {
        Ok(Genesis::Explicit(genesis_keys))
    }
}

/// Extract a Key from a JSON key object.
fn extract_key_from_obj(key_obj: &serde_json::Value) -> crate::Result<Key> {
    let alg = key_obj
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("key.alg"))?;
    let pub_b64 = key_obj
        .get("pub")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("key.pub"))?;
    let tmb_b64 = key_obj
        .get("tmb")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("key.tmb"))?;

    let pub_key = Base64UrlUnpadded::decode_vec(pub_b64)?;
    let tmb_bytes = Base64UrlUnpadded::decode_vec(tmb_b64)?;

    Ok(Key {
        alg: alg.to_string(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    })
}

/// Parse the --store argument into a FileStore.
pub fn parse_store(store_uri: &str) -> crate::Result<FileStore> {
    if let Some(path) = store_uri.strip_prefix("file:") {
        Ok(FileStore::new(path))
    } else {
        Err(Error::InvalidArgument(format!(
            "unsupported store URI: {store_uri} (expected file:<path>)"
        )))
    }
}

/// Parse a base64url principal root string into a PrincipalGenesis.
pub fn parse_principal_genesis(s: &str) -> crate::Result<cyphr::PrincipalGenesis> {
    let bytes = Base64UrlUnpadded::decode_vec(s)?;
    Ok(cyphr::PrincipalGenesis::from_bytes(bytes))
}

/// Decode base64url string to bytes.
pub fn decode_b64(s: &str) -> crate::Result<Vec<u8>> {
    Ok(Base64UrlUnpadded::decode_vec(s)?)
}

/// Generate a new keypair using `Alg` dispatch.
///
/// Returns the thumbprint string, a `StoredKey` for keystore, and a
/// `cyphr::Key` for protocol operations.
pub fn generate_key(algo: &str, tag: Option<&str>) -> crate::Result<(String, StoredKey, Key)> {
    let alg_enum = coz::Alg::from_str(algo)
        .ok_or_else(|| Error::InvalidArgument(format!("unknown algorithm: {algo}")))?;

    let keypair = alg_enum.generate_keypair();
    let tmb_b64 = Base64UrlUnpadded::encode_string(keypair.thumbprint.as_bytes());

    let now = current_timestamp();

    let stored = StoredKey {
        alg: algo.to_string(),
        pub_key: keypair.pub_bytes.clone(),
        prv_key: keypair.prv_bytes,
        tag: tag.map(String::from),
    };

    let key = Key {
        alg: algo.to_string(),
        tmb: Thumbprint::from_bytes(keypair.thumbprint.as_bytes().to_vec()),
        pub_key: keypair.pub_bytes,
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: tag.map(String::from),
    };

    Ok((tmb_b64, stored, key))
}
