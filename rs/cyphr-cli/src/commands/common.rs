//! Shared helper functions for CLI commands.
//!
//! These were previously duplicated across multiple command modules.
//! Consolidated per C.2 audit finding.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphr::Key;
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_sqlite::SqliteIndexer;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::{CommitEntry, Genesis};

/// Type alias representing the concrete storage engine type used by the CLI.
pub type CliStorageEngine = StorageEngine<FjallBlobStore, SqliteIndexer>;

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

/// Parse the CLI options into a CliStorageEngine.
pub fn parse_store(cli: &crate::Cli) -> crate::Result<CliStorageEngine> {
    let store_uri = &cli.store;
    let keystore_path = &cli.keystore;
    let total_check = cli.total_check;

    if let Some(path) = store_uri.strip_prefix("file:") {
        let path = std::path::Path::new(path);
        let blob_store = FjallBlobStore::open(&path.join("blobs"))
            .map_err(|e| crate::Error::Storage(e.to_string()))?;
        let indexer = SqliteIndexer::open(&path.join("index.db"))
            .map_err(|e| crate::Error::Storage(e.to_string()))?;
        let engine = StorageEngine::new(blob_store, indexer);

        // Open keystore and extract keys
        let keystore = JsonKeyStore::open(keystore_path)?;
        let thumbprints = keystore.list();
        let mut keys = Vec::new();
        for tmb in &thumbprints {
            if let Ok(key) = load_key_from_keystore(&keystore, tmb) {
                keys.push(key);
            }
        }

        // Reindex on startup synchronously
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(async { engine.reindex(&keys, total_check).await })
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        Ok(engine)
    } else {
        Err(Error::InvalidArgument(format!(
            "unsupported store URI: {store_uri} (expected file:<path>)"
        )))
    }
}

/// Get the principal ID string for a PrincipalGenesis
pub fn get_principal_id(pr: &cyphr::PrincipalGenesis) -> crate::Result<String> {
    use cyphr::StateDigest;
    let mh = pr.as_multihash();
    let alg = mh
        .algorithms()
        .next()
        .ok_or_else(|| crate::Error::Storage("empty PR algorithms".into()))?;
    let bytes = mh
        .get(alg)
        .ok_or_else(|| crate::Error::Storage("missing PR variant".into()))?;
    Ok(format!("{alg}:{}", Base64UrlUnpadded::encode_string(bytes)))
}

/// Get the principal ID string from a Principal
pub fn get_principal_id_from_principal(principal: &cyphr::Principal) -> crate::Result<String> {
    use cyphr::StateDigest;
    let mh = if let Some(pg) = principal.pg() {
        pg.as_multihash()
    } else {
        let genesis_tmb = principal
            .genesis_keys()
            .first()
            .ok_or_else(|| crate::Error::Storage("no genesis keys found".into()))?;
        let bytes = Base64UrlUnpadded::decode_vec(genesis_tmb)?;
        let alg = principal.hash_alg();
        return Ok(format!(
            "{alg}:{}",
            Base64UrlUnpadded::encode_string(&bytes)
        ));
    };
    let alg = mh
        .algorithms()
        .next()
        .ok_or_else(|| crate::Error::Storage("empty PR/PS algorithms".into()))?;
    let bytes = mh
        .get(alg)
        .ok_or_else(|| crate::Error::Storage("missing PR/PS variant".into()))?;
    Ok(format!("{alg}:{}", Base64UrlUnpadded::encode_string(bytes)))
}

/// Load a principal from the storage engine.
pub fn load_principal_from_engine(
    engine: &CliStorageEngine,
    keystore: &JsonKeyStore,
    identity: &str,
) -> crate::Result<cyphr::Principal> {
    let pr = parse_principal_genesis(identity)?;
    let principal_id = get_principal_id(&pr)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let tip = engine
            .get_tip(&principal_id)
            .await
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        let is_implicit_genesis = keystore.get(identity).is_ok();

        if tip.is_none() {
            // Genesis state - reconstruct from keystore
            let key = load_key_from_keystore(keystore, identity)?;
            Ok(cyphr::Principal::implicit(key)?)
        } else {
            let genesis = if is_implicit_genesis {
                let genesis_key = load_key_from_keystore(keystore, identity)?;
                cyphr_storage::Genesis::Implicit(genesis_key)
            } else {
                engine
                    .resolve_genesis(&principal_id, &[])
                    .await
                    .map_err(|e| crate::Error::Storage(e.to_string()))?
            };

            engine
                .load_principal(&principal_id, genesis)
                .await
                .map_err(|e| crate::Error::Storage(e.to_string()))
        }
    })
}

/// Save a principal's new commits to the storage engine.
pub fn save_principal_to_engine(
    engine: &CliStorageEngine,
    keystore: &JsonKeyStore,
    principal: &cyphr::Principal,
) -> crate::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let principal_id = get_principal_id_from_principal(principal)?;

        let tip = engine
            .get_tip(&principal_id)
            .await
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        let stored_count = tip.map(|t| t.commit_count as usize).unwrap_or(0);

        let commits = cyphr_storage::export_commits(principal)
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        for (i, commit) in commits.iter().enumerate().skip(stored_count) {
            let mut raw_blobs = Vec::new();
            let mut key_iter = commit.keys.iter();
            for coz in &commit.cozies {
                let mut coz_mut = coz.clone();
                let typ = coz_mut
                    .get("pay")
                    .and_then(|p| p.get("typ"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if typ.contains("/key/create") || typ.contains("/key/replace") {
                    if let Some(key_entry) = key_iter.next() {
                        if let Some(obj) = coz_mut.as_object_mut() {
                            obj.insert("key".to_string(), serde_json::to_value(key_entry)?);
                        }
                    }
                } else if i == 0 && typ.contains("/commit/create") {
                    use coz::base64ct::{Base64UrlUnpadded, Encoding};
                    let identity_fallback = principal_id.split(':').last().unwrap().to_string();
                    let identity = principal
                        .genesis_keys()
                        .first()
                        .unwrap_or(&identity_fallback);
                    if let Ok(key) = load_key_from_keystore(keystore, identity) {
                        let key_entry = cyphr_storage::KeyEntry {
                            alg: key.alg.clone(),
                            pub_key: Base64UrlUnpadded::encode_string(&key.pub_key),
                            tmb: key.tmb.to_b64(),
                            tag: key.tag.clone(),
                            now: Some(key.first_seen),
                        };
                        if let Some(obj) = coz_mut.as_object_mut() {
                            obj.insert("key".to_string(), serde_json::to_value(&key_entry)?);
                        }
                    }
                }

                let bytes = serde_json::to_vec(&coz_mut).map_err(crate::Error::Json)?;
                raw_blobs.push(bytes);
            }
            let raw_refs: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

            let genesis = if i == 0 {
                let identity_fallback = principal_id.split(':').last().unwrap().to_string();
                let identity = principal
                    .genesis_keys()
                    .first()
                    .unwrap_or(&identity_fallback);
                if let Ok(key) = load_key_from_keystore(keystore, identity) {
                    Some(cyphr_storage::Genesis::Implicit(key))
                } else {
                    let parsed_commit = cyphr_storage::CommitEntry {
                        cozies: commit.cozies.clone(),
                        keys: commit.keys.clone(),
                        commit_id: commit.commit_id.clone(),
                        auth_root: commit.auth_root.clone(),
                        sr: commit.sr.clone(),
                        pr: commit.pr.clone(),
                    };
                    let extracted = extract_genesis_from_commits(&[parsed_commit], Some(keystore))?;
                    Some(extracted)
                }
            } else {
                None
            };

            engine
                .submit_commit(&principal_id, genesis, &raw_refs)
                .await
                .map_err(|e| crate::Error::Storage(e.to_string()))?;
        }

        Ok(())
    })
}

/// Retrieve all commits for an identity from the storage engine.
pub fn get_commits_from_engine(
    engine: &CliStorageEngine,
    identity: &str,
) -> crate::Result<Vec<CommitEntry>> {
    let pr = parse_principal_genesis(identity)?;
    let principal_id = get_principal_id(&pr)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        use cyphr_storage::blob::BlobStore;
        use cyphr_storage::index::Indexer;

        let chain = engine
            .indexer()
            .get_commit_chain(&principal_id, None, None)
            .await
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let mut cozies = Vec::with_capacity(commit_ref.blob_hashes.len());
            let mut keys = Vec::new();

            for hash in &commit_ref.blob_hashes {
                let data = engine
                    .blob_store()
                    .get(hash)
                    .await
                    .map_err(|e| crate::Error::Storage(e.to_string()))?
                    .ok_or_else(|| crate::Error::Storage(format!("blob {hash} not found")))?;

                let json_str = String::from_utf8(data)
                    .map_err(|e| crate::Error::Storage(format!("blob is not UTF-8: {e}")))?;
                let value: serde_json::Value =
                    serde_json::from_str(&json_str).map_err(crate::Error::Json)?;

                if let Some(key_obj) = value.get("key") {
                    if let Ok(ke) =
                        serde_json::from_value::<cyphr_storage::KeyEntry>(key_obj.clone())
                    {
                        keys.push(ke);
                    }
                }

                cozies.push(value);
            }

            commit_entries.push(cyphr_storage::CommitEntry::new(
                cozies,
                keys,
                commit_ref.commit_id.clone(),
                String::new(),
                String::new(),
                commit_ref.pr.clone(),
            ));
        }

        Ok(commit_entries)
    })
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
