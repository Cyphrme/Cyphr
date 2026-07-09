//! Shared helper functions for CLI commands.
//!
//! These were previously duplicated across multiple command modules.
//! Consolidated per C.2 audit finding.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphr::Key;
use cyphr_blob_fjall::FjallBlobStore;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::{CommitEntry, Genesis};

/// Type alias representing the concrete storage engine type used by the CLI.
pub type CliStorageEngine =
    StorageEngine<FjallBlobStore, FjallIndexer, cyphr_blob_fjall::storage_fjall::FjallStorage>;

/// Type alias for a `Principal` backed by the CLI's durable Commit Tree
/// storage — what [`load_principal_from_engine`] always returns.
pub type CliPrincipal = cyphr::Principal<cyphr_blob_fjall::storage_fjall::FjallStorage>;

use crate::Error;
use crate::keystore::{JsonKeyStore, KeyStore, StoredKey};

/// Build a fresh single-threaded tokio runtime and drive `fut` to
/// completion on it.
///
/// The CLI is synchronous end-to-end; every entry point that needs to await
/// one async storage call spins up a short-lived runtime just for that call
/// rather than making the whole CLI async.
pub fn block_on<F: std::future::Future>(fut: F) -> crate::Result<F::Output> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(rt.block_on(fut))
}

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
        let db = fjall::Database::builder(path.join("blobs"))
            .open()
            .map_err(|e| crate::Error::Storage(e.to_string()))?;
        let blob_store = FjallBlobStore::from_database(db.clone())
            .map_err(|e| crate::Error::Storage(e.to_string()))?;
        let indexer = FjallIndexer::open(&path.join("index"))
            .map_err(|e| crate::Error::Storage(e.to_string()))?;
        let engine =
            StorageEngine::with_storage_factory(blob_store, indexer, move |principal_id: &str| {
                cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), principal_id)
                    .map_err(|e| e.to_string())
            });

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
        block_on(engine.reindex(&keys, total_check))?
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        Ok(engine)
    } else {
        Err(Error::InvalidArgument(format!(
            "unsupported store URI: {store_uri} (expected file:<path>)"
        )))
    }
}

/// Get the principal ID string for a PrincipalGenesis
pub fn get_principal_id(pg: &cyphr::PrincipalGenesis) -> crate::Result<String> {
    use cyphr::StateDigest;
    Ok(pg.as_multihash().tagged_first()?.to_string())
}

/// Get the principal ID string from a Principal.
///
/// This must be *stable*: it is used as the storage engine's lookup key for
/// this principal's tip across its entire lifetime, so calling it again
/// after further commits have been applied must still yield the same
/// string it returned right after genesis.
///
/// Established (Level 3+) principals key off `pg()`, which is frozen for
/// life the moment `principal/create` sets it. But a still-nascent
/// principal (including multi-key explicit genesis before that commit --
/// the common case, since the CLI never issues `principal/create`) has no
/// stable field to key off other than `genesis_keys()`, which is fixed at
/// construction and never mutated afterward. `pr()` is NOT stable here: it
/// is the live, continuously-recomputed Principal State, which moves with
/// every subsequent commit -- using it produced a different "stable" ID on
/// every save once any operation happened after genesis, silently losing
/// the principal's own tip.
///
/// So a nascent principal's ID is the genesis-time PR, recomputed by
/// rebuilding a throwaway `Principal` from the original genesis keys
/// (looked up in `keystore` by their still-immutable thumbprints) --
/// byte-identical to what `init` computed and showed the user, regardless
/// of how many mutations this principal has since accumulated.
pub fn get_principal_id_from_principal<S: cyphr::eml::Storage>(
    principal: &cyphr::Principal<S>,
    keystore: &JsonKeyStore,
) -> crate::Result<String> {
    use cyphr::StateDigest;

    if let Some(pg) = principal.pg() {
        return Ok(pg.as_multihash().tagged_first()?.to_string());
    }

    let genesis_keys = principal
        .genesis_keys()
        .iter()
        .map(|tmb| load_key_from_keystore(keystore, tmb))
        .collect::<crate::Result<Vec<_>>>()?;
    let genesis_principal = cyphr::Principal::<cyphr::eml::MemoryStorage>::explicit(genesis_keys)?;
    Ok(genesis_principal
        .pr()
        .as_multihash()
        .tagged_first()?
        .to_string())
}

/// Load a principal from the storage engine.
pub fn load_principal_from_engine(
    engine: &CliStorageEngine,
    keystore: &JsonKeyStore,
    identity: &str,
) -> crate::Result<CliPrincipal> {
    let pg = parse_principal_genesis(identity)?;
    let principal_id = get_principal_id(&pg)?;

    block_on(async {
        let tip = engine
            .get_tip(&principal_id)
            .await
            .map_err(|e| crate::Error::Storage(e.to_string()))?;

        // `identity` matching a keystore thumbprint directly IS implicit
        // (single-key) genesis, independent of whether a tip has been
        // stored yet -- this must be checked before falling back on
        // `tip.is_none()`, otherwise a never-yet-pushed *explicit*
        // multi-key genesis (whose identity is a combined digest, not any
        // single key's thumbprint) gets misread as implicit and fails to
        // reload with a confusing "key not found" error.
        let is_implicit_genesis = keystore.get(identity).is_ok();

        let genesis = if is_implicit_genesis {
            let genesis_key = load_key_from_keystore(keystore, identity)?;
            cyphr_storage::Genesis::Implicit(genesis_key)
        } else if let Some(tmbs) = keystore.lookup_genesis(&principal_id) {
            // Explicit multi-key genesis recorded locally at `init` time
            // (see `init`'s call to `record_genesis`) -- the only way to
            // reconstruct it before any commit exists to anchor it in
            // storage.
            let keys = tmbs
                .iter()
                .map(|tmb| load_key_from_keystore(keystore, tmb))
                .collect::<crate::Result<Vec<_>>>()?;
            cyphr_storage::Genesis::Explicit(keys)
        } else if tip.is_none() {
            return Err(crate::Error::Storage(format!(
                "identity {identity} has no stored commits and does not match any keystore key or \
                 recorded genesis; cannot resolve genesis"
            )));
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
    })?
}

/// Whether a coz `typ` string indicates a key-embedding transaction
/// (`key/create` or `key/replace`) -- i.e. one whose blob must carry the
/// new key's material inline, not just the signer's thumbprint.
///
/// Thin wrapper over `cyphr::parsed_coz::typ::is_key_introducing`, the
/// crate-spanning canonical implementation of this rule (F41).
fn is_key_embedding_typ(typ: &str) -> bool {
    cyphr::parsed_coz::typ::is_key_introducing(typ)
}

/// Save a principal's new commits to the storage engine.
///
/// Generic over `principal`'s own Commit Tree backend `S`: callers pass
/// both a freshly-constructed, not-yet-persisted `Principal` (backed by
/// [`cyphr::eml::MemoryStorage`], e.g. from `init`/`import`) and a
/// [`CliPrincipal`] loaded via [`load_principal_from_engine`] and then
/// mutated (e.g. from `key add`/`key revoke`). Either way, only `engine`'s
/// own durable storage is written to — `principal`'s backend is read-only
/// here, via `cyphr_storage::export_commits`.
pub fn save_principal_to_engine<S: cyphr::eml::Storage>(
    engine: &CliStorageEngine,
    keystore: &JsonKeyStore,
    principal: &cyphr::Principal<S>,
) -> crate::Result<()> {
    block_on(async {
        let principal_id = get_principal_id_from_principal(principal, keystore)?;

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

                if is_key_embedding_typ(typ) {
                    if let Some(key_entry) = key_iter.next() {
                        if let Some(obj) = coz_mut.as_object_mut() {
                            obj.insert("key".to_string(), serde_json::to_value(key_entry)?);
                        }
                    }
                } else if i == 0 && typ.contains("/commit/create") {
                    use coz::base64ct::{Base64UrlUnpadded, Encoding};
                    let identity_fallback =
                        principal_id.split(':').next_back().unwrap().to_string();
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
                let identity_fallback = principal_id.split(':').next_back().unwrap().to_string();
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
    })?
}

/// Retrieve all commits for an identity from the storage engine.
pub fn get_commits_from_engine(
    engine: &CliStorageEngine,
    identity: &str,
) -> crate::Result<Vec<CommitEntry>> {
    let pg = parse_principal_genesis(identity)?;
    let principal_id = get_principal_id(&pg)?;

    block_on(async {
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
                commit_ref.ar.clone(),
                commit_ref.sr.clone(),
                commit_ref.pr.clone(),
            ));
        }

        Ok(commit_entries)
    })?
}

/// Parse a base64url principal genesis string into a PrincipalGenesis.
pub fn parse_principal_genesis(s: &str) -> crate::Result<cyphr::PrincipalGenesis> {
    let bytes = Base64UrlUnpadded::decode_vec(s)?;
    Ok(cyphr::PrincipalGenesis::from_bytes(bytes)?)
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
