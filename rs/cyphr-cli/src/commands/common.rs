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

    // The keystore is local trust, but a corrupted or swapped record must
    // not yield a key whose tmb is not its pub's thumbprint.
    Ok(Key::new(
        stored.alg.clone(),
        Thumbprint::from_bytes(decode_b64(tmb)?),
        stored.pub_key.clone(),
    )?
    .with_first_seen(now)
    .with_tag(stored.tag.clone()))
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
                // The keystore is the local authority: a key embedded in
                // the (untrusted) bundle never overrides it.
                if let Ok(key) = load_key_from_keystore(ks, signer_tmb) {
                    return Ok(Genesis::Implicit(key));
                }

                // Not in the keystore: fall back to the self-signed
                // genesis key the bundle embeds.
                if let Some(key_obj) = first_tx.get("key") {
                    if key_obj.get("tmb").and_then(|v| v.as_str()) == Some(signer_tmb) {
                        return extract_key_from_obj(key_obj).map(Genesis::Implicit);
                    }
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
        return Err(Error::MissingField("genesis key in the first commit"));
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

    Ok(Key::new(
        alg.to_string(),
        Thumbprint::from_bytes(tmb_bytes),
        pub_key,
    )?)
}

/// Parse the CLI options into a CliStorageEngine.
pub fn parse_store(cli: &crate::Cli) -> crate::Result<CliStorageEngine> {
    let path = store_path(cli)?;
    refuse_interrupted_swap(path)?;
    open_store(path, cli.total_check)
}

/// Refuse to open a store that is missing while a rebase left siblings
/// behind: opening would silently create an empty store beside the real
/// history. A store that was never created (no siblings) opens normally.
fn refuse_interrupted_swap(path: &std::path::Path) -> crate::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Ok(());
    };
    let parent = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(parent)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_str().is_some_and(|n| {
                n.strip_prefix(name).is_some_and(|rest| {
                    rest == super::network::SWAP_MARKER
                        || rest == ".rebase"
                        || rest.starts_with(".pre-rebase-")
                })
            })
        })
        .map(|e| e.path())
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    found.sort();
    Err(Error::InterruptedRebase {
        store: path.to_owned(),
        found,
    })
}

/// The directory a `file:<path>` store URI names.
pub fn store_path(cli: &crate::Cli) -> crate::Result<&std::path::Path> {
    cli.store
        .strip_prefix("file:")
        .map(std::path::Path::new)
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "unsupported store URI: {} (expected file:<path>)",
                cli.store
            ))
        })
}

/// Open (creating if absent) the store rooted at `path`.
///
/// `total_check` discards the index and rebuilds it instead of healing
/// manifest-backed gaps lazily on first use.
pub fn open_store(path: &std::path::Path, total_check: bool) -> crate::Result<CliStorageEngine> {
    let db = fjall::Database::builder(path.join("blobs")).open()?;
    let blob_store = FjallBlobStore::from_database(db.clone())?;
    let indexer = FjallIndexer::open(&path.join("index"))?;
    let engine =
        StorageEngine::with_storage_factory(blob_store, indexer, move |principal_id: &str| {
            cyphr_blob_fjall::open_eml_storage_scoped(db.clone(), principal_id)
                .map_err(|e| e.to_string())
        });

    if total_check {
        block_on(engine.rebuild_index_from_scratch())??;
    }

    Ok(engine)
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
/// life the moment `principal/create` sets it. A principal that has not
/// committed yet (the CLI commits its genesis before its first key change)
/// has no stable field to key off other than `genesis_key()`, which is
/// fixed at construction and never mutated afterward. `pr()` is NOT stable here: it
/// is the live, continuously-recomputed Principal State, which moves with
/// every subsequent commit -- using it produced a different "stable" ID on
/// every save once any operation happened after genesis, silently losing
/// the principal's own tip.
///
/// So a nascent principal's ID is the genesis-time PR, recomputed by
/// rebuilding a throwaway `Principal` from the genesis key (looked up in
/// `keystore` by its still-immutable thumbprint) -- byte-identical to what
/// `init` computed and showed the user, regardless of how many mutations
/// this principal has since accumulated.
pub fn get_principal_id_from_principal<S: cyphr::eml::Storage>(
    principal: &cyphr::Principal<S>,
    keystore: &JsonKeyStore,
) -> crate::Result<String> {
    use cyphr::StateDigest;

    if let Some(pg) = principal.pg() {
        return Ok(pg.as_multihash().tagged_first()?.to_string());
    }

    let genesis_key = load_key_from_keystore(keystore, principal.genesis_key())?;
    let genesis_principal = cyphr::Principal::<cyphr::eml::MemoryStorage>::implicit(genesis_key)?;
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
        let tip = engine.get_tip(&principal_id).await?;

        // `identity` matching a keystore thumbprint directly IS implicit
        // (single-key) genesis, independent of whether a tip has been
        // stored yet. A multi-key principal exists only through its
        // genesis commit (SPEC 5.1), so its genesis comes from storage.
        let is_implicit_genesis = keystore.get(identity).is_ok();

        let genesis = if is_implicit_genesis {
            let genesis_key = load_key_from_keystore(keystore, identity)?;
            cyphr_storage::Genesis::Implicit(genesis_key)
        } else if tip.is_none() {
            return Err(crate::Error::UnresolvableGenesis(identity.to_owned()));
        } else {
            engine.resolve_genesis(&principal_id, &[]).await?
        };

        Ok(engine.load_principal(&principal_id, genesis).await?)
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

/// Resolve `principal`'s genesis from its own `genesis_key()` and the local
/// `keystore`. Every further key enters by a `key/create` its commits
/// carry, so the genesis key alone replays it.
///
/// # Errors
///
/// Returns an error if the genesis key's thumbprint is not found in
/// `keystore` (e.g. an imported principal whose genesis material never
/// lived in this local keystore) — callers fall back to reconstructing
/// genesis from stored blob material instead (see
/// [`extract_genesis_from_commits`]).
fn resolve_local_genesis<S: cyphr::eml::Storage>(
    principal: &cyphr::Principal<S>,
    keystore: &JsonKeyStore,
) -> crate::Result<Genesis> {
    Ok(Genesis::Implicit(load_key_from_keystore(
        keystore,
        principal.genesis_key(),
    )?))
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

        let tip = engine.get_tip(&principal_id).await?;

        let stored_count = tip.map(|t| t.commit_count as usize).unwrap_or(0);

        // A line is new when the commits before it are not all stored yet.
        // An action-only line forms no commit, so it does not count toward
        // `stored_count`; one stored already hashes to the same manifest, so
        // submitting it again changes nothing.
        let mut commits_before = 0usize;
        for commit in &cyphr_storage::export_commits(principal)? {
            let is_new = commits_before >= stored_count;
            if !commit.commit_id.is_empty() {
                commits_before += 1;
            }
            if !is_new {
                continue;
            }
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
                }

                let bytes = serde_json::to_vec(&coz_mut).map_err(crate::Error::Json)?;
                raw_blobs.push(bytes);
            }
            let raw_refs: Vec<&[u8]> = raw_blobs.iter().map(|b| b.as_slice()).collect();

            // Resolve the genesis from what this caller knows locally (its
            // genesis key); the engine reads a stored principal's genesis
            // from its first commit anyway.
            let genesis = match resolve_local_genesis(principal, keystore) {
                Ok(genesis) => genesis,
                Err(_) => {
                    extract_genesis_from_commits(std::slice::from_ref(commit), Some(keystore))?
                },
            };

            engine
                .submit_commit(&principal_id, Some(genesis), &raw_refs)
                .await?;
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
            .await?;

        let mut commit_entries = Vec::with_capacity(chain.len());
        for commit_ref in &chain {
            let mut cozies = Vec::with_capacity(commit_ref.blob_hashes.len());
            let mut keys = Vec::new();

            for hash in &commit_ref.blob_hashes {
                let data = engine
                    .blob_store()
                    .get(hash)
                    .await?
                    .ok_or(crate::Error::MissingBlob(*hash))?;

                let json_str = String::from_utf8(data)?;
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

/// One stored commit as the exact wire blobs the store holds, so a peer
/// receives the bytes the commit's digests were computed over.
pub struct RawCommit {
    /// The commit id (tagged digest).
    pub commit_id: String,
    /// The commit's coz blobs, in commit order.
    pub blobs: Vec<Vec<u8>>,
}

/// A principal's stored history as raw wire blobs, oldest first. Empty when
/// the store holds nothing for `principal_id`.
pub async fn raw_chain(
    engine: &CliStorageEngine,
    principal_id: &str,
) -> crate::Result<Vec<RawCommit>> {
    use cyphr_storage::blob::BlobStore;
    use cyphr_storage::index::Indexer;

    let chain = engine
        .indexer()
        .get_commit_chain(principal_id, None, None)
        .await?;
    let mut out = Vec::with_capacity(chain.len());
    for commit_ref in &chain {
        let mut blobs = Vec::with_capacity(commit_ref.blob_hashes.len());
        for hash in &commit_ref.blob_hashes {
            blobs.push(
                engine
                    .blob_store()
                    .get(hash)
                    .await?
                    .ok_or(crate::Error::MissingBlob(*hash))?,
            );
        }
        out.push(RawCommit {
            commit_id: commit_ref.commit_id.clone(),
            blobs,
        });
    }
    Ok(out)
}

/// The genesis a locally held keystore can state for `identity`, if any:
/// the key itself, when `identity` is a key's thumbprint. `None` means the
/// genesis must come from stored blobs or the peer's.
pub fn local_genesis(keystore: &JsonKeyStore, identity: &str) -> crate::Result<Option<Genesis>> {
    if keystore.get(identity).is_ok() {
        return Ok(Some(Genesis::Implicit(load_key_from_keystore(
            keystore, identity,
        )?)));
    }
    Ok(None)
}

/// Parse a base64url principal genesis string into a PrincipalGenesis.
///
/// The digest is read under the hash its width names (SHA-256, SHA-384 or
/// SHA-512), as the core builds it: a genesis key's thumbprint is hashed
/// with that key's own algorithm, so an Ed25519 identity is 64 bytes.
pub fn parse_principal_genesis(s: &str) -> crate::Result<cyphr::PrincipalGenesis> {
    use coz::HashAlg;

    let bytes = Base64UrlUnpadded::decode_vec(s)?;
    let alg = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
        .into_iter()
        .find(|a| a.digest_size() == bytes.len())
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "identity is {} bytes; expected 32, 48 or 64 (SHA-256, SHA-384, SHA-512)",
                bytes.len()
            ))
        })?;
    Ok(cyphr::PrincipalGenesis::from_digest(alg, bytes)?)
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

    let key = Key::from_pub_key(algo.to_string(), keypair.pub_bytes)?
        .with_first_seen(now)
        .with_tag(tag.map(String::from));

    Ok((tmb_b64, stored, key))
}

/// One step of a replayable history, in order.
pub enum Placed<C, A> {
    /// The commit at this position.
    Commit(usize, C),
    /// An action-only bundle accepted when this many commits existed.
    Actions(usize, A),
}

/// Order a history for replay: a bundle accepted when `n` commits existed
/// precedes commit `n`, and later ones come last, so a `ds/create` finds
/// the actions it includes (SPEC 4.8.2). The one placement rule fetch,
/// rebase, verify and export share, matching `cyphr_storage::export_commits`.
pub fn place<C, A>(
    commits: impl IntoIterator<Item = C>,
    actions: impl IntoIterator<Item = (usize, A)>,
) -> Vec<Placed<C, A>> {
    let mut out = Vec::new();
    let mut bundles = actions.into_iter().peekable();
    for (i, commit) in commits.into_iter().enumerate() {
        while let Some((after, held)) = bundles.next_if(|(after, _)| *after <= i) {
            out.push(Placed::Actions(after, held));
        }
        out.push(Placed::Commit(i, commit));
    }
    out.extend(bundles.map(|(after, held)| Placed::Actions(after, held)));
    out
}

/// Submit a peer's or a store's history to `engine` in replay order, from
/// the commit at `from` on (and the bundles that precede it). A bundle the
/// engine already holds is a no-op (SPEC 7.6). Returns the commits applied.
pub async fn submit_history(
    engine: &CliStorageEngine,
    principal_id: &str,
    genesis: Option<Genesis>,
    commits: &[Vec<Vec<u8>>],
    actions: &[(usize, Vec<Vec<u8>>)],
    from: usize,
) -> crate::Result<usize> {
    let mut applied = 0;
    for step in place(commits, actions.iter().map(|(a, b)| (*a, b))) {
        let (index, blobs, is_commit) = match step {
            Placed::Commit(i, blobs) => (i, blobs, true),
            Placed::Actions(after, blobs) => (after, blobs, false),
        };
        if index < from {
            continue;
        }
        let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(principal_id, genesis.clone(), &refs)
            .await?;
        applied += usize::from(is_commit);
    }
    Ok(applied)
}
