//! Shared helper functions for CLI commands.
//!
//! These were previously duplicated across multiple command modules.
//! Consolidated per C.2 audit finding.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphr::Key;
use cyphr::replay::WireBundle;
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
use crate::keystore::{Error as KeystoreError, JsonKeyStore, KeyBackend};

/// The one place a command opens the key backend. Selecting a backend at
/// runtime (an OS keychain, a hardware token) changes this function and
/// nothing else: commands see only the [`KeyBackend`] trait.
pub fn open_backend(cli: &crate::Cli) -> crate::Result<JsonKeyStore> {
    Ok(JsonKeyStore::open(&cli.keystore)?)
}

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
pub fn load_key_from_keystore(keystore: &impl KeyBackend, tmb: &str) -> crate::Result<Key> {
    let stored = keystore.public(tmb)?;
    let now = current_timestamp();

    // The keystore is local trust, but a corrupted or swapped record must
    // not yield a key whose tmb is not its pub's thumbprint.
    Ok(Key::new(
        stored.alg,
        Thumbprint::from_bytes(decode_b64(tmb)?),
        stored.pub_key,
    )?
    .with_first_seen(now)
    .with_tag(stored.tag))
}

/// Extract genesis from stored commits.
///
/// Strategy depends on whether a keystore is available:
///
/// **With keystore**: Look up the signer of the first coz by
/// thumbprint (`pay.tmb`). This is the correct approach for import,
/// where the genesis key (signer) may not be in the commit's `keys` but
/// the *new* key being added might be.
///
/// **Without keystore**: the first commit's `keys` entries its
/// `key/create` cozies name, in transaction order. This works for
/// inspect/verify/list where all key material is in the commits
/// themselves.
pub fn extract_genesis_from_commits(
    commits: &[CommitEntry],
    keystore: Option<&impl KeyBackend>,
) -> crate::Result<Genesis> {
    let first_commit = commits.first().ok_or(Error::MissingField("commits"))?;
    let named = |tmb: &str| first_commit.keys.iter().find(|k| k.tmb == tmb);

    // When keystore is available, prefer signer-based lookup.
    // The signer of the first coz IS the genesis key.
    if let Some(ks) = keystore {
        if let Some(signer_tmb) = first_commit
            .txs
            .first()
            .and_then(|tx| tx.first())
            .and_then(|coz| coz.pointer("/pay/tmb"))
            .and_then(|v| v.as_str())
        {
            // The keystore is the local authority: a key in the
            // (untrusted) bundle never overrides it.
            if let Ok(key) = load_key_from_keystore(ks, signer_tmb) {
                return Ok(Genesis::Implicit(key));
            }

            // Not in the keystore: fall back to the self-signed genesis
            // key the bundle discloses.
            if let Some(entry) = named(signer_tmb) {
                return entry_key(entry).map(Genesis::Implicit);
            }
        }
    }

    // No keystore or signer lookup failed — the keys the key/creates name.
    let mut genesis_keys = Vec::new();
    for coz in first_commit.txs.iter().flatten() {
        let typ = coz
            .pointer("/pay/typ")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::KEY_CREATE) {
            continue;
        }
        if let Some(entry) = coz
            .pointer("/pay/id")
            .and_then(|v| v.as_str())
            .and_then(named)
        {
            genesis_keys.push(entry_key(entry)?);
        }
    }

    if genesis_keys.is_empty() {
        return Err(Error::MissingField("genesis key in the first commit"));
    }

    if genesis_keys.len() == 1 {
        Ok(Genesis::Implicit(genesis_keys.remove(0)))
    } else {
        Ok(Genesis::Disclosed(genesis_keys))
    }
}

/// A commit `keys` entry as a [`Key`].
fn entry_key(entry: &cyphr_storage::KeyEntry) -> crate::Result<Key> {
    entry.to_key().map_err(|e| match e {
        cyphr::replay::WireError::Key(refusal) => refusal.into(),
        other => Error::InvalidArgument(format!("key {}: {other}", entry.tmb)),
    })
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
    let logs = cyphr_blob_fjall::EmlLogs::new(db)?;
    let engine = StorageEngine::with_log_factory(blob_store, indexer, logs);

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
    keystore: &impl KeyBackend,
) -> crate::Result<String> {
    use cyphr::StateDigest;

    if let Some(pg) = principal.pg() {
        return Ok(pg.as_multihash().tagged_first()?.to_string());
    }

    let genesis_key = load_key_from_keystore(keystore, principal.genesis_key())?;
    let genesis_principal = cyphr::PrincipalState::genesis(genesis_key)?;
    Ok(genesis_principal
        .pr()
        .as_multihash()
        .tagged_first()?
        .to_string())
}

/// Load a principal from the storage engine.
pub fn load_principal_from_engine(
    engine: &CliStorageEngine,
    keystore: &impl KeyBackend,
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
        let is_implicit_genesis = keystore.public(identity).is_ok();

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
    keystore: &impl KeyBackend,
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
    keystore: &impl KeyBackend,
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
            let bundle = commit.bundle().map_err(crate::Error::Json)?;

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
                .submit_commit(&principal_id, Some(genesis), &bundle)
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
        let patch = engine.get_patch(&principal_id, None, None).await?;
        patch
            .entries
            .iter()
            .map(|entry| {
                Ok(CommitEntry {
                    commit_id: entry.commit.commit_id.clone(),
                    auth_root: entry.commit.ar.clone(),
                    sr: entry.commit.sr.clone(),
                    pr: entry.commit.pr.clone(),
                    ..CommitEntry::from_bundle(&entry.bundle).map_err(crate::Error::Json)?
                })
            })
            .collect()
    })?
}

/// One stored commit as the exact wire bundle the store holds, so a peer
/// receives the bytes the commit's digests were computed over.
pub struct RawCommit {
    /// The commit id (tagged digest).
    pub commit_id: String,
    /// The commit's bundle, grouped by transaction.
    pub bundle: WireBundle,
}

/// A principal's stored history as raw wire bundles, oldest first. Empty
/// when the store holds nothing for `principal_id`.
pub async fn raw_chain(
    engine: &CliStorageEngine,
    principal_id: &str,
) -> crate::Result<Vec<RawCommit>> {
    if engine.get_tip(principal_id).await?.is_none() {
        return Ok(Vec::new());
    }
    Ok(engine
        .get_patch(principal_id, None, None)
        .await?
        .entries
        .into_iter()
        .map(|entry| RawCommit {
            commit_id: entry.commit.commit_id,
            bundle: entry.bundle,
        })
        .collect())
}

/// The genesis a locally held keystore can state for `identity`, if any:
/// the key itself, when `identity` is a key's thumbprint. `None` means the
/// genesis must come from stored blobs or the peer's.
pub fn local_genesis(keystore: &impl KeyBackend, identity: &str) -> crate::Result<Option<Genesis>> {
    if keystore.public(identity).is_ok() {
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

/// Generate a new keypair inside `keystore`.
///
/// Returns the thumbprint string and a `cyphr::Key` for protocol
/// operations; the private half never leaves the backend.
pub fn generate_key(
    keystore: &mut impl KeyBackend,
    algo: &str,
    tag: Option<&str>,
) -> crate::Result<(String, Key)> {
    let info = keystore.generate(algo, tag).map_err(|e| match e {
        KeystoreError::UnknownAlgorithm(a) => {
            Error::InvalidArgument(format!("unknown algorithm: {a}"))
        },
        other => other.into(),
    })?;

    let key = Key::from_pub_key(info.alg, info.pub_key)?
        .with_first_seen(current_timestamp())
        .with_tag(info.tag);

    Ok((info.tmb, key))
}

/// Sign the pay `pay_bytes` as it stands through `signer`, as
/// `coz::sign_json` does with raw key bytes: the signature over the pay's
/// canonical hash, and the czd of the signed coz.
pub fn sign_pay(
    signer: &impl cyphr::signer::Signer,
    pay_bytes: &[u8],
) -> crate::Result<(Vec<u8>, coz::Czd)> {
    let alg = signer.alg();
    let cad = coz::canonical_hash_for_alg(pay_bytes, alg, None)
        .ok_or_else(|| Error::Signing(format!("cannot canonicalize pay for {alg}")))?;
    let sig = block_on(signer.sign(&cad))?.map_err(|e| Error::Signing(e.to_string()))?;
    let czd = coz::czd_for_alg(&cad, &sig, alg)
        .ok_or_else(|| Error::Signing("czd_for_alg failed".into()))?;
    Ok((sig, czd))
}

/// Submit a peer's or a store's history to `engine`: the commits from the
/// one at `from` on, then every action-only bundle (actions hold no chain
/// position, SPEC 4.8.1). A bundle the engine already holds is a no-op
/// (SPEC 7.6). Returns the commits applied.
pub async fn submit_history(
    engine: &CliStorageEngine,
    principal_id: &str,
    genesis: Option<Genesis>,
    commits: &[WireBundle],
    actions: &[Vec<Vec<u8>>],
    from: usize,
) -> crate::Result<usize> {
    let mut applied = 0;
    for bundle in commits.iter().skip(from) {
        engine
            .submit_commit(principal_id, genesis.clone(), bundle)
            .await?;
        applied += 1;
    }
    for blobs in actions {
        engine
            .submit_commit(
                principal_id,
                genesis.clone(),
                &WireBundle::actions(blobs.clone()),
            )
            .await?;
    }
    Ok(applied)
}
