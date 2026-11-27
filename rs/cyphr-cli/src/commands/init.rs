//! Identity initialization command.

use cyphr::{Principal, PrincipalGenesis};

use super::common::{
    block_on, current_timestamp, generate_key, load_key_from_keystore, parse_store,
    save_principal_to_engine,
};
use crate::keystore::KeyBackend;
use crate::{Cli, Error, OutputFormat};

/// Commit the principal's genesis (SPEC 5.1, 5.2, 5.3) if it has none:
/// the genesis key signs a `key/create` for itself and for each of
/// `others`, the `principal/create` and the commit transaction. Every
/// commit chain begins with this commit, so it precedes the first commit
/// any command makes.
pub(crate) fn commit_genesis<S: cyphr::eml::Storage>(
    principal: &mut Principal<S>,
    keystore: &impl KeyBackend,
    others: &[cyphr::Key],
    authority: &str,
) -> crate::Result<()> {
    if principal.pg().is_some() {
        return Ok(());
    }
    let genesis = principal.genesis_key();
    let signer = keystore.signer(genesis)?;
    block_on(principal.commit_genesis(&signer, others, current_timestamp(), authority))??;
    Ok(())
}

/// Refuse a Level 1 identity (no genesis commit, SPEC 5.1) before anything is
/// signed: moving it up is the user's explicit act (`upgrade`, or a
/// command's `--upgrade`), never a side effect of another command.
pub(crate) fn require_genesis_commit<S: cyphr::eml::Storage>(
    principal: &Principal<S>,
    upgradable: bool,
) -> crate::Result<()> {
    if principal.pg().is_some() {
        Ok(())
    } else {
        Err(Error::NoGenesisCommit { upgradable })
    }
}

/// Run `cyphr upgrade`: the genesis commit of a Level 1 identity.
pub fn upgrade(cli: &Cli, identity: &PrincipalGenesis) -> crate::Result<()> {
    let keystore = super::common::open_backend(cli)?;
    let store = parse_store(cli)?;
    let mut principal = super::common::load_principal_from_engine(&store, &keystore, identity)?;
    if principal.pg().is_some() {
        return Err(Error::AlreadyCommitted(identity.to_string()));
    }
    commit_genesis(&mut principal, &keystore, &[], &cli.authority)?;
    save_principal_to_engine(&store, &keystore, &principal)?;
    let commit_id = cyphr_storage::export_commits(&principal)?
        .into_iter()
        .rfind(|l| !l.commit_id.is_empty())
        .map(|l| l.commit_id)
        .ok_or_else(|| Error::EmptyHistory(identity.to_string()))?;
    match cli.format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "identity": identity, "commit_id": commit_id,
            }))?
        ),
        OutputFormat::Table => {
            println!("Upgraded identity {identity} with a genesis commit");
            println!("  commit: {commit_id}");
        },
    }
    Ok(())
}

/// Run the init command.
pub fn run(
    cli: &Cli,
    algo: &str,
    key_tmb: Option<&str>,
    keys_tmb: Option<&[String]>,
    genesis_commit: bool,
) -> crate::Result<()> {
    let mut keystore = super::common::open_backend(cli)?;

    // The genesis key, and the further keys its genesis commit creates.
    let (genesis, others) = match (key_tmb, keys_tmb) {
        // Multi-key genesis: the first key creates the rest (SPEC 5.3)
        (None, Some(tmbs)) if !tmbs.is_empty() => {
            let mut keys = tmbs
                .iter()
                .map(|tmb| load_key_from_keystore(&keystore, tmb))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter();
            let genesis = keys.next().ok_or_else(|| {
                Error::InvalidArgument("--keys requires at least one thumbprint".into())
            })?;
            (genesis, keys.collect())
        },

        // Genesis with an existing key
        (Some(tmb), None) => (load_key_from_keystore(&keystore, tmb)?, Vec::new()),

        // Generate a new genesis key
        (None, None) => {
            let (_, key) = generate_key(&mut keystore, algo, None)?;
            (key, Vec::new())
        },

        // Conflicting options
        (Some(_), Some(_)) => {
            return Err(Error::InvalidArgument(
                "cannot specify both --key and --keys".into(),
            ));
        },

        // Empty explicit list
        (None, Some(_)) => {
            return Err(Error::InvalidArgument(
                "--keys requires at least one thumbprint".into(),
            ));
        },
    };

    let mut principal = block_on(Principal::implicit(genesis))??;
    // A multi-key principal is Level 3+, which exists only through its
    // genesis commit (SPEC 5.1), so `--keys` with further keys commits it.
    if genesis_commit || !others.is_empty() {
        commit_genesis(&mut principal, &keystore, &others, &cli.authority)?;
    }

    // The identity printed: PG once established; before genesis (L1/L2) the
    // genesis identifier is the PR.
    let identity = match principal.pg() {
        Some(pg) => pg.clone(),
        None => principal.pr_id()?,
    };

    // Store the identity
    let store = parse_store(cli)?;
    save_principal_to_engine(&store, &keystore, &principal)?;

    // Output result
    match cli.format {
        OutputFormat::Json => {
            let keys: Vec<_> = principal.active_keys().map(|k| k.tmb().to_b64()).collect();
            let output = serde_json::json!({
                "pg": identity,
                "keys": keys,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Created identity");
            println!("  pg: {identity}");
            println!("  keys:");
            for key in principal.active_keys() {
                let tag_str = key.tag().unwrap_or("-");
                println!("    {} ({}) [{}]", key.tmb().to_b64(), key.alg(), tag_str);
            }
            println!("  stored: {}", cli.store);
        },
    }

    Ok(())
}
