//! ParsedCoz commands.

use cyphr::StateDigest;

use super::common::{
    get_commits_from_engine, load_key_from_keystore, load_principal_from_engine,
    parse_principal_genesis, parse_store,
};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, Error, OutputFormat, TxCommands};

/// Run a tx subcommand.
pub fn run(cli: &Cli, command: &TxCommands) -> crate::Result<()> {
    match command {
        TxCommands::List { identity } => list(cli, identity),
        TxCommands::Verify { identity } => verify(cli, identity),
    }
}

/// List cozies for an identity.
fn list(cli: &Cli, identity: &str) -> crate::Result<()> {
    let principal = load_identity(cli, identity)?;

    let cozies: Vec<_> = principal.iter_all_cozies().collect();

    match cli.output {
        OutputFormat::Json => {
            let tx_list: Vec<_> = cozies
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    serde_json::json!({
                        "index": i,
                        "kind": tx.kind().to_string(),
                        "signer": tx.signer().to_b64(),
                        "timestamp": tx.now(),
                        "czd": tx.czd().to_b64(),
                    })
                })
                .collect();

            let output = serde_json::json!({
                "identity": identity,
                "transaction_count": cozies.len(),
                "cozies": tx_list,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Transactions for: {identity}");
            println!();

            if cozies.is_empty() {
                println!("  (no cozies - genesis state)");
            } else {
                for (i, tx) in cozies.iter().enumerate() {
                    println!(
                        "  [{}] {:?} by {} @ {}",
                        i,
                        tx.kind(),
                        &tx.signer().to_b64()[..12],
                        tx.now()
                    );
                }
            }

            println!();
            println!("Total: {} cozies", cozies.len());
        },
    }

    Ok(())
}

/// Verify coz chain integrity for an identity.
pub fn verify(cli: &Cli, identity: &str) -> crate::Result<()> {
    let store = parse_store(&cli.store, &cli.keystore)?;

    // Load commits from store
    let commits = get_commits_from_engine(&store, identity).unwrap_or_default();

    if commits.is_empty() {
        // Genesis state - verify by reconstructing from keystore
        let keystore = JsonKeyStore::open(&cli.keystore)?;
        let key = load_key_from_keystore(&keystore, identity)?;
        let principal = cyphr::Principal::implicit(key)?;

        // Verify PR matches (L1 has no PR)
        if let Some(pr) = principal.pg() {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let computed_pr = pr
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| Error::Storage(format!("PR empty: {e}")))?;
            if computed_pr != identity {
                return Err(Error::Storage(format!(
                    "PR mismatch: computed {} != {}",
                    computed_pr, identity
                )));
            }
        }

        match cli.output {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "identity": identity,
                    "status": "OK",
                    "commits_verified": 0,
                    "transactions_verified": 0,
                    "message": "genesis state verified",
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            },
            OutputFormat::Table => {
                println!("Verification: OK");
                println!("  Identity: {identity}");
                println!("  Commits: 0 (genesis state)");
                println!("  Transactions: 0");
            },
        }

        return Ok(());
    }

    // Detect implicit genesis: if identity (PR) is in keystore, it's an implicit genesis identity
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal = load_principal_from_engine(&store, &keystore, identity)?;

    // Verify PR matches
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    if let Some(pr) = principal.pg() {
        let computed_pr = pr
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| Error::Storage(format!("PR empty: {e}")))?;
        if computed_pr != identity {
            return Err(Error::Storage(format!(
                "PR mismatch: computed {} != expected {}",
                computed_pr, identity
            )));
        }
    }

    // Verify state digests from commits match computed state
    let Some(last_commit) = commits.last() else {
        return Ok(());
    };
    let computed_ps = principal
        .pr()
        .as_multihash()
        .first_variant()
        .map(Base64UrlUnpadded::encode_string)
        .map_err(|e| Error::Storage(format!("PS empty: {e}")))?;

    // Parse stored ps which may be in "alg:digest" format
    let stored_ps_digest = last_commit.pr.split(':').last().unwrap_or(&last_commit.pr);

    if computed_ps != stored_ps_digest {
        return Err(Error::Storage(format!(
            "PS mismatch: computed {} != stored {}",
            computed_ps, stored_ps_digest
        )));
    }

    let tx_count: usize = principal.iter_all_cozies().count();

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "identity": identity,
                "status": "OK",
                "commits_verified": commits.len(),
                "transactions_verified": tx_count,
                "computed_ps": computed_ps,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Verification: OK");
            println!("  Identity: {identity}");
            println!("  Commits: {} verified", commits.len());
            println!("  Transactions: {} verified", tx_count);
            println!("  PS: {}", computed_ps);
        },
    }

    Ok(())
}

/// Load identity from storage or keystore.
fn load_identity(cli: &Cli, identity: &str) -> crate::Result<cyphr::Principal> {
    let store = parse_store(&cli.store, &cli.keystore)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    load_principal_from_engine(&store, &keystore, identity)
}
