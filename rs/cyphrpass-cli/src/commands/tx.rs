//! Transaction commands.

use cyphrpass::Key;
use cyphrpass_storage::{FileStore, Genesis, load_principal_from_commits};

use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, OutputFormat, TxCommands};

/// Run a tx subcommand.
pub fn run(cli: &Cli, command: &TxCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        TxCommands::List { identity } => list(cli, identity),
        TxCommands::Verify { identity } => verify(cli, identity),
    }
}

/// List transactions for an identity.
fn list(cli: &Cli, identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let principal = load_identity(cli, identity)?;

    let txs: Vec<_> = principal.transactions().collect();

    match cli.output {
        OutputFormat::Json => {
            let tx_list: Vec<_> = txs
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
                "transaction_count": txs.len(),
                "transactions": tx_list,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Transactions for: {identity}");
            println!();

            if txs.is_empty() {
                println!("  (no transactions - genesis state)");
            } else {
                for (i, tx) in txs.iter().enumerate() {
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
            println!("Total: {} transactions", txs.len());
        },
    }

    Ok(())
}

/// Verify transaction chain integrity for an identity.
fn verify(cli: &Cli, identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Load commits from store
    let commits = match store.get_commits(&pr) {
        Ok(c) => c,
        Err(_) => vec![],
    };

    if commits.is_empty() {
        // Genesis state - verify by reconstructing from keystore
        let keystore = JsonKeyStore::open(&cli.keystore)?;
        let key = load_key_from_keystore(&keystore, identity)?;
        let principal = cyphrpass::Principal::implicit(key)?;

        // Verify PR matches
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let computed_pr = principal
            .pr()
            .as_multihash()
            .variants()
            .values()
            .next()
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .expect("PrincipalRoot must have at least one variant");
        if computed_pr != identity {
            return Err(format!("PR mismatch: computed {} != {}", computed_pr, identity).into());
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
    let is_implicit_genesis = keystore.get(identity).is_ok();

    let principal = if is_implicit_genesis {
        // Implicit genesis with commits: use keystore key as genesis
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = Genesis::Implicit(genesis_key);
        load_principal_from_commits(genesis, &commits)?
    } else {
        // Explicit genesis: extract from commits
        let genesis = extract_genesis_from_commits(&commits)?;
        load_principal_from_commits(genesis, &commits)?
    };

    // Verify PR matches
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let computed_pr = principal
        .pr()
        .as_multihash()
        .variants()
        .values()
        .next()
        .map(|b| Base64UrlUnpadded::encode_string(b))
        .expect("PrincipalRoot must have at least one variant");
    if computed_pr != identity {
        return Err(format!(
            "PR mismatch: computed {} != expected {}",
            computed_pr, identity
        )
        .into());
    }

    // Verify state digests from commits match computed state
    // Note: Empty commits case is handled above at line 96, but we use
    // defensive pattern here rather than unwrap for robustness.
    let Some(last_commit) = commits.last() else {
        // This branch should be unreachable due to the earlier empty check,
        // but we handle it gracefully rather than panicking.
        return Ok(());
    };
    let computed_ps = principal
        .ps()
        .as_multihash()
        .variants()
        .values()
        .next()
        .map(|b| Base64UrlUnpadded::encode_string(b))
        .expect("PrincipalState must have at least one variant");

    if computed_ps != last_commit.ps {
        return Err(format!(
            "PS mismatch: computed {} != stored {}",
            computed_ps, last_commit.ps
        )
        .into());
    }

    let tx_count: usize = principal.transactions().count();

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
fn load_identity(
    cli: &Cli,
    identity: &str,
) -> Result<cyphrpass::Principal, Box<dyn std::error::Error>> {
    let store = parse_store(&cli.store)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let pr = parse_principal_root(identity)?;

    let commits = match store.get_commits(&pr) {
        Ok(c) => c,
        Err(_) => vec![],
    };

    // Check if identity is in keystore (implicit genesis indicator)
    let is_implicit_genesis = keystore.get(identity).is_ok();

    if commits.is_empty() {
        // Genesis state - reconstruct from keystore
        let key = load_key_from_keystore(&keystore, identity)?;
        Ok(cyphrpass::Principal::implicit(key)?)
    } else if is_implicit_genesis {
        // Has commits + in keystore = implicit genesis with transactions
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = Genesis::Implicit(genesis_key);
        Ok(load_principal_from_commits(genesis, &commits)?)
    } else {
        // Not in keystore = explicit genesis (key embedded in commits)
        let genesis = extract_genesis_from_commits(&commits)?;
        Ok(load_principal_from_commits(genesis, &commits)?)
    }
}

/// Load a cyphrpass Key from keystore by thumbprint.
fn load_key_from_keystore(
    keystore: &JsonKeyStore,
    tmb: &str,
) -> Result<Key, Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};

    use coz::Thumbprint;

    let stored = keystore.get(tmb)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

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
fn extract_genesis_from_commits(
    commits: &[cyphrpass_storage::CommitEntry],
) -> Result<Genesis, Box<dyn std::error::Error>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use coz::Thumbprint;

    let first_commit = commits.first().ok_or("no commits")?;
    let mut genesis_keys = Vec::new();

    for tx_value in &first_commit.txs {
        if let Some(key_obj) = tx_value.get("key") {
            let alg = key_obj
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("missing key.alg")?;
            let pub_b64 = key_obj
                .get("pub")
                .and_then(|v| v.as_str())
                .ok_or("missing key.pub")?;
            let tmb_b64 = key_obj
                .get("tmb")
                .and_then(|v| v.as_str())
                .ok_or("missing key.tmb")?;

            let pub_key =
                Base64UrlUnpadded::decode_vec(pub_b64).map_err(|_| "invalid base64 in key.pub")?;
            let tmb_bytes =
                Base64UrlUnpadded::decode_vec(tmb_b64).map_err(|_| "invalid base64 in key.tmb")?;

            genesis_keys.push(Key {
                alg: alg.to_string(),
                tmb: Thumbprint::from_bytes(tmb_bytes),
                pub_key,
                first_seen: 0,
                last_used: None,
                revocation: None,
                tag: None,
            });
        }
    }

    if genesis_keys.is_empty() {
        return Err("cannot determine genesis keys from storage".into());
    }

    if genesis_keys.len() == 1 {
        Ok(Genesis::Implicit(genesis_keys.remove(0)))
    } else {
        Ok(Genesis::Explicit(genesis_keys))
    }
}

/// Parse the --store argument into a FileStore.
fn parse_store(store_uri: &str) -> Result<FileStore, Box<dyn std::error::Error>> {
    if let Some(path) = store_uri.strip_prefix("file:") {
        Ok(FileStore::new(path))
    } else {
        Err(format!("unsupported store URI: {store_uri}").into())
    }
}

/// Parse a base64url principal root string into a PrincipalRoot.
fn parse_principal_root(s: &str) -> Result<cyphrpass::PrincipalRoot, Box<dyn std::error::Error>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let bytes =
        Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("invalid principal root: {e}"))?;
    Ok(cyphrpass::PrincipalRoot::from_bytes(bytes))
}

/// Decode base64url string to bytes.
fn decode_b64(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("invalid base64url: {e}").into())
}
