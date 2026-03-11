//! Key management commands.

use cyphrpass_storage::{Genesis, export_commits, load_principal_from_commits};
use indexmap::IndexMap;
use serde_json::Value;

use super::common::{
    current_timestamp, extract_genesis_from_commits, generate_key, load_key_from_keystore,
    parse_principal_root, parse_store,
};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, Error, KeyCommands, OutputFormat};

/// Run a key subcommand.
pub fn run(cli: &Cli, command: &KeyCommands) -> crate::Result<()> {
    match command {
        KeyCommands::Generate { algo, tag } => generate(cli, algo, tag.as_deref()),
        KeyCommands::Add {
            identity,
            key,
            signer,
        } => add(cli, identity, key.as_deref(), signer),
        KeyCommands::Revoke {
            identity,
            key,
            signer,
        } => revoke(cli, identity, key, signer),
        KeyCommands::List { identity } => list(cli, identity.as_deref()),
    }
}

/// Generate a new keypair and store it in the keystore.
fn generate(cli: &Cli, algo: &str, tag: Option<&str>) -> crate::Result<()> {
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

    let (tmb, stored_key, _key) = generate_key(algo, tag)?;
    keystore.store(&tmb, stored_key)?;
    keystore.save()?;

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "tmb": tmb,
                "alg": algo,
                "tag": tag,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Generated {algo} key");
            println!("  tmb: {tmb}");
            if let Some(t) = tag {
                println!("  tag: {t}");
            }
            println!("  stored: {}", cli.keystore.display());
        },
    }

    Ok(())
}

/// Add a key to an identity.
fn add(cli: &Cli, identity: &str, key_tmb: Option<&str>, signer_tmb: &str) -> crate::Result<()> {
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Load current principal state
    let commits = store.get_commits(&pr).unwrap_or_default();

    // Detect implicit genesis: if identity (PR) is in keystore, it's an implicit genesis identity
    let is_implicit_genesis = keystore.get(identity).is_ok();

    let mut principal = if commits.is_empty() {
        // Genesis state - reconstruct from keystore
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        cyphrpass::Principal::implicit(genesis_key)?
    } else if is_implicit_genesis {
        // Implicit genesis with commits: use keystore key as genesis
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = Genesis::Implicit(genesis_key);
        load_principal_from_commits(genesis, &commits)?
    } else {
        // Explicit genesis: extract from commits
        let genesis = extract_genesis_from_commits(&commits, None)?;
        load_principal_from_commits(genesis, &commits)?
    };

    // Get or generate the new key
    let (new_key_tmb, new_key) = match key_tmb {
        Some(tmb) => {
            let key = load_key_from_keystore(&keystore, tmb)?;
            (tmb.to_string(), key)
        },
        None => {
            // Generate new key (use same algorithm as signer)
            let signer_stored = keystore.get(signer_tmb)?;
            let (tmb, stored, key) = generate_key(&signer_stored.alg, None)?;
            keystore.store(&tmb, stored)?;
            keystore.save()?;
            (tmb, key)
        },
    };

    // Get signer key for signing
    let signer_stored = keystore.get(signer_tmb)?;

    // Build pay JSON for key/create
    let now = current_timestamp();
    // Get pre (commit state before transaction) in alg:digest format
    let pre = principal.commit_state_tagged()?;

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer_stored.alg.clone()));
    pay_map.insert("commit".to_string(), Value::Bool(true));
    pay_map.insert("id".to_string(), Value::String(new_key_tmb.clone()));
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("pre".to_string(), Value::String(pre));
    pay_map.insert("tmb".to_string(), Value::String(signer_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String("cyphr.me/key/create".to_string()),
    );

    let pay_json = serde_json::to_vec(&pay_map)?;

    // Sign with coz
    let (sig_bytes, cad) = coz::sign_json(
        &pay_json,
        &signer_stored.alg,
        &signer_stored.prv_key,
        &signer_stored.pub_key,
    )
    .ok_or_else(|| Error::Signing("signing failed".into()))?;

    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer_stored.alg)
        .ok_or_else(|| Error::Signing("czd computation failed".into()))?;

    // Apply transaction — verify_and_apply_transaction auto-finalizes as single-tx commit.
    principal.verify_and_apply_transaction(&pay_json, &sig_bytes, czd, Some(new_key.clone()))?;

    // Store updated state
    let new_commits = export_commits(&principal)?;
    // Only append new commits (the ones after current)
    for commit in new_commits.iter().skip(commits.len()) {
        store.append_commit(
            principal.pr().expect("key add requires PR (Level 3+)"),
            commit,
        )?;
    }

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "identity": identity,
                "added_key": new_key_tmb,
                "signed_by": signer_tmb,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Added key to identity");
            println!("  identity: {identity}");
            println!("  key: {new_key_tmb}");
            println!("  signed by: {signer_tmb}");
        },
    }

    Ok(())
}

/// Revoke a key from an identity.
fn revoke(cli: &Cli, identity: &str, key_tmb: &str, signer_tmb: &str) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Load current principal state
    let commits = store.get_commits(&pr).unwrap_or_default();

    // Detect implicit genesis: if identity (PR) is in keystore, it's an implicit genesis identity
    let is_implicit_genesis = keystore.get(identity).is_ok();

    let mut principal = if commits.is_empty() {
        // Genesis state - reconstruct from keystore
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        cyphrpass::Principal::implicit(genesis_key)?
    } else if is_implicit_genesis {
        // Implicit genesis with commits: use keystore key as genesis
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = Genesis::Implicit(genesis_key);
        load_principal_from_commits(genesis, &commits)?
    } else {
        // Explicit genesis: extract from commits
        let genesis = extract_genesis_from_commits(&commits, None)?;
        load_principal_from_commits(genesis, &commits)?
    };

    // Get signer key for signing
    let signer_stored = keystore.get(signer_tmb)?;

    // Build pay JSON for key/revoke
    let now = current_timestamp();
    // Get pre (commit state before transaction) in alg:digest format
    let pre = principal.commit_state_tagged()?;

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer_stored.alg.clone()));
    pay_map.insert("commit".to_string(), Value::Bool(true));
    pay_map.insert("id".to_string(), Value::String(key_tmb.to_string()));
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("pre".to_string(), Value::String(pre));
    pay_map.insert("rvk".to_string(), Value::Number(now.into()));
    pay_map.insert("tmb".to_string(), Value::String(signer_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String("cyphr.me/key/revoke".to_string()),
    );

    let pay_json = serde_json::to_vec(&pay_map)?;

    // Sign with coz
    let (sig_bytes, cad) = coz::sign_json(
        &pay_json,
        &signer_stored.alg,
        &signer_stored.prv_key,
        &signer_stored.pub_key,
    )
    .ok_or_else(|| Error::Signing("signing failed".into()))?;

    let czd = coz::czd_for_alg(&cad, &sig_bytes, &signer_stored.alg)
        .ok_or_else(|| Error::Signing("czd computation failed".into()))?;

    // Apply transaction — verify_and_apply_transaction auto-finalizes as single-tx commit.
    principal.verify_and_apply_transaction(&pay_json, &sig_bytes, czd, None)?;

    // Store updated state
    let new_commits = export_commits(&principal)?;
    for commit in new_commits.iter().skip(commits.len()) {
        store.append_commit(
            principal.pr().expect("key revoke requires PR (Level 3+)"),
            commit,
        )?;
    }

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "identity": identity,
                "revoked_key": key_tmb,
                "signed_by": signer_tmb,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Revoked key from identity");
            println!("  identity: {identity}");
            println!("  key: {key_tmb}");
            println!("  signed by: {signer_tmb}");
        },
    }

    Ok(())
}

/// List keys - from keystore if identity is None, from identity if provided.
fn list(cli: &Cli, identity: Option<&str>) -> crate::Result<()> {
    match identity {
        None => list_keystore(cli),
        Some(pr) => list_identity(cli, pr),
    }
}

/// List all keys in the keystore.
fn list_keystore(cli: &Cli) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let thumbprints = keystore.list();

    if thumbprints.is_empty() {
        match cli.output {
            OutputFormat::Json => println!("[]"),
            OutputFormat::Table => println!("No keys in keystore"),
        }
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let mut keys = Vec::new();
            for tmb in &thumbprints {
                let key = keystore.get(tmb)?;
                keys.push(serde_json::json!({
                    "tmb": tmb,
                    "alg": key.alg,
                    "tag": key.tag,
                }));
            }
            println!("{}", serde_json::to_string_pretty(&keys)?);
        },
        OutputFormat::Table => {
            println!("Keys in keystore:");
            for tmb in thumbprints {
                let key = keystore.get(tmb)?;
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("  {} ({}) [{}]", tmb, key.alg, tag_str);
            }
        },
    }

    Ok(())
}

/// List keys for an identity.
fn list_identity(cli: &Cli, identity: &str) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    let commits = store.get_commits(&pr).unwrap_or_default();

    // Detect implicit genesis: if identity (PR) is in keystore, it's an implicit genesis identity
    let is_implicit_genesis = keystore.get(identity).is_ok();

    let principal = if commits.is_empty() {
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        cyphrpass::Principal::implicit(genesis_key)?
    } else if is_implicit_genesis {
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = Genesis::Implicit(genesis_key);
        load_principal_from_commits(genesis, &commits)?
    } else {
        let genesis = extract_genesis_from_commits(&commits, None)?;
        load_principal_from_commits(genesis, &commits)?
    };

    let active: Vec<_> = principal.active_keys().collect();

    match cli.output {
        OutputFormat::Json => {
            let keys: Vec<_> = active
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "tmb": k.tmb.to_b64(),
                        "alg": k.alg,
                        "tag": k.tag,
                    })
                })
                .collect();
            let output = serde_json::json!({
                "identity": identity,
                "active_keys": keys,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Active keys for {identity}:");
            for key in active {
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("  {} ({}) [{}]", key.tmb.to_b64(), key.alg, tag_str);
            }
        },
    }

    Ok(())
}
