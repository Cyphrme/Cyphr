//! Key management commands.

use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphrpass::Key;
use cyphrpass_storage::{FileStore, Genesis, export_commits, load_principal_from_commits};
use indexmap::IndexMap;
use serde_json::Value;

use crate::keystore::{JsonKeyStore, KeyStore, StoredKey};
use crate::{Cli, KeyCommands, OutputFormat};

/// Run a key subcommand.
pub fn run(cli: &Cli, command: &KeyCommands) -> Result<(), Box<dyn std::error::Error>> {
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
fn generate(cli: &Cli, algo: &str, tag: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    use coz::{ES256, ES384, ES512, Ed25519, SigningKey};

    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

    // Generate keypair based on algorithm
    let (tmb, stored_key) = match algo {
        "ES256" => {
            let key = SigningKey::<ES256>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: tag.map(String::from),
            };
            (tmb, stored)
        },
        "ES384" => {
            let key = SigningKey::<ES384>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: tag.map(String::from),
            };
            (tmb, stored)
        },
        "ES512" => {
            let key = SigningKey::<ES512>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: tag.map(String::from),
            };
            (tmb, stored)
        },
        "Ed25519" => {
            let key = SigningKey::<Ed25519>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: tag.map(String::from),
            };
            (tmb, stored)
        },
        _ => {
            return Err(format!("unknown algorithm: {algo}").into());
        },
    };

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
fn add(
    cli: &Cli,
    identity: &str,
    key_tmb: Option<&str>,
    signer_tmb: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
        let genesis = extract_genesis_from_commits(&commits)?;
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
            let (tmb, stored, key) = generate_key_for_add(&signer_stored.alg)?;
            keystore.store(&tmb, stored)?;
            keystore.save()?;
            (tmb, key)
        },
    };

    // Get signer key for signing
    let signer_stored = keystore.get(signer_tmb)?;

    // Build pay JSON for key/create
    let now = current_timestamp();
    // Get pre (auth state before transaction) in alg:digest format
    let pre = principal.auth_state_tagged();

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
    .ok_or("signing failed")?;

    let czd =
        coz::czd_for_alg(&cad, &sig_bytes, &signer_stored.alg).ok_or("czd computation failed")?;

    // Apply transaction to principal (auto-finalizes due to commit: true)
    principal.verify_and_apply_transaction(&pay_json, &sig_bytes, czd, Some(new_key.clone()))?;

    // Store updated state
    let new_commits = export_commits(&principal);
    // Only append new commits (the ones after current)
    for commit in new_commits.iter().skip(commits.len()) {
        store.append_commit(principal.pr(), commit)?;
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
fn revoke(
    cli: &Cli,
    identity: &str,
    key_tmb: &str,
    signer_tmb: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
        let genesis = extract_genesis_from_commits(&commits)?;
        load_principal_from_commits(genesis, &commits)?
    };

    // Get signer key for signing
    let signer_stored = keystore.get(signer_tmb)?;

    // Build pay JSON for key/revoke
    let now = current_timestamp();
    // Get pre (auth state before transaction) in alg:digest format
    let pre = principal.auth_state_tagged();

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
    .ok_or("signing failed")?;

    let czd =
        coz::czd_for_alg(&cad, &sig_bytes, &signer_stored.alg).ok_or("czd computation failed")?;

    // Apply transaction to principal (auto-finalizes due to commit: true)
    principal.verify_and_apply_transaction(&pay_json, &sig_bytes, czd, None)?;

    // Store updated state
    let new_commits = export_commits(&principal);
    for commit in new_commits.iter().skip(commits.len()) {
        store.append_commit(principal.pr(), commit)?;
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
fn list(cli: &Cli, identity: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    match identity {
        None => list_keystore(cli),
        Some(pr) => list_identity(cli, pr),
    }
}

/// List all keys in the keystore.
fn list_keystore(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
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
            let keys: Vec<_> = thumbprints
                .iter()
                .map(|tmb| {
                    let key = keystore.get(tmb).unwrap();
                    serde_json::json!({
                        "tmb": tmb,
                        "alg": key.alg,
                        "tag": key.tag,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&keys)?);
        },
        OutputFormat::Table => {
            println!("Keys in keystore:");
            for tmb in thumbprints {
                let key = keystore.get(tmb).unwrap();
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("  {} ({}) [{}]", tmb, key.alg, tag_str);
            }
        },
    }

    Ok(())
}

/// List keys for an identity.
fn list_identity(cli: &Cli, identity: &str) -> Result<(), Box<dyn std::error::Error>> {
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
        let genesis = extract_genesis_from_commits(&commits)?;
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

// ============================================================================
// Helpers
// ============================================================================

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_key_for_add(
    algo: &str,
) -> Result<(String, StoredKey, Key), Box<dyn std::error::Error>> {
    use coz::{ES256, ES384, ES512, Ed25519, SigningKey};

    let now = current_timestamp();

    match algo {
        "ES256" => {
            let key = SigningKey::<ES256>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: None,
            };
            let cyphrpass_key = Key {
                alg: algo.to_string(),
                tmb: Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(&tmb)?),
                pub_key: stored.pub_key.clone(),
                first_seen: now,
                last_used: None,
                revocation: None,
                tag: None,
            };
            Ok((tmb, stored, cyphrpass_key))
        },
        "ES384" => {
            let key = SigningKey::<ES384>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: None,
            };
            let cyphrpass_key = Key {
                alg: algo.to_string(),
                tmb: Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(&tmb)?),
                pub_key: stored.pub_key.clone(),
                first_seen: now,
                last_used: None,
                revocation: None,
                tag: None,
            };
            Ok((tmb, stored, cyphrpass_key))
        },
        "ES512" => {
            let key = SigningKey::<ES512>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: None,
            };
            let cyphrpass_key = Key {
                alg: algo.to_string(),
                tmb: Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(&tmb)?),
                pub_key: stored.pub_key.clone(),
                first_seen: now,
                last_used: None,
                revocation: None,
                tag: None,
            };
            Ok((tmb, stored, cyphrpass_key))
        },
        "Ed25519" => {
            let key = SigningKey::<Ed25519>::generate();
            let tmb = key.thumbprint().to_b64();
            let stored = StoredKey {
                alg: algo.to_string(),
                pub_key: key.verifying_key().public_key_bytes().to_vec(),
                prv_key: key.private_key_bytes(),
                tag: None,
            };
            let cyphrpass_key = Key {
                alg: algo.to_string(),
                tmb: Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(&tmb)?),
                pub_key: stored.pub_key.clone(),
                first_seen: now,
                last_used: None,
                revocation: None,
                tag: None,
            };
            Ok((tmb, stored, cyphrpass_key))
        },
        _ => Err(format!("unknown algorithm: {algo}").into()),
    }
}

fn load_key_from_keystore(
    keystore: &JsonKeyStore,
    tmb: &str,
) -> Result<Key, Box<dyn std::error::Error>> {
    let stored = keystore.get(tmb)?;
    let now = current_timestamp();

    Ok(Key {
        alg: stored.alg.clone(),
        tmb: Thumbprint::from_bytes(Base64UrlUnpadded::decode_vec(tmb)?),
        pub_key: stored.pub_key.clone(),
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: stored.tag.clone(),
    })
}

fn extract_genesis_from_commits(
    commits: &[cyphrpass_storage::CommitEntry],
) -> Result<Genesis, Box<dyn std::error::Error>> {
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

fn parse_store(store_uri: &str) -> Result<FileStore, Box<dyn std::error::Error>> {
    if let Some(path) = store_uri.strip_prefix("file:") {
        Ok(FileStore::new(path))
    } else {
        Err(format!("unsupported store URI: {store_uri}").into())
    }
}

fn parse_principal_root(s: &str) -> Result<cyphrpass::PrincipalRoot, Box<dyn std::error::Error>> {
    let bytes =
        Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("invalid principal root: {e}"))?;
    Ok(cyphrpass::PrincipalRoot::from_bytes(bytes))
}
