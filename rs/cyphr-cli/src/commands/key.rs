use cyphr::signer::Signer;
use indexmap::IndexMap;
use serde_json::Value;

use super::common::{
    CliPrincipal, block_on, current_timestamp, generate_key, load_key_from_keystore,
    load_principal_from_engine, parse_store, save_principal_to_engine,
};
use crate::keystore::{JsonKeyStore, KeyBackend};
use crate::{Cli, KeyCommands, OutputFormat};

/// Run a key subcommand.
pub fn run(cli: &Cli, command: &KeyCommands) -> crate::Result<()> {
    match command {
        KeyCommands::Generate { algo, tag } => generate(cli, algo, tag.as_deref()),
        KeyCommands::Add {
            identity,
            key,
            signer,
        } => add(cli, identity, key.as_deref(), signer, &cli.authority),
        KeyCommands::Revoke {
            identity,
            key,
            signer,
        } => revoke(cli, identity, key, signer, &cli.authority),
        KeyCommands::List { identity } => list(cli, identity.as_deref()),
    }
}

/// Generate a new keypair and store it in the keystore.
fn generate(cli: &Cli, algo: &str, tag: Option<&str>) -> crate::Result<()> {
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

    let (tmb, _key) = generate_key(&mut keystore, algo, tag)?;

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
    authority: &str,
) -> crate::Result<()> {
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;

    // Get or generate the new key
    let (new_key_tmb, new_key) = match key_tmb {
        Some(tmb) => {
            let key = load_key_from_keystore(&keystore, tmb)?;
            (tmb.to_string(), key)
        },
        None => {
            // Generate new key (use same algorithm as signer)
            let signer_alg = keystore.public(signer_tmb)?.alg;
            let (tmb, key) = generate_key(&mut keystore, &signer_alg, None)?;
            (tmb, key)
        },
    };

    apply_key_create(
        &mut principal,
        &keystore,
        &new_key_tmb,
        &new_key,
        signer_tmb,
        authority,
    )?;

    // Store updated state
    save_principal_to_engine(&store, &keystore, &principal)?;

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
    authority: &str,
) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;

    apply_key_revoke(&mut principal, &keystore, key_tmb, signer_tmb, authority)?;

    // Store updated state
    save_principal_to_engine(&store, &keystore, &principal)?;

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

/// Commit one `key/create` of `new_key` (thumbprint `new_key_tmb`), signed
/// by `signer_tmb`, onto `principal`. Shared by `key add` and rebase replay.
pub(crate) fn apply_key_create(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    new_key_tmb: &str,
    new_key: &cyphr::Key,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    super::init::commit_genesis(principal, keystore, &[], authority)?;
    let signer = keystore.signer(signer_tmb)?;

    // Build pay Value for key/create (without commit — finalize_with_commit injects it)
    let now = current_timestamp();

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer.alg().to_string()));
    pay_map.insert("id".to_string(), Value::String(new_key_tmb.to_string()));
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("tmb".to_string(), Value::String(signer_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String(format!(
            "{}/{}",
            authority,
            cyphr::parsed_coz::typ::KEY_CREATE
        )),
    );

    let pay_value: Value = serde_json::to_value(&pay_map)?;

    // Use CommitScope to atomically compute CS, inject commit field, sign, and finalize.
    let pay_vec = serde_json::to_vec(&pay_value)?;
    let (sig_bytes, czd) = super::common::sign_pay(&signer, &pay_vec)?;
    let mut scope = principal.begin_commit();
    scope.verify_and_apply(&pay_vec, &sig_bytes, czd, Some(new_key.clone()))?;
    block_on(scope.finalize_with_signer(&signer, now, authority))??;
    Ok(())
}

/// Commit one self-`key/revoke` of `signer_tmb` onto `principal`. Shared by
/// `key revoke` and rebase replay.
pub(crate) fn apply_key_revoke(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    key_tmb: &str,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    super::init::commit_genesis(principal, keystore, &[], authority)?;
    let signer = keystore.signer(signer_tmb)?;

    // Self-revoke is the only revoke type the protocol supports (SPEC §3.2).
    // The key being revoked must be the signer itself.
    if key_tmb != signer_tmb {
        return Err(crate::Error::InvalidArgument(
            "key revoke only supports self-revoke: --key must equal --signer".into(),
        ));
    }

    // Build pay Value for key/revoke. `id` MUST be absent for self-revoke;
    // its presence is rejected at parse time.
    let now = current_timestamp();

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer.alg().to_string()));
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("rvk".to_string(), Value::Number(now.into()));
    pay_map.insert("tmb".to_string(), Value::String(signer_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String(format!(
            "{}/{}",
            authority,
            cyphr::parsed_coz::typ::KEY_REVOKE
        )),
    );

    let pay_value: Value = serde_json::to_value(&pay_map)?;

    // Use CommitScope to atomically compute CS, inject commit field, sign, and finalize.
    let pay_vec = serde_json::to_vec(&pay_value)?;
    let (sig_bytes, czd) = super::common::sign_pay(&signer, &pay_vec)?;
    let mut scope = principal.begin_commit();
    scope.verify_and_apply(&pay_vec, &sig_bytes, czd, None)?;
    block_on(scope.finalize_with_signer(&signer, now, authority))??;
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
    let keys = keystore.list()?;

    if keys.is_empty() {
        match cli.output {
            OutputFormat::Json => println!("[]"),
            OutputFormat::Table => println!("No keys in keystore"),
        }
        return Ok(());
    }

    match cli.output {
        OutputFormat::Json => {
            let keys: Vec<_> = keys
                .iter()
                .map(|key| {
                    serde_json::json!({
                        "tmb": key.tmb,
                        "alg": key.alg,
                        "tag": key.tag,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&keys)?);
        },
        OutputFormat::Table => {
            println!("Keys in keystore:");
            for key in keys {
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("  {} ({}) [{}]", key.tmb, key.alg, tag_str);
            }
        },
    }

    Ok(())
}

/// List keys for an identity.
fn list_identity(cli: &Cli, identity: &str) -> crate::Result<()> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(cli)?;
    let principal = load_principal_from_engine(&store, &keystore, identity)?;

    let active: Vec<_> = principal.active_keys().collect();

    match cli.output {
        OutputFormat::Json => {
            let keys: Vec<_> = active
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "tmb": k.tmb().to_b64(),
                        "alg": k.alg(),
                        "tag": k.tag(),
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
                let tag_str = key.tag().unwrap_or("-");
                println!("  {} ({}) [{}]", key.tmb().to_b64(), key.alg(), tag_str);
            }
        },
    }

    Ok(())
}
