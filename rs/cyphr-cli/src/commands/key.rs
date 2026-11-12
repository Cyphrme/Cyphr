use base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::Signer;
use indexmap::IndexMap;
use serde_json::Value;

use super::common::{
    CliPrincipal, block_on, current_timestamp, generate_key, load_key_from_keystore,
    load_principal_from_engine, parse_store, save_principal_to_engine,
};
use crate::keystore::KeyBackend;
use crate::net::Peer;
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
        KeyCommands::Delete {
            identity,
            key,
            signer,
        } => delete(cli, identity, key, signer, &cli.authority),
        KeyCommands::Replace {
            identity,
            key,
            signer,
        } => replace(cli, identity, key.as_deref(), signer, &cli.authority),
        KeyCommands::NakedRevoke { key, msg, peer } => {
            naked_revoke(cli, key, msg.as_deref(), peer)
        },
        KeyCommands::List { identity } => list(cli, identity.as_deref()),
    }
}

/// Generate a new keypair and store it in the keystore.
fn generate(cli: &Cli, algo: &str, tag: Option<&str>) -> crate::Result<()> {
    let mut keystore = super::common::open_backend(cli)?;

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
    let mut keystore = super::common::open_backend(cli)?;
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
    let keystore = super::common::open_backend(cli)?;
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

/// Remove a key from an identity without marking it compromised.
fn delete(
    cli: &Cli,
    identity: &str,
    key_tmb: &str,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    let keystore = super::common::open_backend(cli)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;

    apply_key_delete(&mut principal, &keystore, key_tmb, signer_tmb, authority)?;
    save_principal_to_engine(&store, &keystore, &principal)?;

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "identity": identity,
                "deleted_key": key_tmb,
                "signed_by": signer_tmb,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Deleted key from identity");
            println!("  identity: {identity}");
            println!("  key: {key_tmb}");
            println!("  signed by: {signer_tmb}");
        },
    }
    Ok(())
}

/// Swap the signing key for a new one in one commit.
fn replace(
    cli: &Cli,
    identity: &str,
    key_tmb: Option<&str>,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    let mut keystore = super::common::open_backend(cli)?;
    let store = parse_store(cli)?;
    let mut principal = load_principal_from_engine(&store, &keystore, identity)?;

    let (new_key_tmb, new_key) = match key_tmb {
        Some(tmb) => (tmb.to_string(), load_key_from_keystore(&keystore, tmb)?),
        None => {
            let signer_alg = keystore.public(signer_tmb)?.alg;
            generate_key(&mut keystore, &signer_alg, None)?
        },
    };

    apply_key_replace(
        &mut principal,
        &keystore,
        &new_key_tmb,
        &new_key,
        signer_tmb,
        authority,
    )?;
    save_principal_to_engine(&store, &keystore, &principal)?;

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "identity": identity,
                "replaced_key": signer_tmb,
                "new_key": new_key_tmb,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Replaced key of identity");
            println!("  identity: {identity}");
            println!("  old key: {signer_tmb}");
            println!("  new key: {new_key_tmb}");
        },
    }
    Ok(())
}

/// Sign a naked revoke (SPEC 6.4) with the key itself, outside any commit,
/// and send it to each `--peer`. It names no principal and mutates no chain:
/// a peer records the key as dead, and further use of it is refused.
fn naked_revoke(cli: &Cli, key_tmb: &str, msg: Option<&str>, peers: &[String]) -> crate::Result<()> {
    let keystore = super::common::open_backend(cli)?;
    let signer = keystore.signer(key_tmb)?;
    let public = keystore.public(key_tmb)?;
    let now = current_timestamp();

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer.alg().to_string()));
    if let Some(m) = msg {
        pay_map.insert("msg".to_string(), Value::String(m.to_string()));
    }
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("rvk".to_string(), Value::Number(now.into()));
    pay_map.insert("tmb".to_string(), Value::String(key_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String(format!(
            "{}/{}",
            cli.authority,
            cyphr::parsed_coz::typ::KEY_REVOKE
        )),
    );
    let pay = serde_json::to_value(&pay_map)?;
    let (sig, _czd) = super::common::sign_pay(&signer, &serde_json::to_vec(&pay)?)?;
    let envelope = serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {
            "alg": public.alg,
            "pub": Base64UrlUnpadded::encode_string(&public.pub_key),
        },
    });

    for url in peers {
        let peer = Peer::new(url, cli.peer_timeout_secs, cli.allow_cleartext)?;
        block_on(peer.post_revoke(&envelope))??;
    }

    match cli.output {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "revoked_key": key_tmb,
                "peers": peers,
                "revoke": envelope,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Signed a naked revoke of {key_tmb}");
            for url in peers {
                println!("  accepted by: {url}");
            }
        },
    }
    Ok(())
}

/// Commit one key transaction signed by `signer_tmb` onto `principal`:
/// the pay is built from `typ` and `fields`, verified and applied inside one
/// `CommitScope`, and finalized as one commit. `new_key` is the public half
/// a `key/create` or `key/replace` introduces.
fn commit_key_tx(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    signer_tmb: &str,
    authority: &str,
    typ: &str,
    fields: &[(&str, Value)],
    new_key: Option<cyphr::Key>,
) -> crate::Result<()> {
    super::init::commit_genesis(principal, keystore, &[], authority)?;
    let signer = keystore.signer(signer_tmb)?;
    let now = current_timestamp();

    let mut pay_map: IndexMap<String, Value> = IndexMap::new();
    pay_map.insert("alg".to_string(), Value::String(signer.alg().to_string()));
    for (name, value) in fields {
        pay_map.insert((*name).to_string(), value.clone());
    }
    pay_map.insert("now".to_string(), Value::Number(now.into()));
    pay_map.insert("tmb".to_string(), Value::String(signer_tmb.to_string()));
    pay_map.insert(
        "typ".to_string(),
        Value::String(format!("{authority}/{typ}")),
    );

    // The signed bytes are the pay as written, so its field order must be the
    // one the verifier reconstructs: alphabetical, as every other pay is.
    pay_map.sort_keys();
    let pay_vec = serde_json::to_vec(&serde_json::to_value(&pay_map)?)?;
    let (sig_bytes, czd) = super::common::sign_pay(&signer, &pay_vec)?;
    let mut scope = principal.begin_commit();
    scope.verify_and_apply(&pay_vec, &sig_bytes, czd, new_key)?;
    block_on(scope.finalize_with_signer(&signer, now, authority))??;
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
    commit_key_tx(
        principal,
        keystore,
        signer_tmb,
        authority,
        cyphr::parsed_coz::typ::KEY_CREATE,
        &[("id", Value::String(new_key_tmb.to_string()))],
        Some(new_key.clone()),
    )
}

/// Commit one `key/delete` (SPEC 6.2) of `key_tmb`, signed by `signer_tmb`,
/// onto `principal`. Shared by `key delete` and rebase replay.
pub(crate) fn apply_key_delete(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    key_tmb: &str,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    commit_key_tx(
        principal,
        keystore,
        signer_tmb,
        authority,
        cyphr::parsed_coz::typ::KEY_DELETE,
        &[("id", Value::String(key_tmb.to_string()))],
        None,
    )
}

/// Commit one `key/replace` (SPEC 6.3): `signer_tmb` is swapped for
/// `new_key` (thumbprint `new_key_tmb`) atomically. Shared by `key replace`
/// and rebase replay.
pub(crate) fn apply_key_replace(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    new_key_tmb: &str,
    new_key: &cyphr::Key,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    commit_key_tx(
        principal,
        keystore,
        signer_tmb,
        authority,
        cyphr::parsed_coz::typ::KEY_REPLACE,
        &[("id", Value::String(new_key_tmb.to_string()))],
        Some(new_key.clone()),
    )
}

/// Commit one self-`key/revoke` of `signer_tmb` onto `principal`: the
/// standard revoke of SPEC 6.4, signed by the key itself inside a commit.
/// Shared by `key revoke` and rebase replay.
pub(crate) fn apply_key_revoke(
    principal: &mut CliPrincipal,
    keystore: &impl KeyBackend,
    key_tmb: &str,
    signer_tmb: &str,
    authority: &str,
) -> crate::Result<()> {
    // A commit-carried revoke is self-signed: the key being revoked must be
    // the signer. Revoking a key you do not hold is the naked revoke's
    // job (`key naked-revoke`), which the key's own holder signs.
    if key_tmb != signer_tmb {
        return Err(crate::Error::InvalidArgument(
            "key revoke is signed by the key itself: --key must equal --signer \
             (to remove another key use `key delete`)"
                .into(),
        ));
    }
    // `id` MUST be absent for a self-revoke; its presence is rejected at
    // parse time.
    let rvk = Value::Number(current_timestamp().into());
    commit_key_tx(
        principal,
        keystore,
        signer_tmb,
        authority,
        cyphr::parsed_coz::typ::KEY_REVOKE,
        &[("rvk", rvk)],
        None,
    )
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
    let keystore = super::common::open_backend(cli)?;
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
    let keystore = super::common::open_backend(cli)?;
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
