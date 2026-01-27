//! Key management commands.

use crate::keystore::{JsonKeyStore, KeyStore, StoredKey};
use crate::{Cli, KeyCommands, OutputFormat};
use coz::{ES256, ES384, ES512, Ed25519, SigningKey};

/// Run a key subcommand.
pub fn run(cli: &Cli, command: &KeyCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        KeyCommands::Generate { algo, tag } => generate(cli, algo, tag.as_deref()),
        KeyCommands::Add {
            identity,
            key,
            signer,
        } => add(cli, identity, key, signer),
        KeyCommands::Revoke {
            identity,
            key,
            signer,
        } => revoke(cli, identity, key, signer),
        KeyCommands::List { identity } => list(cli, identity),
    }
}

/// Generate a new keypair and store it in the keystore.
fn generate(cli: &Cli, algo: &str, tag: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
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

fn add(
    _cli: &Cli,
    _identity: &str,
    _key: &str,
    _signer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key add: not yet implemented");
    Ok(())
}

fn revoke(
    _cli: &Cli,
    _identity: &str,
    _key: &str,
    _signer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key revoke: not yet implemented");
    Ok(())
}

fn list(_cli: &Cli, _identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key list: not yet implemented");
    Ok(())
}
