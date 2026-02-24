//! Identity initialization command.

use std::time::{SystemTime, UNIX_EPOCH};

use coz::Thumbprint;
use cyphrpass::{Key, Principal};
use cyphrpass_storage::export_commits;

use super::common::{decode_b64, load_key_from_keystore, parse_store};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, OutputFormat};

/// Run the init command.
pub fn run(
    cli: &Cli,
    algo: &str,
    key_tmb: Option<&str>,
    keys_tmb: Option<&[String]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;

    // Determine which genesis path to use
    let principal = match (key_tmb, keys_tmb) {
        // Explicit genesis with multiple keys
        (None, Some(tmbs)) if !tmbs.is_empty() => {
            let keys = tmbs
                .iter()
                .map(|tmb| load_key_from_keystore(&keystore, tmb))
                .collect::<Result<Vec<_>, _>>()?;
            Principal::explicit(keys)?
        },

        // Implicit genesis with existing key
        (Some(tmb), None) => {
            let key = load_key_from_keystore(&keystore, tmb)?;
            Principal::implicit(key)?
        },

        // Generate new key and use implicit genesis
        (None, None) => {
            let key = generate_and_store_key(cli, algo)?;
            Principal::implicit(key)?
        },

        // Conflicting options
        (Some(_), Some(_)) => {
            return Err("cannot specify both --key and --keys".into());
        },

        // Empty explicit list
        (None, Some(_)) => {
            return Err("--keys requires at least one thumbprint".into());
        },
    };

    // Get PR for output
    let pr = {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        principal
            .pr()
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| format!("PR empty: {e}"))?
    };

    // Store the identity
    let store = parse_store(&cli.store)?;
    let commits = export_commits(&principal)?;
    for commit in &commits {
        store.append_commit(principal.pr(), commit)?;
    }

    // Output result
    match cli.output {
        OutputFormat::Json => {
            let keys: Vec<_> = principal.active_keys().map(|k| k.tmb.to_b64()).collect();
            let output = serde_json::json!({
                "pr": pr,
                "keys": keys,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Created identity");
            println!("  pr: {pr}");
            println!("  keys:");
            for key in principal.active_keys() {
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("    {} ({}) [{}]", key.tmb.to_b64(), key.alg, tag_str);
            }
            println!("  stored: {}", cli.store);
        },
    }

    Ok(())
}

/// Generate a new key, store it in keystore, and return as cyphrpass Key.
fn generate_and_store_key(cli: &Cli, algo: &str) -> Result<Key, Box<dyn std::error::Error>> {
    use coz::{ES256, ES384, ES512, Ed25519, SigningKey};

    use crate::keystore::StoredKey;

    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

    let (tmb_str, pub_key, prv_key) = match algo {
        "ES256" => {
            let key = SigningKey::<ES256>::generate();
            (
                key.thumbprint().to_b64(),
                key.verifying_key().public_key_bytes().to_vec(),
                key.private_key_bytes(),
            )
        },
        "ES384" => {
            let key = SigningKey::<ES384>::generate();
            (
                key.thumbprint().to_b64(),
                key.verifying_key().public_key_bytes().to_vec(),
                key.private_key_bytes(),
            )
        },
        "ES512" => {
            let key = SigningKey::<ES512>::generate();
            (
                key.thumbprint().to_b64(),
                key.verifying_key().public_key_bytes().to_vec(),
                key.private_key_bytes(),
            )
        },
        "Ed25519" => {
            let key = SigningKey::<Ed25519>::generate();
            (
                key.thumbprint().to_b64(),
                key.verifying_key().public_key_bytes().to_vec(),
                key.private_key_bytes(),
            )
        },
        _ => return Err(format!("unknown algorithm: {algo}").into()),
    };

    let stored = StoredKey {
        alg: algo.to_string(),
        pub_key: pub_key.clone(),
        prv_key,
        tag: None,
    };
    keystore.store(&tmb_str, stored)?;
    keystore.save()?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    Ok(Key {
        alg: algo.to_string(),
        tmb: Thumbprint::from_bytes(decode_b64(&tmb_str)?),
        pub_key,
        first_seen: now,
        last_used: None,
        revocation: None,
        tag: None,
    })
}
