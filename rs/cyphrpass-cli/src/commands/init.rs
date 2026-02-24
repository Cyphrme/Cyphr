//! Identity initialization command.

use cyphrpass::Principal;
use cyphrpass_storage::export_commits;

use super::common::{generate_key, load_key_from_keystore, parse_store};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, Error, OutputFormat};

/// Run the init command.
pub fn run(
    cli: &Cli,
    algo: &str,
    key_tmb: Option<&str>,
    keys_tmb: Option<&[String]>,
) -> crate::Result<()> {
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

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
            let (tmb_str, stored, key) = generate_key(algo, None)?;
            keystore.store(&tmb_str, stored)?;
            keystore.save()?;
            Principal::implicit(key)?
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

    // Get PR for output
    let pr = {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        principal
            .pr()
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| Error::Storage(format!("PR empty: {e}")))?
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
