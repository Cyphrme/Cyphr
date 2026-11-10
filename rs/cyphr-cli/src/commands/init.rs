//! Identity initialization command.

use cyphr::{Principal, StateDigest};

use super::common::{
    current_timestamp, decode_b64, generate_key, load_key_from_keystore, parse_store,
    save_principal_to_engine,
};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, Error, OutputFormat};

/// Commit the principal's genesis (SPEC 5.1, 5.2, 5.3) if it has none:
/// the genesis key signs a `key/create` for itself and for each of
/// `others`, the `principal/create` and the commit transaction. Every
/// commit chain begins with this commit, so it precedes the first commit
/// any command makes.
pub(crate) fn commit_genesis<S: cyphr::eml::Storage>(
    principal: &mut Principal<S>,
    keystore: &JsonKeyStore,
    others: &[cyphr::Key],
    authority: &str,
) -> crate::Result<()> {
    if principal.pg().is_some() {
        return Ok(());
    }
    let genesis = principal.genesis_key();
    let signer = keystore.get(genesis)?;
    let tmb = coz::Thumbprint::from_bytes(decode_b64(genesis)?);
    let software =
        cyphr::signer::SoftwareSigner::new(&signer.alg, &signer.prv_key, &signer.pub_key, &tmb);
    principal.commit_genesis(&software, others, current_timestamp(), authority)?;
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
    let mut keystore = JsonKeyStore::open(&cli.keystore)?;

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
            let (tmb_str, stored, key) = generate_key(algo, None)?;
            keystore.store(&tmb_str, stored)?;
            keystore.save()?;
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

    let mut principal = Principal::implicit(genesis)?;
    // A multi-key principal is Level 3+, which exists only through its
    // genesis commit (SPEC 5.1), so `--keys` with further keys commits it.
    if genesis_commit || !others.is_empty() {
        commit_genesis(&mut principal, &keystore, &others, &cli.authority)?;
    }

    // Get identity string for output: PG if available, else PR
    let identity_str = {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        if let Some(pg) = principal.pg() {
            pg.as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)?
        } else {
            principal
                .pr()
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)?
        }
    };

    // Store the identity
    let store = parse_store(cli)?;
    save_principal_to_engine(&store, &keystore, &principal)?;

    // Output result
    match cli.output {
        OutputFormat::Json => {
            let keys: Vec<_> = principal.active_keys().map(|k| k.tmb().to_b64()).collect();
            let output = serde_json::json!({
                "pr": identity_str,
                "keys": keys,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Created identity");
            println!("  pr: {identity_str}");
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
