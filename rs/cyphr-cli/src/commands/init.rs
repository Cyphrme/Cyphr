//! Identity initialization command.

use cyphr::{Principal, StateDigest};

use super::common::{
    current_timestamp, decode_b64, generate_key, get_principal_id_from_principal,
    load_key_from_keystore, parse_store, save_principal_to_engine,
};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, Error, OutputFormat};

/// Commit the principal's genesis (SPEC 5.1, 5.2, 5.3) if it has none:
/// the genesis key (the first) signs a `key/create` for itself and for each
/// further genesis key, the `principal/create` and the commit transaction.
/// Every commit chain begins with this commit, so it precedes the first
/// commit any command makes.
pub(crate) fn commit_genesis<S: cyphr::eml::Storage>(
    principal: &mut Principal<S>,
    keystore: &JsonKeyStore,
    authority: &str,
) -> crate::Result<()> {
    if principal.pg().is_some() {
        return Ok(());
    }
    let genesis = principal
        .genesis_keys()
        .first()
        .cloned()
        .ok_or_else(|| Error::InvalidArgument("genesis has no key".into()))?;
    let signer = keystore.get(&genesis)?;
    let tmb = coz::Thumbprint::from_bytes(decode_b64(&genesis)?);
    let software =
        cyphr::signer::SoftwareSigner::new(&signer.alg, &signer.prv_key, &signer.pub_key, &tmb);
    principal.commit_genesis(&software, current_timestamp(), authority)?;
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

    // Determine which genesis path to use
    let mut principal = match (key_tmb, keys_tmb) {
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

    if genesis_commit {
        commit_genesis(&mut principal, &keystore, &cli.authority)?;
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

    // Explicit multi-key genesis has no key of its own equal to its
    // identity digest (unlike implicit genesis, where identity == the sole
    // key's thumbprint), and it produces no commit -- and thus no stored
    // tip -- until some later operation happens. Without a local record of
    // which keys compose it, it would be unrecoverable to any subsequent
    // command in this same store/keystore, including the very `key add`
    // that would otherwise anchor it in storage.
    if principal.genesis_keys().len() > 1 {
        let principal_id = get_principal_id_from_principal(&principal, &keystore)?;
        let key_tmbs = principal.active_keys().map(|k| k.tmb().to_b64()).collect();
        keystore.record_genesis(&principal_id, key_tmbs)?;
    }

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
