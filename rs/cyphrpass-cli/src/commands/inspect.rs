//! Identity inspection command.

use cyphrpass::Key;
use cyphrpass_storage::{FileStore, Genesis, load_principal_from_commits};

use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, OutputFormat};

/// Run the inspect command.
pub fn run(cli: &Cli, identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Try to load commits from store
    let commits = match store.get_commits(&pr) {
        Ok(c) => c,
        Err(_) => vec![], // No file exists yet
    };

    let principal = if commits.is_empty() {
        // No commits - try to reconstruct from keystore (genesis state)
        let keystore = JsonKeyStore::open(&cli.keystore)?;
        let key = load_key_from_keystore(&keystore, identity)?;
        cyphrpass::Principal::implicit(key)?
    } else {
        // Load from commits
        let genesis = extract_genesis_from_commits(&commits)?;
        load_principal_from_commits(genesis, &commits)?
    };

    match cli.output {
        OutputFormat::Json => {
            let active_keys: Vec<_> = principal
                .active_keys()
                .map(|k| {
                    serde_json::json!({
                        "tmb": k.tmb.to_b64(),
                        "alg": k.alg,
                        "tag": k.tag,
                        "first_seen": k.first_seen,
                        "last_used": k.last_used,
                    })
                })
                .collect();

            let output = serde_json::json!({
                "pr": principal.pr().as_cad().to_b64(),
                "ps": principal.ps().as_cad().to_b64(),
                "ks": principal.key_state().as_cad().to_b64(),
                "as": principal.auth_state().as_cad().to_b64(),
                "active_keys": active_keys,
                "commit_count": principal.commits().count(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Identity: {}", principal.pr().as_cad().to_b64());
            println!();
            println!("State:");
            println!("  PR: {}", principal.pr().as_cad().to_b64());
            println!("  PS: {}", principal.ps().as_cad().to_b64());
            println!("  KS: {}", principal.key_state().as_cad().to_b64());
            println!("  AS: {}", principal.auth_state().as_cad().to_b64());
            println!();

            let active: Vec<_> = principal.active_keys().collect();

            println!("Active Keys ({}):", active.len());
            for key in active {
                let tag_str = key.tag.as_deref().unwrap_or("-");
                println!("  {} ({}) [{}]", key.tmb.to_b64(), key.alg, tag_str);
            }

            println!();
            println!("Commits: {}", principal.commits().count());
        },
    }

    Ok(())
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
///
/// Looks at the first commit to find the genesis key(s).
fn extract_genesis_from_commits(
    commits: &[cyphrpass_storage::CommitEntry],
) -> Result<Genesis, Box<dyn std::error::Error>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use coz::Thumbprint;

    // For genesis, we need to find the key material in the first commit
    // The key is stored as a separate `key` field on the transaction
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

    // If no key transactions in first commit, this is implicit genesis
    // The PR itself is the key thumbprint
    if genesis_keys.is_empty() {
        return Err("cannot determine genesis keys from storage (no key material found)".into());
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
        Err(format!("unsupported store URI: {store_uri} (expected file:<path>)").into())
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
