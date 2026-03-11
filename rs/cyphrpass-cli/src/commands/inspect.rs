//! Identity inspection command.

use cyphrpass_storage::load_principal_from_commits;

use super::common::{
    extract_genesis_from_commits, load_key_from_keystore, parse_principal_root, parse_store,
};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, OutputFormat};

/// Run the inspect command.
pub fn run(cli: &Cli, identity: &str) -> crate::Result<()> {
    let store = parse_store(&cli.store)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let pr = parse_principal_root(identity)?;

    // Try to load commits from store
    let commits = store.get_commits(&pr).unwrap_or_default();

    // Check if identity is in keystore (implicit genesis indicator)
    let is_implicit_genesis = keystore.get(identity).is_ok();

    let principal = if commits.is_empty() {
        // No commits - try to reconstruct from keystore (genesis state)
        let key = load_key_from_keystore(&keystore, identity)?;
        cyphrpass::Principal::implicit(key)?
    } else if is_implicit_genesis {
        // Has commits + in keystore = implicit genesis with transactions
        let genesis_key = load_key_from_keystore(&keystore, identity)?;
        let genesis = cyphrpass_storage::Genesis::Implicit(genesis_key);
        load_principal_from_commits(genesis, &commits)?
    } else {
        // Not in keystore = explicit genesis (key embedded in commits)
        let genesis = extract_genesis_from_commits(&commits, None)?;
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
                "pr": format_pr(&principal),
                "ps": format_ps(&principal),
                "ks": format_ks(&principal),
                "as": format_as(&principal),
                "active_keys": active_keys,
                "commit_count": principal.commits().count(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        },
        OutputFormat::Table => {
            println!("Identity: {}", format_pr(&principal));
            println!();
            println!("State:");
            println!("  PR: {}", format_pr(&principal));
            println!("  PS: {}", format_ps(&principal));
            println!("  KS: {}", format_ks(&principal));
            println!("  AS: {}", format_as(&principal));
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

// ============================================================================
// Display helpers (unique to inspect)
// ============================================================================

/// Format KeyState for display.
fn format_ks(principal: &cyphrpass::Principal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let ks = principal.key_state();
    let hash_alg = principal.hash_alg();

    ks.get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format AuthState for display.
fn format_as(principal: &cyphrpass::Principal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let auth_state = principal.auth_state();
    let hash_alg = principal.hash_alg();

    auth_state
        .get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format PrincipalState for display.
fn format_ps(principal: &cyphrpass::Principal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let ps = principal.ps();
    let hash_alg = principal.hash_alg();

    ps.get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format PrincipalRoot for display.
fn format_pr(principal: &cyphrpass::Principal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let hash_alg = principal.hash_alg();

    principal
        .pr()
        .and_then(|pr| pr.get(hash_alg))
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<none>".to_string())
}
