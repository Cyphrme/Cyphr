//! Identity inspection command.

use cyphr::StateDigest;

use super::common::{CliPrincipal, load_principal_from_engine, parse_store};
use crate::keystore::JsonKeyStore;
use crate::{Cli, OutputFormat};

/// Run the inspect command.
pub fn run(cli: &Cli, identity: &str) -> crate::Result<()> {
    let store = parse_store(cli)?;
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let principal = load_principal_from_engine(&store, &keystore, identity)?;

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

/// Format KeyRoot for display.
fn format_ks(principal: &CliPrincipal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let ks = principal.key_root();
    let hash_alg = principal.hash_alg();

    ks.get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format AuthRoot for display.
fn format_as(principal: &CliPrincipal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let auth_root = principal.auth_root();
    let hash_alg = principal.hash_alg();

    auth_root
        .get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format PrincipalRoot for display.
fn format_ps(principal: &CliPrincipal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let ps = principal.pr();
    let hash_alg = principal.hash_alg();

    ps.get(hash_alg)
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<no variant>".to_string())
}

/// Format PrincipalGenesis for display.
fn format_pr(principal: &CliPrincipal) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let hash_alg = principal.hash_alg();

    principal
        .pg()
        .and_then(|pr| pr.get(hash_alg))
        .map(Base64UrlUnpadded::encode_string)
        .unwrap_or_else(|| "<none>".to_string())
}
