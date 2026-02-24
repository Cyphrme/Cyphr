//! Import/export commands.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use coz::Thumbprint;
use cyphrpass::Key;
use cyphrpass_storage::{CommitEntry, FileStore, Genesis, load_principal_from_commits};

use super::common::{parse_principal_root, parse_store};
use crate::keystore::{JsonKeyStore, KeyStore};
use crate::{Cli, OutputFormat};

/// Run the export command.
pub fn export(cli: &Cli, identity: &str, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Get commits from storage
    let commits = store.get_commits(&pr)?;

    if commits.is_empty() {
        return Err("no commits found for identity (genesis-only state cannot be exported)".into());
    }

    // Write commits to JSONL file
    let file = File::create(output)?;
    let mut writer = BufWriter::new(file);

    for commit in &commits {
        let line = serde_json::to_string(commit)?;
        writeln!(writer, "{}", line)?;
    }
    writer.flush()?;

    match cli.output {
        OutputFormat::Json => {
            let result = serde_json::json!({
                "identity": identity,
                "output": output.display().to_string(),
                "commits": commits.len(),
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        OutputFormat::Table => {
            println!("Exported identity to {}", output.display());
            println!("  identity: {identity}");
            println!("  commits: {}", commits.len());
        },
    }

    Ok(())
}

/// Run the import command.
pub fn import(cli: &Cli, input: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let keystore = JsonKeyStore::open(&cli.keystore)?;
    let store = parse_store(&cli.store)?;

    // Read commits from JSONL file
    let file = File::open(input)?;
    let reader = BufReader::new(file);
    let mut commits: Vec<CommitEntry> = Vec::new();

    for (line_num, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        let commit: CommitEntry =
            serde_json::from_str(&line).map_err(|e| format!("line {}: {}", line_num + 1, e))?;
        commits.push(commit);
    }

    if commits.is_empty() {
        return Err("no commits found in file".into());
    }

    // Determine genesis from first commit
    let genesis = extract_genesis_from_commits(&commits, &keystore)?;

    // Verify by loading the principal (this replays and verifies all transactions)
    let principal = load_principal_from_commits(genesis, &commits)?;
    let pr = principal.pr();

    // Check if identity already exists in storage
    let existing = store.get_commits(pr).unwrap_or_default();
    if !existing.is_empty() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let pr_b64 = pr
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| format!("PR empty: {e}"))?;
        return Err(format!("identity {} already exists in storage", pr_b64).into());
    }

    // Store commits
    for commit in &commits {
        store.append_commit(pr, commit)?;
    }

    match cli.output {
        OutputFormat::Json => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pr_b64 = pr
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| format!("PR empty: {e}"))?;
            let result = serde_json::json!({
                "identity": pr_b64,
                "input": input.display().to_string(),
                "commits": commits.len(),
                "verified": true,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        OutputFormat::Table => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pr_b64 = pr
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| format!("PR empty: {e}"))?;
            println!("Imported identity from {}", input.display());
            println!("  identity: {}", pr_b64);
            println!("  commits: {}", commits.len());
            println!("  verified: OK");
        },
    }

    Ok(())
}

// ============================================================================
// Helpers (io-specific: keystore-aware genesis extraction)
// ============================================================================

/// Extract genesis from commits with keystore fallback.
///
/// Unlike `common::extract_genesis_from_commits`, this variant can fall back
/// to the keystore when the signer's public key is not embedded in the commit.
/// This is needed for import where the exported file may come from an implicit
/// genesis identity.
fn extract_genesis_from_commits(
    commits: &[CommitEntry],
    keystore: &JsonKeyStore,
) -> Result<Genesis, Box<dyn std::error::Error>> {
    let first_commit = commits.first().ok_or("no commits")?;
    let first_tx = first_commit
        .txs
        .first()
        .ok_or("no transactions in first commit")?;

    // Get signer from pay.tmb
    let pay = first_tx.get("pay").ok_or("missing pay in first tx")?;
    let signer_tmb = pay
        .get("tmb")
        .and_then(|v| v.as_str())
        .ok_or("missing pay.tmb")?;

    // Look for embedded key matching the signer
    if let Some(key_obj) = first_tx.get("key") {
        let key_tmb = key_obj.get("tmb").and_then(|v| v.as_str());

        if key_tmb == Some(signer_tmb) {
            // Signer is the embedded key
            let alg = key_obj
                .get("alg")
                .and_then(|v| v.as_str())
                .ok_or("missing key.alg")?;
            let pub_b64 = key_obj
                .get("pub")
                .and_then(|v| v.as_str())
                .ok_or("missing key.pub")?;
            let tmb_bytes = Base64UrlUnpadded::decode_vec(signer_tmb)?;
            let pub_key = Base64UrlUnpadded::decode_vec(pub_b64)?;

            return Ok(Genesis::Implicit(Key {
                alg: alg.to_string(),
                tmb: Thumbprint::from_bytes(tmb_bytes),
                pub_key,
                first_seen: 0,
                last_used: None,
                revocation: None,
                tag: None,
            }));
        }
    }

    // Signer's public key not in commit - try keystore
    if let Ok(stored) = keystore.get(signer_tmb) {
        let tmb_bytes = Base64UrlUnpadded::decode_vec(signer_tmb)?;
        return Ok(Genesis::Implicit(Key {
            alg: stored.alg.clone(),
            tmb: Thumbprint::from_bytes(tmb_bytes),
            pub_key: stored.pub_key.clone(),
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: stored.tag.clone(),
        }));
    }

    Err("cannot determine genesis key: signer not in commits or keystore. For import without keystore, the exported file must be from an explicit genesis identity.".into())
}
