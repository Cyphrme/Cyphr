//! Import/export commands.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use cyphrpass_storage::{CommitEntry, Genesis, load_principal_from_commits};

use super::common::{extract_genesis_from_commits, parse_principal_root, parse_store};
use crate::keystore::JsonKeyStore;
use crate::{Cli, Error, OutputFormat};

/// Run the export command.
pub fn export(cli: &Cli, identity: &str, output: &Path) -> crate::Result<()> {
    let store = parse_store(&cli.store)?;
    let pr = parse_principal_root(identity)?;

    // Get commits from storage
    let commits = store.get_commits(&pr)?;

    if commits.is_empty() {
        return Err(Error::Storage(
            "no commits found for identity (genesis-only state cannot be exported)".into(),
        ));
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
pub fn import(cli: &Cli, input: &Path) -> crate::Result<()> {
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
        let commit: CommitEntry = serde_json::from_str(&line)
            .map_err(|e| Error::Storage(format!("line {}: {}", line_num + 1, e)))?;
        commits.push(commit);
    }

    if commits.is_empty() {
        return Err(Error::Storage("no commits found in file".into()));
    }

    // Determine genesis from first commit
    let genesis = extract_genesis_from_commits(&commits, Some(&keystore))?;

    // Verify by loading the principal (this replays and verifies all transactions)
    let principal = load_principal_from_commits(genesis.clone(), &commits)?;
    // For Level 2 identities (no PR established), use the genesis thumbprint
    let pr = match principal.pr() {
        Some(pr) => pr.clone(),
        None => match &genesis {
            Genesis::Implicit(k) => cyphrpass::PrincipalRoot::from_bytes(k.tmb.as_bytes().to_vec()),
            Genesis::Explicit(_) => {
                return Err(Error::Storage(
                    "explicit genesis must establish a PR".into(),
                ));
            },
        },
    };

    // Check if identity already exists in storage
    let existing = store.get_commits(&pr).unwrap_or_default();
    if !existing.is_empty() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let pr_b64 = pr
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| Error::Storage(format!("PR empty: {e}")))?;
        return Err(Error::Storage(format!(
            "identity {} already exists in storage",
            pr_b64
        )));
    }

    // Store commits
    for commit in &commits {
        store.append_commit(&pr, commit)?;
    }

    match cli.output {
        OutputFormat::Json => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pr_b64 = pr
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| Error::Storage(format!("PR empty: {e}")))?;
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
                .map_err(|e| Error::Storage(format!("PR empty: {e}")))?;
            println!("Imported identity from {}", input.display());
            println!("  identity: {}", pr_b64);
            println!("  commits: {}", commits.len());
            println!("  verified: OK");
        },
    }

    Ok(())
}
