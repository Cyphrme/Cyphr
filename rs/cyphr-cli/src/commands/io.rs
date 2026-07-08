//! Import/export commands.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use cyphr::StateDigest;
use cyphr_storage::{CommitEntry, Genesis, load_principal_from_commits};

use super::common::{
    block_on, extract_genesis_from_commits, get_commits_from_engine, get_principal_id,
    parse_store, save_principal_to_engine,
};
use crate::keystore::JsonKeyStore;
use crate::{Cli, Error, OutputFormat};

/// Run the export command.
pub fn export(cli: &Cli, identity: &str, output: &Path) -> crate::Result<()> {
    let store = parse_store(cli)?;
    // Get commits from storage
    let commits = get_commits_from_engine(&store, identity)?;

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
    let store = parse_store(cli)?;

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

    // Verify by loading the principal (this replays and verifies all cozies)
    let principal = load_principal_from_commits(genesis.clone(), &commits)?;
    // For Level 2 identities (no PG established), use the genesis thumbprint
    let pg = match principal.pg() {
        Some(pg) => pg.clone(),
        None => match &genesis {
            Genesis::Implicit(k) => cyphr::PrincipalGenesis::from_bytes(k.tmb.as_bytes().to_vec()),
            Genesis::Explicit(_) => {
                return Err(Error::Storage(
                    "explicit genesis must establish a PG".into(),
                ));
            },
        },
    };

    // Check if identity already exists in storage
    let pg_id = get_principal_id(&pg)?;
    let tip = block_on(async { store.get_tip(&pg_id).await })?
        .map_err(|e| Error::Storage(e.to_string()))?;
    if tip.is_some() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let pg_b64 = pg
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)
            .map_err(|e| Error::Storage(format!("PG empty: {e}")))?;
        return Err(Error::Storage(format!(
            "identity {} already exists in storage",
            pg_b64
        )));
    }

    // Store commits
    save_principal_to_engine(&store, &keystore, &principal)?;

    match cli.output {
        OutputFormat::Json => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pg_b64 = pg
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| Error::Storage(format!("PG empty: {e}")))?;
            let result = serde_json::json!({
                "identity": pg_b64,
                "input": input.display().to_string(),
                "commits": commits.len(),
                "verified": true,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        },
        OutputFormat::Table => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pg_b64 = pg
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)
                .map_err(|e| Error::Storage(format!("PG empty: {e}")))?;
            println!("Imported identity from {}", input.display());
            println!("  identity: {}", pg_b64);
            println!("  commits: {}", commits.len());
            println!("  verified: OK");
        },
    }

    Ok(())
}
