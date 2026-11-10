//! Import/export commands.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use cyphr::StateDigest;
use cyphr_storage::{CommitEntry, Genesis, load_principal_from_commits};

use super::common::{
    block_on, extract_genesis_from_commits, get_commits_from_engine, get_principal_id,
    parse_principal_genesis, parse_store, save_principal_to_engine,
};
use crate::keystore::JsonKeyStore;
use crate::{Cli, Error, OutputFormat};

/// Run the export command.
pub fn export(cli: &Cli, identity: &str, output: &Path) -> crate::Result<()> {
    let store = parse_store(cli)?;
    // Get commits from storage
    let commits = get_commits_from_engine(&store, identity)?;

    if commits.is_empty() {
        return Err(Error::EmptyHistory(identity.to_owned()));
    }

    // Write commits to JSONL file
    let file = File::create(output)?;
    let mut writer = BufWriter::new(file);

    // Action-only lines carry the data actions a `ds/create` includes, each
    // ahead of the commit that follows it, as `export_commits` writes them.
    let principal_id = get_principal_id(&parse_principal_genesis(identity)?)?;
    let mut bundles = block_on(store.get_patch(&principal_id, None, None))??
        .actions
        .into_iter()
        .peekable();
    let action_line = |blobs: &[Vec<u8>]| -> crate::Result<String> {
        let cozies = blobs
            .iter()
            .map(|b| serde_json::from_slice(b))
            .collect::<Result<Vec<serde_json::Value>, _>>()?;
        let line = CommitEntry::new(cozies, Vec::new(), String::new(), None, None, String::new());
        Ok(serde_json::to_string(&line)?)
    };
    for (i, commit) in commits.iter().enumerate() {
        while let Some(held) = bundles.next_if(|a| a.after <= i as u64) {
            writeln!(writer, "{}", action_line(&held.blobs)?)?;
        }
        writeln!(writer, "{}", serde_json::to_string(commit)?)?;
    }
    for held in bundles {
        writeln!(writer, "{}", action_line(&held.blobs)?)?;
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
        let commit = CommitEntry::from_json(&line).map_err(|source| Error::Bundle {
            line: line_num + 1,
            source,
        })?;
        commits.push(commit);
    }

    if commits.is_empty() {
        return Err(Error::EmptyBundle);
    }

    // Determine genesis from first commit
    let genesis = extract_genesis_from_commits(&commits, Some(&keystore))?;

    // Verify by loading the principal (this replays and verifies all cozies)
    let principal = load_principal_from_commits(genesis.clone(), &commits)?;
    // For Level 2 identities (no PG established), use the genesis thumbprint
    let pg = match principal.pg() {
        Some(pg) => pg.clone(),
        None => match &genesis {
            // The thumbprint is hashed with the key's own algorithm, so the
            // digest is read under it, not assumed SHA-256.
            Genesis::Implicit(k) => cyphr::PrincipalGenesis::from_digest(
                cyphr::state::hash_alg_from_str(k.alg())?,
                k.tmb().as_bytes().to_vec(),
            )?,
            Genesis::Explicit(_) => {
                return Err(Error::ExplicitGenesisWithoutPg);
            },
        },
    };

    // Check if identity already exists in storage
    let pg_id = get_principal_id(&pg)?;
    let tip = block_on(async { store.get_tip(&pg_id).await })??;
    if tip.is_some() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let pg_b64 = pg
            .as_multihash()
            .first_variant()
            .map(Base64UrlUnpadded::encode_string)?;
        return Err(Error::AlreadyExists(pg_b64));
    }

    // Store commits
    save_principal_to_engine(&store, &keystore, &principal)?;

    match cli.output {
        OutputFormat::Json => {
            use coz::base64ct::{Base64UrlUnpadded, Encoding};
            let pg_b64 = pg
                .as_multihash()
                .first_variant()
                .map(Base64UrlUnpadded::encode_string)?;
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
                .map(Base64UrlUnpadded::encode_string)?;
            println!("Imported identity from {}", input.display());
            println!("  identity: {}", pg_b64);
            println!("  commits: {}", commits.len());
            println!("  verified: OK");
        },
    }

    Ok(())
}
