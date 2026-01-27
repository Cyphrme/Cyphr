//! Key management commands.

use crate::{Cli, KeyCommands};

/// Run a key subcommand.
pub fn run(cli: &Cli, command: &KeyCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        KeyCommands::Generate { algo, tag } => generate(cli, algo, tag.as_deref()),
        KeyCommands::Add {
            identity,
            key,
            signer,
        } => add(cli, identity, key, signer),
        KeyCommands::Revoke {
            identity,
            key,
            signer,
        } => revoke(cli, identity, key, signer),
        KeyCommands::List { identity } => list(cli, identity),
    }
}

fn generate(_cli: &Cli, _algo: &str, _tag: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key generate: not yet implemented");
    Ok(())
}

fn add(
    _cli: &Cli,
    _identity: &str,
    _key: &str,
    _signer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key add: not yet implemented");
    Ok(())
}

fn revoke(
    _cli: &Cli,
    _identity: &str,
    _key: &str,
    _signer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key revoke: not yet implemented");
    Ok(())
}

fn list(_cli: &Cli, _identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("key list: not yet implemented");
    Ok(())
}
