//! Transaction commands.

use crate::{Cli, TxCommands};

/// Run a tx subcommand.
pub fn run(cli: &Cli, command: &TxCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        TxCommands::List { identity } => list(cli, identity),
        TxCommands::Verify { identity } => verify(cli, identity),
    }
}

fn list(_cli: &Cli, _identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("tx list: not yet implemented");
    Ok(())
}

fn verify(_cli: &Cli, _identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("tx verify: not yet implemented");
    Ok(())
}
