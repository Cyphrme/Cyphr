//! Identity inspection command.

use crate::Cli;

/// Run the inspect command.
pub fn run(_cli: &Cli, _identity: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("inspect: not yet implemented");
    Ok(())
}
