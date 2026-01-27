//! Import/export commands.

use std::path::Path;

use crate::Cli;

/// Run the export command.
pub fn export(
    _cli: &Cli,
    _identity: &str,
    _output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("export: not yet implemented");
    Ok(())
}

/// Run the import command.
pub fn import(_cli: &Cli, _input: &Path) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("import: not yet implemented");
    Ok(())
}
