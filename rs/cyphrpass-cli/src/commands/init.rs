//! Identity initialization command.

use crate::Cli;

/// Run the init command.
pub fn run(
    _cli: &Cli,
    _algo: &str,
    _key: Option<&str>,
    _keys: Option<&[String]>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("init: not yet implemented");
    Ok(())
}
