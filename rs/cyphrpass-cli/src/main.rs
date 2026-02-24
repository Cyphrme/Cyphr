//! Cyphrpass CLI - Reference implementation for the Cyphrpass identity protocol.

use std::process::ExitCode;

use clap::Parser;
use cyphrpass_cli::{Cli, Commands, commands};

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn run(cli: Cli) -> cyphrpass_cli::Result<()> {
    match &cli.command {
        Commands::Init { algo, key, keys } => {
            commands::init::run(&cli, algo, key.as_deref(), keys.as_deref())
        },
        Commands::Key { command } => commands::key::run(&cli, command),
        Commands::Tx { command } => commands::tx::run(&cli, command),
        Commands::Inspect { identity } => commands::inspect::run(&cli, identity),
        Commands::Export { identity, output } => commands::io::export(&cli, identity, output),
        Commands::Import { input } => commands::io::import(&cli, input),
    }
}
