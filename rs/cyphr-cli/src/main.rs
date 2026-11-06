//! Cyphr CLI - Reference implementation for the Cyphr identity protocol.

use std::process::ExitCode;

use clap::Parser;
use cyphr_cli::{Cli, Commands, OutputFormat, commands};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let json = matches!(cli.output, OutputFormat::Json);
    if let Err(e) = run(cli) {
        if json {
            // One object on the last stderr line, switchable on `error.kind`.
            let obj = serde_json::json!({"error": {"kind": e.kind(), "message": e.to_string()}});
            eprintln!("{obj}");
        } else {
            eprintln!("error: {e}");
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn run(cli: Cli) -> cyphr_cli::Result<()> {
    match &cli.command {
        Commands::Init { algo, key, keys } => {
            commands::init::run(&cli, algo, key.as_deref(), keys.as_deref())
        },
        Commands::Key { command } => commands::key::run(&cli, command),
        Commands::Tx { command } => commands::tx::run(&cli, command),
        Commands::Inspect { identity } => commands::inspect::run(&cli, identity),
        Commands::Export { identity, output } => commands::io::export(&cli, identity, output),
        Commands::Import { input } => commands::io::import(&cli, input),
        Commands::Push { identity, peer } => commands::network::push(&cli, identity, peer),
        Commands::Rebase { identity, peer } => commands::network::rebase(&cli, identity, peer),
        Commands::Fetch { identity, peer } => commands::network::fetch(&cli, identity, peer),
        Commands::Verify {
            identity,
            peer,
            anchor,
            choices,
            freshness_secs,
        } => commands::network::verify(
            &cli,
            identity,
            peer,
            anchor.as_deref(),
            choices.as_deref(),
            *freshness_secs,
        ),
    }
}
