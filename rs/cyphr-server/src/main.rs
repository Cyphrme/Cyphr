//! Cyphr Server — binary entrypoint.
//!
//! Parses CLI, resolves configuration, initializes tracing,
//! and dispatches to the appropriate subcommand.

use std::process::ExitCode;

use clap::Parser;
use cyphr_server::config::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let config = match cyphr_server::config::resolve_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::FAILURE;
        },
    };

    cyphr_server::logging::init_tracing(&config);

    match cli.command {
        Command::Serve(_) => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = rt.block_on(cyphr_server::serve(config)) {
                tracing::error!(error = %e, "server exited with error");
                return ExitCode::FAILURE;
            }
        },
        Command::RebuildIndex { .. } => {
            tracing::warn!("rebuild-index not yet implemented");
        },
        Command::Export { .. } => {
            tracing::warn!("export not yet implemented");
        },
    }

    ExitCode::SUCCESS
}
