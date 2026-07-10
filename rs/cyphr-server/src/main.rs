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
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return ExitCode::FAILURE;
                },
            };
            if let Err(e) = rt.block_on(cyphr_server::serve(config)) {
                tracing::error!(error = %e, "server exited with error");
                return ExitCode::FAILURE;
            }
        },
        Command::RebuildIndex { data_dir } => {
            let mut resolved_config = config;
            if let Some(dir) = data_dir {
                resolved_config.data_dir = dir;
            }
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return ExitCode::FAILURE;
                },
            };
            if let Err(e) = rt.block_on(async {
                let state = cyphr_server::AppState::new(resolved_config)?;
                tracing::info!(
                    "Starting total index rebuild in {}",
                    state.config.data_dir.display()
                );
                state.engine.reindex(&[], true).await?;
                tracing::info!("Index rebuild completed successfully");
                Ok::<(), Box<dyn std::error::Error>>(())
            }) {
                tracing::error!(error = %e, "rebuild-index failed");
                return ExitCode::FAILURE;
            }
        },
        Command::Export { .. } => {
            // Not yet implemented: fail loudly with a non-zero exit code
            // rather than logging a warning (easily missed, or filtered
            // out entirely depending on log level) and then exiting 0 as
            // if the export had actually happened.
            eprintln!("error: export is not yet implemented");
            return ExitCode::FAILURE;
        },
    }

    ExitCode::SUCCESS
}
