//! Cyphr Server — binary entrypoint.
//!
//! Parses CLI, resolves configuration, initializes tracing,
//! and dispatches to the appropriate subcommand.

use std::process::ExitCode;

use clap::Parser;
use cyphr_server::config::{AdmissionConfig, Cli, Command, InviteAction};
use cyphr_server::ops::{self, OpsError};

mod rotate;

fn runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Runtime::new().map_err(|e| {
        eprintln!("failed to create tokio runtime: {e}");
        ExitCode::FAILURE
    })
}

/// Run one offline operator command, print its report, and map failure to
/// a non-zero exit.
fn run_op<R: std::fmt::Display>(
    op: impl std::future::Future<Output = Result<R, OpsError>>,
) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    match rt.block_on(op) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        },
    }
}

/// `verify-all` also exits non-zero when it reports a failed chain.
fn run_verify_all(config: &cyphr_server::config::ServerConfig) -> ExitCode {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    match rt.block_on(ops::chains::verify_all(config)) {
        Ok(report) => {
            println!("{report}");
            if report.failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        },
    }
}

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
                state.engine.rebuild_index_from_scratch().await?;
                tracing::info!("Index rebuild completed successfully");
                Ok::<(), Box<dyn std::error::Error>>(())
            }) {
                tracing::error!(error = %e, "rebuild-index failed");
                return ExitCode::FAILURE;
            }
        },
        Command::RotateKey(_) => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("failed to create tokio runtime: {e}");
                    return ExitCode::FAILURE;
                },
            };
            match rt.block_on(rotate::rotate_key(config)) {
                Ok(report) => println!("{report}"),
                Err(e) => {
                    eprintln!("error: rotate-key failed: {e}");
                    return ExitCode::FAILURE;
                },
            }
        },
        Command::Backup { dest, .. } => {
            return run_op(ops::snapshot::backup(&config, &dest));
        },
        Command::Restore { from, .. } => {
            return run_op(ops::snapshot::restore(&config, &from));
        },
        Command::Export { out, .. } => {
            return run_op(async {
                let ids = ops::chains::export(&config, &out).await?;
                Ok(format!(
                    "exported {} principal(s) to {}",
                    ids.len(),
                    out.display()
                ))
            });
        },
        Command::VerifyAll { .. } => {
            return run_verify_all(&config);
        },
        Command::Invite { action } => {
            let InviteAction::New { count } = action;
            // The tokens file location is single-sourced from the configured
            // admission policy, so issued hashes land where the running server
            // reads them.
            let tokens_path = match &config.admission {
                AdmissionConfig::Invite { tokens_path } => tokens_path.clone(),
                _ => {
                    eprintln!(
                        "error: `invite` requires [admission] policy = \"invite\" with a \
                         tokens_path"
                    );
                    return ExitCode::FAILURE;
                },
            };
            match cyphr_server::admission::issue_tokens(&tokens_path, count) {
                Ok(tokens) => {
                    for token in tokens {
                        println!("{token}");
                    }
                },
                Err(e) => {
                    eprintln!("error issuing invite tokens: {e}");
                    return ExitCode::FAILURE;
                },
            }
        },
    }

    ExitCode::SUCCESS
}
