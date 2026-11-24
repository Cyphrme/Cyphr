//! Cyphr CLI - Reference implementation for the Cyphr identity protocol.

use std::process::ExitCode;

use clap::Parser;
use commands::verifier::{self, Inputs};
use cyphr_cli::{Cli, Commands, GossipCommands, OutputFormat, commands};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let json = matches!(cli.output, OutputFormat::Json);
    if let Err(e) = run_on_runtime(cli) {
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

/// Build the process's one runtime and run the command on a blocking
/// thread of it; see [`commands::common::block_on`].
fn run_on_runtime(cli: Cli) -> cyphr_cli::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::task::spawn_blocking(move || run(cli))
            .await
            .map_err(|e| std::io::Error::other(format!("command task failed: {e}")))?
    })
}

fn run(cli: Cli) -> cyphr_cli::Result<()> {
    match &cli.command {
        Commands::Init {
            algo,
            key,
            keys,
            genesis_commit,
        } => commands::init::run(&cli, algo, key.as_deref(), keys.as_deref(), *genesis_commit),
        Commands::Upgrade { identity } => commands::init::upgrade(&cli, identity),
        Commands::Key { command } => commands::key::run(&cli, command),
        Commands::Tx { command } => commands::tx::run(&cli, command),
        Commands::Data { command } => commands::data::run(&cli, command),
        Commands::Inspect { identity } => commands::inspect::run(&cli, identity),
        Commands::Export { identity, output } => commands::io::export(&cli, identity, output),
        Commands::Import { input } => commands::io::import(&cli, input),
        Commands::Push {
            identity,
            peer,
            assert_local,
        } => commands::network::push(&cli, identity, peer, *assert_local),
        Commands::Login {
            identity,
            signer,
            audience,
            peer,
            sign_only,
            challenge,
            channel_hash,
        } => commands::login::run(
            &cli,
            &commands::login::Request {
                identity,
                signer,
                audience,
                peer: peer.as_deref(),
                sign_only: *sign_only,
                challenge: challenge.as_deref(),
                channel_hash: channel_hash.as_deref(),
            },
        ),
        Commands::Resync {
            identity,
            peer,
            signer,
        } => commands::network::resync(&cli, identity, peer, signer.as_deref()),
        Commands::Fetch {
            identity,
            peer,
            trust_remote,
        } => commands::network::fetch(&cli, identity, peer, *trust_remote),
        Commands::Verify {
            identity,
            peer,
            anchor,
            choices,
            freshness_secs,
        } => verifier::verify(
            &cli,
            &Inputs {
                identity,
                peers: peer,
                anchor: anchor.as_deref(),
                choices: choices.as_deref(),
                freshness: *freshness_secs,
            },
        ),
        Commands::Watch {
            identity,
            peer,
            anchor,
            choices,
            freshness_secs,
            interval_secs,
            rounds,
        } => verifier::watch(
            &cli,
            &Inputs {
                identity,
                peers: peer,
                anchor: anchor.as_deref(),
                choices: choices.as_deref(),
                freshness: *freshness_secs,
            },
            *interval_secs,
            *rounds,
        ),
        Commands::Audit {
            identity,
            peer,
            anchor,
            choices,
            freshness_secs,
        } => verifier::audit(
            &cli,
            &Inputs {
                identity,
                peers: peer,
                anchor: anchor.as_deref(),
                choices: choices.as_deref(),
                freshness: *freshness_secs,
            },
        ),
        Commands::Recover {
            identity,
            head,
            reason,
            clear: _,
        } => verifier::recover(&cli, identity, head.as_deref(), reason.as_deref()),
        Commands::Gossip { command } => match command {
            GossipCommands::Export { identity, file } => verifier::export(&cli, identity, file),
            GossipCommands::Import {
                identity,
                file,
                anchor,
            } => verifier::import(&cli, identity, file, anchor.as_deref()),
        },
    }
}
