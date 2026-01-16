//! Fixture-gen CLI for Cyphrpass test fixtures.
//!
//! Commands:
//! - `generate`: Transform intent TOML → golden JSON
//! - `pool`: Key pool management

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fixture-gen")]
#[command(about = "Generate and manage Cyphrpass test fixtures")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to key pool file
    #[arg(long, default_value = "tests/keys/pool.toml", global = true)]
    pool: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate golden JSON from intent TOML
    Generate {
        /// Intent TOML file
        intent: PathBuf,
        /// Output golden JSON file
        output: PathBuf,
    },
    /// Key pool management
    Pool {
        #[command(subcommand)]
        cmd: PoolCmd,
    },
}

#[derive(Subcommand)]
enum PoolCmd {
    /// Validate pool file
    Validate,
    /// List all keys
    List,
    /// Add a new key
    Add {
        /// Key name
        name: String,
        /// Algorithm (ES256, ES384, Ed25519)
        alg: String,
    },
    /// Remove a key
    Remove {
        /// Key name
        name: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { intent, output } => {
            // Load pool
            let pool = match test_fixtures::Pool::load(&cli.pool) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("✗ Failed to load pool '{}': {}", cli.pool.display(), e);
                    std::process::exit(1);
                },
            };

            // Load intent
            let intent_data = match test_fixtures::Intent::load(&intent) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("✗ Failed to load intent '{}': {}", intent.display(), e);
                    std::process::exit(1);
                },
            };

            // Generate golden test cases
            let goldens = match test_fixtures::generate(&intent_data, &pool) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("✗ Generation failed: {}", e);
                    std::process::exit(1);
                },
            };

            // Write output as pretty JSON
            let json = match serde_json::to_string_pretty(&goldens) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("✗ Failed to serialize output: {}", e);
                    std::process::exit(1);
                },
            };

            // Create parent directories if needed
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!(
                            "✗ Failed to create output directory '{}': {}",
                            parent.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                }
            }

            // Write to file
            if let Err(e) = std::fs::write(&output, &json) {
                eprintln!("✗ Failed to write output '{}': {}", output.display(), e);
                std::process::exit(1);
            }

            println!(
                "✓ Generated {} test case(s) → {}",
                goldens.len(),
                output.display()
            );
        },
        Commands::Pool { cmd } => match cmd {
            PoolCmd::Validate => {
                println!("Validating pool: {:?}", cli.pool);
                match test_fixtures::Pool::load(&cli.pool) {
                    Ok(pool) => match pool.validate() {
                        Ok(()) => println!("✓ Pool is valid"),
                        Err(errors) => {
                            for e in errors {
                                eprintln!("✗ {}", e);
                            }
                            std::process::exit(1);
                        },
                    },
                    Err(e) => {
                        eprintln!("✗ Failed to load pool: {}", e);
                        std::process::exit(1);
                    },
                }
            },
            PoolCmd::List => {
                println!("Listing keys from: {:?}", cli.pool);
                match test_fixtures::Pool::load(&cli.pool) {
                    Ok(pool) => {
                        for key in &pool.pool.key {
                            println!("  {} ({})", key.name, key.alg);
                            if let Some(tag) = &key.tag {
                                println!("    tag: {}", tag);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("✗ Failed to load pool: {}", e);
                        std::process::exit(1);
                    },
                }
            },
            PoolCmd::Add { name, alg } => {
                println!("Add key: {} ({})", name, alg);
                // TODO: Implement key generation
                eprintln!("Not yet implemented");
                std::process::exit(1);
            },
            PoolCmd::Remove { name } => {
                println!("Remove key: {}", name);
                // TODO: Implement key removal
                eprintln!("Not yet implemented");
                std::process::exit(1);
            },
        },
    }
}
