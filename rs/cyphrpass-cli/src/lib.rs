//! Cyphrpass CLI library components.
//!
//! This module exposes the CLI types for potential reuse in tests or other tools.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub mod commands;

/// Cyphrpass identity protocol CLI.
#[derive(Parser)]
#[command(name = "cyphrpass", version, about, long_about = None)]
pub struct Cli {
    /// Storage backend URI (e.g., file:./data)
    #[arg(long, default_value = "file:./cyphrpass-data")]
    pub store: String,

    /// Path to private key storage
    #[arg(long, default_value = "./cyphrpass-keys.json")]
    pub keystore: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table format
    Table,
    /// Machine-parseable JSON
    Json,
}

/// Top-level subcommands.
#[derive(Subcommand)]
pub enum Commands {
    /// Create a new identity
    Init {
        /// Algorithm for genesis key (ES256, ES384, ES512, Ed25519)
        #[arg(long, default_value = "ES256")]
        algo: String,

        /// Use existing key from keystore (by thumbprint)
        #[arg(long)]
        key: Option<String>,

        /// Create explicit genesis with multiple keys (comma-separated thumbprints)
        #[arg(long, value_delimiter = ',')]
        keys: Option<Vec<String>>,
    },

    /// Key management operations
    Key {
        /// Key subcommand to execute
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Transaction operations
    Tx {
        /// Transaction subcommand to execute
        #[command(subcommand)]
        command: TxCommands,
    },

    /// Display identity state
    Inspect {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },

    /// Export identity to JSONL file
    Export {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Output file path
        #[arg(long)]
        output: PathBuf,
    },

    /// Import identity from JSONL file
    Import {
        /// Input file path
        #[arg(long)]
        input: PathBuf,
    },
}

/// Key management subcommands.
#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new keypair
    Generate {
        /// Algorithm (ES256, ES384, ES512, Ed25519)
        #[arg(long, default_value = "ES256")]
        algo: String,

        /// Optional tag for the key
        #[arg(long)]
        tag: Option<String>,
    },

    /// Add a key to an identity
    Add {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Thumbprint of key to add
        #[arg(long)]
        key: String,

        /// Thumbprint of signing key
        #[arg(long)]
        signer: String,
    },

    /// Revoke a key from an identity
    Revoke {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Thumbprint of key to revoke
        #[arg(long)]
        key: String,

        /// Thumbprint of signing key
        #[arg(long)]
        signer: String,
    },

    /// List keys for an identity
    List {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },
}

/// Transaction subcommands.
#[derive(Subcommand)]
pub enum TxCommands {
    /// List transactions for an identity
    List {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },

    /// Verify transaction chain integrity
    Verify {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },
}
