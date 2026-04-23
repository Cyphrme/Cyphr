//! Cyphr CLI library components.
//!
//! This module exposes the CLI types for potential reuse in tests or other tools.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub mod commands;
pub mod keystore;

/// CLI error type. Replaces `Box<dyn Error>` throughout the CLI crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// Keystore operation failed.
    #[error("{0}")]
    Keystore(#[from] keystore::Error),

    /// Core cyphr protocol error.
    #[error("{0}")]
    Cyphr(#[from] cyphr::Error),

    /// JSON serialization/deserialization error.
    #[error("{0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error.
    #[error("invalid base64url: {0}")]
    Base64(#[from] base64ct::Error),

    /// A required field was missing from a JSON object.
    #[error("missing field: {0}")]
    MissingField(&'static str),

    /// Invalid argument or option value.
    #[error("{0}")]
    InvalidArgument(String),

    /// Cryptographic signing or verification failed.
    #[error("{0}")]
    Signing(String),

    /// Storage layer error (file store operations).
    #[error("{0}")]
    Storage(String),

    /// File store error.
    #[error("{0}")]
    FileStore(#[from] cyphr_storage::FileStoreError),

    /// Load error (importing/replaying commits).
    #[error("{0}")]
    Load(#[from] cyphr_storage::LoadError),

    /// Export error (serializing principal to commits).
    #[error("{0}")]
    Export(#[from] cyphr_storage::ExportError),
}

/// CLI result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Cyphr identity protocol CLI.
#[derive(Parser)]
#[command(name = "cyphr", version, about, long_about = None)]
pub struct Cli {
    /// Storage backend URI (e.g., file:./data)
    #[arg(long, default_value = "file:./cyphr-data")]
    pub store: String,

    /// Path to private key storage
    #[arg(long, default_value = "./cyphr-keys.json")]
    pub keystore: PathBuf,

    /// Authority domain for transaction typ URIs (e.g., example.com)
    #[arg(long, default_value = "cyphr.me")]
    pub authority: String,

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

    /// ParsedCoz operations
    Tx {
        /// ParsedCoz subcommand to execute
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

        /// Thumbprint of key to add (if omitted, generates new key)
        #[arg(long)]
        key: Option<String>,

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

    /// List keys (from keystore if no identity, from identity if provided)
    List {
        /// Principal Root (base64url) - if omitted, lists keystore keys
        #[arg(long)]
        identity: Option<String>,
    },
}

/// ParsedCoz subcommands.
#[derive(Subcommand)]
pub enum TxCommands {
    /// List cozies for an identity
    List {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },

    /// Verify coz chain integrity
    Verify {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,
    },
}
