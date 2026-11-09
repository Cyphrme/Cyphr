//! Cyphr CLI library components.
//!
//! This module exposes the CLI types for potential reuse in tests or other tools.

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

pub mod choices;
pub mod commands;
pub mod keystore;
pub mod net;

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

    /// The blob store failed.
    #[error("blob store: {0}")]
    Blob(#[from] cyphr_storage::blob::BlobStoreError),

    /// The index failed or refused the stored schema.
    #[error("index: {0}")]
    Index(#[from] cyphr_storage::index::IndexerError),

    /// The storage engine refused or failed an operation.
    #[error("storage engine: {0}")]
    Engine(Box<cyphr_storage::engine::EngineError>),

    /// The fjall database could not be opened.
    #[error("database: {0}")]
    Database(#[from] fjall::Error),

    /// A bundle line could not be read.
    #[error("bundle line {line}: {source}")]
    Bundle {
        /// 1-based line number in the bundle file.
        line: usize,
        /// Why the line was refused.
        #[source]
        source: cyphr_storage::BundleError,
    },

    /// A stored blob is not UTF-8.
    #[error("stored blob is not UTF-8: {0}")]
    BlobEncoding(#[from] std::string::FromUtf8Error),

    /// The index names a blob the blob store does not hold.
    #[error("blob {0} not found in the blob store although the index names it")]
    MissingBlob(cyphr_storage::blob::Blake3Hash),

    /// The identity has no commits to act on.
    #[error("no commits found for identity {0} (a genesis-only state has none)")]
    EmptyHistory(String),

    /// An import file holds no commits.
    #[error("no commits found in file")]
    EmptyBundle,

    /// Import refused to overwrite an identity the store already holds.
    #[error("identity {0} already exists in storage")]
    AlreadyExists(String),

    /// The genesis of an identity cannot be determined from what is held.
    #[error(
        "cannot resolve genesis for identity {0}: no stored commits, keystore key or recorded \
         genesis"
    )]
    UnresolvableGenesis(String),

    /// An explicit genesis did not establish a Principal Genesis.
    #[error("explicit genesis must establish a PG")]
    ExplicitGenesisWithoutPg,

    /// The Principal Genesis computed from history differs from the identity.
    #[error("PG mismatch: computed {computed} != expected {expected}")]
    PgMismatch {
        /// Computed from replay.
        computed: String,
        /// Named by the caller.
        expected: String,
    },

    /// The Principal Root computed from history differs from the stored one.
    #[error("PR mismatch: computed {computed} != stored {stored}")]
    PrMismatch {
        /// Computed from replay.
        computed: String,
        /// Recorded in the last commit.
        stored: String,
    },

    /// A peer exchange failed or was refused.
    #[error(transparent)]
    Peer(#[from] net::PeerError),

    /// The choices file is unreadable or malformed.
    #[error(transparent)]
    Choices(Box<choices::ChoicesError>),

    /// `verify` was given no peer to ask: neither a flag nor the choices file
    /// names one.
    #[error("verify needs at least one peer (--peer or `peers` in the choices file)")]
    NoPeers,

    /// Rebase cannot replay a local commit's transaction onto the peer's tip.
    #[error("rebase cannot replay a `{0}` transaction")]
    RebaseUnsupported(String),

    /// The store directory is missing but a rebase left siblings next to it:
    /// the process likely died between the two renames of the swap.
    #[error(
        "store {} is missing but a rebase left {}; the previous store is the `.pre-rebase-*` entry \
         (the rebuilt one is `.rebase`): move the right one back to {} and retry",
        store.display(),
        found.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "),
        store.display()
    )]
    InterruptedRebase {
        /// The missing store directory.
        store: PathBuf,
        /// The leftovers found beside it.
        found: Vec<PathBuf>,
    },

    /// Rebase found its scratch store directory already present.
    #[error("rebase workspace {} already exists; remove it and retry", .0.display())]
    RebaseWorkspace(PathBuf),

    /// Load error (importing/replaying commits).
    #[error("{0}")]
    Load(#[from] cyphr_storage::LoadError),

    /// Export error (serializing principal to commits).
    #[error("{0}")]
    Export(#[from] cyphr_storage::ExportError),
}

// Boxed variants stay out of `#[from]` so the common `Result` stays small.
impl From<cyphr_storage::engine::EngineError> for Error {
    fn from(e: cyphr_storage::engine::EngineError) -> Self {
        Self::Engine(Box::new(e))
    }
}

impl From<choices::ChoicesError> for Error {
    fn from(e: choices::ChoicesError) -> Self {
        Self::Choices(Box::new(e))
    }
}

impl Error {
    /// The refusal kind a machine reader switches on, named as the scenario
    /// harness's `RefusalKind`s lowercased. Failures that are no refusal by a
    /// peer or of an input (local I/O, keystore, engine faults) are `other`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        use cyphr_storage::BundleError;
        use cyphr_storage::index::IndexerError;
        match self {
            Self::Peer(e) => e.kind(),
            Self::Choices(e) => e.kind(),
            Self::Bundle {
                source: BundleError::UnsupportedVersion { .. },
                ..
            }
            | Self::Index(IndexerError::UnsupportedVersion { .. }) => "unknownversion",
            Self::Bundle { .. }
            | Self::Json(_)
            | Self::Base64(_)
            | Self::MissingField(_)
            | Self::InvalidArgument(_)
            | Self::Load(_)
            | Self::EmptyBundle => "malformed",
            _ => "other",
        }
    }
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

    /// Force a total index rebuild on startup instead of incremental update
    #[arg(long, default_value_t = false)]
    pub total_check: bool,

    /// Path to private key storage
    #[arg(long, default_value = "./cyphr-keys.json")]
    pub keystore: PathBuf,

    /// Authority domain for transaction typ URIs (e.g., example.com)
    #[arg(long, default_value = "cyphr.me")]
    pub authority: String,

    /// Seconds a peer request may take in total before it fails as unreachable
    #[arg(long, default_value_t = 30)]
    pub peer_timeout_secs: u64,

    /// Allow plain http:// to a peer that is not loopback (sent in the clear)
    #[arg(long)]
    pub allow_cleartext: bool,

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

        /// Publish a single-key genesis: the genesis key signs a
        /// principal/create (id = the principal's state) and the commit
        /// finalizing it, with no further key (SPEC 5.1/5.2). Without it,
        /// init leaves a commitless principal that `push` has nothing to
        /// send for.
        #[arg(long, conflicts_with = "keys")]
        genesis_commit: bool,
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

    /// Send the commits a peer lacks; refuses a peer holding a newer tip
    Push {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Peer base URL (e.g., http://127.0.0.1:8080)
        #[arg(long)]
        peer: String,
    },

    /// Replay unpushed local commits onto a peer's tip
    ///
    /// The store keeps no commit once it is written, so the replay builds a
    /// fresh store beside the old one and swaps them; the old store is kept
    /// as `<store>.pre-rebase-<unix seconds>`.
    Rebase {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Peer base URL
        #[arg(long)]
        peer: String,
    },

    /// Pull and verify a peer's commits into the local store
    Fetch {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Peer base URL
        #[arg(long)]
        peer: String,
    },

    /// Report a principal's standing from the local view and its peers
    ///
    /// The answer states how old the view is and whether a peer reported a
    /// newer tip; it never claims the view is current.
    Verify {
        /// Principal Root (base64url)
        #[arg(long)]
        identity: String,

        /// Peer base URL to ask (repeatable)
        #[arg(long)]
        peer: Vec<String>,

        /// Trust anchor: a principal or commit root the history must contain
        #[arg(long)]
        anchor: Option<String>,

        /// TOML file with `anchor`, `peers` and `freshness_secs`; flags win
        #[arg(long)]
        choices: Option<PathBuf>,

        /// View age beyond which the answer reports the view as stale
        #[arg(long)]
        freshness_secs: Option<u64>,
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
