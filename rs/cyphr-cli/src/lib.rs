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
pub use cyphr_keystore as keystore;
pub mod net;
pub mod state;

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

    /// The commit logs could not be opened or migrated.
    #[error("commit logs: {0}")]
    Logs(#[from] cyphr_blob_fjall::EmlLogsError),

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
    #[error("cannot resolve genesis for identity {0}: no stored commits or keystore key")]
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

    /// The anchor is not a genesis key or a genesis commit id.
    #[error("{0}")]
    AnchorRule(String),

    /// A bundle file states a version this build does not read.
    #[error("bundle version {found} is not the supported {supported}")]
    BundleVersion {
        /// The stated version.
        found: u64,
        /// The one version this build reads.
        supported: u64,
    },

    /// `verify` was given no peer to ask: neither a flag nor the choices file
    /// names one.
    #[error("verify needs at least one peer (--peer or `peers` in the choices file)")]
    NoPeers,

    /// The store directory is missing but a store swap left siblings next to
    /// it: the process likely died between the two renames of the swap.
    #[error(
        "store {} is missing but a swap left {}; the previous store is the `.pre-adopt-*` entry \
         (the rebuilt one is `.adopt`): move the right one back to {} and retry",
        store.display(),
        found.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "),
        store.display()
    )]
    InterruptedSwap {
        /// The missing store directory.
        store: PathBuf,
        /// The leftovers found beside it.
        found: Vec<PathBuf>,
    },

    /// A store swap found its scratch store directory already present.
    #[error("swap workspace {} already exists; remove it and retry", .0.display())]
    SwapWorkspace(PathBuf),

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
            Self::BundleVersion { .. } => "unknownversion",
            Self::AnchorRule(_) => "malformed",
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
        #[arg(long, allow_hyphen_values = true)]
        key: Option<String>,

        /// Create a multi-key genesis (comma-separated thumbprints; the first
        /// is the genesis key, which creates the rest)
        #[arg(long, allow_hyphen_values = true, value_delimiter = ',')]
        keys: Option<Vec<String>>,

        /// Publish the genesis commit: the genesis key (the first) signs a
        /// key/create for itself and each further key, a principal/create
        /// (id = the principal's state) and the commit finalizing it (SPEC
        /// 5.1-5.3). Without it, a single-key init leaves a commitless
        /// principal that `push` has nothing to send for; `--keys` with more
        /// than one key always commits it, as a multi-key principal exists
        /// only through its genesis commit.
        #[arg(long)]
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

    /// Data actions and their inclusion in the Principal Tree
    Data {
        /// Data subcommand to execute
        #[command(subcommand)]
        command: DataCommands,
    },

    /// Display identity state
    Inspect {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,
    },

    /// Export identity to JSONL file
    Export {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
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
    ///
    /// A peer whose history differs from the local one is refused, with the
    /// parting point and the commits each side holds after it. The user
    /// chooses: `cyphr fetch --trust-remote` adopts the peer's, or
    /// `--assert-local` pushes the local commits as a fork.
    Push {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL (e.g., http://127.0.0.1:8080)
        #[arg(long)]
        peer: String,

        /// Assert the local history is correct: send the local commits past
        /// the parting point as a fork the peer's fork rules then apply to
        #[arg(long)]
        assert_local: bool,
    },

    /// Resolve a fork by a proof of possession of the local tip
    ///
    /// Signs a `resync/create` over this store's tip with a key of the
    /// identity that is active there, and sends it to the peer with the
    /// local commits the peer may lack (SPEC 15.8 item 2). No commit is
    /// made. A proof settles a fork even when both branches are extended;
    /// a proof on a second branch leaves it in Error for good, and recovery
    /// is the only other exit.
    Resync {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL
        #[arg(long)]
        peer: String,

        /// Thumbprint of the key to sign with (default: the first keystore
        /// key active at the local tip)
        #[arg(long)]
        signer: Option<String>,
    },

    /// Pull and verify a peer's commits into the local store
    ///
    /// Local commits that differ from the peer's are refused, with the
    /// parting point and what each side holds after it; nothing changes.
    /// `--trust-remote` discards only the local commits after the parting
    /// point and adopts the peer's. The store keeps no commit once it is
    /// written, so it is rebuilt beside the old one and swapped; the old
    /// store is kept as `<store>.pre-adopt-<unix seconds>` (`-<n>` appended
    /// if that name is taken). Recorded data actions survive when the
    /// adopted history accepts them as signed; any other is dropped and
    /// listed under `dropped_actions`, never re-signed.
    Fetch {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL
        #[arg(long)]
        peer: String,

        /// On divergence, trust the peer: discard the local commits after
        /// the parting point
        #[arg(long)]
        trust_remote: bool,
    },

    /// Report a principal's standing from the local view and its peers
    ///
    /// The answer states how old the view is and whether a peer reported a
    /// newer tip; it never claims the view is current.
    Verify {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL to ask (repeatable)
        #[arg(long)]
        peer: Vec<String>,

        /// Trust anchor: the genesis key or the genesis commit id (never the
        /// PG alone)
        #[arg(long, allow_hyphen_values = true)]
        anchor: Option<String>,

        /// TOML file with `anchor`, `peers` and `freshness_secs`; flags win
        #[arg(long)]
        choices: Option<PathBuf>,

        /// View age beyond which the answer reports the view as stale
        #[arg(long)]
        freshness_secs: Option<u64>,
    },

    /// Run `verify` on a timer, printing each round's verdict
    Watch {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL to ask (repeatable)
        #[arg(long)]
        peer: Vec<String>,

        /// Trust anchor: the genesis key or genesis commit id
        #[arg(long, allow_hyphen_values = true)]
        anchor: Option<String>,

        /// TOML file with `anchor`, `peers` and `freshness_secs`; flags win
        #[arg(long)]
        choices: Option<PathBuf>,

        /// View age beyond which the answer reports the view as stale
        #[arg(long)]
        freshness_secs: Option<u64>,

        /// Seconds between rounds
        #[arg(long, default_value_t = 30)]
        interval_secs: u64,

        /// Stop after this many rounds (default: run until killed)
        #[arg(long)]
        rounds: Option<u64>,
    },

    /// Run `verify` and print the evidence held (both branches of a fork,
    /// the resolving key, the naked revokes) in full
    Audit {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL to ask (repeatable)
        #[arg(long)]
        peer: Vec<String>,

        /// Trust anchor: the genesis key or genesis commit id
        #[arg(long, allow_hyphen_values = true)]
        anchor: Option<String>,

        /// TOML file with `anchor`, `peers` and `freshness_secs`; flags win
        #[arg(long)]
        choices: Option<PathBuf>,

        /// View age beyond which the answer reports the view as stale
        #[arg(long)]
        freshness_secs: Option<u64>,
    },

    /// Choose which branch head to trust for a principal in Error (human
    /// recovery, a last resort)
    ///
    /// The choice is local and revisable: a new one replaces the old,
    /// `--clear` returns to no branch chosen. It is never stored with
    /// commits or sent to a peer, and `verify` still reports Error.
    Recover {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// The branch head to trust, as `verify` lists it
        #[arg(
            long,
            allow_hyphen_values = true,
            conflicts_with = "clear",
            required_unless_present = "clear"
        )]
        head: Option<String>,

        /// Why, recorded beside the choice
        #[arg(long, conflicts_with = "clear")]
        reason: Option<String>,

        /// Drop the choice
        #[arg(long)]
        clear: bool,
    },

    /// Carry what this client verified to another, with no peer
    Gossip {
        /// Gossip subcommand to execute
        #[command(subcommand)]
        command: GossipCommands,
    },
}

/// Client-to-client exchange subcommands.
#[derive(Subcommand)]
pub enum GossipCommands {
    /// Write the verified record, the other branch of each fork held and
    /// the naked revokes held to a bundle file
    Export {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Bundle file to write
        #[arg(long)]
        file: PathBuf,
    },

    /// Replay a bundle file into the local store, as if each chain in it
    /// were a peer: nothing in it is believed except by replay
    Import {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Bundle file to read
        #[arg(long)]
        file: PathBuf,

        /// Trust anchor: the genesis key or genesis commit id (without it
        /// the bundle's own genesis commit is a hint)
        #[arg(long, allow_hyphen_values = true)]
        anchor: Option<String>,
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
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of key to add (if omitted, generates new key)
        #[arg(long, allow_hyphen_values = true)]
        key: Option<String>,

        /// Thumbprint of signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,
    },

    /// Remove a key from an identity without marking it compromised (SPEC 6.2)
    Delete {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of the key to remove
        #[arg(long, allow_hyphen_values = true)]
        key: String,

        /// Thumbprint of signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,
    },

    /// Swap the signing key for a new one in one commit (SPEC 6.3)
    Replace {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of the new key (if omitted, generates one)
        #[arg(long, allow_hyphen_values = true)]
        key: Option<String>,

        /// Thumbprint of the key to replace, which signs
        #[arg(long, allow_hyphen_values = true)]
        signer: String,

        /// Sign with this `now` (unix seconds) instead of the clock
        #[arg(long)]
        now: Option<i64>,
    },

    /// Sign a naked revoke with the key itself, outside any commit (SPEC 6.4)
    ///
    /// The revoke names no principal and changes no chain; each peer that
    /// accepts it refuses further use of the key.
    NakedRevoke {
        /// Thumbprint of the key to revoke, which must be in the keystore
        #[arg(long, allow_hyphen_values = true)]
        key: String,

        /// Why the key is compromised
        #[arg(long)]
        msg: Option<String>,

        /// Peer base URL to send the revoke to (repeatable)
        #[arg(long)]
        peer: Vec<String>,
    },

    /// Revoke a key from an identity, by a commit signed by that key
    Revoke {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of key to revoke
        #[arg(long, allow_hyphen_values = true)]
        key: String,

        /// Thumbprint of signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,
    },

    /// Enroll this device's own key: sign a pairing request with it
    ///
    /// The new key is generated here and never leaves the device; the
    /// request carries only its public half, signed by the key itself as a
    /// proof of possession. Carry it to a device already in the principal.
    Request {
        /// Principal Root (base64url) the request is for
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Algorithm (ES256, ES384, ES512, Ed25519)
        #[arg(long, default_value = "ES256")]
        algo: String,

        /// Optional tag for the key
        #[arg(long)]
        tag: Option<String>,

        /// Write the request here instead of stdout
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// Accept a pairing request: commit its key to an identity
    ///
    /// Refused unless the request's proof of possession verifies, it names
    /// this identity, and its `now` is within the window.
    Accept {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of the signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,

        /// The pairing request file
        #[arg(long)]
        file: PathBuf,

        /// Seconds either side of now the request's `now` may sit
        #[arg(long, default_value_t = crate::commands::pair::DEFAULT_WINDOW_SECS)]
        window: u64,
    },

    /// List keys (from keystore if no identity, from identity if provided)
    List {
        /// Principal Root (base64url) - if omitted, lists keystore keys
        #[arg(long, allow_hyphen_values = true)]
        identity: Option<String>,
    },
}

/// Data subcommands (SPEC 4.8).
#[derive(Subcommand)]
pub enum DataCommands {
    /// Sign a data action and record it in the Data Tree
    ///
    /// The action enters DT only; DR enters PR when `data commit` signs a
    /// `ds/create`. `push` sends recorded actions ahead of the commits.
    Action {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of the signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,

        /// Message the `comment/create` action carries
        #[arg(long)]
        msg: String,

        /// Sign with this `now` (unix seconds) instead of the clock
        #[arg(long)]
        now: Option<i64>,

        /// Print the signed action without recording it locally
        #[arg(long)]
        sign_only: bool,
    },

    /// Sign a `ds/create` over the local DT; its `id` becomes DR in PR
    Commit {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Thumbprint of the signing key
        #[arg(long, allow_hyphen_values = true)]
        signer: String,
    },

    /// Send a signed action (the output of `data action`) to a peer
    Submit {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,

        /// Peer base URL
        #[arg(long)]
        peer: String,

        /// File holding the signed action JSON
        #[arg(long)]
        file: PathBuf,
    },
}

/// ParsedCoz subcommands.
#[derive(Subcommand)]
pub enum TxCommands {
    /// List cozies for an identity
    List {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,
    },

    /// Verify coz chain integrity
    Verify {
        /// Principal Root (base64url)
        #[arg(long, allow_hyphen_values = true)]
        identity: String,
    },
}
