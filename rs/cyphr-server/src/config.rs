//! 12-factor configuration for cyphr-server.
//!
//! Precedence (highest to lowest):
//! 1. CLI flags
//! 2. Environment variables (`CYPHR_*`)
//! 3. TOML config file
//! 4. Compiled defaults

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;

// ========================================================================
// CLI (clap)
// ========================================================================

/// Cyphr Protocol server — self-sovereign identity authority.
#[derive(Parser, Debug)]
#[command(name = "cyphr-server", version, about)]
pub struct Cli {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "cyphr-server.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

/// Server subcommands (Factor XII — admin processes as one-off commands).
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the HTTP server.
    Serve(ServeArgs),

    /// Rebuild the index from the blob store.
    RebuildIndex {
        /// Data directory containing blob storage.
        #[arg(long, env = "CYPHR_DATA_DIR")]
        data_dir: Option<PathBuf>,
    },

    /// Copy the stopped server's `record/` tree to a new directory. The
    /// signing key is never copied.
    Backup {
        /// Directory to create (must not exist).
        dest: PathBuf,
        #[command(flatten)]
        ops: OpsArgs,
    },

    /// Replace the stopped server's `record/` with a backup and report the
    /// window of commits the restored store lost. The principals re-push
    /// to fill it.
    Restore {
        /// A directory `backup` wrote.
        from: PathBuf,
        #[command(flatten)]
        ops: OpsArgs,
    },

    /// Write every stored principal chain as bundles, one file each.
    Export {
        /// Directory to write into.
        out: PathBuf,
        #[command(flatten)]
        ops: OpsArgs,
    },

    /// Replay every stored chain from the blob store; exits non-zero and
    /// names each chain that fails. It rebuilds the index and rewrites the
    /// quarantine set from the replay (both derived, never the record).
    VerifyAll {
        #[command(flatten)]
        ops: OpsArgs,
    },

    /// Rotate the server's signing key (offline: the server must be
    /// stopped).
    RotateKey(RotateKeyArgs),

    /// Manage invite tokens (admission policy `invite`).
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },
}

/// Arguments shared by the offline operator commands (`backup`, `restore`,
/// `export`, `verify-all`).
#[derive(Debug, clap::Args)]
pub struct OpsArgs {
    /// Data directory of the stopped server.
    #[arg(long, env = "CYPHR_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// The server's signing key file; only consulted so `backup` and
    /// `restore` can refuse a key inside the tree they copy.
    #[arg(long, env = "CYPHR_SIGNING_KEY_PATH")]
    pub signing_key_path: Option<PathBuf>,
}

/// Arguments for the `rotate-key` subcommand.
///
/// Overrides layer over the TOML file like [`ServeArgs`], so the command
/// reads the same data directory and key file `serve` does.
#[derive(Debug, clap::Args)]
pub struct RotateKeyArgs {
    /// Data directory holding the server's chain.
    #[arg(long, env = "CYPHR_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Path to the server's signing key file; replaced in place.
    #[arg(long, env = "CYPHR_SIGNING_KEY_PATH")]
    pub signing_key_path: Option<PathBuf>,
}

/// `invite` subcommands.
#[derive(Subcommand, Debug)]
pub enum InviteAction {
    /// Issue fresh single-use tokens: append their `sha256` hashes to the
    /// configured tokens file and print the plaintext tokens to distribute.
    New {
        /// Number of tokens to issue.
        #[arg(long, default_value_t = 1)]
        count: usize,
    },
}

/// Arguments for the `serve` subcommand.
///
/// All fields are `Option` so clap only overrides when the user or
/// environment provides a value. The merge logic in [`resolve_config`]
/// layers these over the TOML file and compiled defaults.
#[derive(Debug, clap::Args)]
pub struct ServeArgs {
    /// Listen address (e.g., 127.0.0.1:3000).
    #[arg(long, env = "CYPHR_LISTEN")]
    pub listen: Option<String>,

    /// Listen address for the Noise transport (e.g., 127.0.0.1:3100). When
    /// unset the transport is off. A keyless server refuses it.
    #[arg(long, env = "CYPHR_TRANSPORT_LISTEN")]
    pub transport_listen: Option<String>,

    /// Data directory for blob and index storage.
    #[arg(long, env = "CYPHR_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Log output format.
    #[arg(long, env = "CYPHR_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// Server operating mode.
    #[arg(long, env = "CYPHR_MODE")]
    pub mode: Option<ServerMode>,

    /// Path to the server's signing key file (see `auth::ServerIdentity`).
    /// When unset, the server holds no signing identity.
    #[arg(long, env = "CYPHR_SIGNING_KEY_PATH")]
    pub signing_key_path: Option<PathBuf>,

    /// The audience identity clients must name when logging in (the
    /// authority segment of the login `typ`, e.g. a domain like
    /// `cyphr.me`). When unset, the server accepts no logins. See
    /// `auth::login`.
    #[arg(long, env = "CYPHR_AUDIENCE")]
    pub audience: Option<String>,

    /// Lifetime of a login session's bearer token, in seconds (at most
    /// [`MAX_SESSION_TTL_SECS`]). A session is never extended; a client
    /// that wants a longer one signs in again.
    #[arg(long, env = "CYPHR_SESSION_TTL_SECS")]
    pub session_ttl_secs: Option<i64>,

    /// Target authority URL for witness mode sync.
    #[arg(long, env = "CYPHR_AUTHORITY_URL")]
    pub authority_url: Option<String>,

    /// A peer to gossip with (repeatable, or comma-separated): its base
    /// URL, dialled exactly as given. Replaces the `[gossip] peers` list.
    #[arg(
        long = "gossip-peer",
        env = "CYPHR_GOSSIP_PEERS",
        value_delimiter = ','
    )]
    pub gossip_peers: Vec<String>,

    /// Seconds between gossip rounds (`[gossip] interval_secs`).
    #[arg(long, env = "CYPHR_GOSSIP_INTERVAL_SECS")]
    pub gossip_interval_secs: Option<u64>,

    /// Allow plain `http://` to a non-loopback upstream (the witness
    /// authority and gossip peers). Off by default: every byte would cross
    /// the network readable and forgeable.
    #[arg(long, env = "CYPHR_ALLOW_CLEARTEXT_UPSTREAM")]
    pub allow_cleartext_upstream: bool,
}

// ========================================================================
// Resolved configuration
// ========================================================================

/// Fully-resolved server configuration.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address.
    pub listen: String,

    /// Listen address for the principal-authenticated Noise transport
    /// (`crate::transport`). `None` keeps the transport off.
    #[serde(default)]
    pub transport_listen: Option<String>,

    /// Data directory.
    pub data_dir: PathBuf,

    /// Log format.
    pub log_format: LogFormat,

    /// Operating mode.
    pub mode: ServerMode,

    /// Path to the server's signing key file. `None` means the server
    /// holds no signing identity (see `auth::ServerIdentity`).
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,

    /// The audience identity clients must name in a login payload's
    /// `typ` authority segment, verified against this value (see
    /// `auth::login`). `None` means logins are not accepted.
    #[serde(default)]
    pub audience: Option<String>,

    /// Lifetime of a login session's bearer token, in seconds, clamped to
    /// `1..=`[`MAX_SESSION_TTL_SECS`]. Short because a bearer token is
    /// good for whoever holds it until it expires (see `auth::token`).
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: i64,

    /// Target authority URL for witness mode sync.
    #[serde(default)]
    pub authority_url: Option<String>,

    /// Whether upstream calls (the witness authority and gossip peers) may
    /// use plain `http://` to a host that is not loopback. Off by default:
    /// a tip report or a patch could be rewritten in transit. `https://`
    /// and loopback never need it.
    #[serde(default)]
    pub allow_cleartext_upstream: bool,

    /// Peer-side anti-entropy (the `[gossip]` TOML table).
    #[serde(default)]
    pub gossip: GossipConfig,

    /// The expected upstream-authority signing identity a witness verifies
    /// a `GET /patch` envelope's signature against before consuming any
    /// entry (the authenticated-channel identity, K10). `None` preserves the
    /// legacy unauthenticated sync path; when set, an unsigned, mis-signed,
    /// or entry-unbound patch response is a sync failure, never applied.
    ///
    /// Carries verifiable KEY MATERIAL (alg + public-key bytes), not a bare
    /// thumbprint: `coz::verify_json` needs the actual public key, and a
    /// thumbprint verifies nothing. Mirrors the disclosed-key `alg`/`pub`
    /// pattern (`crate::revoke::DisclosedKey`).
    #[serde(default)]
    pub authority_identity: Option<AuthorityIdentity>,

    /// Server-side admission policy (the `[admission]` TOML table). Gates
    /// new-principal residency only; defaults to `Open` (permissionless).
    #[serde(default)]
    pub admission: AdmissionConfig,

    /// Server-side resource fences (the `[limits]` TOML table). Bounds
    /// per-request resource use -- rate, body size, per-principal commit
    /// count -- orthogonally to the protocol. Every field has a conservative,
    /// overridable default, so a bare server (no `[limits]` table) is still
    /// bounded rather than unlimited.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Peer-side anti-entropy (the `[gossip]` TOML table): a timer that runs
/// the verifier's pull step (`cyphr_client::pull`) against configured
/// peers for every principal this server holds, and stores what verifies.
///
/// Peers are mirrors of principal-signed objects, so the list is this
/// operator's choice of whom to ask, not a trust list. It is dialled at the
/// address given, so a deployment (or the scenario proxy) can carry and cut
/// that link.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GossipConfig {
    /// Base URLs of the peers to pull from. Empty (the default) keeps
    /// gossip off.
    pub peers: Vec<String>,

    /// Seconds between rounds. A round replays each held principal from its
    /// stored chain (replay-cost caching is deferred), so the default is
    /// minutes of slack, not seconds; a deployment that wants faster
    /// convergence pays for it here.
    pub interval_secs: u64,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            interval_secs: 60,
        }
    }
}

/// Resource-fence limits (the `[limits]` TOML table). Additive to
/// `[admission]` and mirroring its structured-config pattern; consumed only by
/// the `rate_limit` fences composed in [`crate::serve`], never by a protocol
/// handler.
///
/// `#[serde(default)]` makes every field independently omittable, so a partial
/// `[limits]` table tunes one fence and inherits defaults for the rest.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum request body in bytes; an over-cap body is refused `413` before
    /// any handler work. Defaults to 2 MiB (the historical push-body bound).
    pub max_body_bytes: u64,

    /// Per-principal hard commit-count cap. A principal already at or over
    /// this many commits is refused a further commit with a distinct quota
    /// `4xx`. Generous by default so it bounds runaway growth without
    /// impeding ordinary use.
    pub count_quota: u64,

    /// Rate bucket keyed on the connection peer address (per-IP fence).
    ///
    /// There is deliberately no per-principal RATE bucket: keying a rate
    /// fence on the `principal_id` peeked from a raw, unverified `/push`
    /// body would let an unauthenticated attacker throttle a victim merely
    /// by naming its principal in a garbage flood (the peeked field is never
    /// authenticated before the fence would see it). The write path is
    /// bounded instead by this per-IP fence (keyed on the real, un-nameable
    /// TCP peer) and `count_quota` below (which reads durable, uninflatable
    /// commit-count state, so garbage pushes -- which never commit -- cannot
    /// inflate it).
    pub per_ip: RateBucket,

    /// Per-operation bucket for reads (`GET` routes) -- generous.
    pub read: RateBucket,

    /// Per-operation bucket for `POST /push` -- the tightest, as the write
    /// path is the costliest operation.
    pub push: RateBucket,

    /// Per-operation bucket for the login / challenge routes.
    pub login: RateBucket,

    /// Per-operation bucket for `POST /revoke`. Ordinary limits -- `/revoke`
    /// is not exempt from rate limiting.
    pub revoke: RateBucket,

    /// The most keys the naked-revoke death set may hold. A naked revoke
    /// needs no prior knowledge of its key, so this quota (with the rate
    /// buckets) is what bounds the set; a revoke past it is refused `507`.
    pub max_dead_keys: u64,
}

/// The expected upstream-authority signing identity for witness-mode sync
/// (`ServerConfig::authority_identity`).
///
/// Verifiable key material -- `alg` names the signature algorithm and
/// `pub_key` is the raw public key `coz::verify_json` checks the patch
/// envelope's signature against. A bare thumbprint is deliberately NOT
/// sufficient: it identifies a key but cannot verify a signature. Mirrors
/// the `alg`/`pub` wire shape of [`crate::revoke::DisclosedKey`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityIdentity {
    /// The authority's signature algorithm (e.g. `Ed25519`).
    pub alg: String,
    /// The authority's public key bytes (base64url in JSON, wire field `pub`).
    #[serde(rename = "pub", with = "coz::b64")]
    pub pub_key: Vec<u8>,
}

/// A token-bucket rate: `per_second` cells replenished each second, up to a
/// `burst` capacity. Deserialized from a `{ per_second = N, burst = N }`
/// inline TOML table.
///
/// Unlike `max_body_bytes = 0` / `count_quota = 0` (rejected loudly at
/// startup by `resolve_config` -- a zero there silently bricks every request
/// or every principal's first commit), a `0` here is deliberately clamped to
/// the tightest live bucket rather than rejected: see `rate_limit`'s
/// `quota()` for the clamp and its rationale. A misconfigured rate stays
/// functional (merely very strict) rather than bricking writes, so it is
/// loosened, not refused.
#[derive(Debug, Clone, Copy, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateBucket {
    /// Sustained replenishment rate in requests per second.
    pub per_second: u32,
    /// Bucket capacity -- the largest instantaneous burst admitted.
    pub burst: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        // Conservative but comfortably above any legitimate single-client
        // burst: a real flood trips these, ordinary traffic never does. All
        // overridable per deployment.
        let reads = RateBucket {
            per_second: 100,
            burst: 200,
        };
        let writes = RateBucket {
            per_second: 50,
            burst: 100,
        };
        Self {
            max_body_bytes: 2 * 1024 * 1024,
            count_quota: 1_000_000,
            per_ip: reads,
            read: reads,
            push: writes,
            login: writes,
            revoke: writes,
            max_dead_keys: 1_000_000,
        }
    }
}

/// Admission policy for new-principal residency (see `admission`).
///
/// Selected by the `policy` tag of the `[admission]` TOML table. `Open`
/// (the default) installs no fence at all -- a bare server is permissionless.
///
/// Deserialized through [`AdmissionWire`] so that unknown keys are refused
/// even under `policy = "open"`: serde's internally tagged enums ignore
/// every key a *unit* variant does not name, which would let a misspelled
/// `polcy = "invite"` silently fall back to open admission.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "lowercase", from = "AdmissionWire")]
pub enum AdmissionConfig {
    /// No admission fence. The layer is absent, not an always-pass
    /// middleware; a new principal may take up residency without a token.
    #[default]
    Open,

    /// Single-use invite tokens. `tokens_path` is a deployment-managed file
    /// of `sha256(token)` hex lines; a new-principal genesis push must carry
    /// an `X-Cyphr-Invite` token whose hash is in that file and unspent.
    ///
    /// Single-use only by design; multi-use and expiring tokens are a
    /// deferred extension that fits this file+hash shape without a wire
    /// change -- see issue #117.
    Invite {
        /// Path to the deployment's `sha256(token)` hex-line file.
        tokens_path: PathBuf,
    },
}

/// Strict wire shape of [`AdmissionConfig`]: `Open` is a field-less struct
/// variant here so `deny_unknown_fields` applies to it.
#[derive(Deserialize)]
#[serde(tag = "policy", rename_all = "lowercase", deny_unknown_fields)]
enum AdmissionWire {
    Open {},
    Invite { tokens_path: PathBuf },
}

impl From<AdmissionWire> for AdmissionConfig {
    fn from(wire: AdmissionWire) -> Self {
        match wire {
            AdmissionWire::Open {} => Self::Open,
            AdmissionWire::Invite { tokens_path } => Self::Invite { tokens_path },
        }
    }
}

impl ServerConfig {
    /// True when this config is a witness pointed at an authority but has no
    /// [`AuthorityIdentity`] to verify its `/patch` responses against -- the
    /// sync channel is fully unauthenticated (K10 disabled). Not
    /// attacker-influenced (deployment configuration only, and
    /// `authority_identity` has no CLI/env override -- TOML only), so this
    /// is a deployment-safety gap rather than an attack: the fully
    /// unauthenticated path is a deliberate, documented backward-compatible
    /// mode (see `crate::sync`), not one this refuses to start -- it is
    /// surfaced as a loud, explicit warning instead.
    pub fn witness_authenticated_channel_unconfigured(&self) -> bool {
        self.mode == ServerMode::Witness
            && self.authority_url.is_some()
            && self.authority_identity.is_none()
    }

    /// The `record/` subtree: every store the server was told and cannot
    /// recover if lost (ADR-0002 Decision 1). Every durable-store
    /// construction site under `record/` joins onto this, so the grouping
    /// has exactly one place asserting where `record/` sits.
    pub fn record_dir(&self) -> PathBuf {
        self.data_dir.join(RECORD_DIR_NAME)
    }

    /// The blob database's path -- coz blobs, commit manifests, and every
    /// principal's EML commit-tree keyspaces (ADR-0002 Decision 1, 6: the
    /// EML commit tree is record data, not a derived projection).
    pub fn blobs_dir(&self) -> PathBuf {
        self.record_dir().join("blobs")
    }

    /// The naked-revoke observation store's path (the key death-set):
    /// server-local, told, and not derivable from any chain.
    pub fn observations_dir(&self) -> PathBuf {
        self.record_dir().join("observations")
    }

    /// The index database's path -- the sole derived-class member
    /// (ADR-0002 Decision 1, 6). Unchanged by the `record/` regroup: it
    /// stays a direct sibling of `record/`, the only directory an operator
    /// may ever `rm -rf`.
    pub fn index_dir(&self) -> PathBuf {
        self.data_dir.join("index")
    }
}

/// The `record/` subtree's directory name (ADR-0002 Decision 1) -- the
/// single spelling every construction site under `record/` joins onto,
/// shared with [`crate::auth::principal`] which builds its own sidecar
/// path from a bare `data_dir` rather than a [`ServerConfig`].
pub const RECORD_DIR_NAME: &str = "record";

/// The longest a login session may live: an hour.
pub const MAX_SESSION_TTL_SECS: i64 = 60 * 60;

fn default_session_ttl_secs() -> i64 {
    crate::auth::token::DEFAULT_TTL_SECS
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000".into(),
            transport_listen: None,
            data_dir: PathBuf::from("./data"),
            log_format: LogFormat::Pretty,
            mode: ServerMode::Authority,
            signing_key_path: None,
            audience: None,
            session_ttl_secs: default_session_ttl_secs(),
            authority_url: None,
            authority_identity: None,
            allow_cleartext_upstream: false,
            gossip: GossipConfig::default(),
            admission: AdmissionConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable, colorized output (development).
    Pretty,
    /// Structured JSON (production).
    Json,
}

/// Server operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    /// Accept and validate writes (`/push`).
    Authority,
    /// Read-only API; sync from a configured authority.
    Witness,
}

// ========================================================================
// Configuration resolution
// ========================================================================

/// Merge configuration layers: defaults → TOML → env/CLI.
///
/// Figment handles layers 1-2 (defaults, TOML file). Clap handles
/// layers 3-4 (env vars, CLI flags) — its internal precedence is
/// CLI > env > default, matching the desired order.
pub fn resolve_config(cli: &Cli) -> Result<ServerConfig, ConfigError> {
    use figment::Figment;
    use figment::providers::{Format, Serialized, Toml};

    // Layer 1: compiled defaults.
    let mut figment = Figment::new().merge(Serialized::defaults(ServerConfig::default()));

    // Layer 2: TOML config file (if it exists).
    if cli.config.exists() {
        figment = figment.merge(Toml::file(&cli.config));
    }

    let mut config: ServerConfig = figment
        .extract()
        .map_err(|e| ConfigError::Figment(Box::new(e)))?;

    // Silent-brick class: `#[serde(default)]` on every `[limits]` field means
    // an operator who writes (or omits, then overrides with) `max_body_bytes = 0` gets a server
    // that refuses every request body, and `count_quota = 0` gets a server that refuses every
    // principal's first commit -- both with no deserialization error, so both
    // must be checked explicitly here.
    if config.limits.max_body_bytes == 0 {
        return Err(ConfigError::LimitsMaxBodyBytesZero);
    }
    if config.limits.count_quota == 0 {
        return Err(ConfigError::LimitsCountQuotaZero);
    }
    if config.limits.max_dead_keys == 0 {
        return Err(ConfigError::LimitsMaxDeadKeysZero);
    }

    // Layers 3-4: env → CLI (clap resolves CLI > env internally).
    if let Command::RotateKey(ref args) = cli.command {
        if let Some(ref data_dir) = args.data_dir {
            config.data_dir = data_dir.clone();
        }
        if let Some(ref signing_key_path) = args.signing_key_path {
            config.signing_key_path = Some(signing_key_path.clone());
        }
    }
    if let Command::Backup { ref ops, .. }
    | Command::Restore { ref ops, .. }
    | Command::Export { ref ops, .. }
    | Command::VerifyAll { ref ops } = cli.command
    {
        if let Some(ref data_dir) = ops.data_dir {
            config.data_dir = data_dir.clone();
        }
        if let Some(ref signing_key_path) = ops.signing_key_path {
            config.signing_key_path = Some(signing_key_path.clone());
        }
    }
    if let Command::Serve(ref args) = cli.command {
        if let Some(ref listen) = args.listen {
            config.listen = listen.clone();
        }
        if let Some(ref transport_listen) = args.transport_listen {
            config.transport_listen = Some(transport_listen.clone());
        }
        if let Some(ref data_dir) = args.data_dir {
            config.data_dir = data_dir.clone();
        }
        if let Some(log_format) = args.log_format {
            config.log_format = log_format;
        }
        if let Some(mode) = args.mode {
            config.mode = mode;
        }
        if let Some(ref signing_key_path) = args.signing_key_path {
            config.signing_key_path = Some(signing_key_path.clone());
        }
        if let Some(ref audience) = args.audience {
            config.audience = Some(audience.clone());
        }
        if let Some(ttl) = args.session_ttl_secs {
            config.session_ttl_secs = ttl;
        }
        if let Some(ref authority_url) = args.authority_url {
            config.authority_url = Some(authority_url.clone());
        }
        if !args.gossip_peers.is_empty() {
            config.gossip.peers = args.gossip_peers.clone();
        }
        if let Some(interval) = args.gossip_interval_secs {
            config.gossip.interval_secs = interval;
        }
        if args.allow_cleartext_upstream {
            config.allow_cleartext_upstream = true;
        }
    }

    // An upstream the server would dial in cleartext is refused here, at
    // startup, rather than discovered as a stalled sync.
    if config.gossip.interval_secs == 0 {
        return Err(ConfigError::GossipIntervalZero);
    }
    for url in config.authority_url.iter().chain(&config.gossip.peers) {
        cyphr_client::HttpConnector::check_url(url, config.allow_cleartext_upstream).map_err(
            |source| match source {
                cyphr_client::ConnectError::CleartextRefused { host } => {
                    ConfigError::CleartextUpstream {
                        url: url.clone(),
                        host,
                    }
                },
                other => ConfigError::UpstreamUrl {
                    url: url.clone(),
                    reason: other.to_string(),
                },
            },
        )?;
    }

    // Deployment-safety warning, not a refusal to start (see
    // `witness_authenticated_channel_unconfigured`'s doc): `eprintln!`
    // rather than `tracing::warn!` because this runs before
    // `logging::init_tracing` (see `main.rs`), so a tracing event here could
    // be silently dropped by the default no-op subscriber -- this must reach
    // an operator regardless of log configuration.
    if config.witness_authenticated_channel_unconfigured() {
        eprintln!(
            "WARNING: witness mode is configured with an authority_url but no \
             [authority_identity] -- the sync channel is UNAUTHENTICATED (K10 disabled). An \
             on-path party can forge, withhold, or substitute /patch entries with no \
             verification. Configure an [authority_identity] table (alg + pub) in the TOML config \
             file to enable the authenticated channel."
        );
    }

    Ok(config)
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Figment extraction failed (bad TOML, type mismatch, etc.).
    #[error("configuration: {0}")]
    Figment(Box<figment::Error>),

    /// `mode = "witness"` was configured for `serve`, but witness mode has
    /// no enforcement anywhere in the server yet.
    #[allow(dead_code)]
    #[error(
        "witness mode is not yet implemented -- no route or handler enforces \
         read-only/sync-from-authority behavior; use mode = \"authority\" (the default)"
    )]
    WitnessModeUnimplemented,

    /// `[limits] max_body_bytes = 0` was configured, which refuses every
    /// request body before any handler runs.
    #[error(
        "limits.max_body_bytes is 0 -- this refuses every request body; set it to the intended \
         cap in bytes (the default is 2 MiB)"
    )]
    LimitsMaxBodyBytesZero,

    /// `[limits] count_quota = 0` was configured, which refuses every
    /// principal's first commit.
    #[error(
        "limits.count_quota is 0 -- this refuses every principal's first commit; set it to the \
         intended per-principal commit cap"
    )]
    LimitsCountQuotaZero,

    /// An upstream (the witness authority or a gossip peer) is plain
    /// `http://` to a host that is not loopback.
    #[error(
        "upstream {url} is plain http to non-loopback host `{host}`: a tip report or patch could \
         be rewritten in transit; use https, or set `allow_cleartext_upstream = true` \
         (--allow-cleartext-upstream) to accept that"
    )]
    CleartextUpstream {
        /// The configured URL.
        url: String,
        /// The host it names.
        host: String,
    },

    /// An upstream URL is not a usable `http(s)://host` URL.
    #[error("upstream {url} is not usable: {reason}")]
    UpstreamUrl {
        /// The configured URL.
        url: String,
        /// Why it cannot be used.
        reason: String,
    },

    /// `[gossip] interval_secs = 0` was configured, which would spin the
    /// gossip loop.
    #[error("gossip.interval_secs is 0 -- set it to the seconds between gossip rounds")]
    GossipIntervalZero,

    /// `[limits] max_dead_keys = 0` was configured, which refuses every
    /// naked revoke.
    #[error(
        "limits.max_dead_keys is 0 -- this refuses every naked revoke; set it to the intended cap \
         on the death set"
    )]
    LimitsMaxDeadKeysZero,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid CLI args")
    }

    /// Backs: operator-visible `--signing-key` flag reaches `ServerConfig` (a keyed server is only
    /// reachable via it). Unit: `serve()` boots a socket; the CLI-to-config resolution is a pure
    /// function.
    #[test]
    fn serve_with_signing_key_flag_resolves_the_path() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
            "--signing-key-path",
            "/etc/cyphr/signing-key.json",
        ]);
        let config = resolve_config(&cli).expect("resolve succeeds");
        assert_eq!(
            config.signing_key_path,
            Some(PathBuf::from("/etc/cyphr/signing-key.json"))
        );
    }

    /// Backs: operator-visible `--audience` flag reaches `ServerConfig` (sign-on audience binding,
    /// SPEC 17.2). Unit: `serve()` boots a socket; the CLI-to-config resolution is a pure function.
    #[test]
    fn serve_with_audience_flag_resolves_it() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
            "--audience",
            "cyphr.me",
        ]);
        let config = resolve_config(&cli).expect("resolve succeeds");
        assert_eq!(config.audience, Some("cyphr.me".to_string()));
    }

    /// Build a `Cli` for `serve` pointing at a TOML file carrying the given
    /// `[admission]` table body.
    fn parse_with_admission_table(tmp: &std::path::Path, admission_table: &str) -> Cli {
        let config_path = tmp.join("cyphr-server.toml");
        std::fs::write(&config_path, admission_table).expect("write config");
        Cli {
            config: config_path,
            command: Command::Serve(ServeArgs {
                listen: None,
                transport_listen: None,
                data_dir: None,
                log_format: None,
                mode: None,
                signing_key_path: None,
                audience: None,
                authority_url: None,
                gossip_peers: Vec::new(),
                gossip_interval_secs: None,
                allow_cleartext_upstream: false,
            }),
        }
    }

    /// Proof-of-work admission was removed; a deployment config still naming
    /// it must fail loudly at resolution, never fall back to another policy
    /// (which would silently change who may take up residency). Scenario:
    /// the operator's stale config file against the current binary.
    #[test]
    fn removed_pow_policy_is_a_config_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(
            tmp.path(),
            "[admission]\npolicy = \"pow\"\ndifficulty = 18\n",
        );
        let result = resolve_config(&cli);
        assert!(
            matches!(&result, Err(ConfigError::Figment(e)) if e.to_string().contains("pow")),
            "a config naming the removed pow policy must be a typed config error, got: {result:?}"
        );
    }

    /// A `max_body_bytes` of 0 refuses every request body, silently bricking
    /// all writes (and reads with a body). Serde happily deserializes it, so
    /// `resolve_config` must reject it explicitly (see `ConfigError::LimitsMaxBodyBytesZero`).
    #[test]
    fn limits_max_body_bytes_zero_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(tmp.path(), "[limits]\nmax_body_bytes = 0\n");
        let result = resolve_config(&cli);
        assert!(
            result.is_err(),
            "a limits max_body_bytes of 0 (which refuses every body) must be rejected at \
             resolution, got: {result:?}"
        );
    }

    /// A `count_quota` of 0 refuses every principal's first commit, silently
    /// bricking all writes; it must be rejected at `resolve_config` exactly as
    /// the zero body cap is (see `ConfigError::LimitsCountQuotaZero`).
    #[test]
    fn limits_count_quota_zero_is_rejected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(tmp.path(), "[limits]\ncount_quota = 0\n");
        let result = resolve_config(&cli);
        assert!(
            result.is_err(),
            "a limits count_quota of 0 (which refuses every principal's first commit) must be \
             rejected at resolution, got: {result:?}"
        );
    }

    /// A witness pointed at an authority with no `[authority_identity]` is
    /// the fully unauthenticated (K10-disabled) sync path -- a deliberate,
    /// documented backward-compatible mode, so `resolve_config` must still
    /// succeed (this is a warning, not a refusal to start), but the gap
    /// must be DETECTED so `main` can surface it loudly.
    #[test]
    fn witness_with_authority_url_and_no_identity_resolves_but_is_flagged() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
            "--mode",
            "witness",
            "--authority-url",
            "http://127.0.0.1:1",
        ]);
        let config = resolve_config(&cli)
            .expect("an unauthenticated witness sync path must not be refused at startup");
        assert!(
            config.witness_authenticated_channel_unconfigured(),
            "a witness with authority_url set and no authority_identity must be flagged"
        );
    }

    /// GUARD: a witness with a correctly configured `authority_identity`
    /// must NOT be flagged -- nothing else pinned that a correctly
    /// configured K10 witness avoids the `UNAUTHENTICATED` startup warning
    /// (`resolve_config`'s `eprintln!`); the other three tests each hold
    /// `authority_identity` at its default `None`, so clause 3
    /// (`authority_identity.is_none()`) was unexercised by every one of
    /// them. `authority_identity` has no CLI/env override (TOML only), so
    /// this constructs the resolved config directly rather than via `parse`.
    #[test]
    fn witness_with_configured_identity_is_not_flagged() {
        let config = ServerConfig {
            mode: ServerMode::Witness,
            authority_url: Some("http://127.0.0.1:1".to_string()),
            authority_identity: Some(AuthorityIdentity {
                alg: "Ed25519".to_string(),
                pub_key: vec![0u8; 32],
            }),
            ..Default::default()
        };
        assert!(
            !config.witness_authenticated_channel_unconfigured(),
            "a witness with a configured authority_identity has an authenticated channel and must \
             not be flagged as unauthenticated"
        );
    }
}
