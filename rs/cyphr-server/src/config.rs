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

    /// Export a principal's data.
    Export {
        /// Principal genesis identifier.
        pr: String,

        /// Data directory containing blob storage.
        #[arg(long, env = "CYPHR_DATA_DIR")]
        data_dir: Option<PathBuf>,
    },

    /// Manage invite tokens (admission policy `invite`).
    Invite {
        #[command(subcommand)]
        action: InviteAction,
    },
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

    /// Target authority URL for witness mode sync.
    #[arg(long, env = "CYPHR_AUTHORITY_URL")]
    pub authority_url: Option<String>,
}

// ========================================================================
// Resolved configuration
// ========================================================================

/// Fully-resolved server configuration.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address.
    pub listen: String,

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

    /// Target authority URL for witness mode sync.
    #[serde(default)]
    pub authority_url: Option<String>,

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

/// Resource-fence limits (the `[limits]` TOML table). Additive to
/// `[admission]` and mirroring its structured-config pattern; consumed only by
/// the `rate_limit` fences composed in [`crate::serve`], never by a protocol
/// handler.
///
/// `#[serde(default)]` makes every field independently omittable, so a partial
/// `[limits]` table tunes one fence and inherits defaults for the rest.
#[derive(Debug, Clone, serde::Serialize, Deserialize)]
#[serde(default)]
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
        }
    }
}

/// Admission policy for new-principal residency (see `admission`).
///
/// Selected by the `policy` tag of the `[admission]` TOML table. `Open`
/// (the default) installs no fence at all -- a bare server is permissionless.
#[derive(Debug, Clone, Default, serde::Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "lowercase")]
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

    /// Stateless proof-of-work admission. A new-principal genesis push must
    /// carry an `X-Cyphr-Pow` nonce whose `blake3` hashcash, bound to the
    /// principal id and the current UTC-hour window, clears `difficulty`
    /// leading zero bits (see `admission`). No server state, no challenge
    /// endpoint -- the server verifies with a single hash.
    Pow {
        /// Target difficulty in leading zero *bits* of the hashcash digest.
        #[serde(default)]
        difficulty: u32,
    },
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("./data"),
            log_format: LogFormat::Pretty,
            mode: ServerMode::Authority,
            signing_key_path: None,
            audience: None,
            authority_url: None,
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

    // A pow difficulty of 0 makes every well-formed nonce admit (the
    // anti-Sybil fence is silently disabled); a difficulty above the
    // blake3 digest's 256 bits is unsatisfiable by any nonce (new-principal
    // onboarding is silently and permanently closed). `#[serde(default)]`
    // on `difficulty` means an operator who omits it from the TOML table
    // gets 0 with no error, so this must be checked explicitly rather than
    // relying on deserialization to catch it.
    if let AdmissionConfig::Pow { difficulty } = config.admission {
        if difficulty == 0 || difficulty > 256 {
            return Err(ConfigError::PowDifficultyInvalid(difficulty));
        }
    }

    // The same silent-brick class as a zero pow difficulty: `#[serde(default)]`
    // on every `[limits]` field means an operator who writes (or omits, then
    // overrides with) `max_body_bytes = 0` gets a server that refuses every
    // request body, and `count_quota = 0` gets a server that refuses every
    // principal's first commit -- both with no deserialization error, so both
    // must be checked explicitly here.
    if config.limits.max_body_bytes == 0 {
        return Err(ConfigError::LimitsMaxBodyBytesZero);
    }
    if config.limits.count_quota == 0 {
        return Err(ConfigError::LimitsCountQuotaZero);
    }

    // Layers 3-4: env → CLI (clap resolves CLI > env internally).
    if let Command::Serve(ref args) = cli.command {
        if let Some(ref listen) = args.listen {
            config.listen = listen.clone();
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
        if let Some(ref authority_url) = args.authority_url {
            config.authority_url = Some(authority_url.clone());
        }
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

    /// `[admission] policy = "pow"` was configured with a `difficulty` outside
    /// the satisfiable range: 0 (every nonce admits -- the anti-Sybil fence is
    /// silently off) or greater than 256 (no nonce can ever clear a blake3
    /// digest's 256 bits -- new-principal onboarding is silently and
    /// permanently closed).
    #[error(
        "admission pow difficulty {0} is invalid -- must be in 1..=256 leading zero bits (0 \
         admits every nonce; blake3 digests are only 256 bits, so >256 admits none)"
    )]
    PowDifficultyInvalid(u32),

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid CLI args")
    }

    #[test]
    fn serve_with_witness_mode_starts() {
        let cli = parse(&["cyphr-server", "serve", "--mode", "witness"]);
        let config =
            resolve_config(&cli).expect("witness mode configuration MUST resolve successfully");
        assert_eq!(config.mode, ServerMode::Witness);
    }

    #[test]
    fn serve_with_authority_mode_succeeds() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
            "--mode",
            "authority",
        ]);
        let config = resolve_config(&cli).expect("authority mode must resolve successfully");
        assert_eq!(config.mode, ServerMode::Authority);
    }

    #[test]
    fn serve_without_signing_key_flag_leaves_it_unset() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
        ]);
        let config = resolve_config(&cli).expect("resolve succeeds");
        assert_eq!(config.signing_key_path, None);
    }

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

    #[test]
    fn serve_without_audience_flag_leaves_it_unset() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
        ]);
        let config = resolve_config(&cli).expect("resolve succeeds");
        assert_eq!(config.audience, None);
    }

    #[test]
    fn serve_with_default_mode_succeeds() {
        // No --mode flag at all: falls back to the compiled default
        // (Authority), which must not be rejected.
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
        ]);
        let config = resolve_config(&cli).expect("default mode must resolve successfully");
        assert_eq!(config.mode, ServerMode::Authority);
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
                data_dir: None,
                log_format: None,
                mode: None,
                signing_key_path: None,
                audience: None,
                authority_url: None,
            }),
        }
    }

    #[test]
    fn pow_difficulty_zero_is_rejected() {
        // `#[serde(default)]` on `difficulty` means omitting it -- or writing
        // it explicitly -- as 0 must not silently disable the anti-Sybil
        // fence (leading_zero_bits(..) >= 0 is always true).
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(tmp.path(), "[admission]\npolicy = \"pow\"\n");
        let result = resolve_config(&cli);
        assert!(
            matches!(result, Err(ConfigError::PowDifficultyInvalid(0))),
            "an omitted (default-0) pow difficulty must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn pow_difficulty_above_256_is_rejected() {
        // blake3 digests are 256 bits; a difficulty above that is
        // unsatisfiable by any nonce -- a silent, permanent onboarding outage.
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(
            tmp.path(),
            "[admission]\npolicy = \"pow\"\ndifficulty = 300\n",
        );
        let result = resolve_config(&cli);
        assert!(
            matches!(result, Err(ConfigError::PowDifficultyInvalid(300))),
            "a pow difficulty above 256 must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn pow_difficulty_in_valid_range_resolves() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(
            tmp.path(),
            "[admission]\npolicy = \"pow\"\ndifficulty = 18\n",
        );
        let config =
            resolve_config(&cli).expect("a pow difficulty within 1..=256 must resolve cleanly");
        assert!(
            matches!(config.admission, AdmissionConfig::Pow { difficulty } if difficulty == 18),
            "must resolve to AdmissionConfig::Pow carrying the configured difficulty, got: {:?}",
            config.admission
        );
    }

    /// A `max_body_bytes` of 0 refuses every request body, silently bricking
    /// all writes (and reads with a body). Like the pow-difficulty zero case,
    /// serde happily deserializes it, so `resolve_config` must reject it
    /// explicitly (see `ConfigError::LimitsMaxBodyBytesZero`).
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

    /// GUARD (green today and after): a `[limits]` table with non-zero caps
    /// resolves cleanly -- the zero-rejection must reject ONLY the degenerate
    /// values, never a valid configuration.
    #[test]
    fn limits_valid_values_resolve_ok() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cli = parse_with_admission_table(
            tmp.path(),
            "[limits]\nmax_body_bytes = 1048576\ncount_quota = 500\n",
        );
        let config = resolve_config(&cli).expect("a valid [limits] table must resolve cleanly");
        assert_eq!(config.limits.max_body_bytes, 1_048_576);
        assert_eq!(config.limits.count_quota, 500);
    }
}
