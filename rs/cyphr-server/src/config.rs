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

    /// How this witness treats a *third-party* naked revoke (an outsider
    /// declaring a principal's key compromised, SPEC §6.4). Self-signed
    /// revokes are always accepted and always block the key at login; only
    /// the third-party disposition is a policy choice. Defaults to
    /// [`ThirdPartyRevokePolicy::RecordOnly`].
    #[serde(default)]
    pub third_party_naked_revoke: ThirdPartyRevokePolicy,
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
            third_party_naked_revoke: ThirdPartyRevokePolicy::default(),
        }
    }
}

/// A witness's disposition toward a *third-party* naked revoke (SPEC §6.4).
///
/// The literal §6.4 reading -- any naked revoke freezes the principal -- is
/// an unauthenticated griefing vector for the third-party case, so a
/// witness never auto-freezes on an outsider's claim (spec clarification
/// pending forge issue #106). The only choice is whether to retain the
/// claim or decline it; freezing is deliberately not an option here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyRevokePolicy {
    /// Record and surface the claim, but never block the key's login or
    /// freeze the principal. The default, anti-griefing posture.
    #[default]
    RecordOnly,
    /// Decline third-party naked revokes outright (4xx) -- for a deployment
    /// that will not store unauthenticated outsider claims at all.
    Reject,
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

        // Witness mode is parsed but has no enforcement anywhere in the
        // server (no route or handler reads `config.mode` at all) --
        // silently accepting it would let a deployer believe they've
        // configured a read-only, sync-from-authority server when
        // nothing about that behavior actually exists yet.
        if config.mode == ServerMode::Witness {
            return Err(ConfigError::WitnessModeUnimplemented);
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
    #[error(
        "witness mode is not yet implemented -- no route or handler enforces \
         read-only/sync-from-authority behavior; use mode = \"authority\" (the default)"
    )]
    WitnessModeUnimplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid CLI args")
    }

    #[test]
    fn serve_with_witness_mode_is_rejected() {
        let cli = parse(&[
            "cyphr-server",
            "--config",
            "/nonexistent-config-for-test.toml",
            "serve",
            "--mode",
            "witness",
        ]);
        let result = resolve_config(&cli);
        assert!(
            matches!(result, Err(ConfigError::WitnessModeUnimplemented)),
            "witness mode must be rejected at config-resolution time, got: {result:?}"
        );
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
}
