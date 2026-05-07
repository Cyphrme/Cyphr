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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000".into(),
            data_dir: PathBuf::from("./data"),
            log_format: LogFormat::Pretty,
            mode: ServerMode::Authority,
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

    let mut config: ServerConfig = figment.extract().map_err(ConfigError::Figment)?;

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
    }

    Ok(config)
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Figment extraction failed (bad TOML, type mismatch, etc.).
    #[error("configuration: {0}")]
    Figment(figment::Error),
}
