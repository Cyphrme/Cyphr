//! Structured logging initialization (tracing ecosystem).
//!
//! All output goes to stderr per Factor XI (logs as event streams,
//! not files). The composable registry architecture means future
//! layers (OpenTelemetry, Jaeger, etc.) are additive — no rewrites.

use crate::config::{LogFormat, ServerConfig};

/// Initialize the global tracing subscriber.
///
/// - `RUST_LOG` env var controls filtering (default: `cyphr_server=info,tower_http=info`).
/// - Log format is switchable via [`LogFormat`]: `pretty` for development, `json` for production.
/// - Uses `Option` layers for type-safe conditional composition.
pub fn init_tracing(config: &ServerConfig) {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cyphr_server=info,tower_http=info"));

    let json_layer = matches!(config.log_format, LogFormat::Json)
        .then(|| fmt::layer().json().with_writer(std::io::stderr));

    let pretty_layer = matches!(config.log_format, LogFormat::Pretty)
        .then(|| fmt::layer().with_writer(std::io::stderr));

    tracing_subscriber::registry()
        .with(filter)
        .with(json_layer)
        .with(pretty_layer)
        .init();
}
