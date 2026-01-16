//! Error types for test fixture operations.

use thiserror::Error;

/// Errors that can occur during fixture operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Failed to read file.
    #[error("failed to read file: {path}")]
    Read {
        /// File path.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse TOML.
    #[error("failed to parse TOML: {path}")]
    TomlParse {
        /// File path.
        path: String,
        /// Underlying parse error.
        #[source]
        source: toml::de::Error,
    },

    /// Failed to parse JSON.
    #[error("failed to parse JSON: {path}")]
    JsonParse {
        /// File path.
        path: String,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },

    /// Key not found in pool.
    #[error("key not found in pool: {name}")]
    KeyNotFound {
        /// Key name.
        name: String,
    },

    /// Pool validation failed.
    #[error("pool validation failed: {message}")]
    PoolValidation {
        /// Validation error message.
        message: String,
    },

    /// Signing failed.
    #[error("signing failed: {message}")]
    Signing {
        /// Error message.
        message: String,
    },
}
