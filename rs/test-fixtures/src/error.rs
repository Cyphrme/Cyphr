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

    /// Key reference not found in pool.
    #[error("key '{name}' not found in pool")]
    KeyRef {
        /// Key name that was not found.
        name: String,
    },

    /// Private key required but not present.
    #[error("key '{name}' requires private key for signing")]
    MissingPrivateKey {
        /// Key name.
        name: String,
    },

    /// Algorithm not supported.
    #[error("unsupported algorithm '{alg}'")]
    UnsupportedAlgorithm {
        /// Algorithm name.
        alg: String,
    },

    /// Generation failed.
    #[error("generation failed for test '{name}': {reason}")]
    Generation {
        /// Test name.
        name: String,
        /// Failure reason.
        reason: String,
    },

    /// Genesis-time principal construction failed, with the underlying
    /// protocol error preserved so a genesis-error test intent's declared
    /// `expected.error` can be validated against what genesis actually
    /// raised, rather than trusted verbatim.
    #[error("failed to create principal for test '{name}': {source}")]
    GenesisFailed {
        /// Test name.
        name: String,
        /// The underlying protocol error genesis construction raised.
        #[source]
        source: cyphr::error::Error,
    },

    /// A test intent's declared `expected.error` does not match the error
    /// genesis construction actually raised.
    #[error(
        "test '{name}': declared expected.error '{declared}' does not \
         match actual genesis error '{actual}' ({source})"
    )]
    DeclaredErrorMismatch {
        /// Test name.
        name: String,
        /// The `expected.error` string declared in the test intent.
        declared: String,
        /// The canonical name of the error genesis actually raised.
        actual: &'static str,
        /// The underlying protocol error genesis construction raised.
        #[source]
        source: cyphr::error::Error,
    },

    /// Invalid intent structure.
    #[error("invalid intent: {message}")]
    InvalidIntent {
        /// Error message.
        message: String,
    },
}
