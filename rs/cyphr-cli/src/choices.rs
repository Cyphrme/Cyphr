//! The verifier's choices file: the trust decisions a person makes once and
//! reuses (which anchor, which peers, how fresh a view must be).
//!
//! The file is TOML and strict: an unknown key is refused rather than
//! ignored, because a misspelled `peers` that silently yields no peers would
//! turn the person's decision into the tool's default.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Choices read from a file. Every field is optional; flags override them.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Choices {
    /// The trust anchor the history must contain.
    pub anchor: Option<String>,
    /// Peers to ask, as base URLs.
    #[serde(default)]
    pub peers: Vec<String>,
    /// View age (seconds) beyond which an answer reports the view as stale.
    pub freshness_secs: Option<u64>,
}

/// Why a choices file was refused.
#[derive(Debug, thiserror::Error)]
pub enum ChoicesError {
    /// The file could not be read.
    #[error("cannot read choices file {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML of the expected shape (including an
    /// unknown key).
    #[error("malformed choices file {}: {source}", path.display())]
    Malformed {
        /// The file.
        path: PathBuf,
        /// The cause.
        #[source]
        source: toml::de::Error,
    },
}

impl ChoicesError {
    /// The refusal kind this error reports under `--output json`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Read { .. } => "other",
            Self::Malformed { .. } => "malformed",
        }
    }
}

impl Choices {
    /// Read and parse the choices file at `path`.
    ///
    /// # Errors
    ///
    /// [`ChoicesError::Read`] when the file cannot be read;
    /// [`ChoicesError::Malformed`] for invalid TOML, a wrongly typed value or
    /// an unknown key.
    pub fn load(path: &Path) -> Result<Self, ChoicesError> {
        let text = std::fs::read_to_string(path).map_err(|source| ChoicesError::Read {
            path: path.to_owned(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ChoicesError::Malformed {
            path: path.to_owned(),
            source,
        })
    }
}
