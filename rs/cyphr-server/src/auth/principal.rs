//! The server's own Cyphr principal.
//!
//! When the server is keyed, its signing key is more than a bare keypair:
//! it is the sole genesis key of an explicit Level-3 principal whose
//! Principal Genesis (PG) is a stable, rotation-surviving identifier. This
//! module creates that principal on first keyed boot, loads it on later
//! boots, and exercises key rotation on its own chain — all through the
//! ordinary validated storage path, so the server is an ordinary principal
//! in its own store (SPEC.md §3.7.1, §5.1).
//!
//! Keyless operation is unaffected: with no signing key there is no
//! principal and nothing here runs.

use std::path::Path;
use std::sync::Arc;

use super::ServerIdentity;

/// `first_seen` stamped on the server's genesis key. Fixed (not wall-clock)
/// so the genesis key — and therefore the PG derived from it — is
/// reproducible: the same signing key always yields the same principal.
pub const GENESIS_FIRST_SEEN: i64 = 0;

/// The concrete storage engine the server runs on.
type ServerEngine = cyphr_storage::engine::StorageEngine<
    cyphr_blob_fjall::FjallBlobStore,
    cyphr_index_fjall::FjallIndexer,
    cyphr_blob_fjall::storage_fjall::FjallStorage,
>;

/// Errors bootstrapping or rotating the server's own principal.
#[derive(Debug, thiserror::Error)]
pub enum ServerPrincipalError {
    /// The storage engine rejected a read or write.
    #[error("server principal storage: {0}")]
    Engine(#[from] cyphr_storage::engine::EngineError),

    /// Chain construction or replay failed in the core protocol.
    #[error("server principal chain: {0}")]
    Chain(#[from] cyphr::Error),

    /// Reading or writing the on-disk genesis record failed.
    #[error("server principal genesis record io: {0}")]
    Io(#[from] std::io::Error),

    /// The genesis record was not valid JSON in the expected shape.
    #[error("server principal genesis record malformed: {0}")]
    Malformed(#[from] serde_json::Error),

    /// coz rejected the server key while signing a chain coz.
    #[error("server key cannot sign chain cozies for algorithm {0}")]
    Signing(String),

    /// A persisted genesis record does not match the configured key, or
    /// its chain is missing from storage — the data directory and key file
    /// have drifted apart.
    #[error("server principal genesis record does not match the configured key or its chain")]
    RecordMismatch,
}

/// The server acting as its own Cyphr principal.
///
/// Holds the stable PG (the engine `principal_id` under which the chain is
/// served) and the material needed to reload and extend that chain. The
/// private signing key stays inside [`ServerIdentity`].
pub struct ServerPrincipal {
    identity: Arc<ServerIdentity>,
    pg: String,
    genesis_key: cyphr::Key,
}

impl ServerPrincipal {
    /// Create the server's principal on first keyed boot, or load it on a
    /// later boot. Idempotent: a second boot with the same key finds the
    /// existing chain and creates no duplicate.
    pub async fn bootstrap(
        _engine: &ServerEngine,
        identity: Arc<ServerIdentity>,
        _data_dir: &Path,
    ) -> Result<Self, ServerPrincipalError> {
        // STUB: real bootstrap not yet implemented.
        Ok(Self {
            identity,
            pg: String::new(),
            genesis_key: cyphr::Key {
                alg: String::new(),
                tmb: coz::Thumbprint::from_bytes(Vec::new()),
                pub_key: Vec::new(),
                first_seen: 0,
                last_used: None,
                revocation: None,
                tag: None,
            },
        })
    }

    /// The server principal's stable tagged PG — the identifier its chain
    /// is served under (`engine.get_tip(pg)`).
    pub fn pg(&self) -> &str {
        &self.pg
    }

    /// The sole genesis key (public material), needed to reload or
    /// independently verify the chain via `Genesis::Explicit`.
    pub fn genesis_key(&self) -> &cyphr::Key {
        &self.genesis_key
    }

    /// Rotate the server's signing key on its own chain: activate
    /// `new_keypair`, retire the current key, leave the PG unchanged.
    pub async fn rotate(
        &self,
        _engine: &ServerEngine,
        _new_keypair: &coz::KeyPair,
    ) -> Result<(), ServerPrincipalError> {
        // STUB: real rotation not yet implemented.
        let _ = &self.identity;
        let _ = &self.genesis_key;
        Err(ServerPrincipalError::RecordMismatch)
    }
}
