//! The offline `rotate-key` command. Its crash safety rests on the boot-time
//! reconciliation, which lives in the library ([`reconcile_key_rotation`],
//! run by `serve`) so an embedder gets it too.
//!
//! It only changes how the file at `signing_key_path` is replaced; where
//! and in what format the key lives is untouched. The crash-safe order
//! itself lives in [`ServerPrincipal::rotate`].

use std::path::PathBuf;
use std::sync::Arc;

use cyphr_server::auth::ServerIdentity;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::{AppState, reconcile_key_rotation};

type BoxError = Box<dyn std::error::Error>;

/// The key file `config` names, or a typed explanation of its absence.
fn key_path(config: &ServerConfig) -> Result<PathBuf, BoxError> {
    config
        .signing_key_path
        .clone()
        .ok_or_else(|| "no signing key path configured (--signing-key-path)".into())
}

/// Rotate the server's signing key on a stopped server and report the
/// rotated-in key's thumbprint. The new key is generated here with the
/// current key's algorithm.
pub async fn rotate_key(config: ServerConfig) -> Result<String, BoxError> {
    let path = key_path(&config)?;
    reconcile_key_rotation(&config).await?;
    // Rotating a never-booted data directory would mint a genesis as a side
    // effect of an offline command; refuse instead.
    ServerPrincipal::require_established(&config.data_dir)?;

    let mut state = AppState::new(config)?;
    let identity: Arc<ServerIdentity> = state
        .identity
        .clone()
        .ok_or("server has no signing identity")?;
    let new_keypair = identity.alg().generate_keypair();
    let principal =
        ServerPrincipal::bootstrap(&state.engine, identity, &path, &state.config.data_dir).await?;
    let pg = principal.pg().to_string();
    state.principal = Some(Arc::new(principal));
    state.rotate_signing_key(&new_keypair).await?;

    let tmb = new_keypair
        .alg
        .compute_thumbprint(&new_keypair.pub_bytes)
        .ok_or("cannot compute the new key's thumbprint")?;
    Ok(format!("rotated {pg} to key {}", tmb.to_b64()))
}
