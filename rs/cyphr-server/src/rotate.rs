//! The offline `rotate-key` command and the boot-time reconciliation that
//! makes it crash-safe.
//!
//! Both only change how the file at `signing_key_path` is replaced; where
//! and in what format the key lives is untouched. The crash-safe order
//! itself lives in [`ServerPrincipal::rotate`].

use std::path::PathBuf;
use std::sync::Arc;

use cyphr_server::AppState;
use cyphr_server::auth::principal::{KeyReconciliation, ServerPrincipal};
use cyphr_server::auth::{ServerIdentity, next_key_path};
use cyphr_server::config::ServerConfig;

type BoxError = Box<dyn std::error::Error>;

/// The key file `config` names, or a typed explanation of its absence.
fn key_path(config: &ServerConfig) -> Result<PathBuf, BoxError> {
    config
        .signing_key_path
        .clone()
        .ok_or_else(|| "no signing key path configured (--signing-key-path)".into())
}

/// Finish or abandon a rotation interrupted by a crash, before the key
/// file is loaded. A no-op (the engine is not even opened) when no
/// `.next` exists, which is every boot but the one after a crash.
pub async fn reconcile(config: &ServerConfig) -> Result<(), BoxError> {
    let Some(path) = config.signing_key_path.clone() else {
        return Ok(());
    };
    if !next_key_path(&path).exists() {
        return Ok(());
    }
    // `state` holds the store open; it is dropped on return so `serve`
    // (or the rotation) can take the data directory afterwards.
    let state = AppState::new(config.clone())?;
    let outcome =
        ServerPrincipal::reconcile_key_file(&state.engine, &path, &config.data_dir).await?;
    match outcome {
        KeyReconciliation::Adopted => {
            tracing::warn!(path = %path.display(), "completed an interrupted key rotation");
        },
        KeyReconciliation::Discarded => {
            tracing::warn!(
                path = %path.display(),
                "discarded a staged key the chain does not know (interrupted rotation)"
            );
        },
        KeyReconciliation::Clean => {},
    }
    Ok(())
}

/// Rotate the server's signing key on a stopped server and report the
/// rotated-in key's thumbprint. The new key is generated here with the
/// current key's algorithm.
pub async fn rotate_key(config: ServerConfig) -> Result<String, BoxError> {
    let path = key_path(&config)?;
    reconcile(&config).await?;

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
