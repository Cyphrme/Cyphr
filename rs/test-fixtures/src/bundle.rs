//! Conformant wire bundles for tests that drive the storage engine or a
//! server: every chain begins with its genesis commit (SPEC 5.1), so a test
//! builds that first and pushes its bundle before any other.

use crate::{Error, PoolKey};

/// Commit `principal`'s genesis signed by its genesis key `genesis` (SPEC
/// 5.1-5.3) and return the commit's wire blobs in order: each `key/create`
/// (disclosing its key), the `principal/create` and the `commit/create`.
///
/// # Errors
///
/// `Generation` if the core refuses the genesis (e.g. `genesis` is not the
/// principal's first key) or a coz does not serialize; as
/// [`PoolKey::software_signer`] otherwise.
pub fn genesis_bundle(
    principal: &mut cyphr::Principal,
    genesis: &PoolKey,
    now: i64,
) -> Result<Vec<Vec<u8>>, Error> {
    let failed = |reason: String| Error::Generation {
        name: genesis.name.clone(),
        reason,
    };
    principal
        .commit_genesis(&genesis.software_signer()?, now, "cyphr.me")
        .map_err(|e| failed(format!("genesis commit: {e}")))?
        .iter()
        .map(|coz| serde_json::to_vec(coz).map_err(|e| failed(format!("wire coz: {e}"))))
        .collect()
}
