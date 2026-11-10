//! Conformant wire bundles for tests that drive the storage engine or a
//! server: every chain begins with its genesis commit (SPEC 5.1), so a test
//! builds that first and pushes its bundle before any other.

use crate::{Error, PoolKey};

/// Commit `principal`'s genesis signed by its genesis key `genesis`,
/// creating each of `others` after it (SPEC 5.1-5.3), and return the
/// commit's wire blobs in order: each `key/create` (disclosing its key),
/// the `principal/create` and the `commit/create`.
///
/// # Errors
///
/// `Generation` if the core refuses the genesis (e.g. `genesis` is not the
/// principal's genesis key) or a coz does not serialize; as
/// [`PoolKey::software_signer`] otherwise.
pub async fn genesis_bundle(
    principal: &mut cyphr::Principal,
    genesis: &PoolKey,
    others: &[cyphr::Key],
    now: i64,
) -> Result<Vec<Vec<u8>>, Error> {
    let failed = |reason: String| Error::Generation {
        name: genesis.name.clone(),
        reason,
    };
    principal
        .commit_genesis(&genesis.software_signer()?, others, now, "cyphr.me")
        .await
        .map_err(|e| failed(format!("genesis commit: {e}")))?
        .iter()
        .map(|coz| serde_json::to_vec(coz).map_err(|e| failed(format!("wire coz: {e}"))))
        .collect()
}

/// The PG a genesis commit's wire `blobs` name: the `id` of its
/// `principal/create` (SPEC 5.1 step 3), the id a multi-key principal is
/// stored under. `None` when no blob is a `principal/create`.
#[must_use]
pub fn genesis_id(blobs: &[impl AsRef<[u8]>]) -> Option<String> {
    blobs.iter().find_map(|blob| {
        let coz: serde_json::Value = serde_json::from_slice(blob.as_ref()).ok()?;
        let typ = coz.pointer("/pay/typ")?.as_str()?;
        cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::PRINCIPAL_CREATE)
            .then(|| coz.pointer("/pay/id")?.as_str().map(str::to_owned))
            .flatten()
    })
}
