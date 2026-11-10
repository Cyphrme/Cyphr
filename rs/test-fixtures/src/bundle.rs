//! Conformant wire bundles for tests that drive the storage engine or a
//! server: every chain begins with its genesis commit (SPEC 5.1), so a test
//! builds that first and pushes its bundle before any other.

use cyphr::replay::WireBundle;

use crate::{Error, PoolKey};

/// Commit `principal`'s genesis signed by its genesis key `genesis`,
/// creating each of `others` after it (SPEC 5.1-5.3), and return the
/// commit's wire bundle (SPEC 4.6.2): each `key/create` its own
/// transaction, then the `principal/create` and the `commit/create`, with
/// the keys they create in `keys`.
///
/// # Errors
///
/// `Generation` if the core refuses the genesis (e.g. `genesis` is not the
/// principal's genesis key) or the commit does not export; as
/// [`PoolKey::software_signer`] otherwise.
pub async fn genesis_bundle(
    principal: &mut cyphr::Principal,
    genesis: &PoolKey,
    others: &[cyphr::Key],
    now: i64,
) -> Result<WireBundle, Error> {
    let failed = |reason: String| Error::Generation {
        name: genesis.name.clone(),
        reason,
    };
    principal
        .commit_genesis(&genesis.software_signer()?, others, now, "cyphr.me")
        .await
        .map_err(|e| failed(format!("genesis commit: {e}")))?;
    last_commit_bundle(principal).map_err(failed)
}

/// The wire bundle of `principal`'s last commit, as a push carries it.
///
/// # Errors
///
/// Why the principal has no commit, or it does not serialize.
pub fn last_commit_bundle(principal: &cyphr::Principal) -> Result<WireBundle, String> {
    let commit = principal.commits().last().ok_or("no commit")?;
    WireBundle::of_commit(commit).map_err(|e| format!("wire bundle: {e}"))
}

/// The PG a genesis commit's bundle names: the `id` of its
/// `principal/create` (SPEC 5.1 step 3), the id a multi-key principal is
/// stored under. `None` when no transaction is a `principal/create`.
#[must_use]
pub fn genesis_id(bundle: &WireBundle) -> Option<String> {
    bundle.txs.iter().flatten().find_map(|blob| {
        let coz: serde_json::Value = serde_json::from_slice(blob).ok()?;
        let typ = coz.pointer("/pay/typ")?.as_str()?;
        cyphr::parsed_coz::typ::has_suffix(typ, cyphr::parsed_coz::typ::PRINCIPAL_CREATE)
            .then(|| coz.pointer("/pay/id")?.as_str().map(str::to_owned))
            .flatten()
    })
}
