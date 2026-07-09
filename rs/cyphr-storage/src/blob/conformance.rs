//! Shared behavioral conformance suite for [`BlobStore`] implementations.
//!
//! Mirrors `index::conformance` (see N09-kv-index premise p4): every
//! `BlobStore` backend (in this crate or another) is held to the same
//! functions here rather than a hand-duplicated, backend-specific subset.
//! Feature-gated (`conformance-tests`) so an out-of-crate backend can add
//! this crate as a dev-dependency with that feature enabled and call these
//! functions directly from its own `#[tokio::test]` wrappers.
//!
//! `BlobStore` is content-addressed with no principal/tenant concept (unlike
//! `Indexer`), so there is no multitenancy-isolation function here --
//! content-addressing is itself the collision-resistance property,
//! exercised by [`put_is_idempotent`] below.

use super::*;

pub async fn put_get_roundtrip<S: BlobStore>(store: &S) {
    let data = b"hello cyphr protocol";
    let hash = store.put(data).await.expect("put failed");
    let retrieved = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("missing blob");
    assert_eq!(retrieved, data, "round-trip content mismatch");
}

pub async fn get_missing_returns_none<S: BlobStore>(store: &S) {
    let bogus = Blake3Hash::from_bytes([0xAB; 32]);
    let result = store.get(&bogus).await.expect("get failed");
    assert!(result.is_none(), "nonexistent hash should return None");
}

pub async fn exists_reflects_presence<S: BlobStore>(store: &S) {
    let data = b"exists-check payload";
    let hash = store.put(data).await.expect("put failed");
    let bogus = Blake3Hash::from_bytes([0xCD; 32]);

    assert!(
        store.exists(&hash).await.expect("exists failed"),
        "stored blob should exist"
    );
    assert!(
        !store.exists(&bogus).await.expect("exists failed"),
        "absent blob should not exist"
    );
}

pub async fn put_is_idempotent<S: BlobStore>(store: &S) {
    let data = b"idempotent payload";
    let hash = store.put(data).await.expect("first put failed");
    let hash2 = store.put(data).await.expect("second put failed");
    assert_eq!(hash, hash2, "idempotent put should return same hash");
}

pub async fn iter_returns_all_stored<S: BlobStore>(store: &S) {
    let a = store.put(b"iter blob a").await.expect("put a failed");
    let b = store.put(b"iter blob b").await.expect("put b failed");

    let all: Vec<Blake3Hash> = store
        .iter()
        .await
        .expect("iter failed")
        .collect::<Result<Vec<_>, _>>()
        .expect("iter item failed");

    assert!(
        all.len() >= 2,
        "iter should return at least 2 entries, got {}",
        all.len()
    );
    assert!(all.contains(&a), "iter should contain first blob");
    assert!(all.contains(&b), "iter should contain second blob");
}

/// `store` must already be configured with a max blob size of exactly `max`
/// (e.g. via `with_max_blob_size(max)`) -- this function only exercises the
/// boundary, it doesn't configure it, since builder shape differs per
/// backend.
pub async fn max_blob_size_enforced<S: BlobStore>(store: &S, max: usize) {
    let at_limit = vec![0u8; max];
    store
        .put(&at_limit)
        .await
        .expect("put at exactly the limit should succeed");

    let over_limit = vec![0u8; max + 1];
    let err = store
        .put(&over_limit)
        .await
        .expect_err("put over the limit should fail");
    assert!(
        matches!(
            err,
            BlobStoreError::BlobTooLarge {
                size,
                max: reported_max
            } if size == max + 1 && reported_max == max
        ),
        "expected BlobTooLarge{{size: {}, max: {max}}}, got {err:?}",
        max + 1
    );
}
