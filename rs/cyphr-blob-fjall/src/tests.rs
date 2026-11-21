//! `FjallBlobStore` conformance + durability tests.
//!
//! The conformance functions are the same ones `MemoryBlobStore`'s own test
//! suite calls (`cyphr_storage::blob::conformance`, gated behind that
//! crate's `conformance-tests` dev-dependency feature) -- per the shared-
//! conformance-suite requirement (extended to `BlobStore` during the test-
//! hardening pass), this backend must be held to the identical behavioral
//! bar, not a hand-picked subset.

use cyphr_storage::blob::conformance;
use cyphr_storage::engine::LogFactory as _;
use eml::Storage as _;

use super::*;

/// Backs the `BlobStore` contract (put/get round trip, missing is `None`,
/// presence, idempotent put, full iteration, size cap) for the durable
/// backend: every shared function in `cyphr_storage::blob::conformance`
/// against a fresh `FjallBlobStore`. Unit: the trait seam is internal; no
/// end-to-end route names a backend-independent contract.
#[tokio::test]
async fn fjall_blob_store_passes_the_shared_conformance_suite() {
    conformance::run_all(|cap| {
        let (store, guard) = FjallBlobStore::temp().expect("open");
        match cap {
            Some(n) => (store.with_max_blob_size(n), guard),
            None => (store, guard),
        }
    })
    .await;
}

/// Trivial fixed-width hasher for exercising generic EML log storage in
/// these tests — unrelated to cyphr's own MALT hashing, which lives in
/// the `cyphr` crate this storage-layer crate deliberately does not
/// depend on.
#[derive(Debug)]
struct Blake3Hasher;

impl eml::Hasher for Blake3Hasher {
    fn leaf(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    fn node(&self, children: &[&[u8]]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        for child in children {
            hasher.update(child);
        }
        hasher.finalize().as_bytes().to_vec()
    }

    fn empty(&self) -> Vec<u8> {
        blake3::hash(b"").as_bytes().to_vec()
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }

    fn clone_box(&self) -> Box<dyn eml::Hasher> {
        Box::new(Blake3Hasher)
    }
}

/// Writes to the blob partition and writes to the EML partitions must
/// never be observable through each other, even though both live in one
/// physical fjall database.
#[tokio::test]
async fn blob_and_eml_partitions_are_isolated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::builder(dir.path()).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let eml_storage = EmlLogs::new(db.clone())
        .expect("logs")
        .open("SHA-256:partition", 0)
        .expect("eml storage");

    let blob_a = blob_store.put(b"blob-partition-marker-a").await.unwrap();
    let blob_b = blob_store.put(b"blob-partition-marker-b").await.unwrap();

    let mut log = eml::new(eml_storage, Box::new(Blake3Hasher))
        .await
        .expect("new log");
    log.append_leaf(b"eml-partition-marker-0").await.unwrap();
    log.append_leaf(b"eml-partition-marker-1").await.unwrap();
    log.append_leaf(b"eml-partition-marker-2").await.unwrap();

    // The blob partition sees exactly the blobs it was given — no EML
    // leaves leaked in.
    let blob_hashes: Vec<Blake3Hash> = blob_store
        .iter()
        .await
        .expect("iter")
        .collect::<Result<_, _>>()
        .expect("iter items");
    assert_eq!(blob_hashes.len(), 2);
    assert!(blob_hashes.contains(&blob_a));
    assert!(blob_hashes.contains(&blob_b));

    // The EML partition sees exactly its own three leaves — unaffected
    // by the two unrelated blob writes.
    assert_eq!(log.size(), 3);
    assert_eq!(
        log.storage().get_leaf(0).await.unwrap(),
        b"eml-partition-marker-0"
    );
}
