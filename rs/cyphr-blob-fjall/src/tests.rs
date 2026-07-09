//! `FjallBlobStore` conformance + durability tests.
//!
//! The conformance functions are the same ones `MemoryBlobStore`'s own test
//! suite calls (`cyphr_storage::blob::conformance`, gated behind that
//! crate's `conformance-tests` dev-dependency feature) -- per N09-kv-index
//! premise p4 (applied here to `BlobStore` per N15-test-hardening), this
//! backend must be held to the identical behavioral bar, not a hand-picked
//! subset.

use cyphr_storage::blob::conformance;
use eml::Storage as _;

use super::*;

macro_rules! conformance_test {
    ($name:ident) => {
        #[tokio::test]
        async fn $name() {
            let (store, _dir) = FjallBlobStore::temp().expect("open temp store");
            conformance::$name(&store).await;
        }
    };
}

conformance_test!(put_get_roundtrip);
conformance_test!(get_missing_returns_none);
conformance_test!(exists_reflects_presence);
conformance_test!(put_is_idempotent);
conformance_test!(iter_returns_all_stored);

#[tokio::test]
async fn max_blob_size_enforced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FjallBlobStore::open(dir.path())
        .expect("open")
        .with_max_blob_size(10);
    conformance::max_blob_size_enforced(&store, 10).await;
}

/// A durably-reopened `FjallBlobStore` (fresh `Database`, not a clone of the
/// live one) must see everything written before the reopen -- otherwise this
/// backend would be strictly weaker than a real production store, which the
/// conformance suite (in-memory only) can't itself catch. Mirrors
/// `cyphr_index_fjall`'s `survives_disk_reload`.
#[tokio::test]
async fn survives_disk_reload() {
    let dir = tempfile::tempdir().expect("tempdir");

    let hash = {
        let store = FjallBlobStore::open(dir.path()).expect("open");
        store
            .put(b"a blob that must survive reload")
            .await
            .expect("put")
    };

    let reopened = FjallBlobStore::open(dir.path()).expect("reopen");
    let retrieved = reopened
        .get(&hash)
        .await
        .expect("get")
        .expect("blob survives reload");
    assert_eq!(retrieved, b"a blob that must survive reload");
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

/// The Commit Tree (EML log) must survive a disk write/reload cycle,
/// genuinely sharing one fjall database with the blob store rather than
/// opening a second, uncoordinated one.
#[tokio::test]
async fn eml_log_survives_disk_reload_sharing_blob_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaves: [&[u8]; 3] = [b"commit-0", b"commit-1", b"commit-2"];

    let (original_root, original_size, blob_hash) = {
        let db = Database::builder(dir.path()).open().expect("open db");
        let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
        let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

        let blob_hash = blob_store.put(b"a blob living beside the log").await.unwrap();

        let mut log = eml::new(eml_storage, Box::new(Blake3Hasher))
            .await
            .expect("new log");
        for leaf in leaves {
            log.append_leaf(leaf).await.expect("append leaf");
        }

        (log.root_for(0).expect("root"), log.size(), blob_hash)
        // `db`, `blob_store`, and `log` all drop here, releasing the
        // on-disk database before it's reopened below.
    };

    // Reopen from scratch at the same path — a fresh `Database`, not a
    // clone of the one above — to prove the state is genuinely durable.
    let db = Database::builder(dir.path()).open().expect("reopen db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

    let reconstructed = eml::from_storage(eml_storage, vec![(0, Box::new(Blake3Hasher))])
        .await
        .expect("reconstruct log from disk");

    assert_eq!(reconstructed.size(), original_size, "leaf count must survive reload");
    assert_eq!(
        reconstructed.root_for(0).expect("root"),
        original_root,
        "root must survive reload byte-for-byte"
    );

    // The blob written in the first session must also still be there,
    // proving the blob and EML partitions truly share one database
    // rather than each independently persisting to its own file.
    let retrieved = blob_store.get(&blob_hash).await.unwrap();
    assert!(retrieved.is_some(), "blob must survive reload in the shared database");
}

/// Writes to the blob partition and writes to the EML partitions must
/// never be observable through each other, even though both live in one
/// physical fjall database.
#[tokio::test]
async fn blob_and_eml_partitions_are_isolated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::builder(dir.path()).open().expect("open db");
    let blob_store = FjallBlobStore::from_database(db.clone()).expect("blob store");
    let eml_storage = open_eml_storage(db.clone()).expect("eml storage");

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

/// Two principals' EML logs, opened via [`open_eml_storage_scoped`] with
/// distinct prefixes on the same physical database, must not observe
/// each other's leaves — the multitenancy counterpart to
/// `blob_and_eml_partitions_are_isolated` above.
#[tokio::test]
async fn scoped_eml_opens_on_one_database_do_not_collide() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::builder(dir.path()).open().expect("open db");

    let storage_a =
        open_eml_storage_scoped(db.clone(), "principal-a").expect("scoped storage a");
    let storage_b =
        open_eml_storage_scoped(db.clone(), "principal-b").expect("scoped storage b");

    let mut log_a = eml::new(storage_a, Box::new(Blake3Hasher))
        .await
        .expect("new log a");
    let mut log_b = eml::new(storage_b, Box::new(Blake3Hasher))
        .await
        .expect("new log b");

    log_a.append_leaf(b"a-leaf-0").await.unwrap();
    log_b.append_leaf(b"b-leaf-0").await.unwrap();
    log_b.append_leaf(b"b-leaf-1").await.unwrap();

    assert_eq!(log_a.size(), 1, "tenant a's log must see only its own leaf");
    assert_eq!(log_b.size(), 2, "tenant b's log must see only its own leaves");
    assert_eq!(log_a.storage().get_leaf(0).await.unwrap(), b"a-leaf-0");
    assert_eq!(log_b.storage().get_leaf(0).await.unwrap(), b"b-leaf-0");
    assert_eq!(log_b.storage().get_leaf(1).await.unwrap(), b"b-leaf-1");
}

/// A Cyphr `principal_id` (the intended real-world scoping identifier,
/// e.g. `"SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"`) always
/// contains a `:` separator, which is outside
/// `storage_fjall::FjallStorage::with_database_scoped`'s allowed
/// keyspace-name charset. `open_eml_storage_scoped` must still accept it
/// — the caller should not need to know or work around fjall's naming
/// constraints.
#[tokio::test]
async fn scoped_eml_open_accepts_a_principal_id_shaped_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::builder(dir.path()).open().expect("open db");

    let principal_id = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    let mut storage = open_eml_storage_scoped(db, principal_id)
        .expect("scoped open must accept a principal_id-shaped prefix");

    // Exercise it like a real Commit Tree would, proving the returned
    // storage is genuinely usable, not just successfully constructed.
    storage.store_leaf(0, b"leaf-0").await.unwrap();
    assert_eq!(storage.get_leaf(0).await.unwrap(), b"leaf-0");
}
