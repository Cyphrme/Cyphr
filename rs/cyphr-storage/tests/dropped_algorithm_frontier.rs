//! A durable commit log must reopen after an algorithm stops being active.
//!
//! Deleting the only key of a hash algorithm (SPEC 6.2) removes that
//! algorithm from later commits' TRs, but the log keeps it registered. A
//! leaf with no variant for an algorithm hashes to that algorithm's null
//! constant, so every Merkle node above only such leaves is null and is
//! not persisted; reopening then demands that node as part of the
//! algorithm's frontier.

use std::collections::BTreeMap;

use cyphr::HashAlg;
use cyphr::commit_root::{CommitTrees, MaltHasher, hash_alg_to_u64};

/// A commit-log leaf carrying a variant for each of `algs`, in the shape
/// `MaltHasher::leaf` reads.
fn leaf(algs: &[HashAlg], n: u8) -> Vec<u8> {
    let variants: BTreeMap<u64, Vec<u8>> = algs
        .iter()
        .map(|&a| (hash_alg_to_u64(a), vec![n; 32]))
        .collect();
    serde_json::to_vec(&variants).expect("serialize leaf")
}

#[test]
fn log_reopens_after_an_algorithm_leaves_the_active_set() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // Leaf 0 is SHA-512 only; SHA-256 joins at leaf 1 (a paired ES256 key)
    // and is gone from leaf 3 on (that key deleted).
    rt.block_on(async {
        let db = fjall::Database::builder(dir.path().join("db"))
            .open()
            .expect("open db");
        let storage = cyphr_blob_fjall::open_eml_storage(db).expect("eml storage");
        let mut log = CommitTrees::open(storage).await.expect("open log");
        log.add_algorithm(
            hash_alg_to_u64(HashAlg::Sha512),
            Box::new(MaltHasher::new(HashAlg::Sha512)),
        )
        .await
        .expect("add sha512");
        log.append(&leaf(&[HashAlg::Sha512], 0)).await.expect("leaf 0");
        log.add_algorithm(
            hash_alg_to_u64(HashAlg::Sha256),
            Box::new(MaltHasher::new(HashAlg::Sha256)),
        )
        .await
        .expect("add sha256");
        for n in 1..3 {
            log.append(&leaf(&[HashAlg::Sha512, HashAlg::Sha256], n))
                .await
                .expect("leaf with both");
        }
        for n in 3..6 {
            log.append(&leaf(&[HashAlg::Sha512], n))
                .await
                .expect("leaf sha512 only");
        }
    });

    rt.block_on(async {
        let db = fjall::Database::builder(dir.path().join("db"))
            .open()
            .expect("reopen db");
        let storage = cyphr_blob_fjall::open_eml_storage(db).expect("eml storage");
        CommitTrees::open(storage)
            .await
            .expect("the log reopens with the dropped algorithm registered");
    });
}
