//! Red-first regression test for GitHub issue #32: a storage-backend
//! failure during an EML operation must surface as `Error::Storage` (which
//! the server maps to HTTP 500 — an infrastructure failure), never as
//! `Error::Storage`'s pre-fix stand-in `Error::UnsupportedAlgorithm` (which
//! the server maps to HTTP 422 — a client-facing protocol question).
//!
//! `Principal<S>` is generic over any `S: eml::Storage`
//! ([`cyphr::principal`]), so a storage backend that fails on demand is
//! enough to drive a real call site without needing a fault-injecting fork
//! of `eml` itself.

use coz::Thumbprint;
use cyphr::eml::{AlgorithmMetas, Storage};
use cyphr::error::Error;
use cyphr::key::Key;
use cyphr::Principal;

/// A minimal single-key genesis key, sufficient to reach
/// `Principal::implicit_with_storage`'s `CommitTrees::open` call.
fn genesis_key() -> Key {
    Key {
        alg: "ES256".to_string(),
        tmb: Thumbprint::from_bytes(vec![0u8; 32]),
        pub_key: vec![0u8; 64],
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Always-failing storage error, standing in for a real infrastructure
/// failure (disk I/O error, connection loss, etc).
#[derive(Debug)]
struct InjectedStorageFailure;

impl std::fmt::Display for InjectedStorageFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "injected storage failure")
    }
}

impl std::error::Error for InjectedStorageFailure {}

/// An `eml::Storage` backend that fails every operation — a backing store
/// that is simply down, not one with a specific corrupted record. Every
/// method is exercised by some caller in `rs/cyphr/src`, so failing all of
/// them (rather than just `load_algorithm_metas`) keeps this fixture
/// reusable for any of the 16 remapped call sites, not only the one this
/// test drives.
#[derive(Debug, Default, Clone, Copy)]
struct FailingStorage;

impl Storage for FailingStorage {
    type Error = InjectedStorageFailure;

    async fn store_leaf(&mut self, _index: u64, _data: &[u8]) -> Result<(), Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn get_leaf(&self, _index: u64) -> Result<Vec<u8>, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn len(&self) -> Result<u64, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn store_node(
        &mut self,
        _alg_id: u64,
        _left: u64,
        _height: u32,
        _hash: &[u8],
    ) -> Result<(), Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn get_node(
        &self,
        _alg_id: u64,
        _left: u64,
        _height: u32,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn store_algorithm_meta(
        &mut self,
        _alg_id: u64,
        _epochs: &[(u64, u64)],
    ) -> Result<(), Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn load_algorithm_metas(&self) -> Result<AlgorithmMetas, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn load_log_meta(&self) -> Result<Option<(u64, u8)>, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn load_checkpoint_roots(&self) -> Result<Vec<(u64, Vec<u8>)>, Self::Error> {
        Err(InjectedStorageFailure)
    }

    async fn write_batch(
        &mut self,
        _leaves: &[(u64, &[u8])],
        _nodes: &[(u64, u64, u32, &[u8])],
        _algorithm_metas: &[(u64, &[(u64, u64)])],
        _log_meta: Option<(u64, u8)>,
        _checkpoint_roots: &[(u64, &[u8])],
    ) -> Result<(), Self::Error> {
        Err(InjectedStorageFailure)
    }
}

/// ac-storage-error-honest: `CommitTrees::open` (principal.rs's
/// `implicit_with_storage`, one of the 16 enumerated sites) must surface a
/// backend failure as `Error::Storage`, not `Error::UnsupportedAlgorithm` —
/// the genesis key's algorithm is valid and fully supported; only the
/// storage backend is broken.
#[test]
fn storage_backend_failure_surfaces_as_storage_error() {
    let result = Principal::implicit_with_storage(genesis_key(), FailingStorage);

    match result {
        Err(Error::Storage(_)) => {},
        Err(other) => panic!(
            "storage-backend failure must surface as Error::Storage, got {other:?} instead \
             (Error::UnsupportedAlgorithm misreports an infrastructure failure as a client-\
             facing algorithm-support question — see GitHub issue #32)"
        ),
        Ok(_) => panic!("expected the injected storage failure to propagate as an error"),
    }
}
