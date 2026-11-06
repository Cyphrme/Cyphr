//! `MemoryBlobStore` tests.

use super::{conformance, *};

/// Backs the `BlobStore` contract (put/get round trip, missing is `None`,
/// presence, idempotent put, full iteration, size cap) for the in-memory
/// backend: every shared function in [`super::conformance`], the bar
/// `FjallBlobStore` is held to as well. Unit: the trait seam is internal;
/// no end-to-end route names a backend-independent contract.
#[tokio::test]
async fn memory_blob_store_passes_the_shared_conformance_suite() {
    conformance::put_get_roundtrip(&MemoryBlobStore::new()).await;
    conformance::get_missing_returns_none(&MemoryBlobStore::new()).await;
    conformance::exists_reflects_presence(&MemoryBlobStore::new()).await;
    conformance::put_is_idempotent(&MemoryBlobStore::new()).await;
    conformance::iter_returns_all_stored(&MemoryBlobStore::new()).await;
    let capped = MemoryBlobStore::new().with_max_blob_size(10);
    conformance::max_blob_size_enforced(&capped, 10).await;
}

// -- Blake3Hash unit tests --

/// Backs I1: blob addresses are 64-char hex BLAKE3 digests; a malformed
/// address (wrong length, non-hex) is refused rather than parsed. Unit: the
/// parser is reached end to end only through already-valid manifests.
#[test]
fn blake3_hash_round_trips_and_rejects_malformed() {
    let hash = Blake3Hash::from_bytes(*blake3::hash(b"test").as_bytes());
    let hex = hash.to_string();
    assert_eq!(hex.len(), 64, "hex string should be 64 chars");
    assert_eq!(hash, hex.parse().expect("parse failed"));
    assert!("abcd".parse::<Blake3Hash>().is_err(), "short hex");
    assert!("z".repeat(64).parse::<Blake3Hash>().is_err(), "non-hex");
}

/// Backs I1 (the BLAKE3 content-addressed blob store is the source of
/// truth): `put` returns exactly the BLAKE3 of the bytes and `get` returns
/// them unchanged, for coz-shaped payloads. Unit: the conformance suite
/// does not pin the address function.
#[tokio::test]
async fn integration_coz_bytes_roundtrip() {
    let payloads: &[&[u8]] = &[
        br#"{"alg":"ES256","tag":"dBucR...","pay":{"typ":"key/create"},"sig":"MEU..."}"#,
        br#"{"alg":"ES256","tag":"xKzWq...","pay":{"typ":"key/revoke","id":"dBucR..."},"sig":"MEY..."}"#,
        br#"{"alg":"Ed25519","tag":"aBcDe...","pay":{"typ":"cyphr/action","act":"set","path":"/profile/name","val":"Alice"},"sig":"abc123..."}"#,
    ];

    let mem = MemoryBlobStore::new();

    for payload in payloads {
        let expected_hash = Blake3Hash::from_bytes(*blake3::hash(payload).as_bytes());

        let mh = mem.put(payload).await.expect("mem put");
        assert_eq!(mh, expected_hash);
        let got = mem.get(&mh).await.expect("mem get").expect("mem missing");
        assert_eq!(&got, *payload, "mem round-trip mismatch");
    }

    let mem_count = mem.iter().await.expect("mem iter").count();
    assert_eq!(mem_count, payloads.len());
}
