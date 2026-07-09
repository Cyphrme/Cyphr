//! `MemoryBlobStore` conformance wrappers.
//!
//! Each test delegates to a shared, generic behavior function in
//! [`super::conformance`] -- the same functions any other `BlobStore`
//! implementation's own test suite calls, so `MemoryBlobStore` and every
//! durable backend are held to one behavioral bar, not independently
//! hand-duplicated ones.

use super::{conformance, *};

#[tokio::test]
async fn put_get_roundtrip() {
    conformance::put_get_roundtrip(&MemoryBlobStore::new()).await;
}

#[tokio::test]
async fn get_missing_returns_none() {
    conformance::get_missing_returns_none(&MemoryBlobStore::new()).await;
}

#[tokio::test]
async fn exists_reflects_presence() {
    conformance::exists_reflects_presence(&MemoryBlobStore::new()).await;
}

#[tokio::test]
async fn put_is_idempotent() {
    conformance::put_is_idempotent(&MemoryBlobStore::new()).await;
}

#[tokio::test]
async fn iter_returns_all_stored() {
    conformance::iter_returns_all_stored(&MemoryBlobStore::new()).await;
}

#[tokio::test]
async fn max_blob_size_enforced() {
    let store = MemoryBlobStore::new().with_max_blob_size(10);
    conformance::max_blob_size_enforced(&store, 10).await;
}

// -- Blake3Hash unit tests --

#[test]
fn blake3_hash_display_roundtrip() {
    let bytes = *blake3::hash(b"test").as_bytes();
    let hash = Blake3Hash::from_bytes(bytes);
    let hex = hash.to_string();
    assert_eq!(hex.len(), 64, "hex string should be 64 chars");
    let parsed: Blake3Hash = hex.parse().expect("parse failed");
    assert_eq!(hash, parsed, "display/parse round-trip failed");
}

#[test]
fn blake3_hash_parse_invalid_length() {
    let result = "abcd".parse::<Blake3Hash>();
    assert!(result.is_err(), "short hex should fail");
}

#[test]
fn blake3_hash_parse_invalid_hex() {
    let result =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".parse::<Blake3Hash>();
    assert!(result.is_err(), "non-hex chars should fail");
}

// -- Integration: raw coz-like payloads through BlobStore --

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
