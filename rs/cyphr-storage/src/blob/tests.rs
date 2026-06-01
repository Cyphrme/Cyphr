use super::*;

/// Run a test suite against the MemoryBlobStore implementation.
async fn test_blob_store<S: BlobStore>(store: &S) {
    // put + get round-trip
    let data = b"hello cyphr protocol";
    let hash = store.put(data).await.expect("put failed");
    let retrieved = store
        .get(&hash)
        .await
        .expect("get failed")
        .expect("missing blob");
    assert_eq!(retrieved, data, "round-trip content mismatch");

    // get nonexistent returns None
    let bogus = Blake3Hash::from_bytes([0xAB; 32]);
    let result = store.get(&bogus).await.expect("get failed");
    assert!(result.is_none(), "nonexistent hash should return None");

    // exists true/false
    assert!(
        store.exists(&hash).await.expect("exists failed"),
        "stored blob should exist"
    );
    assert!(
        !store.exists(&bogus).await.expect("exists failed"),
        "absent blob should not exist"
    );

    // put is idempotent: same content → same hash, no error
    let hash2 = store.put(data).await.expect("idempotent put failed");
    assert_eq!(hash, hash2, "idempotent put should return same hash");

    // iter returns all stored entries
    let data2 = b"second blob";
    let hash3 = store.put(data2).await.expect("put failed");

    let iter = store.iter().await.expect("iter failed");
    let all: Vec<Blake3Hash> = iter
        .collect::<Result<Vec<_>, _>>()
        .expect("iter item failed");

    assert!(
        all.len() >= 2,
        "iter should return at least 2 entries, got {}",
        all.len()
    );
    assert!(
        all.iter().any(|h| *h == hash),
        "iter should contain first blob",
    );
    assert!(
        all.iter().any(|h| *h == hash3),
        "iter should contain second blob",
    );
}

#[tokio::test]
async fn memory_blob_store() {
    let store = MemoryBlobStore::new();
    test_blob_store(&store).await;
}

#[tokio::test]
async fn memory_blob_store_limits() {
    let store = MemoryBlobStore::new().with_max_blob_size(10);
    assert!(store.put(b"short").await.is_ok());
    let err = store.put(b"this is way too long").await.unwrap_err();
    assert!(matches!(
        err,
        BlobStoreError::BlobTooLarge { size: 20, max: 10 }
    ));
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
