use super::*;

/// Run a test suite against any BlobStore implementation.
fn test_blob_store(store: &dyn BlobStore) {
    // put + get round-trip
    let data = b"hello cyphr protocol";
    let hash = store.put(data).expect("put failed");
    let retrieved = store.get(&hash).expect("get failed").expect("missing blob");
    assert_eq!(retrieved, data, "round-trip content mismatch");

    // get nonexistent returns None
    let bogus = Blake3Hash::from_bytes([0xAB; 32]);
    let result = store.get(&bogus).expect("get failed");
    assert!(result.is_none(), "nonexistent hash should return None");

    // exists true/false
    assert!(
        store.exists(&hash).expect("exists failed"),
        "stored blob should exist"
    );
    assert!(
        !store.exists(&bogus).expect("exists failed"),
        "absent blob should not exist"
    );

    // put is idempotent: same content → same hash, no error
    let hash2 = store.put(data).expect("idempotent put failed");
    assert_eq!(hash, hash2, "idempotent put should return same hash");

    // iter returns all stored entries
    let data2 = b"second blob";
    let hash3 = store.put(data2.as_slice()).expect("put failed");

    let all: Vec<(Blake3Hash, Vec<u8>)> = store
        .iter()
        .expect("iter failed")
        .collect::<Result<Vec<_>, _>>()
        .expect("iter item failed");

    assert!(
        all.len() >= 2,
        "iter should return at least 2 entries, got {}",
        all.len()
    );
    assert!(
        all.iter().any(|(h, v)| *h == hash && v == data),
        "iter should contain first blob",
    );
    assert!(
        all.iter().any(|(h, v)| *h == hash3 && v == data2),
        "iter should contain second blob",
    );
}

#[test]
fn memory_blob_store() {
    let store = MemoryBlobStore::new();
    test_blob_store(&store);
}

#[test]
fn fjall_blob_store() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = FjallBlobStore::open(dir.path()).expect("failed to open fjall store");
    test_blob_store(&store);
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

/// Simulates storing protocol-shaped JSON payloads (representative of
/// signed coz messages) and verifying content-addressed retrieval.
#[test]
fn integration_coz_bytes_roundtrip() {
    // Representative coz-like JSON payloads (not real signatures, but
    // structurally representative of what the server will store).
    let payloads: &[&[u8]] = &[
        br#"{"alg":"ES256","tag":"dBucR...","pay":{"typ":"key/create"},"sig":"MEU..."}"#,
        br#"{"alg":"ES256","tag":"xKzWq...","pay":{"typ":"key/revoke","id":"dBucR..."},"sig":"MEY..."}"#,
        br#"{"alg":"Ed25519","tag":"aBcDe...","pay":{"typ":"cyphr/action","act":"set","path":"/profile/name","val":"Alice"},"sig":"abc123..."}"#,
    ];

    // Test both backends
    let mem = MemoryBlobStore::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let fjall = FjallBlobStore::open(dir.path()).expect("fjall open");

    for payload in payloads {
        let expected_hash = Blake3Hash::from_bytes(*blake3::hash(payload).as_bytes());

        // Memory backend
        let mh = mem.put(payload).expect("mem put");
        assert_eq!(mh, expected_hash);
        let got = mem.get(&mh).expect("mem get").expect("mem missing");
        assert_eq!(&got, *payload, "mem round-trip mismatch");

        // Fjall backend
        let fh = fjall.put(payload).expect("fjall put");
        assert_eq!(fh, expected_hash);
        let got = fjall.get(&fh).expect("fjall get").expect("fjall missing");
        assert_eq!(&got, *payload, "fjall round-trip mismatch");
    }

    // Verify both stores have all entries
    let mem_count = mem.iter().expect("mem iter").count();
    let fjall_count = fjall.iter().expect("fjall iter").count();
    assert_eq!(mem_count, payloads.len());
    assert_eq!(fjall_count, payloads.len());
}
