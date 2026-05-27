//! Property-based tests for the cyphr library.

use std::collections::BTreeMap;

use coz::Thumbprint;
use cyphr::MultihashDigest;
use cyphr::key::{Key, Revocation};
use cyphr::state::{HashAlg, derive_hash_algs};
use proptest::prelude::*;

// Generators for test inputs

fn hash_alg_strategy() -> impl Strategy<Value = HashAlg> {
    prop_oneof![
        Just(HashAlg::Sha256),
        Just(HashAlg::Sha384),
        Just(HashAlg::Sha512),
    ]
}

fn key_strategy() -> impl Strategy<Value = Key> {
    (
        prop_oneof![
            Just("ES256".to_string()),
            Just("ES384".to_string()),
            Just("Ed25519".to_string()),
        ],
        prop::collection::vec(any::<u8>(), 32),
        prop::collection::vec(any::<u8>(), 64),
        any::<i64>(),
        any::<bool>(), // true = active, false = revoked
    )
        .prop_map(|(alg, tmb_bytes, pub_key, first_seen, active)| {
            let tmb = Thumbprint::from_bytes(tmb_bytes);
            let revocation = if active {
                None
            } else {
                Some(Revocation {
                    rvk: first_seen.saturating_add(100),
                    by: None,
                })
            };
            Key {
                alg,
                tmb,
                pub_key,
                first_seen,
                last_used: None,
                revocation,
                tag: None,
            }
        })
}

proptest! {
    #[test]
    fn test_derive_hash_algs_matches_active_keys(
        keys in prop::collection::vec(key_strategy(), 1..10),
    ) {
        // Collect references to keys
        let key_refs: Vec<&Key> = keys.iter().collect();

        // Compute derived active algorithms
        let derived = derive_hash_algs(&key_refs);

        // Compute expected algorithms: unique, sorted HashAlg corresponding to active keys' algorithms
        let mut expected = std::collections::BTreeSet::new();
        for key in &keys {
            if key.is_active() {
                let alg = match key.alg.as_str() {
                    "ES256" => HashAlg::Sha256,
                    "ES384" => HashAlg::Sha384,
                    "Ed25519" => HashAlg::Sha512,
                    _ => continue,
                };
                expected.insert(alg);
            }
        }
        let expected: Vec<HashAlg> = expected.into_iter().collect();

        assert_eq!(derived, expected);
    }

    #[test]
    fn test_multihash_digest_validation(
        alg in hash_alg_strategy(),
        digest_bytes in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        let expected_len = match alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        };

        let result = MultihashDigest::from_single(alg, digest_bytes.clone());

        if digest_bytes.len() == expected_len {
            let mh = result.expect("Valid digest length should succeed");
            assert_eq!(mh.get(alg).unwrap(), &digest_bytes[..]);
            assert!(mh.contains(alg));
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_multihash_digest_multiple_validation(
        sha256_bytes in prop::collection::vec(any::<u8>(), 1..100),
        sha384_bytes in prop::collection::vec(any::<u8>(), 1..100),
        sha512_bytes in prop::collection::vec(any::<u8>(), 1..100),
    ) {
        let mut variants = BTreeMap::new();
        variants.insert(HashAlg::Sha256, sha256_bytes.clone().into_boxed_slice());
        variants.insert(HashAlg::Sha384, sha384_bytes.clone().into_boxed_slice());
        variants.insert(HashAlg::Sha512, sha512_bytes.clone().into_boxed_slice());

        let result = MultihashDigest::new(variants);

        let valid_256 = sha256_bytes.len() == 32;
        let valid_384 = sha384_bytes.len() == 48;
        let valid_512 = sha512_bytes.len() == 64;

        if valid_256 && valid_384 && valid_512 {
            let mh = result.expect("All valid sizes should succeed");
            assert_eq!(mh.get(HashAlg::Sha256).unwrap(), &sha256_bytes[..]);
            assert_eq!(mh.get(HashAlg::Sha384).unwrap(), &sha384_bytes[..]);
            assert_eq!(mh.get(HashAlg::Sha512).unwrap(), &sha512_bytes[..]);
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_tagged_digest_parsing_roundtrip(
        alg in hash_alg_strategy(),
        digest_bytes in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        use cyphr::state::TaggedDigest;
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        use std::str::FromStr;

        let expected_len = match alg {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        };

        let base64_str = Base64UrlUnpadded::encode_string(&digest_bytes);
        let formatted = format!("{}:{}", alg, base64_str);

        let parse_result = TaggedDigest::from_str(&formatted);

        if digest_bytes.len() == expected_len {
            let td = parse_result.expect("Valid digest should parse successfully");
            assert_eq!(td.alg(), alg);
            assert_eq!(td.as_bytes(), &digest_bytes[..]);
            assert_eq!(td.to_string(), formatted);
        } else {
            assert!(parse_result.is_err());
        }
    }

    #[test]
    fn test_tagged_digest_invalid_parsing_does_not_panic(s in any::<String>()) {
        use cyphr::state::TaggedDigest;
        use std::str::FromStr;

        let _ = TaggedDigest::from_str(&s);
    }
}
