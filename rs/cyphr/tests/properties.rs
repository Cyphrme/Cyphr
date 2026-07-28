//! Property-based tests for the cyphr library.

use std::collections::BTreeMap;

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::key::{Key, Revocation};
use cyphr::state::{HashAlg, derive_hash_algs};
use cyphr::{Error, MultihashDigest, Principal};
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

// ============================================================================
// Arrow verification properties (Error::CommitMismatch /
// CommitScope::matches_arrow).
//
// Per-mutation `pre` has been removed from the protocol, so these two call
// sites — CommitScope::matches_arrow (write path, gates
// cyphr-storage's engine before it finalizes a commit) and
// Principal::finalize_commit's own arrow check (replay/import path) — are
// the sole surviving chain-integrity guards. Both independently recompute
// Arrow = MR(pre, sr, tmr) and compare it against the value claimed by the
// closing commit/create coz's `arrow` field; each needs its own coverage
// since they are distinct call sites sharing only the formula.
// ============================================================================

/// (pool key name, expected signer hash algorithm) — covers all three
/// digest widths (SHA-256/384/512) via ES256/ES384/Ed25519 signers.
const ARROW_GENESIS_CHOICES: &[(&str, HashAlg)] = &[
    ("golden", HashAlg::Sha256),
    ("diana_es384", HashAlg::Sha384),
    ("eve_ed25519", HashAlg::Sha512),
];

/// Distinct pool keys used as `key/create` mutation targets. Never equal to
/// any `ARROW_GENESIS_CHOICES` entry, and mutually distinct so up to 3
/// mutations can be applied in one commit without a DuplicateKey error.
const ARROW_TARGET_KEYS: &[&str] = &["key_a", "alice", "bob"];

fn arrow_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("should have rs/ parent")
        .parent()
        .expect("should have repo root parent")
        .join("tests")
        .join("keys")
        .join("pool.toml");
    test_fixtures::Pool::load(&path).expect("failed to load pool.toml")
}

fn arrow_pool_key<'p>(pool: &'p test_fixtures::Pool, name: &str) -> &'p test_fixtures::PoolKey {
    pool.get(name)
        .unwrap_or_else(|| panic!("pool key '{}' not found", name))
}

fn arrow_domain_key(pk: &test_fixtures::PoolKey) -> Key {
    let pub_bytes =
        Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("invalid pool pub key base64");
    let tmb = pk.compute_tmb().expect("failed to compute tmb");
    Key {
        alg: pk.alg.clone(),
        tmb,
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn arrow_prv_bytes(pk: &test_fixtures::PoolKey) -> Vec<u8> {
    let prv_b64 = pk
        .prv
        .as_ref()
        .unwrap_or_else(|| panic!("pool key '{}' has no private key material", pk.name));
    Base64UrlUnpadded::decode_vec(prv_b64).expect("invalid pool prv base64")
}

/// Build and sign a real `key/create` mutation coz adding `target` under `signer`.
fn arrow_signed_key_create(
    signer: &test_fixtures::PoolKey,
    signer_tmb_b64: &str,
    target: &test_fixtures::PoolKey,
    now: i64,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let target_tmb_b64 = target.compute_tmb_b64().expect("target tmb b64");

    let mut pay = serde_json::Map::new();
    pay.insert("alg".to_string(), serde_json::json!(signer.alg));
    pay.insert("id".to_string(), serde_json::json!(target_tmb_b64));
    pay.insert("now".to_string(), serde_json::json!(now));
    pay.insert("tmb".to_string(), serde_json::json!(signer_tmb_b64));
    pay.insert(
        "typ".to_string(),
        serde_json::json!("cyphr.me/cyphr/key/create"),
    );
    let mut pay_obj = serde_json::Value::Object(pay);
    pay_obj.as_object_mut().expect("object").sort_keys();
    let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize key/create pay");

    let prv_bytes = arrow_prv_bytes(signer);
    let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub base64");
    let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
        .expect("sign_json should support pool algorithm");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
        .expect("czd_for_alg should support pool algorithm");
    (pay_vec, sig, czd)
}

/// Build and sign a real `commit/create` coz carrying `arrow_tagged`
/// (`alg:base64digest`) under `signer`. Used both for the genuine value
/// (via `finalize_with_arrow`, elsewhere) and, here, for deliberately
/// tampered values driven through the real signature-verification path.
fn arrow_signed_commit_create(
    signer: &test_fixtures::PoolKey,
    signer_tmb_b64: &str,
    arrow_tagged: &str,
    now: i64,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let mut pay = serde_json::Map::new();
    pay.insert("alg".to_string(), serde_json::json!(signer.alg));
    pay.insert("arrow".to_string(), serde_json::json!(arrow_tagged));
    pay.insert("now".to_string(), serde_json::json!(now));
    pay.insert("tmb".to_string(), serde_json::json!(signer_tmb_b64));
    pay.insert(
        "typ".to_string(),
        serde_json::json!("cyphr.me/cyphr/commit/create"),
    );
    let mut pay_obj = serde_json::Value::Object(pay);
    pay_obj.as_object_mut().expect("object").sort_keys();
    let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize commit/create pay");

    let prv_bytes = arrow_prv_bytes(signer);
    let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub base64");
    let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
        .expect("sign_json should support pool algorithm");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
        .expect("czd_for_alg should support pool algorithm");
    (pay_vec, sig, czd)
}

/// Build and sign a real `principal/create` coz under `signer`, carrying
/// `id_tagged` (the pre-genesis Auth State digest, `alg:base64digest`) —
/// the coz that transitions a Nascent multi-key principal to Established.
fn arrow_signed_principal_create(
    signer: &test_fixtures::PoolKey,
    signer_tmb_b64: &str,
    id_tagged: &str,
    now: i64,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let mut pay = serde_json::Map::new();
    pay.insert("alg".to_string(), serde_json::json!(signer.alg));
    pay.insert("id".to_string(), serde_json::json!(id_tagged));
    pay.insert("now".to_string(), serde_json::json!(now));
    pay.insert("tmb".to_string(), serde_json::json!(signer_tmb_b64));
    pay.insert(
        "typ".to_string(),
        serde_json::json!("cyphr.me/cyphr/principal/create"),
    );
    let mut pay_obj = serde_json::Value::Object(pay);
    pay_obj.as_object_mut().expect("object").sort_keys();
    let pay_vec = serde_json::to_vec(&pay_obj).expect("serialize principal/create pay");

    let prv_bytes = arrow_prv_bytes(signer);
    let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("signer pub base64");
    let (sig, cad) = coz::sign_json(&pay_vec, &signer.alg, &prv_bytes, &pub_bytes)
        .expect("sign_json should support pool algorithm");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg)
        .expect("czd_for_alg should support pool algorithm");
    (pay_vec, sig, czd)
}

/// Flip one byte of `digest`'s bytes at `alg`, preserving byte length
/// exactly, and rebuild as a single-variant `MultihashDigest`.
fn arrow_tamper_digest(
    digest: &MultihashDigest,
    alg: HashAlg,
    byte_index: usize,
    mask: u8,
) -> MultihashDigest {
    let bytes = digest
        .get(alg)
        .expect("genuine arrow should carry the signer's algorithm");
    let mut tampered = bytes.to_vec();
    let i = byte_index % tampered.len();
    tampered[i] ^= mask;
    MultihashDigest::from_single(alg, tampered).expect("tamper preserves original byte length")
}

fn arrow_genesis_idx_strategy() -> impl Strategy<Value = usize> {
    0usize..ARROW_GENESIS_CHOICES.len()
}

fn arrow_mutation_count_strategy() -> impl Strategy<Value = usize> {
    1usize..=ARROW_TARGET_KEYS.len()
}

proptest! {
    /// Property 1: `matches_arrow` rejects any single-byte tamper to a
    /// genuine arrow, across all three digest widths and 1..=3 mutations.
    #[test]
    fn test_matches_arrow_rejects_tampered_arrow(
        genesis_idx in arrow_genesis_idx_strategy(),
        mutation_count in arrow_mutation_count_strategy(),
        byte_index in any::<usize>(),
        mask in 1u8..=255u8,
    ) {
        let pool = arrow_pool();
        let (genesis_name, signer_alg) = ARROW_GENESIS_CHOICES[genesis_idx];
        let genesis = arrow_pool_key(&pool, genesis_name);
        let signer_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        // Two independently-constructed principals from byte-identical
        // genesis material, kept in lockstep by replaying the SAME signed
        // mutation bytes onto both (never re-signed — ECDSA signing is
        // randomized per call, so re-signing would desync their state).
        let mut principal_a = Principal::implicit(arrow_domain_key(genesis)).expect("genesis a");
        let mut principal_b = Principal::implicit(arrow_domain_key(genesis)).expect("genesis b");
        let mut scope_a = principal_a.begin_commit();
        let mut scope_b = principal_b.begin_commit();

        for target_name in ARROW_TARGET_KEYS.iter().take(mutation_count) {
            let target = arrow_pool_key(&pool, target_name);
            let (pay, sig, czd) = arrow_signed_key_create(genesis, &signer_tmb_b64, target, now);
            scope_a
                .verify_and_apply(&pay, &sig, czd.clone(), Some(arrow_domain_key(target)))
                .expect("mutation should apply to scope_a");
            scope_b
                .verify_and_apply(&pay, &sig, czd, Some(arrow_domain_key(target)))
                .expect("mutation should apply to scope_b");
        }

        // scope_a finalizes for real to learn the genuine arrow; scope_b
        // stays pending (same projected state) so matches_arrow can be
        // exercised against it directly.
        let prv_bytes = arrow_prv_bytes(genesis);
        let pub_bytes = Base64UrlUnpadded::decode_vec(&genesis.pub_key).expect("genesis pub base64");
        let commit = scope_a
            .finalize_with_arrow(&genesis.alg, &prv_bytes, &pub_bytes, &genesis_tmb, now + 1, "cyphr.me")
            .expect("finalize_with_arrow should succeed for a genuine commit");
        let genuine_arrow = commit
            .commit_tx()
            .0
            .last()
            .expect("commit tx should carry at least one coz")
            .arrow()
            .expect("commit/create coz should carry an arrow")
            .clone();

        let tampered = arrow_tamper_digest(&genuine_arrow, signer_alg, byte_index, mask);

        prop_assert!(
            !scope_b.matches_arrow(&tampered),
            "matches_arrow must reject a single-byte-tampered arrow (alg={:?}, mutation_count={})",
            signer_alg, mutation_count
        );
    }

    /// Property 2: `matches_arrow` accepts a genuine, untampered arrow —
    /// the non-triviality counterpart to property 1 (rules out a suite
    /// that is green only because it never builds a valid case).
    #[test]
    fn test_matches_arrow_accepts_genuine_arrow(
        genesis_idx in arrow_genesis_idx_strategy(),
        mutation_count in arrow_mutation_count_strategy(),
    ) {
        let pool = arrow_pool();
        let (genesis_name, _signer_alg) = ARROW_GENESIS_CHOICES[genesis_idx];
        let genesis = arrow_pool_key(&pool, genesis_name);
        let signer_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;

        let mut principal_a = Principal::implicit(arrow_domain_key(genesis)).expect("genesis a");
        let mut principal_b = Principal::implicit(arrow_domain_key(genesis)).expect("genesis b");
        let mut scope_a = principal_a.begin_commit();
        let mut scope_b = principal_b.begin_commit();

        for target_name in ARROW_TARGET_KEYS.iter().take(mutation_count) {
            let target = arrow_pool_key(&pool, target_name);
            let (pay, sig, czd) = arrow_signed_key_create(genesis, &signer_tmb_b64, target, now);
            scope_a
                .verify_and_apply(&pay, &sig, czd.clone(), Some(arrow_domain_key(target)))
                .expect("mutation should apply to scope_a");
            scope_b
                .verify_and_apply(&pay, &sig, czd, Some(arrow_domain_key(target)))
                .expect("mutation should apply to scope_b");
        }

        let prv_bytes = arrow_prv_bytes(genesis);
        let pub_bytes = Base64UrlUnpadded::decode_vec(&genesis.pub_key).expect("genesis pub base64");
        let commit = scope_a
            .finalize_with_arrow(&genesis.alg, &prv_bytes, &pub_bytes, &genesis_tmb, now + 1, "cyphr.me")
            .expect("finalize_with_arrow should succeed for a genuine commit");
        let genuine_arrow = commit
            .commit_tx()
            .0
            .last()
            .expect("commit tx should carry at least one coz")
            .arrow()
            .expect("commit/create coz should carry an arrow")
            .clone();

        prop_assert!(
            scope_b.matches_arrow(&genuine_arrow),
            "matches_arrow must accept the genuine, untampered arrow (mutation_count={})",
            mutation_count
        );
    }

    /// Property 3: `Principal::finalize_commit` raises `Error::CommitMismatch`
    /// for a REAL signed `commit/create` coz whose `arrow` is a genuine
    /// single-byte-tampered (valid-length) value, driven through
    /// `verify_and_apply` + `finalize()` — the replay-path sibling of
    /// property 1's write-path (`matches_arrow`) check. Signature
    /// verification (`verify_and_apply`) must succeed since the tampered
    /// arrow is part of what was actually signed; only `finalize()`'s
    /// independent recomputation must catch the mismatch.
    #[test]
    fn test_finalize_commit_rejects_tampered_arrow(
        genesis_idx in arrow_genesis_idx_strategy(),
        byte_index in any::<usize>(),
        mask in 1u8..=255u8,
    ) {
        let pool = arrow_pool();
        let (genesis_name, signer_alg) = ARROW_GENESIS_CHOICES[genesis_idx];
        let genesis = arrow_pool_key(&pool, genesis_name);
        let signer_tmb_b64 = genesis.compute_tmb_b64().expect("genesis tmb b64");
        let genesis_tmb = genesis.compute_tmb().expect("genesis tmb");
        let now = 1_700_000_000i64;
        let target = arrow_pool_key(&pool, ARROW_TARGET_KEYS[0]);

        // One signed mutation coz, built once and replayed byte-identical
        // onto both the reference and test principals below.
        let (mutation_pay, mutation_sig, mutation_czd) =
            arrow_signed_key_create(genesis, &signer_tmb_b64, target, now);

        // Reference principal: learn the genuine arrow for this exact
        // mutation, so the tamper is a real single-byte flip of a value
        // that would otherwise be accepted — not arbitrary noise.
        let mut principal_ref = Principal::implicit(arrow_domain_key(genesis)).expect("genesis ref");
        let mut scope_ref = principal_ref.begin_commit();
        scope_ref
            .verify_and_apply(
                &mutation_pay,
                &mutation_sig,
                mutation_czd.clone(),
                Some(arrow_domain_key(target)),
            )
            .expect("mutation should apply to reference scope");
        let prv_bytes = arrow_prv_bytes(genesis);
        let pub_bytes = Base64UrlUnpadded::decode_vec(&genesis.pub_key).expect("genesis pub base64");
        let commit = scope_ref
            .finalize_with_arrow(&genesis.alg, &prv_bytes, &pub_bytes, &genesis_tmb, now + 1, "cyphr.me")
            .expect("finalize_with_arrow should succeed for a genuine commit");
        let genuine_arrow = commit
            .commit_tx()
            .0
            .last()
            .expect("commit tx should carry at least one coz")
            .arrow()
            .expect("commit/create coz should carry an arrow")
            .clone();
        let tampered_arrow = arrow_tamper_digest(&genuine_arrow, signer_alg, byte_index, mask);
        let tampered_tagged = tampered_arrow
            .tagged(signer_alg)
            .expect("tampered digest carries signer's algorithm")
            .to_string();

        // Test principal: byte-identical mutation replay, then a REAL
        // signed commit/create coz carrying the tampered arrow, through
        // the actual write path (verify_and_apply, then finalize()).
        let mut principal = Principal::implicit(arrow_domain_key(genesis)).expect("genesis test");
        let mut scope = principal.begin_commit();
        scope
            .verify_and_apply(
                &mutation_pay,
                &mutation_sig,
                mutation_czd,
                Some(arrow_domain_key(target)),
            )
            .expect("mutation should apply to test scope");

        let (commit_pay, commit_sig, commit_czd) =
            arrow_signed_commit_create(genesis, &signer_tmb_b64, &tampered_tagged, now + 1);
        scope
            .verify_and_apply(&commit_pay, &commit_sig, commit_czd, None)
            .expect("a real signature over a well-formed (if tampered) payload must verify");

        let result = scope.finalize();
        prop_assert!(
            matches!(result, Err(Error::CommitMismatch)),
            "finalize() must raise CommitMismatch for a tampered-but-valid-length arrow, got {:?}",
            result.map(|_| ())
        );
    }
}

/// F40 regression: a genuinely fresh explicit multi-key genesis (2+ keys,
/// zero prior commits) — signed and applied through the real production
/// path (`CommitScope::verify_and_apply` + `finalize_with_arrow`, exactly
/// as `cyphr-storage`'s write path and the CLI use it) — must accept a
/// second, ordinary commit signed on top of it. Every prior arrow-property
/// test in this file only ever exercises `Principal::implicit` (single-key,
/// PG-less L1/L2) genesis; no existing test drives an *established*
/// (`principal/create`-finalized) multi-key genesis through a second commit.
#[test]
fn test_explicit_multi_key_genesis_second_commit_succeeds() {
    let pool = arrow_pool();
    let key_a = arrow_pool_key(&pool, "golden");
    let key_b = arrow_pool_key(&pool, "eve_ed25519");
    let key_c = arrow_pool_key(&pool, "bob");

    let a_tmb_b64 = key_a.compute_tmb_b64().expect("golden tmb b64");
    let tmb_a = key_a.compute_tmb().expect("golden tmb");
    let prv_a = arrow_prv_bytes(key_a);
    let pub_a = Base64UrlUnpadded::decode_vec(&key_a.pub_key).expect("golden pub base64");
    let now = 1_700_000_000i64;

    let mut principal = Principal::explicit(vec![arrow_domain_key(key_a), arrow_domain_key(key_b)])
        .expect("explicit multi-key genesis construction");
    assert!(
        principal.pg().is_none(),
        "PG must not exist before principal/create"
    );

    // pre-genesis PR == pre-genesis AR (singleton promotion, no CR/DR yet) —
    // exactly what `principal/create`'s `id` field must carry per SPEC §5.1.
    let id_tagged = principal
        .pr_tagged()
        .expect("pr_tagged should succeed for a fresh genesis");

    // ---- Commit #1: principal/create, establishing PG. ----
    let (pc_pay, pc_sig, pc_czd) =
        arrow_signed_principal_create(key_a, &a_tmb_b64, &id_tagged, now);
    let mut scope1 = principal.begin_commit();
    scope1
        .verify_and_apply(&pc_pay, &pc_sig, pc_czd, None)
        .expect("principal/create should apply to a fresh multi-key genesis");
    scope1
        .finalize_with_arrow("ES256", &prv_a, &pub_a, &tmb_a, now + 1, "cyphr.me")
        .expect("genesis commit should finalize");

    assert!(
        principal.pg().is_some(),
        "PG must be established after the genesis commit"
    );

    // ---- Commit #2: an ordinary mutation signed on top of the now-Established principal. ----
    let (kc_pay, kc_sig, kc_czd) = arrow_signed_key_create(key_a, &a_tmb_b64, key_c, now + 2);
    let mut scope2 = principal.begin_commit();
    scope2
        .verify_and_apply(&kc_pay, &kc_sig, kc_czd, Some(arrow_domain_key(key_c)))
        .expect("key/create mutation should apply to the second commit");
    scope2
        .finalize_with_arrow("ES256", &prv_a, &pub_a, &tmb_a, now + 3, "cyphr.me")
        .expect(
            "a second commit signed on top of a fresh multi-key established genesis must finalize \
             without a state-root mismatch (F40)",
        );
}
