//! Integration tests consuming golden fixtures from tests/golden/.
//!
//! Each test loads a golden JSON file, creates a Principal from the
//! genesis keys, applies Coz message(s), and verifies expected state.

use std::fs;
use std::path::PathBuf;

use cyphrpass::Principal;
use cyphrpass::key::Key;
use test_fixtures::{Golden, GoldenExpected, KeyEntry, Pool, PoolKey};

// ============================================================================
// Test helpers
// ============================================================================

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("should have rs/ parent")
        .parent()
        .expect("should have repo root parent")
        .join("tests")
}

fn golden_dir() -> PathBuf {
    tests_dir().join("golden")
}

/// Parse hash algorithm name from string (e.g., "SHA-256" -> HashAlg::Sha256).
fn parse_hash_alg(s: &str) -> Option<coz::HashAlg> {
    match s {
        "SHA-256" => Some(coz::HashAlg::Sha256),
        "SHA-384" => Some(coz::HashAlg::Sha384),
        "SHA-512" => Some(coz::HashAlg::Sha512),
        _ => None,
    }
}

/// Parse algorithm-prefixed digest string (e.g., "SHA-256:abc123..." -> ("SHA-256", "abc123...")).
fn parse_alg_digest(s: &str) -> Option<(String, String)> {
    let (alg, digest) = s.split_once(':')?;

    Some((alg.to_string(), digest.to_string()))
}

fn load_pool() -> Pool {
    let path = tests_dir().join("keys").join("pool.toml");
    Pool::load(&path).expect("failed to load pool.toml")
}

/// Try to convert a pool key to domain key, returning None for unsupported algorithms.
fn try_pool_key_to_domain(pk: &PoolKey) -> Option<Key> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).ok()?;
    let tmb = pk.compute_tmb().ok()?;

    Some(Key {
        alg: pk.alg.clone(),
        tmb,
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    })
}

fn cad_to_b64(cad: &coz::Cad) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(cad.as_bytes())
}

/// Apply a storage-format entry {pay, sig, key?} to Principal.
/// Verifies that computed czd matches expected_czd.
/// `commit_keys` provides commit-level keys for key/create and key/replace.
fn try_apply_entry(
    principal: &mut Principal,
    entry: &serde_json::Value,
    expected_czd: &str,
    test_name: &str,
    commit_keys: &[KeyEntry],
) -> Result<(), cyphrpass::error::Error> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pay = entry.get("pay").expect("entry missing pay");
    let sig_b64 = entry
        .get("sig")
        .and_then(|v| v.as_str())
        .expect("entry missing sig");
    let sig = Base64UrlUnpadded::decode_vec(sig_b64).expect("invalid sig base64");

    let pay_json = serde_json::to_vec(pay).expect("failed to serialize pay");

    // Compute czd from pay+sig
    let alg = pay
        .get("alg")
        .and_then(|v| v.as_str())
        .expect("entry pay missing alg");
    let cad =
        coz::canonical_hash_for_alg(&pay_json, alg, None).expect("unsupported algorithm for cad");
    let computed_czd = coz::czd_for_alg(&cad, &sig, alg).expect("unsupported algorithm for czd");
    let computed_czd_b64 = Base64UrlUnpadded::encode_string(computed_czd.as_bytes());

    // Verify czd matches expected
    assert_eq!(
        computed_czd_b64, expected_czd,
        "{}: czd mismatch for entry",
        test_name
    );

    // Look up new key from commit-level keys[] by matching pay.id to key.tmb
    let new_key = pay.get("id").and_then(|id_val| {
        let id_str = id_val.as_str()?;
        commit_keys.iter().find_map(|ke| {
            if ke.tmb == id_str {
                let pub_bytes = Base64UrlUnpadded::decode_vec(&ke.pub_key).ok()?;
                let tmb_bytes = Base64UrlUnpadded::decode_vec(&ke.tmb).ok()?;
                Some(Key {
                    alg: ke.alg.clone(),
                    tmb: coz::Thumbprint::from_bytes(tmb_bytes),
                    pub_key: pub_bytes,
                    first_seen: 0,
                    last_used: None,
                    revocation: None,
                    tag: None,
                })
            } else {
                None
            }
        })
    });

    // Determine if this is a transaction or action based on typ field
    let typ = pay.get("typ").and_then(|v| v.as_str()).unwrap_or("");
    if typ.starts_with("cyphr.me/key/") || typ == "cyphr.me/principal/create" {
        // Transaction
        principal.verify_and_apply_transaction(&pay_json, &sig, computed_czd, new_key)?;
    } else {
        // Action
        principal.verify_and_record_action(&pay_json, &sig, computed_czd)?;
    }

    Ok(())
}

fn error_name(e: &cyphrpass::error::Error) -> &'static str {
    use cyphrpass::error::Error;
    match e {
        Error::InvalidPrior => "InvalidPrior",
        Error::UnknownKey => "UnknownKey",
        Error::KeyRevoked => "KeyRevoked",
        Error::NoActiveKeys => "NoActiveKeys",
        Error::DuplicateKey => "DuplicateKey",
        Error::TimestampPast => "TimestampPast",
        Error::TimestampFuture => "TimestampFuture",
        Error::InvalidSignature => "InvalidSignature",
        Error::MalformedPayload => "MalformedPayload",
        Error::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
        _ => "UnknownError",
    }
}

fn verify_expected(principal: &Principal, expected: &GoldenExpected, test_name: &str) {
    if let Some(count) = expected.key_count {
        assert_eq!(
            principal.active_key_count(),
            count,
            "{}: key_count mismatch",
            test_name
        );
    }

    if let Some(level) = expected.level {
        assert_eq!(
            principal.level() as u8,
            level,
            "{}: level mismatch",
            test_name
        );
    }

    if let Some(ref ks) = expected.ks {
        // Parse alg:digest format
        let (alg, expected_digest) = parse_alg_digest(ks)
            .unwrap_or_else(|| panic!("{}: invalid ks format (expected alg:digest)", test_name));
        let hash_alg = parse_hash_alg(&alg)
            .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
        let actual_ks = principal
            .key_state()
            .get(hash_alg)
            .map(|b| {
                use coz::base64ct::{Base64UrlUnpadded, Encoding};
                Base64UrlUnpadded::encode_string(b)
            })
            .unwrap_or_default();
        assert_eq!(actual_ks, expected_digest, "{}: ks mismatch", test_name);
    }

    if let Some(ref auth_state) = expected.auth_state {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        // Parse alg:digest format
        let (alg, expected_digest) = parse_alg_digest(auth_state)
            .unwrap_or_else(|| panic!("{}: invalid as format (expected alg:digest)", test_name));
        let hash_alg = parse_hash_alg(&alg)
            .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
        let actual_as = principal
            .auth_state()
            .get(hash_alg)
            .map(Base64UrlUnpadded::encode_string)
            .unwrap_or_default();
        assert_eq!(actual_as, expected_digest, "{}: as mismatch", test_name);
    }

    if let Some(ref ps) = expected.ps {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        // Parse alg:digest format
        let (alg, expected_digest) = parse_alg_digest(ps)
            .unwrap_or_else(|| panic!("{}: invalid ps format (expected alg:digest)", test_name));
        let hash_alg = parse_hash_alg(&alg)
            .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
        let actual_ps = principal
            .ps()
            .get(hash_alg)
            .map(Base64UrlUnpadded::encode_string)
            .unwrap_or_default();
        assert_eq!(actual_ps, expected_digest, "{}: ps mismatch", test_name);
    }

    if let Some(ref pr) = expected.pr {
        // Skip empty PR or non-prefixed format (implicit genesis uses raw thumbprint)
        if !pr.is_empty() {
            if let Some((alg, expected_digest)) = parse_alg_digest(pr) {
                use coz::base64ct::{Base64UrlUnpadded, Encoding};
                let hash_alg = parse_hash_alg(&alg)
                    .unwrap_or_else(|| panic!("{}: unknown hash algorithm {}", test_name, alg));
                let actual_pr = principal
                    .pr()
                    .and_then(|pr_val| pr_val.get(hash_alg))
                    .map(Base64UrlUnpadded::encode_string)
                    .unwrap_or_default();
                assert_eq!(actual_pr, expected_digest, "{}: pr mismatch", test_name);
            }
            // If no ':' in pr, it's a raw thumbprint format - skip alg:digest verification
        }
    }

    if let Some(ref ds) = expected.ds {
        let principal_ds = principal
            .data_state()
            .map(|d| cad_to_b64(&d.0))
            .unwrap_or_else(|| "<no ds>".to_string());
        assert_eq!(principal_ds, *ds, "{}: ds mismatch", test_name);
    }

    // Verify per-algorithm multihash variants (SPEC §14 cross-implementation parity)
    if let Some(ref mh_ks) = expected.multihash_ks {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_ks {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .key_state()
                .get(hash_alg)
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_ks[{}] mismatch",
                test_name, alg_name
            );
        }
    }

    if let Some(ref mh_as) = expected.multihash_as {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_as {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .auth_state()
                .get(hash_alg)
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_as[{}] mismatch",
                test_name, alg_name
            );
        }
    }

    if let Some(ref mh_ps) = expected.multihash_ps {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        for (alg_name, expected_digest) in mh_ps {
            let hash_alg = parse_hash_alg(alg_name)
                .unwrap_or_else(|| panic!("{}: invalid hash algorithm {}", test_name, alg_name));
            let actual = principal
                .ps()
                .get(hash_alg)
                .map(Base64UrlUnpadded::encode_string)
                .unwrap_or_default();
            assert_eq!(
                actual, *expected_digest,
                "{}: multihash_ps[{}] mismatch",
                test_name, alg_name
            );
        }
    }
}

fn run_golden_test(fixture_path: &PathBuf, pool: &Pool) {
    let content = fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", fixture_path, e));
    let fixture: Golden = serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {:?}: {}", fixture_path, e));

    // Check if this is an error test
    let expected_error = fixture.expected.error.as_deref();

    // Resolve genesis keys from pool (fallibly for unsupported algorithms)
    let pool_keys: Vec<&PoolKey> = fixture
        .principal
        .iter()
        .map(|name| {
            pool.pool
                .key
                .iter()
                .find(|k| k.name == *name)
                .unwrap_or_else(|| panic!("{}: key '{}' not found in pool", fixture.name, name))
        })
        .collect();

    // Try to convert pool keys to domain keys (may fail for unsupported algs)
    let genesis_keys: Result<Vec<Key>, &str> = pool_keys
        .iter()
        .map(|pk| try_pool_key_to_domain(pk).ok_or("UnsupportedAlgorithm"))
        .collect();

    // Handle genesis-time errors (e.g., unsupported algorithm)
    let genesis_keys = match genesis_keys {
        Ok(keys) => keys,
        Err(_) => {
            // Genesis failed (unsupported algorithm)
            if let Some(expected) = expected_error {
                if expected == "UnsupportedAlgorithm" {
                    println!("  ✓ {} (expected error: {})", fixture.name, expected);
                    return;
                }
            }
            panic!(
                "{}: genesis failed due to unsupported algorithm, but expected error was {:?}",
                fixture.name, expected_error
            );
        },
    };

    // Create principal
    let mut principal = if genesis_keys.len() == 1 {
        Principal::implicit(genesis_keys.into_iter().next().unwrap())
            .expect("implicit genesis failed")
    } else {
        Principal::explicit(genesis_keys).expect("explicit genesis failed")
    };

    // Apply setup modifiers (e.g., pre-revoke keys)
    if let Some(ref setup) = fixture.setup {
        if let Some(ref key_name) = setup.revoke_key {
            let rvk_time = setup.revoke_at.unwrap_or(0);
            let pool_key = pool
                .pool
                .key
                .iter()
                .find(|k| k.name == *key_name)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: setup.revoke_key '{}' not found in pool",
                        fixture.name, key_name
                    )
                });
            let tmb = pool_key.compute_tmb().expect("failed to compute tmb");
            principal.pre_revoke_key(&tmb, rvk_time);
        }
    }

    // ========================================================================
    // Apply commits from fixture
    // ========================================================================
    if let (Some(commits), Some(digests)) = (&fixture.commits, &fixture.digests) {
        // Apply transactions from commits
        let mut digest_idx = 0;
        let commit_count = commits.len();

        for (ci, commit) in commits.iter().enumerate() {
            let is_last_commit = ci == commit_count - 1;
            let tx_count = commit.txs.len();

            for (ti, tx) in commit.txs.iter().enumerate() {
                let is_last_tx = is_last_commit && ti == tx_count - 1;
                let czd = &digests[digest_idx];
                digest_idx += 1;

                match try_apply_entry(&mut principal, tx, czd, &fixture.name, &commit.keys) {
                    Ok(()) => {
                        if is_last_tx {
                            if let Some(err) = expected_error {
                                panic!(
                                    "{}: expected error '{}' but last tx succeeded",
                                    fixture.name, err
                                );
                            }
                        }
                    },
                    Err(e) => {
                        if is_last_tx {
                            if let Some(expected) = expected_error {
                                assert_eq!(
                                    error_name(&e),
                                    expected,
                                    "{}: wrong error type on last tx",
                                    fixture.name
                                );
                                println!(
                                    "  ✓ {} (expected error: {}) [commits]",
                                    fixture.name, expected
                                );
                                return;
                            }
                        }
                        panic!(
                            "{}: commit {} tx {} failed: {:?}",
                            fixture.name,
                            ci + 1,
                            ti + 1,
                            e
                        );
                    },
                }
            }
        }

        // Verify expected state
        verify_expected(&principal, &fixture.expected, &fixture.name);
        println!("  ✓ {}", fixture.name);
        return;
    }

    // No commits - check for genesis-only test
    panic!(
        "{}: fixture has no commits array - regenerate with fixture-gen",
        fixture.name
    );
}

fn run_golden_dir(subdir: &str) {
    let pool = load_pool();
    let dir = golden_dir().join(subdir);

    if !dir.exists() {
        println!("Skipping {} (not found)", subdir);
        return;
    }

    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("failed to read dir") {
        let path = entry.expect("failed to read entry").path();
        if path.extension().is_some_and(|ext| ext == "json") {
            run_golden_test(&path, &pool);
            count += 1;
        }
    }
    println!("Ran {} test(s) from {}/", count, subdir);
}

// ============================================================================
// Tests - one per category
// ============================================================================

#[test]
fn test_golden_mutations() {
    run_golden_dir("mutations");
}

#[test]
fn test_golden_multi_key() {
    run_golden_dir("multi_key");
}

#[test]
fn test_golden_algorithm_diversity() {
    run_golden_dir("algorithm_diversity");
}

#[test]
fn test_golden_edge_cases() {
    run_golden_dir("edge_cases");
}

#[test]
fn test_golden_actions() {
    run_golden_dir("actions");
}

#[test]
fn test_golden_state_computation() {
    run_golden_dir("state_computation");
}

#[test]
fn test_golden_errors() {
    run_golden_dir("errors");
}
