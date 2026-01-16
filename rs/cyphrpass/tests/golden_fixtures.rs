//! Integration tests consuming golden fixtures from tests/golden/.
//!
//! Each test loads a golden JSON file, creates a Principal from the
//! genesis keys, applies Coz message(s), and verifies expected state.

use std::fs;
use std::path::PathBuf;

use coz::Thumbprint;
use cyphrpass::Principal;
use cyphrpass::key::Key;
use test_fixtures::{Golden, GoldenCoz, GoldenExpected, Pool, PoolKey};

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

fn load_pool() -> Pool {
    let path = tests_dir().join("keys").join("pool.toml");
    Pool::load(&path).expect("failed to load pool.toml")
}

fn pool_key_to_domain(pk: &PoolKey) -> Key {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("invalid pub base64");
    // Compute thumbprint using PoolKey's method
    let tmb = pk.compute_tmb().expect("failed to compute thumbprint");

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

fn golden_key_to_domain(gk: &test_fixtures::GoldenKey) -> Key {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&gk.pub_key).expect("invalid pub base64");
    let tmb_bytes = Base64UrlUnpadded::decode_vec(&gk.tmb).expect("invalid tmb base64");

    Key {
        alg: gk.alg.clone(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn try_apply_coz(
    principal: &mut Principal,
    coz: &GoldenCoz,
) -> Result<(), cyphrpass::error::Error> {
    use coz::Czd;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pay_json = serde_json::to_vec(&coz.pay).expect("failed to serialize pay");
    let sig = Base64UrlUnpadded::decode_vec(&coz.sig).expect("invalid sig base64");
    let czd_bytes = Base64UrlUnpadded::decode_vec(&coz.czd).expect("invalid czd base64");
    let czd = Czd::from_bytes(czd_bytes);

    let new_key = coz.key.as_ref().map(golden_key_to_domain);

    principal.verify_and_apply_transaction(&pay_json, &sig, czd, new_key)?;
    Ok(())
}

fn try_apply_action(
    principal: &mut Principal,
    action: &GoldenCoz,
) -> Result<(), cyphrpass::error::Error> {
    use coz::Czd;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pay_json = serde_json::to_vec(&action.pay).expect("failed to serialize pay");
    let sig = Base64UrlUnpadded::decode_vec(&action.sig).expect("invalid sig base64");
    let czd_bytes = Base64UrlUnpadded::decode_vec(&action.czd).expect("invalid czd base64");
    let czd = Czd::from_bytes(czd_bytes);

    principal.verify_and_record_action(&pay_json, &sig, czd)?;
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
        assert_eq!(
            cad_to_b64(principal.key_state().as_cad()),
            *ks,
            "{}: ks mismatch",
            test_name
        );
    }

    if let Some(ref auth_state) = expected.auth_state {
        assert_eq!(
            cad_to_b64(principal.auth_state().as_cad()),
            *auth_state,
            "{}: as mismatch",
            test_name
        );
    }

    if let Some(ref ps) = expected.ps {
        assert_eq!(
            cad_to_b64(principal.ps().as_cad()),
            *ps,
            "{}: ps mismatch",
            test_name
        );
    }

    if let Some(ref pr) = expected.pr {
        assert_eq!(
            cad_to_b64(principal.pr().as_cad()),
            *pr,
            "{}: pr mismatch",
            test_name
        );
    }

    if let Some(ref ds) = expected.ds {
        let principal_ds = principal
            .data_state()
            .map(|d| cad_to_b64(&d.0))
            .unwrap_or_else(|| "<no ds>".to_string());
        assert_eq!(principal_ds, *ds, "{}: ds mismatch", test_name);
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

    // Apply coz message(s) for transactions
    if let Some(ref coz) = fixture.coz {
        match try_apply_coz(&mut principal, coz) {
            Ok(()) => {
                if let Some(err) = expected_error {
                    panic!(
                        "{}: expected error '{}' but transaction succeeded",
                        fixture.name, err
                    );
                }
            },
            Err(e) => {
                if let Some(expected) = expected_error {
                    assert_eq!(
                        error_name(&e),
                        expected,
                        "{}: wrong error type",
                        fixture.name
                    );
                    println!("  ✓ {} (expected error: {})", fixture.name, expected);
                    return;
                } else {
                    panic!("{}: unexpected error: {:?}", fixture.name, e);
                }
            },
        }
    } else if let Some(ref coz_seq) = fixture.coz_sequence {
        let count = coz_seq.len();
        for (i, coz) in coz_seq.iter().enumerate() {
            let is_last = i == count - 1;

            match try_apply_coz(&mut principal, coz) {
                Ok(()) => {
                    if is_last {
                        if let Some(err) = expected_error {
                            panic!(
                                "{}: expected error '{}' but last step succeeded",
                                fixture.name, err
                            );
                        }
                    }
                },
                Err(e) => {
                    if is_last {
                        if let Some(expected) = expected_error {
                            assert_eq!(
                                error_name(&e),
                                expected,
                                "{}: wrong error type on last step",
                                fixture.name
                            );
                            println!("  ✓ {} (expected error: {})", fixture.name, expected);
                            return;
                        }
                    }
                    panic!("{}: step {} failed: {:?}", fixture.name, i + 1, e);
                },
            }
        }
    }

    // Apply action(s)
    if let Some(ref action) = fixture.action {
        match try_apply_action(&mut principal, action) {
            Ok(()) => {
                if let Some(err) = expected_error {
                    panic!(
                        "{}: expected error '{}' but action succeeded",
                        fixture.name, err
                    );
                }
            },
            Err(e) => {
                if let Some(expected) = expected_error {
                    assert_eq!(
                        error_name(&e),
                        expected,
                        "{}: wrong error type",
                        fixture.name
                    );
                    println!("  ✓ {} (expected error: {})", fixture.name, expected);
                    return;
                } else {
                    panic!("{}: unexpected error: {:?}", fixture.name, e);
                }
            },
        }
    } else if let Some(ref action_seq) = fixture.action_sequence {
        let count = action_seq.len();
        for (i, action) in action_seq.iter().enumerate() {
            let is_last = i == count - 1;

            match try_apply_action(&mut principal, action) {
                Ok(()) => {
                    if is_last {
                        if let Some(err) = expected_error {
                            panic!(
                                "{}: expected error '{}' but last action succeeded",
                                fixture.name, err
                            );
                        }
                    }
                },
                Err(e) => {
                    if is_last {
                        if let Some(expected) = expected_error {
                            assert_eq!(
                                error_name(&e),
                                expected,
                                "{}: wrong error type on last action",
                                fixture.name
                            );
                            println!("  ✓ {} (expected error: {})", fixture.name, expected);
                            return;
                        }
                    }
                    panic!("{}: action {} failed: {:?}", fixture.name, i + 1, e);
                },
            }
        }
    }

    // Verify expected state (only for non-error tests)
    verify_expected(&principal, &fixture.expected, &fixture.name);

    println!("  ✓ {}", fixture.name);
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
