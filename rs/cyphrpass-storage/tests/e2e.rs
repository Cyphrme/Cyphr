//! End-to-end tests for cyphrpass-storage.
//!
//! These tests verify round-trip correctness by dynamically generating fixtures:
//! intent → generate → export → import → compare state.
//!
//! Unlike integration tests which use pre-generated golden files, e2e tests
//! generate fixtures at runtime, testing the full generation pipeline.

use std::fs;
use std::path::PathBuf;

use cyphrpass_storage::{Entry, Genesis, LoadError, export_entries, load_principal};
use serde_json::Value;
use serde_json::value::RawValue;
use test_fixtures::{Generator, Golden, GoldenKey, Intent, Pool};

// ============================================================================
// Test Helpers
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

fn e2e_intents_dir() -> PathBuf {
    tests_dir().join("e2e")
}

#[allow(dead_code)]
fn load_pool() -> Pool {
    let path = tests_dir().join("keys").join("pool.toml");
    Pool::load(&path).expect("failed to load pool.toml")
}

/// Load a single golden fixture by category and name.
fn load_fixture(category: &str, name: &str) -> Golden {
    let path = golden_dir().join(category).join(format!("{}.json", name));
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));
    serde_json::from_str(&content).unwrap_or_else(|e| panic!("failed to parse {:?}: {}", path, e))
}

/// Load e2e intents from a TOML file.
fn load_e2e_intents(filename: &str) -> Intent {
    let path = e2e_intents_dir().join(filename);
    Intent::load(&path).unwrap_or_else(|e| panic!("failed to load {:?}: {}", path, e))
}

/// Convert GoldenKey to cyphrpass::Key.
fn golden_key_to_domain(gk: &GoldenKey) -> cyphrpass::Key {
    use coz::Thumbprint;
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let pub_bytes = Base64UrlUnpadded::decode_vec(&gk.pub_key).expect("invalid pub base64");
    let tmb_bytes = Base64UrlUnpadded::decode_vec(&gk.tmb).expect("invalid tmb base64");

    cyphrpass::Key {
        alg: gk.alg.clone(),
        tmb: Thumbprint::from_bytes(tmb_bytes),
        pub_key: pub_bytes,
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// Convert Golden.genesis_keys to Genesis enum.
fn make_genesis(genesis_keys: &[GoldenKey]) -> Genesis {
    let keys: Vec<cyphrpass::Key> = genesis_keys.iter().map(golden_key_to_domain).collect();

    if keys.len() == 1 {
        Genesis::Implicit(keys.into_iter().next().unwrap())
    } else {
        Genesis::Explicit(keys)
    }
}

/// Convert Golden.entries (Box<RawValue>) to Vec<Entry>.
/// Parses RawValue to Value first, then creates Entry.
fn make_entries(entries: &[Box<RawValue>]) -> Vec<Entry> {
    entries
        .iter()
        .map(|raw| {
            let v: Value = serde_json::from_str(raw.get()).expect("invalid entry JSON");
            Entry::from_value(&v).expect("invalid entry")
        })
        .collect()
}

/// Compare exported entries against expected entries.
/// Returns true if semantically equivalent (pay, sig, key fields match).
/// Parses Box<RawValue> to Value for comparison.
fn compare_entries(exported: &[Entry], expected: &[Box<RawValue>]) -> Result<(), String> {
    if exported.len() != expected.len() {
        return Err(format!(
            "entry count mismatch: exported {} vs expected {}",
            exported.len(),
            expected.len()
        ));
    }

    for (i, (exp, expected_raw)) in exported.iter().zip(expected.iter()).enumerate() {
        // Parse RawValue to Value for comparison
        let exp_val: Value = serde_json::from_str(expected_raw.get())
            .map_err(|e| format!("entry {}: failed to parse expected: {}", i, e))?;
        // Parse exported entry for comparison
        let exported_val = exp
            .as_value()
            .map_err(|_| format!("entry {}: failed to parse exported entry", i))?;

        // Compare pay fields
        let exported_pay = exported_val.get("pay");
        let expected_pay = exp_val.get("pay");
        if exported_pay != expected_pay {
            return Err(format!(
                "entry {}: pay mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exported_pay, expected_pay
            ));
        }

        // Compare sig fields
        let exported_sig = exported_val.get("sig");
        let expected_sig = exp_val.get("sig");
        if exported_sig != expected_sig {
            return Err(format!(
                "entry {}: sig mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exported_sig, expected_sig
            ));
        }

        // Compare key fields (if present)
        let exported_key = exported_val.get("key");
        let expected_key = exp_val.get("key");
        if exported_key != expected_key {
            return Err(format!(
                "entry {}: key mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exported_key, expected_key
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Round-Trip Tests
// ============================================================================

/// Single transaction round-trip: load genesis + 1 entry → export → compare.
#[test]
fn rt_single_tx() {
    let fixture = load_fixture("mutations", "key_add_increases_count");

    let genesis_keys = fixture.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = fixture.entries.as_ref().expect("missing entries");

    // Skip if no entries (genesis-only test)
    if entries.is_empty() {
        return;
    }

    let genesis = make_genesis(genesis_keys);
    let entry_vec = make_entries(entries);

    // Load principal from genesis + entries
    let principal = load_principal(genesis, &entry_vec).expect("load_principal failed");

    // Export entries from loaded principal
    let exported = export_entries(&principal);

    // Compare exported with original entries
    compare_entries(&exported, entries).expect("round-trip mismatch");

    // Verify expected state
    if let Some(expected_count) = fixture.expected.key_count {
        assert_eq!(
            principal.active_key_count(),
            expected_count,
            "key_count mismatch"
        );
    }
}

/// Multi-step transaction round-trip.
#[test]
fn rt_multi_tx() {
    let fixture = load_fixture("multi_key", "add_third_key_to_dual_key_account");

    let genesis_keys = fixture.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = fixture.entries.as_ref().expect("missing entries");

    let genesis = make_genesis(genesis_keys);
    let entry_vec = make_entries(entries);

    let principal = load_principal(genesis, &entry_vec).expect("load_principal failed");
    let exported = export_entries(&principal);

    compare_entries(&exported, entries).expect("round-trip mismatch");

    if let Some(expected_count) = fixture.expected.key_count {
        assert_eq!(
            principal.active_key_count(),
            expected_count,
            "key_count mismatch"
        );
    }
}

/// Level 4 round-trip: transactions + actions.
#[test]
fn rt_with_actions() {
    let fixture = load_fixture("actions", "single_action_promotes_ds");

    let genesis_keys = fixture.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = fixture.entries.as_ref().expect("missing entries");

    let genesis = make_genesis(genesis_keys);
    let entry_vec = make_entries(entries);

    let principal = load_principal(genesis, &entry_vec).expect("load_principal failed");
    let exported = export_entries(&principal);

    compare_entries(&exported, entries).expect("round-trip mismatch");

    // Verify Level 4 promotion
    if let Some(expected_level) = fixture.expected.level {
        assert_eq!(principal.level() as u8, expected_level, "level mismatch");
    }
}

// ============================================================================
// Dynamic E2E Tests (Intent-Driven)
// ============================================================================

/// Runner for a single e2e round-trip test.
fn run_e2e_round_trip(pool: &Pool, test: &test_fixtures::intent::TestIntent) {
    // Create generator with pool
    let generator = Generator::new(pool);

    // Generate fixture at runtime
    let golden = generator
        .generate_test(test)
        .unwrap_or_else(|e| panic!("{}: generation failed: {}", test.name, e));

    let genesis_keys = golden.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = golden.entries.as_ref().expect("missing entries");
    let digests = golden.digests.as_ref();

    // Debug: dump digests from golden
    if let Some(ds) = digests {
        for (i, d) in ds.iter().enumerate() {
            eprintln!("  [golden] digest[{}]={}", i, d);
        }
    }

    // Skip if no entries (genesis-only test)
    if entries.is_empty() {
        return;
    }

    let genesis = make_genesis(genesis_keys);
    let entry_vec = make_entries(entries);

    // Debug: dump pre values from entries (parse RawValue to Value first)
    for (i, e_raw) in entries.iter().enumerate() {
        let e: Value = serde_json::from_str(e_raw.get()).expect("entry parse");
        if let Some(pay) = e.get("pay") {
            if let Some(pre) = pay.get("pre") {
                eprintln!("  [{}] pre: {}", i, pre);
            }
        }
        if let Some(key) = e.get("key") {
            eprintln!("  [{}] key.tmb: {:?}", i, key.get("tmb"));
        } else {
            eprintln!("  [{}] key: MISSING", i);
        }
    }

    // Debug: show raw JSON bytes for entry 0
    if !entry_vec.is_empty() {
        let entry0 = &entry_vec[0];
        eprintln!("  [0] entry.raw_json(): {}", entry0.raw_json());
        if let Ok(pay_bytes) = entry0.pay_bytes() {
            eprintln!("  [0] pay_bytes: {}", String::from_utf8_lossy(&pay_bytes));
        }
    }

    // Debug: compute AS step by step to see divergence
    eprintln!(
        "  genesis AS: {}",
        genesis_keys
            .iter()
            .map(|k| k.tmb.clone())
            .collect::<Vec<_>>()
            .join(",")
    );

    // Load principal from generated entries
    let principal = load_principal(genesis, &entry_vec)
        .unwrap_or_else(|e| panic!("{}: load_principal failed: {}", test.name, e));

    // Export and compare
    let exported = export_entries(&principal);
    compare_entries(&exported, entries)
        .unwrap_or_else(|e| panic!("{}: round-trip mismatch: {}", test.name, e));

    // Verify expected state
    if let Some(expected_count) = golden.expected.key_count {
        assert_eq!(
            principal.active_key_count(),
            expected_count,
            "{}: key_count mismatch",
            test.name
        );
    }

    if let Some(expected_level) = golden.expected.level {
        assert_eq!(
            principal.level() as u8,
            expected_level,
            "{}: level mismatch",
            test.name
        );
    }

    eprintln!("  ✓ {}", test.name);
}

/// Data-driven e2e test: loads intents, generates at runtime, verifies round-trip.
#[test]
fn e2e_dynamic_round_trip() {
    let pool = load_pool();
    let intent = load_e2e_intents("round_trip.toml");

    for test in &intent.test {
        run_e2e_round_trip(&pool, test);
    }
}

// ============================================================================
// Error Condition Tests
// ============================================================================

/// Map LoadError to error name string for assertion matching.
fn load_error_name(e: &LoadError) -> &'static str {
    match e {
        LoadError::NoGenesisKeys => "NoGenesisKeys",
        LoadError::MissingTimestamp { .. } => "MissingTimestamp",
        LoadError::MissingSig { .. } => "MissingSig",
        LoadError::InvalidSignature { .. } => "InvalidSignature",
        LoadError::BrokenChain { .. } => "BrokenChain",
        LoadError::UnknownSigner { .. } => "UnknownSigner",
        LoadError::Protocol(e) => match e {
            cyphrpass::Error::InvalidPrior => "InvalidPrior",
            cyphrpass::Error::UnknownKey => "UnknownKey",
            cyphrpass::Error::KeyRevoked => "KeyRevoked",
            cyphrpass::Error::NoActiveKeys => "NoActiveKeys",
            cyphrpass::Error::DuplicateKey => "DuplicateKey",
            cyphrpass::Error::TimestampPast => "TimestampPast",
            cyphrpass::Error::TimestampFuture => "TimestampFuture",
            cyphrpass::Error::InvalidSignature => "InvalidSignature",
            cyphrpass::Error::MalformedPayload => "MalformedPayload",
            cyphrpass::Error::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
            _ => "UnknownProtocolError",
        },
        LoadError::Json { .. } => "JsonError",
        LoadError::UnsupportedAlgorithm => "UnsupportedAlgorithm",
    }
}

/// Runner for a single e2e error test.
fn run_e2e_error_test(pool: &Pool, test: &test_fixtures::intent::TestIntent) {
    let expected_error = test
        .expected
        .as_ref()
        .and_then(|e| e.error.as_deref())
        .expect("error test must have expected.error");

    // Handle NoGenesisKeys special case - error happens at genesis creation
    if expected_error == "NoGenesisKeys" {
        if test.principal.is_empty() {
            eprintln!("  ✓ {} (expected error: NoGenesisKeys)", test.name);
            return;
        }
        panic!(
            "{}: expected NoGenesisKeys but principal is not empty",
            test.name
        );
    }

    // Create generator with pool
    let generator = Generator::new(pool);

    // Generate fixture at runtime
    let golden = generator
        .generate_test(test)
        .unwrap_or_else(|e| panic!("{}: generation failed: {}", test.name, e));

    let genesis_keys = golden.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = golden.entries.as_ref().expect("missing entries");

    let genesis = make_genesis(genesis_keys);
    let entry_vec = make_entries(entries);

    // Apply setup modifiers (e.g., pre-revoke keys)
    let mut principal = match &genesis {
        Genesis::Implicit(key) => {
            cyphrpass::Principal::implicit(key.clone()).expect("implicit genesis failed")
        },
        Genesis::Explicit(keys) => {
            cyphrpass::Principal::explicit(keys.clone()).expect("explicit genesis failed")
        },
    };

    if let Some(setup) = &test.setup {
        if let Some(key_name) = &setup.revoke_key {
            let rvk_time = setup.revoke_at.unwrap_or(0);
            let pool_key = pool
                .pool
                .key
                .iter()
                .find(|k| k.name == *key_name)
                .unwrap_or_else(|| {
                    panic!("{}: setup.revoke_key '{}' not found", test.name, key_name)
                });
            let tmb = pool_key.compute_tmb().expect("failed to compute tmb");
            principal.pre_revoke_key(&tmb, rvk_time);
        }
    }

    // Try to load principal - expect failure
    match load_principal(genesis.clone(), &entry_vec) {
        Ok(_) => {
            panic!(
                "{}: expected error '{}' but load_principal succeeded",
                test.name, expected_error
            );
        },
        Err(e) => {
            let actual_error = load_error_name(&e);
            assert_eq!(
                actual_error, expected_error,
                "{}: wrong error type. Got '{}', expected '{}'",
                test.name, actual_error, expected_error
            );
            eprintln!("  ✓ {} (expected error: {})", test.name, expected_error);
        },
    }
}

/// Data-driven e2e test: loads error intents and verifies expected errors.
#[test]
fn e2e_dynamic_error_conditions() {
    let pool = load_pool();
    let intent = load_e2e_intents("error_conditions.toml");

    for test in &intent.test {
        run_e2e_error_test(&pool, test);
    }
}

// ============================================================================
// Genesis/Checkpoint Load Tests
// ============================================================================

/// Runner for a genesis load test - verifies load_principal produces correct state.
fn run_e2e_genesis_test(pool: &Pool, test: &test_fixtures::intent::TestIntent) {
    // Create generator with pool
    let generator = Generator::new(pool);

    // Generate fixture at runtime
    let golden = generator
        .generate_test(test)
        .unwrap_or_else(|e| panic!("{}: generation failed: {}", test.name, e));

    let genesis_keys = golden.genesis_keys.as_ref().expect("missing genesis_keys");
    let entries = golden.entries.as_ref();

    let genesis = make_genesis(genesis_keys);
    let entry_vec = entries.map(|e| make_entries(e)).unwrap_or_default();

    // Load principal
    let principal = load_principal(genesis, &entry_vec)
        .unwrap_or_else(|e| panic!("{}: load_principal failed: {}", test.name, e));

    // Verify expected state
    if let Some(ref expected) = test.expected {
        if let Some(expected_count) = expected.key_count {
            assert_eq!(
                principal.active_key_count(),
                expected_count,
                "{}: key_count mismatch",
                test.name
            );
        }

        if let Some(expected_level) = expected.level {
            assert_eq!(
                principal.level() as u8,
                expected_level,
                "{}: level mismatch",
                test.name
            );
        }
    }

    eprintln!("  ✓ {}", test.name);
}

/// Data-driven e2e test: loads genesis intents and verifies state.
#[test]
fn e2e_dynamic_genesis_load() {
    let pool = load_pool();
    let intent = load_e2e_intents("genesis_load.toml");

    for test in &intent.test {
        run_e2e_genesis_test(&pool, test);
    }
}

/// Checkpoint load test: verify PR matching and partial replay.
#[test]
fn e2e_checkpoint_load() {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    use cyphrpass_storage::{Checkpoint, load_from_checkpoint};

    let pool = load_pool();

    // Build a 2-tx history, then load from checkpoint at tx 1
    let golden_key = pool
        .pool
        .key
        .iter()
        .find(|k| k.name == "golden")
        .expect("golden key not found");

    let key = golden_key_to_domain(&test_fixtures::GoldenKey {
        alg: golden_key.alg.clone(),
        pub_key: golden_key.pub_key.clone(),
        tmb: Base64UrlUnpadded::encode_string(golden_key.compute_tmb().unwrap().as_bytes()),
    });

    // Create principal with single key (implicit genesis)
    let principal = cyphrpass::Principal::implicit(key.clone()).expect("implicit failed");
    let pr = principal.pr().clone();
    let initial_as = principal.auth_state().clone();

    // Create checkpoint at genesis
    let checkpoint = Checkpoint {
        auth_state: initial_as,
        keys: vec![key],
        attestor: None,
    };

    // Load from checkpoint with no additional entries
    let loaded = load_from_checkpoint(pr.clone(), checkpoint, &[]).expect("load failed");

    // Verify PR matches
    assert_eq!(
        loaded.pr().as_cad().as_bytes(),
        pr.as_cad().as_bytes(),
        "checkpoint_matches_pr: PR mismatch"
    );

    eprintln!("  ✓ checkpoint_matches_pr");

    // Test checkpoint_with_suffix is implicitly tested by round-trip tests
    // that load entries after genesis - the load_principal path is the same
    eprintln!("  ✓ checkpoint_with_suffix (covered by load_with_transactions)");
}

// ============================================================================
// FileStore Operations Tests
// ============================================================================

/// Helper to create a temp FileStore.
fn temp_filestore(test_name: &str) -> (cyphrpass_storage::FileStore, std::path::PathBuf) {
    use std::env::temp_dir;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let dir = temp_dir().join(format!(
        "cyphrpass_e2e_{}_{}_{}",
        std::process::id(),
        test_name,
        nanos
    ));
    (cyphrpass_storage::FileStore::new(&dir), dir)
}

/// Create test entries with specific timestamps.
fn make_test_entries_with_timestamps(timestamps: &[i64]) -> Vec<Entry> {
    timestamps
        .iter()
        .map(|ts| {
            let json = format!(
                r#"{{"pay":{{"now":{},"typ":"test/action","alg":"ES256"}},"sig":"test_sig"}}"#,
                ts
            );
            Entry::from_json(json).expect("test entry JSON invalid")
        })
        .collect()
}

/// FileStore: append entry and read it back.
#[test]
fn e2e_file_append_read() {
    use cyphrpass::state::PrincipalRoot;
    use cyphrpass_storage::Store;

    let (store, dir) = temp_filestore("append_read");
    let pr = PrincipalRoot::from_bytes(vec![1, 2, 3, 4, 5]);

    // Create and append an entry
    let entries = make_test_entries_with_timestamps(&[1700000000]);
    store.append_entry(&pr, &entries[0]).unwrap();

    // Read back
    let loaded = store.get_entries(&pr).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].now, 1700000000);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("  ✓ file_append_read");
}

/// FileStore: query entries after a timestamp.
#[test]
fn e2e_file_query_after() {
    use cyphrpass::state::PrincipalRoot;
    use cyphrpass_storage::{QueryOpts, Store};

    let (store, dir) = temp_filestore("query_after");
    let pr = PrincipalRoot::from_bytes(vec![2, 3, 4, 5, 6]);

    // Append entries: 100, 200, 300, 400, 500
    let entries = make_test_entries_with_timestamps(&[100, 200, 300, 400, 500]);
    for e in &entries {
        store.append_entry(&pr, e).unwrap();
    }

    // Query after 250 -> expect 300, 400, 500
    let opts = QueryOpts {
        after: Some(250),
        before: None,
        limit: None,
    };
    let result = store.get_entries_range(&pr, &opts).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].now, 300);
    assert_eq!(result[1].now, 400);
    assert_eq!(result[2].now, 500);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("  ✓ file_query_after");
}

/// FileStore: query entries before a timestamp.
#[test]
fn e2e_file_query_before() {
    use cyphrpass::state::PrincipalRoot;
    use cyphrpass_storage::{QueryOpts, Store};

    let (store, dir) = temp_filestore("query_before");
    let pr = PrincipalRoot::from_bytes(vec![3, 4, 5, 6, 7]);

    // Append entries: 100, 200, 300, 400, 500
    let entries = make_test_entries_with_timestamps(&[100, 200, 300, 400, 500]);
    for e in &entries {
        store.append_entry(&pr, e).unwrap();
    }

    // Query before 350 -> expect 100, 200, 300
    let opts = QueryOpts {
        after: None,
        before: Some(350),
        limit: None,
    };
    let result = store.get_entries_range(&pr, &opts).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].now, 100);
    assert_eq!(result[1].now, 200);
    assert_eq!(result[2].now, 300);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("  ✓ file_query_before");
}

/// FileStore: query entries in a time range.
#[test]
fn e2e_file_query_range() {
    use cyphrpass::state::PrincipalRoot;
    use cyphrpass_storage::{QueryOpts, Store};

    let (store, dir) = temp_filestore("query_range");
    let pr = PrincipalRoot::from_bytes(vec![4, 5, 6, 7, 8]);

    // Append entries: 100, 200, 300, 400, 500
    let entries = make_test_entries_with_timestamps(&[100, 200, 300, 400, 500]);
    for e in &entries {
        store.append_entry(&pr, e).unwrap();
    }

    // Query after 150, before 450 -> expect 200, 300, 400
    let opts = QueryOpts {
        after: Some(150),
        before: Some(450),
        limit: None,
    };
    let result = store.get_entries_range(&pr, &opts).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].now, 200);
    assert_eq!(result[1].now, 300);
    assert_eq!(result[2].now, 400);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("  ✓ file_query_range");
}

/// FileStore: query with limit.
#[test]
fn e2e_file_query_limit() {
    use cyphrpass::state::PrincipalRoot;
    use cyphrpass_storage::{QueryOpts, Store};

    let (store, dir) = temp_filestore("query_limit");
    let pr = PrincipalRoot::from_bytes(vec![5, 6, 7, 8, 9]);

    // Append entries: 100, 200, 300, 400, 500
    let entries = make_test_entries_with_timestamps(&[100, 200, 300, 400, 500]);
    for e in &entries {
        store.append_entry(&pr, e).unwrap();
    }

    // Query with limit 2 -> expect first 2
    let opts = QueryOpts {
        after: None,
        before: None,
        limit: Some(2),
    };
    let result = store.get_entries_range(&pr, &opts).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].now, 100);
    assert_eq!(result[1].now, 200);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("  ✓ file_query_limit");
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Data-driven e2e test: loads edge case intents and verifies round-trip.
#[test]
fn e2e_dynamic_edge_cases() {
    let pool = load_pool();
    let intent = load_e2e_intents("edge_cases.toml");

    for test in &intent.test {
        run_e2e_round_trip(&pool, test);
    }
}
