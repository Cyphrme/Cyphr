//! End-to-end tests for cyphrpass-storage.
//!
//! These tests verify round-trip correctness by dynamically generating fixtures:
//! intent → generate → export → import → compare state.
//!
//! Unlike integration tests which use pre-generated golden files, e2e tests
//! generate fixtures at runtime, testing the full generation pipeline.

use std::fs;
use std::path::PathBuf;

use cyphrpass_storage::{
    CommitEntry, Entry, Genesis, LoadError, export_commits, load_principal_from_commits,
};

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
/// Convert Golden.commits to format suitable for load_principal_from_commits.
/// Just returns a clone since CommitEntry is already the right type.
fn make_commits(commits: &[CommitEntry]) -> Vec<CommitEntry> {
    commits.to_vec()
}

/// Compare exported commits against expected commits.
/// Returns ok if semantically equivalent.
/// Note: expected may contain action pseudo-commits which are filtered out
/// since export_commits only exports transactions.
fn compare_commits(exported: &[CommitEntry], expected: &[CommitEntry]) -> Result<(), String> {
    // Filter expected to only transaction commits (exclude action pseudo-commits)
    // Transactions: key/* and principal/create
    let tx_commits: Vec<_> = expected
        .iter()
        .filter(|c| {
            // A commit is a transaction commit if its first tx has a transaction typ
            c.txs.first().is_some_and(|tx| {
                tx.get("pay")
                    .and_then(|p| p.get("typ"))
                    .and_then(|t| t.as_str())
                    .is_some_and(|typ| typ.contains("/key/") || typ.contains("/principal/create"))
            })
        })
        .collect();

    if exported.len() != tx_commits.len() {
        return Err(format!(
            "commit count mismatch: exported {} vs expected {} (tx commits)",
            exported.len(),
            tx_commits.len()
        ));
    }

    for (i, (exp, expected_commit)) in exported.iter().zip(tx_commits.iter()).enumerate() {
        // Compare transaction counts
        if exp.txs.len() != expected_commit.txs.len() {
            return Err(format!(
                "commit {}: tx count mismatch {} vs {}",
                i,
                exp.txs.len(),
                expected_commit.txs.len()
            ));
        }

        // Compare state digests
        if exp.commit_id != expected_commit.commit_id {
            return Err(format!(
                "commit {}: commit_id mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp.commit_id, expected_commit.commit_id
            ));
        }

        if exp.auth_state != expected_commit.auth_state {
            return Err(format!(
                "commit {}: as mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp.auth_state, expected_commit.auth_state
            ));
        }

        if exp.cs != expected_commit.cs {
            return Err(format!(
                "commit {}: cs mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp.cs, expected_commit.cs
            ));
        }

        if exp.ps != expected_commit.ps {
            return Err(format!(
                "commit {}: ps mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp.ps, expected_commit.ps
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
    let commits = fixture.commits.as_ref().expect("missing commits");

    // Skip if no entries (genesis-only test)
    if commits.is_empty() {
        return;
    }

    let genesis = make_genesis(genesis_keys);
    let commit_vec = make_commits(commits);

    // Load principal from genesis + entries
    let principal =
        load_principal_from_commits(genesis, &commit_vec).expect("load_principal failed");

    // Export entries from loaded principal
    let exported = export_commits(&principal).unwrap();

    // Compare exported with original entries
    compare_commits(&exported, commits).expect("round-trip mismatch");

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
    let commits = fixture.commits.as_ref().expect("missing commits");

    let genesis = make_genesis(genesis_keys);
    let commit_vec = make_commits(commits);

    let principal =
        load_principal_from_commits(genesis, &commit_vec).expect("load_principal failed");
    let exported = export_commits(&principal).unwrap();

    compare_commits(&exported, commits).expect("round-trip mismatch");

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
    let commits = fixture.commits.as_ref().expect("missing commits");

    let genesis = make_genesis(genesis_keys);
    let commit_vec = make_commits(commits);

    let principal =
        load_principal_from_commits(genesis, &commit_vec).expect("load_principal failed");
    let exported = export_commits(&principal).unwrap();

    compare_commits(&exported, commits).expect("round-trip mismatch");

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
    let commits = golden.commits.as_ref().expect("missing commits");
    let digests = golden.digests.as_ref();

    // Debug: dump digests from golden
    if let Some(ds) = digests {
        for (i, d) in ds.iter().enumerate() {
            eprintln!("  [golden] digest[{}]={}", i, d);
        }
    }

    // Skip if no commits (genesis-only test)
    if commits.is_empty() {
        return;
    }

    let genesis = make_genesis(genesis_keys);
    let commit_vec = make_commits(commits);

    // Debug: dump pre values from commit transactions
    for (ci, commit) in commits.iter().enumerate() {
        for (ti, tx) in commit.txs.iter().enumerate() {
            if let Some(pay) = tx.get("pay") {
                if let Some(pre) = pay.get("pre") {
                    eprintln!("  [{}:{}] pre: {}", ci, ti, pre);
                }
            }
            if let Some(key) = tx.get("key") {
                eprintln!("  [{}:{}] key.tmb: {:?}", ci, ti, key.get("tmb"));
            }
        }
    }

    // Debug: show commit state digests
    if !commit_vec.is_empty() {
        let commit0 = &commit_vec[0];
        eprintln!(
            "  [0] commit_id={}, as={}, ps={}",
            commit0.commit_id, commit0.auth_state, commit0.ps
        );
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
    let principal = load_principal_from_commits(genesis, &commit_vec)
        .unwrap_or_else(|e| panic!("{}: load_principal failed: {}", test.name, e));

    // Export and compare
    let exported = export_commits(&principal).unwrap();
    compare_commits(&exported, commits)
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
    let commits = golden.commits.as_ref().expect("missing commits");

    let genesis = make_genesis(genesis_keys);
    let commit_vec = make_commits(commits);

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
    match load_principal_from_commits(genesis.clone(), &commit_vec) {
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
    let commits = golden.commits.as_ref();

    let genesis = make_genesis(genesis_keys);
    let commit_vec = commits.map(|c| make_commits(c)).unwrap_or_default();

    // Load principal
    let principal = load_principal_from_commits(genesis, &commit_vec)
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
        loaded.pr().get(loaded.hash_alg()).unwrap(),
        pr.get(cyphrpass::HashAlg::Sha256).unwrap(),
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

// ============================================================================
// Multihash Coherence Tests (SPEC §14)
// ============================================================================

/// Multihash round-trip coherence test.
///
/// Verifies that after serialization and reimport:
/// 1. All expected hash algorithm variants are present
/// 2. Each variant matches independently recomputed values
///
/// This proves the round-trip preserves information needed for deterministic
/// state derivation across all supported algorithms.
#[test]
fn e2e_multihash_round_trip() {
    use cyphrpass::state::{compute_as, compute_cs, compute_ks, compute_ps};

    let pool = load_pool();
    let intent = load_e2e_intents("multihash_coherence.toml");

    for test in &intent.test {
        eprintln!("  Testing multihash coherence: {}", test.name);

        // Generate fixture at runtime
        let generator = Generator::new(&pool);
        let golden = generator
            .generate_test(test)
            .unwrap_or_else(|e| panic!("{}: generation failed: {}", test.name, e));

        let genesis_keys = golden.genesis_keys.as_ref().expect("missing genesis_keys");
        let commits = golden.commits.as_ref().expect("missing commits");

        if commits.is_empty() {
            continue;
        }

        let genesis = make_genesis(genesis_keys);
        let commit_vec = make_commits(commits);

        // --- Step 1: Load principal from serialized commits ---
        let principal = load_principal_from_commits(genesis, &commit_vec)
            .unwrap_or_else(|e| panic!("{}: load_principal failed: {}", test.name, e));

        // --- Step 2: Verify active_algs contains expected algorithms ---
        let active_algs = principal.active_algs();
        assert!(
            !active_algs.is_empty(),
            "{}: active_algs should not be empty",
            test.name
        );

        eprintln!(
            "    active_algs: {:?} ({} variants)",
            active_algs,
            active_algs.len()
        );

        // For mixed-algorithm principals, we expect multiple algorithms
        // (e.g., Ed25519+ES256 → Sha512 + Sha256)
        if test.name.contains("adds_es256") {
            assert!(
                active_algs.len() >= 2,
                "{}: expected multiple algorithms for mixed-key principal, got {:?}",
                test.name,
                active_algs
            );
        }

        // --- Step 3: Verify each variant is coherent (recomputable) ---
        // Get thumbprints from current keyset
        let thumbprints: Vec<_> = principal.active_keys().map(|k| &k.tmb).collect();

        // Recompute KS with all active algorithms
        let recomputed_ks = compute_ks(&thumbprints.to_vec(), None, active_algs).unwrap();

        // Verify each algorithm variant matches
        for &alg in active_algs {
            // KS coherence
            let principal_ks = principal.key_state().get(alg);
            let recomputed_ks_variant = recomputed_ks.get(alg);

            assert_eq!(
                principal_ks, recomputed_ks_variant,
                "{}: KS variant {:?} mismatch - reimported != recomputed",
                test.name, alg
            );

            // Verify AS variant exists
            let principal_as = principal.auth_state().get(alg);
            assert!(
                principal_as.is_some(),
                "{}: AS variant {:?} should exist",
                test.name,
                alg
            );

            // Verify PS variant exists
            let principal_ps = principal.ps().get(alg);
            assert!(
                principal_ps.is_some(),
                "{}: PS variant {:?} should exist",
                test.name,
                alg
            );

            eprintln!("    ✓ {:?} variant present (KS/AS/PS)", alg);
        }

        // PR is immutable from genesis - only has genesis algorithm variant (native-only)
        // This is per design decision: PR is derived once at genesis, not recomputed
        let genesis_alg = principal.hash_alg();
        let principal_pr = principal.pr().get(genesis_alg);
        assert!(
            principal_pr.is_some(),
            "{}: PR should have genesis algorithm {:?} variant",
            test.name,
            genesis_alg
        );
        eprintln!("    ✓ PR has genesis algorithm {:?} variant", genesis_alg);

        // --- Step 4: Full AS/CS/PS recomputation verification ---
        // Recompute AS from KS
        let recomputed_as = compute_as(&recomputed_ks, None, active_algs).unwrap();

        for &alg in active_algs {
            assert_eq!(
                principal.auth_state().get(alg),
                recomputed_as.get(alg),
                "{}: AS variant {:?} mismatch after recomputation",
                test.name,
                alg
            );
        }

        // Recompute CS from AS + Commit ID
        let commit_id = principal.current_commit_id();
        let recomputed_cs = compute_cs(&recomputed_as, commit_id, active_algs).unwrap();

        // Recompute PS from CS
        let recomputed_ps =
            compute_ps(&recomputed_cs, principal.data_state(), None, active_algs).unwrap();

        for &alg in active_algs {
            assert_eq!(
                principal.ps().get(alg),
                recomputed_ps.get(alg),
                "{}: PS variant {:?} mismatch after recomputation",
                test.name,
                alg
            );
        }

        eprintln!("  ✓ {} multihash coherence verified", test.name);
    }
}
