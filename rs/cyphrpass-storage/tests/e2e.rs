//! End-to-end tests for cyphrpass-storage.
//!
//! These tests verify round-trip correctness by dynamically generating fixtures:
//! intent → generate → export → import → compare state.
//!
//! Unlike integration tests which use pre-generated golden files, e2e tests
//! generate fixtures at runtime, testing the full generation pipeline.

use std::fs;
use std::path::PathBuf;

use cyphrpass_storage::{Entry, Genesis, export_entries, load_principal};
use serde_json::Value;
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

/// Convert Golden.entries to Vec<Entry>.
fn make_entries(entries: &[Value]) -> Vec<Entry> {
    entries
        .iter()
        .map(|v| Entry::from_value(v).expect("invalid entry"))
        .collect()
}

/// Compare exported entries against expected entries.
/// Returns true if semantically equivalent (pay, sig, key fields match).
fn compare_entries(exported: &[Entry], expected: &[Value]) -> Result<(), String> {
    if exported.len() != expected.len() {
        return Err(format!(
            "entry count mismatch: exported {} vs expected {}",
            exported.len(),
            expected.len()
        ));
    }

    for (i, (exp, exp_val)) in exported.iter().zip(expected.iter()).enumerate() {
        // Parse exported entry for comparison
        let exp_raw = exp
            .as_value()
            .map_err(|_| format!("entry {}: failed to parse exported entry", i))?;

        // Compare pay fields
        let exp_pay = exp_raw.get("pay");
        let expected_pay = exp_val.get("pay");
        if exp_pay != expected_pay {
            return Err(format!(
                "entry {}: pay mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp_pay, expected_pay
            ));
        }

        // Compare sig fields
        let exp_sig = exp_raw.get("sig");
        let expected_sig = exp_val.get("sig");
        if exp_sig != expected_sig {
            return Err(format!(
                "entry {}: sig mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp_sig, expected_sig
            ));
        }

        // Compare key fields (if present)
        let exp_key = exp_raw.get("key");
        let expected_key = exp_val.get("key");
        if exp_key != expected_key {
            return Err(format!(
                "entry {}: key mismatch\n  exported: {:?}\n  expected: {:?}",
                i, exp_key, expected_key
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
    let generator = Generator::new(&pool);

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

    // Debug: dump pre values from entries
    for (i, e) in entries.iter().enumerate() {
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
