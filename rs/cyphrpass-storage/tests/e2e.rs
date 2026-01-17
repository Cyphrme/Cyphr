//! End-to-end tests for cyphrpass-storage.
//!
//! These tests consume golden fixtures to verify round-trip correctness:
//! genesis + entries → load_principal → export_entries → compare.

use std::fs;
use std::path::PathBuf;

use cyphrpass_storage::{Entry, Genesis, export_entries, load_principal};
use serde_json::Value;
use test_fixtures::{Golden, GoldenKey, Pool};

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

#[allow(dead_code)]
fn load_pool() -> Pool {
    let path = tests_dir().join("keys").join("pool.toml");
    Pool::load(&path).expect("failed to load pool.toml")
}

/// Load a single golden fixture by category and name.
fn load_fixture(category: &str, name: &str) -> Golden {
    let path = golden_dir().join(category).join(format!("{}.json", name));
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {:?}: {}", path, e))
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
        .map(|v| Entry::from_value(v.clone()).expect("invalid entry"))
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
        let exp_raw = &exp.raw;

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
