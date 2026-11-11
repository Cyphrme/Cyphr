//! End-to-end checks on the numbered-key and repeated-item corpus forms
//! (tests/README.md, "Numbered keys and repeated items").
//!
//! Each test names the claim it backs. They are corpus scenarios: they load
//! the committed intents and goldens the way a consumer does, so a vector
//! that drifts from its intent, or from the property it exists to pin, turns
//! them red.

use std::path::PathBuf;

use serde_json::Value;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("rs/test-fixtures sits two levels under the repository root")
        .join("tests")
}

/// The committed golden `name` of intent file `file` (a stem under tests/golden).
fn golden(file: &str, name: &str) -> Value {
    let path = tests_dir().join(format!("golden/{file}/{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("committed golden {} is missing: {e}", path.display()));
    serde_json::from_str(&text).expect("golden is JSON")
}

fn kr(g: &Value) -> &Value {
    &g["expected"]["kr"]
}

/// Claim (SPEC 4, n-arity): a collection node past 256 items folds into a
/// second tree level, and removing the surplus leaves KR exactly that of
/// the 256-key principal. Red if the Merkle fold changes past 256 keys, or
/// deleting a key leaves residue in KR. End to end: yes (genesis -> commit
/// -> roots).
#[test]
fn past_256_keys_fold_and_delete_returns_to_256() {
    let k256 = golden("numbered_keys", "explicit_genesis_256_keys");
    let k257 = golden("numbered_keys", "explicit_genesis_257_keys");
    let k300 = golden("numbered_keys", "explicit_genesis_300_keys");
    let del = golden("numbered_keys", "key_delete_257th_matches_256_keys");
    for (g, n) in [(&k256, 256), (&k257, 257), (&k300, 300)] {
        assert_eq!(g["genesis_keys"].as_array().map(Vec::len), Some(n));
        assert_eq!(g["expected"]["key_count"], n);
    }
    assert_ne!(kr(&k256), kr(&k257), "a 257th key must change KR");
    assert_ne!(kr(&k257), kr(&k300));
    assert_eq!(del["expected"]["key_count"], 256);
    assert_eq!(
        kr(&del),
        kr(&k256),
        "delete of the 257th key must restore KR"
    );
}

/// Claim (SPEC 3.7): a Dead principal that holds data keeps DR; SR is then
/// the DR alone (no AR to fold with), and KR and AR are absent. Red if a
/// dying commit drops the data root, or SR still folds in a stale AR. End
/// to end: yes (action -> ds/create -> last-key revoke).
#[test]
fn dead_principal_keeps_data_root() {
    let g = golden("lifecycle", "dead_with_data_keeps_dr");
    let e = &g["expected"];
    assert_eq!(e["key_count"], 0);
    assert!(
        e["kr"].is_null() && e.get("kr").is_some(),
        "KR must be null"
    );
    assert!(
        e["ar"].is_null() && e.get("ar").is_some(),
        "AR must be null"
    );
    let dr = e["dr"].as_str().expect("DR present");
    assert_eq!(e["sr"], format!("SHA-256:{dr}"), "SR must equal DR");
}
