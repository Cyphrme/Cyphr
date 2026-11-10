//! Transaction application, action recording and key-ledger tests.

use super::*;

// ========================================================================
// ParsedCoz application tests
// ========================================================================

// ========================================================================
// Action recording tests (Level 4)
// ========================================================================

// ========================================================================
// Self-revoke guard tests (C12)
// ========================================================================

// ========================================================================
// Key first_seen tests (C14)
// ========================================================================

/// Backs the key model (`first_seen` is the adding coz's `now`, never caller-supplied).
/// Unit: the golden vectors compare roots and counts, not per-key metadata.
#[test]
fn key_add_sets_first_seen_from_tx_now() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();
    principal.genesis_test().unwrap();

    let mut key2 = make_test_key(0x22);
    key2.set_first_seen(0); // Caller may not set this

    // ParsedCoz has now=2000
    let cz = make_key_add_tx(&key2, key1.tmb());
    assert_eq!(cz.now, 2000);

    principal
        .apply_transaction_test(cz, Some(key2.clone()))
        .unwrap();

    // New key's first_seen should be set from cz.now
    let added_key = principal.get_key(key2.tmb()).unwrap();
    assert_eq!(added_key.first_seen(), 2000);
}

// ========================================================================
// Revoked key guard tests (C15)
// ========================================================================

// ========================================================================
// Last-used tracking tests (C17)
// ========================================================================

/// Backs the key model (`last_used` is the signer's latest coz `now`) on the commit path.
/// Unit: the golden vectors compare roots and counts, not per-key metadata.
#[test]
fn transaction_updates_signer_last_used() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();
    principal.genesis_test().unwrap();
    // The genesis commit is the key's first use.
    assert_eq!(principal.get_key(key1.tmb()).unwrap().last_used(), Some(1));

    // Apply a key/create coz with now=5000
    let key2 = make_test_key(0x22);

    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};
    let cz = ParsedCoz {
        kind: CozKind::KeyCreate {
            id: key2.tmb().clone(),
        },
        signer: key1.tmb().clone(),
        now: 5000,
        czd: Czd::from_bytes(vec![0xBB; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };
    principal.apply_transaction_test(cz, Some(key2)).unwrap();

    // Signer's last_used should now be 5000
    assert_eq!(
        principal.get_key(key1.tmb()).unwrap().last_used(),
        Some(5000)
    );
}

/// Backs the key model (`last_used`) on the data-action path.
/// Unit: as above.
#[test]
fn action_updates_signer_last_used() {
    let key = make_test_key(0xAA);
    let mut principal = Principal::implicit(key.clone()).unwrap();

    assert!(principal.get_key(key.tmb()).unwrap().last_used().is_none());

    // Record action with now=7000
    let action = make_test_action(key.tmb());
    // Our test helper uses now=3000, let's verify that
    assert_eq!(action.now, 3000);

    principal.record_action(action).unwrap();

    assert_eq!(
        principal.get_key(key.tmb()).unwrap().last_used(),
        Some(3000)
    );
}
