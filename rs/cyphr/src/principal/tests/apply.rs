//! Transaction application, action recording and key-ledger tests.

use super::*;

// ========================================================================
// ParsedCoz application tests
// ========================================================================

#[test]
fn apply_key_add_increases_key_count() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();

    let key2 = make_test_key(0x22);
    let cz = make_key_add_tx(&key2, key1.tmb());

    principal
        .apply_transaction_test(cz, Some(key2.clone()))
        .unwrap();

    assert_eq!(principal.active_key_count(), 2);
    assert!(principal.is_key_active(key2.tmb()));
    assert_eq!(principal.level(), Level::L3);
}

#[test]
fn apply_key_add_changes_state() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();

    let old_as = principal
        .auth_root()
        .get(principal.hash_alg())
        .unwrap()
        .to_vec();
    let key2 = make_test_key(0x22);
    let cz = make_key_add_tx(&key2, key1.tmb());

    principal.apply_transaction_test(cz, Some(key2)).unwrap();
    // apply_transaction_test auto-finalizes the commit

    let new_as = principal
        .auth_root()
        .get(principal.hash_alg())
        .unwrap()
        .to_vec();
    // Auth state must change after adding key
    assert_ne!(old_as, new_as);
}

#[test]
fn pr_still_none_after_transaction() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();

    // PR is None at L1
    assert!(
        principal.pg().is_none(),
        "PR should be None before principal/create"
    );

    let key2 = make_test_key(0x22);
    let cz = make_key_add_tx(&key2, key1.tmb());

    principal.apply_transaction_test(cz, Some(key2)).unwrap();

    // PR should still be None (no principal/create was issued)
    assert!(
        principal.pg().is_none(),
        "PR should still be None without principal/create"
    );
}

// ========================================================================
// Action recording tests (Level 4)
// ========================================================================

#[test]
fn record_action_upgrades_to_level_4() {
    let key = make_test_key(0xAA);
    let mut principal = Principal::implicit(key.clone()).unwrap();

    assert_eq!(principal.level(), Level::L1);
    assert!(principal.data_root().is_none());

    let action = make_test_action(key.tmb());
    principal.record_action(action).unwrap();

    assert_eq!(principal.level(), Level::L4);
    assert!(principal.data_root().is_some());
    assert_eq!(principal.action_count(), 1);
}

#[test]
fn record_action_changes_ps() {
    let key = make_test_key(0xBB);
    let mut principal = Principal::implicit(key.clone()).unwrap();

    let pr_before = principal.pr().get(principal.hash_alg()).unwrap().to_vec();

    let action = make_test_action(key.tmb());
    principal.record_action(action).unwrap();

    let pr_after = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
    // PR changes when DS is added
    assert_ne!(pr_before, pr_after);
}

#[test]
fn record_action_unknown_signer_fails() {
    let key = make_test_key(0xCC);
    let mut principal = Principal::implicit(key).unwrap();

    // Try to record action from unknown key
    let unknown_tmb = Thumbprint::from_bytes(vec![0xFF; 32]);
    let action = make_test_action(&unknown_tmb);

    let result = principal.record_action(action);
    assert!(matches!(result, Err(Error::UnknownKey)));
}

// ========================================================================
// Self-revoke guard tests (C12)
// ========================================================================

#[test]
fn self_revoke_last_key_prevented() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let key = make_test_key(0xDD);
    let mut principal = Principal::implicit(key.clone()).unwrap();

    // Level 1: single key, self-revoke should fail
    assert_eq!(principal.level(), Level::L1);

    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 2000 },
        signer: key.tmb().clone(),
        now: 2000,
        czd: Czd::from_bytes(vec![0xEE; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    let result = principal.apply_transaction_test(cz, None);
    assert!(matches!(result, Err(Error::NoActiveKeys)));

    // Key should still be active (no mutation occurred)
    assert_eq!(principal.active_key_count(), 1);
    assert!(principal.is_key_active(key.tmb()));
}

#[test]
fn revoke_allowed_when_multiple_keys() {
    let key1 = make_test_key(0x11);
    let key2 = make_test_key(0x22);
    let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

    assert_eq!(principal.active_key_count(), 2);

    // Revoke key2 via self-revoke (key2 revokes itself)
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 2000 },
        signer: key2.tmb().clone(),
        now: 2000,
        czd: Czd::from_bytes(vec![0xFF; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    principal.apply_transaction_test(cz, None).unwrap();

    assert_eq!(principal.active_key_count(), 1);
    assert!(principal.is_key_active(key1.tmb()));
    assert!(!principal.is_key_active(key2.tmb()));
}

// ========================================================================
// Key first_seen tests (C14)
// ========================================================================

#[test]
fn key_add_sets_first_seen_from_tx_now() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();

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

#[test]
fn revoked_key_in_revoked_set() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let key1 = make_test_key(0x11);
    let key2 = make_test_key(0x22);
    let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

    // Revoke key2 (self-revoke)
    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 1500 },
        signer: key2.tmb().clone(),
        now: 1500,
        czd: Czd::from_bytes(vec![0xAA; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };
    principal.apply_transaction_test(cz, None).unwrap();

    // key2 should be in revoked set, not active
    assert!(!principal.is_key_active(key2.tmb()));
    assert!(principal.auth.revoked.contains_key(&key2.tmb().to_b64()));

    // get_key still finds it (for historical verification)
    assert!(principal.get_key(key2.tmb()).is_some());
}

// ========================================================================
// Last-used tracking tests (C17)
// ========================================================================

#[test]
fn transaction_updates_signer_last_used() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).unwrap();

    // Initially, last_used should be None
    assert!(principal.get_key(key1.tmb()).unwrap().last_used().is_none());

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
