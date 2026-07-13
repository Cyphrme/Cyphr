//! RED acceptance tests for the lifecycle transactions N03 must implement:
//! `principal/delete` (Close, SPEC.md:1994-2013), `freeze/create`
//! (SPEC.md:2782-2801), and `freeze/delete` (Thaw, SPEC.md:2803-2818).
//!
//! None of these `typ` suffixes are recognized `CozKind` variants yet.
//! `ParsedCoz::from_pay` dispatches on `typ` through a fixed chain of
//! `ends_with` checks (`parsed_coz.rs`'s `parse_kind`); any `typ` outside
//! that chain falls through the final `else` arm and returns
//! `Error::MalformedPayload`. Every test below asserts the TARGET
//! behavior (a successful parse, and — once N03 wires application — the
//! matching `LifecycleState` transition) and is expected to fail until
//! N03 lands.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::{Czd, Pay, Thumbprint};
use cyphr::lifecycle::LifecycleState;
use cyphr::state::HashAlg;
use cyphr::{Key, ParsedCoz, Principal};

fn make_test_key(id: u8) -> Key {
    Key {
        alg: "ES256".to_string(),
        tmb: Thumbprint::from_bytes(vec![id; 32]),
        pub_key: vec![id; 64],
        first_seen: 1000,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

/// A dummy `CozJson` for cozies whose signature is never checked: these
/// tests call `ParsedCoz::from_pay` directly, bypassing
/// `verify_coz`/signature verification (the same idiom `principal.rs`'s
/// own unit tests use for constructing test-only cozies).
fn dummy_coz_json() -> coz::CozJson {
    coz::CozJson {
        pay: serde_json::json!({ "typ": "cyphr.me/test", "alg": "ES256", "now": 1000 }),
        sig: vec![0; 64],
    }
}

/// A plausible tagged-digest `id` value (SPEC.md's `<target PR>` /
/// `<targeted PR>` field). Its exact bytes are irrelevant to every test
/// below: `parse_kind` rejects the `typ` before any field extraction is
/// attempted, so `id` is never actually read yet.
fn target_pr(fill: u8) -> String {
    format!(
        "{}:{}",
        HashAlg::Sha256,
        Base64UrlUnpadded::encode_string(&[fill; 32])
    )
}

/// Build a lifecycle-transaction `Pay`: signer `tmb`, full
/// authority-prefixed `typ` (`cyphr.me/<typ_suffix>`, matching
/// `parse_kind`'s suffix-based `ends_with` dispatch), target `id`, and
/// timestamp `now`.
fn lifecycle_pay(tmb: &Thumbprint, typ_suffix: &str, id: &str, now: i64) -> Pay {
    let mut pay = Pay::new();
    pay.alg = Some("ES256".to_string());
    pay.now = Some(now);
    pay.tmb = Some(tmb.clone());
    pay.typ = Some(format!("cyphr.me/{typ_suffix}"));
    pay.extra.insert("id".to_string(), serde_json::json!(id));
    pay
}

// ============================================================================
// principal/delete (Close) — SPEC.md:1994-2013
// ============================================================================

#[test]
fn principal_delete_parses_and_targets_deleted_state() {
    let key = make_test_key(0xD0);
    let tmb = key.tmb.clone();
    let principal = Principal::implicit(key).unwrap();
    assert_eq!(principal.lifecycle_state(), LifecycleState::Active);

    let pay = lifecycle_pay(&tmb, "cyphr/principal/delete", &target_pr(0xD0), 2000);
    let result = ParsedCoz::from_pay(
        &pay,
        Czd::from_bytes(vec![0x01; 32]),
        HashAlg::Sha256,
        dummy_coz_json(),
    );

    assert!(
        result.is_ok(),
        "principal/delete (SPEC.md:1994-2013) should parse into a CozKind \
         once N03 implements it, and applying it should transition the \
         principal from Active to LifecycleState::Deleted; currently: \
         {result:?}"
    );
}

// ============================================================================
// freeze/create — SPEC.md:2782-2801
// ============================================================================

#[test]
fn freeze_create_parses_and_targets_frozen_state() {
    let key = make_test_key(0xF0);
    let tmb = key.tmb.clone();
    let principal = Principal::implicit(key).unwrap();
    assert_eq!(principal.lifecycle_state(), LifecycleState::Active);

    let pay = lifecycle_pay(&tmb, "cyphr/freeze/create", &target_pr(0xF0), 2000);
    let result = ParsedCoz::from_pay(
        &pay,
        Czd::from_bytes(vec![0x02; 32]),
        HashAlg::Sha256,
        dummy_coz_json(),
    );

    assert!(
        result.is_ok(),
        "freeze/create (SPEC.md:2782-2801) should parse into a CozKind \
         once N03 implements it, and applying it should transition the \
         principal from Active to LifecycleState::Frozen; currently: \
         {result:?}"
    );
}

// ============================================================================
// freeze/delete (Thaw) — SPEC.md:2803-2818
// ============================================================================

#[test]
fn freeze_delete_parses_and_targets_thaw_to_active() {
    // The Frozen PRE-state this transaction targets can't be constructed
    // yet either (freeze/create doesn't parse — see
    // freeze_create_parses_and_targets_frozen_state), so this test uses a
    // fresh Active principal as a stand-in; the reachable target today is
    // that freeze/delete itself parses.
    let key = make_test_key(0xF1);
    let tmb = key.tmb.clone();
    let principal = Principal::implicit(key).unwrap();
    assert_eq!(principal.lifecycle_state(), LifecycleState::Active);

    let pay = lifecycle_pay(&tmb, "cyphr/freeze/delete", &target_pr(0xF1), 2000);
    let result = ParsedCoz::from_pay(
        &pay,
        Czd::from_bytes(vec![0x03; 32]),
        HashAlg::Sha256,
        dummy_coz_json(),
    );

    assert!(
        result.is_ok(),
        "freeze/delete (SPEC.md:2803-2818) should parse into a CozKind \
         once N03 implements it, and applying it to a Frozen principal \
         should transition it back to LifecycleState::Active; currently: \
         {result:?}"
    );
}

// ============================================================================
// Mutual exclusion invariant — SPEC.md:1974-1978
// ============================================================================

#[test]
fn deleted_and_frozen_mutual_exclusion_is_unreachable_today() {
    // SPEC.md:1974-1978: "a principal cannot be frozen and deleted at the
    // same time." Exercising that invariant end-to-end requires applying
    // BOTH principal/delete and freeze/create, which both require parsing
    // first — neither parses today, so the invariant can't yet be
    // reached, let alone violated or upheld. This asserts the
    // reachability precondition (both parse), which is the documented
    // reason [no-both-deleted-and-frozen] is untestable today; once both
    // parse, extend this test to apply one then the other and assert
    // !(principal.is_deleted() && principal.is_frozen()).
    let key = make_test_key(0xE0);
    let tmb = key.tmb.clone();
    let principal = Principal::implicit(key).unwrap();
    assert!(!principal.is_deleted());
    assert!(!principal.is_frozen());

    let delete_pay = lifecycle_pay(&tmb, "cyphr/principal/delete", &target_pr(0xE0), 3000);
    let delete_result = ParsedCoz::from_pay(
        &delete_pay,
        Czd::from_bytes(vec![0x04; 32]),
        HashAlg::Sha256,
        dummy_coz_json(),
    );

    let freeze_pay = lifecycle_pay(&tmb, "cyphr/freeze/create", &target_pr(0xE0), 3001);
    let freeze_result = ParsedCoz::from_pay(
        &freeze_pay,
        Czd::from_bytes(vec![0x05; 32]),
        HashAlg::Sha256,
        dummy_coz_json(),
    );

    assert!(
        delete_result.is_ok() && freeze_result.is_ok(),
        "principal/delete and freeze/create must both parse before \
         [no-both-deleted-and-frozen] (SPEC.md:1974-1978) is reachable; \
         currently delete={delete_result:?} freeze={freeze_result:?}"
    );
}
