//! U3: what a write and a read cost does not grow with what the principal
//! already holds. Unit tests on counters (`crate::probe`): the work they
//! count is invisible to any end-to-end scenario, whose answers are
//! identical either way (`rs/cyphr-storage/tests/kept_state.rs` pins that
//! the answers are the replay's).

use coz::Czd;

use super::*;
use crate::action::Action;
use crate::parsed_coz::{CozKind, ParsedCoz};
use crate::probe;

/// An action of `signer` dated `now`, distinct per `n`.
fn action_at(signer: &Thumbprint, now: i64, n: u8) -> Action {
    let mut action = make_test_action(signer);
    action.now = now;
    action.czd = Czd::from_bytes(vec![n; 32]);
    action
}

async fn principal_holding(actions: u8) -> (Principal, Key) {
    let key = make_test_key(0x11);
    let mut principal = Principal::implicit(key.clone()).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();
    for n in 0..actions {
        principal
            .state_mut()
            .record_action(action_at(key.tmb(), 100 + i64::from(n), n))
            .unwrap();
    }
    // As `hold_actions` does once the actions are held.
    principal.state_mut().settle();
    (principal, key)
}

/// Cost: a commit write copies none of the actions or commits the principal
/// holds.
/// Red while the commit scope clones the whole state.
#[tokio::test]
async fn a_commit_write_copies_no_held_action() {
    let (mut principal, key) = principal_holding(40).await;
    let key2 = make_test_key(0x22);
    let cz = ParsedCoz {
        kind: CozKind::KeyCreate {
            id: key2.tmb().clone(),
        },
        signer: key.tmb().clone(),
        now: 5000,
        czd: Czd::from_bytes(vec![0xBB; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };
    let (before, commits_before) = (probe::action_clones(), probe::commit_clones());
    principal
        .apply_transaction_test(cz, Some(key2))
        .await
        .unwrap();
    assert_eq!(probe::action_clones() - before, 0);
    assert_eq!(
        probe::commit_clones() - commits_before,
        0,
        "the genesis commit was copied by the write after it"
    );
    assert_eq!(principal.action_count(), 40, "the held set is intact");
}

/// Cost: DT's view is read from a memo, and a write of one more action
/// judges that action alone, so a read after an unrelated write judges
/// nothing again. Red while every read judges every held action.
#[tokio::test]
async fn a_read_after_an_action_write_judges_only_that_action() {
    let (mut principal, key) = principal_holding(40).await;
    assert_eq!(principal.action_count(), 40);

    let before = probe::view_judgments();
    assert_eq!(principal.action_count(), 40);
    assert_eq!(principal.actions().count(), 40);
    assert_eq!(probe::view_judgments() - before, 0, "a repeated read");

    principal
        .state_mut()
        .record_action(action_at(key.tmb(), 200, 99))
        .unwrap();
    let before = probe::view_judgments();
    assert_eq!(principal.action_count(), 41);
    assert!(
        probe::view_judgments() - before <= 1,
        "a read after one write judged {} actions",
        probe::view_judgments() - before
    );
}

fn coz(kind: CozKind, signer: &Key, now: i64, n: u8) -> ParsedCoz {
    ParsedCoz {
        kind,
        signer: signer.tmb().clone(),
        now,
        czd: Czd::from_bytes(vec![n; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    }
}

/// A principal of keys 0x11 and 0x22 holding 40 actions of 0x11 dated
/// 100..140, whose view has been read.
async fn principal_with_read_view() -> (Principal, Key, Key) {
    let (key, key2) = (make_test_key(0x11), make_test_key(0x22));
    let mut principal = Principal::implicit(key.clone()).await.unwrap();
    principal.genesis_test(vec![key2.clone()]).await.unwrap();
    for n in 0..40u8 {
        principal
            .state_mut()
            .record_action(action_at(key.tmb(), 100 + i64::from(n), n))
            .unwrap();
    }
    principal.state_mut().settle();
    assert_eq!(principal.action_count(), 40);
    (principal, key, key2)
}

/// Cost, SPEC 6.5: a commit dated at the tip changes the verdicts of
/// actions dated at or after it only, so a read after one judges none of
/// the 40 actions dated before it. Red while any commit drops the view.
#[tokio::test]
async fn a_read_after_a_tip_dated_commit_judges_nothing_before_it() {
    let (mut principal, key, _) = principal_with_read_view().await;
    let key3 = make_test_key(0x33);
    let cz = coz(
        CozKind::KeyCreate {
            id: key3.tmb().clone(),
        },
        &key,
        5000,
        0xB1,
    );
    principal
        .apply_transaction_test(cz, Some(key3))
        .await
        .unwrap();
    let before = probe::view_judgments();
    assert_eq!(principal.action_count(), 40);
    assert_eq!(principal.actions().count(), 40);
    assert_eq!(probe::view_judgments() - before, 0);
}

/// Cost, SPEC 6.2/6.5: a commit dated 120 that deletes the signer's key
/// takes out the actions dated 120 or later, and a read after it judges
/// exactly those 20, not the 20 before it. Red while any commit drops the
/// view.
#[tokio::test]
async fn a_read_after_a_backdated_delete_judges_exactly_the_suffix() {
    let (mut principal, key, key2) = principal_with_read_view().await;
    let cz = coz(
        CozKind::KeyDelete {
            id: key.tmb().clone(),
        },
        &key2,
        120,
        0xB2,
    );
    principal.apply_transaction_test(cz, None).await.unwrap();
    let before = probe::view_judgments();
    assert_eq!(principal.action_count(), 20);
    assert_eq!(probe::view_judgments() - before, 20);
}
