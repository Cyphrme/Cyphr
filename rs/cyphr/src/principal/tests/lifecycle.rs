//! Genesis, lifecycle-state and deleted-principal tests.

use super::*;
use crate::multihash::MultihashDigest;
use crate::parsed_coz::VerifiedCoz;

// ========================================================================
// Lifecycle state (SPEC.md §11)
// ========================================================================

// ========================================================================
// Lifecycle transactions (SPEC.md §11.4 Close, §14.9 Freeze)
// ========================================================================

/// Build a lifecycle-transaction `ParsedCoz` (`PrincipalDelete`,
/// `FreezeCreate`, or `FreezeDelete`) signed by `signer`. Bypasses
/// signature verification, matching every other mutator test in this
/// module (`self_revoke_last_key_prevented` et al.).
fn make_lifecycle_cz(
    kind: crate::parsed_coz::CozKind,
    signer: &Thumbprint,
    now: i64,
) -> crate::parsed_coz::ParsedCoz {
    use coz::Czd;

    use crate::parsed_coz::ParsedCoz;

    ParsedCoz {
        kind,
        signer: signer.clone(),
        now,
        czd: Czd::from_bytes(vec![now as u8; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    }
}

/// Backs the freeze scope (SPEC 2.3.2, 11, 4.1): a frozen principal is
/// default-deny. Only `freeze/delete` (the thaw) and `principal/delete`
/// (close, R1/F5) mutate it; `freeze/create` is typed `AlreadyFrozen`;
/// `commit/create` is the mutation-free finalizer of the commit that
/// froze or thawed; every other kind is refused with `Frozen`. The
/// expectation comes from an exhaustive match over `CozKind`, so adding a
/// kind (merge, nonce, ...) stops this test compiling until the kind is
/// classified, and a classified-as-refused kind that slips through turns
/// it red. Unit level: the kinds are crate-private values that no signed
/// scenario can enumerate; data actions are covered end to end by
/// `spec_conformance::frozen_principal_rejects_data_actions_until_thawed`.
#[tokio::test]
async fn frozen_principal_is_default_deny_for_every_coz_kind() {
    use crate::nonce::{Nonce, NonceLevel};
    use crate::parsed_coz::CozKind;

    enum Expect {
        Frozen,
        AlreadyFrozen,
        Accepted,
    }
    fn expect(kind: &CozKind) -> Expect {
        match kind {
            CozKind::KeyCreate { .. }
            | CozKind::KeyDelete { .. }
            | CozKind::KeyReplace { .. }
            | CozKind::SelfRevoke { .. }
            | CozKind::NonceCreate { .. }
            | CozKind::NonceDelete { .. }
            | CozKind::Merge(_)
            | CozKind::MergeAck(_)
            | CozKind::PrincipalCreate { .. }
            | CozKind::DataRootCreate { .. } => Expect::Frozen,
            CozKind::FreezeCreate { .. } => Expect::AlreadyFrozen,
            // CommitCreate stays exempt: it finalizes the very commit that
            // carries freeze/create or freeze/delete, so denying it would
            // make freezing and thawing impossible. It mutates nothing.
            CozKind::FreezeDelete { .. }
            | CozKind::PrincipalDelete { .. }
            | CozKind::CommitCreate { .. } => Expect::Accepted,
        }
    }

    let key = make_test_key(0xE9);
    let tmb = key.tmb().clone();
    let frozen = async || {
        let mut p = Principal::implicit(key.clone()).await.unwrap();
        p.genesis_test(Vec::new()).await.unwrap();
        let freeze = make_lifecycle_cz(CozKind::FreezeCreate { id: p.pr().clone() }, &tmb, 2000);
        p.apply_transaction_test(freeze, None).await.unwrap();
        assert!(p.is_frozen(), "premise: principal is frozen");
        p
    };
    let probe = frozen().await;
    let nonce = Nonce::parse(
        "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        HashAlg::Sha256,
    )
    .unwrap();
    let claim = crate::merge::MergeClaim {
        from: vec![probe.pr().clone()],
        to_pr: probe.pr().clone(),
    };
    let kinds = vec![
        CozKind::KeyCreate { id: tmb.clone() },
        CozKind::KeyDelete { id: tmb.clone() },
        CozKind::KeyReplace { id: tmb.clone() },
        CozKind::SelfRevoke { rvk: 2001 },
        CozKind::NonceCreate {
            level: NonceLevel::Kt,
            nonce: nonce.clone(),
        },
        CozKind::NonceDelete {
            level: NonceLevel::Kt,
            nonce,
        },
        CozKind::PrincipalCreate {
            id: AuthRoot(probe.pr().as_multihash().clone()),
        },
        CozKind::Merge(claim.clone()),
        CozKind::MergeAck(claim),
        CozKind::FreezeCreate {
            id: probe.pr().clone(),
        },
        CozKind::FreezeDelete {
            id: probe.pr().clone(),
        },
        CozKind::PrincipalDelete {
            id: probe.pr().clone(),
        },
        CozKind::CommitCreate {
            arrow: MultihashDigest::from_single(HashAlg::Sha256, vec![0; 32]).unwrap(),
        },
        CozKind::DataRootCreate {
            id: crate::state::DataRoot(
                MultihashDigest::from_single(HashAlg::Sha256, vec![0; 32]).unwrap(),
            ),
        },
    ];
    for kind in kinds {
        let label = kind.to_string();
        let want = expect(&kind);
        let mut p = frozen().await;
        let cz = make_lifecycle_cz(kind, &tmb, 2001);
        let got = p
            .state_mut()
            .apply_verified_internal(VerifiedCoz::from_transaction_unsafe(cz, None));
        match (want, &got) {
            (Expect::Frozen, Err(Error::Frozen))
            | (Expect::AlreadyFrozen, Err(Error::AlreadyFrozen))
            | (Expect::Accepted, Ok(())) => {},
            (_, got) => panic!("frozen principal, {label}: unexpected outcome {got:?}"),
        }
    }
}

#[tokio::test]
async fn principal_delete_from_frozen_succeeds_and_clears_frozen() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE1);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal
        .apply_transaction_test(freeze_cz, None)
        .await
        .unwrap();
    assert!(principal.is_frozen());

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    principal
        .apply_transaction_test(delete_cz, None)
        .await
        .unwrap();

    assert!(principal.is_deleted());
    assert!(
        !principal.is_frozen(),
        "delete must clear frozen (mutual exclusivity, SPEC.md:1974-1978)"
    );
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Deleted
    );
}

#[tokio::test]
async fn freeze_create_on_deleted_is_rejected() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE2);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal
        .apply_transaction_test(delete_cz, None)
        .await
        .unwrap();
    assert!(principal.is_deleted());

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    let result = principal.apply_transaction_test(freeze_cz, None);
    assert!(matches!(result.await, Err(Error::AlreadyDeleted)));
    assert!(!principal.is_frozen());
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Deleted,
        "[no-both-deleted-and-frozen]: a rejected freeze/create must not perturb the Deleted state"
    );
}

/// Backs SPEC 11.2: `freeze/delete` on a principal that is not frozen is refused as `NotFrozen`.
/// Unit: golden `freeze_delete_thaws_to_active` covers only the legal thaw.
#[tokio::test]
async fn freeze_delete_on_non_frozen_is_rejected() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE4);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    assert!(!principal.is_frozen());

    let thaw_cz = make_lifecycle_cz(
        CozKind::FreezeDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    let result = principal.apply_transaction_test(thaw_cz, None);
    assert!(matches!(result.await, Err(Error::NotFrozen)));
}

// ========================================================================
// Blanket deleted-principal gate (SPEC.md §11.4, F23, N11)
//
// [no-transactions-on-deleted] applied to the six non-lifecycle CozKind
// variants (KeyCreate, KeyDelete, KeyReplace, SelfRevoke,
// PrincipalCreate, CommitCreate) plus data actions. CommitCreate is
// exempted (its own commit's finalizer must complete even when an
// earlier transaction in the same commit was the delete itself, as in
// the `principal_delete_transitions_to_deleted` golden vector).
// FreezeDelete is exempted from this gate too, but for a structural
// reason rather than a same-commit one: it requires `self.frozen`,
// and Deleted/Frozen are mutually exclusive (SPEC.md:1974-1978), so
// FreezeDelete can never be reachable on a Deleted principal in the
// first place, so no redundant check is added.
// ========================================================================

/// Build a genuinely Deleted principal via a real `principal/delete`
/// transaction (not a mocked flag), with two active keys so KeyDelete/
/// SelfRevoke have a legal target/signer to attempt against it.
async fn build_deleted_principal() -> (Principal, Key, Key) {
    use crate::parsed_coz::CozKind;

    let key1 = make_test_key(0xD1);
    let key2 = make_test_key(0xD2);
    let mut principal = Principal::implicit(key1.clone()).await.unwrap();
    principal.genesis_test(vec![key2.clone()]).await.unwrap();

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        key1.tmb(),
        2000,
    );
    principal
        .apply_transaction_test(delete_cz, None)
        .await
        .unwrap();
    assert!(principal.is_deleted(), "setup: principal must be Deleted");

    (principal, key1, key2)
}

#[tokio::test]
async fn key_create_on_deleted_principal_is_rejected() {
    let (mut principal, key1, _key2) = build_deleted_principal().await;

    let new_key = make_test_key(0xD3);
    let cz = make_key_add_tx(&new_key, key1.tmb());

    let result = principal.apply_transaction_test(cz, Some(new_key));
    assert!(matches!(result.await, Err(Error::AlreadyDeleted)));
}

#[tokio::test]
async fn key_delete_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, key2) = build_deleted_principal().await;

    let cz = ParsedCoz {
        kind: CozKind::KeyDelete {
            id: key2.tmb().clone(),
        },
        signer: key1.tmb().clone(),
        now: 2001,
        czd: Czd::from_bytes(vec![0xD4; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    let result = principal.apply_transaction_test(cz, None);
    assert!(matches!(result.await, Err(Error::AlreadyDeleted)));
}

/// SelfRevoke DOES mutate state (revokes the signer's own key) and has
/// no same-commit-completion necessity the way CommitCreate does, so
/// SPEC.md §11.4's "no further transactions" is not exempted here --
/// unlike CommitCreate, gating SelfRevoke does not reopen the ability
/// to ever close a principal.
#[tokio::test]
async fn self_revoke_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, _key1, key2) = build_deleted_principal().await;

    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 2001 },
        signer: key2.tmb().clone(),
        now: 2001,
        czd: Czd::from_bytes(vec![0xD7; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    let result = principal.apply_transaction_test(cz, None);
    assert!(matches!(result.await, Err(Error::AlreadyDeleted)));
    assert!(
        principal.is_key_active(key2.tmb()),
        "rejected self-revoke must not mutate the key set"
    );
}

#[tokio::test]
async fn data_action_on_deleted_principal_is_rejected() {
    let (mut principal, key1, _key2) = build_deleted_principal().await;

    let pay = serde_json::json!({
        "alg": key1.alg(),
        "now": 2001,
        "tmb": key1.tmb().to_b64(),
        "typ": "cyphr.me/comment",
    });
    let pay_json = serde_json::to_vec(&pay).unwrap();
    let sig = vec![0u8; 64];
    let czd = coz::Czd::from_bytes(vec![0xD9; 32]);

    let result = principal.verify_and_record_action(&pay_json, &sig, czd);
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
}

/// c-later-commit-now-rejected (F35 narrowing, this node): unlike
/// a same-commit delete and finalizer (golden
/// `principal_delete_transitions_to_deleted`), this
/// principal was deleted in an EARLIER, separately-finalized commit
/// -- `self.deleted` is already `true` BEFORE this new commit/create
/// is applied, not made `true` by this commit's own transaction. A
/// bare `commit/create` (no other transaction in this commit) must
/// now be rejected by [no-transactions-on-deleted], not silently
/// exempted the way N11's original, unconditional exemption allowed.
#[tokio::test]
async fn later_commit_bare_finalizer_on_already_deleted_is_rejected() {
    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, _key2) = build_deleted_principal().await;
    assert!(
        principal.is_deleted(),
        "setup: principal must already be Deleted"
    );

    // A brand-new commit/create finalizer with no other transaction
    // in this commit. The arrow's exact bytes are irrelevant here --
    // [no-transactions-on-deleted] is enforced in
    // `apply_transaction_internal`, before any arrow is validated
    // (arrow validation happens later, in `stage_commit`).
    let arrow_md = MultihashDigest::from_single(HashAlg::Sha256, vec![0u8; 32]).unwrap();
    let commit_coz = ParsedCoz {
        kind: CozKind::CommitCreate {
            arrow: arrow_md.clone(),
        },
        signer: key1.tmb().clone(),
        now: 3000,
        czd: coz::Czd::from_bytes(vec![0xE9; 32]),
        hash_alg: HashAlg::Sha256,
        arrow: Some(arrow_md),
        raw: dummy_coz_json(),
    };
    let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);

    let result = principal.state_mut().apply_verified_internal(commit_vtx);
    assert!(
        matches!(result, Err(Error::AlreadyDeleted)),
        "a bare commit/create against a principal deleted in an earlier, separately-finalized \
         commit must be rejected, got {result:?}"
    );
}

/// Backs SPEC 10.1 at the principal: deleting a nonce that is absent is
/// `UnknownNonce`. Unit level: the signed wire scenarios in
/// `tests/nonce.rs` never delete an absent nonce (they pin the duplicate
/// create), and this refusal has no cheaper scenario. Turns red if the
/// delete is accepted.
#[tokio::test]
async fn absent_nonce_delete_is_a_typed_refusal() {
    use crate::nonce::{Nonce, NonceLevel};
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE5);
    let tmb = key.tmb().clone();
    let mut p = Principal::implicit(key).await.unwrap();
    p.genesis_test(Vec::new()).await.unwrap();
    let nonce = Nonce::parse(
        "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        HashAlg::Sha256,
    )
    .unwrap();
    let delete = || CozKind::NonceDelete {
        level: NonceLevel::Kt,
        nonce: nonce.clone(),
    };

    let r = p
        .state_mut()
        .apply_verified_internal(VerifiedCoz::from_transaction_unsafe(
            make_lifecycle_cz(delete(), &tmb, 2000),
            None,
        ));
    assert!(matches!(r, Err(Error::UnknownNonce)), "{r:?}");
}
