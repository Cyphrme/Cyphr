//! Genesis, lifecycle-state and deleted-principal tests.

use super::*;
use crate::commit::PendingCommit;
use crate::multihash::MultihashDigest;
use crate::parsed_coz::VerifiedCoz;
use crate::semantic_tree::derive_state_roots;
use crate::state::{compute_dr, derive_hash_algs};

#[test]
fn implicit_genesis_single_key() {
    let key = make_test_key(0xAA);
    let principal = Principal::implicit(key.clone()).unwrap();

    // Level 1: PR is None (no principal/create at L1)
    assert!(principal.pg().is_none(), "PR should be None at Level 1");
    assert_eq!(
        principal.pr().get(principal.hash_alg()).unwrap(),
        key.tmb().as_bytes()
    );
    assert_eq!(
        principal.auth_root().get(principal.hash_alg()).unwrap(),
        key.tmb().as_bytes()
    );
    assert_eq!(
        principal.key_root().get(principal.hash_alg()).unwrap(),
        key.tmb().as_bytes()
    );
}

#[test]
fn implicit_genesis_has_one_active_key() {
    let key = make_test_key(0xBB);
    let tmb = key.tmb().clone();
    let principal = Principal::implicit(key).unwrap();

    assert_eq!(principal.active_key_count(), 1);
    assert!(principal.is_key_active(&tmb));
    assert_eq!(principal.level(), Level::L1);
}

#[test]
fn explicit_genesis_multi_key() {
    let key1 = make_test_key(0x11);
    let key2 = make_test_key(0x22);
    let principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

    // PR should be None (not yet established — needs principal/create)
    assert!(
        principal.pg().is_none(),
        "PR should be None before principal/create"
    );

    // Should have 2 active keys
    assert_eq!(principal.active_key_count(), 2);
    assert!(principal.is_key_active(key1.tmb()));
    assert!(principal.is_key_active(key2.tmb()));

    // Level 3 due to multiple keys
    assert_eq!(principal.level(), Level::L3);
}

#[test]
fn explicit_genesis_empty_keys_errors() {
    let result = Principal::explicit(vec![]);
    assert!(matches!(result, Err(Error::NoActiveKeys)));
}

#[test]
fn pg_is_none_at_level1() {
    let key = make_test_key(0xCC);
    let principal = Principal::implicit(key).unwrap();

    // PG is None at Level 1 (no principal/create)
    assert!(principal.pg().is_none(), "PG should be None at Level 1");

    // PR still exists and is stable
    let pr_bytes = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
    assert!(!pr_bytes.is_empty());
}

// ========================================================================
// Lifecycle state (SPEC.md §11)
// ========================================================================

#[test]
fn fresh_implicit_principal_derives_active() {
    let key = make_test_key(0xD0);
    let principal = Principal::implicit(key).unwrap();

    assert!(!principal.is_deleted());
    assert!(!principal.is_frozen());
    assert!(!principal.is_errored());
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Active
    );
}

#[test]
fn checkpoint_restored_principal_derives_active() {
    // ac-field-threading: a checkpoint-restored principal must not be
    // spuriously Frozen/Deleted — the new fields must default cleanly
    // through `from_checkpoint`, not just the constructors that build a
    // principal directly.
    let (principal, keys) = build_principal_with_commits(2);
    let trees = principal.commit_trees().clone();

    let restored = Principal::from_checkpoint(
        principal.pg().cloned(),
        principal.auth_root().clone(),
        keys,
        Some(trees),
    )
    .unwrap();

    assert!(!restored.is_deleted());
    assert!(!restored.is_frozen());
    assert_eq!(
        restored.lifecycle_state(),
        crate::lifecycle::LifecycleState::Active
    );
}

#[test]
fn principal_with_no_active_keys_derives_dead() {
    let key = make_test_key(0xD1);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    principal.pre_revoke_key(&tmb, 1000).unwrap();

    assert_eq!(principal.active_key_count(), 0);
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Dead,
        "a principal with zero active keys and Level < L4 must derive Dead"
    );
}

/// c-zombie-unreachable (integration level): across every principal
/// shape this node can actually construct (varying key counts, with and
/// without revocation, with and without commits), `lifecycle_state()`
/// never returns Zombie. `CanMutateAR` is wired as `== HasActiveKeys`
/// below Level 5 (SPEC.md:1990-1992; this crate's `Level` enum has no
/// L5+ variant — see `rs/cyphr/src/principal.rs`'s `Level` definition),
/// so `¬CanMutateAR ∧ CanDataAction` can never hold and Zombie is
/// unreachable for any principal reachable through the public API.
#[test]
fn zombie_unreachable_across_constructed_principals() {
    let single = Principal::implicit(make_test_key(0xD2)).unwrap();
    assert_ne!(
        single.lifecycle_state(),
        crate::lifecycle::LifecycleState::Zombie
    );

    let multi = Principal::explicit(vec![make_test_key(0xD3), make_test_key(0xD4)]).unwrap();
    assert_ne!(
        multi.lifecycle_state(),
        crate::lifecycle::LifecycleState::Zombie
    );

    let mut revoked = Principal::implicit(make_test_key(0xD5)).unwrap();
    let tmb = revoked.active_keys().next().unwrap().tmb().clone();
    revoked.pre_revoke_key(&tmb, 2000).unwrap();
    assert_ne!(
        revoked.lifecycle_state(),
        crate::lifecycle::LifecycleState::Zombie
    );

    let (with_commits, _keys) = build_principal_with_commits(3);
    assert_ne!(
        with_commits.lifecycle_state(),
        crate::lifecycle::LifecycleState::Zombie
    );
}

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
#[test]
fn frozen_principal_is_default_deny_for_every_coz_kind() {
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
            | CozKind::PrincipalCreate { .. } => Expect::Frozen,
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
    let frozen = || {
        let mut p = Principal::implicit(key.clone()).unwrap();
        let freeze = make_lifecycle_cz(CozKind::FreezeCreate { id: p.pr().clone() }, &tmb, 2000);
        p.apply_transaction_test(freeze, None).unwrap();
        assert!(p.is_frozen(), "premise: principal is frozen");
        p
    };
    let probe = frozen();
    let nonce = Nonce::parse(
        "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        HashAlg::Sha256,
    )
    .unwrap();
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
    ];
    for kind in kinds {
        let label = kind.to_string();
        let want = expect(&kind);
        let mut p = frozen();
        let cz = make_lifecycle_cz(kind, &tmb, 2001);
        let got = p.apply_verified_internal(VerifiedCoz::from_transaction_unsafe(cz, None));
        match (want, &got) {
            (Expect::Frozen, Err(Error::Frozen))
            | (Expect::AlreadyFrozen, Err(Error::AlreadyFrozen))
            | (Expect::Accepted, Ok(())) => {},
            (_, got) => panic!("frozen principal, {label}: unexpected outcome {got:?}"),
        }
    }
}

#[test]
fn principal_delete_from_frozen_succeeds_and_clears_frozen() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE1);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal.apply_transaction_test(freeze_cz, None).unwrap();
    assert!(principal.is_frozen());

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    principal.apply_transaction_test(delete_cz, None).unwrap();

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

#[test]
fn freeze_create_on_deleted_is_rejected() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE2);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal.apply_transaction_test(delete_cz, None).unwrap();
    assert!(principal.is_deleted());

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    let result = principal.apply_transaction_test(freeze_cz, None);
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
    assert!(!principal.is_frozen());
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Deleted,
        "[no-both-deleted-and-frozen]: a rejected freeze/create must not perturb the Deleted state"
    );
}

#[test]
fn freeze_create_on_already_frozen_is_rejected() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE3);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal.apply_transaction_test(freeze_cz, None).unwrap();
    assert!(principal.is_frozen());

    let freeze_again_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    let result = principal.apply_transaction_test(freeze_again_cz, None);
    assert!(matches!(result, Err(Error::AlreadyFrozen)));
}

#[test]
fn freeze_delete_on_non_frozen_is_rejected() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE4);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    assert!(!principal.is_frozen());

    let thaw_cz = make_lifecycle_cz(
        CozKind::FreezeDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    let result = principal.apply_transaction_test(thaw_cz, None);
    assert!(matches!(result, Err(Error::NotFrozen)));
}

#[test]
fn freeze_create_then_freeze_delete_thaws_to_active() {
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE5);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    let freeze_cz = make_lifecycle_cz(
        CozKind::FreezeCreate {
            id: principal.pr().clone(),
        },
        &tmb,
        2000,
    );
    principal.apply_transaction_test(freeze_cz, None).unwrap();
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Frozen
    );

    let thaw_cz = make_lifecycle_cz(
        CozKind::FreezeDelete {
            id: principal.pr().clone(),
        },
        &tmb,
        2001,
    );
    principal.apply_transaction_test(thaw_cz, None).unwrap();

    assert!(!principal.is_frozen());
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Active
    );
}

// ========================================================================
// Blanket deleted-principal gate (SPEC.md §11.4, F23, N11)
//
// [no-transactions-on-deleted] applied to the six non-lifecycle CozKind
// variants (KeyCreate, KeyDelete, KeyReplace, SelfRevoke,
// PrincipalCreate, CommitCreate) plus data actions. CommitCreate is
// exempted (its own commit's finalizer must complete even when an
// earlier transaction in the same commit was the delete itself, see
// `same_commit_delete_and_own_finalizer_succeeds` below).
// FreezeDelete is exempted from this gate too, but for a structural
// reason rather than a same-commit one: it requires `self.frozen`,
// and Deleted/Frozen are mutually exclusive (SPEC.md:1974-1978), so
// FreezeDelete can never be reachable on a Deleted principal in the
// first place -- `freeze_delete_on_deleted_still_rejected_as_not_frozen`
// confirms this rather than adding a redundant check.
// ========================================================================

/// Build a genuinely Deleted principal via a real `principal/delete`
/// transaction (not a mocked flag), with two active keys so KeyDelete/
/// SelfRevoke have a legal target/signer to attempt against it.
fn build_deleted_principal() -> (Principal, Key, Key) {
    use crate::parsed_coz::CozKind;

    let key1 = make_test_key(0xD1);
    let key2 = make_test_key(0xD2);
    let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

    let delete_cz = make_lifecycle_cz(
        CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        key1.tmb(),
        2000,
    );
    principal.apply_transaction_test(delete_cz, None).unwrap();
    assert!(principal.is_deleted(), "setup: principal must be Deleted");

    (principal, key1, key2)
}

#[test]
fn key_create_on_deleted_principal_is_rejected() {
    let (mut principal, key1, _key2) = build_deleted_principal();

    let new_key = make_test_key(0xD3);
    let cz = make_key_add_tx(&new_key, key1.tmb());

    let result = principal.apply_transaction_test(cz, Some(new_key));
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
}

#[test]
fn key_delete_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, key2) = build_deleted_principal();

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
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
}

#[test]
fn key_replace_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, _key2) = build_deleted_principal();

    let new_key = make_test_key(0xD5);
    let cz = ParsedCoz {
        kind: CozKind::KeyReplace {
            id: new_key.tmb().clone(),
        },
        signer: key1.tmb().clone(),
        now: 2001,
        czd: Czd::from_bytes(vec![0xD6; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    let result = principal.apply_transaction_test(cz, Some(new_key));
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
}

/// SelfRevoke DOES mutate state (revokes the signer's own key) and has
/// no same-commit-completion necessity the way CommitCreate does, so
/// SPEC.md §11.4's "no further transactions" is not exempted here --
/// unlike CommitCreate, gating SelfRevoke does not reopen the ability
/// to ever close a principal.
#[test]
fn self_revoke_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, _key1, key2) = build_deleted_principal();

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
    assert!(matches!(result, Err(Error::AlreadyDeleted)));
    assert!(
        principal.is_key_active(key2.tmb()),
        "rejected self-revoke must not mutate the key set"
    );
}

#[test]
fn principal_create_on_deleted_principal_is_rejected() {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, _key2) = build_deleted_principal();

    let cz = ParsedCoz {
        kind: CozKind::PrincipalCreate {
            id: principal.auth_root().clone(),
        },
        signer: key1.tmb().clone(),
        now: 2001,
        czd: Czd::from_bytes(vec![0xD8; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    let result = principal.apply_transaction_test(cz, None);
    assert!(
        matches!(result, Err(Error::AlreadyDeleted)),
        "the blanket gate must reject PrincipalCreate before genesis-key/id validation ever runs, \
         since a Deleted principal is by definition already Established and genesis finalization \
         can never legitimately be reachable here"
    );
}

/// Confirms the reasoning in this node's non-goals: FreezeDelete
/// requires `self.frozen`, and Deleted/Frozen are mutually exclusive,
/// so FreezeDelete on a genuinely Deleted principal is already
/// unreachable via its own existing check (`NotFrozen`) -- no new gate
/// entry is needed, and the blanket gate must not shadow this error
/// with `AlreadyDeleted`.
#[test]
fn freeze_delete_on_deleted_still_rejected_as_not_frozen() {
    let (mut principal, key1, _key2) = build_deleted_principal();
    assert!(!principal.is_frozen());

    let thaw_cz = make_lifecycle_cz(
        crate::parsed_coz::CozKind::FreezeDelete {
            id: principal.pr().clone(),
        },
        key1.tmb(),
        2001,
    );
    let result = principal.apply_transaction_test(thaw_cz, None);
    assert!(matches!(result, Err(Error::NotFrozen)));
}

#[test]
fn data_action_on_deleted_principal_is_rejected() {
    let (mut principal, key1, _key2) = build_deleted_principal();

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

/// c-same-commit-delete-still-finalizes: the load-bearing test for this
/// node. A commit whose own transaction is `principal/delete`, followed
/// by that SAME commit's `commit/create` finalizer, must still finalize
/// successfully -- the finalizer is applied through
/// `apply_transaction_internal` exactly as the real per-cozy commit
/// ingestion path does (see `CommitScope::verify_and_apply` ->
/// `CommitScope::apply` -> `apply_verified_internal`), at a point where
/// `self.deleted` is already `true` from the earlier delete in this
/// same commit. Get the exemption wrong (too narrow) and this test
/// fails with `AlreadyDeleted`, meaning a principal could never
/// actually be closed.
#[test]
fn same_commit_delete_and_own_finalizer_succeeds() {
    use crate::parsed_coz::{CozKind, ParsedCoz};

    let key = make_test_key(0xDA);
    let tmb = key.tmb().clone();
    let mut principal = Principal::implicit(key).unwrap();

    let delete_cz = ParsedCoz {
        kind: CozKind::PrincipalDelete {
            id: principal.pr().clone(),
        },
        signer: tmb.clone(),
        now: 2000,
        czd: coz::Czd::from_bytes(vec![0xDB; 32]),
        hash_alg: HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    };

    // Apply principal/delete eagerly -- self.deleted is now true,
    // exactly as it would be on CommitScope's projected principal
    // mid-commit.
    let delete_vtx = VerifiedCoz::from_transaction_unsafe(delete_cz.clone(), None);
    principal.apply_verified_internal(delete_vtx).unwrap();
    assert!(principal.is_deleted());

    let mut pending = PendingCommit::new();
    let delete_vtx2 = VerifiedCoz::from_transaction_unsafe(delete_cz.clone(), None);
    pending.push_tx(crate::transaction::Transaction(vec![delete_vtx2]));

    // Compute the correct arrow for the finalizer -- same technique as
    // `apply_transaction_test`.
    let key_refs: Vec<&Key> = principal.auth.keys.values().collect();
    let active_algs = derive_hash_algs(&key_refs);
    let thumbprints: Vec<&coz::Thumbprint> =
        principal.auth.keys.values().map(|k| k.tmb()).collect();
    let action_refs: Vec<&Action> = principal.data.actions.iter().collect();
    let dr = compute_dr(&action_refs, None, &active_algs).unwrap();
    let (_kr, _ar, sr) = derive_state_roots(&thumbprints, dr.as_ref(), &active_algs).unwrap();

    let tx_alg = delete_cz.hash_alg;
    let (tmr_opt, _tcr, _tr) = pending.compute_roots(&[tx_alg]);
    let tmr = tmr_opt.unwrap();

    let arrow_digest = crate::commit::arrow_digest(tx_alg, &principal.pr, &sr, &tmr).unwrap();
    let arrow_md = MultihashDigest::from_single(tx_alg, arrow_digest).unwrap();

    let commit_coz = ParsedCoz {
        kind: CozKind::CommitCreate {
            arrow: arrow_md.clone(),
        },
        signer: tmb.clone(),
        now: 2000,
        czd: coz::Czd::from_bytes(vec![0xDC; 32]),
        hash_alg: tx_alg,
        arrow: Some(arrow_md),
        raw: dummy_coz_json(),
    };
    let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);

    // The load-bearing assertion: this must NOT be rejected by
    // [no-transactions-on-deleted] despite self.deleted already being
    // true from the delete applied moments ago in this same commit.
    principal
        .apply_verified_internal(commit_vtx.clone())
        .expect(
            "commit/create finalizing its own commit's principal/delete must not be rejected by \
             the blanket deleted gate",
        );

    pending.push_tx(crate::transaction::Transaction(vec![commit_vtx]));

    principal.finalize_commit(pending).unwrap();

    assert!(
        principal.is_deleted(),
        "principal must still be Deleted after its own delete-commit finalizes"
    );
    assert_eq!(
        principal.lifecycle_state(),
        crate::lifecycle::LifecycleState::Deleted
    );
}

/// c-later-commit-now-rejected (F35 narrowing, this node): unlike
/// `same_commit_delete_and_own_finalizer_succeeds` above, this
/// principal was deleted in an EARLIER, separately-finalized commit
/// -- `self.deleted` is already `true` BEFORE this new commit/create
/// is applied, not made `true` by this commit's own transaction. A
/// bare `commit/create` (no other transaction in this commit) must
/// now be rejected by [no-transactions-on-deleted], not silently
/// exempted the way N11's original, unconditional exemption allowed.
#[test]
fn later_commit_bare_finalizer_on_already_deleted_is_rejected() {
    use crate::parsed_coz::{CozKind, ParsedCoz};

    let (mut principal, key1, _key2) = build_deleted_principal();
    assert!(
        principal.is_deleted(),
        "setup: principal must already be Deleted"
    );

    // A brand-new commit/create finalizer with no other transaction
    // in this commit. The arrow's exact bytes are irrelevant here --
    // [no-transactions-on-deleted] is enforced in
    // `apply_transaction_internal`, before any arrow is validated
    // (arrow validation happens later, in `finalize_commit`).
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

    let result = principal.apply_verified_internal(commit_vtx);
    assert!(
        matches!(result, Err(Error::AlreadyDeleted)),
        "a bare commit/create against a principal deleted in an earlier, separately-finalized \
         commit must be rejected, got {result:?}"
    );
}

/// Backs SPEC 7.6 / 10.1 at the principal: creating a nonce twice at one
/// level is `DuplicateNonce`, deleting one that is absent is `UnknownNonce`,
/// and a refused nonce leaves the roots as they were. Unit level: the signed
/// wire scenarios in `tests/nonce.rs` never repeat a nonce or delete an
/// absent one at the principal, and these two refusals have no cheaper
/// scenario. Turns red if either refusal is accepted or moves a root.
#[test]
fn duplicate_nonce_and_absent_delete_are_typed_refusals() {
    use crate::nonce::{Nonce, NonceLevel};
    use crate::parsed_coz::CozKind;

    let key = make_test_key(0xE5);
    let tmb = key.tmb().clone();
    let mut p = Principal::implicit(key).unwrap();
    let nonce = Nonce::parse(
        "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        HashAlg::Sha256,
    )
    .unwrap();
    let create = || CozKind::NonceCreate {
        level: NonceLevel::Kt,
        nonce: nonce.clone(),
    };
    let delete = || CozKind::NonceDelete {
        level: NonceLevel::Kt,
        nonce: nonce.clone(),
    };

    let r = p.apply_verified_internal(VerifiedCoz::from_transaction_unsafe(
        make_lifecycle_cz(delete(), &tmb, 2000),
        None,
    ));
    assert!(matches!(r, Err(Error::UnknownNonce)), "{r:?}");

    p.apply_verified_internal(VerifiedCoz::from_transaction_unsafe(
        make_lifecycle_cz(create(), &tmb, 2001),
        None,
    ))
    .unwrap();
    let r = p.apply_verified_internal(VerifiedCoz::from_transaction_unsafe(
        make_lifecycle_cz(create(), &tmb, 2002),
        None,
    ));
    assert!(matches!(r, Err(Error::DuplicateNonce)), "{r:?}");
}
