//! Principal Tree genesis-invariance and isolation tests.

use super::*;

// ========================================================================
// Principal Tree (PT) genesis invariance and isolation tests
// ========================================================================

/// c2/a2 — the correctness pivot of this node: for a principal with 2+
/// registered hash algorithms, `pg()` (frozen at `principal/create`,
/// while the Commit Tree/cell-1 is still empty) must equal `sr()`
/// byte-for-byte for EVERY registered algorithm, not just one.
///
/// A single-algorithm principal cannot distinguish `EpochTree::root(alg_id)`
/// (correct) from `combined_root()` (folds every other algorithm's root
/// in, wrong) — both coincide when only one algorithm is registered. This
/// test's ES256 (SHA-256) + Ed25519 (SHA-512) key set is what makes the
/// distinction observable.
#[tokio::test]
async fn multi_alg_genesis_pg_equals_sr_for_every_algorithm() {
    let key_es256 = make_test_key(0x11);
    let key_ed25519 = make_test_key_ed25519(0x22);

    let mut principal = Principal::implicit(key_es256).await.unwrap();
    principal.genesis_test(vec![key_ed25519]).await.unwrap();
    assert_eq!(
        principal.active_algs(),
        vec![HashAlg::Sha256, HashAlg::Sha512]
    );

    let pg = principal.pg().expect("principal/create must establish PG");
    let sr = principal.sr().expect("SR must exist after genesis");
    for alg in [HashAlg::Sha256, HashAlg::Sha512] {
        assert_eq!(
            pg.get(alg),
            sr.get(alg),
            "PG must equal SR byte-for-byte for algorithm {alg:?} at genesis (cell 1/CR still \
             empty) — a mismatch here means root(alg_id) and combined_root() diverged, i.e. \
             combined_root leaked in"
        );
    }
}

/// c6/a6 — an abandoned `CommitScope` (dropped without `finalize()`) must
/// not leak any state into the live principal: not the key set (already
/// covered structurally by the borrow checker + explicit copy-back), and
/// not PR/SR/PT, which is the new hazard this node introduces (SR now
/// lives inside a PT cell that would be shared state if `PrincipalTree`
/// were `Arc`-wrapped).
#[tokio::test]
async fn abandoned_commit_scope_does_not_leak_state() {
    let key1 = make_test_key(0x11);
    let mut principal = Principal::implicit(key1.clone()).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    let pr_before = principal.pr().clone();
    let sr_before = principal.sr().cloned();
    let key_count_before = principal.active_key_count();

    {
        let mut scope = principal.begin_commit();
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&key2, key1.tmb());
        let vtx = crate::parsed_coz::VerifiedCoz::from_transaction_unsafe(cz, Some(key2));
        scope.apply(vtx).unwrap();
        // Deliberately dropped here without calling finalize().
    }

    assert_eq!(
        principal.pr(),
        &pr_before,
        "abandoned scope must not mutate the live PR"
    );
    assert_eq!(
        principal.sr().cloned(),
        sr_before,
        "abandoned scope must not mutate the live SR"
    );
    assert_eq!(
        principal.active_key_count(),
        key_count_before,
        "abandoned scope must not mutate the live key set"
    );
}

/// c7/a7 — PR's variant set must track the *current* `active_algs`, not
/// the Principal Tree's cumulative registered-algorithm set.
///
/// `PrincipalTree::ensure_algorithm` only ever adds algorithms to the
/// underlying `EpochTree` — there is no de-registration API. If PR were
/// assembled from the tree's registered algorithms instead of being
/// re-derived from `active_algs` on every mutation (see
/// `stage_commit`'s `[alg-set-evolution]` comment), revoking a
/// principal's only SHA-512 key would leave a stale SHA-512 entry in PR
/// forever, since the tree itself never forgets it was once registered.
#[tokio::test]
async fn revoked_key_algorithm_drops_from_pr_variants() {
    use crate::parsed_coz::{CozKind, ParsedCoz};

    let key_es256 = make_test_key(0x11);
    let key_ed25519 = make_test_key_ed25519(0x22);

    let mut principal = Principal::implicit(key_es256.clone()).await.unwrap();
    principal
        .genesis_test(vec![key_ed25519.clone()])
        .await
        .unwrap();
    assert_eq!(
        principal.active_algs(),
        vec![HashAlg::Sha256, HashAlg::Sha512]
    );
    assert!(
        principal.pr().get(HashAlg::Sha512).is_some(),
        "PR must have a SHA-512 variant while the Ed25519 key is active"
    );

    // Ed25519 key self-revokes; ES256 remains, so this is not a
    // last-active-key revoke (which would be rejected).
    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 2000 },
        signer: key_ed25519.tmb().clone(),
        now: 2000,
        czd: coz::Czd::from_bytes(vec![0x44; 64]),
        hash_alg: HashAlg::Sha512,
        arrow: None,
        raw: dummy_coz_json(),
    };
    principal.apply_transaction_test(cz, None).await.unwrap();

    assert!(
        !principal.is_key_active(key_ed25519.tmb()),
        "Ed25519 key must be revoked"
    );
    assert_eq!(
        principal.active_algs(),
        vec![HashAlg::Sha256],
        "SHA-512 must drop out of active_algs once its only key is revoked"
    );
    assert!(
        principal.pr().get(HashAlg::Sha512).is_none(),
        "PR must not retain a stale SHA-512 variant after its only key is revoked — this only \
         holds if PR is assembled from live active_algs rather than the tree's cumulative \
         registered-algorithm set"
    );
    assert!(
        principal.pr().get(HashAlg::Sha256).is_some(),
        "PR must still have a SHA-256 variant for the surviving ES256 key"
    );
}

/// c-liveness-shrinkage-rebuild — extends
/// `revoked_key_algorithm_drops_from_pr_variants`'s metamorphic pattern
/// to every new tree level, not just PR: KT, AR-node, and SR-node are
/// rebuilt fresh from the post-revocation key set on every mutation, so
/// a dropped algorithm cannot survive in KR/AR/SR either.
#[tokio::test]
async fn revoked_key_algorithm_drops_from_kr_ar_sr_too() {
    use crate::parsed_coz::{CozKind, ParsedCoz};

    let key_es256 = make_test_key(0x11);
    let key_ed25519 = make_test_key_ed25519(0x22);

    let mut principal = Principal::implicit(key_es256.clone()).await.unwrap();
    principal
        .genesis_test(vec![key_ed25519.clone()])
        .await
        .unwrap();
    assert_eq!(
        principal.active_algs(),
        vec![HashAlg::Sha256, HashAlg::Sha512]
    );
    assert!(
        principal
            .key_root()
            .expect("a live principal has a KR")
            .get(HashAlg::Sha512)
            .is_some()
    );
    assert!(
        principal
            .auth_root()
            .expect("a live principal has an AR")
            .get(HashAlg::Sha512)
            .is_some()
    );
    assert!(principal.sr().unwrap().get(HashAlg::Sha512).is_some());

    let cz = ParsedCoz {
        kind: CozKind::SelfRevoke { rvk: 2000 },
        signer: key_ed25519.tmb().clone(),
        now: 2000,
        czd: coz::Czd::from_bytes(vec![0x44; 64]),
        hash_alg: HashAlg::Sha512,
        arrow: None,
        raw: dummy_coz_json(),
    };
    principal.apply_transaction_test(cz, None).await.unwrap();

    assert_eq!(principal.active_algs(), vec![HashAlg::Sha256]);
    assert!(
        principal
            .key_root()
            .expect("a live principal has a KR")
            .get(HashAlg::Sha512)
            .is_none(),
        "KR must not retain a stale SHA-512 variant — KT must be rebuilt with only live \
         algorithms registered, not masked"
    );
    assert!(
        principal
            .auth_root()
            .expect("a live principal has an AR")
            .get(HashAlg::Sha512)
            .is_none(),
        "AR must not retain a stale SHA-512 variant — AR-node must be rebuilt with only live \
         algorithms registered, not masked"
    );
    assert!(
        principal.sr().unwrap().get(HashAlg::Sha512).is_none(),
        "SR must not retain a stale SHA-512 variant — SR-node must be rebuilt with only live \
         algorithms registered, not masked"
    );
    assert!(
        principal
            .key_root()
            .expect("a live principal has a KR")
            .get(HashAlg::Sha256)
            .is_some()
    );
    assert!(
        principal
            .auth_root()
            .expect("a live principal has an AR")
            .get(HashAlg::Sha256)
            .is_some()
    );
    assert!(principal.sr().unwrap().get(HashAlg::Sha256).is_some());
}

/// Reproduces a proptest-discovered defect: a `DataRoot` cached from
/// `record_action` under a narrower `active_algs` set must not be
/// reused unrefreshed once a later key of a NEW algorithm expands
/// `active_algs` — the stale DR is missing a variant for the new
/// algorithm, and `MultihashDigest::get_or_err`'s "first available
/// variant" fallback silently substitutes a wrong-width value, which
/// the tree's width-uniform fold contract correctly rejects.
#[tokio::test]
async fn adding_new_algorithm_key_after_action_recorded_does_not_panic() {
    use coz::Czd;
    use serde_json::json;

    use crate::parsed_coz::CozKind;

    let key = make_test_key(0x11);
    let mut principal = Principal::implicit(key.clone()).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    let action = make_test_action(key.tmb());
    principal.state_mut().record_action(action).unwrap();
    assert_eq!(principal.active_algs(), vec![HashAlg::Sha256]);

    // A key/create tx timestamped after the action (make_test_action
    // uses now=3000; make_key_add_tx's fixed now=2000 would fail
    // timestamp ordering, so this is constructed inline instead).
    let key2 = make_test_key_ed25519(0x22);
    let raw = coz::CozJson {
        pay: json!({
            "typ": "cyphr.me/key/create",
            "alg": "Ed25519",
            "now": 4000,
            "tmb": key.tmb().to_b64(),
            "id": key2.tmb().to_b64()
        }),
        sig: vec![0; 64],
    };
    let cz = crate::parsed_coz::ParsedCoz {
        kind: CozKind::KeyCreate {
            id: key2.tmb().clone(),
        },
        signer: key.tmb().clone(),
        now: 4000,
        czd: Czd::from_bytes(vec![0xAB; 32]),
        hash_alg: HashAlg::Sha256,
        arrow: None,
        raw,
    };
    principal
        .apply_transaction_test(cz, Some(key2.clone()))
        .await
        .unwrap();

    assert_eq!(
        principal.active_algs(),
        vec![HashAlg::Sha256, HashAlg::Sha512]
    );
    assert!(principal.sr().unwrap().get(HashAlg::Sha512).is_some());
}

/// c2/a2 — the recursive singleton-promotion property, extended through
/// the FULL new chain (`genesis_pr_equals_sr_verbatim` already proves it
/// at PT's root alone): for a single-key, no-data-action, no-commit
/// principal, `tmb == KR == AR == SR == PR`, byte-for-byte, for every
/// registered algorithm. Every hop is the same native 1-cell promotion
/// mechanism, composed recursively — no special-case machinery.
#[tokio::test]
async fn genesis_recursive_promotion_tmb_equals_kr_ar_sr_pr() {
    let key = make_test_key_ed25519(0xCC);
    let tmb_bytes = key.tmb().as_bytes().to_vec();
    let principal = Principal::implicit(key).await.unwrap();

    let alg = principal.hash_alg();
    assert_eq!(principal.active_algs(), vec![alg]);

    assert_eq!(
        principal
            .key_root()
            .expect("a live principal has a KR")
            .get(alg)
            .unwrap(),
        tmb_bytes.as_slice()
    );
    assert_eq!(
        principal
            .auth_root()
            .expect("a live principal has an AR")
            .get(alg)
            .unwrap(),
        tmb_bytes.as_slice()
    );
    assert_eq!(
        principal.sr().unwrap().get(alg).unwrap(),
        tmb_bytes.as_slice()
    );
    assert_eq!(principal.pr().get(alg).unwrap(), tmb_bytes.as_slice());
}

// ========================================================================
// c3/a3 — establish_pg works for any storage backend
// ========================================================================

/// Apply the `key/create` of the genesis key `signer`, then of each of
/// `others`, all signed by `signer`; a `principal/create` requires the
/// first (SPEC 5.1 step 1, 7.7 Example 1).
fn create_genesis_keys<S: eml::Storage>(
    principal: &mut Principal<S>,
    signer: &Key,
    others: &[Key],
    czd_byte: u8,
) {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz, VerifiedCoz};

    let keys = std::iter::once(signer).chain(others).cloned();
    for (i, key) in keys.enumerate() {
        let cz = ParsedCoz {
            kind: CozKind::KeyCreate {
                id: key.tmb().clone(),
            },
            signer: signer.tmb().clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![czd_byte.wrapping_add(1 + i as u8); 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal
            .state_mut()
            .apply_verified_internal(VerifiedCoz::from_transaction_unsafe(cz, Some(key)))
            .unwrap();
    }
}

/// Build a genesis `principal/create` coz for `key`, signed against the
/// `id` the given principal's state names — the minimal mutation that
/// drives `establish_pg`'s Nascent → Established transition.
fn make_principal_create_tx<S: eml::Storage>(
    principal: &Principal<S>,
    key: &Key,
    czd_byte: u8,
) -> crate::parsed_coz::ParsedCoz {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    ParsedCoz {
        kind: CozKind::PrincipalCreate {
            id: crate::state::AuthRoot(principal.genesis_pr().expect("genesis PR").0),
        },
        signer: key.tmb().clone(),
        now: 2000,
        czd: Czd::from_bytes(vec![czd_byte; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw: dummy_coz_json(),
    }
}

/// c3/a3 — `establish_pg` (reached via a `principal/create` coz) must
/// work correctly for `Principal<storage_fjall::FjallStorage>` — a
/// storage backend with no `Default` impl — without requiring `S:
/// Default` and without a fake/panicking `Default` on `FjallStorage`.
/// PG must be set exactly once, and byte-identical to what the same
/// operations produce under `Principal<eml::MemoryStorage>`.
#[tokio::test]
async fn establish_pg_works_for_disk_backed_storage() {
    use crate::parsed_coz::VerifiedCoz;

    let key = make_test_key(0x11);

    // Disk-backed principal.
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage_fjall::FjallStorage::open(dir.path()).expect("open fjall storage");
    let mut disk_principal = Principal::open(key.clone(), storage).await.unwrap();
    assert!(
        disk_principal.pg().is_none(),
        "PG must be absent before principal/create"
    );

    create_genesis_keys(&mut disk_principal, &key, &[], 0x10);
    let cz = make_principal_create_tx(&disk_principal, &key, 0x44);
    let vtx = VerifiedCoz::from_transaction_unsafe(cz, None);
    disk_principal
        .state_mut()
        .apply_verified_internal(vtx)
        .unwrap();
    let pg_disk = disk_principal
        .pg()
        .expect("establish_pg must set PG for a disk-backed Principal")
        .clone();

    // The equivalent in-memory principal, driven through the identical
    // sequence of operations.
    let mut mem_principal = Principal::implicit(key.clone()).await.unwrap();
    create_genesis_keys(&mut mem_principal, &key, &[], 0x10);
    let mem_cz = make_principal_create_tx(&mem_principal, &key, 0x44);
    let mem_vtx = VerifiedCoz::from_transaction_unsafe(mem_cz, None);
    mem_principal
        .state_mut()
        .apply_verified_internal(mem_vtx)
        .unwrap();
    let pg_mem = mem_principal
        .pg()
        .expect("establish_pg must set PG for an in-memory Principal")
        .clone();

    assert_eq!(
        pg_disk.as_multihash(),
        pg_mem.as_multihash(),
        "PG must be byte-identical between a disk-backed and an in-memory storage backend"
    );

    // PG is set exactly once: a second principal/create must fail, not
    // silently re-establish or panic. In the same genesis commit nothing
    // but the commit/create may follow the first (SPEC 5.1 steps 3-4).
    let second_cz = make_principal_create_tx(&disk_principal, &key, 0x55);
    let second_vtx = VerifiedCoz::from_transaction_unsafe(second_cz, None);
    let result = disk_principal
        .state_mut()
        .apply_verified_internal(second_vtx);
    assert!(
        matches!(result, Err(Error::GenesisIncomplete)),
        "a second principal/create must fail — PG is already established"
    );
}
