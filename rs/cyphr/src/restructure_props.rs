//! Property net for the three mechanisms the principal restructure
//! collapses to one definition each: the Arrow, `PrincipalCore`
//! construction, and the active-signer lookup.
//!
//! These live under `src/` rather than `tests/` because two of the call
//! sites they pin are crate-private (`Principal::record_action` and the
//! unverified `CommitScope::apply` path behind
//! `VerifiedCoz::from_transaction_unsafe`), which an integration test
//! cannot reach. They are property tests over invariants, not scenarios:
//! each one states the claim it backs and the defect that turns it red.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use proptest::prelude::*;

use crate::error::Error;
use crate::key::Key;
use crate::principal::Principal;
use crate::signer::SoftwareSigner;

const AUTHORITY: &str = "cyphr.me";
const T0: i64 = 1_700_000_000;

/// Supported-algorithm pool keys: ES256 (SHA-256), ES384 (SHA-384) and
/// Ed25519 (SHA-512), so generated principals span one to three hash
/// algorithms and reach every `arrow_component_bytes` branch (direct
/// variant, single-variant fallback, multi-variant fold).
const POOL_NAMES: &[&str] = &[
    "golden",
    "key_a",
    "alice",
    "bob",
    "diana_es384",
    "eve_ed25519",
];

fn pool() -> test_fixtures::Pool {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("tests/keys/pool.toml loads")
}

fn pool_key<'p>(pool: &'p test_fixtures::Pool, name: &str) -> &'p test_fixtures::PoolKey {
    pool.get(name).expect("named pool key exists")
}

fn domain_key(pk: &test_fixtures::PoolKey) -> Key {
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub is base64");
    Key::new(pk.alg.clone(), pk.compute_tmb().expect("tmb"), pub_bytes).expect("key binds tmb")
}

fn software_signer(pk: &test_fixtures::PoolKey) -> SoftwareSigner {
    let prv = Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("pool key has prv"))
        .expect("pool prv is base64");
    let pub_bytes = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pool pub is base64");
    SoftwareSigner::new(&pk.alg, &prv, &pub_bytes, &pk.compute_tmb().expect("tmb"))
}

/// Sign `fields` (plus `alg` and `tmb` for `signer`) as a real coz.
fn sign_pay(
    signer: &test_fixtures::PoolKey,
    fields: serde_json::Value,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let mut pay = fields
        .as_object()
        .expect("pay fields are an object")
        .clone();
    pay.insert("alg".into(), serde_json::json!(signer.alg));
    pay.insert(
        "tmb".into(),
        serde_json::json!(signer.compute_tmb_b64().expect("tmb b64")),
    );
    pay.sort_keys();
    let pay_vec = serde_json::to_vec(&pay).expect("pay serializes");
    let prv = Base64UrlUnpadded::decode_vec(signer.prv.as_ref().expect("prv")).expect("prv b64");
    let pub_bytes = Base64UrlUnpadded::decode_vec(&signer.pub_key).expect("pub b64");
    let (sig, cad) =
        coz::sign_json(&pay_vec, &signer.alg, &prv, &pub_bytes).expect("pool alg signs");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("pool alg has czd");
    (pay_vec, sig, czd)
}

fn key_create_pay(
    signer: &test_fixtures::PoolKey,
    target: &test_fixtures::PoolKey,
    now: i64,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign_pay(
        signer,
        serde_json::json!({
            "typ": "cyphr.me/cyphr/key/create",
            "id": target.compute_tmb_b64().expect("tmb b64"),
            "now": now,
        }),
    )
}

fn action_pay(signer: &test_fixtures::PoolKey, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign_pay(
        signer,
        serde_json::json!({ "typ": "cyphr.me/comment/create", "msg": "hi", "now": now }),
    )
}

/// One commit of a generated history: how many fresh keys it adds, whether
/// a data action is recorded before it, and which key (by index into the
/// keys active once the commit's mutations are applied) signs its
/// `commit/create`.
#[derive(Debug, Clone)]
struct CommitPlan {
    adds: usize,
    action_first: bool,
    finalizer: usize,
}

fn history_strategy() -> impl Strategy<Value = (usize, Vec<&'static str>, Vec<CommitPlan>)> {
    let plan = (1usize..=2, any::<bool>(), any::<prop::sample::Index>()).prop_map(
        |(adds, action_first, idx)| CommitPlan {
            adds,
            action_first,
            // Resolved against the live key count when the commit runs.
            finalizer: idx.index(usize::MAX),
        },
    );
    (
        0usize..3,
        Just(POOL_NAMES.to_vec()).prop_shuffle(),
        prop::collection::vec(plan, 1..=3),
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Claim: for any valid commit history, the Arrow the write path
    /// signs into `commit/create` (`CommitScope::prepare_commit`) is the
    /// Arrow `Principal::finalize_commit` recomputes and accepts, and the
    /// Arrow `CommitScope::matches_arrow` accepts for the same scope.
    /// Turns red if: any one of the three Arrow computations diverges
    /// (component order, variant selection, fold, or digest), because
    /// finalize then rejects with `CommitMismatch` or `matches_arrow`
    /// returns false. Histories mix ES256/ES384/Ed25519 keys and let a key
    /// added in the same commit sign the finalizer, so `pre` may lack the
    /// signer's algorithm (single-variant and fold branches). Not an
    /// end-to-end scenario.
    #[test]
    fn arrow_written_equals_arrow_verified(
        (genesis_idx, order, plans) in history_strategy(),
    ) {
        let pool = pool();
        let genesis_name = ["golden", "diana_es384", "eve_ed25519"][genesis_idx];
        let genesis = pool_key(&pool, genesis_name);
        let mut targets = order.into_iter().filter(|n| *n != genesis_name);
        let mut active: Vec<&test_fixtures::PoolKey> = vec![genesis];
        let mut principal = Principal::implicit(domain_key(genesis)).expect("genesis");
        let mut now = T0;

        for plan in plans {
            if plan.action_first {
                now += 1;
                let (pay, sig, czd) = action_pay(genesis, now);
                principal.verify_and_record_action(&pay, &sig, czd).expect("action records");
            }
            let mut shadow = principal.clone();
            let mut scope = principal.begin_commit();
            let mut shadow_scope = shadow.begin_commit();
            for _ in 0..plan.adds {
                let Some(name) = targets.next() else { break };
                let target = pool_key(&pool, name);
                now += 1;
                let (pay, sig, czd) = key_create_pay(genesis, target, now);
                scope
                    .verify_and_apply(&pay, &sig, czd.clone(), Some(domain_key(target)))
                    .expect("key/create applies");
                shadow_scope
                    .verify_and_apply(&pay, &sig, czd, Some(domain_key(target)))
                    .expect("key/create applies to shadow");
                active.push(target);
            }
            if shadow_scope.is_empty() {
                break;
            }
            let finalizer = active[plan.finalizer % active.len()];
            now += 1;
            let written = scope
                .finalize_with_software(&software_signer(finalizer), now, AUTHORITY)
                .map_err(|e| TestCaseError::fail(format!(
                    "finalize rejected the arrow prepare_commit wrote \
                     (finalizer {}): {e:?}", finalizer.name)))?
                .commit_tx()
                .0
                .last()
                .and_then(|c| c.arrow())
                .cloned()
                .expect("commit/create carries the arrow");
            prop_assert!(
                shadow_scope.matches_arrow(&written),
                "matches_arrow refused the arrow prepare_commit wrote (finalizer {})",
                finalizer.name
            );
        }
    }

    /// Claim: every genesis constructor yields the same KR, AR, SR and PR
    /// (and the same genesis-key list and active-key order) for the same
    /// keys: `explicit`/`explicit_with_storage`, and
    /// `implicit`/`implicit_with_storage` for a single key.
    /// Turns red if: one constructor's copy of the root derivation, the
    /// Principal Tree assembly, or the key-ledger fill drifts from the
    /// others. Not an end-to-end scenario.
    #[test]
    fn constructors_agree_on_roots(
        names in prop::sample::subsequence(POOL_NAMES.to_vec(), 1..=4)
            .prop_shuffle(),
    ) {
        let pool = pool();
        let keys: Vec<Key> = names.iter().map(|n| domain_key(pool_key(&pool, n))).collect();

        let reference = Principal::explicit(keys.clone()).expect("explicit genesis");
        let mut candidates = vec![
            ("explicit_with_storage", Principal::explicit_with_storage(
                keys.clone(), eml::MemoryStorage::new()).expect("explicit_with_storage")),
        ];
        if keys.len() == 1 {
            candidates.push(("implicit", Principal::implicit(keys[0].clone()).expect("implicit")));
            candidates.push(("implicit_with_storage", Principal::implicit_with_storage(
                keys[0].clone(), eml::MemoryStorage::new()).expect("implicit_with_storage")));
        }
        for (name, p) in &candidates {
            assert_same_state(name, &reference, p)?;
        }
    }
}

fn assert_same_state(
    name: &str,
    reference: &Principal,
    p: &Principal,
) -> std::result::Result<(), TestCaseError> {
    prop_assert_eq!(p.key_root(), reference.key_root(), "{} KR", name);
    prop_assert_eq!(p.auth_root(), reference.auth_root(), "{} AR", name);
    prop_assert_eq!(p.sr(), reference.sr(), "{} SR", name);
    prop_assert_eq!(p.pr(), reference.pr(), "{} PR", name);
    prop_assert_eq!(p.cr(), reference.cr(), "{} CR", name);
    prop_assert_eq!(
        p.genesis_keys(),
        reference.genesis_keys(),
        "{} genesis keys",
        name
    );
    let order = |q: &Principal| {
        q.active_keys()
            .map(|k| k.tmb().to_b64())
            .collect::<Vec<_>>()
    };
    prop_assert_eq!(order(p), order(reference), "{} active-key order", name);
    Ok(())
}

/// Which refusal a signer lookup produced, so results from different call
/// sites compare by variant (`Error` has no `PartialEq`).
fn refusal<T>(r: crate::error::Result<T>) -> Option<&'static str> {
    match r {
        Err(Error::UnknownKey) => Some("UnknownKey"),
        Err(Error::KeyRevoked) => Some("KeyRevoked"),
        _ => None,
    }
}

/// Claim: every call site that resolves a signer refuses an unknown key
/// with `UnknownKey` and a revoked key with `KeyRevoked`, and none refuses
/// an active key: `Principal::verify_and_record_action`,
/// `Principal::verify_and_apply_transaction`, `Principal::record_action`,
/// `CommitScope::verify_and_apply`, `CommitScope::prepare_commit`, and
/// `CommitScope::apply` (the unverified apply path).
/// Turns red if: one site's lookup classifies a key differently (e.g.
/// reports a revoked key as unknown, or skips the revoked set).
/// Exhaustive over the pool rather than sampled: the domain is six keys.
/// Not an end-to-end scenario.
#[test]
fn signer_lookup_refuses_alike_at_every_site() {
    let pool = pool();
    let genesis = pool_key(&pool, "golden");
    let revoked = pool_key(&pool, "key_a");
    let filler = pool_key(&pool, "alice");
    let unknowns = ["bob", "diana_es384", "eve_ed25519"];

    // golden + key_a + alice active, then key_a moved to the revoked set.
    let mut principal = Principal::implicit(domain_key(genesis)).expect("genesis");
    for (i, target) in [revoked, filler].into_iter().enumerate() {
        let now = T0 + 2 * i as i64;
        let mut scope = principal.begin_commit();
        let (pay, sig, czd) = key_create_pay(genesis, target, now);
        scope
            .verify_and_apply(&pay, &sig, czd, Some(domain_key(target)))
            .expect("applies");
        scope
            .finalize_with_software(&software_signer(genesis), now + 1, AUTHORITY)
            .expect("commit finalizes");
    }
    principal
        .pre_revoke_key(&revoked.compute_tmb().expect("tmb"), T0 + 5)
        .expect("revokes");

    let mut probes: Vec<(&test_fixtures::PoolKey, Option<&str>)> = unknowns
        .iter()
        .map(|n| (pool_key(&pool, n), Some("UnknownKey")))
        .collect();
    probes.push((revoked, Some("KeyRevoked")));
    probes.push((genesis, None));
    probes.push((filler, None));

    let now = T0 + 100;
    for (probe, expected) in probes {
        let tmb = probe.compute_tmb().expect("tmb");
        let mut sites: Vec<(&str, Option<&str>)> = Vec::new();

        let (pay, sig, czd) = action_pay(probe, now);
        let mut p = principal.clone();
        sites.push((
            "verify_and_record_action",
            refusal(p.verify_and_record_action(&pay, &sig, czd.clone())),
        ));

        let mut p = principal.clone();
        let action = crate::action::Action::new(
            "cyphr.me/comment/create".into(),
            tmb.clone(),
            now,
            czd,
            coz::CozJson {
                pay: serde_json::json!({}),
                sig: vec![],
            },
        );
        sites.push(("record_action", refusal(p.record_action(action))));

        let target = pool_key(&pool, "carol");
        let (pay, sig, czd) = key_create_pay(probe, target, now);
        let mut p = principal.clone();
        sites.push((
            "verify_and_apply_transaction",
            refusal(p.verify_and_apply_transaction(
                &pay,
                &sig,
                czd.clone(),
                Some(domain_key(target)),
            )),
        ));

        let mut p = principal.clone();
        let mut scope = p.begin_commit();
        sites.push((
            "CommitScope::verify_and_apply",
            refusal(scope.verify_and_apply(&pay, &sig, czd.clone(), Some(domain_key(target)))),
        ));

        let mut p = principal.clone();
        let mut scope = p.begin_commit();
        let parsed = crate::parsed_coz::ParsedCoz {
            kind: crate::parsed_coz::CozKind::KeyCreate {
                id: target.compute_tmb().expect("tmb"),
            },
            signer: tmb.clone(),
            now,
            czd,
            hash_alg: crate::state::hash_alg_from_str(&probe.alg).expect("pool alg"),
            arrow: None,
            raw: coz::CozJson {
                pay: serde_json::json!({}),
                sig: vec![],
            },
        };
        sites.push((
            "CommitScope::apply",
            refusal(
                scope.apply(crate::parsed_coz::VerifiedCoz::from_transaction_unsafe(
                    parsed,
                    Some(domain_key(target)),
                )),
            ),
        ));

        // prepare_commit needs a non-empty scope: one genuine mutation
        // signed by the genesis key, then the probe as finalizer.
        let mut p = principal.clone();
        let mut scope = p.begin_commit();
        let (gpay, gsig, gczd) = key_create_pay(genesis, target, now);
        scope
            .verify_and_apply(&gpay, &gsig, gczd, Some(domain_key(target)))
            .expect("genuine mutation applies");
        sites.push((
            "CommitScope::prepare_commit",
            refusal(scope.prepare_commit(&software_signer(probe), now + 1, AUTHORITY)),
        ));

        for (site, got) in sites {
            assert_eq!(
                got, expected,
                "{site} classified signer {} as {got:?}, expected {expected:?}",
                probe.name
            );
        }
    }
}
