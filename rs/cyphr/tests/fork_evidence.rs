//! Fork evidence: two conflicting commits on one `pre` must each be
//! checkable from the common ancestor (SPEC.md: a fork is detected, never
//! merged), so a third party can hold both as proof of equivocation.
//!
//! Claims backed here:
//! - F1 (green): branches built on FRESH ancestors both finalize to different PRs, and a linear
//!   replayer rejects the second branch.
//! - F2 (red, G0): branches built on CLONES of one ancestor must do the same. They currently do
//!   not, because `Principal::clone` shares the commit log between clones.
//! - `clone_independence_*` (red, G0): a public clone is fully independent of its source, and a
//!   durable-storage principal cannot be publicly cloned at all (rather than silently sharing).
//! - `commit_scope_records_to_own_principal_*` (green guard, G0): the fix must not detach a commit
//!   scope from the principal it was opened on.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Error, Key, Principal};
use test_fixtures::Pool;

struct Signer {
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn signer(name: &str) -> Signer {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = Pool::load(&path).expect("pool.toml loads");
    let pk = pool
        .get(name)
        .unwrap_or_else(|| panic!("pool key {name} missing"));
    Signer {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("pool key has prv"))
            .expect("prv base64"),
        pub_key: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub base64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn domain_key(s: &Signer) -> Key {
    Key::new(s.alg.clone(), s.tmb.clone(), s.pub_key.clone())
        .expect("key binds its tmb")
        .with_first_seen(1_700_000_000)
}

type Wire = Vec<(Vec<u8>, Vec<u8>, coz::Czd)>;

fn delete_pay(signer: &Signer, target: &Signer, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let pay = serde_json::json!({"alg": signer.alg, "tmb": signer.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/delete", "id": target.tmb.to_b64(), "now": now});
    let bytes = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) =
        coz::sign_json(&bytes, &signer.alg, &signer.prv, &signer.pub_key).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    (bytes, sig, czd)
}

/// One commit on `p`: `signer` deletes `target`. Returns the commit's cozies
/// as a peer would receive them, or the finalize error.
fn delete_commit<S: eml::Storage>(
    p: &mut Principal<S>,
    signer: &Signer,
    target: &Signer,
    now: i64,
) -> Result<Wire, Error> {
    let (b, s, c) = delete_pay(signer, target, now);
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&b, &s, c, None)?;
    scope.finalize_with_software(
        &cyphr::signer::SoftwareSigner::new(&signer.alg, &signer.prv, &signer.pub_key, &signer.tmb),
        now,
        "cyphr.me",
    )?;
    Ok(p.commits()
        .last()
        .expect("commit recorded")
        .all_cozies()
        .iter()
        .map(|vc| {
            let raw = vc.raw();
            (
                serde_json::to_vec(&raw.pay).expect("serialize pay"),
                raw.sig.clone(),
                vc.czd().clone(),
            )
        })
        .collect())
}

fn replay(p: &mut Principal, wire: &Wire) -> Result<String, Error> {
    let mut scope = p.begin_commit();
    for (b, s, c) in wire {
        scope.verify_and_apply(b, s, c.clone(), None)?;
    }
    scope.finalize().map(|c| format!("{:?}", c.pr()))
}

// Practice: SPEC.md section 15.7.1 and section 15.8: on a fork "witnesses hold both branches and the principal's consensus state is Error" until resolved; with root AGENTS.md invariant I2 ("a fork is detected, never merged"), each conflicting commit must verify independently against the shared ancestor.
// Claim F1. Mutation that turns this red: a commit verifier that depends on state outside the
// ancestor plus the commit's cozies, or one that accepts the second branch on top of the first.
#[test]
fn fork_branches_verify_from_fresh_ancestors() {
    let (g, a) = (signer("golden"), signer("key_a"));
    let fresh = || Principal::explicit(vec![domain_key(&g), domain_key(&a)]).expect("ancestor");

    // Branch A: golden deletes key_a. Branch B: key_a deletes golden. Same pre.
    let wire_a = delete_commit(&mut fresh(), &g, &a, 1_700_000_100).expect("branch A builds");
    let wire_b = delete_commit(&mut fresh(), &a, &g, 1_700_000_101).expect("branch B builds");

    // A peer holding only the ancestor verifies each branch independently.
    let ra = replay(&mut fresh(), &wire_a).expect("branch A verifies from ancestor");
    let rb = replay(&mut fresh(), &wire_b).expect("branch B verifies from ancestor");
    assert_ne!(ra, rb, "conflicting commits reach different PRs");

    // A linear replayer that has applied A rejects B: key_a is already gone.
    let mut linear = fresh();
    replay(&mut linear, &wire_a).expect("A applies");
    let r = replay(&mut linear, &wire_b);
    assert!(
        matches!(r, Err(Error::UnknownKey)),
        "expected Err(UnknownKey), got {r:?}"
    );
}

// Practice: SPEC.md section 15.7.1 and section 15.8: witnesses must be able to hold both branches
// of a fork, and root AGENTS.md invariant I2 requires the fork be detected, so deriving the
// branches by cloning the ancestor must not couple them. Claim F2 (RED, owner G0). Mutation that
// makes this green: `Principal::clone` giving each clone its own commit log instead of sharing the
// `Arc`.
#[test]
#[ignore = "RED(G0): Principal::clone shares the commit log"]
fn fork_branches_from_cloned_ancestor() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let ancestor =
        Principal::explicit(vec![domain_key(&golden), domain_key(&key_a)]).expect("ancestor");

    let mut a = ancestor.clone();
    let ra = delete_commit(&mut a, &golden, &key_a, 1_700_000_100);
    assert!(ra.is_ok(), "branch A on a clone of the ancestor: {ra:?}");

    let mut b = ancestor.clone();
    let (bytes, sig, czd) = delete_pay(&key_a, &golden, 1_700_000_101);
    let mut scope = b.begin_commit();
    scope
        .verify_and_apply(&bytes, &sig, czd, None)
        .expect("branch B coz applies");
    let r = scope.finalize_with_software(
        &cyphr::signer::SoftwareSigner::new(&key_a.alg, &key_a.prv, &key_a.pub_key, &key_a.tmb),
        1_700_000_101,
        "cyphr.me",
    );
    assert!(r.is_ok(), "RED(G0): branch from a cloned ancestor: {r:?}");
}

// ---------------------------------------------------------------------------------------------
// G0 acceptance: clone independence
// ---------------------------------------------------------------------------------------------

/// Observable state of a principal that a sibling clone must never perturb.
fn snapshot<S: eml::Storage>(p: &Principal<S>) -> (String, String, Vec<String>) {
    (
        format!("{:?}", p.pr()),
        format!("{:?}", p.cr()),
        p.commits().map(|c| format!("{:?}", c.pr())).collect(),
    )
}

mod clone_independence {
    use proptest::prelude::*;

    use super::*;

    // Claim: a public clone is fully independent of its source: commits applied to one never
    // appear in the other's PR, CR or commit list, and the untouched side can still commit its
    // own next commit (property over random valid commit sequences, both directions).
    // Defect that turns it red: any shared mutable state between clones; today `Principal::clone`
    // shares the commit log `Arc`, so the untouched clone's CR (and its next commit) is perturbed.
    // End-to-end scenario: no, a property test for an invariant.
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 8,
            // The expected red must not write a regressions file into the tree.
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        #[ignore = "RED(G0): Principal::clone shares the commit log"]
        fn clone_independence_property(
            // Targets golden deletes on branch A, in order: a random non-empty prefix of a
            // random permutation of the three non-golden keys.
            order in Just(vec!["key_a", "alice", "bob"]).prop_shuffle(),
            take in 1usize..=3,
        ) {
            let golden = signer("golden");
            let key_a = signer("key_a");
            let targets: Vec<Signer> = order[..take].iter().map(|n| signer(n)).collect();
            let mut keys = vec![domain_key(&golden), domain_key(&key_a)];
            keys.extend(["alice", "bob"].iter().map(|n| domain_key(&signer(n))));
            let ancestor = Principal::explicit(keys).expect("ancestor");

            let mut a = ancestor.clone();
            let mut b = ancestor.clone();
            let before = snapshot(&ancestor);
            prop_assert_eq!(snapshot(&b), before.clone());

            // Apply the sequence to A only.
            for (i, t) in targets.iter().enumerate() {
                delete_commit(&mut a, &golden, t, 1_700_000_100 + i as i64)
                    .expect("A's commit sequence is valid");
            }
            prop_assert_eq!(a.commits().count(), take);

            // B and the ancestor itself are untouched by A's commits.
            prop_assert_eq!(snapshot(&b), before.clone(), "A's commits leaked into clone B");
            prop_assert_eq!(snapshot(&ancestor), before.clone(), "A's commits leaked into the source");

            // B can still commit its own next commit, and A does not see it.
            let a_after = snapshot(&a);
            delete_commit(&mut b, &key_a, &golden, 1_700_000_500)
                .expect("B can still commit after A committed on a clone of the same ancestor");
            prop_assert_eq!(b.commits().count(), 1);
            prop_assert_ne!(snapshot(&b).0, a_after.0.clone(), "branches reached the same PR");
            prop_assert_eq!(snapshot(&a), a_after, "B's commit leaked into A");
        }
    }

    /// Autoref probe: `Probe::<T>::IS_CLONE` is `true` iff `T: Clone`, decided at compile time for
    /// a concrete `T` (the inherent const shadows the trait default only when the bound holds).
    struct Probe<T>(std::marker::PhantomData<T>);
    // Never named: the trait exists only so `Probe::<T>::IS_CLONE` resolves to this default.
    #[allow(dead_code)]
    trait NotClone {
        const IS_CLONE: bool = false;
    }
    impl<T> NotClone for Probe<T> {}
    impl<T: Clone> Probe<T> {
        const IS_CLONE: bool = true;
    }

    // Claim: cloning a durable-storage principal must fail at compile time rather than silently
    // share one Fjall-backed log (brief Reserved halt predicate; FjallStorage has no copy
    // primitive in eml 0.11). Expressed at runtime via a compile-time trait probe because the
    // package has no trybuild dependency and Cargo.toml is outside this node's file surface.
    // Defect that turns it red: `Principal<S>: Clone` for every `S: eml::Storage`, as today.
    // The in-memory principal must stay publicly Clone (F2 and the property above need it).
    // End-to-end scenario: no, a type-level invariant has no scenario that reaches it.
    #[test]
    #[ignore = "RED(G0): Principal<S>: Clone for every S, durable included"]
    fn clone_independence_durable_principal_not_publicly_clone() {
        // Constants by design; the const-assert lint would suggest a build-time error instead,
        // which would break compilation of the whole file rather than fail this one test.
        #[allow(clippy::assertions_on_constants)]
        let () = assert!(
            Probe::<Principal>::IS_CLONE,
            "the in-memory principal must stay publicly Clone"
        );
        #[allow(clippy::assertions_on_constants)]
        let () = assert!(
            !Probe::<Principal<storage_fjall::FjallStorage>>::IS_CLONE,
            "Principal<FjallStorage> must not be Clone: a clone would share one durable log"
        );
    }
}

// Claim: a commit scope records to the principal it was opened on, for in-memory and for
// durable-storage principals: after finalize the scope's own principal holds the commit, CR and
// new PR. Green guard (c-scope), not red on the base: it fails only if the fix detaches the scope
// from its principal (e.g. scope projects onto a now-independent clone and forgets to write back).
// End-to-end scenario: yes (build, sign, finalize, observe).
#[test]
fn commit_scope_records_to_own_principal_memory_and_durable() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let keys = || vec![domain_key(&golden), domain_key(&key_a)];

    let mut mem = Principal::explicit(keys()).expect("memory principal");
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = storage_fjall::FjallStorage::open(dir.path()).expect("open fjall");
    let mut disk = Principal::explicit_with_storage(keys(), storage).expect("durable principal");

    let (mem_pr, disk_pr) = (format!("{:?}", mem.pr()), format!("{:?}", disk.pr()));
    delete_commit(&mut mem, &golden, &key_a, 1_700_000_100).expect("memory commit");
    delete_commit(&mut disk, &golden, &key_a, 1_700_000_100).expect("durable commit");

    for (name, count, cr, pr, before) in [
        (
            "memory",
            mem.commits().count(),
            mem.cr().is_some(),
            format!("{:?}", mem.pr()),
            mem_pr,
        ),
        (
            "durable",
            disk.commits().count(),
            disk.cr().is_some(),
            format!("{:?}", disk.pr()),
            disk_pr,
        ),
    ] {
        assert_eq!(
            count, 1,
            "{name}: commit recorded on the scope's own principal"
        );
        assert!(cr, "{name}: CR present after finalize");
        assert_ne!(
            pr, before,
            "{name}: PR advanced on the scope's own principal"
        );
    }
    assert_eq!(
        format!("{:?}", mem.pr()),
        format!("{:?}", disk.pr()),
        "same ancestor and commit give the same PR regardless of storage"
    );
}
