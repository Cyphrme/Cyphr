//! Fork evidence: two conflicting commits on one `pre` must each be
//! checkable from the common ancestor (SPEC.md: a fork is detected, never
//! merged), so a third party can hold both as proof of equivocation.
//!
//! Claims backed here:
//! - F1 (green): branches built on FRESH ancestors both finalize to different PRs, and a linear
//!   replayer rejects the second branch.
//! - F2 (red, G0): branches built on CLONES of one ancestor must do the same. They currently do
//!   not, because `Principal::clone` shares the commit log between clones.

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
    Key {
        alg: s.alg.clone(),
        tmb: s.tmb.clone(),
        pub_key: s.pub_key.clone(),
        first_seen: 1_700_000_000,
        last_used: None,
        revocation: None,
        tag: None,
    }
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
fn delete_commit(
    p: &mut Principal,
    signer: &Signer,
    target: &Signer,
    now: i64,
) -> Result<Wire, Error> {
    let (b, s, c) = delete_pay(signer, target, now);
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&b, &s, c, None)?;
    scope.finalize_with_arrow(
        &signer.alg,
        &signer.prv,
        &signer.pub_key,
        &signer.tmb,
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
    let r = scope.finalize_with_arrow(
        &key_a.alg,
        &key_a.prv,
        &key_a.pub_key,
        &key_a.tmb,
        1_700_000_101,
        "cyphr.me",
    );
    assert!(r.is_ok(), "RED(G0): branch from a cloned ancestor: {r:?}");
}
