//! Nonce acceptance tests (SPEC be0663f 10.1, 10.2, 3.7).
//!
//! A nonce is an opaque, high-entropy digest inserted at a tree level by
//! `*/nonce/create` and removed by `*/nonce/delete` (`id` is the nonce).
//! The `typ` carries the path, with the protocol authority first:
//!
//! - `cyphr.me/cyphr/nonce/create`: the Principal Root level (PT).
//! - `cyphr.me/cyphr/AT/nonce/create`: the root of AT (an input of AR).
//! - `cyphr.me/cyphr/AT/KT/nonce/create`: the root of KT (an input of KR).
//!
//! Every test drives the wire (a signed coz applied through the public
//! `begin_commit` / `verify_and_apply` API), so none depends on how the
//! implementation names its kinds. The nonce `id` is the tagged form
//! `SHA-256:<b64ut>` (10.2: "associated with a hashing algorithm"; the bare
//! 10.1 example form is not pinned, see the SPEC ambiguities in the node
//! report). Bit-length rejection (10.2) lives in `spec_conformance.rs`
//! (`s10_2_*`).
//!
//! Hand oracle: with no data and no rules, 3.7 promotes a lone child, so
//! `SR == AR == KR` and `KR = H(sort(tmb..., nonce...))` (rules 1-4). Every
//! exact digest below is computed here with `sha2` from those rules, never
//! from the code under test.
//!
//! Red-first: until nonces exist every `nonce/*` typ is refused as a
//! malformed payload, so each RED test fails on its first success assertion.
//! Run the red ones with `cargo test -p cyphr --test nonce -- --ignored`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::sha2::{Digest, Sha256};
use cyphr::signer::SoftwareSigner;
use cyphr::state::HashAlg;
use cyphr::{AuthRoot, Key, KeyRoot, Principal, StateDigest, StateRoot, compute_pr};
use proptest::prelude::*;
use serde_json::json;

const T: i64 = 1_700_000_000;

// ============================================================================
// Harness
// ============================================================================

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn pool_key(name: &str) -> Kp {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool");
    let pk = pool.get(name).expect("key in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    assert_eq!(pk.alg, "ES256", "premise: {name} is ES256 (SHA-256)");
    Kp {
        alg: pk.alg.clone(),
        pubb: d(&pk.pub_key),
        prv: d(pk.prv.as_ref().expect("signing key has prv")),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// `p` with its genesis committed (SPEC 5.1: a commit chain begins with the
/// genesis key's `key/create` of itself, the `principal/create` and the
/// `commit/create`), signed by its genesis key `k`.
fn genesis_of(mut p: Principal, k: &Kp) -> Principal {
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb),
        1,
        "cyphr.me",
    )
    .expect("genesis commit");
    p
}

fn b64(t: &coz::Thumbprint) -> String {
    Base64UrlUnpadded::encode_string(t.as_bytes())
}

type Signed = (Vec<u8>, Vec<u8>, coz::Czd);

fn sign(k: &Kp, mut pay: serde_json::Value) -> Signed {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

/// One finalized commit by `signer` applying a single signed coz plus an
/// optional sidecar key.
fn commit_one(
    p: &mut Principal,
    signer: &Kp,
    parts: Signed,
    sidecar: Option<Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, sidecar)?;
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&signer.alg, &signer.prv, &signer.pubb, &signer.tmb),
            now,
            "cyphr.me",
        )
        .map(|_| ())
}

/// The three insertion points SPEC 10.1 names.
#[derive(Clone, Copy, Debug)]
enum Level {
    /// Principal Root (`cyphr/nonce/...`).
    Pr,
    /// Root of AT (`cyphr/AT/nonce/...`).
    At,
    /// Root of KT (`cyphr/AT/KT/nonce/...`).
    Kt,
}

impl Level {
    fn typ(self, verb: &str) -> String {
        let path = match self {
            Level::Pr => "cyphr",
            Level::At => "cyphr/AT",
            Level::Kt => "cyphr/AT/KT",
        };
        format!("cyphr.me/{path}/nonce/{verb}")
    }
}

/// A SHA-256 nonce in the tagged `id` form.
fn nonce_id(bytes: &[u8]) -> String {
    format!("SHA-256:{}", Base64UrlUnpadded::encode_string(bytes))
}

fn nonce_pay(level: Level, verb: &str, signer: &Kp, id: &str, now: i64) -> Signed {
    sign(
        signer,
        json!({"alg": signer.alg, "id": id, "now": now, "tmb": b64(&signer.tmb),
               "typ": level.typ(verb)}),
    )
}

fn create(level: Level, signer: &Kp, nonce: &[u8], now: i64) -> Signed {
    nonce_pay(level, "create", signer, &nonce_id(nonce), now)
}

fn delete(level: Level, signer: &Kp, nonce: &[u8], now: i64) -> Signed {
    nonce_pay(level, "delete", signer, &nonce_id(nonce), now)
}

fn key_create(signer: &Kp, id: &Kp, now: i64) -> Signed {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(&id.tmb), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/create"}),
    )
}

/// A two-key principal (`golden` + `key_a`, both ES256) after one finalized
/// commit, so it has a Commit Root and no data: the minimal shape where
/// `PR = H(SR || CR)` and `SR == AR == KR`.
fn base() -> (Principal, Kp, Kp) {
    let (g, a) = (pool_key("golden"), pool_key("key_a"));
    let mut p = genesis_of(Principal::implicit(key_of(&g)).expect("genesis"), &g);
    commit_one(&mut p, &g, key_create(&g, &a, T), Some(key_of(&a)), T).expect("add key_a");
    (p, g, a)
}

/// Every root a nonce could disturb, plus the counters a leak would move.
#[derive(Clone, Debug, PartialEq)]
struct Roots {
    kr: KeyRoot,
    ar: AuthRoot,
    sr: Option<StateRoot>,
    keys: usize,
}

fn roots(p: &Principal) -> Roots {
    Roots {
        kr: p.key_root().expect("a live principal has a KR").clone(),
        ar: p.auth_root().expect("a live principal has an AR").clone(),
        sr: p.sr().cloned(),
        keys: p.active_key_count(),
    }
}

/// `PR` as the nonce-free formula `H(SR || CR)` (3.7.1) would give it. PR
/// equals this exactly when no nonce sits at the PR level.
fn pr_without_embedding(p: &Principal) -> cyphr::PrincipalRoot {
    compute_pr(p.sr().expect("sr"), p.cr(), &p.active_algs()).expect("compute_pr")
}

fn sha256_of_sorted(parts: &[&[u8]]) -> Vec<u8> {
    let mut sorted = parts.to_vec();
    sorted.sort();
    let mut h = Sha256::new();
    for part in sorted {
        h.update(part);
    }
    h.finalize().to_vec()
}

fn sha256_of_concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().to_vec()
}

fn sha256_bytes<T: StateDigest>(root: &T) -> Vec<u8> {
    root.get(HashAlg::Sha256).expect("SHA-256 variant").to_vec()
}

fn nonce_bytes(seed: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([seed]);
    h.finalize().into()
}

// ============================================================================
// Characterization (green today): the premises the oracles lean on
// ============================================================================

/// Backs the oracle premises of every test below: with two keys, no data
/// and no nonce, `KR = H(sort(tmb_g, tmb_a))` (3.7.3), `AR` and `SR` promote
/// `KR` unchanged (3.7 rule 3), and `PR = H(SR || CR)`. Turns red if the
/// base shape stops matching 3.7, which would make the RED tests assert
/// against a moved target. Not end to end: a characterization of the
/// pre-nonce roots.
#[test]
fn premise_roots_without_nonce_follow_3_7() {
    let (p, g, a) = base();
    let kr = sha256_of_sorted(&[g.tmb.as_bytes(), a.tmb.as_bytes()]);
    assert_eq!(
        sha256_bytes(p.key_root().expect("a live principal has a KR")),
        kr,
        "KR = H(sort(tmb...))"
    );
    assert_eq!(
        p.auth_root()
            .expect("a live principal has an AR")
            .as_multihash(),
        p.key_root()
            .expect("a live principal has a KR")
            .as_multihash()
    );
    assert_eq!(
        p.sr().expect("sr").as_multihash(),
        p.key_root()
            .expect("a live principal has a KR")
            .as_multihash()
    );
    assert_eq!(
        &pr_without_embedding(&p),
        p.pr(),
        "PR = H(SR || CR) with no PR-level embedding"
    );
}

// ============================================================================
// a-paths: which roots a nonce moves, and that its delete undoes it
// ============================================================================

/// What 3.7 says a nonce at `level` moves, as (KR, AR, SR) changed flags.
/// KT nonce is a KR input (and so moves everything above); an AT nonce is an
/// AR input; a PR nonce is a PR input only, so SR and below stay put.
fn expected_moved(level: Level) -> (bool, bool, bool) {
    match level {
        Level::Kt => (true, true, true),
        Level::At => (false, true, true),
        Level::Pr => (false, false, false),
    }
}

fn state_after_create(level: Level, n: &[u8]) -> (Principal, Roots, Roots, Kp) {
    let (mut p, g, _) = base();
    let before = roots(&p);
    let r = commit_one(&mut p, &g, create(level, &g, n, T + 10), None, T + 10);
    assert!(
        r.is_ok(),
        "{level:?} nonce/create was refused (nonces are not implemented): {r:?}"
    );
    let after = roots(&p);
    (p, before, after, g)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    /// Backs 10.1 / 3.7: a nonce at a path changes exactly the roots 3.7
    /// says it changes and nothing else; its `nonce/delete` restores them
    /// (property over path and nonce value). Per level:
    /// KT moves KR, AR, SR; AT moves AR, SR but not KR; PR moves none of
    /// the state roots and shows up only in PR (`PR != H(SR || CR)`).
    /// Below the nonce's level `PR == H(SR || CR)` still holds, so the nonce
    /// does not reach PR except through SR. After the delete every state
    /// root equals its pre-create value, and the PR formula holds again (no
    /// residue). The nonce is not a key. Also metamorphic: a different nonce
    /// value at the same path gives a different root at the level's own
    /// root (the value matters; "it only changes digests").
    /// Turns red on: a no-op create (the level's root does not move); a
    /// create that leaks into a root it should not (KR moved by an AT
    /// nonce, SR moved by a PR nonce, PR changed by a KT nonce); a delete
    /// that leaves residue (a root differs from before the create, or PR
    /// stays embedded); a nonce counted as a key; a nonce whose value is
    /// ignored. Property test: the invariant ranges over paths and values.
    #[test]
    fn paths_nonce_moves_only_its_roots_and_delete_restores(
        level in prop_oneof![Just(Level::Pr), Just(Level::At), Just(Level::Kt)],
        n1 in any::<[u8; 32]>(),
        n2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(n1 != n2);
        let (mut p, before, after, g) = state_after_create(level, &n1);
        let (kr, ar, sr) = expected_moved(level);
        prop_assert_eq!(after.kr != before.kr, kr, "KR moved wrongly at {:?}", level);
        prop_assert_eq!(after.ar != before.ar, ar, "AR moved wrongly at {:?}", level);
        prop_assert_eq!(after.sr != before.sr, sr, "SR moved wrongly at {:?}", level);
        prop_assert_eq!(after.keys, before.keys, "a nonce became a key");
        match level {
            Level::Pr => prop_assert_ne!(
                &pr_without_embedding(&p), p.pr(), "a PR nonce is not in PR"
            ),
            _ => prop_assert_eq!(
                &pr_without_embedding(&p), p.pr(), "{:?} nonce leaked into PR", level
            ),
        }

        // A different value at the same path gives a different root there.
        let (other, _, other_after, _) = state_after_create(level, &n2);
        match level {
            Level::Kt => prop_assert_ne!(other_after.kr, after.kr.clone()),
            Level::At => prop_assert_ne!(other_after.ar, after.ar.clone()),
            Level::Pr => prop_assert_ne!(other.pr(), p.pr()),
        }

        let r = commit_one(&mut p, &g, delete(level, &g, &n1, T + 20), None, T + 20);
        prop_assert!(r.is_ok(), "{:?} nonce/delete was refused: {:?}", level, r);
        prop_assert_eq!(roots(&p), before, "delete left residue at {:?}", level);
        prop_assert_eq!(
            &pr_without_embedding(&p), p.pr(), "delete left a PR embedding at {:?}", level
        );
    }
}

/// Backs 10.1 / 10.2 / 3.7 exactly: several nonces may sit at one KT level
/// and the root is the sorted hash of every key thumbprint and nonce, so
/// `KR = H(sort(tmb_g, tmb_a, N1, N2))`; the set is order-free (a second
/// principal creating N2 then N1 agrees); `nonce/delete` of one leaves the
/// other (`KR = H(sort(tmb_g, tmb_a, N2))`); deleting the last restores the
/// pre-nonce KR. With the chain promotion, `SR == AR == KR` throughout.
/// Turns red on: a nonce hashed in the wrong place or unsorted (the exact
/// digest differs); a second nonce replacing the first; a delete removing
/// every nonce or the wrong one; an insertion-order-dependent root.
/// End to end: yes (create, create, delete, delete on a live principal).
#[test]
fn kt_nonces_are_sorted_into_the_key_root_and_delete_one_by_one() {
    let (n1, n2) = (nonce_bytes(1), nonce_bytes(2));
    let (mut p, g, a) = base();
    let tmbs = [g.tmb.as_bytes(), a.tmb.as_bytes()];
    let pre = roots(&p);

    let r = commit_one(&mut p, &g, create(Level::Kt, &g, &n1, T + 10), None, T + 10);
    assert!(r.is_ok(), "KT nonce/create was refused: {r:?}");
    assert_eq!(
        sha256_bytes(p.key_root().expect("a live principal has a KR")),
        sha256_of_sorted(&[tmbs[0], tmbs[1], &n1]),
        "KR with one nonce"
    );
    assert_eq!(
        p.auth_root()
            .expect("a live principal has an AR")
            .as_multihash(),
        p.key_root()
            .expect("a live principal has a KR")
            .as_multihash()
    );
    assert_eq!(
        p.sr().expect("sr").as_multihash(),
        p.key_root()
            .expect("a live principal has a KR")
            .as_multihash()
    );

    let r = commit_one(&mut p, &g, create(Level::Kt, &g, &n2, T + 11), None, T + 11);
    assert!(r.is_ok(), "a second KT nonce was refused: {r:?}");
    assert_eq!(
        sha256_bytes(p.key_root().expect("a live principal has a KR")),
        sha256_of_sorted(&[tmbs[0], tmbs[1], &n1, &n2]),
        "KR with two nonces"
    );
    let two = roots(&p);

    // The same two nonces in the other order: same state roots.
    let (mut q, g2, _) = base();
    commit_one(
        &mut q,
        &g2,
        create(Level::Kt, &g2, &n2, T + 10),
        None,
        T + 10,
    )
    .expect("reordered first nonce");
    commit_one(
        &mut q,
        &g2,
        create(Level::Kt, &g2, &n1, T + 11),
        None,
        T + 11,
    )
    .expect("reordered second nonce");
    assert_eq!(roots(&q), two, "the nonce set is order-dependent");

    let r = commit_one(&mut p, &g, delete(Level::Kt, &g, &n1, T + 20), None, T + 20);
    assert!(r.is_ok(), "deleting one of two nonces was refused: {r:?}");
    assert_eq!(
        sha256_bytes(p.key_root().expect("a live principal has a KR")),
        sha256_of_sorted(&[tmbs[0], tmbs[1], &n2]),
        "KR after deleting N1 must keep N2"
    );

    let r = commit_one(&mut p, &g, delete(Level::Kt, &g, &n2, T + 21), None, T + 21);
    assert!(r.is_ok(), "deleting the last nonce was refused: {r:?}");
    assert_eq!(
        roots(&p),
        pre,
        "deleting every nonce must restore the roots"
    );
}

/// Backs 10.1 / 3.7 at the AT level: an AT nonce is hashed with KR into AR
/// (`AR = H(sort(KR, N))`; 3.7 rule 2 sorts, though AR's role slots are
/// positional in the code, so the oracle accepts either operand order and
/// pins only that AR is the hash of exactly KR and N), KR itself does not
/// move, `SR` promotes `AR`, and two AT nonces are order-free. Turns red on:
/// an AT nonce folded into KR (KR moves); an AT nonce that does not enter
/// AR; AR hashing anything but KR and the nonce; an insertion-order
/// dependent AR. End to end: yes (live principal, create, create, delete).
#[test]
fn at_nonce_is_hashed_with_the_key_root_into_the_auth_root() {
    let (n1, n2) = (nonce_bytes(3), nonce_bytes(4));
    let (mut p, g, _) = base();
    let pre = roots(&p);
    let kr = sha256_bytes(p.key_root().expect("a live principal has a KR"));

    let r = commit_one(&mut p, &g, create(Level::At, &g, &n1, T + 10), None, T + 10);
    assert!(r.is_ok(), "AT nonce/create was refused: {r:?}");
    assert_eq!(roots(&p).kr, pre.kr, "an AT nonce reached KR");
    let ar = sha256_bytes(p.auth_root().expect("a live principal has an AR"));
    assert!(
        ar == sha256_of_concat(&[&kr, &n1]) || ar == sha256_of_concat(&[&n1, &kr]),
        "AR is not the hash of KR and the nonce"
    );
    assert_eq!(
        p.sr().expect("sr").as_multihash(),
        p.auth_root()
            .expect("a live principal has an AR")
            .as_multihash(),
        "SR promotes AR"
    );

    let r = commit_one(&mut p, &g, create(Level::At, &g, &n2, T + 11), None, T + 11);
    assert!(r.is_ok(), "a second AT nonce was refused: {r:?}");
    let two = roots(&p);
    assert_eq!(two.kr, pre.kr, "a second AT nonce reached KR");
    assert_ne!(
        two.ar, pre.ar,
        "two AT nonces left AR at its pre-nonce value"
    );

    let (mut q, g2, _) = base();
    commit_one(
        &mut q,
        &g2,
        create(Level::At, &g2, &n2, T + 10),
        None,
        T + 10,
    )
    .expect("reordered first nonce");
    commit_one(
        &mut q,
        &g2,
        create(Level::At, &g2, &n1, T + 11),
        None,
        T + 11,
    )
    .expect("reordered second nonce");
    assert_eq!(roots(&q), two, "the AT nonce set is order-dependent");

    for (n, now) in [(&n1, T + 20), (&n2, T + 21)] {
        let r = commit_one(&mut p, &g, delete(Level::At, &g, n, now), None, now);
        assert!(r.is_ok(), "AT nonce/delete was refused: {r:?}");
    }
    assert_eq!(
        roots(&p),
        pre,
        "deleting every AT nonce must restore the roots"
    );
}

/// Backs 10.1: `nonce/delete` removes "the nonce" whose `id` it names at
/// the path it names, and only that. Scenario: a nonce is created at AT;
/// a delete naming it at the KT path, at the PR path, a delete of a value
/// never created at the AT path, and a delete of a different value at AT
/// are each refused and leave every root untouched; control: the matching
/// delete at AT is accepted, so the refusals are the path/value mismatch.
/// Turns red on: a delete that matches by value alone or by suffix `nonce/delete`
/// (path-blind); a delete accepted for an absent nonce; a delete that
/// removes some nonce rather than the named one. The refusal of an
/// absent-nonce delete is the narrowest reading (mirrors `key/delete` of an
/// unknown key); 10.1 does not say (SPEC ambiguity, node report). End to end:
/// yes.
// @docket: rv-nonce-ledger :: scripts/docket-run rv-nonce-ledger
#[test]
fn nonce_delete_removes_only_the_named_nonce_at_the_named_path() {
    let (n, never) = (nonce_bytes(5), nonce_bytes(6));
    let (mut p, g, _) = base();
    let r = commit_one(&mut p, &g, create(Level::At, &g, &n, T + 10), None, T + 10);
    assert!(r.is_ok(), "AT nonce/create was refused: {r:?}");
    let armed = roots(&p);
    let commits = p.commits().count();

    let refusals = [
        ("delete at the KT path", delete(Level::Kt, &g, &n, T + 20)),
        ("delete at the PR path", delete(Level::Pr, &g, &n, T + 21)),
        (
            "delete of a never-created value",
            delete(Level::At, &g, &never, T + 22),
        ),
    ];
    let mut accepted = vec![];
    for (what, parts) in refusals {
        let now = parts_now(&parts);
        if commit_one(&mut p, &g, parts, None, now).is_ok() {
            accepted.push(what);
        }
    }
    assert!(accepted.is_empty(), "wrongly accepted: {accepted:?}");
    assert_eq!(roots(&p), armed, "a refused delete moved a root");
    assert_eq!(p.commits().count(), commits, "a refused delete finalized");

    let r = commit_one(&mut p, &g, delete(Level::At, &g, &n, T + 30), None, T + 30);
    assert!(r.is_ok(), "control: the matching delete was refused: {r:?}");
}

/// Backs the nonce set at one level (SPEC 7.6, 10.1): a nonce created twice
/// at one level is refused and leaves every root and the commit count as
/// they were, while the same value at another level is a separate nonce.
/// Turns red if a repeat create is accepted (the set becomes a multiset and
/// one delete no longer removes the nonce) or if levels share one set. End
/// to end: yes. Controls: the first create and the other-level create are
/// accepted.
// @docket: rv-nonce-ledger :: scripts/docket-run rv-nonce-ledger
#[test]
fn nonce_created_twice_at_one_level_is_refused() {
    let n = nonce_bytes(9);
    let (mut p, g, _) = base();
    let r = commit_one(&mut p, &g, create(Level::Kt, &g, &n, T + 10), None, T + 10);
    assert!(r.is_ok(), "control: first KT create was refused: {r:?}");
    let armed = roots(&p);
    let commits = p.commits().count();

    let r = commit_one(&mut p, &g, create(Level::Kt, &g, &n, T + 11), None, T + 11);
    assert!(r.is_err(), "a repeat KT create was accepted");
    assert_eq!(roots(&p), armed, "a refused create moved a root");
    assert_eq!(p.commits().count(), commits, "a refused create finalized");

    let r = commit_one(&mut p, &g, create(Level::At, &g, &n, T + 12), None, T + 12);
    assert!(
        r.is_ok(),
        "control: the same value at AT was refused: {r:?}"
    );
}

/// The signed `now` of a pre-built coz, so a loop can finalize at it.
fn parts_now(parts: &Signed) -> i64 {
    serde_json::from_slice::<serde_json::Value>(&parts.0).expect("pay json")["now"]
        .as_i64()
        .expect("now")
}

/// Backs the Non-Goal "no meaning is read from a nonce; it only changes
/// digests" (10.2: indistinguishable from a key thumbprint). Scenario: a KT
/// nonce whose value is the thumbprint of a key that is not in the
/// principal; that key does not become active and cannot admit another key
/// with its signature. Control: the same nonce is accepted. Turns red if
/// `nonce/create` is handled as `key/create` (the key activates) or if the
/// nonce `id` is looked up as a thumbprint (the create is refused as an
/// unknown key). End to end: yes.
#[test]
fn nonce_is_opaque_even_when_it_looks_like_a_thumbprint() {
    let (mut p, g, _) = base();
    let stranger = pool_key("alice");
    let before = roots(&p);
    let r = commit_one(
        &mut p,
        &g,
        create(Level::Kt, &g, stranger.tmb.as_bytes(), T + 10),
        None,
        T + 10,
    );
    assert!(r.is_ok(), "a thumbprint-shaped nonce was refused: {r:?}");
    assert_eq!(p.active_key_count(), before.keys, "a nonce became a key");
    assert!(!p.is_key_active(&stranger.tmb), "the nonce activated a key");
    assert_ne!(roots(&p).kr, before.kr, "control: the nonce still moves KR");

    let third = pool_key("bob");
    let r = commit_one(
        &mut p,
        &stranger,
        key_create(&stranger, &third, T + 11),
        Some(key_of(&third)),
        T + 11,
    );
    assert!(r.is_err(), "the nonce's lookalike key signed a commit");
}

/// Backs 11.2 / 2.3.2 for nonces: "No mutations until unfrozen". A nonce
/// create and a nonce delete are mutations of PT. Scenario: a frozen
/// principal refuses `nonce/create` (every level) and the delete of a
/// nonce created before the freeze; after `freeze/delete` the same
/// creates are accepted (so the refusals are the freeze). Turns red if a
/// nonce kind bypasses the frozen gate (its `frozen_exempt` match), or if a
/// nonce is refused after the thaw. End to end: yes.
#[test]
fn frozen_principal_refuses_nonce_mutations_until_thawed() {
    let (n_old, n_new) = (nonce_bytes(7), nonce_bytes(8));
    let (mut p, g, _) = base();
    let r = commit_one(
        &mut p,
        &g,
        create(Level::Kt, &g, &n_old, T + 10),
        None,
        T + 10,
    );
    assert!(r.is_ok(), "pre-freeze nonce/create was refused: {r:?}");
    let lifecycle = |p: &Principal, suffix: &str, now: i64| {
        sign(
            &g,
            json!({"alg": g.alg, "id": p.pr_tagged().expect("pr"), "now": now,
                   "tmb": b64(&g.tmb), "typ": format!("cyphr.me/cyphr/{suffix}")}),
        )
    };
    let f = lifecycle(&p, "freeze/create", T + 20);
    commit_one(&mut p, &g, f, None, T + 21).expect("premise: freeze/create applies");
    assert!(p.is_frozen(), "premise: frozen");
    let frozen = roots(&p);

    let mut accepted = vec![];
    for (i, level) in [Level::Pr, Level::At, Level::Kt].into_iter().enumerate() {
        let now = T + 30 + i as i64;
        let n = nonce_bytes(20 + i as u8);
        if commit_one(&mut p, &g, create(level, &g, &n, now), None, now).is_ok() {
            accepted.push(format!("{level:?} create"));
        }
    }
    let now = T + 40;
    if commit_one(&mut p, &g, delete(Level::Kt, &g, &n_old, now), None, now).is_ok() {
        accepted.push("KT delete".to_string());
    }
    assert!(
        accepted.is_empty(),
        "a frozen principal accepted {accepted:?}"
    );
    assert_eq!(roots(&p), frozen, "a refused nonce moved a root");

    let thaw = lifecycle(&p, "freeze/delete", T + 50);
    commit_one(&mut p, &g, thaw, None, T + 51).expect("premise: freeze/delete thaws");
    let r = commit_one(
        &mut p,
        &g,
        create(Level::Kt, &g, &n_new, T + 60),
        None,
        T + 60,
    );
    assert!(
        r.is_ok(),
        "control: a thawed principal refused a nonce: {r:?}"
    );
}

// ============================================================================
// Dead principal: the nonces that remain (SPEC 3.7, 10.2)
// ============================================================================

/// Backs SPEC 3.7 and 10.2: revoking or deleting the last key removes no
/// nonce (only `nonce/delete` does), and an empty component is omitted, so
/// the roots of a principal with no key are derived from the nonces that
/// remain and a lone nonce is promoted. Scenarios, each ending with the
/// only key's removal (revoke, then delete in the last): (a) a KT nonce
/// only: KR is that nonce and AR and SR promote it; (b) an AT nonce only:
/// no KT, so KR is absent, AR is the nonce and SR promotes it; (c) both: KR
/// is the KT nonce and AR = H(KR || AT nonce) (3.7.4, AR cells are KR then
/// nonces). Turns red if the dying commit drops the nonces (KR/AR absent,
/// or KR/AR of a keyless principal derived from nothing), if a lone nonce
/// is hashed instead of promoted, or if the AT nonce is placed after an
/// absent KR slot. End to end: yes.
#[test]
fn dead_principal_roots_keep_the_nonces_that_remain() {
    let (n_kt, n_at) = (nonce_bytes(11), nonce_bytes(12));
    let revoke = |g: &Kp, now: i64| {
        sign(
            g,
            json!({"alg": g.alg, "now": now, "rvk": now, "tmb": b64(&g.tmb),
                   "typ": "cyphr.me/cyphr/key/revoke"}),
        )
    };
    let delete_self = |g: &Kp, now: i64| {
        sign(
            g,
            json!({"alg": g.alg, "id": b64(&g.tmb), "now": now, "tmb": b64(&g.tmb),
                   "typ": "cyphr.me/cyphr/key/delete"}),
        )
    };
    type Die = Box<dyn Fn(&Kp, i64) -> Signed>;
    let ways: [(&str, Die); 2] = [
        ("revoke", Box::new(revoke)),
        ("delete", Box::new(delete_self)),
    ];
    for (way, die) in ways {
        for (kt, at) in [(true, false), (false, true), (true, true)] {
            let g = pool_key("golden");
            let mut p = genesis_of(Principal::implicit(key_of(&g)).expect("genesis"), &g);
            let mut now = T;
            if kt {
                commit_one(&mut p, &g, create(Level::Kt, &g, &n_kt, now), None, now)
                    .expect("KT nonce");
                now += 1;
            }
            if at {
                commit_one(&mut p, &g, create(Level::At, &g, &n_at, now), None, now)
                    .expect("AT nonce");
                now += 1;
            }
            let r = commit_one(&mut p, &g, die(&g, now), None, now + 1);
            assert!(r.is_ok(), "{way} of the last key (kt={kt} at={at}): {r:?}");
            assert_eq!(p.active_key_count(), 0);

            let want_kr: Option<Vec<u8>> = kt.then(|| n_kt.to_vec());
            let want_ar: Vec<u8> = match (kt, at) {
                (true, false) => n_kt.to_vec(),
                (false, true) => n_at.to_vec(),
                (true, true) => sha256_of_concat(&[&n_kt, &n_at]),
                (false, false) => unreachable!("covered by the nonce-free Dead tests"),
            };
            let case = format!("{way} kt={kt} at={at}");
            assert_eq!(p.key_root().map(sha256_bytes), want_kr, "{case}: KR");
            assert_eq!(
                p.auth_root().map(sha256_bytes),
                Some(want_ar.clone()),
                "{case}: AR"
            );
            assert_eq!(
                p.sr().map(sha256_bytes),
                Some(want_ar),
                "{case}: SR (no DR)"
            );
        }
    }
}
