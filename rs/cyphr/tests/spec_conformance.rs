//! SPEC conformance (SC1): every normative `must` / `must not` / `never` on
//! the Levels 1-4 security path of SPEC.md (zami `be0663f`, sections 2-12,
//! 15.2, 15.8) maps to a test that fails when it breaks. The map is
//! `docs/architecture/spec-conformance.md`; this file holds the tests that
//! had no existing home, plus the map's own consistency tests (`map_*`).
//!
//! Every scenario test states the SPEC sentence it backs, the defect that
//! turns it red, and whether it is end to end. A test marked
//! `RED(<tracking id>)` is ignored on purpose: it fails today for the stated
//! behavioural defect and goes green when the named fix lands.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::{Error, Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let k = coz::Alg::Ed25519.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

fn key_of(k: &Kp) -> Key {
    Key {
        alg: k.alg.clone(),
        tmb: k.tmb.clone(),
        pub_key: k.pubb.clone(),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn b64(t: &coz::Thumbprint) -> String {
    Base64UrlUnpadded::encode_string(t.as_bytes())
}

type Signed = (Vec<u8>, Vec<u8>, coz::Czd);

/// Sign `pay` (keys sorted) with `k`.
fn sign(k: &Kp, mut pay: serde_json::Value) -> Signed {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

fn key_create_pay(signer: &Kp, id: &coz::Thumbprint, now: i64) -> serde_json::Value {
    json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
           "typ": "cyphr.me/cyphr/key/create"})
}

fn key_delete_pay(signer: &Kp, id: &coz::Thumbprint, now: i64) -> serde_json::Value {
    json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
           "typ": "cyphr.me/cyphr/key/delete"})
}

fn revoke_pay(k: &Kp, now: i64, rvk: serde_json::Value) -> serde_json::Value {
    json!({"alg": k.alg, "now": now, "rvk": rvk, "tmb": b64(&k.tmb),
           "typ": "cyphr.me/cyphr/key/revoke"})
}

/// Observable principal state: a rejected operation must leave all of it
/// untouched.
fn snapshot(p: &Principal) -> (cyphr::PrincipalRoot, usize, usize, usize) {
    (
        p.pr().clone(),
        p.active_key_count(),
        p.action_count(),
        p.commits().count(),
    )
}

fn software(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// One finalized commit by `signer` applying a single signed coz plus an
/// optional sidecar key.
fn commit_one(
    p: &mut Principal,
    signer: &Kp,
    coz_parts: Signed,
    sidecar: Option<Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let (pay, sig, czd) = coz_parts;
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, sidecar)?;
    scope
        .finalize_with_software(&software(signer), now, "cyphr.me")
        .map(|_| ())
}

/// Two-key principal `{a, b}` (explicit genesis), the shape every
/// lifecycle and revoke scenario below starts from.
fn two_key_principal() -> (Principal, Kp, Kp) {
    let (a, b) = (kp(), kp());
    let p = Principal::explicit(vec![key_of(&a), key_of(&b)]).expect("explicit genesis");
    (p, a, b)
}

// ============================================================================
// SPEC 2.3.1 (line 226): all cozies must have alg, tmb, now, typ
// ============================================================================

/// Apply a `key/create` missing exactly `missing`; `Ok` means it was
/// accepted and finalized.
fn create_missing_field(missing: &str) -> cyphr::error::Result<()> {
    let (g, k2) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&g)).expect("genesis");
    let before = snapshot(&p);
    let mut pay = key_create_pay(&g, &k2.tmb, T);
    pay.as_object_mut().expect("object").remove(missing);
    let r = commit_one(&mut p, &g, sign(&g, pay), Some(key_of(&k2)), T + 1);
    if r.is_err() {
        assert_eq!(
            before,
            snapshot(&p),
            "rejected coz (no {missing}) changed state"
        );
    }
    r
}

/// Backs SPEC 2.3.1: "All cozies must have the fields: `alg`, `tmb`, `now`,
/// `typ`". Scenario: a validly signed `key/create` omitting `tmb`, `now` or
/// `typ` is rejected and leaves the principal untouched; the complete coz is
/// the control that shows the rejections are about the missing field. Turns
/// red if a missing field is tolerated (a default substituted, or the field
/// never read). End to end: yes (sign, verify, apply, finalize).
#[test]
fn s2_3_1_coz_missing_tmb_now_or_typ_is_rejected() {
    for missing in ["tmb", "now", "typ"] {
        assert!(
            create_missing_field(missing).is_err(),
            "a coz without `{missing}` was accepted and finalized"
        );
    }
    let (g, k2) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T)),
        Some(key_of(&k2)),
        T + 1,
    )
    .expect("control: the complete coz is accepted");
}

/// Backs SPEC 2.3.1 for `alg`. RED: `verify_coz` never reads `pay.alg` (it
/// verifies under the stored key's algorithm), so a coz with no `alg` is
/// accepted. Turns green when KA1's `pay.alg == key.alg` check treats an
/// absent `alg` as a mismatch. End to end: yes.
#[test]
#[ignore = "RED(KA1): SPEC 2.3.1 absent pay.alg accepted"]
fn s2_3_1_coz_missing_alg_is_rejected() {
    assert!(
        create_missing_field("alg").is_err(),
        "a coz without `alg` was accepted and finalized"
    );
}

// ============================================================================
// SPEC 2.3.2 (line 246): antecedent authorization gate
// ============================================================================

/// Backs SPEC 2.3.2: "Every authentication component required to apply an
/// action (keys, rules) must already be active before the transaction is
/// applied." Scenario: an outsider key that is not in the principal signs a
/// `key/create` adding itself; the coz carries a genuine signature, so the
/// only thing standing between it and the principal is the gate. Turns red
/// if a key that is not yet active can authorize its own admission. End to
/// end: yes.
// @docket: sc-l246 :: scripts/docket-run sc-l246
#[test]
fn s2_3_2_inactive_key_cannot_authorize_its_own_admission() {
    let (mut p, a, _b) = two_key_principal();
    let outsider = kp();
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &outsider,
        sign(&outsider, key_create_pay(&outsider, &outsider.tmb, T)),
        Some(key_of(&outsider)),
        T + 1,
    );
    assert!(
        matches!(r, Err(Error::UnknownKey)),
        "an inactive key authorized itself: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a rejected admission changed state");
    assert!(!p.is_key_active(&outsider.tmb));
    commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &outsider.tmb, T + 2)),
        Some(key_of(&outsider)),
        T + 3,
    )
    .expect("control: an active key may admit the same key");
    assert!(p.is_key_active(&outsider.tmb));
}

// ============================================================================
// SPEC 2.3.2 / 11.2: a frozen principal rejects mutations
// ============================================================================

fn lifecycle_pay(signer: &Kp, p: &Principal, suffix: &str, now: i64) -> serde_json::Value {
    json!({"alg": signer.alg, "id": p.pr_tagged().expect("pr"), "now": now,
           "tmb": b64(&signer.tmb), "typ": format!("cyphr.me/cyphr/{suffix}")})
}

/// Backs SPEC 2.3.2 ("a frozen principal rejects mutations") and 11.2
/// ("Frozen ... No mutations until unfrozen"). Scenario: a two-key principal
/// signs `freeze/create`; then each key mutation (`key/create`, `key/delete`,
/// a self-`key/revoke`) is attempted by an active key. Control: after
/// `freeze/delete` the same `key/create` is accepted, so the rejections are
/// the freeze, not a general refusal. Turns red if any mutation changes the
/// principal while it is frozen. RED: `apply_verified_internal` gates only
/// `deleted`; `frozen` is recorded and never consulted. End to end: yes.
#[test]
#[ignore = "RED(SC1-F1): SPEC 2.3.2 frozen principal accepts mutations"]
fn s11_2_frozen_principal_rejects_key_mutations() {
    let frozen = || {
        let (mut p, a, b) = two_key_principal();
        let f = sign(&a, lifecycle_pay(&a, &p, "freeze/create", T));
        commit_one(&mut p, &a, f, None, T + 1).expect("premise: freeze/create applies");
        assert!(p.is_frozen(), "premise: principal is frozen");
        (p, a, b)
    };

    let mut accepted = vec![];
    let (mut p, a, _) = frozen();
    let k3 = kp();
    if commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T + 2)),
        Some(key_of(&k3)),
        T + 3,
    )
    .is_ok()
    {
        accepted.push("key/create");
    }
    let (mut p, a, b) = frozen();
    if commit_one(
        &mut p,
        &a,
        sign(&a, key_delete_pay(&a, &b.tmb, T + 2)),
        None,
        T + 3,
    )
    .is_ok()
    {
        accepted.push("key/delete");
    }
    let (mut p, _, b) = frozen();
    if commit_one(
        &mut p,
        &b,
        sign(&b, revoke_pay(&b, T + 2, json!(T + 2))),
        None,
        T + 3,
    )
    .is_ok()
    {
        accepted.push("key/revoke");
    }
    assert!(
        accepted.is_empty(),
        "a frozen principal accepted and finalized: {accepted:?}"
    );

    let (mut p, a, _) = frozen();
    let thaw = sign(&a, lifecycle_pay(&a, &p, "freeze/delete", T + 2));
    commit_one(&mut p, &a, thaw, None, T + 3).expect("control: freeze/delete thaws");
    let k3 = kp();
    commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T + 4)),
        Some(key_of(&k3)),
        T + 5,
    )
    .expect("control: key/create is accepted once thawed");
}

// ============================================================================
// SPEC 6.4 (lines 1067, 1069): rvk and now bounds
// ============================================================================

/// Apply `pay_for(b)` signed by `b` on a fresh two-key principal (the pay is
/// built from the principal's own key, so a rejection cannot be the
/// signer simply being unknown).
fn revoke_outcome(pay_for: impl Fn(&Kp) -> serde_json::Value) -> cyphr::error::Result<()> {
    let (mut p, _a, b) = two_key_principal();
    let before = snapshot(&p);
    let r = commit_one(&mut p, &b, sign(&b, pay_for(&b)), None, T + 1);
    if r.is_err() {
        assert_eq!(before, snapshot(&p), "a rejected revoke changed state");
    }
    r
}

/// Backs SPEC 6.4: "`rvk` and `now` must be a positive integer less than
/// 2^53 - 1 ... Revoke checks must error if `rvk` is not an integer or
/// larger than 2^53 - 1." Scenario: a self-revoke signed by an active key
/// carries each out-of-range `rvk` (zero, negative, 2^53, a fraction, a
/// string); every one must be rejected, while `rvk = 1` (the value the SPEC
/// calls suitable) is the control. Turns red if an out-of-range `rvk` revokes
/// the key. The exact bound 2^53 - 1 is not exercised: the two sentences
/// disagree on whether it is in range (a question for the spec author).
/// RED: in-commit `key/revoke` parses `rvk` as any `i64` and never bounds
/// it (the naked-revoke path in the server does). End to end: yes.
#[test]
#[ignore = "RED(SC1-F2): SPEC 6.4 in-commit rvk unbounded"]
fn s6_4_revoke_rvk_must_be_a_positive_bounded_integer() {
    let cases = [
        ("zero", json!(0)),
        ("negative", json!(-1)),
        ("2^53", json!(9_007_199_254_740_992_i64)),
        ("fraction", json!(1.5)),
        ("string", json!("1")),
    ];
    let mut accepted = vec![];
    for (label, rvk) in cases {
        if revoke_outcome(|b| revoke_pay(b, T, rvk.clone())).is_ok() {
            accepted.push(label);
        }
    }
    assert!(
        accepted.is_empty(),
        "key/revoke accepted out-of-range rvk: {accepted:?}"
    );
    revoke_outcome(|b| revoke_pay(b, T, json!(1))).expect("control: rvk = 1 is accepted");
}

/// Backs SPEC 6.4: "`rvk` and `now` must be a positive integer less than
/// 2^53 - 1." for `now`. Scenario: a self-revoke with a valid `rvk` and each
/// out-of-range `now` (zero, negative, 2^53) must be rejected; `now = T` is
/// the control. Turns red if an out-of-range `now` is accepted. RED: `now`
/// is read as any `i64` and only compared with the principal's latest
/// timestamp, so zero and 2^53 pass. End to end: yes.
#[test]
#[ignore = "RED(SC1-F2): SPEC 6.4 now unbounded"]
fn s6_4_revoke_now_must_be_a_positive_bounded_integer() {
    let mut accepted = vec![];
    for (label, now) in [
        ("zero", 0_i64),
        ("negative", -1),
        ("2^53", 9_007_199_254_740_992),
    ] {
        if revoke_outcome(|b| revoke_pay(b, now, json!(1))).is_ok() {
            accepted.push(label);
        }
    }
    assert!(
        accepted.is_empty(),
        "key/revoke accepted out-of-range now: {accepted:?}"
    );
    revoke_outcome(|b| revoke_pay(b, T, json!(1))).expect("control: now = T is accepted");
}

// ============================================================================
// SPEC 6.4 (line 1059): the revoke must be signed by the revoked key itself
// ============================================================================

/// Backs SPEC 6.4: "the key signing a revoke message must be the key
/// itself." Scenario: active key `b` signs (1) a `key/revoke` that names key
/// `a` through `id`, and (2) a `key/revoke` whose `tmb` claims to be `a`.
/// Both must be rejected and `a` must stay active. Turns red if one key can
/// revoke another. End to end: yes.
// @docket: sc-l1059 :: scripts/docket-run sc-l1059
#[test]
fn s6_4_one_key_cannot_revoke_another() {
    let (mut p, a, b) = two_key_principal();
    let before = snapshot(&p);

    let mut names_a = revoke_pay(&b, T, json!(T));
    names_a["id"] = json!(b64(&a.tmb));
    let r1 = commit_one(&mut p, &b, sign(&b, names_a), None, T + 1);
    assert!(r1.is_err(), "b revoked a through `id`: {r1:?}");

    let claims_a = revoke_pay(&a, T, json!(T));
    let r2 = commit_one(&mut p, &b, sign(&b, claims_a), None, T + 1);
    assert!(
        r2.is_err(),
        "b's signature was accepted as a's revoke: {r2:?}"
    );

    assert_eq!(
        before,
        snapshot(&p),
        "a rejected cross-key revoke changed state"
    );
    assert!(
        p.is_key_active(&a.tmb) && !p.is_key_revoked(&a.tmb),
        "a was revoked"
    );
}

// ============================================================================
// SPEC 4.6.2 (line 592): the commit transaction must be last
// ============================================================================

/// Backs SPEC 4.6.2: "Commit transaction must be last." Scenario: a commit
/// whose `commit/create` coz is first and a `key/create` follows it. Turns
/// red if the finalizer is accepted anywhere but last. End to end: yes
/// (verify, apply, finalize through the public scope).
// @docket: sc-l592 :: scripts/docket-run sc-l592
#[test]
fn s4_6_commit_coz_must_be_last_in_txs() {
    let (g, k2) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&g)).expect("genesis");
    let before = snapshot(&p);
    let arrow = format!("SHA-512:{}", Base64UrlUnpadded::encode_string(&[7u8; 64]));
    let finalizer = sign(
        &g,
        json!({"alg": g.alg, "arrow": arrow, "now": T, "tmb": b64(&g.tmb),
               "typ": "cyphr.me/cyphr/commit/create"}),
    );
    let mut scope = p.begin_commit();
    let (pay, sig, czd) = finalizer;
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("finalizer coz applies");
    let (pay, sig, czd) = sign(&g, key_create_pay(&g, &k2.tmb, T));
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(&k2)))
        .expect("key/create applies");
    let r = scope.finalize().map(|_| ());
    assert!(
        matches!(r, Err(Error::CommitNotLast)),
        "a commit with its finalizer first was not rejected as CommitNotLast: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a rejected commit changed state");
}

// ============================================================================
// SPEC 2.2.13 (line 203): public keys must be revealed for verification
// ============================================================================

/// Backs SPEC 2.2.13: "Public keys must be revealed for verification". The
/// `pub` travels in an unsigned sidecar; a `key/create` whose new key is
/// never revealed has nothing to verify its later signatures against.
/// Scenario: `key/create` with no sidecar is rejected and the thumbprint
/// does not become active. Turns red if a key is admitted by thumbprint
/// alone. End to end: yes.
// @docket: sc-l203 :: scripts/docket-run sc-l203
#[test]
fn s2_2_13_key_create_without_revealed_pub_is_rejected() {
    let (g, k2) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&g)).expect("genesis");
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T)),
        None,
        T + 1,
    );
    assert!(
        r.is_err(),
        "key/create without a revealed pub was accepted: {r:?}"
    );
    assert_eq!(before, snapshot(&p));
    assert!(!p.is_key_active(&k2.tmb));
}

// ============================================================================
// SPEC 2.3.2 (line 237): commits are append-only; implicit forks prohibited
// ============================================================================

/// One commit by `signer` adding `new`; returns the commit's cozies as a
/// peer would receive them (coz bytes, signature, czd) and the sidecar key.
fn add_key_commit(p: &mut Principal, signer: &Kp, new: &Kp, now: i64) -> Vec<Signed> {
    commit_one(
        p,
        signer,
        sign(signer, key_create_pay(signer, &new.tmb, now)),
        Some(key_of(new)),
        now + 1,
    )
    .expect("honest commit builds");
    p.commits()
        .last()
        .expect("commit recorded")
        .all_cozies()
        .iter()
        .map(|vc| {
            let raw = vc.raw();
            (
                serde_json::to_vec(&raw.pay).expect("pay"),
                raw.sig.clone(),
                vc.czd().clone(),
            )
        })
        .collect()
}

/// Backs SPEC 2.3.2: "Commits are never removed from the chain and implicit
/// forks are prohibited by the protocol." Scenario: from one ancestor, two
/// fully authorized commits branch (A adds key k3, B adds key k4, both
/// signed by the same active key, so authorization cannot be why B fails). A
/// replayer that has applied A must reject B, because B's `arrow` commits to
/// the ancestor's PR as `pre`, not to A's. Turns red if a second commit on a
/// stale `pre` is appended to a chain that has already advanced. End to end:
/// yes (two peers, one replay).
// @docket: sc-l237 :: scripts/docket-run sc-l237
// @docket: sc-l2827 :: scripts/docket-run sc-l2827
// @docket: sc-l2828 :: scripts/docket-run sc-l2828
#[test]
fn s2_3_2_second_commit_on_a_stale_pre_is_rejected() {
    let (a, b) = (kp(), kp());
    let (k3, k4) = (kp(), kp());
    let ancestor = || Principal::explicit(vec![key_of(&a), key_of(&b)]).expect("ancestor");

    let wire_a = add_key_commit(&mut ancestor(), &a, &k3, T);
    let wire_b = add_key_commit(&mut ancestor(), &a, &k4, T + 10);

    let replay = |p: &mut Principal, wire: &[Signed], new: &Kp| -> cyphr::error::Result<()> {
        let mut scope = p.begin_commit();
        for (i, (pay, sig, czd)) in wire.iter().enumerate() {
            let sidecar = (i == 0).then(|| key_of(new));
            scope.verify_and_apply(pay, sig, czd.clone(), sidecar)?;
        }
        scope.finalize().map(|_| ())
    };

    let mut linear = ancestor();
    replay(&mut linear, &wire_a, &k3).expect("control: branch A applies on the ancestor");
    let before = snapshot(&linear);
    let r = replay(&mut linear, &wire_b, &k4);
    assert!(
        matches!(r, Err(Error::CommitMismatch)),
        "branch B must fail on its arrow (stale pre), got {r:?}"
    );
    assert_eq!(
        before,
        snapshot(&linear),
        "a rejected fork commit changed state"
    );
    assert!(
        !linear.is_key_active(&k4.tmb),
        "the abandoned branch's key became active"
    );

    replay(&mut ancestor(), &wire_b, &k4)
        .expect("control: branch B is valid on its own ancestor, so the rejection is the pre");
}

// ============================================================================
// SPEC 4 (line 463): the Merkle tree primitive must support n-arity
// ============================================================================

/// Backs SPEC 4 ("Merkle tree primitive must support n-arity"): the Key Tree
/// is a Merkle tree, so a principal must be able to hold more keys than a
/// fixed fan-out. Scenario: explicit genesis of 257 distinct keys. Control:
/// 256 keys build. Turns red if the tree refuses a key set the SPEC does not
/// bound. RED: the collection node is capped at 256 children and returns
/// `CollectionArityExceeded` (`error.rs` records it as a known, deferred
/// gap). End to end: no; a unit-level boundary, because no scenario reaches
/// 257 keys more cheaply.
#[test]
#[ignore = "RED(SC1-F3): SPEC 4 KT capped at 256 children"]
fn s4_key_tree_supports_more_than_256_keys() {
    let keys = |n: usize| -> Vec<Key> { (0..n).map(|_| key_of(&kp())).collect() };
    Principal::explicit(keys(256)).expect("control: 256 keys build");
    let r = Principal::explicit(keys(257));
    assert!(r.is_ok(), "257 keys refused: {:?}", r.err());
}

// ============================================================================
// The map: docs/architecture/spec-conformance.md
// ============================================================================
//
// Claim: every security-path requirement of the SPEC is accounted for, every
// row names tests that exist, and a row's disposition agrees with the
// ignore-state of its tests. These are consistency tests over the map, not
// scenarios (a unit-level check is all a document can have).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

/// The SPEC commit the map is written against (the spec author's `zami`
/// branch; AGENTS.md I3).
const SPEC_COMMIT: &str = "be0663f";
const CORE_FILE: &str = "rs/cyphr/tests/spec_conformance.rs";
const SERVER_FILE: &str = "rs/cyphr-server/tests/spec_conformance.rs";
const DISPOSITIONS: [&str; 5] = [
    "covered",
    "red-existing",
    "red-new",
    "not-testable",
    "out-of-scope",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repository root")
        .to_path_buf()
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[derive(Debug)]
struct Row {
    line: usize,
    source: String,
    disposition: String,
    spec_text: String,
    tests: Vec<String>,
}

fn parse_map() -> (Vec<Row>, BTreeMap<String, usize>) {
    let doc = read_repo("docs/architecture/spec-conformance.md");
    let mut rows = vec![];
    let mut summary = BTreeMap::new();
    let mut cur: Option<(String, Vec<&str>)> = None;
    let mut blocks = vec![];
    for l in doc.lines() {
        if let Some(rest) = l.strip_prefix("### [") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some((rest.trim_end_matches(']').to_string(), vec![]));
        } else if l.starts_with("## ") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
        } else if let Some((_, body)) = cur.as_mut() {
            body.push(l);
        } else if let Some(cells) = l.strip_prefix("| `") {
            let mut it = cells.split('|').map(str::trim);
            if let (Some(d), Some(n)) = (it.next(), it.next()) {
                if let Ok(n) = n.parse::<usize>() {
                    summary.insert(d.trim_end_matches('`').to_string(), n);
                }
            }
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    for (id, body) in blocks {
        let field = |k: &str| {
            body.iter()
                .find_map(|l| l.strip_prefix(&format!("- {k}: ")))
                .unwrap_or_else(|| panic!("row {id}: missing `- {k}:`"))
                .trim()
                .to_string()
        };
        let line: usize = field("spec-line").parse().expect("spec-line is a number");
        assert_eq!(id, format!("sc-l{line}"), "row id must be sc-l<spec-line>");
        let mut tests = vec![];
        let mut in_tests = false;
        for l in &body {
            if l.starts_with("- tests:") {
                in_tests = true;
            } else if in_tests {
                match l.strip_prefix("  - `") {
                    Some(t) => tests.push(t.trim_end_matches('`').to_string()),
                    None => in_tests = false,
                }
            }
        }
        rows.push(Row {
            line,
            source: field("source"),
            disposition: field("disposition"),
            spec_text: field("spec-text"),
            tests,
        });
    }
    (rows, summary)
}

/// The extraction rule, shared by the map's prose and `map_has_one_row_*`:
/// a line is a requirement when it holds `must`, `shall` or `never`
/// (lowercase) or `MUST` / `SHALL` as a whole word.
fn is_requirement_line(l: &str) -> bool {
    l.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| matches!(w, "must" | "shall" | "never" | "MUST" | "SHALL"))
}

/// 1-based line numbers of the in-scope requirement lines of `spec`:
/// sections 2-12 (up to `# Extended`), 15.2 and 15.8.
fn spec_requirement_lines(spec: &str) -> BTreeMap<usize, String> {
    let lines: Vec<&str> = spec.lines().collect();
    let at = |prefix: &str, from: usize| {
        (from..lines.len())
            .find(|&i| lines[i].starts_with(prefix))
            .unwrap_or_else(|| panic!("SPEC has no line starting {prefix:?}"))
    };
    let s2 = at("## 2. ", 0);
    let extended = at("# Extended", s2);
    let s152 = at("### 15.2 ", extended);
    let s152_end = at("### ", s152 + 1);
    let s158 = at("#### 15.8 ", s152_end);
    let s158_end = at("### ", s158 + 1);
    let mut out = BTreeMap::new();
    for (lo, hi) in [(s2, extended), (s152, s152_end), (s158, s158_end)] {
        for (i, l) in lines.iter().enumerate().take(hi).skip(lo) {
            if is_requirement_line(l) {
                out.insert(i + 1, l.trim().to_string());
            }
        }
    }
    out
}

/// The formatter that owns the map collapses runs of spaces; compare modulo
/// whitespace runs.
fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Backs the map's completeness. Scenario: re-extract the in-scope
/// requirement sentences from the SPEC at `SPEC_COMMIT` by the stated rule
/// and require exactly one `rule` row for each, none extra; every
/// `supplement` row's quote must sit on its line and must not already be a
/// rule line. Turns red if a requirement sentence has no row, a row has no
/// sentence, or a quote drifted from its line. The SPEC commit lives on the
/// `zami` branch and is absent from shallow clones: without it the test
/// reports that and stops, unless `SC1_REQUIRE_SPEC` is set, which turns the
/// absence into a failure.
#[test]
fn map_has_one_row_per_spec_requirement() {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .arg("show")
        .arg(format!("{SPEC_COMMIT}:SPEC.md"))
        .output()
        .expect("run git");
    if !out.status.success() {
        assert!(
            std::env::var_os("SC1_REQUIRE_SPEC").is_none(),
            "SPEC at {SPEC_COMMIT} is unavailable: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        eprintln!("SKIPPED: SPEC at {SPEC_COMMIT} is not in this clone (fetch the zami branch)");
        return;
    }
    let spec = String::from_utf8(out.stdout).expect("SPEC is UTF-8");
    let spec_lines: Vec<&str> = spec.lines().collect();
    let expected = spec_requirement_lines(&spec);
    let (rows, _) = parse_map();

    let rule_rows: BTreeMap<usize, &Row> = rows
        .iter()
        .filter(|r| r.source == "rule")
        .map(|r| (r.line, r))
        .collect();
    let missing: Vec<_> = expected
        .keys()
        .filter(|l| !rule_rows.contains_key(l))
        .collect();
    let extra: Vec<_> = rule_rows
        .keys()
        .filter(|l| !expected.contains_key(l))
        .collect();
    assert!(
        missing.is_empty(),
        "requirement lines with no row: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "rule rows with no requirement line: {extra:?}"
    );

    for r in &rows {
        let text = spec_lines
            .get(r.line - 1)
            .unwrap_or_else(|| panic!("row for line {} is past the end of the SPEC", r.line))
            .trim();
        assert_eq!(
            collapse(&r.spec_text),
            collapse(text),
            "row {}: quote drifted from the SPEC line",
            r.line
        );
        if r.source == "supplement" {
            assert!(
                !expected.contains_key(&r.line),
                "line {} is a rule line; a supplement duplicates it",
                r.line
            );
        }
    }
}

/// Source of the named test fn, and its attribute block (the contiguous
/// `#[..]` / `//` lines directly above it).
fn fn_attrs(file_src: &str, name: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = file_src.lines().collect();
    let idx = lines.iter().position(|l| {
        let l = l.trim_start();
        let l = l.strip_prefix("pub ").unwrap_or(l);
        let l = l.strip_prefix("async ").unwrap_or(l);
        l.strip_prefix(&format!("fn {name}"))
            .is_some_and(|rest| rest.starts_with('(') || rest.starts_with('<'))
    })?;
    let mut attrs = vec![];
    for l in lines[..idx].iter().rev() {
        let t = l.trim();
        if t.starts_with("#[") || t.starts_with("//") {
            attrs.push(t.to_string());
        } else {
            break;
        }
    }
    Some(attrs)
}

/// `path::fn` or `path::fn[category/vector]`.
fn split_ref(r: &str) -> (&str, &str, Option<&str>) {
    let (path, rest) = r.split_once("::").expect("test ref is path::fn");
    match rest.split_once('[') {
        Some((f, v)) => (path, f, Some(v.trim_end_matches(']'))),
        None => (path, rest, None),
    }
}

/// Backs the map's honesty. Scenario: every named test resolves to a `fn`
/// in its file (a golden `[vector]` to a file under `tests/golden/`), and
/// each row's disposition agrees with its tests' ignore state: `covered`
/// rows name no ignored test; `red-existing` and `red-new` rows name an
/// ignored `RED(..)` test (in another file / in this node's files);
/// `not-testable` and `out-of-scope` rows name none. Every ignore in this
/// node's files is `RED(..)` and is named by a row, and the summary counts
/// equal the rows. Turns red if a row names a renamed or deleted test, a fix
/// lands and un-ignores a test the map still calls red, or a red is
/// ignored without a row.
#[test]
fn map_rows_resolve_and_agree_with_their_tests() {
    let (rows, summary) = parse_map();
    assert!(!rows.is_empty(), "the map has no rows");

    let mut seen = BTreeSet::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut named_reds: BTreeSet<(String, String)> = BTreeSet::new();
    for r in &rows {
        assert!(seen.insert(r.line), "two rows for SPEC line {}", r.line);
        assert!(
            DISPOSITIONS.contains(&r.disposition.as_str()),
            "line {}: unknown disposition {:?}",
            r.line,
            r.disposition
        );
        assert!(["rule", "supplement"].contains(&r.source.as_str()));
        // The rule decides which source a row has; offline, that is checkable
        // from the quote alone.
        assert_eq!(
            is_requirement_line(&r.spec_text),
            r.source == "rule",
            "line {}: source {:?} disagrees with the extraction rule on its quote",
            r.line,
            r.source
        );
        *counts.entry(r.disposition.clone()).or_default() += 1;

        let testless = matches!(r.disposition.as_str(), "not-testable" | "out-of-scope");
        assert_eq!(
            testless,
            r.tests.is_empty(),
            "line {}: tests vs disposition",
            r.line
        );

        let (mut ignored_here, mut ignored_elsewhere) = (0, 0);
        for t in &r.tests {
            let (path, name, vector) = split_ref(t);
            let src = read_repo(path);
            let attrs = fn_attrs(&src, name)
                .unwrap_or_else(|| panic!("line {}: no `fn {name}` in {path}", r.line));
            if let Some(v) = vector {
                assert!(
                    repo_root().join(format!("tests/golden/{v}.json")).is_file(),
                    "line {}: no golden vector {v}",
                    r.line
                );
            }
            let ignore: Vec<_> = attrs.iter().filter(|a| a.starts_with("#[ignore")).collect();
            if !ignore.is_empty() {
                assert!(
                    ignore.iter().all(|a| a.contains("RED(")),
                    "line {}: {name} is ignored without RED(..)",
                    r.line
                );
                named_reds.insert((path.to_string(), name.to_string()));
                if path == CORE_FILE || path == SERVER_FILE {
                    ignored_here += 1;
                } else {
                    ignored_elsewhere += 1;
                }
            }
        }
        let ok = match r.disposition.as_str() {
            "covered" | "not-testable" | "out-of-scope" => ignored_here + ignored_elsewhere == 0,
            "red-existing" => ignored_elsewhere > 0 && ignored_here == 0,
            "red-new" => ignored_here > 0,
            _ => unreachable!("validated above"),
        };
        assert!(
            ok,
            "line {}: disposition {} disagrees with its tests' ignore state (ignored here \
             {ignored_here}, elsewhere {ignored_elsewhere})",
            r.line, r.disposition
        );
    }

    for file in [CORE_FILE, SERVER_FILE] {
        let src = read_repo(file);
        let lines: Vec<&str> = src.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim_start();
            if !t.starts_with("#[ignore") {
                continue;
            }
            assert!(
                t.contains("RED("),
                "{file}:{}: ignore without RED(..)",
                i + 1
            );
            let name = lines[i..]
                .iter()
                .find_map(|l| {
                    let l = l.trim_start();
                    let l = l.strip_prefix("async ").unwrap_or(l);
                    l.strip_prefix("fn ")
                        .map(|r| r.split(['(', '<']).next().unwrap_or("").to_string())
                })
                .expect("ignored attribute precedes a fn");
            assert!(
                named_reds.contains(&(file.to_string(), name.clone())),
                "{file}: red test {name} has no map row"
            );
        }
    }

    for d in DISPOSITIONS {
        assert_eq!(
            summary.get(d).copied().unwrap_or(0),
            counts.get(d).copied().unwrap_or(0),
            "summary count for {d} disagrees with the rows"
        );
    }
    assert_eq!(
        summary.get("total").copied(),
        Some(rows.len()),
        "summary total"
    );
}
