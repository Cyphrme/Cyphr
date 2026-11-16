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
use cyphr::{Error, Key, Principal, StateDigest};
use serde_json::json;

const T: i64 = 1_700_000_000;

/// 2^53 - 1, the largest integer in range for `rvk` and `now`.
const MAX_SAFE: i64 = 9_007_199_254_740_991;

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
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// `p` with its genesis committed (SPEC 5.1: a commit chain begins with the
/// genesis key's `key/create` of itself, the `principal/create` and the
/// `commit/create`), signed by its genesis key `k`, which creates
/// each of `others` after itself.
async fn genesis_of(mut p: Principal, k: &Kp, others: &[Key]) -> Principal {
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb),
        others,
        1,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    p
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
async fn commit_one(
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
        .await
        .map(|_| ())
}

/// Two-key principal `{a, b}` (a two-key genesis), the shape every
/// lifecycle and revoke scenario below starts from.
async fn two_key_principal() -> (Principal, Kp, Kp) {
    let (a, b) = (kp(), kp());
    let p = genesis_of(
        Principal::implicit(key_of(&a)).await.expect("genesis"),
        &a,
        &[key_of(&b)],
    )
    .await;
    (p, a, b)
}

// ============================================================================
// SPEC 2.3.1 (line 226): all cozies must have alg, tmb, now, typ
// ============================================================================

/// Apply a `key/create` missing exactly `missing`; `Ok` means it was
/// accepted and finalized.
async fn create_missing_field(missing: &str) -> cyphr::error::Result<()> {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let before = snapshot(&p);
    let mut pay = key_create_pay(&g, &k2.tmb, T);
    pay.as_object_mut().expect("object").remove(missing);
    let r = commit_one(&mut p, &g, sign(&g, pay), Some(key_of(&k2)), T + 1).await;
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
// @docket: rv-coz-wellformed :: scripts/docket-run rv-coz-wellformed
#[tokio::test]
async fn s2_3_1_coz_missing_tmb_now_or_typ_is_rejected() {
    for missing in ["tmb", "now", "typ"] {
        assert!(
            create_missing_field(missing).await.is_err(),
            "a coz without `{missing}` was accepted and finalized"
        );
    }
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T)),
        Some(key_of(&k2)),
        T + 1,
    )
    .await
    .expect("control: the complete coz is accepted");
}

/// Backs SPEC 2.3.1 for `alg`. A coz with no `alg` lacks a required field,
/// so it is refused as `MalformedPayload`; `AlgMismatch` is kept for an
/// `alg` that is present and names another algorithm than the signing
/// key's. Turns red if a coz with no `alg` is accepted, or refused as a
/// mismatch. End to end: yes.
#[tokio::test]
async fn s2_3_1_coz_missing_alg_is_rejected() {
    let r = create_missing_field("alg").await;
    assert!(
        matches!(r, Err(cyphr::Error::MalformedPayload)),
        "a coz without `alg` must be MalformedPayload: {r:?}"
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
#[tokio::test]
async fn s2_3_2_inactive_key_cannot_authorize_its_own_admission() {
    let (mut p, a, _b) = two_key_principal().await;
    let outsider = kp();
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &outsider,
        sign(&outsider, key_create_pay(&outsider, &outsider.tmb, T)),
        Some(key_of(&outsider)),
        T + 1,
    )
    .await;
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
    .await
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
/// principal while it is frozen. End to end: yes.
// @docket: rv-lifecycle-gate :: scripts/docket-run rv-lifecycle-gate
#[tokio::test]
async fn s11_2_frozen_principal_rejects_key_mutations() {
    let frozen = async || {
        let (mut p, a, b) = two_key_principal().await;
        let f = sign(&a, lifecycle_pay(&a, &p, "freeze/create", T));
        commit_one(&mut p, &a, f, None, T + 1)
            .await
            .expect("premise: freeze/create applies");
        assert!(p.is_frozen(), "premise: principal is frozen");
        (p, a, b)
    };

    let mut accepted = vec![];
    let (mut p, a, _) = frozen().await;
    let k3 = kp();
    if commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T + 2)),
        Some(key_of(&k3)),
        T + 3,
    )
    .await
    .is_ok()
    {
        accepted.push("key/create");
    }
    let (mut p, a, b) = frozen().await;
    if commit_one(
        &mut p,
        &a,
        sign(&a, key_delete_pay(&a, &b.tmb, T + 2)),
        None,
        T + 3,
    )
    .await
    .is_ok()
    {
        accepted.push("key/delete");
    }
    let (mut p, a, _) = frozen().await;
    let k4 = kp();
    if commit_one(
        &mut p,
        &a,
        sign(
            &a,
            json!({"alg": a.alg, "id": b64(&k4.tmb), "now": T + 2, "tmb": b64(&a.tmb),
                   "typ": "cyphr.me/cyphr/key/replace"}),
        ),
        Some(key_of(&k4)),
        T + 3,
    )
    .await
    .is_ok()
    {
        accepted.push("key/replace");
    }
    let (mut p, _, b) = frozen().await;
    if commit_one(
        &mut p,
        &b,
        sign(&b, revoke_pay(&b, T + 2, json!(T + 2))),
        None,
        T + 3,
    )
    .await
    .is_ok()
    {
        accepted.push("key/revoke");
    }
    assert!(
        accepted.is_empty(),
        "a frozen principal accepted and finalized: {accepted:?}"
    );

    let (mut p, a, _) = frozen().await;
    let thaw = sign(&a, lifecycle_pay(&a, &p, "freeze/delete", T + 2));
    commit_one(&mut p, &a, thaw, None, T + 3)
        .await
        .expect("control: freeze/delete thaws");
    let k3 = kp();
    commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T + 4)),
        Some(key_of(&k3)),
        T + 5,
    )
    .await
    .expect("control: key/create is accepted once thawed");
}

/// Backs the freeze scope ruled from SPEC 2.3.2 ("a frozen principal
/// rejects mutations"), 11 ("No mutations until unfrozen"), 4.1 (a
/// transaction "results in a mutation of PT") and 14.9: a frozen principal
/// cannot change at all except by being unfrozen. Scenario: a two-key
/// principal records a data action (control: accepted while active),
/// freezes, then a data action signed by an active key is attempted; it
/// must be refused and leave every observable counter untouched. Then
/// `freeze/delete` is accepted, the principal is no longer frozen, and the
/// same action shape is accepted again, so the refusal is the freeze and not
/// a blanket ban. Turns red if a data action is recorded while frozen, or
/// if thawing does not restore the principal. End to end: yes.
#[tokio::test]
async fn frozen_principal_rejects_data_actions_until_thawed() {
    let action = |k: &Kp, now: i64| {
        sign(
            k,
            json!({"alg": k.alg, "msg": "hello", "now": now, "tmb": b64(&k.tmb),
                   "typ": "cyphr.me/comment/create"}),
        )
    };
    let record = |p: &mut Principal, k: &Kp, now: i64| {
        let (pay, sig, czd) = action(k, now);
        p.verify_and_record_action(&pay, &sig, czd).map(|_| ())
    };

    let (mut p, a, _) = two_key_principal().await;
    record(&mut p, &a, T).expect("control: an active principal records an action");
    let f = sign(&a, lifecycle_pay(&a, &p, "freeze/create", T + 1));
    commit_one(&mut p, &a, f, None, T + 2)
        .await
        .expect("premise: freeze/create applies");
    assert!(p.is_frozen(), "premise: principal is frozen");

    let before = snapshot(&p);
    let r = record(&mut p, &a, T + 3);
    assert!(
        matches!(r, Err(cyphr::error::Error::Frozen)),
        "a frozen principal must refuse an action with Frozen: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a refused action changed state");

    let thaw = sign(&a, lifecycle_pay(&a, &p, "freeze/delete", T + 4));
    commit_one(&mut p, &a, thaw, None, T + 5)
        .await
        .expect("freeze/delete is accepted while frozen");
    assert!(!p.is_frozen(), "freeze/delete must unfreeze the principal");
    record(&mut p, &a, T + 6).expect("control: the thawed principal records actions again");
}

// ============================================================================
// SPEC 6.4 (lines 1067, 1069): rvk and now bounds
// ============================================================================

/// Apply `pay_for(b)` signed by `b` on a fresh two-key principal (the pay is
/// built from the principal's own key, so a rejection cannot be the
/// signer simply being unknown).
async fn revoke_outcome(pay_for: impl Fn(&Kp) -> serde_json::Value) -> cyphr::error::Result<()> {
    revoke_outcome_at(None, pay_for).await
}

/// [`revoke_outcome`] under an injected verifier clock, to reach `now`
/// values the system clock would refuse as future-dated.
async fn revoke_outcome_at(
    clock: Option<cyphr::principal::Clock>,
    pay_for: impl Fn(&Kp) -> serde_json::Value,
) -> cyphr::error::Result<()> {
    let (mut p, _a, b) = two_key_principal().await;
    if let Some(clock) = clock {
        p.set_clock(clock);
    }
    let before = snapshot(&p);
    let r = commit_one(&mut p, &b, sign(&b, pay_for(&b)), None, T + 1).await;
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
/// the key. The boundary is pinned both ways: 2^53 - 1 is accepted (the Coz
/// reference implementations reject only above it) and 2^53 is rejected.
/// End to end: yes.
#[tokio::test]
async fn s6_4_revoke_rvk_must_be_a_positive_bounded_integer() {
    let cases = [
        ("zero", json!(0)),
        ("negative", json!(-1)),
        ("2^53", json!(9_007_199_254_740_992_i64)),
        ("fraction", json!(1.5)),
        ("string", json!("1")),
    ];
    let mut accepted = vec![];
    for (label, rvk) in cases {
        if revoke_outcome(|b| revoke_pay(b, T, rvk.clone()))
            .await
            .is_ok()
        {
            accepted.push(label);
        }
    }
    revoke_outcome(|b| revoke_pay(b, T, json!(1)))
        .await
        .expect("control: rvk = 1 is accepted");
    revoke_outcome(|b| revoke_pay(b, T, json!(MAX_SAFE)))
        .await
        .expect("control: rvk = 2^53 - 1 is in range (Coz references reject only above it)");
    assert!(
        accepted.is_empty(),
        "key/revoke accepted out-of-range rvk: {accepted:?}"
    );
}

/// Backs SPEC 6.4: "`rvk` and `now` must be a positive integer less than
/// 2^53 - 1." for `now`. Scenario: a self-revoke with a valid `rvk` and each
/// out-of-range `now` (zero, negative, 2^53) must be rejected; `now = T` is
/// the control. Turns red if an out-of-range `now` is accepted. End to end:
/// yes.
// @docket: rv-timestamp-range :: scripts/docket-run rv-timestamp-range
#[tokio::test]
async fn s6_4_revoke_now_must_be_a_positive_bounded_integer() {
    let mut accepted = vec![];
    for (label, now) in [
        ("zero", 0_i64),
        ("negative", -1),
        ("2^53", 9_007_199_254_740_992),
    ] {
        if revoke_outcome(|b| revoke_pay(b, now, json!(1)))
            .await
            .is_ok()
        {
            accepted.push(label);
        }
    }
    revoke_outcome(|b| revoke_pay(b, T, json!(1)))
        .await
        .expect("control: now = T is accepted");
    // The in-range control sits at the verifier clock, not at 2^53 - 1: the
    // future-timestamp bound (SPEC 15.9) refuses that value as a message from
    // the future, which the W1 tests pin separately.
    revoke_outcome(|b| revoke_pay(b, unix_now(), json!(1)))
        .await
        .expect("control: now at the verifier clock is in range");
    assert!(
        accepted.is_empty(),
        "key/revoke accepted out-of-range now: {accepted:?}"
    );
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
#[tokio::test]
async fn s6_4_one_key_cannot_revoke_another() {
    let (mut p, a, b) = two_key_principal().await;
    let before = snapshot(&p);

    let mut names_a = revoke_pay(&b, T, json!(T));
    names_a["id"] = json!(b64(&a.tmb));
    let r1 = commit_one(&mut p, &b, sign(&b, names_a), None, T + 1).await;
    assert!(r1.is_err(), "b revoked a through `id`: {r1:?}");

    let claims_a = revoke_pay(&a, T, json!(T));
    let r2 = commit_one(&mut p, &b, sign(&b, claims_a), None, T + 1).await;
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
// @docket: rv-intra-commit-shape :: scripts/docket-run rv-intra-commit-shape
#[tokio::test]
async fn s4_6_commit_coz_must_be_last_in_txs() {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
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
    let r = scope.finalize().await.map(|_| ());
    assert!(
        matches!(r, Err(Error::CommitNotLast)),
        "a commit with its finalizer first was not rejected as CommitNotLast: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a rejected commit changed state");
}

// ============================================================================
// archrev:A1 / A5 / A6 (core): finality, transaction typs, revoked keys
// ============================================================================

/// archrev:A1. Backs SPEC 4.3: a commit "is finalized with a commit
/// transaction, `commit/create`, with the field `arrow`". Scenario: a
/// `key/create` that carries an `arrow` field must not be accepted as a
/// finalizer; before the fix the core treated any coz with an `arrow` as
/// the commit transaction. Turns red if `arrow` on a non-`commit/create`
/// typ is accepted. End to end: yes (public verify path).
#[tokio::test]
async fn archrev_a1_arrow_on_a_non_commit_create_coz_is_refused() {
    let (mut p, a, _) = two_key_principal().await;
    let k3 = kp();
    let before = snapshot(&p);
    let arrow = format!("SHA-512:{}", Base64UrlUnpadded::encode_string(&[7u8; 64]));
    let mut pay = key_create_pay(&a, &k3.tmb, T);
    pay["arrow"] = json!(arrow);
    let (pay, sig, czd) = sign(&a, pay);
    let mut scope = p.begin_commit();
    let r = scope.verify_and_apply(&pay, &sig, czd, Some(key_of(&k3)));
    assert!(
        matches!(r, Err(Error::MalformedPayload)),
        "a key/create carrying `arrow` was accepted: {r:?}"
    );
    drop(scope);
    assert_eq!(before, snapshot(&p), "a refused coz changed state");
}

/// archrev:A5. Backs SPEC 7.6 / 4.1: a transaction is applied through a
/// commit, a data action is recorded as an action; the two never mix.
/// Scenario: recording a signed `key/create` as a data action must be
/// refused, and the same coz must still apply as a transaction (before the
/// fix it was recorded as an action, and the real transaction then failed
/// as COZ_REUSE). End to end: yes (public action and commit APIs).
#[tokio::test]
async fn archrev_a5_transaction_typ_is_not_a_data_action() {
    let (mut p, a, _) = two_key_principal().await;
    let k3 = kp();
    let before = snapshot(&p);
    let (pay, sig, czd) = sign(&a, key_create_pay(&a, &k3.tmb, T));
    let r = p.verify_and_record_action(&pay, &sig, czd.clone());
    assert!(
        matches!(r, Err(Error::MalformedPayload)),
        "a key/create was recorded as a data action: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a refused action changed state");
    commit_one(&mut p, &a, (pay, sig, czd), Some(key_of(&k3)), T + 1)
        .await
        .expect("the key/create still applies as a transaction");
    assert!(p.is_key_active(&k3.tmb));
}

/// archrev:A6. Backs SPEC 6.4: "a revoked key is never trusted again".
/// Scenario: a `Key` already marked revoked, offered through `key/create`,
/// must be refused with `KeyRevoked`; before the fix it entered the key
/// set, its algorithm left the active set, and the roots diverged. End to
/// end: yes (public commit API).
#[tokio::test]
async fn archrev_a6_key_create_refuses_an_already_revoked_key() {
    let (mut p, a, _) = two_key_principal().await;
    let k3 = kp();
    let before = snapshot(&p);
    let revoked = key_of(&k3).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let r = commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T)),
        Some(revoked),
        T + 1,
    )
    .await;
    assert!(
        matches!(r, Err(Error::KeyRevoked)),
        "a pre-revoked key was added through key/create: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a refused key/create changed state");
}

/// archrev:A6. Backs SPEC 6.4 as above, for `key/replace`: it reaches the
/// same key-set insert as `key/create`, and before the fix a pre-revoked
/// key swapped in for the signer. End to end: yes (public commit API).
#[tokio::test]
async fn archrev_a6_key_replace_refuses_an_already_revoked_key() {
    let (mut p, a, _) = two_key_principal().await;
    let k3 = kp();
    let before = snapshot(&p);
    let revoked = key_of(&k3).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let mut pay = key_create_pay(&a, &k3.tmb, T);
    pay["typ"] = json!("cyphr.me/cyphr/key/replace");
    let r = commit_one(&mut p, &a, sign(&a, pay), Some(revoked), T + 1).await;
    assert!(
        matches!(r, Err(Error::KeyRevoked)),
        "a pre-revoked key was swapped in through key/replace: {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a refused key/replace changed state");
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
// @docket: rv-key-material :: scripts/docket-run rv-key-material
#[tokio::test]
async fn s2_2_13_key_create_without_revealed_pub_is_rejected() {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T)),
        None,
        T + 1,
    )
    .await;
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
async fn add_key_commit(p: &mut Principal, signer: &Kp, new: &Kp, now: i64) -> Vec<Signed> {
    commit_one(
        p,
        signer,
        sign(signer, key_create_pay(signer, &new.tmb, now)),
        Some(key_of(new)),
        now + 1,
    )
    .await
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
#[tokio::test]
async fn s2_3_2_second_commit_on_a_stale_pre_is_rejected() {
    let (a, b) = (kp(), kp());
    let (k3, k4) = (kp(), kp());
    let ancestor = async || {
        genesis_of(
            Principal::implicit(key_of(&a)).await.expect("ancestor"),
            &a,
            &[key_of(&b)],
        )
        .await
    };

    let wire_a = add_key_commit(&mut ancestor().await, &a, &k3, T).await;
    let wire_b = add_key_commit(&mut ancestor().await, &a, &k4, T + 10).await;

    let replay = async |p: &mut Principal, wire: &[Signed], new: &Kp| -> cyphr::error::Result<()> {
        let mut scope = p.begin_commit();
        for (i, (pay, sig, czd)) in wire.iter().enumerate() {
            let sidecar = (i == 0).then(|| key_of(new));
            scope.verify_and_apply(pay, sig, czd.clone(), sidecar)?;
        }
        scope.finalize().await.map(|_| ())
    };

    let mut linear = ancestor().await;
    replay(&mut linear, &wire_a, &k3)
        .await
        .expect("control: branch A applies on the ancestor");
    let before = snapshot(&linear);
    let r = replay(&mut linear, &wire_b, &k4).await;
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

    replay(&mut ancestor().await, &wire_b, &k4)
        .await
        .expect("control: branch B is valid on its own ancestor, so the rejection is the pre");
}

// ============================================================================
// SPEC 4 (line 463): the Merkle tree primitive must support n-arity
// ============================================================================

/// Backs SPEC 4 ("Merkle tree primitive must support n-arity"): the Key Tree
/// is a Merkle tree, so a principal must be able to hold more keys than a
/// fixed fan-out. Scenario: a genesis commit creating 257 distinct keys.
/// Control: 256 keys build. Turns red if the tree refuses a key set the SPEC
/// does not bound. End to end: no; a unit-level boundary, because no
/// scenario reaches 257 keys more cheaply.
#[tokio::test]
async fn s4_key_tree_supports_more_than_256_keys() {
    let a = kp();
    let genesis = async |others: usize| {
        let others: Vec<Key> = (0..others).map(|_| key_of(&kp())).collect();
        genesis_of(
            Principal::implicit(key_of(&a)).await.expect("principal"),
            &a,
            &others,
        )
        .await
    };
    genesis(255).await;
    let p = genesis(256).await;
    assert_eq!(p.active_key_count(), 257, "not every key is active");
}

/// Backs SPEC 4 ("Merkle tree primitive must support n-arity") as a
/// lifecycle: a principal at the old 256-key bound can grow past it by signed
/// `key/create`, and `key/delete` returns it to the earlier Key Root. Scenario:
/// a genesis of 256 keys (control: builds today); `a` creates keys
/// 257-259 one commit each, every Key Root distinct from all before it; `a`
/// then deletes them in reverse and each Key Root equals the one recorded
/// when that size was first reached. Turns red if: the 257th key is refused
/// (the cap stays), a key beyond 256 is dropped from the root (Key Root
/// unchanged by the create), or a delete leaves residue (root not restored).
/// End to end: yes (signed commits through `finalize`); the genesis-only form is the
/// `s4_key_tree_supports_more_than_256_keys` red above.
#[tokio::test]
async fn key_tree_arity_growth_past_256_and_delete_restores_the_key_root() {
    let a = kp();
    let mut keys = vec![key_of(&a)];
    keys.extend((1..256).map(|_| key_of(&kp())));
    let mut p = genesis_of(
        Principal::implicit(keys[0].clone())
            .await
            .expect("principal"),
        &a,
        &keys[1..],
    )
    .await;
    let mut roots = vec![p.key_root().expect("live KR").clone()];
    let extra: Vec<Kp> = (0..3).map(|_| kp()).collect();
    for (i, k) in extra.iter().enumerate() {
        let now = T + i as i64;
        commit_one(
            &mut p,
            &a,
            sign(&a, key_create_pay(&a, &k.tmb, now)),
            Some(key_of(k)),
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("key {} refused: {e:?}", 257 + i));
        assert!(
            !roots.contains(p.key_root().expect("live KR")),
            "key {} did not change the Key Root",
            257 + i
        );
        roots.push(p.key_root().expect("live KR").clone());
    }
    for (step, (i, k)) in extra.iter().enumerate().rev().enumerate() {
        // Commit timestamps must not go backwards, so `now` follows the
        // delete order, not the key index.
        let now = T + 10 + step as i64;
        commit_one(
            &mut p,
            &a,
            sign(&a, key_delete_pay(&a, &k.tmb, now)),
            None,
            now,
        )
        .await
        .expect("delete of an added key");
        assert_eq!(
            p.key_root(),
            Some(&roots[i]),
            "deleting key {} did not restore the Key Root",
            257 + i
        );
    }
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
/// Built by `concat!` so a text search for ignored tests does not match this
/// file's own scanner.
const IGNORE_ATTR: &str = concat!("#[", "ignore");
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
            if let (Some(d), Some(n)) = (it.next(), it.next())
                && let Ok(n) = n.parse::<usize>()
            {
                summary.insert(d.trim_end_matches('`').to_string(), n);
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
/// sections 2-12 (up to `# Extended`), 15.2, 15.8, 15.9, 17.2 and 19.5.
fn spec_requirement_lines(spec: &str) -> BTreeMap<usize, String> {
    let lines: Vec<&str> = spec.lines().collect();
    let at = |prefix: &str, from: usize| {
        (from..lines.len())
            .find(|&i| lines[i].starts_with(prefix))
            .unwrap_or_else(|| panic!("SPEC has no line starting {prefix:?}"))
    };
    let s2 = at("## 2. ", 0);
    let extended = at("# Extended", s2);
    let end_of = |start: usize| at("#", start + 1);
    let mut out = BTreeMap::new();
    let mut ranges = vec![(s2, extended)];
    for heading in [
        "### 15.2 ",
        "#### 15.8 ",
        "### 15.9 ",
        "### 17.2 ",
        "### 19.5 ",
    ] {
        let start = at(heading, extended);
        ranges.push((start, end_of(start)));
    }
    for (lo, hi) in ranges {
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
/// `zami` branch, which governs; the test fails when it cannot read it.
#[test]
fn map_has_one_row_per_spec_requirement() {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .arg("show")
        .arg(format!("{SPEC_COMMIT}:SPEC.md"))
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "SPEC at {SPEC_COMMIT} is unavailable (the zami branch must be fetched): {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
            let ignore: Vec<_> = attrs
                .iter()
                .filter(|a| a.starts_with(IGNORE_ATTR))
                .collect();
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
            if !t.starts_with(IGNORE_ATTR) {
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

// ============================================================================
// SPEC 7.6 (line 1267): coz reuse by a principal is prohibited (COZ_REUSE)
// ============================================================================

/// Backs SPEC 7.6: "For transactions, coz reuse by a particular principal is
/// prohibited and results in error `COZ_REUSE`." Scenario: key `a` signs a
/// `key/delete` of `k3` (coz D); `k3` is added, deleted by D, and re-added by
/// a different coz; D is then replayed. All `now` values are equal so the
/// timestamp rule cannot be what rejects the replay. Control: a fresh
/// `key/delete` coz signed by `b` in the same state is accepted, so the
/// rejection can only be the reuse. Turns red if a previously included
/// transaction coz is applied a second time. End to end: yes.
#[tokio::test]
async fn s7_6_transaction_coz_reuse_by_the_same_principal_is_rejected() {
    let (a, b, k3) = (kp(), kp(), kp());
    let build = async || {
        let mut p = genesis_of(
            Principal::implicit(key_of(&a)).await.expect("genesis"),
            &a,
            &[key_of(&b)],
        )
        .await;
        let d = sign(&a, key_delete_pay(&a, &k3.tmb, T));
        commit_one(
            &mut p,
            &a,
            sign(&a, key_create_pay(&a, &k3.tmb, T)),
            Some(key_of(&k3)),
            T,
        )
        .await
        .expect("add k3");
        commit_one(&mut p, &a, d.clone(), None, T)
            .await
            .expect("first inclusion of D");
        commit_one(
            &mut p,
            &b,
            sign(&b, key_create_pay(&b, &k3.tmb, T)),
            Some(key_of(&k3)),
            T,
        )
        .await
        .expect("re-add k3 by another coz");
        assert!(p.is_key_active(&k3.tmb), "premise: k3 active again");
        (p, d)
    };

    let (mut p, _) = build().await;
    commit_one(
        &mut p,
        &b,
        sign(&b, key_delete_pay(&b, &k3.tmb, T)),
        None,
        T,
    )
    .await
    .expect("control: a fresh delete coz is accepted");

    let (mut p, d) = build().await;
    let before = snapshot(&p);
    let r = commit_one(&mut p, &a, d, None, T).await;
    assert!(
        r.is_err(),
        "a previously included transaction coz was applied again"
    );
    assert_eq!(before, snapshot(&p), "a rejected reuse changed state");
}

// ----------------------------------------------------------------------------
// N09 acceptance: typed COZ_REUSE, first inclusion authoritative, per-principal
// scope, and replay under another encoding or digest width of the same coz.
// ----------------------------------------------------------------------------

/// The reuse fixture: `{a, b}` principal; `a` adds `k3` (coz C), `a` deletes
/// it (coz D, signed by `signer`), `b` re-adds it with a different coz, so D
/// is state-valid again. Every `now` is `T`, so the timestamp rule cannot be
/// what rejects a replay. Returns the principal, D and the keys.
async fn reuse_fixture(a: &Kp, b: &Kp, k3: &Kp, d_signer: &Kp) -> (Principal, Signed) {
    let mut p = genesis_of(
        Principal::implicit(key_of(a)).await.expect("genesis"),
        a,
        &[key_of(b)],
    )
    .await;
    let d = sign(d_signer, key_delete_pay(d_signer, &k3.tmb, T));
    commit_one(
        &mut p,
        a,
        sign(a, key_create_pay(a, &k3.tmb, T)),
        Some(key_of(k3)),
        T,
    )
    .await
    .expect("add k3");
    commit_one(&mut p, d_signer, d.clone(), None, T)
        .await
        .expect("first inclusion of D");
    commit_one(
        &mut p,
        b,
        sign(b, key_create_pay(b, &k3.tmb, T)),
        Some(key_of(k3)),
        T,
    )
    .await
    .expect("re-add k3 by another coz");
    assert!(p.is_key_active(&k3.tmb), "premise: D is state-valid again");
    (p, d)
}

/// The typed rejection is `Error::CozReuse`. The variant does not exist yet,
/// so the name is pinned through `Debug` (the golden vector's error name is
/// the same string); this keeps the file compiling on the base.
fn assert_coz_reuse(r: cyphr::error::Result<()>) {
    match r {
        Err(e) => assert_eq!(
            format!("{e:?}"),
            "CozReuse",
            "a replayed transaction coz must fail with the typed COZ_REUSE error"
        ),
        Ok(()) => panic!("a previously included transaction coz was applied again"),
    }
}

/// Backs SPEC 7.6: "coz reuse by a particular principal is prohibited and
/// results in error `COZ_REUSE`. The first inclusion of a transaction coz is
/// considered authoritative." Scenario: see [`reuse_fixture`]; D is replayed.
/// Controls (green on the base, so the red is the reuse check alone): the
/// SAME coz C and D applied by a different principal that shares the keys is
/// accepted (the spec allows cross-principal reuse). Asserts: the replay
/// fails with the typed `CozReuse`; it leaves state untouched (first
/// inclusion stays the only inclusion); and the principal is not wedged: a
/// fresh coz still applies afterwards. Turns red if reuse is accepted, is
/// rejected with an untyped error, or is rejected globally across principals
/// (the cross-principal control then fails first). Mutants caught: a no-op
/// `Ok` (accepts), `Err(StateMismatch)` (wrong type), a process-global czd
/// set (control). End to end: yes.
// @docket: rv-no-coz-reuse :: scripts/docket-run rv-no-coz-reuse
#[tokio::test]
async fn s7_6_reuse_is_typed_and_scoped_to_one_principal() {
    let (a, b, c3, k3) = (kp(), kp(), kp(), kp());
    let (mut p, d) = reuse_fixture(&a, &b, &k3, &a).await;

    // Control: a different principal (extra genesis key, so a different PR)
    // applying the very same cozes C and D is not rejected.
    let c = sign(&a, key_create_pay(&a, &k3.tmb, T));
    let mut other = genesis_of(
        Principal::implicit(key_of(&a)).await.expect("other"),
        &a,
        &[key_of(&b), key_of(&c3)],
    )
    .await;
    commit_one(&mut other, &a, c, Some(key_of(&k3)), T)
        .await
        .expect("other: C accepted");
    commit_one(&mut other, &a, d.clone(), None, T)
        .await
        .expect("other: D accepted, reuse is per principal");

    let before = snapshot(&p);
    assert_coz_reuse(commit_one(&mut p, &a, d, None, T).await);
    assert_eq!(before, snapshot(&p), "a rejected reuse changed state");
    assert!(p.is_key_active(&k3.tmb), "first inclusion stays in force");

    commit_one(
        &mut p,
        &b,
        sign(&b, key_delete_pay(&b, &k3.tmb, T)),
        None,
        T,
    )
    .await
    .expect("a fresh coz still applies after a rejected reuse");
}

/// Backs SPEC 7.6 and SPEC 12.1 (all hash variants name the same content,
/// so one matching variant is not a match). Scenario: a mixed
/// ES256 + ES384 principal; the replayed coz D is signed by the ES384 key, so
/// its czd is a SHA-384 digest and the principal carries both SHA-256 and
/// SHA-384 state variants. D is replayed verbatim after `k3` returns. The
/// czd under another algorithm is not a route in: the core already answers
/// `CzdMismatch` for a czd not derived under the signing key's algorithm
/// (`verify_coz`), so the same-coz-under-another-digest probe collapses to
/// this wide-digest case. Turns red if the reuse check compares only a
/// SHA-256-width identifier, a first variant, or a truncation, and so never
/// recognises an ES384 coz. Mutant caught: a set of `[u8; 32]` czd prefixes.
/// End to end: yes.
#[tokio::test]
async fn multihash_replay_of_an_es384_signed_coz_is_reuse() {
    let (a, b, k3) = (
        kp_alg(coz::Alg::ES256),
        kp_alg(coz::Alg::ES384),
        kp_alg(coz::Alg::ES256),
    );
    let (mut p, d) = reuse_fixture(&a, &b, &k3, &b).await;
    assert_eq!(d.2.as_bytes().len(), 48, "premise: D's czd is SHA-384 wide");

    let before = snapshot(&p);
    assert_coz_reuse(commit_one(&mut p, &b, d, None, T).await);
    assert_eq!(before, snapshot(&p), "a rejected reuse changed state");
}

/// Backs SPEC 12.1 / 7.6 (a replay must not slip through a repeating hash
/// variant): every active algorithm's Commit Root variant is a function of
/// the whole log, so it must change with every commit. Scenario: an
/// ES256 + ES384 principal takes three commits; after each, CR carries both
/// the SHA-256 and SHA-384 variants and each differs from its value after
/// the previous commit. Turns red if a variant stops advancing (frozen or
/// recomputed from a stale tree) or a variant goes missing. Mutant caught:
/// leaving one algorithm's MALT tree out of the per-commit append. End to
/// end: yes.
#[tokio::test]
async fn every_active_algorithms_cr_variant_advances_with_every_commit() {
    let (a, b) = (kp_alg(coz::Alg::ES256), kp_alg(coz::Alg::ES384));
    let mut p = genesis_of(
        Principal::implicit(key_of(&a)).await.expect("genesis"),
        &a,
        &[key_of(&b)],
    )
    .await;
    let cr_variants = |p: &Principal| {
        p.cr()
            .map(|cr| cr.as_multihash().variants().clone())
            .unwrap_or_default()
    };
    let mut prev = cr_variants(&p);
    for step in 0..3 {
        let k = kp_alg(coz::Alg::ES256);
        commit_one(
            &mut p,
            &a,
            sign(&a, key_create_pay(&a, &k.tmb, T)),
            Some(key_of(&k)),
            T,
        )
        .await
        .expect("commit");
        let now = cr_variants(&p);
        assert_eq!(now.len(), 2, "step {step}: CR must carry both algorithms");
        for (alg, digest) in &now {
            assert_ne!(
                prev.get(alg),
                Some(digest),
                "step {step}: the {alg:?} CR variant did not advance"
            );
        }
        prev = now;
    }
}

// ============================================================================
// SPEC 15.9 (line 2834): future-dated messages are rejected
// ============================================================================

fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

/// Backs SPEC 15.9: "comparing now to witness time on receipt and rejecting
/// outside +-360 s default tolerance ... and rejecting future-dated
/// messages." Scenario, with a default `Principal`: a data action and a
/// `key/create` dated a day ahead of the clock are applied; the same coz
/// dated at the clock is the control. Turns red if a message far beyond the
/// tolerance is accepted. The backdated side (a first message far in the past)
/// is not tested: the whole corpus uses fixed 2023 timestamps (question Q10).
/// End to end: yes.
#[tokio::test]
async fn s15_9_future_dated_message_is_rejected_by_default() {
    let now = unix_now();
    let outcome = async |at: i64| {
        let (g, k2) = (kp(), kp());
        let mut p = genesis_of(
            Principal::implicit(key_of(&g)).await.expect("genesis"),
            &g,
            &[],
        )
        .await;
        let (pay, sig, czd) = sign(
            &g,
            json!({"alg": g.alg, "now": at, "tmb": b64(&g.tmb), "typ": "cyphr.me/cyphr/data/x"}),
        );
        let action = p.verify_and_record_action(&pay, &sig, czd).map(|_| ());
        let create = commit_one(
            &mut p,
            &g,
            sign(&g, key_create_pay(&g, &k2.tmb, at)),
            Some(key_of(&k2)),
            at,
        )
        .await;
        (action, create)
    };
    let (action, create) = outcome(now).await;
    action.expect("control: an action dated now is accepted");
    create.expect("control: a key/create dated now is accepted");

    let (action, create) = outcome(now + 86_400).await;
    let mut accepted = vec![];
    if action.is_ok() {
        accepted.push("data action");
    }
    if create.is_ok() {
        accepted.push("key/create");
    }
    assert!(
        accepted.is_empty(),
        "day-ahead messages accepted: {accepted:?}"
    );
}

// ============================================================================
// W1: the `now` bound on every entry path
// ============================================================================

/// Apply the same `now` through both entry paths (a data action and a
/// `key/create` commit) on a default `Principal`, returning each outcome.
async fn now_outcomes(at: i64) -> (cyphr::error::Result<()>, cyphr::error::Result<()>) {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let (pay, sig, czd) = sign(
        &g,
        json!({"alg": g.alg, "now": at, "tmb": b64(&g.tmb), "typ": "cyphr.me/cyphr/data/x"}),
    );
    let action = p.verify_and_record_action(&pay, &sig, czd).map(|_| ());
    let create = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, at)),
        Some(key_of(&k2)),
        at,
    );
    (action, create.await)
}

/// Backs the same rule from the other side: it must not over-reach. Scenario:
/// a data action and a `key/create` dated at the clock, an hour behind it,
/// and one second ahead of it (inside any non-zero drift window) are all
/// accepted. A green characterization that must survive the fix: it turns red
/// if the bound is made strict (no drift) or two-sided against the clock.
/// Unit-level on purpose: the window edge has no cheaper scenario.
#[tokio::test]
async fn now_bound_inside_the_drift_window_is_accepted() {
    let now = unix_now();
    for (label, at) in [
        ("at the clock", now),
        ("an hour behind", now - 3_600),
        ("1s ahead", now + 1),
    ] {
        let (action, create) = now_outcomes(at).await;
        action.unwrap_or_else(|e| panic!("action {label}: {e:?}"));
        create.unwrap_or_else(|e| panic!("key/create {label}: {e:?}"));
    }
}

// ============================================================================
// SPEC 2.2.2 (line 119): b64ut errors on non-canonical encodings
// ============================================================================

/// The non-canonical alias of a canonical b64ut string: the last character
/// carries zero padding bits, so bumping its index sets one and decodes to
/// the same bytes under a lenient decoder.
fn non_canonical_alias(s: &str) -> String {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = s.chars().last().expect("non-empty");
    let idx = ALPHABET.find(last).expect("b64url char");
    let bumped = ALPHABET.chars().nth(idx + 1).expect("not the last letter");
    format!("{}{bumped}", &s[..s.len() - 1])
}

/// Backs SPEC 2.2.2: "b64ut ... errors on non-canonical encodings". Scenario:
/// a `key/create` signed by an active key whose `id` is a non-canonical
/// alias of the new key's thumbprint must be rejected (otherwise one key has
/// two spellings and two valid cozies). Control: the canonical `id` is
/// accepted. Turns red if a lenient decoder admits the alias. End to end: yes.
// @docket: sc-l119 :: scripts/docket-run sc-l119
#[tokio::test]
async fn s2_2_2_non_canonical_b64ut_is_rejected() {
    let (g, k2) = (kp(), kp());
    let canonical = b64(&k2.tmb);
    let alias = non_canonical_alias(&canonical);
    assert_ne!(alias, canonical, "premise: the alias differs");

    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let mut pay = key_create_pay(&g, &k2.tmb, T);
    pay["id"] = json!(alias);
    let before = snapshot(&p);
    let r = commit_one(&mut p, &g, sign(&g, pay), Some(key_of(&k2)), T + 1).await;
    assert!(r.is_err(), "a non-canonical id was accepted: {r:?}");
    assert_eq!(before, snapshot(&p));
    commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T)),
        Some(key_of(&k2)),
        T + 1,
    )
    .await
    .expect("control: the canonical id is accepted");
}

// ============================================================================
// SPEC 2.3.2 (line 240): Principal Genesis is immutable
// ============================================================================

/// Backs SPEC 2.3.2: "No operation can change a PG." Scenario: a two-key
/// genesis establishes its PG, a second `principal/create` (the only
/// writer of the PG) is refused with `StateMismatch`, then it runs every key operation (create,
/// replace, delete of a genesis key, revoke); its PG is compared after each. Turns red if any
/// operation changes the recorded PG. End to end: yes.
// @docket: sc-l240 :: scripts/docket-run sc-l240
// @docket: rv-genesis-immutable :: scripts/docket-run rv-genesis-immutable
#[tokio::test]
async fn s2_3_2_no_operation_changes_the_principal_genesis() {
    let (a, b) = (kp(), kp());
    let mut p = Principal::implicit(key_of(&a)).await.expect("genesis");
    let mut scope = p.begin_commit();
    scope
        .create_genesis_keys(&software(&a), &[key_of(&b)], T, "cyphr.me")
        .await
        .expect("genesis key/creates");
    let establish = json!({"alg": a.alg, "id": scope.genesis_id().expect("id"), "now": T,
                           "tmb": b64(&a.tmb), "typ": "cyphr.me/cyphr/principal/create"});
    let (pay, sig, czd) = sign(&a, establish);
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("principal/create establishes PG");
    scope
        .finalize_with_software(&software(&a), T, "cyphr.me")
        .await
        .expect("genesis commit");
    let pg = format!("{:?}", p.pg());
    assert_ne!(pg, "None", "premise: principal/create records a PG");
    let again = json!({"alg": a.alg, "id": p.pr_tagged().expect("pr"), "now": T,
                       "tmb": b64(&a.tmb), "typ": "cyphr.me/cyphr/principal/create"});
    let before = snapshot(&p);
    let r = commit_one(&mut p, &a, sign(&a, again), None, T).await;
    assert!(
        matches!(r, Err(Error::StateMismatch)),
        "a second principal/create must be refused (PG is write-once): {r:?}"
    );
    assert_eq!(
        format!("{:?}", p.pg()),
        pg,
        "a refused second principal/create changed the PG"
    );
    assert_eq!(before, snapshot(&p));
    let (k3, k4) = (kp(), kp());
    let steps: Vec<(&str, Signed, Option<Key>, &Kp)> = vec![
        (
            "key/create",
            sign(&a, key_create_pay(&a, &k3.tmb, T)),
            Some(key_of(&k3)),
            &a,
        ),
        (
            "key/replace",
            sign(
                &a,
                json!({"alg": a.alg, "id": b64(&k4.tmb), "now": T, "tmb": b64(&a.tmb),
                       "typ": "cyphr.me/cyphr/key/replace"}),
            ),
            Some(key_of(&k4)),
            &a,
        ),
        (
            "key/delete",
            sign(&k4, key_delete_pay(&k4, &b.tmb, T)),
            None,
            &k4,
        ),
        (
            "key/revoke",
            sign(&k3, revoke_pay(&k3, T, json!(1))),
            None,
            &k3,
        ),
    ];
    for (label, coz, sidecar, signer) in steps {
        commit_one(&mut p, signer, coz, sidecar, T)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e:?}"));
        assert_eq!(format!("{:?}", p.pg()), pg, "{label} changed the PG");
    }
}

// ============================================================================
// SPEC 7.7 (line 1300): a principal is created only by principal/create
// ============================================================================

/// Backs SPEC 7.7 Example 2: "A principal may only be created using
/// `principal/create`. A `principal/fork/create` does not create a
/// principal." Scenario: a validly signed `principal/fork/create` applied to
/// an existing principal is rejected and changes nothing. Turns red if the
/// fork typ is accepted as a creation or any other state change. End to end:
/// yes.
// @docket: sc-l1287 :: scripts/docket-run sc-l1287
// @docket: sc-l1300 :: scripts/docket-run sc-l1300
#[tokio::test]
async fn s7_7_fork_create_does_not_create_a_principal() {
    let (mut p, a, _b) = two_key_principal().await;
    let before = snapshot(&p);
    let pay = json!({"alg": a.alg, "fork_pr": p.pr_tagged().expect("pr"), "now": T,
                     "tmb": b64(&a.tmb), "typ": "cyphr.me/cyphr/principal/fork/create"});
    let r = commit_one(&mut p, &a, sign(&a, pay), None, T).await;
    assert!(r.is_err(), "principal/fork/create was applied: {r:?}");
    assert_eq!(before, snapshot(&p));
}

// ============================================================================
// SPEC 11.2 (line 1869): a Dead principal accepts nothing
// ============================================================================

/// Backs SPEC 11.2: "Dead: No transactions or actions possible at all." The
/// protocol refuses to remove the last key, so Dead is reached only through
/// `pre_revoke_key` (a naked revoke ahead of any commit). Scenario: the only
/// key is revoked; the principal derives Dead; a `key/create` and a data
/// action by that key are both rejected and change nothing. Turns red if a
/// Dead principal still takes a transaction or action. End to end: yes.
// @docket: sc-l1869 :: scripts/docket-run sc-l1869
#[tokio::test]
async fn s11_2_dead_principal_accepts_no_transaction_or_action() {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    p.pre_revoke_key(&g.tmb, T).expect("revoke the only key");
    assert_eq!(p.lifecycle_state(), cyphr::lifecycle::LifecycleState::Dead);
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T + 1)),
        Some(key_of(&k2)),
        T + 2,
    )
    .await;
    assert!(r.is_err(), "a dead principal took a key/create: {r:?}");
    let (pay, sig, czd) = sign(
        &g,
        json!({"alg": g.alg, "now": T + 1, "tmb": b64(&g.tmb), "typ": "cyphr.me/cyphr/data/x"}),
    );
    let r = p.verify_and_record_action(&pay, &sig, czd);
    assert!(r.is_err(), "a dead principal took a data action: {r:?}");
    assert_eq!(before, snapshot(&p));
}

// ============================================================================
// SPEC 19.5 (line 3353): rejected transactions apply no partial state
// ============================================================================

/// Backs SPEC 19.5: "Not apply partial state changes (atomic)." Scenario: a
/// commit applies one valid `key/create` and then a transaction that fails
/// (a `key/delete` of an unknown key); the scope is dropped. The principal
/// must show nothing of the first transaction, and a fresh commit must still
/// build. Turns red if any part of a failed commit leaks into the principal.
/// End to end: yes.
// @docket: sc-l3350 :: scripts/docket-run sc-l3350
// @docket: sc-l3353 :: scripts/docket-run sc-l3353
#[tokio::test]
async fn s19_5_failed_commit_leaves_no_partial_state() {
    let (mut p, a, _b) = two_key_principal().await;
    let (k3, ghost) = (kp(), kp());
    let before = snapshot(&p);
    {
        let mut scope = p.begin_commit();
        let (pay, sig, czd) = sign(&a, key_create_pay(&a, &k3.tmb, T));
        scope
            .verify_and_apply(&pay, &sig, czd, Some(key_of(&k3)))
            .expect("first tx applies");
        let (pay, sig, czd) = sign(&a, key_delete_pay(&a, &ghost.tmb, T));
        assert!(
            scope.verify_and_apply(&pay, &sig, czd, None).is_err(),
            "premise: deleting an unknown key fails"
        );
    }
    assert_eq!(before, snapshot(&p), "a failed commit leaked state");
    assert!(
        !p.is_key_active(&k3.tmb),
        "the first tx of a failed commit is active"
    );
    commit_one(
        &mut p,
        &a,
        sign(&a, key_create_pay(&a, &k3.tmb, T)),
        Some(key_of(&k3)),
        T,
    )
    .await
    .expect("control: the same key/create commits afterwards");
}

// ============================================================================
// SPEC 4.1 (line 468): all cozies of a transaction share one typ
// ============================================================================

/// Backs SPEC 4.1: "All cozies for a particular transaction contain an
/// identical `typ`." Scenario: one transaction (an unnamed array of cozies)
/// holds a `key/create` coz and a `key/delete` coz, both validly signed by an
/// active key. Control: two `key/create` cozies in one transaction apply.
/// Turns red if a transaction of mixed `typ` is applied through `apply_tx`
/// (the only path that groups cozies). End to end: yes.
#[tokio::test]
async fn s4_1_transaction_cozies_must_share_one_typ() {
    let verified = |p: &Principal, coz: Signed, sidecar: Option<Key>, signer: &Kp| {
        let (pay, sig, czd) = coz;
        let key = p.get_key(&signer.tmb).expect("signer key").clone();
        cyphr::parsed_coz::verify_coz(&pay, &sig, &key, czd, sidecar).expect("verifies")
    };
    let (mut p, a, b) = two_key_principal().await;
    let (k3, k4) = (kp(), kp());
    let same = vec![
        verified(
            &p,
            sign(&a, key_create_pay(&a, &k3.tmb, T)),
            Some(key_of(&k3)),
            &a,
        ),
        verified(
            &p,
            sign(&a, key_create_pay(&a, &k4.tmb, T)),
            Some(key_of(&k4)),
            &a,
        ),
    ];
    p.begin_commit()
        .apply_tx(same)
        .expect("control: a same-typ transaction applies");

    let k5 = kp();
    let mixed = vec![
        verified(
            &p,
            sign(&a, key_create_pay(&a, &k5.tmb, T)),
            Some(key_of(&k5)),
            &a,
        ),
        verified(&p, sign(&a, key_delete_pay(&a, &b.tmb, T)), None, &a),
    ];
    // Applying each coz alone must succeed, so a rejection below is the mix.
    let solo = vec![mixed[0].clone()];
    p.fork()
        .await
        .expect("fork")
        .begin_commit()
        .apply_tx(solo)
        .expect("premise: each coz is valid alone");
    let r = p.begin_commit().apply_tx(mixed);
    assert!(
        matches!(r, Err(Error::MixedTransactionTyp)),
        "a mixed-typ transaction must fail with MixedTransactionTyp: {r:?}"
    );
}

// ============================================================================
// SPEC 6 (line 944): the private component is never transmitted
// ============================================================================

use proptest::prelude::*;

fn kp_alg(alg: coz::Alg) -> Kp {
    let k = alg.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Backs SPEC 6 ("`prv` ... never transmitted"): for any principal built
    /// from random keys of either algorithm, no serialized wire form (every
    /// coz of every commit, and every key as it travels in a sidecar)
    /// contains any key's private component, in base64url or hex. Property
    /// test: the invariant is over all key sets, and there is no scenario
    /// that enumerates them. Turns red if a wire type ever gains the private
    /// component (a `prv` field on `Key`, a signer copy in a coz).
    // @docket: sc-l944 :: scripts/docket-run sc-l944
    #[test]
    fn s6_no_wire_form_carries_private_key_material(
        algs in proptest::collection::vec(any::<bool>(), 2..5),
    ) {
        block_on(async move {
        let keys: Vec<Kp> = algs
            .iter()
            .map(|&ed| kp_alg(if ed { coz::Alg::Ed25519 } else { coz::Alg::ES256 }))
            .collect();
        let mut p = genesis_of(Principal::implicit(key_of(&keys[0])).await.expect("genesis"), &keys[0], &[]).await;
        let mut wire: Vec<String> = vec![];
        for (i, k) in keys.iter().enumerate().skip(1) {
            let now = T + i64::try_from(i).expect("small");
            let coz = sign(&keys[0], key_create_pay(&keys[0], &k.tmb, now));
            commit_one(&mut p, &keys[0], coz, Some(key_of(k)), now).await.expect("honest commit");
        }
        for c in p.commits() {
            for vc in c.all_cozies() {
                wire.push(serde_json::to_string(vc.raw()).expect("coz serializes"));
            }
        }
        for k in &keys {
            let needles = [
                Base64UrlUnpadded::encode_string(&k.prv),
                k.prv.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ];
            for w in &wire {
                for n in &needles {
                    prop_assert!(!w.contains(n.as_str()), "wire form carries a private component");
                }
            }
        }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

// ============================================================================
// SPEC 3.1 (line 298): a last-key self-revoke is allowed and leaves Dead
// ============================================================================

/// Backs SPEC 3.1 ("Self-revoke results in permanent lockout"), 11 (Dead is
/// "a consequence of any condition that leaves the principal with no keys")
/// and 14.1 (services that ignore revokes are out of compliance). Scenario:
/// the only key of a principal signs a self-`key/revoke`; the revoke is
/// accepted and the principal is Dead and takes nothing afterwards. Control:
/// with two keys the same revoke is accepted. Turns red if the only key's
/// revoke is refused, which leaves the compromised key live for anyone who
/// copied it. The golden vectors `lifecycle/last_key_revoke_leaves_dead` and
/// `lifecycle/dead_principal_rejects_commit` pin the same behaviour for
/// other implementations. End to end: yes.
// @docket: sc-l298 :: scripts/docket-run sc-l298
#[tokio::test]
async fn s3_1_last_key_self_revoke_is_accepted_and_leaves_the_principal_dead() {
    let (g, k2) = (kp(), kp());
    let mut two = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[key_of(&k2)],
    )
    .await;
    commit_one(
        &mut two,
        &g,
        sign(&g, revoke_pay(&g, T, json!(T))),
        None,
        T + 1,
    )
    .await
    .expect("control: a revoke with a second key left is accepted");

    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, revoke_pay(&g, T, json!(T))),
        None,
        T + 1,
    )
    .await;
    assert!(r.is_ok(), "the only key's self-revoke was refused: {r:?}");
    assert_eq!(p.lifecycle_state(), cyphr::lifecycle::LifecycleState::Dead);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T + 2)),
        Some(key_of(&k2)),
        T + 3,
    )
    .await;
    assert!(r.is_err(), "a dead principal took a key/create: {r:?}");
}

/// Backs SPEC 11 (Dead: "no transactions or actions are possible") for the
/// last-key revoke. Scenario: the only key of a principal records a data
/// action (control: accepted while alive), then self-revokes (must be
/// accepted), then tries a second action with the same, now revoked, key:
/// that must be refused and leave every observable counter untouched. A
/// second principal that kept a key shows the same action shape is still
/// accepted after a sibling's revoke, so the refusal is the Dead state and
/// not a blanket action ban. Turns red if the last-key revoke is refused,
/// or if a Dead principal records an action. Catches a lying fix
/// that gates only the transaction path and leaves actions open, and a
/// no-op fix that flags Dead without revoking the key. End to end: yes.
#[tokio::test]
async fn s3_1_dead_principal_after_last_key_revoke_records_no_action() {
    let action = |k: &Kp, now: i64| {
        sign(
            k,
            json!({"alg": k.alg, "msg": "hello", "now": now, "tmb": b64(&k.tmb),
                   "typ": "cyphr.me/comment/create"}),
        )
    };
    let record = |p: &mut Principal, k: &Kp, now: i64| {
        let (pay, sig, czd) = action(k, now);
        p.verify_and_record_action(&pay, &sig, czd).map(|_| ())
    };

    let (mut two, a, b) = two_key_principal().await;
    commit_one(
        &mut two,
        &b,
        sign(&b, revoke_pay(&b, T, json!(T))),
        None,
        T + 1,
    )
    .await
    .expect("control: a sibling's revoke is accepted");
    record(&mut two, &a, T + 2).expect("control: the surviving key still records actions");

    let g = kp();
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    record(&mut p, &g, T).expect("control: the lone key records an action while alive");
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, revoke_pay(&g, T + 1, json!(T + 1))),
        None,
        T + 2,
    )
    .await;
    assert!(r.is_ok(), "the only key's self-revoke was refused: {r:?}");
    let before = snapshot(&p);
    let r = record(&mut p, &g, T + 3);
    assert!(r.is_err(), "a dead principal recorded an action: {r:?}");
    assert_eq!(before, snapshot(&p), "a refused action changed state");
}

// ============================================================================
// SPEC 3.7 and 4.2: the roots of the commit that leaves a principal Dead
// ============================================================================

/// Variants of a root as an alg-to-bytes map, so roots of different types
/// compare by content.
fn variants_of(mh: &cyphr::multihash::MultihashDigest) -> BTreeMap<coz::HashAlg, Vec<u8>> {
    mh.variants()
        .iter()
        .map(|(a, d)| (*a, d.to_vec()))
        .collect()
}

/// Backs SPEC 3.7 (empty components are omitted; a lone child is promoted)
/// and 4.2 (the new PR is calculated after the commit). Scenario: a
/// principal with no data revokes its only key. With no key there is no KT,
/// so KR and AR are absent; with no DR there is no SR; with no SR the PR is
/// the promoted CR. The principal, its commit and its PR all say so. Turns
/// red if any of those roots is fabricated for a keyless principal (a
/// stale pre-death KR/AR or SR, an empty-set digest), or if PR differs
/// from CR. End to end: yes.
#[tokio::test]
async fn dead_principal_roots_are_absent_and_pr_is_cr_without_data() {
    let g = kp();
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    commit_one(
        &mut p,
        &g,
        sign(&g, revoke_pay(&g, T, json!(T))),
        None,
        T + 1,
    )
    .await
    .expect("the only key's revoke is accepted");
    assert!(p.key_root().is_none(), "dead principal has a KR");
    assert!(p.auth_root().is_none(), "dead principal has an AR");
    assert!(p.sr().is_none(), "dead principal without data has an SR");
    let commit = p.commits().last().expect("the dying commit");
    assert!(commit.auth_root().is_none(), "dying commit carries an AR");
    assert!(commit.sr().is_none(), "dying commit carries an SR");
    let cr = p.cr().expect("a commit exists, so CR exists");
    assert_eq!(
        variants_of(p.pr().as_multihash()),
        variants_of(cr.as_multihash()),
        "PR must be the promoted CR when SR is absent"
    );
    assert_eq!(commit.pr(), p.pr());
}

/// Backs SPEC 3.7 (SR = MR(AR, DR?); a lone child is promoted) for a
/// keyless principal that holds data. Scenario: a lone key records an
/// action (Level 4), then in one commit includes DR with `ds/create`
/// (SPEC 4.8.2) and revokes itself. AR is absent, so SR is the promoted
/// DR; KR and AR stay absent; PR is MR(SR, CR), different from both.
/// Turns red if SR is absent despite included data, SR differs from DR, or
/// PR drops SR. End to end: yes.
#[tokio::test]
async fn dead_principal_roots_state_root_is_the_data_root() {
    let g = kp();
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let (pay, sig, czd) = sign(
        &g,
        json!({"alg": g.alg, "msg": "hi", "now": T, "tmb": b64(&g.tmb),
               "typ": "cyphr.me/comment/create"}),
    );
    p.verify_and_record_action(&pay, &sig, czd).expect("action");
    let mut scope = p.begin_commit();
    let id = scope
        .data_tree_id()
        .expect("DT id")
        .expect("DT holds the action");
    let (pay, sig, czd) = sign(
        &g,
        json!({"alg": g.alg, "id": id, "now": T + 1, "tmb": b64(&g.tmb),
               "typ": "cyphr.me/cyphr/ds/create"}),
    );
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("ds/create");
    let (pay, sig, czd) = sign(&g, revoke_pay(&g, T + 1, json!(T + 1)));
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("the only key's revoke is accepted");
    scope
        .finalize_with_software(&software(&g), T + 2, "cyphr.me")
        .await
        .expect("the dying commit");
    assert!(p.key_root().is_none() && p.auth_root().is_none());
    let dr = p.data_root().expect("DR survives death");
    let sr = p.sr().expect("data makes an SR");
    assert_eq!(
        variants_of(sr.as_multihash()),
        variants_of(&dr.0),
        "SR must equal DR when AR is absent"
    );
    let commit = p.commits().last().expect("the dying commit");
    assert!(commit.auth_root().is_none());
    assert_eq!(commit.sr(), Some(sr));
    let cr = p.cr().expect("CR");
    let pr = variants_of(p.pr().as_multihash());
    assert_ne!(pr, variants_of(sr.as_multihash()));
    assert_ne!(pr, variants_of(cr.as_multihash()));
}

/// Backs SPEC 3.7 as ruled for the dying commit: its roots hash under
/// the algorithm set in force before the commit, since the post-commit set
/// is empty. Scenario: an ES256 and an ES384 key each self-revoke
/// in one commit, leaving no keys. PR, CR
/// and the commit's PR still carry both SHA-256 and SHA-384 variants. Turns
/// red if the dying commit hashes under the empty post-commit set (the
/// commit fails) or under only the signer's algorithm. End to end: yes.
#[tokio::test]
async fn dead_principal_roots_hash_under_the_pre_commit_algorithm_set() {
    let (a, b) = (kp_alg(coz::Alg::ES256), kp_alg(coz::Alg::ES384));
    let mut p = genesis_of(
        Principal::implicit(key_of(&a)).await.expect("genesis"),
        &a,
        &[key_of(&b)],
    )
    .await;
    let both: BTreeSet<coz::HashAlg> = [coz::HashAlg::Sha256, coz::HashAlg::Sha384]
        .into_iter()
        .collect();
    let algs_of = |mh: &cyphr::multihash::MultihashDigest| -> BTreeSet<coz::HashAlg> {
        mh.variants().keys().copied().collect()
    };
    assert_eq!(algs_of(p.pr().as_multihash()), both, "control: genesis set");
    let mut scope = p.begin_commit();
    for (k, now) in [(&a, T), (&b, T + 1)] {
        let (pay, sig, czd) = sign(k, revoke_pay(k, now, json!(now)));
        scope
            .verify_and_apply(&pay, &sig, czd, None)
            .expect("revoke");
    }
    scope
        .finalize_with_software(&software(&a), T + 2, "cyphr.me")
        .await
        .expect("the dying commit");
    assert_eq!(p.lifecycle_state(), cyphr::lifecycle::LifecycleState::Dead);
    assert_eq!(algs_of(p.pr().as_multihash()), both, "PR algorithm set");
    let cr = p.cr().expect("CR");
    assert_eq!(algs_of(cr.as_multihash()), both, "CR algorithm set");
    let commit = p.commits().last().expect("dying commit");
    assert_eq!(algs_of(commit.pr().as_multihash()), both);
}

/// Backs SPEC 11.2 ("Dead is a consequence of any condition that leaves the
/// principal with no keys"): deleting the last key, not only revoking it,
/// leaves the principal Dead. Scenario: a lone key signs a `key/delete` of
/// itself; the commit is accepted, the principal is Dead with KR, AR and SR
/// absent and PR equal to CR, and the deleted key then signs nothing (a
/// deleted key is unknown, not revoked). Control: with a second key the
/// same delete is accepted and the principal stays live. Turns red if the
/// delete is refused (`NoActiveKeys`), or if a Dead principal accepts a
/// commit. End to end: yes.
#[tokio::test]
async fn dead_principal_roots_key_delete_of_the_last_key_leaves_dead() {
    let (mut two, a, b) = two_key_principal().await;
    commit_one(
        &mut two,
        &a,
        sign(&a, key_delete_pay(&a, &b.tmb, T)),
        None,
        T + 1,
    )
    .await
    .expect("control: deleting one of two keys is accepted");
    assert_eq!(two.active_key_count(), 1);

    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_delete_pay(&g, &g.tmb, T)),
        None,
        T + 1,
    )
    .await;
    assert!(r.is_ok(), "deleting the only key was refused: {r:?}");
    assert_eq!(p.lifecycle_state(), cyphr::lifecycle::LifecycleState::Dead);
    assert!(p.key_root().is_none() && p.auth_root().is_none() && p.sr().is_none());
    let cr = p.cr().expect("CR");
    assert_eq!(
        variants_of(p.pr().as_multihash()),
        variants_of(cr.as_multihash()),
        "PR must be the promoted CR when SR is absent"
    );
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T + 2)),
        Some(key_of(&k2)),
        T + 3,
    )
    .await;
    assert!(r.is_err(), "a dead principal took a commit: {r:?}");
    assert_eq!(before, snapshot(&p));
}

/// Backs SPEC 11 (Dead is final: no transactions or actions) after the
/// dying commit finalizes, across the cold path too. Scenario: a Dead
/// principal (revoked in a commit) refuses a second commit signed by a
/// still-known key, with the typed revoked-key error, and nothing changes.
/// Turns red if a Dead principal accepts any further commit. End to end:
/// yes.
#[tokio::test]
async fn dead_principal_roots_are_final_no_further_commit() {
    let (g, k2) = (kp(), kp());
    let mut p = genesis_of(
        Principal::implicit(key_of(&g)).await.expect("genesis"),
        &g,
        &[],
    )
    .await;
    commit_one(
        &mut p,
        &g,
        sign(&g, revoke_pay(&g, T, json!(T))),
        None,
        T + 1,
    )
    .await
    .expect("dying commit");
    let before = snapshot(&p);
    let r = commit_one(
        &mut p,
        &g,
        sign(&g, key_create_pay(&g, &k2.tmb, T + 2)),
        Some(key_of(&k2)),
        T + 3,
    )
    .await;
    assert!(matches!(r, Err(Error::KeyRevoked)), "got {r:?}");
    assert_eq!(before, snapshot(&p));
}

// ============================================================================
// SPEC 10.2 (lines 1673-1674): a nonce's bit length matches its algorithm
// ============================================================================

/// Backs SPEC 10.2: "The nonce's bit length must match the declared
/// algorithm's output size (e.g., a nonce declared as SHA-256 must be 256
/// bits)." Scenario: for a SHA-256 (ES256), SHA-384 (ES384) and SHA-512
/// (Ed25519) principal, at each of the three nonce paths (PR, AT, KT), a
/// `nonce/create` whose `id` declares the principal's algorithm but whose
/// value is 0, 1, n-1, n+1, 2n bytes or another algorithm's width is
/// refused and leaves the principal untouched. Control: a value of exactly
/// n bytes is accepted at the same path, so the refusals are the width and
/// not a blanket ban. The `id` is the tagged `<alg>:<b64ut>` form.
/// Turns red if any width mismatch is accepted (a missing or one-sided
/// length check, such as `len >= n` or a check on the label alone), or if a
/// correct width is refused. RED: nonces are not implemented, so the
/// control fails first (`MalformedPayload`). End to end: yes.
// @docket: sc-l1673 :: scripts/docket-run sc-l1673
// @docket: sc-l1674 :: scripts/docket-run sc-l1674
#[tokio::test]
async fn s10_2_nonce_bit_length_must_match_the_declared_algorithm() {
    let algs = [
        (coz::Alg::ES256, "SHA-256", 32usize),
        (coz::Alg::ES384, "SHA-384", 48),
        (coz::Alg::Ed25519, "SHA-512", 64),
    ];
    let paths = ["cyphr", "cyphr/AT", "cyphr/AT/KT"];
    let nonce_coz = |g: &Kp, label: &str, path: &str, n: &[u8], now: i64| {
        sign(
            g,
            json!({"alg": g.alg, "id": format!("{label}:{}", Base64UrlUnpadded::encode_string(n)),
                   "now": now, "tmb": b64(&g.tmb), "typ": format!("cyphr.me/{path}/nonce/create")}),
        )
    };

    let mut accepted = vec![];
    for (alg, label, n) in algs {
        for path in paths {
            let g = kp_alg(alg);
            let mut ok = genesis_of(
                Principal::implicit(key_of(&g)).await.expect("genesis"),
                &g,
                &[],
            )
            .await;
            let control = commit_one(
                &mut ok,
                &g,
                nonce_coz(&g, label, path, &vec![0xA5; n], T),
                None,
                T + 1,
            )
            .await;
            assert!(
                control.is_ok(),
                "control: a {n}-byte {label} nonce at {path} was refused: {control:?}"
            );

            let mut widths = vec![0, 1, n - 1, n + 1, 2 * n, 32, 48, 64];
            widths.retain(|w| *w != n);
            widths.sort_unstable();
            widths.dedup();
            for w in widths {
                let mut p = genesis_of(
                    Principal::implicit(key_of(&g)).await.expect("genesis"),
                    &g,
                    &[],
                )
                .await;
                let before = snapshot(&p);
                let r = commit_one(
                    &mut p,
                    &g,
                    nonce_coz(&g, label, path, &vec![0xA5; w], T),
                    None,
                    T + 1,
                )
                .await;
                if r.is_ok() {
                    accepted.push(format!("{label} nonce of {w} bytes at {path}"));
                } else {
                    assert_eq!(before, snapshot(&p), "a refused {w}-byte nonce moved state");
                }
            }
        }
    }
    assert!(accepted.is_empty(), "width mismatch accepted: {accepted:?}");
}

/// Backs SPEC 6.4 for a revoke `now`: the range is inclusive at 2^53 - 1.
/// Scenario: under a clock past the range (so only the range binds), a
/// self-revoke at 2^53 - 1 is accepted and one at 2^53 is refused. Turns red
/// if the revoke range check rejects its own upper bound (or drops it). The
/// future-timestamp bound hides this from the system-clock tests above, so an
/// injected clock is the only way to reach it. End to end: yes.
#[tokio::test]
async fn s6_4_revoke_now_upper_bound_is_inclusive() {
    let runaway: cyphr::principal::Clock = || i64::MAX;
    revoke_outcome_at(Some(runaway), |b| revoke_pay(b, MAX_SAFE, json!(1)))
        .await
        .expect("a revoke at now = 2^53 - 1 is in range");
    assert!(
        revoke_outcome_at(Some(runaway), |b| revoke_pay(b, MAX_SAFE + 1, json!(1)))
            .await
            .is_err(),
        "a revoke at now = 2^53 was accepted"
    );
}

/// Drive one proptest case's async body: `proptest!` bodies are
/// synchronous, so each case runs on its own current-thread runtime.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime")
        .block_on(f)
}
