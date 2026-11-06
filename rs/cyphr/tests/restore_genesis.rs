//! Checkpoint restore and genesis-key validation (N12; nrd: "Reject all
//! mismatches" for the #154 identity binding).
//!
//! Two groups, each a RED suite (`cargo test -p cyphr --test restore_genesis
//! -- --ignored`), plus green controls that must stay green.
//!
//! - `genesis_*`: every genesis key is validated (a duplicate or unsupported key is refused, not
//!   dropped), and implicit and explicit genesis agree on a pre-revoked key. Holds under any
//!   fix-or-cut outcome for checkpoints.
//! - `restore_equals_replay_*`: a principal restored from a checkpoint cannot be told apart from
//!   the replayed one. These assume the FIX outcome. Under a CUT the whole group (and every other
//!   caller of `from_checkpoint*`) is deleted with the API, never weakened. All construction goes
//!   through the single [`restore`] helper: a fix that changes the constructor's signature (carry
//!   the reuse set, nonces, revoked set, floor, expected PR) edits that helper only; the assertions
//!   stay.
//!
//! Run the green controls with `cargo test -p cyphr --test restore_genesis`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::state::HashAlg;
use cyphr::{Key, Principal};
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

fn pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool")
}

fn pool_key(name: &str) -> Kp {
    let pool = pool();
    let pk = pool.get(name).expect("key in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    Kp {
        alg: pk.alg.clone(),
        pubb: d(&pk.pub_key),
        prv: pk.prv.as_deref().map(d).unwrap_or_default(),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
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

/// `Err` is the `Debug` text of the protocol error, so two principals'
/// outcomes compare directly.
type Outcome = Result<(), String>;

/// Verify and apply one coz, then (if `finalize`) finalize the commit.
/// Errors name their stage, so a refusal at apply (the protocol verdict
/// under test) is never confused with a failure to finalize.
fn drive(
    p: &mut Principal,
    signer: &Kp,
    parts: Signed,
    side: Option<Key>,
    now: i64,
    finalize: bool,
) -> Outcome {
    let (pay, sig, czd) = parts;
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, side)
        .map_err(|e| format!("apply: {e:?}"))?;
    if !finalize {
        return Ok(());
    }
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&signer.alg, &signer.prv, &signer.pubb, &signer.tmb),
            now,
            "cyphr.me",
        )
        .map(|_| ())
        .map_err(|e| format!("finalize: {e:?}"))
}

fn commit_one(
    p: &mut Principal,
    signer: &Kp,
    parts: Signed,
    side: Option<Key>,
    now: i64,
) -> Outcome {
    drive(p, signer, parts, side, now, true)
}

/// The verdict at apply alone: the scope is dropped unfinalized, so
/// repeated probes do not move the principal.
fn try_apply(p: &mut Principal, signer: &Kp, parts: Signed, side: Option<Key>) -> Outcome {
    drive(p, signer, parts, side, 0, false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Level {
    Pr,
    At,
    Kt,
}

const LEVELS: [Level; 3] = [Level::Pr, Level::At, Level::Kt];

fn nonce_typ(level: Level, verb: &str) -> String {
    let path = match level {
        Level::Pr => "cyphr",
        Level::At => "cyphr/AT",
        Level::Kt => "cyphr/AT/KT",
    };
    format!("cyphr.me/{path}/nonce/{verb}")
}

fn nonce_coz(level: Level, verb: &str, signer: &Kp, n: u8, now: i64) -> Signed {
    let id = format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[n; 32]));
    sign(
        signer,
        json!({"alg": signer.alg, "id": id, "now": now, "tmb": b64(&signer.tmb),
               "typ": nonce_typ(level, verb)}),
    )
}

fn key_create(signer: &Kp, id: &Kp, now: i64) -> Signed {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(&id.tmb), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/create"}),
    )
}

fn self_revoke(k: &Kp, now: i64) -> Signed {
    sign(
        k,
        json!({"alg": k.alg, "now": now, "rvk": now, "tmb": b64(&k.tmb),
               "typ": "cyphr.me/cyphr/key/revoke"}),
    )
}

/// The one place a checkpoint is taken and restored. Every key the live
/// principal knows (active and revoked) is handed over, with its commit
/// log. A fix that needs more inputs (expected PR, reuse set, nonces,
/// timestamp floor) changes this function and nothing else.
fn restore(live: &Principal, known: &[&Kp]) -> cyphr::error::Result<Principal> {
    let keys: Vec<Key> = known
        .iter()
        .filter_map(|k| live.get_key(&k.tmb).cloned())
        .collect();
    // `Some(empty trees)` is itself refused today (restoring a log with no
    // commits asks for a Commit Root of nothing); a checkpoint of a principal
    // with no commits carries no log.
    let trees = live.cr().map(|_| live.commit_trees().clone());
    Principal::from_checkpoint(live.pg().cloned(), live.auth_root().clone(), keys, trees)
}

/// Everything an observer can read that replay determines.
#[derive(Debug, PartialEq)]
struct View {
    pr: cyphr::PrincipalRoot,
    kr: cyphr::KeyRoot,
    ar: cyphr::AuthRoot,
    sr: Option<cyphr::StateRoot>,
    cr: Option<cyphr::CommitRoot>,
    active: Vec<String>,
    revoked: Vec<String>,
    lifecycle: String,
}

fn view(p: &Principal, known: &[&Kp]) -> View {
    let mut active: Vec<String> = p.active_keys().map(|k| b64(k.tmb())).collect();
    active.sort();
    let mut revoked: Vec<String> = known
        .iter()
        .filter(|k| p.is_key_revoked(&k.tmb))
        .map(|k| b64(&k.tmb))
        .collect();
    revoked.sort();
    View {
        pr: p.pr().clone(),
        kr: p.key_root().clone(),
        ar: p.auth_root().clone(),
        sr: p.sr().cloned(),
        cr: p.cr().cloned(),
        active,
        revoked,
        lifecycle: format!("{:?}", p.lifecycle_state()),
    }
}

// ============================================================================
// Genesis: every key validated; implicit and explicit agree
// ============================================================================

/// Claim: genesis refuses a duplicate key instead of silently collapsing
/// it. Turns red if a duplicate genesis key is dropped (the principal is
/// built from fewer keys than the caller named, so its roots differ from
/// what the caller computed). Not end-to-end: no scenario reaches the
/// constructor's argument check more cheaply.
#[test]
#[ignore = "RED(N12): explicit genesis collapses duplicate keys into the key map"]
fn genesis_refuses_duplicate_key() {
    let (g, a) = (pool_key("golden"), pool_key("key_a"));
    for keys in [
        vec![key_of(&g), key_of(&g)],
        vec![key_of(&g), key_of(&a), key_of(&g)],
    ] {
        let n = keys.len();
        let r = Principal::explicit(keys);
        assert!(
            matches!(r, Err(cyphr::Error::DuplicateKey)),
            "{n}-key genesis with a repeated key was not refused as DuplicateKey: {:?}",
            r.map(|p| p.active_key_count())
        );
    }
}

/// Characterization: an unsupported algorithm cannot reach genesis at
/// all, because `Key` refuses to exist for it (no thumbprint), so the
/// "validate every key's algorithm" duty is discharged by the type. Turns
/// red if `Key` starts admitting a key whose algorithm has no hash
/// algorithm, which would reopen the `keys[0]`-only check in genesis.
#[test]
fn genesis_unsupported_algorithm_is_unconstructible() {
    let bad = pool_key("unsupported_key");
    assert_eq!(bad.alg, "RS256", "premise: the pool's unsupported key");
    let r = Key::new(bad.alg.clone(), bad.tmb.clone(), bad.pubb.clone());
    assert!(matches!(r, Err(cyphr::Error::UnknownAlg)), "{r:?}");
}

/// Claim: both genesis paths give the same acceptance and the same
/// hash-algorithm set for a single pre-revoked genesis key. Turns red if
/// they diverge (today implicit counts the revoked key's algorithm,
/// explicit derives the set from active keys only, so they disagree on
/// the set or on acceptance). The agreed answer is the implementer's to
/// pick; this pins only that there is one.
#[test]
#[ignore = "RED(N12): implicit and explicit genesis disagree on a pre-revoked key"]
fn genesis_implicit_and_explicit_agree_on_pre_revoked_key() {
    let g = pool_key("golden");
    let revoked = key_of(&g).with_revocation(cyphr::key::Revocation { rvk: T, by: None });
    let summarize = |r: cyphr::error::Result<Principal>| -> Result<(Vec<HashAlg>, usize), String> {
        r.map(|p| (p.active_algs(), p.active_key_count()))
            .map_err(|e| format!("{e:?}"))
    };
    let implicit = summarize(Principal::implicit(revoked.clone()));
    let explicit = summarize(Principal::explicit(vec![revoked]));
    assert_eq!(
        implicit, explicit,
        "implicit and explicit genesis disagree on a pre-revoked genesis key"
    );
}

/// Green control for the agreed paths: one supported key gives the same
/// algorithm set through implicit and explicit genesis, and a mixed-algorithm
/// explicit genesis derives the union. Catches a "fix" that breaks the
/// ordinary genesis while tightening validation.
#[test]
fn genesis_control_valid_keys_agree_and_derive_algs() {
    for name in ["golden", "diana_es384", "eve_ed25519"] {
        let k = key_of(&pool_key(name));
        let i = Principal::implicit(k.clone()).expect("implicit");
        let e = Principal::explicit(vec![k]).expect("explicit");
        assert_eq!(i.active_algs(), e.active_algs(), "{name}: alg set");
        assert_eq!(i.pr(), e.pr(), "{name}: PR");
    }
    let mixed = Principal::explicit(vec![
        key_of(&pool_key("golden")),
        key_of(&pool_key("diana_es384")),
    ])
    .expect("mixed explicit");
    assert_eq!(mixed.active_algs(), vec![HashAlg::Sha256, HashAlg::Sha384]);
}

// ============================================================================
// Restore: bound to AR (nrd: "Reject all mismatches")
// ============================================================================

/// Claim: a checkpoint whose keys do not hash to its AR is refused, never
/// loaded. Turns red if the constructor trusts the supplied AR (a missing
/// key, an extra key and a foreign AR are all accepted today). Control:
/// the honest checkpoint loads. Not end-to-end: the constructor is the
/// unit that admits state, and no scenario reaches it more cheaply.
#[test]
#[ignore = "RED(N12): restore trusts the supplied AR instead of binding keys to it"]
fn restore_equals_replay_rejects_keys_not_bound_to_ar() {
    let (g, a, b) = (pool_key("golden"), pool_key("key_a"), pool_key("alice"));
    let mut live = Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut live, &g, key_create(&g, &a, T), Some(key_of(&a)), T).expect("add key_a");
    let ar = live.auth_root().clone();
    let trees = || Some(live.commit_trees().clone());
    let cp = |ar: &cyphr::AuthRoot, ks: Vec<Key>| {
        Principal::from_checkpoint(None, ar.clone(), ks, trees())
    };

    cp(&ar, vec![key_of(&g), key_of(&a)]).expect("control: honest checkpoint loads");
    assert!(
        cp(&ar, vec![key_of(&g)]).is_err(),
        "checkpoint missing a key was loaded"
    );
    assert!(
        cp(&ar, vec![key_of(&g), key_of(&a), key_of(&b)]).is_err(),
        "checkpoint with a key outside the AR was loaded"
    );
    let foreign = Principal::implicit(key_of(&b))
        .expect("other")
        .auth_root()
        .clone();
    assert!(
        cp(&foreign, vec![key_of(&g), key_of(&a)]).is_err(),
        "checkpoint under a foreign AR was loaded"
    );
}

// ============================================================================
// Restore: indistinguishable from replay
// ============================================================================

/// A principal with K2 (`key_a`) added then self-revoked, a PR nonce,
/// at T+1..T+4. Returns it with the keys it knows.
fn history() -> (Principal, Kp, Kp) {
    let (g, k2) = (pool_key("golden"), pool_key("key_a"));
    let mut p = Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        key_create(&g, &k2, T + 1),
        Some(key_of(&k2)),
        T + 1,
    )
    .expect("add");
    commit_one(
        &mut p,
        &g,
        nonce_coz(Level::Pr, "create", &g, 7, T + 2),
        None,
        T + 2,
    )
    .expect("nonce");
    commit_one(&mut p, &k2, self_revoke(&k2, T + 3), None, T + 4).expect("revoke");
    (p, g, k2)
}

/// Claim: a key revoked before the checkpoint is still refused after it
/// (SPEC 6.4), and the restored view equals the replayed one. Turns red
/// if restore loses the revoked set (the revoked key comes back active
/// and signs). End-to-end: genesis, add, revoke, checkpoint, then a
/// revoked-key signature and a re-add attempt.
#[test]
#[ignore = "RED(N12): restore loses the revoked set"]
fn restore_equals_replay_keeps_revoked_key_refused() {
    let (live, g, k2) = history();
    let mut r = restore(&live, &[&g, &k2]).expect("restore");
    assert!(
        r.is_key_revoked(&k2.tmb) && !r.is_key_active(&k2.tmb),
        "revoked key active again"
    );
    let by_revoked = try_apply(
        &mut r,
        &k2,
        nonce_coz(Level::At, "create", &k2, 9, T + 9),
        None,
    );
    assert!(
        by_revoked.as_ref().is_err_and(|e| e.contains("KeyRevoked")),
        "revoked key signed after restore: {by_revoked:?}"
    );
    let readd = try_apply(&mut r, &g, key_create(&g, &k2, T + 10), Some(key_of(&k2)));
    assert!(readd.is_err(), "revoked key re-added after restore");
    assert_eq!(
        view(&r, &[&g, &k2]),
        view(&live, &[&g, &k2]),
        "view after restore"
    );
}

/// Claim: a coz included before the checkpoint is refused as reuse after
/// it (SPEC 7.6), with the same error the replayed principal gives. Turns
/// red if restore starts with an empty reuse set. The coz is a nonce
/// create, so the only thing that can refuse it is the reuse set.
#[test]
#[ignore = "RED(N12): restore starts with an empty coz-reuse set"]
fn restore_equals_replay_refuses_included_coz() {
    let (mut live, g, k2) = history();
    let mut r = restore(&live, &[&g, &k2]).expect("restore");
    let again =
        |p: &mut Principal| try_apply(p, &g, nonce_coz(Level::Pr, "create", &g, 7, T + 2), None);
    let expected = again(&mut live);
    assert!(
        expected.as_ref().is_err_and(|e| e.contains("CozReuse")),
        "premise: the replayed principal refuses reuse: {expected:?}"
    );
    assert_eq!(
        again(&mut r),
        expected,
        "restored principal accepted an included coz"
    );
}

/// Claim: the timestamp floor survives the checkpoint (SPEC 14.1). Turns
/// red if restore resets the floor to 0, so a coz older than the last
/// included one is accepted.
#[test]
#[ignore = "RED(N12): restore resets the timestamp floor"]
fn restore_equals_replay_keeps_timestamp_floor() {
    let (mut live, g, k2) = history();
    let mut r = restore(&live, &[&g, &k2]).expect("restore");
    let stale =
        |p: &mut Principal| try_apply(p, &g, nonce_coz(Level::At, "create", &g, 11, T - 5), None);
    let expected = stale(&mut live);
    assert!(
        expected
            .as_ref()
            .is_err_and(|e| e.contains("TimestampPast")),
        "premise: the replayed principal enforces the floor: {expected:?}"
    );
    assert_eq!(
        stale(&mut r),
        expected,
        "restored principal accepted a stale coz"
    );
}

/// Claim: a principal restored from a checkpoint with commits behind it
/// can take the next commit, and lands on the same roots as the replayed
/// principal. Turns red if restore forgets how many commits the log
/// already holds (the next commit is checked against leaf 0 and refused
/// as a durable-leaf mismatch). No revocation, nonce or reuse involved,
/// so only the commit position is in play.
#[test]
#[ignore = "RED(N12): restore does not carry the commit position"]
fn restore_equals_replay_accepts_the_next_commit() {
    let (g, a, b) = (pool_key("golden"), pool_key("key_a"), pool_key("alice"));
    let mut live = Principal::implicit(key_of(&g)).expect("genesis");
    commit_one(&mut live, &g, key_create(&g, &a, T), Some(key_of(&a)), T).expect("add key_a");
    let mut r = restore(&live, &[&g, &a]).expect("restore");
    let step =
        |p: &mut Principal| commit_one(p, &g, key_create(&g, &b, T + 1), Some(key_of(&b)), T + 1);
    assert_eq!(step(&mut live), Ok(()), "premise");
    assert_eq!(
        step(&mut r),
        Ok(()),
        "next commit on the restored principal"
    );
    let all = [&g, &a, &b];
    assert_eq!(
        view(&r, &all),
        view(&live, &all),
        "views after the next commit"
    );
}

/// Claim: a nonce held at any level before the checkpoint is carried: the
/// restored roots equal the replayed roots at once and after a later
/// commit, and the nonce can be deleted. Turns red if restore derives
/// roots as if it held none (PR level moves PR, KT level moves KR, AT
/// level moves the next AR) or forgets it holds the nonce.
#[test]
#[ignore = "RED(N12): restore does not carry nonces"]
fn restore_equals_replay_carries_nonces_at_every_level() {
    for level in LEVELS {
        let (g, a, b) = (pool_key("golden"), pool_key("key_a"), pool_key("alice"));
        let mut live = Principal::implicit(key_of(&g)).expect("genesis");
        commit_one(&mut live, &g, key_create(&g, &a, T), Some(key_of(&a)), T).expect("add");
        commit_one(
            &mut live,
            &g,
            nonce_coz(level, "create", &g, 3, T + 1),
            None,
            T + 1,
        )
        .expect("nonce");
        let known = [&g, &a, &b];
        let mut r = restore(&live, &known[..2]).expect("restore");
        assert_eq!(
            view(&r, &known[..2]),
            view(&live, &known[..2]),
            "{level:?}: at restore"
        );

        let step = |p: &mut Principal| {
            commit_one(p, &g, key_create(&g, &b, T + 2), Some(key_of(&b)), T + 2)
        };
        assert_eq!(step(&mut live), Ok(()), "{level:?}: premise");
        assert_eq!(step(&mut r), Ok(()), "{level:?}: later commit on restored");
        assert_eq!(
            view(&r, &known),
            view(&live, &known),
            "{level:?}: after a later commit"
        );

        let del =
            |p: &mut Principal| try_apply(p, &g, nonce_coz(level, "delete", &g, 3, T + 3), None);
        assert_eq!(del(&mut live), Ok(()), "{level:?}: premise delete");
        assert_eq!(
            del(&mut r),
            Ok(()),
            "{level:?}: delete of a pre-checkpoint nonce"
        );
        commit_one(
            &mut live,
            &g,
            nonce_coz(level, "delete", &g, 3, T + 3),
            None,
            T + 3,
        )
        .expect("premise: delete commits");
        commit_one(
            &mut r,
            &g,
            nonce_coz(level, "delete", &g, 3, T + 3),
            None,
            T + 3,
        )
        .expect("delete commits on restored");
        assert_eq!(
            view(&r, &known),
            view(&live, &known),
            "{level:?}: after delete"
        );
    }
}

// ----------------------------------------------------------------------------
// Property over random histories
// ----------------------------------------------------------------------------

const NAMES: [&str; 5] = ["golden", "key_a", "alice", "bob", "carol"];

#[derive(Clone, Debug)]
enum Op {
    Add(usize),
    Revoke(usize),
    Nonce(usize, u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1usize..NAMES.len()).prop_map(Op::Add),
        (1usize..NAMES.len()).prop_map(Op::Revoke),
        (0usize..3, 0u8..4).prop_map(|(l, n)| Op::Nonce(l, n)),
    ]
}

/// One concrete, signed commit: who finalizes it, its coz, its sidecar.
struct Step {
    signer: usize,
    coz: Signed,
    side: Option<Key>,
    now: i64,
}

/// Turn raw ops into valid signed steps (invalid ops are skipped), with
/// strictly increasing timestamps. The golden key signs everything but
/// self-revocations.
fn steps(ops: &[Op], kps: &[Kp]) -> Vec<Step> {
    let mut added = vec![false; NAMES.len()];
    added[0] = true;
    let mut revoked = vec![false; NAMES.len()];
    let mut nonces = std::collections::HashSet::new();
    let mut out = Vec::new();
    for o in ops {
        let now = T + 10 * (out.len() as i64 + 1);
        match *o {
            Op::Add(i) if !added[i] => {
                added[i] = true;
                out.push(Step {
                    signer: 0,
                    coz: key_create(&kps[0], &kps[i], now),
                    side: Some(key_of(&kps[i])),
                    now,
                });
            },
            Op::Revoke(i) if added[i] && !revoked[i] => {
                revoked[i] = true;
                out.push(Step {
                    signer: i,
                    coz: self_revoke(&kps[i], now),
                    side: None,
                    now,
                });
            },
            Op::Nonce(l, n) if nonces.insert((l, n)) => out.push(Step {
                signer: 0,
                coz: nonce_coz(LEVELS[l], "create", &kps[0], n, now),
                side: None,
                now,
            }),
            _ => {},
        }
    }
    out
}

fn run(p: &mut Principal, s: &Step, kps: &[Kp]) -> Outcome {
    commit_one(p, &kps[s.signer], s.coz.clone(), s.side.clone(), s.now)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 24,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Claim: restored from a checkpoint taken after any prefix of a random
    /// history and then given the same later commits, a principal equals the
    /// replayed one (PR, KR, AR, SR, CR, key set, revoked set, lifecycle)
    /// after every commit and gives the same outcome to every step; every coz
    /// included before the checkpoint and a stale-timestamp coz get the
    /// replayed principal's verdict. Turns red if restore loses a revocation,
    /// a reuse record, a nonce or the timestamp floor. Property test over
    /// histories of key adds, self-revocations and nonces at all three levels.
    #[test]
    #[ignore = "RED(N12): restore loses revoked set, reuse set, nonces and floor"]
    fn restore_equals_replay_random_histories(
        ops in prop::collection::vec(op(), 1..10),
        split in any::<prop::sample::Index>(),
    ) {
        let kps: Vec<Kp> = NAMES.iter().map(|n| pool_key(n)).collect();
        let all: Vec<&Kp> = kps.iter().collect();
        let plan = steps(&ops, &kps);
        prop_assume!(!plan.is_empty());
        let k = split.index(plan.len() + 1);

        let mut live = Principal::implicit(key_of(&kps[0])).expect("genesis");
        for s in &plan[..k] {
            prop_assert_eq!(run(&mut live, s, &kps), Ok(()), "premise: history applies");
        }
        let mut r = restore(&live, &all).expect("restore");

        // Apply-stage verdicts on cozies already included and on a stale
        // one first: they leave both principals untouched and pin the reuse
        // set, floor and revoked set apart from the later commit counter.
        let probe = |p: &mut Principal, s: &Step| try_apply(p, &kps[s.signer], s.coz.clone(), s.side.clone());
        for s in &plan[..k] {
            prop_assert_eq!(probe(&mut r, s), probe(&mut live, s), "included coz");
        }
        let stale = Step {
            now: 0,
            signer: 0,
            coz: nonce_coz(Level::At, "create", &kps[0], 99, T - 5),
            side: None,
        };
        prop_assert_eq!(probe(&mut r, &stale), probe(&mut live, &stale), "stale coz");
        prop_assert_eq!(view(&r, &all), view(&live, &all), "view at restore");

        for s in &plan[k..] {
            prop_assert_eq!(run(&mut r, s, &kps), run(&mut live, s, &kps), "step outcome");
            prop_assert_eq!(view(&r, &all), view(&live, &all), "view after step");
        }
    }
}
