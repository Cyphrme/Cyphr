//! SPEC 6.2 / 6.5: a data action counts when its signer was authorized at
//! the action's own `now`, judged against the whole key timeline. Whether
//! one counts is therefore a function of the commits and the actions a
//! principal holds, never of the order they arrived in: a commit dated
//! before an action already held can remove its signer (and a later one can
//! restore it), and a principal that never restarted answers as a replay of
//! its history does.
//!
//! Every test builds one record two ways: live (arrival order, the
//! actions admitted as they come) and rebuilt (every commit, then each held
//! action: what a restart, a peer or an export does), and holds the
//! actions DT shows and the roots to be equal. End to end: yes, through the
//! public API.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Principal;
use cyphr::replay::{WireBundle, replay_held};
use cyphr::signer::SoftwareSigner;
use proptest::prelude::*;
use serde_json::json;

const T: i64 = 1_700_000_000;

struct K {
    kp: coz::KeyPair,
    tmb: coz::Thumbprint,
}

fn k() -> K {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp.alg.compute_thumbprint(&kp.pub_bytes).expect("tmb");
    K { kp, tmb }
}

fn key(k: &K) -> cyphr::Key {
    cyphr::Key::new(
        k.kp.alg.name().to_string(),
        k.tmb.clone(),
        k.kp.pub_bytes.clone(),
    )
    .expect("key")
}

fn signer(k: &K) -> SoftwareSigner {
    SoftwareSigner::new(k.kp.alg.name(), &k.kp.prv_bytes, &k.kp.pub_bytes, &k.tmb)
}

fn sign(k: &K, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay bytes");
    let alg = k.kp.alg.name();
    let (sig, cad) = coz::sign_json(&v, alg, &k.kp.prv_bytes, &k.kp.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
    (v, sig, czd)
}

/// A data action signed by `k` at `now`.
struct Act {
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
}

fn act(k: &K, now: i64) -> Act {
    let (pay, sig, czd) = sign(
        k,
        json!({"alg": k.kp.alg.name(), "now": now, "tmb": Base64UrlUnpadded::encode_string(k.tmb.as_bytes()),
               "typ": "cyphr.me/cyphr/data/x"}),
    );
    Act { pay, sig, czd }
}

impl Act {
    fn blob(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "pay": serde_json::from_slice::<serde_json::Value>(&self.pay).expect("pay"),
            "sig": Base64UrlUnpadded::encode_string(&self.sig),
        }))
        .expect("blob")
    }
}

/// A commit by `by` of one transaction `typ` (naming `id`, introducing
/// `sidecar`), dated `now`. False if the principal refuses it.
async fn commit(
    p: &mut Principal,
    by: &K,
    typ: &str,
    id: Option<String>,
    sidecar: Option<cyphr::Key>,
    now: i64,
) -> bool {
    let mut pay = json!({"alg": by.kp.alg.name(), "now": now,
        "tmb": Base64UrlUnpadded::encode_string(by.tmb.as_bytes()),
        "typ": format!("cyphr.me/cyphr/{typ}")});
    if let Some(id) = id {
        pay["id"] = json!(id);
    }
    let (pay, sig, czd) = sign(by, pay);
    let mut scope = p.begin_commit();
    if scope.verify_and_apply(&pay, &sig, czd, sidecar).is_err() {
        return false;
    }
    scope
        .finalize_with_software(&signer(by), now, "cyphr.me")
        .await
        .is_ok()
}

fn b64(k: &K) -> String {
    Base64UrlUnpadded::encode_string(k.tmb.as_bytes())
}

async fn delete_key(p: &mut Principal, by: &K, victim: &K, now: i64) -> bool {
    commit(p, by, "key/delete", Some(b64(victim)), None, now).await
}

async fn create_key(p: &mut Principal, by: &K, new: &K, now: i64) -> bool {
    commit(p, by, "key/create", Some(b64(new)), Some(key(new)), now).await
}

/// A principal of genesis keys `g` and `a`, committed at `T`.
async fn genesis(g: &K, a: &K) -> Principal {
    let mut p = Principal::implicit(key(g)).await.expect("implicit");
    p.commit_genesis(&signer(g), &[key(a)], T, "cyphr.me")
        .await
        .expect("genesis commit");
    p
}

/// What a restart does: every commit of `p`, then each held action.
async fn rebuilt(g: &K, p: &Principal, held: &[&Act]) -> Principal {
    let mut r = Principal::implicit(key(g)).await.expect("implicit");
    for c in p.commits() {
        let bundle = WireBundle::of_commit(c).expect("bundle");
        replay_held(&mut r, &bundle.decode().expect("decode"))
            .await
            .expect("commit replays");
    }
    for a in held {
        hold(&mut r, a).await.expect("held action");
    }
    r
}

async fn hold(p: &mut Principal, a: &Act) -> Result<(), String> {
    let bundle = WireBundle::actions(vec![a.blob()]).decode().expect("decode");
    replay_held(p, &bundle)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn dt(p: &Principal) -> Vec<String> {
    let mut czds: Vec<String> = p.actions().map(|a| a.czd().to_b64()).collect();
    czds.sort();
    czds
}

fn czds(acts: &[&Act]) -> Vec<String> {
    let mut czds: Vec<String> = acts.iter().map(|a| a.czd.to_b64()).collect();
    czds.sort();
    czds
}

/// The live principal and the rebuilt one agree on DT and on every root.
async fn assert_rebuilt_equals_live(g: &K, p: &Principal, held: &[&Act], what: &str) {
    let r = rebuilt(g, p, held).await;
    assert_eq!(dt(p), dt(&r), "{what}: DT, live against rebuilt");
    assert_eq!(p.pr(), r.pr(), "{what}: PR");
    assert_eq!(p.sr(), r.sr(), "{what}: SR");
    assert_eq!(p.data_root(), r.data_root(), "{what}: DR");
}

/// SPEC 6.2 ("actions signed after it has been removed are ignored") and
/// 6.5, in both orders. An action by `a` at T+100 is held; a commit dated
/// T+50 then removes `a`: the action is out of DT, as it is in a rebuild
/// that applies the commit first. Red before the fix: the live principal
/// stored the verdict it reached on arrival.
#[tokio::test]
async fn a_commit_dated_before_a_held_action_removes_it_in_either_order() {
    let (g, a) = (k(), k());
    let late = act(&a, T + 100);

    // Arrival order 1: the action, then the commit.
    let mut p = genesis(&g, &a).await;
    p.verify_and_record_action(&late.pay, &late.sig, late.czd.clone())
        .expect("a is active when the action arrives");
    assert_eq!(dt(&p), czds(&[&late]), "premise: authorized on arrival");
    assert!(delete_key(&mut p, &g, &a, T + 50).await, "premise");
    assert!(dt(&p).is_empty(), "the commit removed a before the action");
    assert_rebuilt_equals_live(&g, &p, &[&late], "action then commit").await;

    // Arrival order 2: the commit, then the action as held history.
    let mut q = genesis(&g, &a).await;
    assert!(delete_key(&mut q, &g, &a, T + 50).await, "premise");
    hold(&mut q, &late).await.expect("held history is kept");
    assert!(dt(&q).is_empty());
    assert_eq!(p.sr(), q.sr(), "both orders reach one state");
}

/// SPEC 6.2: a key may have several active periods. Delete, void, re-add:
/// the action is back once the re-add restores the key at its `now`, and
/// out in between. Red before the fix: it was never out.
#[tokio::test]
async fn a_readded_key_restores_the_action_the_delete_voided() {
    let (g, a) = (k(), k());
    let late = act(&a, T + 100);
    let mut p = genesis(&g, &a).await;
    p.verify_and_record_action(&late.pay, &late.sig, late.czd.clone())
        .expect("arrives while a is active");
    assert!(delete_key(&mut p, &g, &a, T + 50).await);
    assert!(dt(&p).is_empty(), "voided by the delete");
    assert!(create_key(&mut p, &g, &a, T + 60).await);
    assert_eq!(dt(&p), czds(&[&late]), "restored by the re-add");
    assert_rebuilt_equals_live(&g, &p, &[&late], "delete, void, re-add").await;
}

/// A commit already held, dated T+50; an action dated T+10 by a key active
/// then arrives afterwards: it counts (its verdict is final), and the state
/// equals the one where it arrived first.
#[tokio::test]
async fn an_action_dated_before_a_held_commit_counts() {
    let (g, a) = (k(), k());
    let early = act(&g, T + 10);
    let mut p = genesis(&g, &a).await;
    assert!(delete_key(&mut p, &g, &a, T + 50).await);
    hold(&mut p, &early).await.expect("held");
    assert_eq!(dt(&p), czds(&[&early]));
    let mut q = genesis(&g, &a).await;
    q.verify_and_record_action(&early.pay, &early.sig, early.czd.clone())
        .expect("arrives first");
    assert!(delete_key(&mut q, &g, &a, T + 50).await);
    assert_eq!(dt(&p), dt(&q));
    assert_eq!((p.sr(), p.pr()), (q.sr(), q.pr()));
}

/// Forge #213: a signature dated exactly at a removal is judged after it,
/// in every arrival order. Red before the fix: arrival decided it.
#[tokio::test]
async fn an_action_dated_at_its_signers_removal_is_ignored_in_either_order() {
    let (g, a) = (k(), k());
    let tie = act(&a, T + 50);
    let mut p = genesis(&g, &a).await;
    p.verify_and_record_action(&tie.pay, &tie.sig, tie.czd.clone())
        .expect("arrives first");
    assert!(delete_key(&mut p, &g, &a, T + 50).await);
    let mut q = genesis(&g, &a).await;
    assert!(delete_key(&mut q, &g, &a, T + 50).await);
    hold(&mut q, &tie).await.expect("held");
    assert_eq!((dt(&p), dt(&q)), (Vec::new(), Vec::new()));
}

/// SPEC 14.9 and 11.4: every gate is judged at the action's own `now`. A
/// freeze (T+50, thawed T+80) voids the action dated inside it and not the
/// ones outside; a principal delete (T+120) voids what is dated after it.
#[tokio::test]
async fn freeze_thaw_and_delete_judge_each_action_at_its_own_now() {
    let (g, a) = (k(), k());
    let (before, inside, outside, after_delete) = (
        act(&g, T + 30),
        act(&g, T + 60),
        act(&g, T + 90),
        act(&g, T + 130),
    );
    let mut p = genesis(&g, &a).await;
    for x in [&before, &inside, &outside, &after_delete] {
        p.verify_and_record_action(&x.pay, &x.sig, x.czd.clone())
            .expect("arrives while open");
    }
    for (typ, now) in [("freeze/create", T + 50), ("freeze/delete", T + 80)] {
        let id = p.pr_tagged().expect("pr");
        assert!(commit(&mut p, &g, typ, Some(id), None, now).await, "{typ}");
    }
    assert_eq!(dt(&p), czds(&[&before, &outside, &after_delete]));
    let id = p.pr_tagged().expect("pr");
    assert!(commit(&mut p, &g, "principal/delete", Some(id), None, T + 120).await);
    assert_eq!(dt(&p), czds(&[&before, &outside]));
    assert_rebuilt_equals_live(
        &g,
        &p,
        &[&before, &inside, &outside, &after_delete],
        "freeze, thaw, delete",
    )
    .await;
}

/// One generated record: commits of non-decreasing `now` that create,
/// delete and re-add keys, and actions of arbitrary `now` by those keys.
#[derive(Debug, Clone)]
struct Script {
    /// (key index 1..3, create?) at `T + 10 * (i + 1)`; the dates tie when
    /// two commits share a step.
    commits: Vec<(usize, bool, i64)>,
    /// (key index 0..3, offset from `T`).
    actions: Vec<(usize, i64)>,
}

fn scripts() -> impl Strategy<Value = Script> {
    (
        proptest::collection::vec((1usize..3, any::<bool>(), 0i64..3), 1..6),
        proptest::collection::vec((0usize..3, 1i64..90), 1..6),
    )
        .prop_map(|(commits, actions)| {
            let mut at = 0;
            let commits = commits
                .into_iter()
                .map(|(k, create, step)| {
                    at += step * 10;
                    (k, create, 10 + at)
                })
                .collect();
            Script { commits, actions }
        })
}

/// The chain of `script` over `keys` (genesis `keys[0]`, `keys[1]` from the
/// genesis commit, `keys[2]` created later), and the commits that applied.
async fn build(keys: &[K], script: &Script) -> (Principal, Vec<(usize, bool, i64)>) {
    let mut p = genesis(&keys[0], &keys[1]).await;
    let mut applied = Vec::new();
    for &(i, create, at) in &script.commits {
        let ok = if create {
            create_key(&mut p, &keys[0], &keys[i], T + at).await
        } else {
            delete_key(&mut p, &keys[0], &keys[i], T + at).await
        };
        if ok {
            applied.push((i, create, at));
        }
    }
    (p, applied)
}

/// The oracle, sharing no code with the core: `keys[i]` counts for an
/// action dated `now` if, of the commits dated at or before `now`, its
/// last is a create (a signature dated at a removal is after it).
fn counts(applied: &[(usize, bool, i64)], i: usize, now: i64) -> bool {
    applied
        .iter()
        .filter(|&&(k, _, at)| k == i && T + at <= now)
        .last()
        .map_or(i < 2, |&(_, create, _)| create)
}

/// A principal of the first `n` commits of `p`, then every action of
/// `held` whose key it has seen: what a restart or a peer does.
async fn replayed(keys: &[K], p: &Principal, n: usize, held: &[(usize, i64, Act)]) -> Principal {
    let mut r = Principal::implicit(key(&keys[0])).await.expect("implicit");
    for c in p.commits().take(n) {
        let bundle = WireBundle::of_commit(c).expect("bundle");
        replay_held(&mut r, &bundle.decode().expect("decode"))
            .await
            .expect("commit replays");
    }
    for (i, _, a) in held {
        if r.held_key(&keys[*i].tmb) {
            hold(&mut r, a).await.expect("held");
        }
    }
    r
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Independent of arrival order, and equal to a brute-force reading of
    /// the commits: for any record, the actions DT shows are those the
    /// signer's key was on for at the action's `now`, whether the actions
    /// arrived between the commits or after every one of them, and at
    /// every prefix of the chain. Finality: an action dated before a
    /// prefix's last commit shows what it shows in the whole chain.
    #[test]
    fn dt_is_a_function_of_the_record_not_of_arrival(script in scripts()) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(async {
                let keys = [k(), k(), k()];
                let (chain, applied) = build(&keys, &script).await;
                let held: Vec<(usize, i64, Act)> = script
                    .actions
                    .iter()
                    .map(|&(i, off)| (i, off, act(&keys[i], T + off)))
                    .collect();

                let whole = replayed(&keys, &chain, applied.len() + 1, &held).await;
                for n in 1..=applied.len() + 1 {
                    let r = replayed(&keys, &chain, n, &held).await;
                    let seen = &applied[..n - 1];
                    let expected: Vec<&Act> = held
                        .iter()
                        .filter(|(i, off, _)| r.held_key(&keys[*i].tmb) && counts(seen, *i, T + off))
                        .map(|(.., a)| a)
                        .collect();
                    prop_assert_eq!(dt(&r), czds(&expected), "prefix {}", n);
                    let last = seen.last().map_or(T, |&(.., at)| T + at);
                    for (_, off, a) in held.iter().filter(|(_, off, _)| T + off < last) {
                        let _ = off;
                        prop_assert_eq!(
                            dt(&r).contains(&a.czd.to_b64()),
                            dt(&whole).contains(&a.czd.to_b64()),
                            "an action dated before the last commit changed verdict"
                        );
                    }
                }

                // Arrival: each action as soon as its key exists, between
                // the commits.
                let mut live = genesis(&keys[0], &keys[1]).await;
                let mut pending: Vec<&(usize, i64, Act)> = held.iter().collect();
                let mut commits = chain.commits().skip(1);
                loop {
                    let mut waiting = Vec::new();
                    for x in pending {
                        if live.held_key(&keys[x.0].tmb) {
                            hold(&mut live, &x.2).await.expect("held");
                        } else {
                            waiting.push(x);
                        }
                    }
                    pending = waiting;
                    let Some(c) = commits.next() else { break };
                    let bundle = WireBundle::of_commit(c).expect("bundle");
                    replay_held(&mut live, &bundle.decode().expect("decode"))
                        .await
                        .expect("commit replays");
                }
                prop_assert_eq!(dt(&live), dt(&whole), "arrival between the commits");
                prop_assert_eq!(live.sr(), whole.sr());
                Ok(())
            })?;
    }
}
