//! Explicit merge, SPEC 11.5.1 (zami branch, be0663f): a source signs
//! `principal/merge` (`merge_from`, `merge_to_pr`); the target accepts it
//! by signing `principal/merge-ack` carrying the same fields. The target
//! adds keys explicitly, AT is never merged implicitly, and the source
//! stays active. The ack exists to stop a "merge attack": an outsider
//! merging themselves into someone else's account.
//!
//! Every test authors its cozies as raw signed pays through the ordinary
//! commit path. Each rejection test opens with a valid-merge prelude (the
//! positive control, `a_merge_and_its_matching_ack_are_accepted`'s shape),
//! so a rejection cannot pass because the kind is simply unrecognised.
//!
//! Readings fixed here (the SPEC does not settle them; question for the
//! spec author, "Xammy"):
//! - `merge_from` is a JSON array of tagged PR strings, `merge_to_pr` one tagged PR string
//!   (`alg:b64ut`, the `principal/create` `id` form). SPEC prose says `merge_to` where the examples
//!   say `merge_to_pr`; the examples win.
//! - `merge_to_pr` and `merge_from` are the CURRENT PRs (SPEC 3.7.1: only PG is permanent), so they
//!   are point-in-time snapshots. These tests ack immediately after the merge, with the target
//!   unmoved; what happens when the target advances between merge and ack, and which PR in the
//!   target's history an ack may name, is left open for the spec author. The narrowest reading
//!   asserted: an ack's `merge_to_pr` must be a PR the acking principal actually had.
//! - A merge is accepted into its signer's own chain on its own; it takes effect only for a
//!   verifier holding both chains, through `merge_status`.

use std::collections::BTreeSet;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::lifecycle::LifecycleState;
use cyphr::state::HashAlg;
use cyphr::{Error, Key, MergeStatus, ParsedCoz, Principal, merge_status};
use serde_json::{Value, json};
use test_fixtures::Pool;

const MERGE_TYP: &str = "cyphr.me/cyphr/principal/merge";
const ACK_TYP: &str = "cyphr.me/cyphr/principal/merge-ack";
const NOW: i64 = 1_700_000_000;

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

/// `p` with its genesis committed (SPEC 5.1: a commit chain begins with the
/// genesis key's `key/create` of itself, the `principal/create` and the
/// `commit/create`), signed by its genesis key `k`.
fn genesis_of(mut p: Principal, k: &Signer) -> Principal {
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pub_key, &k.tmb),
        1,
        "cyphr.me",
    )
    .expect("genesis commit");
    p
}

/// One principal under test: an implicit-genesis principal and its key.
struct Peer {
    signer: Signer,
    principal: Principal,
}

impl Peer {
    fn new(name: &str) -> Self {
        let signer = signer(name);
        let key = Key::new(
            signer.alg.clone(),
            signer.tmb.clone(),
            signer.pub_key.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(NOW);
        let principal = genesis_of(Principal::implicit(key).expect("implicit genesis"), &signer);
        Self { signer, principal }
    }

    fn pr(&self) -> String {
        self.principal.pr_tagged().expect("principal root")
    }

    fn active_tmbs(&self) -> BTreeSet<String> {
        self.principal
            .active_keys()
            .map(|k| k.tmb().to_b64())
            .collect()
    }

    /// Sign `pay` with this peer's key (alphabetical field order, matching
    /// the canonical form the verifier re-derives).
    fn sign(&self, pay: &Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        let bytes = serde_json::to_vec(pay).expect("serialize pay");
        let (sig, cad) = coz::sign_json(
            &bytes,
            &self.signer.alg,
            &self.signer.prv,
            &self.signer.pub_key,
        )
        .expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &self.signer.alg).expect("czd");
        (bytes, sig, czd)
    }

    /// Apply `pays` as one commit and finalize it.
    fn commit(&mut self, pays: &[Value], now: i64) -> Result<(), Error> {
        let with_keys: Vec<_> = pays.iter().map(|p| (p.clone(), None)).collect();
        self.commit_with_keys(with_keys, now)
    }

    /// As [`Peer::commit`], supplying the new key a `key/create` carries.
    fn commit_with_keys(&mut self, pays: Vec<(Value, Option<Key>)>, now: i64) -> Result<(), Error> {
        let signed: Vec<_> = pays
            .iter()
            .map(|(p, k)| (self.sign(p), k.clone()))
            .collect();
        let mut scope = self.principal.begin_commit();
        for ((bytes, sig, czd), key) in signed {
            scope.verify_and_apply(&bytes, &sig, czd, key)?;
        }
        scope.finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &self.signer.alg,
                &self.signer.prv,
                &self.signer.pub_key,
                &self.signer.tmb,
            ),
            now,
            "cyphr.me",
        )?;
        Ok(())
    }

    fn merge_pay(&self, from: &Value, to_pr: &Value, now: i64) -> Value {
        self.merge_shaped(MERGE_TYP, from, to_pr, now)
    }

    fn ack_pay(&self, from: &Value, to_pr: &Value, now: i64) -> Value {
        self.merge_shaped(ACK_TYP, from, to_pr, now)
    }

    fn merge_shaped(&self, typ: &str, from: &Value, to_pr: &Value, now: i64) -> Value {
        json!({
            "alg": self.signer.alg,
            "merge_from": from,
            "merge_to_pr": to_pr,
            "now": now,
            "tmb": self.signer.tmb.to_b64(),
            "typ": typ,
        })
    }

    fn last_commit_types(&self) -> Vec<String> {
        self.principal
            .commits()
            .last()
            .map(|c| {
                c.all_cozies()
                    .iter()
                    .filter_map(|vc| vc.raw().pay["typ"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Claim: merge needs both sides and changes only what it says (positive
/// control for every rejection test in this file). A source's `merge` and
/// the target's matching `merge-ack` are each accepted into their own
/// chains; afterwards the source is still active and the target holds
/// exactly the keys it held before (no implicit key or AT import).
///
/// Turns red if: the kind is unrecognised; the
/// merge deactivates or deletes the source; the merge or ack copies the
/// source's keys or actions into the target.
/// End-to-end scenario: yes (two principals, two commits).
#[test]
fn a_merge_and_its_matching_ack_are_accepted() {
    let mut source = Peer::new("alice");
    let mut target = Peer::new("bob");
    let (source_pr, target_pr) = (source.pr(), target.pr());
    let target_keys_before = target.active_tmbs();
    let target_actions_before = target.principal.action_count();
    let source_keys_before = source.active_tmbs();

    let from = json!([source_pr]);
    let to = json!(target_pr);

    let merge = source.merge_pay(&from, &to, NOW + 10);
    let r = source.commit(&[merge], NOW + 10);
    assert!(
        r.is_ok(),
        "SPEC 11.5.1: the source's principal/merge must be accepted into its chain: {r:?}"
    );
    assert_eq!(
        source.last_commit_types().first().map(String::as_str),
        Some(MERGE_TYP)
    );

    let ack = target.ack_pay(&from, &to, NOW + 20);
    let r = target.commit(&[ack], NOW + 20);
    assert!(
        r.is_ok(),
        "SPEC 11.5.1: the target's matching principal/merge-ack must be accepted: {r:?}"
    );
    assert_eq!(
        target.last_commit_types().first().map(String::as_str),
        Some(ACK_TYP)
    );

    assert_eq!(
        merge_status(&source.principal, &target.principal),
        MergeStatus::Merged,
        "SPEC 11.5.1: a merge and its equal ack, held together, are a merge"
    );
    assert_eq!(
        merge_status(&target.principal, &source.principal),
        MergeStatus::None,
        "the merge is directed: the target did not merge into the source"
    );

    // Source stays active unless explicitly deleted.
    assert_eq!(source.principal.lifecycle_state(), LifecycleState::Active);
    assert!(!source.principal.is_deleted());
    assert_eq!(
        source.active_tmbs(),
        source_keys_before,
        "merge does not alter the source's keys"
    );

    // The target adds keys explicitly; the merge adds none, and no AT.
    assert_eq!(
        target.active_tmbs(),
        target_keys_before,
        "SPEC 11.5.1: merge must not implicitly import the source's keys into the target"
    );
    assert!(!target.active_tmbs().contains(&source.signer.tmb.to_b64()));
    assert_eq!(
        target.principal.action_count(),
        target_actions_before,
        "SPEC 11.5.1: AT is not implicitly merged"
    );
}

/// Claim: an ack must be for the acking principal itself. A target that
/// signs an ack whose `merge_to_pr` names some OTHER principal has
/// acknowledged nothing about itself and must be refused.
///
/// Positive control: the prelude below is the matching ack of
/// `a_merge_and_its_matching_ack_are_accepted` and must be accepted first,
/// which is what keeps a never-accepting stub from passing the rejection
/// alone.
/// Turns red if: the ack kind is unrecognised (prelude fails); ack
/// verification ignores `merge_to_pr` (accept-everything mutant fails the
/// second assertion).
/// End-to-end scenario: yes (the ack is judged against the principal it
/// is committed to).
#[test]
fn an_ack_naming_another_target_is_refused() {
    let source = Peer::new("alice");
    let other = Peer::new("carol");
    let from = json!([source.pr()]);

    // Prelude (positive control): bob's ack for bob is accepted.
    let mut bob = Peer::new("bob");
    let own = json!(bob.pr());
    let good = bob.ack_pay(&from, &own, NOW + 20);
    let r = bob.commit(&[good], NOW + 20);
    assert!(
        r.is_ok(),
        "positive control: a self-targeted ack must be accepted: {r:?}"
    );

    // Same shape from a fresh bob, but naming carol as the target.
    let mut bob = Peer::new("bob");
    let before = bob.pr();
    let wrong = bob.ack_pay(&from, &json!(other.pr()), NOW + 20);
    let r = bob.commit(&[wrong], NOW + 20);
    assert!(
        r.is_err(),
        "SPEC 11.5.1: an ack whose merge_to_pr is not the acking principal must be refused"
    );
    assert_eq!(bob.pr(), before);
    assert_eq!(
        bob.principal.commits().count(),
        1,
        "a refused ack leaves no commit behind the genesis"
    );
}

/// Claim: `merge` and `merge-ack` are untrusted wire input with a fixed
/// shape: `merge_from` an array of tagged PRs, `merge_to_pr` a tagged PR.
/// Malformed shapes are refused, not coerced.
///
/// Positive control: the well-formed pair is accepted first.
/// Turns red if: the parser is unimplemented (prelude); it coerces a bare
/// string into a one-element list, accepts a missing target, or accepts a
/// non-digest element.
/// Not an end-to-end scenario: a table of parser boundary cases, kept
/// here because no multi-peer scenario reaches each malformed shape
/// cheaply.
#[test]
fn malformed_merge_fields_are_refused() {
    let source = Peer::new("alice");
    let target = Peer::new("bob");
    let (spr, tpr) = (source.pr(), target.pr());

    let mut ok = Peer::new("alice");
    let good = ok.merge_pay(&json!([spr]), &json!(tpr), NOW + 10);
    let r = ok.commit(&[good], NOW + 10);
    assert!(
        r.is_ok(),
        "positive control: a well-formed merge must be accepted: {r:?}"
    );

    let cases: Vec<(&str, Value, Value)> = vec![
        (
            "merge_from is a bare string, not a list",
            json!(spr),
            json!(tpr),
        ),
        (
            "merge_from element is not a tagged digest",
            json!(["not-a-digest"]),
            json!(tpr),
        ),
        (
            "merge_to_pr is not a tagged digest",
            json!([spr]),
            json!("not-a-digest"),
        ),
        ("merge_from is null", Value::Null, json!(tpr)),
        ("merge_to_pr is a list", json!([spr]), json!([tpr])),
    ];
    for (why, from, to) in cases {
        for typ in [MERGE_TYP, ACK_TYP] {
            let mut p = Peer::new(if typ == MERGE_TYP { "alice" } else { "bob" });
            let pay = p.merge_shaped(typ, &from, &to, NOW + 10);
            let r = p.commit(&[pay], NOW + 10);
            assert!(r.is_err(), "{typ}: must refuse: {why}");
        }
    }

    // A missing field is a different shape from a null one.
    for typ in [MERGE_TYP, ACK_TYP] {
        for drop in ["merge_from", "merge_to_pr"] {
            // The acking principal must be the ack's target, or self-targeting
            // would refuse it whatever field is missing.
            let mut p = Peer::new(if typ == MERGE_TYP { "alice" } else { "bob" });
            let mut pay = p.merge_shaped(typ, &json!([spr]), &json!(tpr), NOW + 10);
            pay.as_object_mut().expect("object").remove(drop);
            let r = p.commit(&[pay], NOW + 10);
            assert!(r.is_err(), "{typ}: must refuse a pay missing {drop}");
        }
    }
}

/// Claim: an ack matches by PR values, and the target need not be at the
/// PR it names: the ack may name any PR the target has held (architect
/// ruling on SPEC 11.5.1), including one before later commits, but never
/// a PR it never held.
///
/// Positive control: the earlier-PR ack is accepted; the
/// refusal follows it. A name-the-tip-only mutant fails the first
/// assertion; an accept-any-PR mutant fails the second.
/// End-to-end scenario: yes (target commits, then acks an older PR).
#[test]
fn an_ack_may_name_an_earlier_pr_of_the_target() {
    let source = Peer::new("alice");
    let from = json!([source.pr()]);
    let stranger = Peer::new("carol");

    let advance = |p: &mut Peer| {
        let k = signer("key_a");
        let pay = json!({
            "alg": p.signer.alg,
            "id": k.tmb.to_b64(),
            "now": NOW + 5,
            "tmb": p.signer.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/create",
        });
        let key = Key::new(k.alg.clone(), k.tmb.clone(), k.pub_key.clone())
            .expect("key binds its tmb")
            .with_first_seen(NOW + 5);
        p.commit_with_keys(vec![(pay, Some(key))], NOW + 5)
    };

    let mut bob = Peer::new("bob");
    let earlier = bob.pr();
    advance(&mut bob).expect("an ordinary commit advances the target");
    assert_ne!(bob.pr(), earlier);
    let ack = bob.ack_pay(&from, &json!(earlier), NOW + 20);
    let r = bob.commit(&[ack], NOW + 20);
    assert!(
        r.is_ok(),
        "SPEC 11.5.1: an ack may name a PR the target held earlier: {r:?}"
    );

    let mut bob = Peer::new("bob");
    advance(&mut bob).expect("an ordinary commit advances the target");
    let ack = bob.ack_pay(&from, &json!(stranger.pr()), NOW + 20);
    let r = bob.commit(&[ack], NOW + 20);
    assert!(
        r.is_err(),
        "SPEC 11.5.1: an ack naming a PR the target never held must be refused"
    );
}

/// Claim: `principal/merge-ack` is a different transaction from
/// `principal/merge`; the ack must never dispatch as a merge or the
/// reverse. `parse_kind` dispatches by `typ` suffix, so a careless
/// `ends_with("merge")` arm swallows `merge-ack` (or the reverse order
/// shadows `merge`).
///
/// Turns red if: either typ is unrecognised, or both parse to the same
/// kind.
/// Not an end-to-end scenario: the dispatch table has no scenario that
/// reaches the shadowing case without already trusting it.
#[test]
fn merge_and_merge_ack_parse_to_distinct_kinds() {
    let p = Peer::new("alice");
    let from = json!([p.pr()]);
    let to = json!(Peer::new("bob").pr());
    let parse = |pay: Value| {
        let pay: coz::Pay = serde_json::from_value(pay.clone()).expect("pay shape");
        ParsedCoz::from_pay(
            &pay,
            coz::Czd::from_bytes(vec![7; 32]),
            HashAlg::Sha256,
            coz::CozJson {
                pay: serde_json::to_value(&pay).expect("pay value"),
                sig: vec![0; 64],
            },
        )
    };
    let merge = parse(p.merge_pay(&from, &to, NOW));
    let ack = parse(p.ack_pay(&from, &to, NOW));
    let (merge, ack) = (
        merge.expect("SPEC 11.5.1: principal/merge must parse"),
        ack.expect("SPEC 11.5.1: principal/merge-ack must parse"),
    );
    assert_ne!(
        format!("{}", merge.kind()),
        format!("{}", ack.kind()),
        "merge and merge-ack must be distinct kinds"
    );
}

/// Claim: `merge_status` recognises a merge exactly when the source's merge
/// and the target's ack agree, and reports an unanswered merge as Pending.
/// Alice merges into Bob and Bob acks (Merged). Carol merges into Diana
/// but Diana's ack names Alice (Pending for carol; None for alice, whose
/// merge never named Diana). Eve acks Alice though Alice never named her
/// (None).
///
/// Turns red if: any ack matches any merge (accept-any mutant: alice/diana
/// or alice/eve become Merged), or Pending is never reported.
/// End-to-end scenario: yes (five principals, two chains per status).
#[test]
fn merge_status_distinguishes_merged_pending_and_none() {
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");
    let mut carol = Peer::new("carol");
    let mut diana = Peer::new("diana_es384");
    let mut eve = Peer::new("eve_ed25519");
    let (alice_pr, carol_pr) = (alice.pr(), carol.pr());
    let (bob_pr, diana_pr, eve_pr) = (bob.pr(), diana.pr(), eve.pr());

    for (src, from, to) in [
        (&mut alice, &alice_pr, &bob_pr),
        (&mut carol, &carol_pr, &diana_pr),
    ] {
        let pay = src.merge_pay(&json!([from]), &json!(to), NOW + 10);
        src.commit(&[pay], NOW + 10).expect("merge accepted");
    }
    for (who, to) in [
        (&mut bob, &bob_pr),
        (&mut diana, &diana_pr),
        (&mut eve, &eve_pr),
    ] {
        let pay = who.ack_pay(&json!([alice_pr]), &json!(to), NOW + 20);
        who.commit(&[pay], NOW + 20).expect("ack accepted");
    }

    let st = |s: &Peer, t: &Peer| merge_status(&s.principal, &t.principal);
    assert_eq!(st(&alice, &bob), MergeStatus::Merged);
    assert_eq!(st(&alice, &diana), MergeStatus::None);
    assert_eq!(st(&alice, &eve), MergeStatus::None);
    assert_eq!(st(&carol, &diana), MergeStatus::Pending);
}

/// Claim: an ack matches a merge only when `merge_from` is equal too, and
/// equality is order-sensitive (architect ruling on SPEC 11.5.1). Alice
/// merges from two PRs she held into Bob; acks differing only in
/// `merge_from` (reordered, shorter, a different PR) leave it Pending, and
/// the identical ack makes it Merged.
///
/// Turns red if: `merge_from` is ignored or compared as a set, or the
/// positive control (identical ack) is not Merged.
/// End-to-end scenario: yes.
#[test]
fn an_ack_differing_only_in_merge_from_does_not_merge() {
    let carol = Peer::new("carol");
    let mut alice = Peer::new("alice");
    let old = alice.pr();
    let k = signer("key_a");
    let key_pay = json!({
        "alg": alice.signer.alg,
        "id": k.tmb.to_b64(),
        "now": NOW + 5,
        "tmb": alice.signer.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let key = Key::new(k.alg.clone(), k.tmb.clone(), k.pub_key.clone())
        .expect("key binds its tmb")
        .with_first_seen(NOW + 5);
    alice
        .commit_with_keys(vec![(key_pay, Some(key))], NOW + 5)
        .expect("alice advances");
    let new = alice.pr();
    let bob_pr = Peer::new("bob").pr();

    let pay = alice.merge_pay(&json!([old, new]), &json!(bob_pr), NOW + 10);
    alice.commit(&[pay], NOW + 10).expect("merge accepted");

    let variants = [
        ("reordered", json!([new, old])),
        ("shorter", json!([old])),
        ("a different PR", json!([old, carol.pr()])),
    ];
    for (why, from) in variants {
        let mut bob = Peer::new("bob");
        let pay = bob.ack_pay(&from, &json!(bob_pr), NOW + 20);
        bob.commit(&[pay], NOW + 20)
            .expect("an unmatched ack is accepted");
        assert_eq!(
            merge_status(&alice.principal, &bob.principal),
            MergeStatus::Pending,
            "ack differing in merge_from ({why}) must not merge"
        );
    }

    let mut bob = Peer::new("bob");
    let pay = bob.ack_pay(&json!([old, new]), &json!(bob_pr), NOW + 20);
    bob.commit(&[pay], NOW + 20)
        .expect("identical ack accepted");
    assert_eq!(
        merge_status(&alice.principal, &bob.principal),
        MergeStatus::Merged,
        "positive control: the identical ack merges"
    );
}

/// Claim: an empty `merge_from` is malformed for both kinds (architect
/// ruling on SPEC 11.5.1): a merge from nothing names nothing.
///
/// Positive control: the same merge with one PR is accepted.
/// Turns red if: an empty list is accepted.
/// Not an end-to-end scenario: a parser boundary case.
#[test]
fn an_empty_merge_from_is_refused() {
    let tpr = Peer::new("bob").pr();
    let mut ok = Peer::new("alice");
    let pay = ok.merge_pay(&json!([ok.pr()]), &json!(tpr), NOW + 10);
    ok.commit(&[pay], NOW + 10).expect("positive control");
    for (typ, who) in [(MERGE_TYP, "alice"), (ACK_TYP, "bob")] {
        let mut p = Peer::new(who);
        let own = if typ == ACK_TYP { p.pr() } else { tpr.clone() };
        let pay = p.merge_shaped(typ, &json!([]), &json!(own), NOW + 10);
        assert!(
            p.commit(&[pay], NOW + 10).is_err(),
            "{typ}: empty merge_from"
        );
    }
}
