//! Explicit merge over the push path, SPEC 11.5.1 (zami branch, be0663f):
//! a source signs `principal/merge`, the target accepts with
//! `principal/merge-ack`; without the ack nothing happens to the target.
//!
//! The server holds both chains, so the cross-principal rules live here:
//! a merge never reaches its target uninvited, and an ack is accepted only
//! for a merge that was actually signed for it. The core-only rules
//! (shape, self-targeting, distinct kinds) are in
//! `rs/cyphr/tests/merge.rs`; read its header for the readings fixed.
//!
//! Merge cozies are authored through the core verifier first (the peer
//! helper applies them to a local `Principal` before exporting wire
//! blobs), so the first assertion of each test is the verifier half of
//! "push and verifier agree", and the server half follows. Each peer's
//! local `Principal` is the same chain the server holds, so
//! `merge_status` is asserted on the pair of local mirrors.
//!
//! The push-path tests are `RED(PGK)`: the storage engine routes a coz as a
//! transaction by `typ` substring (`is_transaction_typ`), which names no
//! `principal/merge*`, so a merge push is read as a data action and refused
//! as an empty commit. Adding `|| typ.contains("/principal/merge")` there
//! turns all five green (checked); drop the markers with that fix.

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Error, Key, MergeStatus, Principal, merge_status};
use cyphr_server::build_router;
use serde_json::{Value, json};

mod common;

use common::{attestor_server, get_json, implicit_principal_id, load_pool, post_json};

const MERGE_TYP: &str = "cyphr.me/cyphr/principal/merge";
const ACK_TYP: &str = "cyphr.me/cyphr/principal/merge-ack";

/// A client-side principal: pool key material plus a local `Principal`
/// that authors (and verifies) each commit before it goes on the wire.
struct Peer {
    name: String,
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
    tmb: coz::Thumbprint,
    principal: Principal,
    /// The genesis key must ride on the first commit's closing cozy.
    pushed_genesis: bool,
}

impl Peer {
    fn new(name: &str) -> Self {
        let pool = load_pool();
        let pk = pool.get(name).expect("pool key");
        let prv = Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("prv")).expect("prv b64");
        let pub_key = Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64");
        let tmb = pk.compute_tmb().expect("tmb");
        let key = Key::new(pk.alg.clone(), tmb.clone(), pub_key.clone()).expect("key binds tmb");
        Self {
            name: name.to_owned(),
            alg: pk.alg.clone(),
            prv,
            pub_key,
            tmb,
            principal: Principal::implicit(key).expect("implicit genesis"),
            pushed_genesis: false,
        }
    }

    /// The server-side id: the implicit genesis key's thumbprint (SPEC 3.1).
    fn id(&self) -> String {
        implicit_principal_id(&load_pool(), &self.name)
    }

    /// The CURRENT tagged PR (SPEC 3.7.1: it moves with every commit).
    fn pr(&self) -> String {
        self.principal.pr_tagged().expect("principal root")
    }

    fn sign(&self, pay: &Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
        // Alphabetical field order: the server re-canonicalizes before
        // verifying, so the signed bytes must already be in that order
        // whether or not serde_json preserves insertion order.
        let sorted: std::collections::BTreeMap<_, _> =
            pay.as_object().expect("pay object").iter().collect();
        let bytes = serde_json::to_vec(&sorted).expect("pay json");
        let (sig, cad) = coz::sign_json(&bytes, &self.alg, &self.prv, &self.pub_key).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &self.alg).expect("czd");
        (bytes, sig, czd)
    }

    fn pay(&self, typ: &str, fields: Value, now: i64) -> Value {
        let mut pay = json!({
            "alg": self.alg,
            "now": now,
            "tmb": self.tmb.to_b64(),
            "typ": typ,
        });
        pay.as_object_mut()
            .expect("object")
            .extend(fields.as_object().expect("fields object").clone());
        pay
    }

    fn key_create(&self, new_key: &str, now: i64) -> (Value, Option<Key>) {
        let pool = load_pool();
        let nk = pool.get(new_key).expect("new key in pool");
        let nk_pub = Base64UrlUnpadded::decode_vec(&nk.pub_key).expect("pub b64");
        let tmb = nk.compute_tmb().expect("tmb");
        let key = Key::new(nk.alg.clone(), tmb.clone(), nk_pub)
            .expect("key binds tmb")
            .with_first_seen(now);
        (
            self.pay(
                "cyphr.me/cyphr/key/create",
                json!({ "id": tmb.to_b64() }),
                now,
            ),
            Some(key),
        )
    }

    fn merge(&self, from: &[String], to_pr: &str, now: i64) -> (Value, Option<Key>) {
        (
            self.pay(
                MERGE_TYP,
                json!({ "merge_from": from, "merge_to_pr": to_pr }),
                now,
            ),
            None,
        )
    }

    fn ack(&self, from: &[String], to_pr: &str, now: i64) -> (Value, Option<Key>) {
        (
            self.pay(
                ACK_TYP,
                json!({ "merge_from": from, "merge_to_pr": to_pr }),
                now,
            ),
            None,
        )
    }

    /// Apply `pays` as one commit to the local principal and return the
    /// wire blobs for `/push`. The local principal advances even when the
    /// server later refuses, so a test that expects a refusal authors that
    /// commit on a peer it does not reuse.
    fn commit_blobs(
        &mut self,
        pays: Vec<(Value, Option<Key>)>,
        now: i64,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let signed: Vec<_> = pays
            .iter()
            .map(|(p, k)| (self.sign(p), k.clone()))
            .collect();
        let mut scope = self.principal.begin_commit();
        for ((bytes, sig, czd), key) in signed {
            scope.verify_and_apply(&bytes, &sig, czd, key)?;
        }
        scope.finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&self.alg, &self.prv, &self.pub_key, &self.tmb),
            now,
            "cyphr.me",
        )?;

        let entries = cyphr_storage::export_commits(&self.principal).expect("export commits");
        let entry = entries.last().expect("a commit after finalize");
        let mut key_idx = 0;
        let mut blobs: Vec<Value> = entry
            .cozies
            .iter()
            .map(|v| {
                let mut coz = v.clone();
                let typ = coz["pay"]["typ"].as_str().unwrap_or("");
                if cyphr::parsed_coz::typ::is_key_introducing(typ) && key_idx < entry.keys.len() {
                    let k = &entry.keys[key_idx];
                    coz.as_object_mut().expect("object").insert(
                        "key".to_owned(),
                        json!({ "alg": k.alg, "pub": k.pub_key, "tmb": k.tmb }),
                    );
                    key_idx += 1;
                }
                coz
            })
            .collect();
        if !self.pushed_genesis {
            // `resolve_genesis` needs the genesis key on the closing cozy.
            blobs
                .last_mut()
                .expect("closing cozy")
                .as_object_mut()
                .expect("object")
                .insert(
                    "key".to_owned(),
                    json!({
                        "alg": self.alg,
                        "pub": Base64UrlUnpadded::encode_string(&self.pub_key),
                        "tmb": self.tmb.to_b64(),
                    }),
                );
            self.pushed_genesis = true;
        }
        Ok(blobs
            .iter()
            .map(|b| serde_json::to_vec(b).expect("blob json"))
            .collect())
    }

    /// A copy that continues this peer's chain, for authoring a commit the
    /// honest peer's verifier would refuse.
    fn fork(&self) -> Self {
        Self {
            name: self.name.clone(),
            alg: self.alg.clone(),
            prv: self.prv.clone(),
            pub_key: self.pub_key.clone(),
            tmb: self.tmb.clone(),
            principal: self.principal.clone(),
            pushed_genesis: self.pushed_genesis,
        }
    }

    fn push_body(&self, blobs: &[Vec<u8>]) -> String {
        json!({
            "principal_id": self.id(),
            "blobs": blobs.iter().map(|b| Base64UrlUnpadded::encode_string(b)).collect::<Vec<_>>(),
        })
        .to_string()
    }
}

async fn push(app: &Router, peer: &Peer, blobs: &[Vec<u8>]) -> (StatusCode, Value) {
    post_json(app.clone(), "/push", peer.push_body(blobs)).await
}

/// Create the principal on the server: genesis key plus one added key.
async fn bootstrap(app: &Router, peer: &mut Peer, added_key: &str, now: i64) {
    let pays = vec![peer.key_create(added_key, now)];
    let blobs = peer
        .commit_blobs(pays, now)
        .expect("genesis commit authors");
    let (status, body) = push(app, peer, &blobs).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "genesis push of {}: {body:?}",
        peer.name
    );
}

/// The tip fields a merge must not move on a principal that did not ack.
async fn tip(app: &Router, peer: &Peer) -> Value {
    let (status, body) = get_json(app.clone(), &format!("/tip?pr={}", peer.id())).await;
    assert_eq!(status, StatusCode::OK, "tip of {}: {body:?}", peer.name);
    // The attestor server signs its responses; the payload is the same.
    let p = &body["payload"];
    json!({
        "pr": p["pr"], "sr": p["sr"], "ar": p["ar"], "cr": p["cr"],
        "commit_count": p["commit_count"],
    })
}

/// Green characterization: five principals (three key algorithms)
/// bootstrap, and an ordinary second commit pushes, over the helper every
/// RED test uses. Pins the harness so a RED failure is the merge kind's
/// absence, not a broken peer. Not an end-to-end scenario for merge.
#[tokio::test]
async fn harness_bootstraps_peers_and_pushes_a_plain_commit() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let names = ["alice", "bob", "carol", "diana_es384", "eve_ed25519"];
    let mut peers: Vec<Peer> = names.iter().map(|n| Peer::new(n)).collect();
    for p in &mut peers {
        bootstrap(&app, p, "key_a", 1_700_100_000).await;
    }
    let before = tip(&app, &peers[0]).await;
    let pays = vec![peers[0].key_create("key_b", 1_700_100_100)];
    let blobs = peers[0]
        .commit_blobs(pays, 1_700_100_100)
        .expect("plain commit authors");
    let (status, body) = push(&app, &peers[0], &blobs).await;
    assert!(
        status.is_success(),
        "plain second commit must push: {status} {body:?}"
    );
    let after = tip(&app, &peers[0]).await;
    assert_eq!(after["commit_count"], json!(2));
    assert_ne!(before["cr"], after["cr"]);
    // Server and local verifier name the same root in the same tagged form.
    assert_eq!(after["pr"], json!(peers[0].pr()));
}

/// Claim: merge needs both sides and changes only what it says (positive
/// control for every rejection test below). Source signs a merge, target
/// signs the matching ack; both are accepted over `/push`, the target's
/// auth root (key state) is untouched by either, the source remains
/// pushable (active), and the server's tip agrees with the local
/// verifier's commit count.
///
/// Turns red if: the kind is unrecognised by the verifier or the push
/// path ; the merge or ack changes the
/// target's key state (implicit key or AT import); the merge deactivates
/// the source; push and verifier disagree on acceptance.
/// End-to-end scenario: yes (two principals, push path, tips).
#[tokio::test]
#[ignore = "RED(PGK): storage is_transaction_typ does not route principal/merge*"]
async fn merge_with_matching_ack_is_accepted_end_to_end() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let mut source = Peer::new("alice");
    let mut target = Peer::new("bob");
    bootstrap(&app, &mut source, "key_a", 1_700_100_000).await;
    bootstrap(&app, &mut target, "key_b", 1_700_100_000).await;
    let (source_pr, target_pr) = (source.pr(), target.pr());
    let target_before = tip(&app, &target).await;

    let pays = vec![source.merge(std::slice::from_ref(&source_pr), &target_pr, 1_700_100_100)];
    let blobs = source.commit_blobs(pays, 1_700_100_100);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept principal/merge: {blobs:?}"
    );
    let (status, body) = push(&app, &source, &blobs.expect("checked")).await;
    assert!(
        status.is_success(),
        "the source's merge must push: {status} {body:?}"
    );

    let pays = vec![target.ack(&[source_pr], &target_pr, 1_700_100_200)];
    let blobs = target.commit_blobs(pays, 1_700_100_200);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept principal/merge-ack: {blobs:?}"
    );
    let (status, body) = push(&app, &target, &blobs.expect("checked")).await;
    assert!(
        status.is_success(),
        "the target's matching ack must push: {status} {body:?}"
    );

    assert_eq!(
        merge_status(&source.principal, &target.principal),
        MergeStatus::Merged,
        "SPEC 11.5.1: the merge and its equal ack, held together, are a merge"
    );

    let target_after = tip(&app, &target).await;
    assert_eq!(
        target_after["commit_count"],
        json!(2),
        "genesis plus the ack"
    );
    assert_eq!(
        target_after["ar"], target_before["ar"],
        "SPEC 11.5.1: merge+ack must not change the target's key state (no implicit key or AT \
         import)"
    );

    // The source stays active unless explicitly deleted: it still takes commits.
    let pays = vec![source.key_create("key_b", 1_700_100_300)];
    let blobs = source
        .commit_blobs(pays, 1_700_100_300)
        .expect("source authors after merging");
    let (status, body) = push(&app, &source, &blobs).await;
    assert!(
        status.is_success(),
        "a merged source must stay active: {status} {body:?}"
    );
}

/// Claim: the ack prevents a "merge attack": an outsider's `merge` naming
/// a victim leaves the victim untouched and still able to write.
///
/// Positive control: `merge_with_matching_ack_is_accepted_end_to_end`
/// (a valid merge plus its ack IS a merge); the prelude here also needs
/// the attacker's merge to be accepted into the attacker's own chain,
///
/// Turns red if: a merge is accepted without the ack and still moves the
/// target (any of pr, sr, ar, cr, commit_count changes on the victim),
/// or it wedges the victim's next ordinary commit.
/// End-to-end scenario: yes.
#[tokio::test]
#[ignore = "RED(PGK): storage is_transaction_typ does not route principal/merge*"]
async fn merge_without_ack_leaves_the_target_untouched() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let mut attacker = Peer::new("carol");
    let mut victim = Peer::new("bob");
    bootstrap(&app, &mut attacker, "key_a", 1_700_100_000).await;
    bootstrap(&app, &mut victim, "key_b", 1_700_100_000).await;
    let victim_before = tip(&app, &victim).await;

    let pays = vec![attacker.merge(&[attacker.pr()], &victim.pr(), 1_700_100_100)];
    let blobs = attacker.commit_blobs(pays, 1_700_100_100);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept principal/merge: {blobs:?}"
    );
    let (status, body) = push(&app, &attacker, &blobs.expect("checked")).await;
    assert!(
        status.is_success(),
        "an unsolicited merge is accepted into the attacker's chain: {status} {body:?}"
    );

    assert_eq!(
        merge_status(&attacker.principal, &victim.principal),
        MergeStatus::Pending,
        "the merge is signed and names the victim, but the victim has not acked"
    );
    assert_eq!(
        tip(&app, &victim).await,
        victim_before,
        "SPEC 11.5.1: a merge without the target's ack must not change the target at all"
    );

    let pays = vec![victim.key_create("alice", 1_700_100_200)];
    let blobs = victim
        .commit_blobs(pays, 1_700_100_200)
        .expect("victim authors");
    let (status, body) = push(&app, &victim, &blobs).await;
    assert!(
        status.is_success(),
        "the victim must still be able to write: {status} {body:?}"
    );
}

/// Claim: an ack makes a merge only when it matches one actually signed
/// for it (equal `merge_from` and `merge_to_pr`); an unmatched ack is
/// still the target's own valid commit, accepted and producing no merge.
/// Alice merges into Bob; Carol merges into Diana. Bob's ack naming Alice
/// is the matching one (positive control). Diana acking Alice
/// (`merge_from` she never merged from) and Eve acking Alice (a merge that
/// never named Eve) are accepted as commits that change no key state.
///
/// Positive control: Bob's matching ack in the prelude.
/// Turns red if: the ack kind is unrecognised (prelude); an unmatched ack
/// is refused, or alters key state or the commit count by other than one.
/// The `merge_status` assertions at the end tell apart the mutant that
/// treats any ack as a merge.
/// End-to-end scenario: yes.
#[tokio::test]
#[ignore = "RED(PGK): storage is_transaction_typ does not route principal/merge*"]
async fn an_unmatched_ack_is_accepted_but_makes_no_merge() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");
    let mut carol = Peer::new("carol");
    let mut diana = Peer::new("diana_es384");
    let mut eve = Peer::new("eve_ed25519");
    for p in [&mut alice, &mut bob, &mut carol, &mut diana, &mut eve] {
        bootstrap(&app, p, "key_a", 1_700_100_000).await;
    }
    let (alice_pr, carol_pr) = (alice.pr(), carol.pr());
    let (bob_pr, diana_pr, eve_pr) = (bob.pr(), diana.pr(), eve.pr());

    for (src, from, to) in [
        (&mut alice, &alice_pr, &bob_pr),
        (&mut carol, &carol_pr, &diana_pr),
    ] {
        let pays = vec![src.merge(std::slice::from_ref(from), to, 1_700_100_100)];
        let blobs = src.commit_blobs(pays, 1_700_100_100);
        assert!(
            blobs.is_ok(),
            "SPEC 11.5.1: the verifier must accept principal/merge: {blobs:?}"
        );
        let (status, body) = push(&app, src, &blobs.expect("checked")).await;
        assert!(status.is_success(), "merge must push: {status} {body:?}");
    }

    // Positive control: the matching ack.
    let pays = vec![bob.ack(std::slice::from_ref(&alice_pr), &bob_pr, 1_700_100_200)];
    let blobs = bob.commit_blobs(pays, 1_700_100_200);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept principal/merge-ack: {blobs:?}"
    );
    let (status, body) = push(&app, &bob, &blobs.expect("checked")).await;
    assert!(
        status.is_success(),
        "the matching ack must push: {status} {body:?}"
    );

    // An ack with no matching merge is the target's own signed statement:
    // it is accepted into the target's chain and makes no merge (architect
    // ruling on SPEC 11.5.1). Each target is fresh so no commit is reused.
    for (who, to, why) in [
        (
            &mut diana,
            &diana_pr,
            "merge_from names alice, but diana's merge came from carol",
        ),
        (
            &mut eve,
            &eve_pr,
            "alice's merge never named eve as merge_to_pr",
        ),
    ] {
        let before = tip(&app, who).await;
        let pays = vec![who.ack(std::slice::from_ref(&alice_pr), to, 1_700_100_200)];
        let blobs = who
            .commit_blobs(pays, 1_700_100_200)
            .expect("locally well-formed");
        let (status, body) = push(&app, who, &blobs).await;
        assert!(
            status.is_success(),
            "an unmatched ack is still the target's own valid commit ({why}): {status} {body:?}"
        );
        let after = tip(&app, who).await;
        assert_eq!(
            after["commit_count"].as_u64(),
            before["commit_count"].as_u64().map(|n| n + 1),
            "the unmatched ack lands as exactly one commit ({why})"
        );
        assert_eq!(
            after["ar"], before["ar"],
            "an ack never changes key state ({why})"
        );
    }

    // The accept-any-ack mutant is told apart here: only bob's ack equals
    // a merge on both fields.
    assert_eq!(
        merge_status(&alice.principal, &bob.principal),
        MergeStatus::Merged,
        "bob acked alice's merge"
    );
    assert_eq!(
        merge_status(&alice.principal, &diana.principal),
        MergeStatus::None,
        "alice's merge never named diana; diana's ack matches nothing"
    );
    assert_eq!(
        merge_status(&alice.principal, &eve.principal),
        MergeStatus::None,
        "alice never named eve"
    );
    assert_eq!(
        merge_status(&carol.principal, &diana.principal),
        MergeStatus::Pending,
        "carol merged into diana; diana's ack named alice, not carol"
    );
}

/// Claim: an ack may name an earlier PR the target held (not only its
/// tip), and the push path accepts it. The refusal of a PR the target
/// never held is asserted in `rs/cyphr/tests/merge.rs`
/// (`an_ack_may_name_an_earlier_pr_of_the_target`) and, at the wire, in
/// `forged_ack_naming_a_never_held_pr_is_refused_over_push`.
///
/// Positive control: this test is itself the accepted case.
/// Turns red if: the kind is unrecognised, or only the tip PR is accepted.
/// End-to-end scenario: yes.
#[tokio::test]
#[ignore = "RED(PGK): storage is_transaction_typ does not route principal/merge*"]
async fn an_ack_naming_an_earlier_pr_is_accepted_over_push() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");
    bootstrap(&app, &mut alice, "key_a", 1_700_100_000).await;
    bootstrap(&app, &mut bob, "key_b", 1_700_100_000).await;
    let (alice_pr, earlier) = (alice.pr(), bob.pr());

    let pays = vec![alice.merge(std::slice::from_ref(&alice_pr), &earlier, 1_700_100_100)];
    let blobs = alice.commit_blobs(pays, 1_700_100_100);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept principal/merge: {blobs:?}"
    );
    let (status, body) = push(&app, &alice, &blobs.expect("checked")).await;
    assert!(status.is_success(), "merge must push: {status} {body:?}");

    let pays = vec![bob.key_create("alice", 1_700_100_150)];
    let blobs = bob.commit_blobs(pays, 1_700_100_150).expect("bob advances");
    let (status, body) = push(&app, &bob, &blobs).await;
    assert!(status.is_success(), "plain commit: {status} {body:?}");
    assert_ne!(bob.pr(), earlier);

    let pays = vec![bob.ack(std::slice::from_ref(&alice_pr), &earlier, 1_700_100_200)];
    let blobs = bob.commit_blobs(pays, 1_700_100_200);
    assert!(
        blobs.is_ok(),
        "SPEC 11.5.1: the verifier must accept an ack naming an earlier PR: {blobs:?}"
    );
    let (status, body) = push(&app, &bob, &blobs.expect("checked")).await;
    assert!(
        status.is_success(),
        "an ack naming an earlier PR must push: {status} {body:?}"
    );
    assert_eq!(
        merge_status(&alice.principal, &bob.principal),
        MergeStatus::Merged,
        "an ack of an earlier PR the target held matches the merge naming it"
    );
}

/// Claim: an ack is refused at the wire when its `merge_to_pr` is a PR the
/// target never held, with a typed 4xx and no change to the target. Bob's
/// own verifier refuses such an ack, so the commit is authored on a copy
/// of bob's chain that believes carol's PR was bob's (`pretend_held`) and
/// pushed to the real bob. The refusal must not wedge bob: his honest ack
/// of alice's merge pushes afterwards and the merge completes.
///
/// Turns red if: the ack is accepted into bob's chain (accept-any-PR
/// mutant), the refusal is not a typed 4xx, or it changes bob's tip.
/// End-to-end scenario: yes (forged commit over HTTP, then recovery).
#[tokio::test]
#[ignore = "RED(PGK): storage is_transaction_typ does not route principal/merge*"]
async fn forged_ack_naming_a_never_held_pr_is_refused_over_push() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);
    let mut alice = Peer::new("alice");
    let mut bob = Peer::new("bob");
    let mut carol = Peer::new("carol");
    bootstrap(&app, &mut alice, "key_a", 1_700_100_000).await;
    bootstrap(&app, &mut bob, "key_b", 1_700_100_000).await;
    bootstrap(&app, &mut carol, "key_a", 1_700_100_000).await;
    let (alice_pr, bob_pr, carol_pr) = (alice.pr(), bob.pr(), carol.pr());

    let pays = vec![alice.merge(std::slice::from_ref(&alice_pr), &bob_pr, 1_700_100_100)];
    let blobs = alice
        .commit_blobs(pays, 1_700_100_100)
        .expect("merge authors");
    let (status, body) = push(&app, &alice, &blobs).await;
    assert!(status.is_success(), "merge must push: {status} {body:?}");

    // Positive control: the honest peer's verifier refuses the forgery.
    let mut honest = bob.fork();
    let pays = vec![honest.ack(std::slice::from_ref(&alice_pr), &carol_pr, 1_700_100_200)];
    assert!(
        honest.commit_blobs(pays, 1_700_100_200).is_err(),
        "an honest verifier refuses an ack naming a PR it never held"
    );

    let mut forger = bob.fork();
    forger.principal.pretend_held(carol.principal.pr().clone());
    let pays = vec![forger.ack(std::slice::from_ref(&alice_pr), &carol_pr, 1_700_100_200)];
    let blobs = forger
        .commit_blobs(pays, 1_700_100_200)
        .expect("the believing copy authors the forgery");
    let before = tip(&app, &bob).await;
    let (status, body) = push(&app, &forger, &blobs).await;
    assert!(
        status.is_client_error(),
        "a forged ack must be a typed 4xx: {status} {body:?}"
    );
    assert!(
        body["payload"]["error"]
            .as_str()
            .is_some_and(|e| e.contains("state mismatch")),
        "the refusal names its cause: {body:?}"
    );
    assert_eq!(
        tip(&app, &bob).await,
        before,
        "a refused ack leaves bob's chain untouched"
    );

    let pays = vec![bob.ack(&[alice_pr], &bob_pr, 1_700_100_300)];
    let blobs = bob
        .commit_blobs(pays, 1_700_100_300)
        .expect("honest ack authors");
    let (status, body) = push(&app, &bob, &blobs).await;
    assert!(
        status.is_success(),
        "bob is not wedged by the refusal: {status} {body:?}"
    );
    assert_eq!(
        merge_status(&alice.principal, &bob.principal),
        MergeStatus::Merged
    );
}
