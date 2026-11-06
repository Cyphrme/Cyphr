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
//! blobs), so until the kind exists the first assertion of each RED test
//! fails there: that failure is the verifier half of "push and verifier
//! agree", and the server half follows once it passes.
//!
//! Run: `cd rs && cargo test -p cyphr-server --test merge -- --ignored`.

use axum::Router;
use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Error, Key, Principal};
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
/// path (today: the first assertion); the merge or ack changes the
/// target's key state (implicit key or AT import); the merge deactivates
/// the source; push and verifier disagree on acceptance.
/// End-to-end scenario: yes (two principals, push path, tips).
#[tokio::test]
#[ignore = "RED(MG1): SPEC 11.5.1"]
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
/// which is red today.
/// Turns red if: a merge is accepted without the ack and still moves the
/// target (any of pr, sr, ar, cr, commit_count changes on the victim),
/// or it wedges the victim's next ordinary commit.
/// End-to-end scenario: yes.
#[tokio::test]
#[ignore = "RED(MG1): SPEC 11.5.1"]
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

/// Claim: an ack is accepted only for a merge actually signed for it, and
/// a refused ack changes nothing. Alice merges into Bob; Carol merges
/// into Diana. Bob's ack naming Alice is the matching one (accepted,
/// positive control). Diana acking Alice (`merge_from` she never merged
/// from) and Eve acking Alice (a merge that never named Eve as
/// `merge_to_pr`) are both refused with a 4xx, leaving their tips equal.
///
/// Positive control: Bob's matching ack in the prelude (red today).
/// Turns red if: the ack kind is unrecognised (prelude); ack acceptance
/// ignores `merge_from` or `merge_to_pr` (accept-any-ack mutant fails the
/// refusals); a refusal still writes the ack (tip moves).
/// End-to-end scenario: yes.
/// Open question for the spec author: whether a pre-emptive ack (ack
/// before the merge exists) is legal; asserted here only as not-accepted
/// for a merge that does not exist.
#[tokio::test]
#[ignore = "RED(MG1): SPEC 11.5.1"]
async fn an_ack_must_match_a_merge_signed_for_it() {
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

    // Mismatches: each is a fresh target so no refused commit is reused.
    let diana_before = tip(&app, &diana).await;
    let eve_before = tip(&app, &eve).await;
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
        let pays = vec![who.ack(std::slice::from_ref(&alice_pr), to, 1_700_100_200)];
        let blobs = who
            .commit_blobs(pays, 1_700_100_200)
            .expect("locally well-formed");
        let (status, body) = push(&app, who, &blobs).await;
        assert!(
            status.is_client_error(),
            "ack must be refused ({why}): {status} {body:?}"
        );
    }
    assert_eq!(
        tip(&app, &diana).await,
        diana_before,
        "refused ack must leave diana untouched"
    );
    assert_eq!(
        tip(&app, &eve).await,
        eve_before,
        "refused ack must leave eve untouched"
    );
}
