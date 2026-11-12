//! Peer-chain scenarios for the client: a client pins a peer by PG and
//! genesis key, follows the peer's own chain over `/patch`, and judges every
//! statement the peer signs against the keys ACTIVE in the chain it holds.
//!
//! Every test here is an end-to-end scenario over the public API with an
//! in-test carrier (a `Connector` serving canned bodies) and real chains
//! built with `cyphr`. The wire shape the carrier serves (blob format, an unsigned
//! statement slot on `/patch`) is the one the server already uses for a
//! pushed commit; a chain is authenticated by replay against the pinned
//! genesis, not by the patch statement.

mod common;

use std::sync::atomic::AtomicI64;

use common::*;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{PeerChain, PeerFailure, PeerLimits};

/// Claim: a client that pinned a peer holds only what it has followed, so a
/// statement signed by a key the peer introduced LATER is refused until the
/// client follows once, after which the same statement is accepted, and a
/// key the followed chain still does not hold stays refused.
///
/// Turns red if: `follow` does not extend the held chain with the peer's
/// commits; `verify_tip` accepts a key the held chain lacks
/// (trusting the statement's own say-so); or `verify_tip_following` does not follow.
/// End-to-end scenario: yes (real chain replayed from a carrier).
#[tokio::test]
async fn follow_extends_the_chain_and_statements_verify_against_held_keys() {
    let g = kp();
    let k1 = kp();
    let outsider = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let pipe = Pipe::new(peer.patch(std::slice::from_ref(&c1)));
    let (pr, _) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;

    // Before following, the held chain is just the genesis: the later key
    // is unknown and the genesis key's own statements verify.
    let tip = tip_envelope(&k1);
    assert!(
        matches!(
            held.verify_tip(&tip, &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "a key the held chain has not seen must be refused before following"
    );
    assert!(
        held.verify_tip(&tip_envelope(&g), &pr).is_ok(),
        "the pinned genesis key verifies from the start"
    );

    held.follow(&pipe).await.expect("follow the peer chain");
    assert_eq!(pipe.exchanges(), 1, "one follow is one patch fetch");

    let report = held
        .verify_tip(&tip, &pr)
        .expect("the introduced key verifies after following");
    assert_eq!(report.sequence, 1);

    // A key the followed chain never held stays refused.
    assert!(matches!(
        held.verify_tip(&tip_envelope(&outsider), &pr),
        Err(PeerFailure::KeyNotActive { .. })
    ));
}

/// Claim: a statement signed by a key the peer chain NEVER held is refused
/// after one follow, and the client does not loop re-following: following
/// cannot conjure a key, so exactly one patch is fetched.
///
/// Turns red if: the key is accepted; the refusal surfaces as another
/// failure; or `verify_tip_following` fetches more than once.
/// End-to-end scenario: yes.
#[tokio::test]
async fn never_held_key_stays_refused_after_one_follow() {
    let g = kp();
    let k1 = kp();
    let outsider = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let pipe = Pipe::new(peer.patch(&[c1]));
    let (pr, _) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    let refused = held
        .verify_tip_following(&pipe, &tip_envelope(&outsider), &pr)
        .await;
    assert!(
        matches!(refused, Err(PeerFailure::KeyNotActive { .. })),
        "a never-held key must be refused: {refused:?}"
    );
    assert_eq!(pipe.exchanges(), 1, "one follow, no loop");

    // The follow was not wasted: a key the chain does hold now verifies.
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());
}

/// Claim: a patch that does not extend the held chain (a rival commit at a
/// position the client already holds) is refused as `Fork`, and the held
/// chain is left exactly as it was: keys it held still verify, keys only
/// the rival introduced do not, and an honest extension still follows.
///
/// Turns red if: the rival patch is merged or replaces the held commit
/// (I2: a fork is detected, never merged); `follow` errors with something
/// other than `Fork`; or a failed follow mutates the held chain.
/// End-to-end scenario: yes (two diverging histories under one PG).
#[tokio::test]
async fn rival_patch_is_a_fork_and_leaves_the_held_chain_unchanged() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let rival_key = kp();
    let mut honest = Chain::new(&g).await;
    let c1 = honest.commit(&k1, 1_700_000_100).await;
    let c2 = honest.commit(&k2, 1_700_000_200).await;
    let mut rival = Chain::new(&g).await;
    let r1 = rival.commit(&rival_key, 1_700_000_150).await;
    let (pr, _) = subject();

    let pipe = Pipe::new(honest.patch(std::slice::from_ref(&c1)));
    let mut held = PeerChain::pin(&honest.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("follow to the first commit");

    pipe.serve(rival.patch(&[r1]));
    let forked = held.follow(&pipe).await;
    assert!(
        matches!(forked, Err(PeerFailure::Fork { .. })),
        "a rival commit at a held position is a fork: {forked:?}"
    );

    assert!(
        held.verify_tip(&tip_envelope(&k1), &pr).is_ok(),
        "the held chain still holds its own key"
    );
    assert!(
        matches!(
            held.verify_tip(&tip_envelope(&rival_key), &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "nothing of the rival patch was kept"
    );

    pipe.serve(honest.patch(&[c1, c2]));
    held.follow(&pipe)
        .await
        .expect("an honest extension still follows after a refused fork");
    assert!(held.verify_tip(&tip_envelope(&k2), &pr).is_ok());
}

/// Claim: a pin whose PG does not derive from the genesis key it names is
/// refused as `PinMismatch` and nothing is adopted.
///
/// Turns red if: the pin is trusted without checking it against the genesis
/// key, so a client can be pinned to a chain its key does not root.
/// End-to-end scenario: no. Reason: the refusal is a single pure check on
/// the pin arguments; the in-server scenario covers the discovered-PG case.
#[tokio::test]
async fn pin_naming_another_pg_is_refused() {
    let g = kp();
    let k1 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let pipe = Pipe::new(peer.patch(&[c1]));

    let mut held = PeerChain::pin(&b64(5), g.domain_key(1_700_000_000)).await;
    let refused = held.follow(&pipe).await;
    assert!(
        matches!(refused, Err(PeerFailure::PinMismatch { .. })),
        "{refused:?}"
    );
    let (pr, _) = subject();
    assert!(
        held.verify_tip(&tip_envelope(&k1), &pr).is_err(),
        "a mismatched pin adopts nothing"
    );
}

/// Claim: a key the followed chain REVOKED is refused for a tip, while a sibling key the chain still holds verifies, so lookup is
/// among ACTIVE keys and never among every key the chain ever held.
///
/// Turns red if: `verify_tip` looks a key up among all keys
/// the chain has held (a revoked key still vouches), or trust the
/// statement's own signature without the chain's say-so.
/// End-to-end scenario: yes (real chain with a revocation, replayed from a
/// carrier).
#[tokio::test]
async fn revoked_key_in_the_held_chain_is_refused() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let c2 = peer.commit(&k2, 1_700_000_200).await;
    let c3 = peer.revoke(&k1, 1_700_000_300).await;
    let (pr, _) = subject();

    let pipe = Pipe::new(peer.patch(&[c1.clone(), c2.clone()]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe).await.expect("follow before the revoke");
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());

    pipe.serve(peer.patch(&[c1, c2, c3]));
    held.follow(&pipe).await.expect("follow the revoke");
    assert!(matches!(
        held.verify_tip(&tip_envelope(&k1), &pr),
        Err(PeerFailure::KeyNotActive { .. })
    ));
    assert!(held.verify_tip(&tip_envelope(&k2), &pr).is_ok());
}

/// Claim: a data action whose `typ` merely contains `/freeze/` (here
/// `app/freeze/status`) is an ACTION, not a transaction, so a chain holding
/// one follows. Only `/freeze/create` and `/freeze/delete` are lifecycle
/// transactions, as in the storage replay the server runs.
///
/// Turns red if: the classifier treats any `/freeze/` typ as a transaction,
/// so the action is applied as one and the whole follow is refused.
/// End-to-end scenario: yes (real chain with an action, replayed).
#[tokio::test]
async fn data_action_typed_like_a_freeze_follows() {
    let g = kp();
    let k1 = kp();
    let mut peer = Chain::new(&g).await;
    let action = peer.action("cyphr.me/app/freeze/status", 1_700_000_050);
    let mut c1 = vec![action];
    c1.extend(peer.commit(&k1, 1_700_000_100).await);
    let pipe = Pipe::new(peer.patch(&[c1]));
    let (pr, _) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("a chain with an app/freeze/status action follows");
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());
}

/// Claim: key material is read only from an entry's `keys` (SPEC 4.6.2);
/// an unsigned, junk `key` member on a coz is ignored, never a reason to
/// refuse a chain whose signed content is valid.
///
/// Turns red if: a coz's own `key` member is parsed, so a junk member on a
/// `commit/create` coz refuses the follow.
/// End-to-end scenario: yes.
#[tokio::test]
async fn junk_sidecar_on_a_non_introducing_coz_is_ignored() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let mut c2 = peer.commit(&k2, 1_700_000_200).await;
    // The closing cozy of a non-genesis commit carries no sidecar; add junk.
    let closing = c2.last_mut().expect("closing cozy");
    let mut coz: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(closing).expect("b64"))
            .expect("coz json");
    coz["key"] = serde_json::json!({ "junk": true });
    *closing = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).expect("json"));
    let pipe = Pipe::new(peer.patch(&[c1, c2]));
    let (pr, _) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("junk on a non-introducing coz is ignored");
    assert!(held.verify_tip(&tip_envelope(&k2), &pr).is_ok());
}

/// Claim: the accessors a transport or sign-on layer builds on report the
/// held chain truthfully: `pg` is the pinned PG; `active_key` returns the
/// ACTIVE key with the asked thumbprint (and refuses one never held or
/// revoked); `held_tip` counts the commits held and names the tip PR the
/// core derived, advancing as the chain is followed.
///
/// Turns red if: `active_key` returns a key other than the one asked for,
/// or a revoked or unheld one; `held_tip` reports a stale count or a PR
/// other than the replayed chain's.
/// End-to-end scenario: yes (real chain with a revocation, replayed).
#[tokio::test]
async fn accessors_report_the_held_chain() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let outsider = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let c2 = peer.commit(&k2, 1_700_000_200).await;
    let pr_after_two = peer.principal.pr_tagged().expect("pr");
    let c3 = peer.revoke(&k1, 1_700_000_300).await;

    let pipe = Pipe::new(peer.patch(&[c1.clone(), c2.clone()]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    assert_eq!(held.pg(), peer.pg());
    assert_eq!(held.held_tip().expect("tip").commits, 0);
    assert!(held.active_key(&g.tmb).is_ok());
    assert!(matches!(
        held.active_key(&k1.tmb),
        Err(PeerFailure::KeyNotActive { .. })
    ));

    held.follow(&pipe).await.expect("follow two commits");
    let tip = held.held_tip().expect("tip");
    // The genesis commit, then the two key/create commits.
    assert_eq!((tip.commits, tip.pr.as_str()), (3, pr_after_two.as_str()));
    assert_eq!(held.active_key(&k2.tmb).expect("k2").tmb(), &k2.tmb);
    assert_eq!(held.active_key(&k1.tmb).expect("k1").tmb(), &k1.tmb);
    assert!(held.active_key(&outsider.tmb).is_err());

    pipe.serve(peer.patch(&[c1, c2, c3]));
    held.follow(&pipe).await.expect("follow the revoke");
    let tip = held.held_tip().expect("tip");
    assert_eq!(tip.commits, 4, "genesis commit + two adds + the revoke");
    assert_eq!(
        tip.pr,
        peer.principal.pr_tagged().expect("pr"),
        "the tip PR is the replayed chain's"
    );
    assert!(
        matches!(
            held.active_key(&k1.tmb),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "a revoked key is not an active key"
    );
}

impl Chain<'_> {
    /// A one-transaction commit of `typ` signed and finalized by the
    /// genesis key, with `fields` added to the pay. Returns the wire blobs.
    async fn tx(&mut self, typ: &str, fields: serde_json::Value, now: i64) -> Vec<String> {
        let g = self.genesis;
        let mut pay = serde_json::json!({
            "alg": g.kp.alg.name(),
            "now": now,
            "tmb": g.tmb.to_b64(),
            "typ": typ,
        });
        let object = pay.as_object_mut().expect("pay object");
        object.extend(fields.as_object().expect("fields object").clone());
        // Signed in canonical (sorted) order, the form replay verifies.
        object.sort_keys();
        let pay = serde_json::to_vec(&pay).expect("pay json");
        let (sig, cad) =
            coz::sign_json(&pay, g.kp.alg.name(), &g.kp.prv_bytes, &g.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, g.kp.alg.name()).expect("czd");
        let mut scope = self.principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, None)
            .expect("transaction applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    g.kp.alg.name(),
                    &g.kp.prv_bytes,
                    &g.kp.pub_bytes,
                    &g.tmb,
                ),
                now,
                "cyphr.me",
            )
            .await
            .expect("commit finalizes");
        self.principal
            .commits()
            .last()
            .expect("a commit exists")
            .iter_all_cozies()
            .map(|cz| {
                Base64UrlUnpadded::encode_string(&serde_json::to_vec(cz.raw()).expect("coz json"))
            })
            .collect()
    }
}

/// Claim: `follow` compares every bundle it replays, the action-only
/// bundles after the last commit included, so a peer that served one
/// trailing action and later serves a different one in its place is a
/// `Fork`, and the held chain keeps the first.
///
/// Turns red if: `follow` compares only commits, so a rewritten trailing
/// action (which no commit covers) is adopted silently.
/// End-to-end scenario: yes (two histories under one PG that differ only
/// in a trailing action, replayed from a carrier).
#[tokio::test]
async fn trailing_action_rewritten_is_a_fork() {
    let g = kp();
    let k1 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let first = peer.action("cyphr.me/app/post/create", 1_700_000_200);
    let rewrite = peer.action("cyphr.me/app/post/create", 1_700_000_300);

    let pipe = Pipe::new(peer.patch(&[c1.clone(), vec![first.clone()]]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("a chain ending in an action-only bundle follows");
    let tip = held.held_tip().expect("tip");

    pipe.serve(peer.patch(&[c1.clone(), vec![rewrite]]));
    let forked = held.follow(&pipe).await;
    assert!(
        // Bundle 0 is the genesis commit, 1 the key/create, 2 the action.
        matches!(forked, Err(PeerFailure::Fork { index: 2 })),
        "a rewritten trailing action is a fork at its bundle: {forked:?}"
    );
    assert_eq!(
        held.held_tip().expect("tip"),
        tip,
        "a refused follow leaves the held chain as it was"
    );

    pipe.serve(peer.patch(&[c1, vec![first]]));
    held.follow(&pipe)
        .await
        .expect("the same history still follows after a refused fork");
}

/// Claim: the client routes `principal/merge` and `principal/merge-ack` as
/// transactions by the core kind table (SPEC 11.5.1), so a peer chain
/// holding both follows and the client reaches the PR the peer's own core
/// derived; the storage engine reaches the same PR for the same kinds
/// (`replay_equivalence`), so the two paths agree.
///
/// Turns red if: the client classifies by a typ list missing the merge
/// kinds, so a merge is recorded as an action and its commit's arrow
/// refuses the follow.
/// End-to-end scenario: yes (real chain with both merge kinds, replayed
/// from a carrier).
#[tokio::test]
async fn merge_and_merge_ack_chain_follows_to_the_peer_pr() {
    let g = kp();
    let k1 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let foreign = digest(9);
    let own = peer.principal.pr_tagged().expect("pr");
    let c2 = peer
        .tx(
            "cyphr.me/cyphr/principal/merge-ack",
            serde_json::json!({ "merge_from": [foreign.clone()], "merge_to_pr": own }),
            1_700_000_200,
        )
        .await;
    let own = peer.principal.pr_tagged().expect("pr");
    let c3 = peer
        .tx(
            "cyphr.me/cyphr/principal/merge",
            serde_json::json!({ "merge_from": [own], "merge_to_pr": foreign }),
            1_700_000_300,
        )
        .await;

    let pipe = Pipe::new(peer.patch(&[c1, c2, c3]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("a chain with merge kinds follows");
    let tip = held.held_tip().expect("tip");
    assert_eq!(
        // The genesis commit, the key/create and the two merge kinds.
        (tip.commits, tip.pr),
        (4, peer.principal.pr_tagged().expect("pr")),
        "the client replays the merge kinds to the peer's own PR"
    );
}

/// Claim: every nonce golden chain (SPEC 10.1, the NE1 vectors under
/// `tests/golden/mutations/nonce_*`) follows through the client to the PR
/// the vector records, the PR the engine also reaches for the same vectors
/// (`replay_equivalence`), so client and storage classify nonce kinds alike.
///
/// Turns red if: the client classifies by a typ list missing the nonce
/// kinds, so a nonce is recorded as an action and the commit's arrow
/// refuses the follow.
/// End-to-end scenario: yes (golden chains served over a carrier).
#[tokio::test]
async fn nonce_golden_chains_follow_to_the_recorded_pr() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/mutations");
    let mut followed = 0;
    for entry in std::fs::read_dir(&dir).expect("golden dir") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("nonce_") {
            continue;
        }
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read golden")).expect("json");
        let gk = &golden["genesis_keys"][0];
        let decode = |f: &str| Base64UrlUnpadded::decode_vec(gk[f].as_str().expect(f)).expect(f);
        let genesis = cyphr::Key::new(
            gk["alg"].as_str().expect("alg"),
            coz::Thumbprint::from_bytes(decode("tmb")),
            decode("pub"),
        )
        .expect("genesis key");
        let pg = cyphr::Principal::implicit(genesis.clone())
            .await
            .and_then(|p| p.pr_tagged())
            .expect("pg");

        let entries: Vec<Vec<String>> = golden["commits"]
            .as_array()
            .expect("commits")
            .iter()
            .map(|commit| {
                // A golden line's transactions are one coz each; its keys
                // ride on the cozies that name them for `patch_body`.
                let keys = commit["keys"].as_array().cloned().unwrap_or_default();
                commit["actions"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .chain(
                        commit["txs"]
                            .as_array()
                            .expect("txs")
                            .iter()
                            .flat_map(|tx| tx.as_array().expect("transaction")),
                    )
                    .map(|coz| {
                        let mut coz = coz.clone();
                        let id = coz["pay"]["id"].clone();
                        let typ = coz["pay"]["typ"].as_str().expect("typ").to_string();
                        if cyphr::parsed_coz::typ::is_key_introducing(&typ) {
                            if let Some(key) = keys.iter().find(|k| k["tmb"] == id) {
                                coz["key"] = key.clone();
                            }
                        }
                        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).expect("json"))
                    })
                    .collect()
            })
            .collect();

        let pipe = Pipe::new(patch_body(&entries));
        let mut held = PeerChain::pin(&pg, genesis).await;
        held.follow(&pipe)
            .await
            .unwrap_or_else(|e| panic!("{name} follows: {e}"));
        assert_eq!(
            held.held_tip().expect("tip").pr,
            golden["expected"]["pr"].as_str().expect("expected pr"),
            "{name}: the client reaches the PR the vector records"
        );
        followed += 1;
    }
    assert!(followed >= 5, "the nonce vectors were found ({followed})");
}

/// Claim: bundles replay by the order rule: a bundle's data actions are
/// recorded before its transactions (SPEC 4.6.2 `actions`), the commit is
/// formed, and an action served after the commit, in an action-only bundle,
/// is recorded against the post-commit state. So that action may be signed
/// by the key the commit's own `key/create` introduced, and the client
/// reaches the PR its writer derived.
///
/// Turns red if: the leading action is recorded after the commit, or the
/// following action-only bundle is judged against a state without the
/// commit (its signer is then not yet a key, `UnknownKey`).
/// End-to-end scenario: yes (a commit with a leading action, then an
/// action-only bundle, served over a carrier).
#[tokio::test]
async fn action_after_a_transaction_is_judged_after_the_commit() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let lead = peer.action("cyphr.me/app/post/create", 1_700_000_150);
    let commit = peer.commit(&k2, 1_700_000_200).await;
    let trail = peer.action_by(&k2, "cyphr.me/app/post/create", 1_700_000_250);
    let mut bundle = vec![lead];
    bundle.extend(commit);

    let pipe = Pipe::new(peer.patch(&[c1, bundle, vec![trail]]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000)).await;
    held.follow(&pipe)
        .await
        .expect("the bundles follow by the order rule");
    let tip = held.held_tip().expect("tip");
    assert_eq!(
        // The genesis commit, c1 and the bundle's commit.
        (tip.commits, tip.pr),
        (3, peer.principal.pr_tagged().expect("pr")),
        "the client reaches the writer's PR"
    );
}

/// Claim: a gossip participant cannot make a client re-download a peer
/// chain on demand. Each unverified body naming a key the held chain lacks
/// asks `verify_tip_following` to follow; at most one full `/patch` fetch
/// and replay is spent per configured interval per peer, and the refusal
/// is the typed `FetchTooSoon`, never a silent re-fetch. The interval runs
/// on the injected clock.
///
/// Turns red if: the flood causes more than one fetch inside the interval;
/// the refusal is another failure; or the fetch is not allowed again once
/// the injected clock passes the interval.
/// End-to-end scenario: yes (a flood of unknown-key tips against a carrier
/// that counts the fetches it serves).
#[tokio::test]
async fn hardening_unknown_tmb_flood_fetches_once_per_interval() {
    static NOW: AtomicI64 = AtomicI64::new(1_700_001_000);
    fn clock() -> i64 {
        NOW.load(std::sync::atomic::Ordering::SeqCst)
    }
    let (g, k1) = (kp(), kp());
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let pipe = Pipe::new(peer.patch(std::slice::from_ref(&c1)));
    let (pr, _) = subject();
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000))
        .await
        .with_clock(clock)
        .with_limits(PeerLimits {
            min_follow_interval_secs: 60,
            max_patch_entries: 100,
        });

    // The first unknown key follows once and stays refused.
    assert!(matches!(
        held.verify_tip_following(&pipe, &tip_envelope(&kp()), &pr)
            .await,
        Err(PeerFailure::KeyNotActive { .. })
    ));
    assert_eq!(pipe.exchanges(), 1);

    for _ in 0..50 {
        let refused = held
            .verify_tip_following(&pipe, &tip_envelope(&kp()), &pr)
            .await;
        assert!(
            matches!(refused, Err(PeerFailure::FetchTooSoon { .. })),
            "a flood inside the interval is refused with the typed failure, got {refused:?}"
        );
    }
    assert_eq!(pipe.exchanges(), 1, "50 more bodies fetched nothing");

    NOW.store(1_700_001_061, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        held.verify_tip_following(&pipe, &tip_envelope(&kp()), &pr)
            .await,
        Err(PeerFailure::KeyNotActive { .. })
    ));
    assert_eq!(pipe.exchanges(), 2, "one more fetch once the interval ran");
}

/// Claim: a patch longer than the configured cap is refused before any
/// replay, with the typed `PatchTooLarge`, and the held chain is exactly
/// what it was.
///
/// Turns red if: an over-cap patch is replayed or adopted, or the refusal
/// is another failure.
/// End-to-end scenario: yes.
#[tokio::test]
async fn hardening_patch_over_the_cap_is_refused() {
    let (g, k1, k2) = (kp(), kp(), kp());
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let c2 = peer.commit(&k2, 1_700_000_200).await;
    let pipe = Pipe::new(peer.patch(&[c1, c2]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000))
        .await
        .with_limits(PeerLimits {
            min_follow_interval_secs: 0,
            max_patch_entries: 2,
        });
    let before = held.held_tip().expect("tip");
    assert!(matches!(
        held.follow(&pipe).await,
        Err(PeerFailure::PatchTooLarge { offered: 3, cap: 2 })
    ));
    assert_eq!(held.held_tip().expect("tip"), before);
}

/// Claim: the peer chain replays with the injected clock, not the ambient
/// one: a clock that reads before the commits' `now` refuses the follow
/// (the core's future-`now` bound), and the same chain follows under a
/// clock that reads after them.
///
/// Turns red if: `follow` replays with the system clock (the early-clock
/// follow then succeeds).
/// End-to-end scenario: yes.
#[tokio::test]
async fn hardening_follow_replays_with_the_injected_clock() {
    fn early() -> i64 {
        1_600_000_000
    }
    fn late() -> i64 {
        1_700_001_000
    }
    let (g, k1) = (kp(), kp());
    let mut peer = Chain::new(&g).await;
    let c1 = peer.commit(&k1, 1_700_000_100).await;
    let pipe = Pipe::new(peer.patch(std::slice::from_ref(&c1)));
    let pin = async |clock: cyphr::principal::Clock| {
        PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000))
            .await
            .with_clock(clock)
    };
    assert!(matches!(
        pin(early).await.follow(&pipe).await,
        Err(PeerFailure::Replay { .. })
    ));
    pin(late).await.follow(&pipe).await.expect("late clock");
}
