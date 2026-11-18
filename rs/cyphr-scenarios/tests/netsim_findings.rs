// Failures NETSIM found in the product, each reduced to a minimal run and
// kept red but ignored (the ignore reason names the failure, as the CI guard
// requires) until fixed. NETSIM itself steers around each one, so the
// gate stays about the rest of the network; remove the steering with the
// ignore.

use std::time::Duration;

use cyphr_scenarios::actions::{KeyRef, Principal, Standing};
use cyphr_scenarios::{Capability, Harness};

// Found by NETSIM at the gating size, seed 772, whose theft episode on
// principal 1 left its owner unable to commit. Reduced op log (replayable
// with CYPHR_NETSIM_REPLAY before the model refused commits after a theft):
//
//   create p=0 multikey=false holders=0,1
//   pair p=0 d=0
//   theft p=0
//   commit p=0 d=0     (accepted)
//   commit p=0 d=0     (accepted)
//   commit p=0 d=0     (fails: the 6th commit of the chain)
//
// A theft ends with the owner's `key/delete` of the paired device's key. That
// key is ES256, the principal's only key of its hash algorithm, so the store
// holds a Merkle frontier for that algorithm no later commit extends. No
// network, fork or revoke is needed: delete the paired key and commit.
// The failure is in the owner's local store (`cyphr data commit`), reported as
// "corrupted metadata for algorithm 1: missing frontier node for algorithm 1
// at left 4 height 1".
//
// Must hold: a principal keeps committing after the only key of one of its
// hash algorithms is deleted (SPEC 6.2, `key/delete` retires a key).
#[tokio::test(flavor = "multi_thread")]
async fn a_principal_keeps_committing_after_its_paired_key_is_deleted() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    let (alice, laptop) = (h.client("alice"), h.client("laptop"));
    let pr = h.ok(alice.create_principal().await);
    let key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.remove_key(&pr, &key).await);
    for i in 0..6 {
        h.ok(alice.commit_data(&pr, &format!("after{i}")).await);
    }
}

// Found by NETSIM at the large size, seed 20261117 (a peer restored from a
// backup taken before a naked revoke never listed it again), and reduced to
// this log, which the model accepts:
//
//   create p=0 multikey=false holders=0,1,2
//   addkey p=0 d=0
//   backup peer=2
//   nakedrevoke p=0 d=0     (revoke sent to the home, then the owner deletes the key)
//   restore peer=2
//   barrier                 (every peer agrees on the chain; p2 never lists the revoke)
//
// Gossip asks peers for the naked revokes of a principal's active keys, and
// the owner's `key/delete` that SPEC 6.4 prescribes after a naked revoke
// removes the key from that set, so a peer that loses its record of the
// revoke has no reason to ask again. Its chain still refuses the key as not
// active; what is lost is that the key was revoked (compromised) rather
// than retired (SPEC 6.2).
//
// Must hold: at quiescence every holder serves the naked revoke (SPEC 6.4,
// 13.7: revokes travel by gossip).
#[tokio::test(flavor = "multi_thread")]
async fn a_restored_peer_relearns_a_naked_revoke() {
    use cyphr_scenarios::netsim::{Size, plan, run};
    let size = Size::ci();
    let ops = plan::parse(
        "create p=0 multikey=false holders=0,1,2\naddkey p=0 d=0\nbackup peer=2\nnakedrevoke p=0 \
         d=0\nrestore peer=2\nbarrier\n",
    )
    .expect("op log");
    let h = run::start(&size, 20_261_117).await.expect("start peers");
    // N5 asks the restored p2 to list the revoke too.
    run::run(&h, &size, &ops)
        .await
        .unwrap_or_else(|f| panic!("{f}"));
}

async fn lists_revoke(h: &Harness, peer: &str, key: &KeyRef) -> bool {
    let v: serde_json::Value = h
        .http
        .get(format!("http://{}/revoked", h.peer(peer).addr()))
        .query(&[("tmbs", key.0.as_str())])
        .send()
        .await
        .expect("GET /revoked")
        .json()
        .await
        .expect("revoked json");
    v["payload"]["revoked"]
        .as_array()
        .is_some_and(|r| !r.is_empty())
}

// Found by the large run (seed 20261117, a naked revoke while a holder was
// stopped failed the whole `cyphr key naked-revoke` with "unreachable ...
// /revoke"); NETSIM now generates a revoke only while every holder runs.
//
// `naked-revoke` sends to every peer the device knows for the principal, which
// after publication is every holder. An emergency revoke (SPEC 6.4) must not
// abort because one peer is down.
//
// Must hold: with one holder stopped the revoke is still sent, the live
// holders list it, and the stopped holder lists it after it restarts, by
// gossip.
#[tokio::test(flavor = "multi_thread")]
async fn a_naked_revoke_survives_a_stopped_holder() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    let alice = h.client("alice");
    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1", "p2", "p3"]).await)
        .accepted("publish");
    let key = h.ok(alice.add_backup_key(&pr).await);
    h.ok(alice.push(&pr, &["p1", "p2", "p3"]).await)
        .accepted("key push");

    h.ok(h.stop_peer("p3").await);
    h.ok(alice.naked_revoke(&pr, &key).await);
    for live in ["p1", "p2"] {
        h.eventually(
            "a live holder to list the revoke",
            Duration::from_secs(20),
            || async { Ok(lists_revoke(&h, live, &key).await) },
        )
        .await;
    }
    h.ok(h.start_peer("p3").await);
    h.eventually(
        "the restarted holder to learn the revoke",
        Duration::from_secs(30),
        || async { Ok(lists_revoke(&h, "p3", &key).await) },
    )
    .await;
}

// Found by the large run (seed 20261117, barrier 2): a relying party refused
// to sign in a principal whose fork the owner had already resolved, with "the
// principal forked; its lifecycle state is not Active", while every peer and a
// third party's verdict reported it Active (N4 passes).
//
// SPEC 15.6 returns a principal from Error to Active "upon observing a valid
// resolution" and says nothing of a lasting mark. Either the relying party's
// sticky refusal is intended and the spec should say so, or it is a defect:
// for the spec author to rule, not for the harness to pick.
//
// Must hold, if the spec's reading stands: an active key of a principal whose
// fork was resolved signs in.
#[tokio::test(flavor = "multi_thread")]
async fn a_principal_signs_in_after_its_fork_is_resolved() {
    use cyphr_scenarios::netsim::{Size, plan, run};
    let size = Size::ci();
    let ops = plan::parse(
        "create p=0 multikey=false holders=0,1,2\npair p=0 d=0\nfork p=0\nsignin p=0\nbarrier\n",
    )
    .expect("op log");
    let h = run::start(&size, 20_261_117).await.expect("start peers");
    run::run(&h, &size, &ops)
        .await
        .unwrap_or_else(|f| panic!("{f}"));
}

// Found by the large run (seed 20261117): a device paired into a principal
// opened by several keys fails `cyphr rebase` with "cannot resolve genesis for
// identity ...: no stored commits or keystore key", so two devices of such a
// principal cannot reconcile a Stale refusal (SPEC 15.9). Pairing itself, and
// the paired device's first commit, work. NETSIM pairs only single-key
// principals until this is fixed.
//
// Must hold: the second of two devices committing from one tip rebases and
// both commits reach the chain, for a multikey principal as for any other.
#[tokio::test(flavor = "multi_thread")]
async fn a_paired_device_of_a_multikey_principal_rebases() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    let (alice, phone) = (h.client("alice"), h.client("phone"));
    let pr = h.ok(alice.create_multikey_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("publish");
    h.ok(alice.pair_device(&pr, &phone).await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("pairing");
    h.ok(phone.sync(&pr, &["p1"]).await);
    h.ok(alice.commit_data(&pr, "first").await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("alice");
    h.ok(phone.commit_data(&pr, "second").await);
    let stale = h.ok(phone.push(&pr, &["p1"]).await).refused("stale push");
    assert_eq!(stale, cyphr_scenarios::actions::RefusalKind::Stale);
    h.ok(phone.rebase(&pr).await);
    h.ok(phone.push(&pr, &["p1"]).await).accepted("rebased");
}

// Found while pinning NETSIM's oracle: a fork whose kept branch ends in a key
// replacement (`cyphr key replace`, signed by the key it retires) cannot be
// resolved at the peer that holds the rival branch. Two servers, one
// principal, partitioned:
//
//   base (laptop and phone paired, pushed to both)
//   laptop: one data commit, pushed to p2
//   phone:  one commit, pushed to p1 (`replace` is the commit when asked)
//   the link heals; both peers serve the fork as evidence (Error)
//   phone:  one more commit on its branch, signed by its current key,
//           pushed to p1: SPEC 15.8's resolution by extension
//
// With data commits p2 takes the resolution and both peers read Active. With
// the replacement as the phone's commit p2 refuses the resolution in gossip
// with "protocol: unknown key": the resolution is signed by the key the rival
// branch introduced, which p2's canonical state has never held, and p2 stays
// in Error. ("state root mismatch" lines in its log are the rival answered
// as a held fork, which is expected.) That is the theft-recovery shape: the
// owner replaces a key on the branch that rivals the thief's, then resolves.
//
// Must hold: the owner resolves a fork on a branch that replaced a key, and
// every peer follows (SPEC 15.8 item 1).
async fn gossip_a_fork(replace: bool) {
    let h = Harness::start_gossiping(&["p1", "p2"], 1)
        .await
        .expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::CliNetwork,
        Capability::BranchStore,
        Capability::Evidence,
        Capability::PeerGossip,
        Capability::DataCommit,
    ])
    .await;
    let (laptop, phone) = (h.client("alice-laptop"), h.client("alice-phone"));
    let observer = h.client("bob");
    let both = ["p1", "p2"];
    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.pair_device(&pr, &phone).await);
    h.ok(laptop.push(&pr, &both).await).accepted("base push");

    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    h.ok(laptop.commit_data(&pr, "laptop branch").await);
    h.ok(laptop.push(&pr, &["p2"]).await)
        .accepted("laptop branch");
    if replace {
        h.ok(phone.rotate_key(&pr).await);
    } else {
        h.ok(phone.commit_data(&pr, "phone branch").await);
    }
    let kept = h
        .ok(phone.push(&pr, &["p1"]).await)
        .accepted("phone branch");
    h.proxy.heal("p1", "p2");

    h.eventually(
        "each peer to serve the fork as evidence",
        Duration::from_secs(20),
        || async {
            Ok(fork_items(&h, "p1", &pr).await >= 1 && fork_items(&h, "p2", &pr).await >= 1)
        },
    )
    .await;
    let v = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(v.standing, Standing::Error, "two unextended branches");

    let resolved = h.ok(phone.resolve_fork(&pr, &kept).await);
    h.eventually(
        "both peers to hold the resolution",
        Duration::from_secs(20),
        || async {
            Ok(
                h.peer_view("p1", &pr).await.map(|v| v.tip) == Some(resolved.clone())
                    && h.peer_view("p2", &pr).await.map(|v| v.tip) == Some(resolved.clone()),
            )
        },
    )
    .await;
    let v = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(v.standing, Standing::Active, "resolved by extension");
}

async fn fork_items(h: &Harness, peer: &str, p: &Principal) -> usize {
    let body: serde_json::Value = h
        .http
        .get(format!("http://{}/evidence", h.peer(peer).addr()))
        .query(&[("pr", p.0.as_str())])
        .send()
        .await
        .expect("evidence request")
        .json()
        .await
        .expect("evidence json");
    body["payload"]["items"].as_array().map_or(0, Vec::len)
}

// The control: the same fork and resolution with data commits only.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_of_data_commits_is_resolved_at_every_peer() {
    gossip_a_fork(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_with_a_key_replacement_is_resolved_at_every_peer() {
    gossip_a_fork(true).await;
}

// Found by NETSIM at the large size, seed 20261117 (principal 22). Seven of
// its eight holders stayed two commits behind the owner for ever, each pull
// from the home failing with `Replay { commit: 17, source: CommitMismatch }`
// ("state root mismatch"), while the home, which took the commits as the owner
// pushed them, held the whole chain. About one chain in five fails here, and
// which one varies with the random keys, so the test builds twelve.
//
// The chain, by commit:
//   Ed25519 genesis; an ES256 key paired in, the only SHA-256 key
//   key/delete of that ES256 key: SHA-256 has no key left, so the log closes
//     the algorithm (c291afe1)
//   a second ES256 key paired in: SHA-256 returns
//   a commit signed by the second ES256 key (its arrow is a SHA-256 digest)
// A holder replaying the chain from genesis refuses the return of SHA-256.
//
// Must hold: a holder that replays a chain from genesis reaches the root the
// owner's store reached, however the chain's hash algorithms came and went.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_whose_algorithm_returns_replays_at_every_holder() {
    let h = Harness::start_gossiping(&["p1", "p2"], 1)
        .await
        .expect("start peers");
    let both = ["p1", "p2"];
    let mut chains = Vec::new();
    for n in 0..12 {
        let (alice, first, second) = (
            h.client(&format!("alice{n}")),
            h.client(&format!("phone-one{n}")),
            h.client(&format!("phone-two{n}")),
        );
        let pr = h.ok(alice.create_principal().await);
        let key = h.ok(alice.pair_device(&pr, &first).await);
        h.ok(alice.push(&pr, &both).await).accepted("base push");
        h.ok(alice.remove_key(&pr, &key).await);
        h.ok(alice.push(&pr, &both).await)
            .accepted("after the delete");
        h.ok(alice.pair_device(&pr, &second).await);
        h.ok(alice.push(&pr, &["p1"]).await)
            .accepted("after the return");
        h.ok(second
            .commit_data(&pr, "signed by the returned algorithm")
            .await);
        let tip = h
            .ok(second.push(&pr, &["p1"]).await)
            .accepted("late commit");
        chains.push((pr, tip));
    }
    h.eventually(
        "p2 to replay every chain to its owner's tip",
        Duration::from_secs(60),
        || async {
            for (pr, tip) in &chains {
                if h.peer_view("p2", pr).await.map(|v| v.tip).as_ref() != Some(tip) {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;
}

// Frame NETSIM-FIX E4: after a full rotation (Ed25519 -> ES256) every
// commit of the chain must be provable from the tip alone. `/inclusion`
// takes no algorithm choice and answers 200 for every index; each answer
// parses as the typed membership proof and crosses at most the one epoch
// boundary the chain has. (Verifying it against a trusted tip is pinned by
// `cyphr/tests/stitch.rs`; this pins the server contract.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(NETSIM-FIX E4): /inclusion refuses or fails for commits of the retired algorithm"]
async fn every_index_of_a_rotated_chain_has_an_inclusion_proof() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    let (laptop, phone) = (h.client("laptop"), h.client("phone"));
    let pr = h.ok(laptop.create_principal().await);
    h.ok(laptop.commit_data(&pr, "before").await);
    let paired = h.ok(laptop.pair_device(&pr, &phone).await);
    let genesis = KeyRef(h.genesis_tmb(&pr).expect("genesis key"));
    // The phone's ES256 key removes the only Ed25519 key: that family
    // closes, and everything after is ES256 alone.
    h.ok(phone.remove_key(&pr, &genesis).await);
    for i in 0..4 {
        h.ok(phone.commit_data(&pr, &format!("after{i}")).await);
    }
    let _ = paired;
    h.ok(phone.push(&pr, &["p1"]).await)
        .accepted("rotated chain");
    let height = h.peer_view("p1", &pr).await.expect("p1 holds it").height;
    assert!(height >= 8, "height {height}");
    for index in 0..height {
        let resp = h
            .http
            .get(format!("http://{}/inclusion", h.peer("p1").addr()))
            .query(&[("pr", pr.0.as_str()), ("index", &index.to_string())])
            .send()
            .await
            .expect("inclusion request");
        assert_eq!(resp.status(), 200, "index {index} of {height}");
        let body: serde_json::Value = resp.json().await.expect("json");
        let proof = cyphr::proof::MembershipProof::from_payload(&body["payload"])
            .unwrap_or_else(|e| panic!("index {index}: {e}"));
        assert!(
            proof.stitches.len() <= 1,
            "index {index}: one boundary only"
        );
    }
}
