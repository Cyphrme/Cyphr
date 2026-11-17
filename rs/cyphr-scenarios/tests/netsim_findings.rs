// Failures NETSIM found in the product, each reduced to a minimal run and
// kept red but ignored (the ignore reason names the failure, as the CI guard
// requires) until fixed. NETSIM itself steers around each one, so the
// gate stays about the rest of the network; remove the steering with the
// ignore.

use std::time::Duration;

use cyphr_scenarios::Harness;
use cyphr_scenarios::actions::KeyRef;

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
#[ignore = "RED(paired-key-delete): the store fails the 6th commit after the only ES256 key is deleted"]
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
#[ignore = "RED(restored-peer-revoke): a peer restored from before a naked revoke never relearns it"]
async fn a_restored_peer_relearns_a_naked_revoke() {
    use cyphr_scenarios::netsim::{Size, plan, run};
    let size = Size {
        forgive_restored_peers: false,
        ..Size::ci()
    };
    let ops = plan::parse(
        "create p=0 multikey=false holders=0,1,2\n\
         addkey p=0 d=0\n\
         backup peer=2\n\
         nakedrevoke p=0 d=0\n\
         restore peer=2\n\
         barrier\n",
    )
    .expect("op log");
    let h = run::start(&size, 20_261_117).await.expect("start peers");
    // With no exemption for restored peers, N5 asks p2 too.
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
#[ignore = "RED(revoke-with-a-holder-down): naked-revoke fails when one known peer is stopped"]
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
        h.eventually("a live holder to list the revoke", Duration::from_secs(20), || async {
            Ok(lists_revoke(&h, live, &key).await)
        })
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
// for the spec author to rule, not for the harness to pick. NETSIM does not
// ask for this sign-in until it is ruled on.
//
// Must hold, if the spec's reading stands: an active key of a principal whose
// fork was resolved signs in.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(resolved-fork-sign-in): the relying party refuses an active key of a principal whose fork was resolved"]
async fn a_principal_signs_in_after_its_fork_is_resolved() {
    use cyphr_scenarios::netsim::{Size, plan, run};
    let size = Size {
        forgive_forked_sign_in: false,
        ..Size::ci()
    };
    let ops = plan::parse(
        "create p=0 multikey=false holders=0,1,2\n\
         pair p=0 d=0\n\
         fork p=0\n\
         signin p=0\n\
         barrier\n",
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
#[ignore = "RED(multikey-rebase): a device paired into a multikey principal cannot rebase"]
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
