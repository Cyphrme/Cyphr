// Failures NETSIM found in the product, each reduced to a minimal run and
// kept red but ignored (the ignore reason names the failure, as the CI guard
// requires) until fixed. NETSIM itself steers around each one, so the
// gate stays about the rest of the network; remove the steering with the
// ignore.

use cyphr_scenarios::Harness;

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
