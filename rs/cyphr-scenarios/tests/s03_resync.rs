// Scenario S03, resync: the double-offline fork whose both branches were
// extended (SPEC 15.8 item 2).
// Alice's laptop and phone each commit twice on partitioned peers; no commit
// leaves that Error (see s03_offline). Alice resyncs from the phone: a
// `resync/create` over the phone's tip, sent with the phone's line.
// Must hold: every server ends Active on the phone's tip, the laptop's
// branch stays served as evidence, a relying party signs Alice in, and the
// CLI verdict names the PoP's signer as the resolver.
//
// Required capabilities:
// transport,cli-network,branch-store,evidence,peer-gossip,data-commit,key-pairing,relying-party.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(30);

// @docket: sc-l2822 :: scripts/docket-run sc-l2822
#[tokio::test(flavor = "multi_thread")]
async fn s03_resync_resolves_the_double_offline_fork() {
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
    let phone_key = h.ok(laptop.pair_device(&pr, &phone).await);
    h.ok(laptop.push(&pr, &both).await).accepted("base push");
    h.ok(phone.sync(&pr, &both).await);

    // Each device extends its own branch twice behind the cut links.
    h.proxy.partition("p1", "p2");
    h.proxy.partition("alice-laptop", "p1");
    h.proxy.partition("alice-phone", "p2");
    let (mut lt, mut pt) = (None, None);
    for round in 1..=2 {
        h.ok(laptop.commit_data(&pr, &format!("laptop {round}")).await);
        h.ok(phone.commit_data(&pr, &format!("phone {round}")).await);
        lt = Some(
            h.ok(laptop.push(&pr, &["p2"]).await)
                .accepted("laptop branch"),
        );
        pt = Some(
            h.ok(phone.push(&pr, &["p1"]).await)
                .accepted("phone branch"),
        );
    }
    let (lt, pt) = (lt.expect("laptop tip"), pt.expect("phone tip"));
    assert_ne!(lt, pt, "the devices forked");
    h.proxy.heal("p1", "p2");
    h.eventually("every peer to read Error", CONVERGE, || async {
        let v = observer.verdict(&pr, &both).await?;
        Ok(v.standing == Standing::Error)
    })
    .await;

    // Alice answers from the phone: no commit can leave this Error, the PoP does.
    assert_eq!(
        h.ok(phone.resync(&pr).await),
        pt,
        "the PoP asserts the phone's tip"
    );
    h.eventually(
        "every server to be Active on the phone's tip",
        CONVERGE,
        || async {
            for peer in both {
                if h.peer_view(peer, &pr).await.map(|v| v.tip) != Some(pt.clone()) {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;

    let v = h.ok(observer.verdict(&pr, &both).await);
    assert_eq!(v.standing, Standing::Active);
    assert_eq!(v.tip, pt);
    assert_eq!(
        v.resolved_by,
        Some(phone_key),
        "the verdict names the PoP's signer"
    );
    assert!(
        v.abandoned.contains(&lt),
        "the laptop's branch is kept as evidence"
    );
    h.check_verdict(&v, &pr, &Expect::new(&both, &pr.0)).await;

    let rp = h.ok(h.start_relying_party().await);
    let session = h.ok(phone.sign_in(&rp).await);
    assert!(
        h.ok(rp.session_active(&session.token).await),
        "the relying party signs Alice in"
    );
}
