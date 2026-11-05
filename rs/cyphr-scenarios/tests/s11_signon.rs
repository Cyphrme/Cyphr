// Scenario S11: signon.
// Attacker: replays a session token on another channel.
// Alice signs in to a separated relying party over the principal-authenticated
// transport; she removes the key; the token is presented on another channel.
// Must hold: the session ends within the window once the RP's view has the removal;
// the token on another channel is refused.
//
// Required capabilities: transport,relying-party,session-binding.
// Red until they exist: the scenario starts its fresh-keyed peers, then the
// harness reports the first absent capability.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "RED(transport): TR1"]
async fn s11_signon() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::RelyingParty,
        Capability::SessionBinding,
    ])
    .await;

    let alice = h.client("alice");
    // Open (pending nrd): the sign-in window is not fixed by SPEC or the plan.
    const WINDOW: Duration = Duration::from_secs(30);

    let rp = h.ok(h.start_relying_party().await);
    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await);

    let session = h.ok(alice.sign_in(&rp).await);
    assert!(
        h.ok(rp.session_active(&session.token).await),
        "sign-in must open a session"
    );
    assert!(h.ok(rp.present(&session.token, Channel::Original).await));

    h.ok(alice.remove_key(&pr, &session.key).await);
    h.ok(alice.push(&pr, &["p1"]).await);
    h.ok(rp.refresh_view().await);
    h.eventually(
        "the session to end once the RP sees the removal",
        WINDOW,
        || async { Ok(!rp.session_active(&session.token).await?) },
    )
    .await;

    assert!(
        !h.ok(rp.present(&session.token, Channel::Other).await),
        "a token on another channel must be refused"
    );
}
