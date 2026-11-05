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
}
