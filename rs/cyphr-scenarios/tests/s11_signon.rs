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

use std::time::{Duration, Instant};

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
    // Open (pending nrd): SPEC and the plan fix no sign-in window. The bound
    // below is only a default for a relying party that states none.
    const DEFAULT_VIEW_AGE_BOUND: Duration = Duration::from_secs(30);

    let rp = h.ok(h.start_relying_party().await);
    let cfg = h.ok(rp.config().await);
    let window = cfg.view_age_bound.unwrap_or(DEFAULT_VIEW_AGE_BOUND) + cfg.refresh_interval;

    let pr = h.ok(alice.create_principal().await);
    // The principal keeps a second key, so removing the sign-in key leaves
    // it with an authority.
    h.ok(alice.add_backup_key(&pr).await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("setup push");

    let session = h.ok(alice.sign_in(&rp).await);
    assert_eq!(
        session.principal, pr,
        "the token's subject is the canonical principal"
    );
    assert!(
        h.ok(rp.session_active(&session.token).await),
        "sign-in must open a session"
    );
    assert_eq!(
        h.ok(rp.present(&session.token, Channel::Original).await),
        Presented::Accepted
    );

    // A token on another channel is refused while the session is live, so a
    // relying party with no channel binding fails here, not after removal.
    match h.ok(rp.present(&session.token, Channel::Other).await) {
        Presented::Refused(r) => assert_eq!(r.kind, RefusalKind::Unauthorized),
        Presented::Accepted => panic!("a live token was accepted on another channel"),
    }
    assert!(
        h.ok(rp.session_active(&session.token).await),
        "the refusal must not end the session"
    );

    let removed_at = Instant::now();
    h.ok(alice.remove_key(&pr, &session.key).await);
    h.ok(alice.push(&pr, &["p1"]).await)
        .accepted("removal push");
    h.ok(rp.refresh_view().await);
    h.eventually(
        "the session to end once the RP sees the removal",
        window,
        || async { Ok(!rp.session_active(&session.token).await?) },
    )
    .await;
    assert!(
        removed_at.elapsed() <= window,
        "the session outlived the window"
    );
    // The ended session's token is dead on the channel it came from, too.
    // PROVISIONAL: the kind for an ended session awaits the architect.
    match h.ok(rp.present(&session.token, Channel::Original).await) {
        Presented::Refused(r) => assert_eq!(r.kind, RefusalKind::KeyNotActive),
        Presented::Accepted => panic!("an ended session's token was accepted"),
    }
}
