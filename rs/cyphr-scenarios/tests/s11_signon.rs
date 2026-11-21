// Scenario S11: signon.
// Attacker: replays a session token on another channel.
// Alice signs in to a separated relying party over the principal-authenticated
// transport; she removes the key; the token is presented on another channel.
// Must hold: the session ends within the window once the RP's pull has the removal;
// the token on another channel is refused.
//
// Required capabilities: transport,relying-party,session-binding.
// Session binding is observed on a signed-in session; the scenario then
// stops at remove_key, which needs key pairing (N22).

use std::time::Instant;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::{Capability, Harness};

#[tokio::test(flavor = "multi_thread")]
async fn s11_signon() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    h.require(&[
        Capability::Transport,
        Capability::RelyingParty,
        Capability::SessionBinding,
    ])
    .await;

    let alice = h.client("alice");
    let rp = h.ok(h.start_relying_party().await);
    let cfg = h.ok(rp.config().await);
    // The sign-on window: the pull age bound plus one refresh interval, both
    // read from the relying party.
    let window = cfg.pull_age_bound + cfg.refresh_interval;

    // Two keys created at genesis, so the PG is derived from the pair and
    // differs from the genesis key's thumbprint (a single-key principal's
    // PG equals it, which would make the subject check below vacuous), and
    // removing the sign-in key leaves the principal an authority.
    let pr = h.ok(alice.create_multikey_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("setup push");

    let session = h.ok(alice.sign_in(&rp).await);
    // The one-subject check reads the anchor the relying party reports it
    // was enrolled with, never the PG string: the anchor is the genesis
    // key the person handed over, and the subject is the principal its
    // replayed record names, which differs from the anchor here.
    let enrolled = h.ok(rp.enrolled_anchor().await);
    assert_eq!(
        enrolled,
        h.ok(h.genesis_tmb(&pr)),
        "the relying party must report the genesis key it was handed"
    );
    assert!(
        !pr.same_as(&enrolled),
        "the fixture must separate the PG from the anchor"
    );
    assert!(
        session.principal.same_as(pr.bare()),
        "the token's subject {:?} is not the principal's PG",
        session.principal
    );
    assert!(
        !session.principal.same_as(&enrolled),
        "the subject is the principal, not the anchor key"
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
    // The login the client signed names its own channel: carried to a second
    // authenticated session, or to plain HTTP, it opens nothing, and the
    // refusal is about the channel (not a spent challenge).
    for on in [Channel::Other, Channel::Http] {
        match h.ok(rp.replay_login(&session, on).await) {
            Presented::Refused(r) => assert!(
                r.detail.contains("channel"),
                "the replayed login on {on:?} was refused for the wrong reason: {r:?}"
            ),
            Presented::Accepted => panic!("a login for one channel opened a session on {on:?}"),
        }
    }
    match h.ok(rp.present(&session.token, Channel::Http).await) {
        Presented::Refused(r) => assert_eq!(r.kind, RefusalKind::Unauthorized),
        Presented::Accepted => panic!("the token worked with no channel"),
    }

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
    // The ended session's token is dead on the channel it came from, too. The
    // relying party drops a session when it finds its key gone, so the token
    // is then unknown to it: refused as Unauthorized, naming no live session.
    match h.ok(rp.present(&session.token, Channel::Original).await) {
        Presented::Refused(r) => {
            assert_eq!(r.kind, RefusalKind::Unauthorized);
            assert!(
                r.detail.contains("no live session"),
                "an ended session was refused for the wrong reason: {r:?}"
            );
        },
        Presented::Accepted => panic!("an ended session's token was accepted"),
    }
}
