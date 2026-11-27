// Sign-in to a separated relying party, the part of S11 that does not need a
// key removal or a second connection.
//
// Claim: a relying party signs a principal in on what it replayed itself. The
// principal exists only on a peer; the relying party is handed its genesis key
// out of band, pulls the chain over its own route, and decides a login signed
// with the principal's key. The session's subject is the canonical principal,
// the session survives a pull that finds nothing new, and a token the relying
// party never issued opens nothing.
//
// Turns red if: the relying party signs in without a replayed key set, names a
// different principal than the one pinned, or a pull ends a live session.
// End-to-end scenario: yes (shipped CLI and server over the fault proxy).

use cyphr_scenarios::Harness;
use cyphr_scenarios::actions::*;

#[tokio::test(flavor = "multi_thread")]
async fn relying_party_signs_in_from_its_own_pull() {
    let h = Harness::start(&["p1"]).await.expect("start peers");
    let alice = h.client("alice");
    let rp = h.ok(h.start_relying_party().await);

    let cfg = h.ok(rp.config().await);
    assert!(cfg.pull_age_bound > std::time::Duration::ZERO);

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.push(&pr, &["p1"]).await).accepted("setup push");

    let session = h.ok(alice.sign_in(&rp).await);
    assert!(
        session
            .principal
            .0
            .ends_with(&format!(":{}", h.ok(h.genesis_tmb(&pr)))),
        "the subject resolves under the enrolled genesis key"
    );
    assert_eq!(
        session.principal.pg(),
        pr.pg(),
        "the token's subject is the canonical principal, not a spelling"
    );
    assert!(h.ok(rp.session_active(&session.token).await));

    h.ok(rp.refresh_view().await);
    assert!(
        h.ok(rp.session_active(&session.token).await),
        "a pull that finds nothing new must not end a live session"
    );
    assert!(
        !h.ok(rp.session_active(&Token("never-issued".into())).await),
        "a token the relying party never issued opens nothing"
    );
}
