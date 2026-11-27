//! A Dead principal's attestations (SPEC 3.1, 3.7, 11; `docs/specs/receipts.md`).
//!
//! Revoking the last key leaves a principal with no KR and no AR (and no SR
//! without data). An attestor signing the dying commit's receipt and the
//! principal's tip report must say so with JSON `null`, never an empty
//! string, and a client must read both back as absent roots.

use axum::http::StatusCode;
use cyphr_net::{PeerKey, verify_authenticated_envelope};
use cyphr_server::build_router;

mod common;

use common::{
    attestor_server, build_bundle, fixture_principal_id, get_json, load_golden, post_json,
};

/// Backs the receipt rule that `sr` and `ar` MAY be `null` for a Dead
/// principal. Scenario: an attestor takes the push of the genesis commit and
/// then of the dying commit (the lifecycle vector
/// `last_key_revoke_leaves_dead`: the only key revokes itself) and answers
/// the latter 201 with a signed receipt whose `roots.sr` and
/// `roots.ar` are `null` while `pr`, `cr` and the unsigned payload agree; a
/// later `/tip` returns a signed tip report with the same roots; the client
/// verifies both against the attestor's key and reads the absent roots as
/// `None`. Turns red if an absent root is signed as `""` (a client refuses
/// it as malformed), if the receipt or tip payload disagree, or if the
/// attestor refuses to sign a keyless principal's roots. End to end: yes.
#[tokio::test]
async fn dying_commit_push_and_tip_attest_absent_roots_as_null() {
    let (state, identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let fixture = load_golden("lifecycle", "last_key_revoke_leaves_dead");
    let principal_id = fixture_principal_id(&fixture);
    let commits = fixture["commits"].as_array().expect("commits");
    assert_eq!(
        commits.len(),
        2,
        "the genesis commit, then the dying commit"
    );
    let body = |commit: &serde_json::Value| {
        let blobs = build_bundle(commit);
        common::push_body(&principal_id, &blobs)
    };
    let authority = PeerKey {
        alg: identity.alg().name().to_string(),
        pub_key: identity.pub_key().to_vec(),
    };

    let (status, genesis) = post_json(app.clone(), "/push", body(&commits[0])).await;
    assert_eq!(status, StatusCode::CREATED, "{genesis:?}");
    let (status, push) = post_json(app.clone(), "/push", body(&commits[1])).await;
    assert_eq!(status, StatusCode::CREATED, "{push:?}");
    let claims = &push["statement"]["coz"]["pay"]["roots"];
    assert!(
        claims["sr"].is_null() && claims["ar"].is_null(),
        "{claims:?}"
    );
    assert!(
        claims["pr"].is_string() && claims["cr"].is_string(),
        "{claims:?}"
    );
    assert_eq!(claims["pr"], claims["cr"], "PR is the promoted CR");
    let roots = &push["payload"]["roots"];
    assert!(roots["sr"].is_null() && roots["ar"].is_null(), "{roots:?}");
    let report = verify_authenticated_envelope(&push, &authority, &principal_id)
        .expect("the client verifies the dying commit's receipt");
    assert_eq!((report.roots.sr, report.roots.ar), (None, None));

    let (status, tip) = get_json(app, &format!("/tip?pg={principal_id}")).await;
    assert_eq!(status, StatusCode::OK, "{tip:?}");
    assert!(tip["payload"]["sr"].is_null() && tip["payload"]["ar"].is_null());
    let claims = &tip["statement"]["coz"]["pay"]["roots"];
    assert!(
        claims["sr"].is_null() && claims["ar"].is_null(),
        "{claims:?}"
    );
    let report = verify_authenticated_envelope(&tip, &authority, &principal_id)
        .expect("the client verifies the tip report");
    assert_eq!((report.roots.sr, report.roots.ar), (None, None));
    assert!(report.roots.cr.is_some());
}
