//! `POST /push` durability-vs-response-status coherence (#168).
//!
//! `docs/specs/receipts.md`'s receipts are the trust product of this
//! system, but the response *status itself* is also a claim the client
//! acts on. #168 is about that second claim going false while the
//! durable side effect happens anyway: a push can commit a bundle
//! durably and still report `500`, leaving the caller believing the
//! write never happened.

use axum::http::StatusCode;
use cyphr_server::build_router;

mod common;

use common::{attestor_server, build_genesis_push_body, get_json, load_pool, post_json};

/// A client-supplied identifier the engine will happily index a genesis
/// commit under (any string is a usable storage key), but that is not a
/// canonical genesis-thumbprint form -- the literal repro string from
/// #168 itself (`rs/cyphr-server/src/receipt.rs:142`'s
/// `parse_genesis_id_str` refuses it: not valid base64url-decodable to a
/// supported 32/48/64-byte digest length).
const NON_CANONICAL_PRINCIPAL_ID: &str = "bob";

/// RED (#168): pushing a valid genesis bundle under a non-canonical
/// `principal_id`, against a server that holds a signing identity, must
/// never durably accept the commit AND ALSO report the write as failed.
/// Today it does both: `POST /push` returns `500`
/// ("commit receipt signing unavailable") from
/// `rs/cyphr-server/src/routes.rs:553`-561 AFTER
/// `state.engine.submit_commit` (line 497, earlier in the same handler)
/// has already landed the write durably.
///
/// Bound two ways, independent of which of #168's two sanctioned fixes
/// lands (refuse pre-commit, or make post-commit receipt formatting
/// infallible for any `principal_id` that reached ingest):
///
/// 1. the response status must not be `500` -- a client-controlled value
///    being unparseable is a well-formed 4xx-shaped refusal, never an
///    "internal error" that implies a server fault; and
/// 2. if the response was NOT a `2xx` acceptance, the write must
///    genuinely not have landed -- re-submitting the identical bundle,
///    and reading the principal's own tip, must both behave as though the
///    first attempt never happened. This is the only way a caller could
///    ever discover, after the fact, that the first "failed" push
///    actually succeeded, which is exactly what the issue's own
///    reproduction demonstrates happens today (a follow-up login and a
///    retried push both reveal the durable write).
///
/// Mutation this binds: reverting the fix's pre-commit refusal (or its
/// infallible post-commit formatting) back to today's
/// `receipt::commit_receipt(...).ok_or_else(|| AppError::internal(...))?`
/// called strictly after `submit_commit` makes this test fail at its
/// first assertion (status1 == 500).
#[tokio::test]
async fn push_never_reports_failure_for_a_write_that_landed() {
    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let pool = load_pool();
    let now = 1_700_100_000;
    let push_body = build_genesis_push_body(&pool, NON_CANONICAL_PRINCIPAL_ID, now);

    let (status1, body1) = post_json(app.clone(), "/push", push_body.clone()).await;
    assert_ne!(
        status1,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a client-supplied, non-canonical principal_id is a 4xx-shaped refusal, never a 500 \
         internal error: {body1:?}"
    );

    if status1.is_success() {
        // The fix chose to accept the push outright: fine, and definitionally
        // not the "durable write reported as failure" defect -- nothing
        // further to check.
        return;
    }

    // The fix chose to refuse it (a 4xx). The write must then genuinely
    // not have landed: re-submitting the identical bundle must be treated
    // as a FRESH attempt, never as a duplicate of an already-durable
    // commit -- and the principal must not be readable via /tip.
    let (_status2, body2) = post_json(app.clone(), "/push", push_body).await;
    let error_text = body2["payload"]["error"].as_str().unwrap_or_default();
    assert!(
        !error_text.to_lowercase().contains("duplicate"),
        "a refused push must not have landed durably: resubmitting the identical bundle reports \
         a duplicate-key error, proving the first \"refusal\" actually committed: {body2:?}"
    );

    let (tip_status, tip_body) =
        get_json(app.clone(), &format!("/tip?pr={NON_CANONICAL_PRINCIPAL_ID}")).await;
    assert_eq!(
        tip_status,
        StatusCode::NOT_FOUND,
        "a refused push must not have landed durably: the principal is readable via /tip, \
         proving the first \"refusal\" actually committed: {tip_body:?}"
    );
}

/// Positive control: the identical bundle shape, under a CANONICAL
/// principal id, is accepted and receipted -- proving the assertions
/// above are actually discriminating on canonicality, rather than
/// vacuously passing because no push in this suite ever succeeds (or
/// because `attestor_server`/`build_genesis_push_body` themselves are
/// broken).
#[tokio::test]
async fn push_with_canonical_principal_id_is_accepted_and_receipted() {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let (state, _identity, _dir) = attestor_server().await;
    let app = build_router(state);

    let pool = load_pool();
    let principal_id = Base64UrlUnpadded::encode_string(&[0x42u8; 32]);
    let now = 1_700_100_100;
    let push_body = build_genesis_push_body(&pool, &principal_id, now);

    let (status, body) = post_json(app, "/push", push_body).await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    assert_eq!(
        body["statement"]["kind"],
        serde_json::json!("signed"),
        "a canonical principal_id must be signed: {body:?}"
    );
}
