//! `GET /metrics` -- minimal Prometheus text exposition (G6, a-metrics).
//!
//! Run the reds with `cargo test -p cyphr-server --test metrics -- --ignored`.
//!
//! The metric format is the implementer's (delegated), but a test needs
//! names, so THIS SUITE pins three counter families, per
//! <https://prometheus.io/docs/instrumenting/exposition_formats/> and the
//! `_total` counter convention:
//!
//! - `cyphr_requests_total` -- every request answered;
//! - `cyphr_pushes_accepted_total` -- pushes that returned 2xx;
//! - `cyphr_refusals_total{kind="..."}` -- refused requests, one series per kind. The label values
//!   are free; the suite requires only that distinct refusal kinds (400 malformed vs 422 protocol)
//!   are distinct series and that the label set stays bounded and free of request content.
//!
//! Traffic goes through the production router (`build_app_router`).

use std::collections::BTreeMap;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use cyphr_server::build_app_router;
use http_body_util::BodyExt;
use tower::ServiceExt;

mod common;

use common::{build_genesis_push_body, golden_principal_id, keyless_server, load_pool};

const REQUESTS: &str = "cyphr_requests_total";
const PUSHES: &str = "cyphr_pushes_accepted_total";
const REFUSALS: &str = "cyphr_refusals_total";
const EML_BEHIND: &str = "cyphr_eml_append_failures_total";

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn get(app: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    send(
        app,
        Request::builder().uri(uri).body(Body::empty()).unwrap(),
    )
    .await
}

async fn push(app: &Router, body: String) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/push")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    send(app, req).await.0
}

/// Parse the exposition body into `series (name + labels) -> value`.
/// Comment lines (`# HELP`, `# TYPE`) are skipped.
fn parse(text: &str) -> BTreeMap<String, f64> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (series, value) = l.rsplit_once(char::is_whitespace)?;
            Some((series.trim().to_string(), value.parse().ok()?))
        })
        .collect()
}

/// Sum of every series of family `name` (labelled or not).
fn family_sum(m: &BTreeMap<String, f64>, name: &str) -> f64 {
    m.iter()
        .filter(|(k, _)| k.split('{').next() == Some(name))
        .map(|(_, v)| v)
        .sum()
}

/// Series of family `name`.
fn family<'a>(m: &'a BTreeMap<String, f64>, name: &str) -> BTreeMap<&'a str, f64> {
    m.iter()
        .filter(|(k, _)| k.split('{').next() == Some(name))
        .map(|(k, v)| (k.as_str(), *v))
        .collect()
}

async fn scrape(app: &Router) -> (BTreeMap<String, f64>, String) {
    let (status, headers, body) = get(app, "/metrics").await;
    assert_eq!(status, StatusCode::OK, "/metrics must answer 200: {body}");
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("text/plain"),
        "Prometheus text exposition is text/plain, got {content_type:?}"
    );
    (parse(&body), body)
}

/// Claim: the counters reflect traffic -- accepted pushes, refusals by
/// kind, and requests each move by exactly what happened, and nothing else
/// moves them. Traffic: 1 accepted push, 1 malformed push (400), 1 replayed
/// push (422 COZ_REUSE); three non-scrape requests in all.
/// Defects that turn it red: no endpoint (404 today); a counter that never
/// moves; a push counter that counts refused pushes or every request; a
/// refusal counter with no kind (one series, not two); a request counter
/// that double-counts.
/// End-to-end: yes (real router, real storage, real signed push).
#[tokio::test]
async fn metrics_counters_move_exactly_with_traffic() {
    let (state, _dir) = keyless_server();
    let app = build_app_router(state).expect("router");
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;

    let (before, _) = scrape(&app).await;

    let good = build_genesis_push_body(&pool, &id, 1_700_100_000).await;
    assert_eq!(push(&app, good.clone()).await, StatusCode::CREATED);
    assert_eq!(push(&app, "garbage".into()).await, StatusCode::BAD_REQUEST);
    assert_eq!(
        push(&app, good).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "replaying the same bundle is a protocol refusal"
    );

    let (after, _) = scrape(&app).await;

    assert_eq!(
        family_sum(&after, PUSHES) - family_sum(&before, PUSHES),
        1.0,
        "exactly one accepted push (refused pushes must not count): {after:?}"
    );
    assert_eq!(
        family_sum(&after, REFUSALS) - family_sum(&before, REFUSALS),
        2.0,
        "exactly two refusals: {after:?}"
    );
    let request_delta = family_sum(&after, REQUESTS) - family_sum(&before, REQUESTS);
    assert!(
        (3.0..=5.0).contains(&request_delta),
        "three requests plus at most the two scrapes' own self-counts, got {request_delta}"
    );

    // Refusals are counted "by kind": the 400 and the 422 land in distinct
    // series, one each.
    let (b, a) = (family(&before, REFUSALS), family(&after, REFUSALS));
    let moved: Vec<f64> = a
        .iter()
        .map(|(k, v)| v - b.get(k).copied().unwrap_or(0.0))
        .filter(|d| *d != 0.0)
        .collect();
    assert_eq!(
        moved,
        vec![1.0, 1.0],
        "two refusal kinds must move two distinct series by one each: {a:?}"
    );

    // The commit-log-behind series is exposed, and none of the traffic
    // above (accepted or refused) counts as a failed log append. A real
    // append failure cannot be injected below the server's concrete
    // storage; `commit_order` pins that the engine count it reads moves.
    assert_eq!(
        after.get(EML_BEHIND).copied(),
        Some(0.0),
        "the commit-log-behind series is exposed and stays 0 on a healthy log: {after:?}"
    );
}

/// Claim: counters never name a principal, a key, or request content, and
/// their label set stays bounded no matter what a client sends.
/// Traffic embeds the principal id in query strings and paths, a
/// distinctive marker in request bodies, and 20 distinct malformed bodies.
/// Defects that turn it red: no endpoint; a label built from the URI, the
/// `principal_id`, the error message or any body text (leak, and unbounded
/// series growth under the 20 distinct bodies).
/// End-to-end: no (property of the exposition over adversarial traffic;
/// a unit-scale check is enough because the leak is in the label set).
#[tokio::test]
async fn metrics_carry_no_identifier_and_bounded_labels() {
    let (state, _dir) = keyless_server();
    let app = build_app_router(state).expect("router");
    let pool = load_pool();
    let id = golden_principal_id(&pool).await;
    let golden = pool.get("golden").expect("golden key");
    let marker = "LEAKMARKER-8f3a1c";

    assert_eq!(
        push(
            &app,
            build_genesis_push_body(&pool, &id, 1_700_100_000).await
        )
        .await,
        StatusCode::CREATED
    );
    for uri in [
        format!("/tip?pg={id}"),
        format!("/patch?pg={id}"),
        format!("/e/{marker}"),
    ] {
        let _ = get(&app, &uri).await;
    }
    // Distinct, content-bearing refused bodies.
    let (series_after_one, _) = {
        let _ = push(&app, format!(r#"{{"principal_id":"{marker}-0","txs":[]}}"#)).await;
        scrape(&app).await
    };
    for i in 1..20 {
        let _ = push(
            &app,
            format!(r#"{{"principal_id":"{marker}-{i}","txs":[]}}"#),
        )
        .await;
    }

    let (series, text) = scrape(&app).await;
    let id_text = id.to_string();
    // The digest part is a substring of every spelling of the id.
    let id_digest = id_text.split_once(':').expect("labelled id").1;
    for secret in [id_digest, golden.pub_key.as_str(), marker] {
        assert!(
            !text.contains(secret),
            "exposition leaks {secret:?}:\n{text}"
        );
    }
    assert!(
        family(&series, REFUSALS).len() <= family(&series_after_one, REFUSALS).len(),
        "19 more refusals of the same kind must not mint new series:\n{text}"
    );
    assert!(
        family(&series, REFUSALS).len() <= 8,
        "refusal kinds are a small closed set, got {:?}",
        family(&series, REFUSALS)
    );
}
