//! Receipts and tip attestations sign through a `ReceiptSigner`, and a
//! signing failure never turns a committed push into an error.
//!
//! The typed reason a signature failed is server-side (`ReceiptError`), not a
//! wire field: an unsigned statement is unauthenticated, so a client cannot
//! act on a reason carried in it. The wire shows only `{"kind":"unsigned"}`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SignerError;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::build_router;
use cyphr_server::receipt::{ReceiptError, ReceiptSigner, Roots, commit_receipt};

mod common;

use common::{
    build_genesis_push_body, get_json, golden_principal_id, keyed_appstate, load_pool, post_json,
    write_signing_key,
};

/// A signing backend that is down (device unavailable, user denied): it
/// reports the key it would sign with, then fails every signature.
struct FailingSigner {
    alg: String,
    pub_key: Vec<u8>,
}

impl ReceiptSigner for FailingSigner {
    fn alg(&self) -> &str {
        &self.alg
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn sign<'a>(
        &'a self,
        _cad: &'a coz::Cad,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, SignerError>> + Send + 'a>> {
        Box::pin(async { Err(SignerError::Backend("signing device unavailable".into())) })
    }
}

/// A bootstrapped attestor whose receipts sign through `signer` when one is
/// given, else through its own identity. Returns the app and the temp dir
/// guard.
async fn attestor_with(
    failing: bool,
) -> (
    axum::Router,
    std::sync::Arc<cyphr_server::AppState>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = write_signing_key(dir.path());
    let mut state = keyed_appstate(&dir.path().join("data"), &key_path);
    let identity = state.identity.clone().expect("keyed state has identity");
    let sp = ServerPrincipal::bootstrap(
        &state.engine,
        identity.clone(),
        &key_path,
        &state.config.data_dir,
    )
    .await
    .expect("bootstrap the server principal");
    state.principal = Some(Arc::new(sp));
    let signer: Arc<dyn ReceiptSigner> = if failing {
        Arc::new(FailingSigner {
            alg: identity.alg().name().to_string(),
            pub_key: identity.pub_key().to_vec(),
        })
    } else {
        identity
    };
    let state = Arc::new(state.with_receipt_signer(signer));
    (build_router(state.clone()), state, dir)
}

/// Claim: a signing failure never turns a committed push into an error. The
/// commit stays durable and is reported (201), the statement slot says
/// `unsigned`, and the committed state is readable afterwards.
///
/// Turns red if: the push answers 500 after the commit landed; the answer
/// claims `signed` without a signature that verifies; or the commit is not
/// durable. End-to-end scenario: yes (real `/push`, then `/tip`).
#[tokio::test]
async fn failing_signer_leaves_a_committed_push_answered_201_unsigned() {
    let (app, _state, _dir) = attestor_with(true).await;
    let pool = load_pool();
    let pr = golden_principal_id(&pool);

    let (status, push) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &pr, 1_700_000_000),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "committed push: {push:?}");
    assert_eq!(
        push["statement"],
        serde_json::json!({"kind": "unsigned"}),
        "an unsignable receipt degrades to unsigned: {push:?}"
    );
    assert!(
        push["payload"]["commit_id"].is_string(),
        "the commit is still reported: {push:?}"
    );

    // Control on durability: the commit really landed.
    let (status, tip) = get_json(app, &format!("/tip?pr={pr}")).await;
    assert_eq!(status, StatusCode::OK, "tip after commit: {tip:?}");
    assert_eq!(tip["payload"]["commit_count"], serde_json::json!(1));
}

/// Claim: an unsignable tip attestation is served unsigned, never as a 500:
/// the tip is true whether or not the server could attest it.
///
/// Turns red if: `/tip` answers 500 ("tip attestation signing unavailable")
/// or answers `signed`. End-to-end scenario: yes.
#[tokio::test]
async fn failing_signer_leaves_a_tip_answered_200_unsigned() {
    let (app, _state, _dir) = attestor_with(true).await;
    let pool = load_pool();
    let pr = golden_principal_id(&pool);
    let (status, push) = post_json(
        app.clone(),
        "/push",
        build_genesis_push_body(&pool, &pr, 1_700_000_000),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{push:?}");

    let (status, tip) = get_json(app, &format!("/tip?pr={pr}")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unsignable tip is not a 500: {tip:?}"
    );
    assert_eq!(
        tip["statement"],
        serde_json::json!({"kind": "unsigned"}),
        "{tip:?}"
    );
    assert_eq!(tip["payload"]["commit_count"], serde_json::json!(1));
}

/// Positive control: the same scenario with a working injected signer
/// answers `signed`, so the two tests above fail on the signer and not on
/// the harness. Turns red if the injected signer is ignored (receipts still
/// sign with the live identity regardless of `with_receipt_signer`).
/// End-to-end scenario: yes.
#[tokio::test]
async fn working_injected_signer_still_signs_the_push() {
    let (app, _state, _dir) = attestor_with(false).await;
    let pool = load_pool();
    let pr = golden_principal_id(&pool);
    let (status, push) = post_json(
        app,
        "/push",
        build_genesis_push_body(&pool, &pr, 1_700_000_000),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{push:?}");
    assert_eq!(push["statement"]["kind"], serde_json::json!("signed"));
}

/// Claim: the typed reason is server-side. The receipt constructor reports
/// the signer's failure as `ReceiptError::Signer`, not as a malformed field
/// and not as a silent `None`.
///
/// Turns red if: the constructor returns anything but `Err(Signer(_))` for a
/// failing signer, so a caller (and the warn log) cannot tell a down backend
/// from a bad value. A unit test because the reason is deliberately not on
/// the wire, so no HTTP scenario can observe it.
#[tokio::test]
async fn commit_receipt_reports_a_signer_failure_as_receipt_error_signer() {
    let signer = FailingSigner {
        alg: "Ed25519".to_string(),
        pub_key: coz::Alg::Ed25519.generate_keypair().pub_bytes,
    };
    let digest = |n: u8| format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[n; 32]));
    let roots = Roots {
        pr: digest(1),
        sr: Some(digest(2)),
        ar: Some(digest(3)),
        cr: Some(digest(4)),
    };
    let pr = Base64UrlUnpadded::encode_string(&[7u8; 32]);

    let result = commit_receipt(&signer, 1_700_000_000, pr, 0, digest(5), &roots).await;
    assert!(
        matches!(result, Err(ReceiptError::Signer(_))),
        "a failing signer must surface as ReceiptError::Signer: {result:?}"
    );
}
