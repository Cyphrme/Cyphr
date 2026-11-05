//! Carrier-seam scenarios for the sync verify core.
//!
//! Claim: sync does not depend on the carrier. Each test is an
//! end-to-end-ish scenario over the public API only; none reaches into a
//! carrier-specific path. They turn red if the verify core grows a branch
//! that behaves differently per carrier, or if a binding requirement is
//! not enforced before any bytes are exchanged.

use std::sync::atomic::{AtomicUsize, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{
    AuthorityKey, BindingError, BindingKind, BindingPolicy, ChannelBinding, ConnectError,
    Connector, HttpConnector, PatchFailure, PatchRequest, fetch_patch,
    verify_authenticated_envelope,
};

/// base64url of 32 bytes `b`, the bare genesis-id / digest body form.
fn b64(b: u8) -> String {
    Base64UrlUnpadded::encode_string(&[b; 32])
}

struct Authority {
    key: AuthorityKey,
    prv: Vec<u8>,
}

fn authority() -> Authority {
    let kp = coz::Alg::Ed25519.generate_keypair();
    Authority {
        key: AuthorityKey {
            alg: kp.alg.name().to_string(),
            pub_key: kp.pub_bytes.clone(),
        },
        prv: kp.prv_bytes.clone(),
    }
}

fn sign(auth: &Authority, pay: serde_json::Value) -> serde_json::Value {
    let bytes = serde_json::to_vec(&pay).unwrap();
    let (sig, _) = coz::sign_json(&bytes, &auth.key.alg, &auth.prv, &auth.key.pub_key).unwrap();
    serde_json::json!({
        "kind": "signed",
        "coz": { "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) },
    })
}

/// A two-entry patch for principal `pr`, signed by `auth`.
fn patch_body(auth: &Authority, pr: &str) -> Vec<u8> {
    let digest = |b: u8| format!("SHA-256:{}", b64(b));
    let pay = serde_json::json!({
        "alg": auth.key.alg,
        "typ": "cyphr-server/tip",
        "pr": pr,
        "sequence": 1,
        "commit_id": digest(9),
        "roots": { "pr": digest(1), "sr": digest(2), "ar": digest(3), "cr": digest(4) },
    });
    let entry = |seq: u64, blob: &[u8]| serde_json::json!({ "sequence": seq, "blobs": [Base64UrlUnpadded::encode_string(blob)] });
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "payload": { "entries": [entry(0, b"blob-zero"), entry(1, b"blob-one")] },
        "statement": sign(auth, pay),
    }))
    .unwrap()
}

/// An in-memory carrier: serves a canned body and counts exchanges.
struct Pipe {
    body: Vec<u8>,
    binding: Option<ChannelBinding>,
    exchanges: AtomicUsize,
}

impl Pipe {
    fn new(body: Vec<u8>, binding: Option<ChannelBinding>) -> Self {
        Self {
            body,
            binding,
            exchanges: AtomicUsize::new(0),
        }
    }
}

impl Connector for Pipe {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        self.binding.as_ref()
    }

    async fn exchange(&self, _request: &[u8]) -> Result<Vec<u8>, ConnectError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.clone())
    }
}

/// Serve `body` to every connection on a loopback socket as HTTP/1.1.
async fn serve_http(body: Vec<u8>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                     {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

const PR: &str = "SHA-256:principal";

/// Claim: the same authority body yields the same verified entries and the
/// same attested tip over HTTP and over an in-memory pipe. Red if the core
/// has a carrier-specific path. End-to-end scenario: no (client-side only).
#[tokio::test]
async fn connector_pipe_and_http_reach_same_verified_tip() {
    let auth = authority();
    // `pr` must be canonical b64ut of a supported digest length.
    let pr_wire = b64(7);
    let body = patch_body(&auth, &pr_wire);
    let request = PatchRequest {
        principal_id: &format!("SHA-256:{pr_wire}"),
        anchor: None,
    };

    let pipe = Pipe::new(body.clone(), None);
    let over_pipe = fetch_patch(&pipe, &request, BindingPolicy::NotRequired, Some(&auth.key))
        .await
        .expect("pipe sync verifies");

    let base = serve_http(body).await;
    let http = HttpConnector::new(reqwest::Client::new(), &base);
    let over_http = fetch_patch(&http, &request, BindingPolicy::NotRequired, Some(&auth.key))
        .await
        .expect("http sync verifies");

    assert_eq!(
        over_pipe, over_http,
        "the carrier changed the verified result"
    );
    assert_eq!(over_pipe.entries.len(), 2);
    assert_eq!(over_pipe.report.expect("report verified").sequence, 1);
}

/// Claim: a required binding is enforced before any byte is exchanged.
/// Red if the requirement is skipped, or checked only after the fetch.
#[tokio::test]
async fn connector_without_binding_refused_when_required() {
    let auth = authority();
    let pipe = Pipe::new(patch_body(&auth, &b64(7)), None);
    let request = PatchRequest {
        principal_id: PR,
        anchor: None,
    };
    let err = fetch_patch(
        &pipe,
        &request,
        BindingPolicy::Required(BindingKind::NoiseHandshakeHash),
        Some(&auth.key),
    )
    .await
    .expect_err("a binding-less carrier must be refused");
    assert_eq!(
        err,
        PatchFailure::Binding(BindingError::Missing {
            required: BindingKind::NoiseHandshakeHash
        })
    );
    assert_eq!(
        pipe.exchanges.load(Ordering::SeqCst),
        0,
        "request left the client"
    );
}

/// Claim: a carrier that does expose the required binding syncs, and the
/// binding reaches the caller (SO3/TR1 consume it). Red if the binding is
/// dropped or the requirement refuses everything.
#[tokio::test]
async fn connector_binding_is_exposed_to_caller() {
    let auth = authority();
    let pr_wire = b64(7);
    let binding = ChannelBinding::new(BindingKind::NoiseHandshakeHash, vec![0xAA; 32]);
    let pipe = Pipe::new(patch_body(&auth, &pr_wire), Some(binding.clone()));
    let request = PatchRequest {
        principal_id: &format!("SHA-256:{pr_wire}"),
        anchor: None,
    };
    let got = fetch_patch(
        &pipe,
        &request,
        BindingPolicy::Required(BindingKind::NoiseHandshakeHash),
        Some(&auth.key),
    )
    .await
    .expect("bound carrier syncs");
    assert_eq!(got.binding, Some(binding));
}

/// Claim: the public envelope verifier accepts a genuine statement and
/// refuses unsigned, wrong-key and cross-principal ones with the typed
/// reason. Red if any refusal is skipped.
#[test]
fn connector_envelope_verifier_refuses_forgeries() {
    let auth = authority();
    let pr_wire = b64(7);
    let body: serde_json::Value = serde_json::from_slice(&patch_body(&auth, &pr_wire)).unwrap();
    let id = format!("SHA-256:{pr_wire}");

    let ok = verify_authenticated_envelope(&body, &auth.key, &id).expect("genuine verifies");
    assert_eq!(ok.sequence, 1);

    let other = authority();
    assert_eq!(
        verify_authenticated_envelope(&body, &other.key, &id).unwrap_err(),
        PatchFailure::EnvelopeUnsignedOrMisSigned
    );

    let mut unsigned = body.clone();
    unsigned["statement"] = serde_json::json!({ "kind": "unsigned" });
    assert_eq!(
        verify_authenticated_envelope(&unsigned, &auth.key, &id).unwrap_err(),
        PatchFailure::EnvelopeUnsignedOrMisSigned
    );

    assert_eq!(
        verify_authenticated_envelope(&body, &auth.key, &format!("SHA-256:{}", b64(8)))
            .unwrap_err(),
        PatchFailure::PrincipalMismatch
    );
}
