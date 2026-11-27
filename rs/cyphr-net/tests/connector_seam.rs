//! Carrier-seam scenarios for the sync verify core.
//!
//! Claim: sync does not depend on the carrier. Each test is an
//! end-to-end-ish scenario over the public API only; none reaches into a
//! carrier-specific path. They turn red if the verify core grows a branch
//! that behaves differently per carrier, or if a binding requirement is
//! not enforced before any bytes are exchanged.

use std::sync::atomic::{AtomicUsize, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_net::{
    BindingError, BindingKind, BindingPolicy, ChannelBinding, ConnectError, Connector,
    HttpConnector, PatchFailure, PatchRequest, PeerKey, Request, fetch_patch,
    verify_authenticated_envelope,
};

/// base64url of 32 bytes `b`, the bare genesis-id / digest body form.
fn b64(b: u8) -> String {
    Base64UrlUnpadded::encode_string(&[b; 32])
}

struct Authority {
    key: PeerKey,
    prv: Vec<u8>,
}

fn authority() -> Authority {
    let kp = coz::Alg::Ed25519.generate_keypair();
    Authority {
        key: PeerKey {
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

/// A two-entry patch for the principal whose bare digest is `pr` (the
/// statement carries it labelled), signed by `auth`.
fn patch_body(auth: &Authority, pr: &str) -> Vec<u8> {
    let digest = |b: u8| format!("SHA-256:{}", b64(b));
    let pay = serde_json::json!({
        "alg": auth.key.alg,
        "typ": "cyphr-server/receipt/tip",
        "pg": format!("SHA-256:{pr}"),
        "sequence": 1,
        "commit_id": digest(9),
        "roots": { "pr": digest(1), "sr": digest(2), "ar": digest(3), "cr": digest(4) },
    });
    let entry = |seq: u64, blob: &[u8]| serde_json::json!({ "sequence": seq, "txs": [[Base64UrlUnpadded::encode_string(blob)]] });
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

    async fn exchange(&self, _request: &Request) -> Result<Vec<u8>, ConnectError> {
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
        principal_id: &format!("SHA-256:{pr_wire}").parse().expect("labelled id"),
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
        principal_id: &format!("SHA-256:{}", b64(7)).parse().expect("labelled id"),
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
/// binding reaches the caller (the sign-on and transport layers consume it). Red if the binding is
/// dropped or the requirement refuses everything.
#[tokio::test]
async fn connector_binding_is_exposed_to_caller() {
    let auth = authority();
    let pr_wire = b64(7);
    let binding = ChannelBinding::new(BindingKind::NoiseHandshakeHash, vec![0xAA; 32]);
    let pipe = Pipe::new(patch_body(&auth, &pr_wire), Some(binding.clone()));
    let request = PatchRequest {
        principal_id: &format!("SHA-256:{pr_wire}").parse().expect("labelled id"),
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
    let id: cyphr::PrincipalGenesis = format!("SHA-256:{pr_wire}").parse().expect("labelled id");

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
        verify_authenticated_envelope(
            &body,
            &auth.key,
            &format!("SHA-256:{}", b64(8)).parse().expect("labelled id")
        )
        .unwrap_err(),
        PatchFailure::PrincipalMismatch
    );
}

/// Parse one HTTP/1.1 request off `sock`, answer `method SP target LF body`.
async fn echo_http(sock: &mut tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    let (head_end, len) = loop {
        let n = sock.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..i]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (i + 4, len);
        }
    };
    while raw.len() < head_end + len {
        let n = sock.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut reply = format!("{method} {target}\n").into_bytes();
    reply.extend_from_slice(&raw[head_end..]);
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        reply.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(&reply).await;
    let _ = sock.shutdown().await;
}

/// An in-memory carrier that echoes the whole request it was given.
struct EchoPipe;

impl Connector for EchoPipe {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let method = match request.method {
            cyphr_net::Method::Get => "GET",
            cyphr_net::Method::Post => "POST",
        };
        let mut reply = format!("{method} {}\n", request.target).into_bytes();
        reply.extend_from_slice(&request.body);
        Ok(reply)
    }
}

/// Claim: a write (method, target and a binary body) crosses the seam
/// intact on every carrier, so push, evidence and gossip can run over it.
/// Red if a carrier drops the method or the body, or the trait cannot
/// carry them.
#[tokio::test]
async fn connector_post_body_round_trips() {
    let body = vec![0u8, 1, 2, 255, 10, 13, 10, 13];
    let request = Request::post("/evidence?x=1", body.clone());
    let mut expected = b"POST /evidence?x=1\n".to_vec();
    expected.extend_from_slice(&body);

    assert_eq!(EchoPipe.exchange(&request).await.unwrap(), expected);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move { echo_http(&mut sock).await });
        }
    });
    let http = HttpConnector::new(reqwest::Client::new(), &format!("http://{addr}"));
    assert_eq!(
        http.exchange(&request).await.unwrap(),
        expected,
        "the HTTP carrier changed the request"
    );
}
