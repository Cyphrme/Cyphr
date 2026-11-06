//! The HTTP carrier against real sockets: what a peer receives, what the
//! client refuses to send in the clear, and TLS verification. Every test is
//! an end-to-end exchange through `HttpConnector`; none inspects its
//! internals.
//!
//! The `tests/tls/` fixtures are a test-only CA (`ca.der`, its key
//! discarded) and a `localhost`/`127.0.0.1` leaf signed by it, valid for
//! 100 years. The leaf key signs nothing but these tests' handshakes.
#![cfg(feature = "http")]

use std::sync::Arc;
use std::time::Duration;

use cyphr_client::{ConnectError, Connector, HttpConnector, HttpOptions, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ServerConfig, crypto::ring::default_provider};

const CA: &[u8] = include_bytes!("tls/ca.der");
const LEAF: &[u8] = include_bytes!("tls/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("tls/leaf.key.der");

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";

/// Read one request's head (through the blank line) from `conn`.
async fn read_head<S: AsyncReadExt + Unpin>(conn: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        conn.read_exact(&mut byte).await.expect("request head");
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("utf-8 head")
}

/// A loopback peer that answers one request with `{}` and returns the
/// request head it saw.
async fn plain_peer() -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let seen = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("accept");
        let head = read_head(&mut conn).await;
        conn.write_all(OK).await.expect("reply");
        head
    });
    (url, seen)
}

/// A loopback TLS peer (certificate for `localhost` and `127.0.0.1`) that
/// answers one request with `{}`.
async fn tls_peer() -> String {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(LEAF_KEY.to_vec()));
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(LEAF.to_vec())], key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("https://localhost:{}", listener.local_addr().expect("addr").port());
    tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // A failed handshake (the untrusted-client case) is the
                // client's refusal, not this peer's error.
                let Ok(mut conn) = acceptor.accept(conn).await else { return };
                let _ = read_head(&mut conn).await;
                let _ = conn.write_all(OK).await;
                let _ = conn.shutdown().await;
            });
        }
    });
    url
}

fn options() -> HttpOptions {
    HttpOptions::new(Duration::from_secs(10))
}

/// Claim: a `POST` reaches a loopback `http://` peer with `content-type:
/// application/json` (the server refuses a push without it), and the
/// peer's answer comes back. Turns red when the header is absent.
#[tokio::test]
async fn post_to_loopback_peer_carries_json_content_type() {
    let (url, seen) = plain_peer().await;
    let connector = HttpConnector::connect(&url, &options()).expect("loopback http is allowed");
    let body = connector
        .exchange(&Request::post("/push", b"{\"a\":1}".to_vec()))
        .await
        .expect("exchange");
    assert_eq!(body, b"{}");
    let head = seen.await.expect("peer").to_ascii_lowercase();
    assert!(
        head.contains("content-type: application/json\r\n"),
        "request head: {head}"
    );
}

/// Claim: cleartext to a non-loopback host is refused with a typed error
/// that names the host, before any connection; the explicit opt-in lifts
/// the refusal. Turns red when the scheme is not checked or the opt-in is
/// ignored.
#[test]
fn cleartext_to_a_non_loopback_peer_needs_the_explicit_opt_in() {
    let refused = HttpConnector::connect("http://192.0.2.1:8080", &options());
    assert!(
        matches!(&refused, Err(ConnectError::CleartextRefused { host }) if host == "192.0.2.1"),
        "got {:?}",
        refused.err()
    );
    let mut opted_in = options();
    opted_in.allow_cleartext = true;
    assert!(HttpConnector::connect("http://192.0.2.1:8080", &opted_in).is_ok());
}

/// Claim: an `https://` peer whose certificate chains to a trusted root
/// works end to end, and the same peer is refused when the root is not
/// trusted (verification is on). Turns red when TLS is unavailable, or when
/// the client accepts any certificate.
#[tokio::test]
async fn https_peer_works_when_trusted_and_is_refused_when_not() {
    let url = tls_peer().await;

    let mut trusted = options();
    trusted.trust_root_der = vec![CA.to_vec()];
    let connector = HttpConnector::connect(&url, &trusted).expect("https needs no opt-in");
    let body = connector.exchange(&Request::get("/tip")).await.expect("trusted https exchange");
    assert_eq!(body, b"{}");

    let untrusting = HttpConnector::connect(&url, &options()).expect("https needs no opt-in");
    let refused = untrusting.exchange(&Request::get("/tip")).await;
    assert!(matches!(refused, Err(ConnectError::Unreachable(_))), "got {refused:?}");
}
