//! The Noise transport, observed from outside: a real client handshake
//! against a shipped peer, and a hostile responder for the version check.
//!
//! Nothing here mocks the system under test. The client is
//! `cyphr_net::transport::NoiseConnector`; the peer is the shipped
//! `cyphr-server` process. The hostile responder is the other party of the
//! one scenario that needs a peer misbehaving on purpose, and it speaks the
//! same wire through the same `Channel`.

use std::net::SocketAddr;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr_net::transport::{
    Channel, MAX_MESSAGE, NoiseConnector, Role, assemble_statement, decode_request, encode_ack,
    encode_response, statement_pay,
};
use cyphr_net::{
    BindingKind, BindingPolicy, Connector, PatchFailure, PatchRequest, PeerChain, Request,
    fetch_patch,
};
use tokio::net::TcpListener;

use crate::peer::Peer;

/// A fresh Ed25519 key and its thumbprint: a principal's whole identity at
/// Level 1.
struct Identity {
    kp: coz::KeyPair,
    tmb: coz::Thumbprint,
}

impl Identity {
    fn generate() -> Result<Self, String> {
        let kp = coz::Alg::Ed25519.generate_keypair();
        let tmb = kp
            .alg
            .compute_thumbprint(&kp.pub_bytes)
            .ok_or("no thumbprint for a fresh Ed25519 key")?;
        Ok(Self { kp, tmb })
    }

    /// The id of this Level 1 principal: its key's thumbprint, under the
    /// hash its own algorithm names.
    fn pg(&self) -> Result<cyphr::PrincipalGenesis, String> {
        let alg = cyphr::state::hash_alg_from_str(self.kp.alg.name()).map_err(|e| e.to_string())?;
        cyphr::PrincipalGenesis::from_digest(alg, self.tmb.as_bytes().to_vec())
            .map_err(|e| e.to_string())
    }

    fn signer(&self) -> SoftwareSigner {
        SoftwareSigner::new(
            self.kp.alg.name(),
            &self.kp.prv_bytes,
            &self.kp.pub_bytes,
            &self.tmb,
        )
    }

    async fn pin(&self) -> Result<PeerChain, String> {
        let key = cyphr::Key::new(
            self.kp.alg.name().to_string(),
            self.tmb.clone(),
            self.kp.pub_bytes.clone(),
        )
        .map_err(|e| e.to_string())?;
        Ok(PeerChain::pin(&self.pg()?, key).await)
    }
}

/// Complete a handshake with `peer` as a fresh Level 1 principal and serve
/// one request over it. The pass condition is the protocol's own: `connect`
/// returns only once the peer's statement verified against its pinned
/// chain, and the peer accepted ours, so a request served here means both
/// signed statements verified.
pub async fn handshake(peer: &Peer, http: &reqwest::Client) -> Result<(), String> {
    let addr = peer
        .transport_addr()
        .await
        .ok_or("the peer announced no transport address")?;
    handshake_at(addr, peer.addr(), http).await
}

/// A fresh authenticated session with `peer`: the channel a native client's
/// login is sent on. Every call is a new handshake, so two calls are two
/// channels, and the binding is read from the session itself.
pub async fn open_session(peer: &Peer, http: &reqwest::Client) -> Result<NoiseConnector, String> {
    let addr = peer
        .transport_addr()
        .await
        .ok_or("the peer announced no transport address")?;
    connect_fresh(addr, peer.addr(), http).await
}

/// [`handshake`] against an explicit transport address, with the pin
/// material read from the peer's HTTP face at `http_addr`.
pub async fn handshake_at(
    addr: SocketAddr,
    http_addr: SocketAddr,
    http: &reqwest::Client,
) -> Result<(), String> {
    connect_fresh(addr, http_addr, http)
        .await?
        .exchange(&Request::get("/server"))
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

/// An authenticated session as a fresh Level 1 principal.
async fn connect_fresh(
    addr: SocketAddr,
    http_addr: SocketAddr,
    http: &reqwest::Client,
) -> Result<NoiseConnector, String> {
    let discovery: serde_json::Value = http
        .get(format!("http://{http_addr}/server"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let d = &discovery["payload"];
    let g = &d["genesis"];
    let field = |v: &serde_json::Value, name: &str| -> Result<Vec<u8>, String> {
        let s = v[name]
            .as_str()
            .ok_or_else(|| format!("/server has no `{name}`"))?;
        Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("`{name}`: {e}"))
    };
    let genesis = cyphr::Key::new(
        g["alg"].as_str().ok_or("/server genesis has no alg")?,
        coz::Thumbprint::from_bytes(field(g, "tmb")?),
        field(g, "pub")?,
    )
    .map_err(|e| e.to_string())?
    .with_first_seen(g["first_seen"].as_i64().ok_or("no first_seen")?);
    let server_pg: cyphr::PrincipalGenesis = d["pg"]
        .as_str()
        .ok_or("/server has no pg")?
        .parse()
        .map_err(|e: cyphr::Error| e.to_string())?;
    let mut held = PeerChain::pin(&server_pg, genesis).await;
    // The peer may have rotated its signing key since its genesis: a client
    // brings the chain it pinned up to the peer's own, from the peer's own
    // HTTP face, before it judges the key the peer signs the handshake with.
    held.follow(&cyphr_net::HttpConnector::new(
        http.clone(),
        &format!("http://{http_addr}"),
    ))
    .await
    .map_err(|e| format!("following the peer's own chain: {e}"))?;

    let me = Identity::generate()?;
    NoiseConnector::connect(addr, &mut held, &me.signer(), &me.pg()?)
        .await
        .map_err(|e| e.to_string())
}

/// A responder that authenticates honestly as a fresh principal and then
/// answers every request with `envelope`. Returns the address and the chain
/// a client pins to trust it.
async fn hostile_responder(envelope: Vec<u8>) -> Result<(SocketAddr, PeerChain), String> {
    let me = Identity::generate()?;
    let pinned = me.pin().await?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        // One session is all the observation needs; any error just ends it.
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let _ = serve_envelope(stream, &me, &envelope).await;
    });
    Ok((addr, pinned))
}

async fn serve_envelope(
    stream: tokio::net::TcpStream,
    me: &Identity,
    envelope: &[u8],
) -> Result<(), cyphr_net::transport::TransportError> {
    let mut channel = Channel::respond(stream).await?;
    let h = channel.handshake_hash().to_vec();
    let alg = me.kp.alg.name();
    let pay = statement_pay(
        alg,
        &me.tmb,
        &me.pg()
            .map_err(|_| cyphr_net::transport::TransportError::BadBinding {
                what: "the hostile responder has no id",
            })?,
        Role::Responder,
        &h,
        0,
    )?;
    let sig = coz::sign_json(&pay, alg, &me.kp.prv_bytes, &me.kp.pub_bytes)
        .map(|(sig, _)| sig)
        .ok_or(cyphr_net::transport::TransportError::BadBinding {
            what: "the hostile responder could not sign",
        })?;
    channel
        .send_one(&assemble_statement(&pay, &sig, None)?)
        .await?;
    // The initiator is not judged: the observation is the client's, not ours.
    channel.recv_one().await?;
    channel.send_one(&encode_ack(Ok(()))).await?;
    loop {
        let request = channel.recv_message(MAX_MESSAGE).await?;
        decode_request(&request)?;
        channel
            .send_message(&encode_response(200, envelope))
            .await?;
    }
}

/// Whether a transport client fails closed on an envelope of version `v`:
/// a hostile responder authenticates honestly and serves `v`, and the
/// client's patch fetch must refuse with the typed `UnsupportedVersion`
/// naming `v`.
pub async fn client_fails_closed_on_version(v: u64) -> Result<bool, String> {
    let envelope = serde_json::to_vec(&serde_json::json!({
        "v": v,
        "payload": { "entries": [] },
        "statement": { "kind": "unsigned" },
    }))
    .map_err(|e| e.to_string())?;
    Ok(is_version_refusal(&fetch_from_hostile(envelope).await?, v))
}

/// Whether a patch fetch ended in the typed `UnsupportedVersion` naming `v`
/// and not in some other failure.
fn is_version_refusal<T>(outcome: &Result<T, PatchFailure>, v: u64) -> bool {
    matches!(outcome, Err(PatchFailure::UnsupportedVersion { found, .. }) if *found == v)
}

/// What a transport client's patch fetch makes of `envelope`, served by an
/// honestly authenticated hostile responder.
async fn fetch_from_hostile(
    envelope: Vec<u8>,
) -> Result<Result<cyphr_net::VerifiedPatch, PatchFailure>, String> {
    let (addr, mut pinned) = hostile_responder(envelope).await?;
    let me = Identity::generate()?;
    let conn = NoiseConnector::connect(addr, &mut pinned, &me.signer(), &me.pg()?)
        .await
        .map_err(|e| e.to_string())?;
    let pg = pinned.pg().clone();
    Ok(fetch_patch(
        &conn,
        &PatchRequest {
            principal_id: &pg,
            anchor: None,
        },
        BindingPolicy::Required(BindingKind::NoiseHandshakeHash),
        None,
    )
    .await)
}

// These claims back the probes in `capability.rs` that observe the
// transport. They live here, beside the code they exercise, because no
// scenario reaches a probe's own controls.
/// A hostile HTTP responder on loopback: it answers every request with a
/// valid-shaped envelope stating version `v`, then closes. The task lives as
/// long as the test's runtime. Returns its address.
pub async fn serve_http_envelope_version(v: u64) -> Result<SocketAddr, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "v": v, "payload": { "entries": [], "branches": [], "items": [] },
        "statement": { "kind": "unsigned" },
    })
    .to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                // Read the request head, then answer; the body is ignored.
                let mut head = [0u8; 4096];
                let _ = stream.read(&mut head).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: \
                     {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Harness;
    use crate::capability::{Capability, Probe};

    // Claim: the Transport probe observes a real principal-authenticated
    // handshake, not an announcement. Positive control: the shipped keyed
    // peer completes it (both statements verify, a request is served).
    // Negative control: the same handshake aimed at the peer's HTTP port,
    // which is not the transport, fails, so a probe that always says
    // present cannot pass.
    // Turns red if: the probe reads a banner, or the handshake helper
    // never verifies the peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn transport_probe_needs_a_completed_handshake() {
        let h = Harness::start(&["p1"]).await.expect("start peer");
        assert!(
            Probe::Handshake
                .eval(&h, Capability::Transport)
                .await
                .expect("probe runs"),
            "a keyed peer must complete the handshake"
        );
        let p1 = h.peer("p1");
        assert!(
            handshake_at(p1.addr(), p1.addr(), &h.http).await.is_err(),
            "a listener that is not the transport must not read as authenticated"
        );
    }

    // Claim: the VersionCheck probe sees a client fail closed on a hostile
    // envelope version, and only on the version it was rigged with.
    // Control: an envelope of the version the client understands (1) is
    // not an UnsupportedVersion refusal, and a malformed body is another
    // typed refusal, so the probe does not read every failure as present.
    // Turns red if: the probe reports present for any failed fetch.
    #[tokio::test]
    async fn version_probe_distinguishes_the_hostile_version() {
        assert!(client_fails_closed_on_version(99).await.expect("runs"));
        assert!(!client_fails_closed_on_version(1).await.expect("runs"));
        // A refusal of another kind (malformed) is not the version gate.
        let malformed = fetch_from_hostile(b"not json".to_vec())
            .await
            .expect("runs");
        assert!(malformed.is_err(), "the control must be a refusal");
        assert!(!is_version_refusal(&malformed, 99));
    }
}
