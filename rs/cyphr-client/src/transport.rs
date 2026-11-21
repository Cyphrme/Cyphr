//! The principal-authenticated transport: Noise NN, then Cyphr-signed
//! handshake-hash statements.
//!
//! # Design
//!
//! A session has two layers. The Noise layer, `Noise_NN_25519_ChaChaPoly_
//! BLAKE2s`, gives a confidential, integrity-protected stream between two
//! unauthenticated parties, keyed by ephemeral Diffie-Hellman keys that
//! live only in memory for one handshake. The Cyphr layer then
//! authenticates the parties: each signs the Noise handshake hash `h` with
//! a key of its own principal, and the other verifies the signature
//! against that principal's chain. `h` is unique to the session and
//! identical on both sides (Noise section 11.2), so a statement is good
//! for one session and, through its `role`, one direction.
//!
//! The order is SIGMA-I (Krawczyk, "SIGMA", 2003): the responder proves
//! itself first, and the initiator sends its identity only after the
//! responder's statement verified, so an unverified peer never learns who
//! is calling. The statement is a Coz message over the pay
//! `{alg, h, now, pr, role, tmb, typ}` with `typ`
//! [`BIND_TYP`]; the pattern is TLS 1.3 `CertificateVerify` and the SSH
//! exchange-hash signature (RFC 4253 section 8), with a Cyphr key in place
//! of a certificate. The responder is judged by the keys ACTIVE in the
//! [`PeerChain`] the caller pinned ([`PeerChain::active_key`]); the
//! initiator by the chain the server stores for the principal it names (or,
//! for an unstored Level 1 principal, by its self-certifying key sidecar).
//!
//! No long-lived key exists outside Cyphr: both Noise keys are
//! per-handshake ephemerals, and the signing keys are the principals' own,
//! supplied through the [`Signer`] seam. Nothing here stores a private key.
//!
//! ## Why NN
//!
//! Noise's static-key patterns (XX, IK, XK, KK) need each authenticating
//! side to hold a long-lived static DH key, a key that is not a Cyphr key
//! and would need its own distribution, rotation and revocation. N, K and X
//! are one-way patterns (the responder cannot answer on the same stream).
//! NN has no static key at all; identity is carried entirely by the
//! signatures over the handshake hash, which is what Noise section 11.2
//! prescribes for a channel binding.
//!
//! ## Noise implementation record
//!
//! - Crate: `snow`, pinned `=0.10.0`.
//! - Audit: CI's `rust-audit` job (`rustsec/audit-check`) audits this crate at `=0.10.0`; it is the
//!   check of record. RUSTSEC-2024-0011 (unauthenticated nonce increment in the stateful
//!   `TransportState`) is patched from 0.9.5, so 0.10.0 is not affected by it.
//!
//! # Wire format
//!
//! Every handshake message and transport message is one frame: a
//! big-endian `u16` length, then the Noise message. After the handshake:
//!
//! 1. the responder sends its statement as the first transport message;
//! 2. the initiator, once it verified that, replies with its own, plus a `key` sidecar (`{alg, pub,
//!    tmb}`, the push-blob convention) beside `{pay, sig}`;
//! 3. the responder answers with one ack message, accept or a typed refusal ([`encode_ack`]), and
//!    `connect` returns only after an accept;
//! 4. the initiator then sends requests and the responder answers, each a *logical message*: a
//!    `u32` big-endian length and the body, chunked over as many Noise messages as Noise's 65535
//!    byte limit needs. A request body is `method (1 byte), target length (u16), target, payload`;
//!    a response body is `status (u16), payload`.
//!
//! A statement's plaintext is the Coz JSON; an empty plaintext is "no
//! statement". The sidecar is not signed and carries no authority of its
//! own: a responder holding a stored chain for the named principal ignores
//! it and verifies against that chain. Only for a principal it has no chain
//! for (a Level 1 principal, whose id is its key's thumbprint) does it use
//! the sidecar, and then the key must hash to the thumbprint the statement
//! names and the thumbprint must be the claimed principal.

use std::net::SocketAddr;
use std::time::Duration;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::Key;
use cyphr::signer::{Signer, SignerError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::connector::{
    BindingKind, ChannelBinding, ConnectError, Connector, Method, Request as ClientRequest,
};
use crate::peer::{HeldTip, PeerChain, PeerFailure};

/// The Noise suite: ephemeral-only keys, no static key (see "Why NN").
pub const NOISE_PARAMS: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// The `typ` of a binding statement; no other signature can be replayed as
/// one.
pub const BIND_TYP: &str = "cyphr.me/cyphr/transport/bind";

/// How long a handshake step may stall before the session is abandoned.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may wait for its response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The most plaintext one Noise message carries: 65535 less the 16-byte
/// authentication tag.
const MAX_PLAINTEXT: usize = 65535 - 16;

/// The largest logical message either side accepts, bounding what a peer
/// can make the other allocate.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Why a transport session was not established or broke off.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The socket failed.
    #[error("transport I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A handshake step took longer than [`HANDSHAKE_TIMEOUT`].
    #[error("handshake timed out")]
    Timeout,
    /// The Noise layer refused a message.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    /// A frame or message is not the shape the wire format has.
    #[error("malformed transport message: {what}")]
    Malformed {
        /// What is wrong with it.
        what: &'static str,
    },
    /// The peer sent a transport message carrying no statement.
    #[error("the peer sent no binding statement")]
    MissingStatement,
    /// A statement is not bound to this session: malformed, over another
    /// handshake hash, or not signed by the key it names.
    #[error("binding statement refused: {what}")]
    BadBinding {
        /// Which binding check failed.
        what: &'static str,
    },
    /// A statement claims a role other than the direction it arrived in.
    #[error("binding statement claims role {found:?}, expected {expected:?}")]
    WrongRole {
        /// The role the direction requires.
        expected: &'static str,
        /// The role the statement claims.
        found: String,
    },
    /// A statement names a principal other than the one expected.
    #[error("binding statement names principal {found}, expected {expected}")]
    PrincipalMismatch {
        /// The principal the pin (or the session) fixes.
        expected: String,
        /// The principal the statement names.
        found: String,
    },
    /// The signing key is not active in the held chain: never in it, or
    /// retired since.
    #[error("signing key {tmb} is not active in the peer chain")]
    KeyNotActive {
        /// The thumbprint the statement names.
        tmb: String,
    },
    /// The responder verified this side's statement and refused it.
    #[error("the responder refused this side: {reason}")]
    Refused {
        /// The reason the responder gave.
        reason: String,
    },
    /// The pinned chain could not judge the statement at all.
    #[error("pinned chain: {0}")]
    Peer(PeerFailure),
    /// The local signer failed to sign this side's statement.
    #[error("signer: {0}")]
    Signer(#[from] SignerError),
}

fn malformed(what: &'static str) -> TransportError {
    TransportError::Malformed { what }
}

// ---- the Noise channel --------------------------------------------------

/// A Noise transport session over `S`: framed encrypted messages, plus the
/// handshake hash the Cyphr statements bind to. Both ends use this one
/// type, so the wire format is defined once.
pub struct Channel<S> {
    stream: S,
    noise: snow::TransportState,
    handshake_hash: Vec<u8>,
}

fn params() -> Result<snow::params::NoiseParams, TransportError> {
    NOISE_PARAMS
        .parse()
        .map_err(|_| malformed("the Noise suite does not parse"))
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, TransportError> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &[u8],
) -> Result<(), TransportError> {
    let len = u16::try_from(msg.len()).map_err(|_| malformed("frame exceeds 65535 bytes"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(msg).await?;
    stream.flush().await?;
    Ok(())
}

impl<S: AsyncRead + AsyncWrite + Unpin> Channel<S> {
    /// Run the NN handshake as the initiator.
    ///
    /// # Errors
    ///
    /// [`TransportError::Timeout`], [`TransportError::Io`] or
    /// [`TransportError::Noise`] when the handshake cannot complete.
    pub async fn initiate(mut stream: S) -> Result<Self, TransportError> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut hs = snow::Builder::new(params()?).build_initiator()?;
            let mut buf = vec![0u8; 65535];
            let n = hs.write_message(&[], &mut buf)?;
            write_frame(&mut stream, &buf[..n]).await?;
            let reply = read_frame(&mut stream).await?;
            hs.read_message(&reply, &mut buf)?;
            Self::finish(stream, hs)
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    /// Run the NN handshake as the responder.
    ///
    /// # Errors
    ///
    /// As [`initiate`](Self::initiate).
    pub async fn respond(mut stream: S) -> Result<Self, TransportError> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut hs = snow::Builder::new(params()?).build_responder()?;
            let mut buf = vec![0u8; 65535];
            let first = read_frame(&mut stream).await?;
            hs.read_message(&first, &mut buf)?;
            let n = hs.write_message(&[], &mut buf)?;
            write_frame(&mut stream, &buf[..n]).await?;
            Self::finish(stream, hs)
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    fn finish(stream: S, hs: snow::HandshakeState) -> Result<Self, TransportError> {
        let handshake_hash = hs.get_handshake_hash().to_vec();
        Ok(Self {
            stream,
            noise: hs.into_transport_mode()?,
            handshake_hash,
        })
    }

    /// The Noise handshake hash `h`: the channel binding.
    #[must_use]
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// Send one Noise message (at most 65519 bytes of plaintext).
    ///
    /// # Errors
    ///
    /// [`TransportError::Malformed`] for an oversize plaintext; I/O and
    /// Noise errors otherwise.
    pub async fn send_one(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(malformed("message exceeds one Noise message"));
        }
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = self.noise.write_message(plaintext, &mut out)?;
        write_frame(&mut self.stream, &out[..n]).await
    }

    /// Receive and decrypt one Noise message.
    ///
    /// # Errors
    ///
    /// I/O and Noise errors; a frame that fails authentication is
    /// [`TransportError::Noise`].
    pub async fn recv_one(&mut self) -> Result<Vec<u8>, TransportError> {
        let frame = read_frame(&mut self.stream).await?;
        let mut out = vec![0u8; frame.len()];
        let n = self.noise.read_message(&frame, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Send a logical message of any size up to [`MAX_MESSAGE`], chunked
    /// over Noise messages.
    ///
    /// # Errors
    ///
    /// [`TransportError::Malformed`] above [`MAX_MESSAGE`]; I/O and Noise
    /// errors otherwise.
    pub async fn send_message(&mut self, body: &[u8]) -> Result<(), TransportError> {
        if body.len() > MAX_MESSAGE {
            return Err(malformed("message exceeds the size limit"));
        }
        let len = u32::try_from(body.len()).map_err(|_| malformed("message exceeds u32"))?;
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(body);
        for chunk in framed.chunks(MAX_PLAINTEXT) {
            self.send_one(chunk).await?;
        }
        Ok(())
    }

    /// Receive one logical message of at most `max` bytes. The declared
    /// length is checked against `max` as soon as the first chunk arrives,
    /// before the rest is read or buffered, so a peer cannot make this side
    /// hold what it will refuse.
    ///
    /// # Errors
    ///
    /// [`TransportError::Malformed`] for a length above `max` (or
    /// [`MAX_MESSAGE`]) or bytes beyond the declared length; I/O and Noise
    /// errors otherwise.
    pub async fn recv_message(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
        let mut buf = self.recv_one().await?;
        let head: [u8; 4] = buf
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| malformed("message shorter than its length prefix"))?;
        let len = usize::try_from(u32::from_be_bytes(head))
            .map_err(|_| malformed("message length does not fit"))?;
        if len > max.min(MAX_MESSAGE) {
            return Err(malformed("message exceeds the size limit"));
        }
        while buf.len() < 4 + len {
            buf.extend(self.recv_one().await?);
        }
        if buf.len() != 4 + len {
            return Err(malformed("bytes beyond the declared message length"));
        }
        buf.drain(..4);
        Ok(buf)
    }
}

// ---- requests and responses over a channel ------------------------------

/// Encode a request as a logical-message body.
///
/// # Errors
///
/// [`TransportError::Malformed`] when the target is longer than a `u16`.
pub fn encode_request(request: &ClientRequest) -> Result<Vec<u8>, TransportError> {
    let target = request.target.as_bytes();
    let target_len = u16::try_from(target.len()).map_err(|_| malformed("target too long"))?;
    let mut out = Vec::with_capacity(3 + target.len() + request.body.len());
    out.push(match request.method {
        Method::Get => 0,
        Method::Post => 1,
    });
    out.extend_from_slice(&target_len.to_be_bytes());
    out.extend_from_slice(target);
    out.extend_from_slice(&request.body);
    Ok(out)
}

/// Decode a request body written by [`encode_request`].
///
/// # Errors
///
/// [`TransportError::Malformed`] for an unknown method, a truncated body
/// or a target that is not UTF-8.
pub fn decode_request(bytes: &[u8]) -> Result<ClientRequest, TransportError> {
    let (&method, rest) = bytes
        .split_first()
        .ok_or_else(|| malformed("empty request"))?;
    let method = match method {
        0 => Method::Get,
        1 => Method::Post,
        _ => return Err(malformed("unknown request method")),
    };
    let (len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or_else(|| malformed("request lacks a target length"))?;
    let len = usize::from(u16::from_be_bytes(*len));
    let (target, body) = rest
        .split_at_checked(len)
        .ok_or_else(|| malformed("request target is truncated"))?;
    let target = std::str::from_utf8(target)
        .map_err(|_| malformed("request target is not UTF-8"))?
        .to_string();
    Ok(ClientRequest {
        method,
        target,
        body: body.to_vec(),
    })
}

/// Encode a response as a logical-message body.
#[must_use]
pub fn encode_response(status: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a response body written by [`encode_response`].
///
/// # Errors
///
/// [`TransportError::Malformed`] when the status is missing.
pub fn decode_response(bytes: &[u8]) -> Result<(u16, &[u8]), TransportError> {
    let (status, payload) = bytes
        .split_first_chunk::<2>()
        .ok_or_else(|| malformed("response lacks a status"))?;
    Ok((u16::from_be_bytes(*status), payload))
}

/// Encode the responder's verdict on the initiator statement: `Ok(())`
/// accepts, `Err(reason)` refuses with a reason the initiator can report.
#[must_use]
pub fn encode_ack(verdict: Result<(), &str>) -> Vec<u8> {
    match verdict {
        Ok(()) => vec![0],
        Err(reason) => [&[1u8][..], reason.as_bytes()].concat(),
    }
}

/// Decode an ack written by [`encode_ack`].
///
/// # Errors
///
/// [`TransportError::Refused`] for a refusal; [`TransportError::Malformed`]
/// for anything that is not an ack.
pub fn decode_ack(bytes: &[u8]) -> Result<(), TransportError> {
    match bytes.split_first() {
        Some((0, [])) => Ok(()),
        Some((1, reason)) => Err(TransportError::Refused {
            reason: String::from_utf8_lossy(reason).into_owned(),
        }),
        _ => Err(malformed("not an ack message")),
    }
}

// ---- the binding statement ----------------------------------------------

/// Which end of the handshake a statement speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The party that sent the first handshake message.
    Initiator,
    /// The party that answered it.
    Responder,
}

impl Role {
    /// The wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

/// A parsed binding statement, not yet judged. Judging is three separate
/// steps ([`expect`](Self::expect), then the caller's principal and key
/// lookup, then [`verify`](Self::verify)) because the two ends find the
/// key differently.
#[derive(Debug)]
pub struct BindStatement {
    coz: coz::CozJson,
    alg: String,
    h: Vec<u8>,
    pr: String,
    role: String,
    tmb: coz::Thumbprint,
    sidecar: Option<serde_json::Value>,
}

fn str_field<'a>(
    pay: &'a serde_json::Value,
    name: &'static str,
) -> Result<&'a str, TransportError> {
    pay[name].as_str().ok_or(TransportError::BadBinding {
        what: "a required field is missing",
    })
}

fn b64_field(pay: &serde_json::Value, name: &'static str) -> Result<Vec<u8>, TransportError> {
    Base64UrlUnpadded::decode_vec(str_field(pay, name)?).map_err(|_| TransportError::BadBinding {
        what: "a field is not base64url",
    })
}

impl BindStatement {
    /// Parse the plaintext of a statement message.
    ///
    /// # Errors
    ///
    /// [`TransportError::MissingStatement`] for empty plaintext;
    /// [`TransportError::BadBinding`] for anything that is not a Coz
    /// statement of [`BIND_TYP`] with every field present.
    pub fn parse(plaintext: &[u8]) -> Result<Self, TransportError> {
        if plaintext.is_empty() {
            return Err(TransportError::MissingStatement);
        }
        let coz: coz::CozJson =
            serde_json::from_slice(plaintext).map_err(|_| TransportError::BadBinding {
                what: "the statement is not Coz JSON",
            })?;
        if str_field(&coz.pay, "typ")? != BIND_TYP {
            return Err(TransportError::BadBinding {
                what: "the statement typ is not a transport binding",
            });
        }
        Ok(Self {
            alg: str_field(&coz.pay, "alg")?.to_string(),
            h: b64_field(&coz.pay, "h")?,
            pr: str_field(&coz.pay, "pr")?.to_string(),
            role: str_field(&coz.pay, "role")?.to_string(),
            tmb: coz::Thumbprint::from_bytes(b64_field(&coz.pay, "tmb")?),
            sidecar: serde_json::from_slice::<serde_json::Value>(plaintext)
                .ok()
                .and_then(|v| v.get("key").cloned()),
            coz,
        })
    }

    /// The principal the statement claims to speak for.
    #[must_use]
    pub fn pr(&self) -> &str {
        &self.pr
    }

    /// The thumbprint of the key the statement claims signed it.
    #[must_use]
    pub fn tmb(&self) -> &coz::Thumbprint {
        &self.tmb
    }

    /// The key the statement carries as its `key` sidecar, for a responder
    /// that has no stored chain for the principal. `Ok(None)` when there is
    /// none. Unsigned: the caller must still [`verify`](Self::verify) the
    /// statement under it and check it is the key the statement names.
    ///
    /// # Errors
    ///
    /// [`TransportError::BadBinding`] when the sidecar is malformed or its
    /// `tmb` is not the thumbprint of its `alg` and `pub`.
    pub fn sidecar_key(&self) -> Result<Option<Key>, TransportError> {
        let bad = |what| TransportError::BadBinding { what };
        let Some(side) = &self.sidecar else {
            return Ok(None);
        };
        let field = |name: &str| {
            side.get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or(bad("the key sidecar lacks a field"))
        };
        let decode = |name: &str| {
            Base64UrlUnpadded::decode_vec(field(name)?)
                .map_err(|_| bad("the key sidecar has a field that is not base64url"))
        };
        let key = Key::from_pub_key(field("alg")?, decode("pub")?)
            .map_err(|_| bad("the key sidecar names an unusable key"))?;
        if key.tmb().as_bytes() != decode("tmb")?.as_slice() {
            return Err(bad("the key sidecar thumbprint is not its key's"));
        }
        Ok(Some(key))
    }

    /// Check the statement is for the direction it arrived in and for this
    /// session: its `role` is `role`, and its `h` is `handshake_hash`.
    ///
    /// # Errors
    ///
    /// [`TransportError::WrongRole`], then [`TransportError::BadBinding`].
    pub fn expect(&self, role: Role, handshake_hash: &[u8]) -> Result<(), TransportError> {
        if self.role != role.as_str() {
            return Err(TransportError::WrongRole {
                expected: role.as_str(),
                found: self.role.clone(),
            });
        }
        if self.h != handshake_hash {
            return Err(TransportError::BadBinding {
                what: "the statement signs another handshake hash",
            });
        }
        Ok(())
    }

    /// Check the signature under `key`, which the caller found ACTIVE in
    /// the chain of the principal the statement names.
    ///
    /// # Errors
    ///
    /// [`TransportError::BadBinding`] when the key's algorithm is not the
    /// statement's or the signature does not verify.
    pub fn verify(&self, key: &Key) -> Result<(), TransportError> {
        if key.alg() != self.alg {
            return Err(TransportError::BadBinding {
                what: "the statement algorithm is not the key's",
            });
        }
        let pay = serde_json::to_vec(&self.coz.pay).map_err(|_| TransportError::BadBinding {
            what: "the statement pay does not serialize",
        })?;
        if coz::verify_json(&pay, &self.coz.sig, key.alg(), key.pub_key()) != Some(true) {
            return Err(TransportError::BadBinding {
                what: "the signature does not verify under the named key",
            });
        }
        Ok(())
    }
}

/// The signed bytes of a statement: the pay, fields in alphabetical order.
///
/// # Errors
///
/// [`TransportError::Malformed`] if the pay does not serialize.
pub fn statement_pay(
    alg: &str,
    tmb: &coz::Thumbprint,
    pr: &str,
    role: Role,
    handshake_hash: &[u8],
    now: i64,
) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(&serde_json::json!({
        "alg": alg,
        "h": Base64UrlUnpadded::encode_string(handshake_hash),
        "now": now,
        "pr": pr,
        "role": role.as_str(),
        "tmb": tmb.to_b64(),
        "typ": BIND_TYP,
    }))
    .map_err(|_| malformed("the statement pay does not serialize"))
}

/// The `cad` a signer signs for `pay`.
///
/// # Errors
///
/// [`TransportError::BadBinding`] if `alg` cannot hash a payload.
pub fn statement_cad(alg: &str, pay: &[u8]) -> Result<coz::Cad, TransportError> {
    coz::canonical_hash_for_alg(pay, alg, None).ok_or(TransportError::BadBinding {
        what: "the algorithm cannot hash a statement",
    })
}

/// Assemble the statement message from its signed `pay` and `sig`, with the
/// signer's public key as the `key` sidecar when `key` is given.
///
/// # Errors
///
/// [`TransportError::Malformed`] if `pay` is not JSON.
pub fn assemble_statement(
    pay: &[u8],
    sig: &[u8],
    key: Option<(&str, &[u8], &coz::Thumbprint)>,
) -> Result<Vec<u8>, TransportError> {
    let mut statement = serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(pay)
            .map_err(|_| malformed("the statement pay is not JSON"))?,
        "sig": Base64UrlUnpadded::encode_string(sig),
    });
    if let Some((alg, pub_key, tmb)) = key {
        statement["key"] = serde_json::json!({
            "alg": alg,
            "pub": Base64UrlUnpadded::encode_string(pub_key),
            "tmb": tmb.to_b64(),
        });
    }
    serde_json::to_vec(&statement).map_err(|_| malformed("the statement does not serialize"))
}

/// Whether two spellings name one principal: equal, or equal once any
/// algorithm tag (`ALG:digest`) is stripped.
#[must_use]
pub fn same_principal(a: &str, b: &str) -> bool {
    fn bare(s: &str) -> &str {
        s.split_once(':').map_or(s, |(_, digest)| digest)
    }
    a == b || bare(a) == bare(b)
}

// ---- the connector ------------------------------------------------------

/// How the client came to trust the responder's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAnchor {
    /// A bare pin: the genesis key the caller pinned, no chain followed.
    Pinned,
    /// A followed chain: the genesis replayed forward, so a rotation of the
    /// signing key since genesis is known.
    Followed,
}

/// What a completed handshake established about the responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// The responder's principal, as pinned.
    pub pg: String,
    /// The key that signed the responder's statement.
    pub tmb: coz::Thumbprint,
    /// The extent of the held chain the statement was judged against.
    pub verified_at: HeldTip,
    /// How the held chain was obtained.
    pub anchor: PeerAnchor,
}

/// A [`Connector`] over a Noise session whose peer was authenticated as a
/// Cyphr principal. Requests are serialized: one is in flight at a time.
pub struct NoiseConnector {
    channel: Mutex<Channel<TcpStream>>,
    binding: ChannelBinding,
    peer: AuthenticatedPeer,
}

impl NoiseConnector {
    /// Dial `addr`, run the handshake, verify the responder against the
    /// pinned `responder` chain, and only then send this side's statement,
    /// signed by `own` for `own_principal`.
    ///
    /// The responder is judged against the chain as held: a key it has
    /// retired since the last follow is still accepted, as everywhere in
    /// [`PeerChain`] (the caller owns the re-follow policy).
    ///
    /// # Errors
    ///
    /// A typed refusal for each binding fault ([`TransportError::BadBinding`],
    /// [`WrongRole`](TransportError::WrongRole),
    /// [`PrincipalMismatch`](TransportError::PrincipalMismatch),
    /// [`KeyNotActive`](TransportError::KeyNotActive),
    /// [`MissingStatement`](TransportError::MissingStatement)); I/O, Noise
    /// and timeout errors for a session that never got that far. The
    /// responder's verdict on this side's statement is awaited, so a server
    /// that refuses it fails here as [`TransportError::Refused`].
    pub async fn connect(
        addr: SocketAddr,
        responder: &mut PeerChain,
        own: &impl Signer,
        own_principal: &str,
    ) -> Result<Self, TransportError> {
        let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut channel = Channel::initiate(stream).await?;
        let h = channel.handshake_hash().to_vec();

        let incoming = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.recv_one())
            .await
            .map_err(|_| TransportError::Timeout)??;
        let peer = verify_responder(&incoming, &h, responder)?;

        // SIGMA-I: only now does this side reveal who it is.
        let pay = statement_pay(
            own.alg(),
            own.tmb(),
            own_principal,
            Role::Initiator,
            &h,
            unix_now(),
        )?;
        let sig = own.sign(&statement_cad(own.alg(), &pay)?).await?;
        let sidecar = Some((own.alg(), own.pub_key(), own.tmb()));
        channel
            .send_one(&assemble_statement(&pay, &sig, sidecar)?)
            .await?;
        let ack = tokio::time::timeout(HANDSHAKE_TIMEOUT, channel.recv_one())
            .await
            .map_err(|_| TransportError::Timeout)??;
        decode_ack(&ack)?;

        Ok(Self {
            binding: ChannelBinding::new(BindingKind::NoiseHandshakeHash, h),
            channel: Mutex::new(channel),
            peer,
        })
    }

    /// What the handshake established about the responder.
    #[must_use]
    pub fn peer(&self) -> &AuthenticatedPeer {
        &self.peer
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Judge the responder's statement message against the pinned chain.
fn verify_responder(
    incoming: &[u8],
    h: &[u8],
    chain: &PeerChain,
) -> Result<AuthenticatedPeer, TransportError> {
    let statement = BindStatement::parse(incoming)?;
    statement.expect(Role::Responder, h)?;
    if !same_principal(statement.pr(), chain.pg()) {
        return Err(TransportError::PrincipalMismatch {
            expected: chain.pg().to_string(),
            found: statement.pr().to_string(),
        });
    }
    let key = chain
        .active_key(statement.tmb())
        .map_err(|failure| match failure {
            PeerFailure::KeyNotActive { tmb } => TransportError::KeyNotActive { tmb },
            other => TransportError::Peer(other),
        })?;
    statement.verify(key)?;
    let verified_at = chain.held_tip().map_err(TransportError::Peer)?;
    let anchor = if verified_at.commits == 0 {
        PeerAnchor::Pinned
    } else {
        PeerAnchor::Followed
    };
    Ok(AuthenticatedPeer {
        pg: chain.pg().to_string(),
        tmb: key.tmb().clone(),
        verified_at,
        anchor,
    })
}

impl Connector for NoiseConnector {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        Some(&self.binding)
    }

    async fn exchange(&self, request: &ClientRequest) -> Result<Vec<u8>, ConnectError> {
        let unreachable = |e: TransportError| ConnectError::Unreachable(e.to_string());
        let body = encode_request(request).map_err(unreachable)?;
        let mut channel = self.channel.lock().await;
        // A request that times out leaves the stream mid-message, so the
        // session is unusable afterwards; callers reconnect.
        let reply = tokio::time::timeout(REQUEST_TIMEOUT, async {
            channel.send_message(&body).await?;
            channel.recv_message(MAX_MESSAGE).await
        })
        .await
        .map_err(|_| ConnectError::Unreachable("request timed out".into()))?
        .map_err(unreachable)?;
        let (status, payload) = decode_response(&reply).map_err(unreachable)?;
        if !(200..300).contains(&status) {
            return Err(ConnectError::NonSuccess(status));
        }
        Ok(payload.to_vec())
    }
}
