//! Principal-authenticated transport, client side (TR1 reds).
//!
//! The client under test is `NoiseConnector`. Against it stands a fake
//! responder that speaks real Noise NN and then misbehaves in one named
//! way, so each binding rule is exercised as a typed refusal over a real
//! socket.
//!
//! Run: `cd rs && cargo test -p cyphr-net --test transport`
//!
//! Assumptions the implement brief must honour or amend here (a Noise
//! suite and wire framing are free choices; the fake needs one):
//! - Noise params `Noise_NN_25519_ChaChaPoly_BLAKE2s`, via the `snow` crate (a dependency of this
//!   crate's `noise` feature).
//! - Every message, handshake and transport, is one frame: a big-endian `u16` length, then the
//!   Noise message.
//! - The responder's first transport message is its statement; the initiator replies with its own,
//!   only after the responder's verified.
//! - A statement's plaintext is the Coz JSON `{"pay": {...}, "sig": b64}` with pay `{alg, h, now,
//!   pr, role, tmb, typ}` (typ `cyphr.me/cyphr/transport/bind`, `h` the handshake hash, base64url,
//!   `pr` the PG, `role` `initiator` or `responder`). An empty plaintext is "no statement".
//! - The pinned responder is a bare pin on an implicit-genesis key; no follow is needed for the
//!   statement to be judged.

use std::time::Duration;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr_net::PeerChain;
use cyphr_net::transport::{NoiseConnector, TransportError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NOISE_PARAMS: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
const BIND_TYP: &str = "cyphr.me/cyphr/transport/bind";
const NOW: i64 = 1_700_000_000;
/// How long the fake waits for more bytes from a client that has given up.
const QUIET: Duration = Duration::from_millis(500);

// ---- keys --------------------------------------------------------------

struct Kp {
    kp: coz::KeyPair,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("ed25519 thumbprint");
    Kp { kp, tmb }
}

impl Kp {
    /// The implicit-genesis principal this key roots: its id is the tmb.
    fn pg(&self) -> cyphr::PrincipalGenesis {
        format!("SHA-512:{}", self.tmb.to_b64())
            .parse()
            .expect("labelled genesis id")
    }

    fn domain_key(&self) -> cyphr::Key {
        cyphr::Key::new(
            self.kp.alg.name().to_string(),
            self.tmb.clone(),
            self.kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(NOW)
    }

    fn signer(&self) -> SoftwareSigner {
        SoftwareSigner::new(
            self.kp.alg.name(),
            &self.kp.prv_bytes,
            &self.kp.pub_bytes,
            &self.tmb,
        )
    }

    /// A bare pin on this principal, as a client holds a peer it has not
    /// yet followed.
    async fn pinned(&self) -> PeerChain {
        PeerChain::pin(&self.pg(), self.domain_key()).await
    }
}

/// A binding statement: `signer` signs over a pay that claims `tmb`, `pr`,
/// `role` and handshake hash `h`.
fn statement(
    signer: &Kp,
    claimed_tmb: &coz::Thumbprint,
    pg: &cyphr::PrincipalGenesis,
    role: &str,
    h: &[u8],
) -> Vec<u8> {
    // Alphabetical field order: signed bytes are the canonical form.
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.kp.alg.name(),
        "h": Base64UrlUnpadded::encode_string(h),
        "now": NOW,
        "pg": pg.to_string(),
        "role": role,
        "tmb": claimed_tmb.to_b64(),
        "typ": BIND_TYP,
    }))
    .expect("pay json");
    let (sig, _) = coz::sign_json(
        &pay,
        signer.kp.alg.name(),
        &signer.kp.prv_bytes,
        &signer.kp.pub_bytes,
    )
    .expect("sign");
    serde_json::to_vec(&serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .expect("statement json")
}

// ---- the fake responder ------------------------------------------------

/// How the fake's statement misbehaves. `Honest` is the control.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Mode {
    /// A correct responder statement.
    Honest,
    /// Signed over a hash that is not this session's.
    WrongHash,
    /// Correct and signed, but claims the initiator role (a reflection).
    InitiatorRole,
    /// The statement the previous session's responder sent.
    Replay,
    /// A transport message that carries no statement.
    Missing,
    /// Claims the pinned key but the signature is by a key outside the chain.
    ForeignSignature,
    /// Signed by the pinned key, but names another principal as `pr`.
    OtherPrincipal(cyphr::PrincipalGenesis),
}

/// What the fake saw of one session.
struct Seen {
    /// The Noise handshake hash.
    h: Vec<u8>,
    /// The statement plaintext the fake sent.
    sent: Vec<u8>,
    /// Every frame the client sent after its handshake message, as plaintext
    /// where it decrypted under the session keys and `None` where not.
    after: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

async fn read_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn write_frame(s: &mut TcpStream, msg: &[u8]) {
    let len = u16::try_from(msg.len()).expect("frame fits u16");
    s.write_all(&len.to_be_bytes()).await.expect("write len");
    s.write_all(msg).await.expect("write frame");
}

/// Serve one session per entry of `modes`, in order, and report what each
/// saw. `pinned` is the responder key the client pins; `earlier` is the
/// statement a `Replay` session re-sends.
async fn fake_responder(listener: TcpListener, pinned: Kp, modes: Vec<Mode>) -> Vec<Seen> {
    let mut seen: Vec<Seen> = Vec::new();
    for mode in modes {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut hs = snow::Builder::new(NOISE_PARAMS.parse().expect("params"))
            .build_responder()
            .expect("responder");
        let mut buf = vec![0u8; 65535];
        let m1 = read_frame(&mut sock).await.expect("initiator ephemeral");
        hs.read_message(&m1, &mut buf).expect("read e");
        let n = hs.write_message(&[], &mut buf).expect("write e, ee");
        write_frame(&mut sock, &buf[..n]).await;
        let h = hs.get_handshake_hash().to_vec();
        let mut transport = hs.into_transport_mode().expect("transport");

        let pg = pinned.pg();
        let sent = match &mode {
            Mode::Honest => statement(&pinned, &pinned.tmb, &pg, "responder", &h),
            Mode::WrongHash => statement(&pinned, &pinned.tmb, &pg, "responder", &[7u8; 32]),
            Mode::InitiatorRole => statement(&pinned, &pinned.tmb, &pg, "initiator", &h),
            Mode::Replay => seen
                .last()
                .expect("a replay needs an earlier session")
                .sent
                .clone(),
            Mode::Missing => Vec::new(),
            Mode::ForeignSignature => statement(&kp(), &pinned.tmb, &pg, "responder", &h),
            Mode::OtherPrincipal(other) => statement(&pinned, &pinned.tmb, other, "responder", &h),
        };
        let n = transport.write_message(&sent, &mut buf).expect("encrypt");
        write_frame(&mut sock, &buf[..n]).await;

        let mut after = Vec::new();
        while let Ok(Some(frame)) = tokio::time::timeout(QUIET, read_frame(&mut sock)).await {
            let mut out = vec![0u8; 65535];
            let plain = transport
                .read_message(&frame, &mut out)
                .ok()
                .map(|n| out[..n].to_vec());
            after.push((frame, plain));
        }
        seen.push(Seen { h, sent, after });
    }
    seen
}

/// Run `modes` against a fresh client; return the connect outcome of the
/// LAST session and everything the fake saw.
async fn run(
    pinned: Kp,
    mut held: PeerChain,
    client: &Kp,
    modes: Vec<Mode>,
) -> (Result<NoiseConnector, TransportError>, Vec<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let sessions = modes.len();
    let fake = tokio::spawn(fake_responder(listener, pinned, modes));
    let mut last = None;
    for _ in 0..sessions {
        last = Some(NoiseConnector::connect(addr, &mut held, &client.signer(), &client.pg()).await);
    }
    // Bounded: a client that never connects must fail this test, not hang it.
    let seen = tokio::time::timeout(Duration::from_secs(10), fake)
        .await
        .expect("the client never completed a session with the fake")
        .expect("fake task");
    (last.expect("one session"), seen)
}

/// The typed refusal of the last session, or a failure if it was accepted.
fn refusal(outcome: Result<NoiseConnector, TransportError>, why: &str) -> TransportError {
    match outcome {
        Err(e) => e,
        Ok(_) => panic!("accepted: {why}"),
    }
}

// ---- binding: one session, one role -------------------------------------

/// Claim: a binding statement is good for one session only. A responder
/// statement signed over a hash other than this session's handshake hash is
/// refused `BadBinding`.
///
/// Turns red if: the signed `h` is not compared with the client's own
/// handshake hash. End-to-end scenario: yes (real socket, real Noise).
#[tokio::test]
async fn statement_over_another_handshake_hash_is_bad_binding() {
    let (srv, client) = (kp(), kp());
    let held = srv.pinned().await;
    let (outcome, _) = run(srv, held, &client, vec![Mode::WrongHash]).await;
    let err = refusal(outcome, "a statement over another handshake hash");
    assert!(matches!(err, TransportError::BadBinding { .. }), "{err:?}");
}

/// Claim: a binding statement is good for one role only. A correctly
/// signed statement over the right hash that claims the initiator role (a
/// statement reflected back at its role's owner) is refused.
///
/// Turns red if: the role field is not checked against the direction the
/// statement arrived in. End-to-end scenario: yes.
#[tokio::test]
async fn statement_claiming_the_initiator_role_is_refused() {
    let (srv, client) = (kp(), kp());
    let held = srv.pinned().await;
    let (outcome, _) = run(srv, held, &client, vec![Mode::InitiatorRole]).await;
    let err = refusal(outcome, "a responder statement in the initiator role");
    assert!(
        matches!(
            err,
            TransportError::WrongRole { .. } | TransportError::BadBinding { .. }
        ),
        "{err:?}"
    );
}

/// Claim: a statement is good for one session. The statement an honest
/// responder sent in an earlier session, replayed verbatim in the next, is
/// refused `BadBinding` (right role, right key, wrong hash).
///
/// Turns red if: a statement not bound to the current handshake hash is
/// accepted. End-to-end scenario: yes (two real sessions).
#[tokio::test]
async fn statement_replayed_from_an_earlier_session_is_bad_binding() {
    let (srv, client) = (kp(), kp());
    let held = srv.pinned().await;
    let (outcome, seen) = run(srv, held, &client, vec![Mode::Honest, Mode::Replay]).await;
    assert_eq!(seen.len(), 2, "both sessions ran");
    assert_ne!(seen[0].h, seen[1].h, "the sessions are distinct");
    let err = refusal(outcome, "a replayed statement");
    assert!(matches!(err, TransportError::BadBinding { .. }), "{err:?}");
}

/// Claim: the statement binds a principal, not just a key. The pinned key
/// signs a statement that names a different principal as `pr`; it is
/// refused `PrincipalMismatch`.
///
/// Turns red if: `pr` is not compared with the pinned PG. End-to-end
/// scenario: yes.
#[tokio::test]
async fn statement_naming_another_principal_is_a_mismatch() {
    let (srv, client, other) = (kp(), kp(), kp());
    let held = srv.pinned().await;
    let modes = vec![Mode::OtherPrincipal(other.pg())];
    let (outcome, _) = run(srv, held, &client, modes).await;
    let err = refusal(outcome, "a statement naming another principal");
    assert!(
        matches!(err, TransportError::PrincipalMismatch { .. }),
        "{err:?}"
    );
}

/// Claim: only a Cyphr signature by a key the pinned chain holds counts. A
/// statement that claims the pinned key but is signed by another key, and a
/// transport message carrying no statement at all, are both refused.
///
/// Turns red if: either is accepted, or the refusal is not typed.
/// End-to-end scenario: yes.
#[tokio::test]
async fn foreign_signature_and_missing_statement_are_refused() {
    for (mode, what) in [
        (Mode::ForeignSignature, "a signature by a foreign key"),
        (Mode::Missing, "no statement"),
    ] {
        let (srv, client) = (kp(), kp());
        let held = srv.pinned().await;
        let (outcome, _) = run(srv, held, &client, vec![mode.clone()]).await;
        let err = refusal(outcome, what);
        let ok = match mode {
            Mode::Missing => matches!(
                err,
                TransportError::MissingStatement | TransportError::BadBinding { .. }
            ),
            _ => matches!(err, TransportError::BadBinding { .. }),
        };
        assert!(ok, "{what}: {err:?}");
    }
}

// ---- SIGMA-I order: the initiator stays hidden --------------------------

/// Claim: the initiator stays hidden from an unverified responder. Against
/// a fake whose statement fails verification (missing, over the wrong
/// hash, or signed by a foreign key), the client sends no initiator
/// statement: nothing the fake receives after the handshake decrypts to a
/// statement, and nothing contains the client's principal or thumbprint in
/// the clear.
///
/// Turns red if: any initiator identity or signature is sent before the
/// responder's statement verifies. End-to-end scenario: yes. The
/// refusal is also asserted, so a client that never sends because it never
/// connected does not pass vacuously; the control below shows the harness
/// does see an initiator statement when the responder is honest.
#[tokio::test]
async fn sigma_initiator_is_hidden_from_an_unverified_responder() {
    for mode in [Mode::Missing, Mode::WrongHash, Mode::ForeignSignature] {
        let (srv, client) = (kp(), kp());
        let held = srv.pinned().await;
        let (own_pg, own_tmb) = (client.pg().to_string(), client.tmb.to_b64());
        let (outcome, seen) = run(srv, held, &client, vec![mode.clone()]).await;
        assert!(outcome.is_err(), "{mode:?} must be refused");
        for (frame, plain) in &seen[0].after {
            let hay = |needle: &str, bytes: &[u8]| {
                bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
            };
            assert!(
                !hay(&own_pg, frame) && !hay(&own_tmb, frame),
                "{mode:?}: the client identity crossed in the clear"
            );
            assert!(
                plain.is_none(),
                "{mode:?}: the client sent a decryptable message to an unverified responder"
            );
        }
    }
}

/// Claim: the harness above can see an initiator statement, and the one an
/// honest responder gets is the initiator-role, handshake-bound, correctly
/// signed statement of the client's own principal and key. Control for the
/// hidden-initiator test, and the positive half of the SIGMA-I order.
///
/// Turns red if: the initiator statement is absent, in the wrong role,
/// bound to another hash, names another principal or key, or does not
/// verify under the client's key. End-to-end scenario: yes.
#[tokio::test]
async fn sigma_control_honest_responder_receives_the_initiator_statement() {
    let (srv, client) = (kp(), kp());
    let held = srv.pinned().await;
    let (_, seen) = run(srv, held, &client, vec![Mode::Honest]).await;
    let seen = &seen[0];
    let plain = seen
        .after
        .iter()
        .find_map(|(_, p)| p.as_ref())
        .expect("an honest responder receives the initiator statement");
    let coz: coz::CozJson = serde_json::from_slice(plain).expect("a Coz statement");
    assert_eq!(coz.pay["typ"], BIND_TYP);
    assert_eq!(coz.pay["role"], "initiator");
    assert_eq!(coz.pay["h"], Base64UrlUnpadded::encode_string(&seen.h));
    assert_eq!(coz.pay["pg"], client.pg().to_string());
    assert_eq!(coz.pay["tmb"], client.tmb.to_b64());
    let pay = serde_json::to_vec(&coz.pay).expect("pay");
    assert_eq!(
        coz::verify_json(&pay, &coz.sig, client.kp.alg.name(), &client.kp.pub_bytes),
        Some(true),
        "the client's own key signed it"
    );
}
