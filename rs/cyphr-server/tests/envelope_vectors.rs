//! Golden wire vectors for the response envelope
//! (`docs/specs/http-envelope.md`).
//!
//! Byte-exact vectors pin both envelope forms. The unsigned vector is
//! fully deterministic. The signed vector signs a fixed `pay` with a fixed
//! Ed25519 key (seed `[0x11; 32]`) and a fixed timestamp, following the
//! bearer-token golden-vector precedent (`src/auth/token.rs`). A silent
//! change to field order, encoding, or the embedded coz slot breaks these
//! tests loudly instead of drifting unnoticed.
//!
//! The signed `pay` here is illustrative: this node pins that the
//! statement slot carries a coz, not what a server statement claims (that
//! is a later, receipt-design concern). See the design doc.

use std::path::PathBuf;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::envelope::{Envelope, Statement};

/// A fixed principal genesis id, reused from the token vector for a stable,
/// recognizable payload.
const PR: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

/// Read a committed golden vector, trimming a trailing newline so the file
/// can end in one.
fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .trim_end()
        .to_string()
}

/// A fixed, recognizable tip-shaped payload. The envelope is generic over
/// its payload; a `Value` keeps the vector readable and the module
/// decoupled from any route's response struct.
fn demo_payload() -> serde_json::Value {
    serde_json::json!({ "principal_id": PR, "commit_count": 3 })
}

/// Load a deterministic Ed25519 identity from a fixed seed, mirroring the
/// token golden-vector fixture.
fn fixed_identity() -> (tempfile::TempDir, ServerIdentity) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("signing-key.json");

    let prv_key = [0x11u8; 32];
    let pub_key = coz::Alg::Ed25519
        .derive_public_key(&prv_key)
        .expect("derive public key from fixed seed");

    let file = serde_json::json!({
        "alg": coz::Alg::Ed25519.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&pub_key),
        "prv_key": Base64UrlUnpadded::encode_string(&prv_key),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
    (dir, identity)
}

/// Build a fixed server-signed coz for the signed vector.
fn signed_coz(identity: &ServerIdentity) -> coz::CozJson {
    let tmb = identity
        .alg()
        .compute_thumbprint(identity.pub_key())
        .expect("thumbprint");

    let mut pay = coz::Pay::new();
    pay.alg = Some(identity.alg().name().to_string());
    pay.now = Some(1_700_000_000);
    pay.tmb = Some(tmb);
    pay.typ = Some("cyphr-server/statement".to_string());

    let pay_json = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, _cad) = identity.sign(&pay_json).expect("sign");
    let pay_value = serde_json::to_value(&pay).expect("pay to value");
    coz::CozJson {
        pay: pay_value,
        sig,
    }
}

#[test]
fn envelope_vectors_unsigned_is_byte_exact() {
    let env = Envelope::unsigned(demo_payload());
    let wire = serde_json::to_string(&env).unwrap();
    assert_eq!(wire, golden("envelope_unsigned.json"));
}

#[test]
fn envelope_vectors_signed_is_byte_exact() {
    let (_dir, identity) = fixed_identity();
    let env = Envelope::signed(demo_payload(), signed_coz(&identity));

    let wire = serde_json::to_string(&env).unwrap();
    assert_eq!(wire, golden("envelope_signed.json"));

    // The golden coz must itself verify against the fixed key, so a future
    // accidental signature-only drift in the constant is also caught.
    let Statement::Signed(coz) = &env.statement else {
        panic!("signed envelope must carry a signed statement");
    };
    let pay_json = serde_json::to_vec(&coz.pay).unwrap();
    assert_eq!(
        identity.verify(&pay_json, &coz.sig),
        Some(true),
        "the golden signed coz must verify against its fixed key"
    );
}
