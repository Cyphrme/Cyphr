#![no_main]

use std::sync::OnceLock;

use coz::{CozJson, Czd, ES256, Pay, SigningKey};
use cyphr::Key;
use cyphr::parsed_coz::verify_coz;
use libfuzzer_sys::fuzz_target;

/// A single real ES256 keypair, generated once per fuzzer process and reused
/// across every input.
///
/// Verifying against an all-zero dummy key (this target's previous shape)
/// makes every input fail at the earliest signature check, so `verify_coz`'s
/// czd matching, payload re-parsing, and `VerifiedCoz` construction are never
/// reached -- exactly the "mostly hollow" gap this hardens. A real key lets
/// mode-1 inputs (below) produce genuinely valid signatures whenever the
/// fuzzer-chosen payload happens to canonicalize (any valid JSON object),
/// driving the verification path all the way through.
fn signing_key() -> &'static (Vec<u8>, Key) {
    static KEY: OnceLock<(Vec<u8>, Key)> = OnceLock::new();
    KEY.get_or_init(|| {
        let sk = SigningKey::<ES256>::generate();
        let vk = sk.verifying_key();
        let key = Key {
            alg: "ES256".to_string(),
            tmb: vk.thumbprint().clone(),
            pub_key: vk.public_key_bytes().to_vec(),
            first_seen: 0,
            last_used: None,
            revocation: None,
            tag: None,
        };
        (sk.private_key_bytes(), key)
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (mode, rest) = data.split_at(1);
    let (prv, key) = signing_key();

    if mode[0] % 2 == 0 {
        // Fuzz raw parsing of an arbitrary, unauthenticated CozJson envelope
        // -- most inputs are malformed and must be rejected cleanly.
        if let Ok(coz_json) = serde_json::from_slice::<CozJson>(rest) {
            let pay_json = serde_json::to_vec(&coz_json.pay).unwrap_or_default();
            if serde_json::from_slice::<Pay>(&pay_json).is_ok() {
                let czd = Czd::from_bytes(vec![0; 32]);
                let _ = verify_coz(&pay_json, &coz_json.sig, key, czd, None);
            }
        }
    } else if let Some((sig, cad)) = coz::sign_json(rest, "ES256", prv, &key.pub_key) {
        // Real signature over fuzzer-controlled payload bytes: exercises
        // verify_coz's genuine signature-valid path (czd derivation, payload
        // re-parse, VerifiedCoz construction), not just its earliest
        // signature-mismatch rejection.
        if let Some(czd) = coz::czd_for_alg(&cad, &sig, "ES256") {
            let _ = verify_coz(rest, &sig, key, czd, None);
        }
    }
});
