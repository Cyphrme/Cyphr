#![no_main]

use std::sync::OnceLock;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::{ES256, SigningKey};
use cyphr_server::revoke::interpret;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build runtime")
    })
}

/// One real ES256 keypair per fuzzer process: mode 1 signs genuine revokes
/// with it so inputs reach the signature-verified path.
fn keypair() -> &'static (Vec<u8>, Vec<u8>) {
    static KEY: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| {
        let sk = SigningKey::<ES256>::generate();
        (
            sk.private_key_bytes(),
            sk.verifying_key().public_key_bytes().to_vec(),
        )
    })
}

/// The upper bound of a valid `rvk`: 2^53 - 1, the largest integer JSON
/// carries exactly. `coz::is_valid_rvk` accepts `1..=RVK_UPPER`; its own
/// constant is private, so the bound is restated here and pinned against
/// `is_valid_rvk` on first use.
const RVK_UPPER: i64 = (1 << 53) - 1;

/// An integer field chosen by a selector byte, so the fuzzer can steer to
/// the validator's edges without losing the full range:
/// (a) the boundary values behind the gate (each bound, bound +/- 1, 0, -1,
///     `i64::MIN`/`MAX`), (b) a small-int domain, (c) any `i64`.
/// Mutating a full-range `i64` alone almost never lands on an exact edge.
fn int_field(u: &mut Unstructured<'_>) -> i64 {
    debug_assert!(coz::is_valid_rvk(RVK_UPPER) && !coz::is_valid_rvk(RVK_UPPER + 1));
    const EDGES: [i64; 11] = [
        0,
        -1,
        1,
        2,
        RVK_UPPER - 1,
        RVK_UPPER,
        RVK_UPPER + 1,
        i64::MIN,
        i64::MIN + 1,
        i64::MAX - 1,
        i64::MAX,
    ];
    match u8::arbitrary(u).unwrap_or(0) % 3 {
        0 => EDGES[usize::from(u8::arbitrary(u).unwrap_or(0)) % EDGES.len()],
        1 => i64::from(u16::arbitrary(u).unwrap_or(0) % 1024) - 8,
        _ => i64::arbitrary(u).unwrap_or_default(),
    }
}

// Mode 0 fuzzes the request body as sent: deserialized to
// JSON and handed to `interpret`.
//
// Mode 1 signs a revoke naming the process key, with the fuzzer choosing
// `rvk`, `now` and padding. Blind mutation cannot forge a key-bound
// thumbprint and signature, so without it `interpret` is never exercised
// past its `tmb` bind; padding drives the `RVK_MAX_SIZE` bound.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let envelope = if mode % 2 == 0 {
        match serde_json::from_slice::<serde_json::Value>(rest) {
            Ok(e) => e,
            Err(_) => return,
        }
    } else {
        let (prv, pubk) = keypair();
        let Some(tmb) = coz::compute_thumbprint_for_alg("ES256", pubk) else {
            return;
        };
        let mut u = Unstructured::new(rest);
        let pay = json!({
            "typ": "cyphr.me/cyphr/key/revoke",
            "alg": "ES256",
            "tmb": tmb,
            "now": int_field(&mut u),
            "rvk": int_field(&mut u),
            "pad": String::arbitrary(&mut u).unwrap_or_default(),
        });
        let Ok(pay_bytes) = serde_json::to_vec(&pay) else {
            return;
        };
        let Some((sig, _cad)) = coz::sign_json(&pay_bytes, "ES256", prv, pubk) else {
            return;
        };
        json!({
            "pay": pay,
            "sig": Base64UrlUnpadded::encode_string(&sig),
            "keys": [{"alg": "ES256", "pub": Base64UrlUnpadded::encode_string(pubk)}],
        })
    };

    let _ = runtime().block_on(interpret(&envelope));
});
