#![no_main]

use std::sync::OnceLock;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_net::{PeerKey, verify_patch_body};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

// The witness's whole inbound surface: a peer-supplied `/patch` body,
// verified by `cyphr_net::verify_patch_body` (envelope signature,
// canonical report parse, principal match, entry blob decoding). The claim
// is that no body, however hostile, panics the verifier, and that a body
// accepted with an authority key attests exactly the principal asked for.
//
// This target is EDGE-SEEDED, not a discoverer of arbitrary values. The
// integer fields (`sequence`, entry sequences) are drawn from the
// validator's bounds (0, 1, `u64::MAX` and its neighbours), a small-int
// domain, and the full `u64` range, chosen by a selector byte. The digest
// and genesis-id grammar is likewise built well-formed in mode 1. Blind
// mutation of a full-range integer almost never lands on an exact bound,
// so what this run covers is those seeded edges and their mutations, not
// the whole value space.
//
// Mode 0 feeds raw bytes, so the JSON/shape rejections are exercised.
// Mode 1 builds a body whose report is genuinely signed by the expected
// authority, so execution reaches the report parse, the principal
// comparison and the entry decoding rather than stopping at the signature.

/// One authority keypair, generated once per fuzzer process.
fn authority() -> &'static (PeerKey, Vec<u8>) {
    static KEY: OnceLock<(PeerKey, Vec<u8>)> = OnceLock::new();
    KEY.get_or_init(|| {
        let kp = coz::Alg::Ed25519.generate_keypair();
        (
            PeerKey {
                alg: kp.alg.name().to_string(),
                pub_key: kp.pub_bytes.clone(),
            },
            kp.prv_bytes.clone(),
        )
    })
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// A `u64` field chosen by a selector byte: (a) the bounds of a canonical
/// sequence and their neighbours, (b) a small-int domain, (c) any `u64`.
fn int_field(u: &mut Unstructured<'_>) -> u64 {
    const EDGES: [u64; 7] = [0, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX, 1 << 53];
    match u8::arbitrary(u).unwrap_or(0) % 3 {
        0 => EDGES[usize::from(u8::arbitrary(u).unwrap_or(0)) % EDGES.len()],
        1 => u64::from(u16::arbitrary(u).unwrap_or(0) % 1024),
        _ => u64::arbitrary(u).unwrap_or_default(),
    }
}

/// A sequence on the wire: a JSON number or the string of its digits, the
/// two spellings the canonical parse accepts, or occasionally garbage.
fn sequence(u: &mut Unstructured<'_>) -> Value {
    let n = int_field(u);
    match u8::arbitrary(u).unwrap_or(0) % 4 {
        0 => json!(n.to_string()),
        1 => json!(format!("{n}x")),
        _ => json!(n),
    }
}

/// A tagged digest, usually well-formed and sometimes fuzzer-chosen.
fn digest(u: &mut Unstructured<'_>) -> Value {
    let (label, len) = match u8::arbitrary(u).unwrap_or(0) % 4 {
        0 => ("SHA-256", 32),
        1 => ("SHA-384", 48),
        2 => ("SHA-512", 64),
        _ => return json!(String::arbitrary(u).unwrap_or_default()),
    };
    let mut bytes = vec![0u8; len];
    let _ = u.fill_buffer(&mut bytes);
    json!(format!("{label}:{}", b64(&bytes)))
}

/// One patch entry: a bundle of up to three transactions of up to three
/// cozies each (SPEC 4.6.2), each coz usually base64url and sometimes not.
fn entry(u: &mut Unstructured<'_>) -> Value {
    let coz = |u: &mut Unstructured<'_>| {
        if bool::arbitrary(u).unwrap_or(true) {
            json!(b64(&Vec::<u8>::arbitrary(u).unwrap_or_default()))
        } else {
            json!(String::arbitrary(u).unwrap_or_default())
        }
    };
    let txs: Vec<Value> = (0..u8::arbitrary(u).unwrap_or(0) % 4)
        .map(|_| {
            let n = u8::arbitrary(u).unwrap_or(1) % 4;
            Value::Array((0..n).map(|_| coz(u)).collect())
        })
        .collect();
    json!({ "sequence": int_field(u), "txs": txs })
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let (key, prv) = authority();

    if mode % 2 == 0 {
        let _ = verify_patch_body(rest, "SHA-256:principal", Some(key));
        let _ = verify_patch_body(rest, "SHA-256:principal", None);
        return;
    }

    let mut u = Unstructured::new(rest);
    let mut pr = [0u8; 32];
    let _ = u.fill_buffer(&mut pr);
    let pr = b64(&pr);
    let cr = if bool::arbitrary(&mut u).unwrap_or(false) {
        Value::Null
    } else {
        digest(&mut u)
    };
    let pay = json!({
        "alg": key.alg,
        "typ": "cyphr-server/receipt/tip",
        "pr": pr,
        "sequence": sequence(&mut u),
        "commit_id": digest(&mut u),
        "roots": { "pr": digest(&mut u), "sr": digest(&mut u), "ar": digest(&mut u), "cr": cr },
    });
    let Ok(pay_bytes) = serde_json::to_vec(&pay) else {
        return;
    };
    let Some((sig, _)) = coz::sign_json(&pay_bytes, &key.alg, prv, &key.pub_key) else {
        return;
    };
    let entries: Vec<Value> = (0..u8::arbitrary(&mut u).unwrap_or(0) % 4)
        .map(|_| entry(&mut u))
        .collect();
    let body = json!({
        "v": 1,
        "payload": { "entries": entries },
        "statement": { "kind": "signed", "coz": { "pay": pay, "sig": b64(&sig) } },
    });
    let Ok(body) = serde_json::to_vec(&body) else {
        return;
    };

    // Ask for the attested principal or, half the time, a different one.
    let asked = if bool::arbitrary(&mut u).unwrap_or(true) {
        format!("SHA-256:{pr}")
    } else {
        String::arbitrary(&mut u).unwrap_or_default()
    };
    if let Ok(verified) = verify_patch_body(&body, &asked, Some(key)) {
        let report = verified
            .report
            .expect("an authenticated patch carries its report");
        let bare = asked.split_once(':').map_or(asked.as_str(), |(_, d)| d);
        assert_eq!(
            report.pg.to_string(),
            bare,
            "accepted a report for a principal that was not asked for"
        );
    }
});
