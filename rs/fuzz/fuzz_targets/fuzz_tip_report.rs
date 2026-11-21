#![no_main]

use cyphr_server::receipt::TipReport;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

fn b64(bytes: &[u8]) -> String {
    <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(bytes)
}

/// A tagged digest string. The label and length are usually well-formed and
/// sometimes fuzzer-chosen, so both the accept path and the length/label
/// rejections are exercised.
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

// A tip report is the peer-supplied signed payload a witness parses with
// `TipReport::parse` after its signature check (`sync.rs`, whose own
// envelope verifier is private to the server crate).
//
// Mode 0 feeds an arbitrary JSON `pay`; mode 1 builds a pay whose digests
// and genesis id are well-formed, since blind mutation of the b64/label
// grammar almost never gets past the first field.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let pay = if mode % 2 == 0 {
        match serde_json::from_slice::<Value>(rest) {
            Ok(v) => v,
            Err(_) => return,
        }
    } else {
        let mut u = Unstructured::new(rest);
        let mut pr = [0u8; 32];
        let _ = u.fill_buffer(&mut pr);
        let cr = if bool::arbitrary(&mut u).unwrap_or(false) {
            Value::Null
        } else {
            digest(&mut u)
        };
        json!({
            "pr": b64(&pr),
            "commit_id": digest(&mut u),
            "sequence": u64::arbitrary(&mut u).unwrap_or_default(),
            "roots": {
                "pr": digest(&mut u),
                "sr": digest(&mut u),
                "ar": digest(&mut u),
                "cr": cr,
            },
        })
    };
    let _ = TipReport::parse(&coz::CozJson {
        pay,
        sig: Vec::new(),
    });
});
