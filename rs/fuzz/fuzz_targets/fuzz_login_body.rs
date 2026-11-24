#![no_main]

use cyphr_client::login::{LoginRequest, REQUEST_TYP_SUFFIX};
use cyphr_server::auth::login::parse_login;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

const AUDIENCE: &str = "fuzz.example";

// Mode 0 fuzzes the login-body parse the `login` handler runs on an
// unauthenticated request: `LoginRequest` deserialization followed by
// `parse_login` (schema and audience binding). The handler itself needs a
// full `AppState`; everything before its principal load is exactly these two
// calls.
//
// Mode 1 builds a payload that is well-formed up to the point of fuzzer-chosen
// variation (each field present or absent, any value, challenge optional).
// Blind byte mutation of mode 0 rarely lands a typ ending in the login suffix
// with the right audience, so without this the field-extraction code behind
// the audience gate is never reached.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    if mode % 2 == 0 {
        if let Ok(body) = std::str::from_utf8(rest)
            && let Ok(coz_json) = serde_json::from_str::<LoginRequest>(body)
        {
            let _ = parse_login(&coz_json, AUDIENCE);
        }
        return;
    }

    let mut u = Unstructured::new(rest);
    let mut pay = Map::new();
    if bool::arbitrary(&mut u).unwrap_or(false) {
        pay.insert(
            "typ".into(),
            json!(format!("{AUDIENCE}{REQUEST_TYP_SUFFIX}")),
        );
    }
    if bool::arbitrary(&mut u).unwrap_or(false) {
        pay.insert(
            "alg".into(),
            json!(String::arbitrary(&mut u).unwrap_or_default()),
        );
    }
    if bool::arbitrary(&mut u).unwrap_or(false) {
        pay.insert(
            "now".into(),
            json!(i64::arbitrary(&mut u).unwrap_or_default()),
        );
    }
    if bool::arbitrary(&mut u).unwrap_or(false) {
        let tmb = <[u8; 32]>::arbitrary(&mut u).unwrap_or_default();
        pay.insert(
            "tmb".into(),
            json!(
                <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(&tmb)
            ),
        );
    }
    if bool::arbitrary(&mut u).unwrap_or(false) {
        pay.insert(
            "pg".into(),
            json!(String::arbitrary(&mut u).unwrap_or_default()),
        );
    }
    if bool::arbitrary(&mut u).unwrap_or(false) {
        pay.insert(
            "challenge".into(),
            json!(String::arbitrary(&mut u).unwrap_or_default()),
        );
    }
    let sig = Vec::<u8>::arbitrary(&mut u).unwrap_or_default();
    let _ = parse_login(
        &LoginRequest {
            coz: coz::CozJson {
                pay: Value::Object(pay),
                sig,
            },
            challenge: None,
        },
        AUDIENCE,
    );
});
