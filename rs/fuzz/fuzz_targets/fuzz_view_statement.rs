#![no_main]

// Claim: the view-statement parser never panics on a peer-supplied `pay`,
// whatever its shape. A panic is a remote crash of any client that reads a
// peer's view. Kind: fuzzing of an untrusted-input parser.

use cyphr_client::ViewStatement;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

fn b64(bytes: &[u8]) -> String {
    <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(bytes)
}

// A view statement is the peer-supplied signed payload a client parses
// after its signature check, mirroring `TipReport::parse`.
//
// Mode 0 feeds an arbitrary JSON `pay`. Mode 1 builds a pay with a
// well-formed `pr` and fuzzer-chosen integers for the tree size and index
// (the layout the parser reads is the implementer's; the two integers and
// the identifier are the fields every layout shares), since blind mutation
// of the b64 grammar almost never gets past the first field.
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
        json!({
            "pr": b64(&pr),
            "tree_size": u64::arbitrary(&mut u).unwrap_or_default(),
            "index": u64::arbitrary(&mut u).unwrap_or_default(),
            "now": i64::arbitrary(&mut u).unwrap_or_default(),
        })
    };
    let _ = ViewStatement::parse(&coz::CozJson {
        pay,
        sig: Vec::new(),
    });
});
