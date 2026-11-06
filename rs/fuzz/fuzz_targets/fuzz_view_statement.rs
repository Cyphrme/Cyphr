#![no_main]

// RED(N15b): `cyphr_client::ViewStatement` does not exist yet. Until it
// does, every line below marked RED(N15b) swaps the real target for an
// empty one so the workspace builds; the implementation removes those
// lines and nothing else. Check the real target with
// `RUSTFLAGS='--cfg red_n15b' cargo check -p cyphr-fuzz --bin fuzz_view_statement`.
//
// Claim: the view-statement parser never panics on a peer-supplied `pay`,
// whatever its shape. A panic is a remote crash of any client that reads a
// peer's view. Kind: fuzzing of an untrusted-input parser.

use libfuzzer_sys::fuzz_target;
#[cfg(red_n15b)] // RED(N15b)
use {
    cyphr_client::ViewStatement,
    libfuzzer_sys::arbitrary::{Arbitrary, Unstructured},
    serde_json::{Value, json},
};

#[cfg(red_n15b)] // RED(N15b)
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
#[cfg(red_n15b)] // RED(N15b)
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

#[cfg(not(red_n15b))] // RED(N15b)
fuzz_target!(|_data: &[u8]| {}); // RED(N15b)
