#![no_main]

use std::sync::OnceLock;

use coz::{CozJson, ES256, SigningKey};
use cyphr_server::auth::ServerIdentity;
use libfuzzer_sys::fuzz_target;

/// One real server identity per fuzzer process.
///
/// `ServerIdentity` is only constructible from a key file, so the file is
/// written once to the process temp dir. A real key lets mode-1 inputs carry
/// a genuine signature, which drives `verify_token` past the signature gate
/// into `typ` binding, claim extraction and the expiry check; against an
/// arbitrary key every input would die at the first signature check.
fn identity() -> &'static ServerIdentity {
    static ID: OnceLock<ServerIdentity> = OnceLock::new();
    ID.get_or_init(|| {
        let sk = SigningKey::<ES256>::generate();
        let vk = sk.verifying_key();
        let b64 = |bytes: &[u8]| {
            <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(bytes)
        };
        let file = serde_json::json!({
            "alg": "ES256",
            "pub_key": b64(vk.public_key_bytes()),
            "v": 1,
            "prv_key": b64(&sk.private_key_bytes()),
        });
        let path = std::env::temp_dir().join(format!("fuzz-bearer-{}.key", std::process::id()));
        std::fs::write(
            &path,
            serde_json::to_vec(&file).expect("key file serializes"),
        )
        .expect("temp dir writable");
        let id = ServerIdentity::load_from_path(&path).expect("generated key file loads");
        let _ = std::fs::remove_file(&path);
        id
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let id = identity();

    if mode % 2 == 0 {
        // Arbitrary bytes presented as a bearer token string (the wire form
        // `verify_token` takes from an `Authorization` header).
        if let Ok(token) = std::str::from_utf8(rest) {
            let _ = id.verify_token(token, 0);
        }
    } else if let Ok(pay) = serde_json::from_slice::<serde_json::Value>(rest)
        && let Ok(pay_json) = serde_json::to_vec(&pay)
        && let Some((sig, _cad)) = id.sign(&pay_json)
        && let Ok(token) = serde_json::to_string(&CozJson { pay, sig })
    {
        // Genuine signature over a fuzzer-chosen payload: exercises the
        // post-signature path (`typ` binding, claim extraction, expiry).
        let _ = id.verify_token(&token, 0);
    }
});
