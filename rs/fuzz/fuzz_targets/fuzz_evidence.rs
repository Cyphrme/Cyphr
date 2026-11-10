#![no_main]

// Claim: parsing and verifying a peer-served evidence item never panics,
// whatever its shape. A served item is untrusted input to every client that
// reads `GET /evidence`; a panic is a remote crash. Kind: fuzzing of an
// untrusted-input parser.

use cyphr::eml::MemoryStorage;
use cyphr_client::evidence::{
    EvidenceItem, KeyHistory, verify_peer_equivocation, verify_principal_fork,
};
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

/// One runtime for every input: the core's replay is async.
static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime")
    })
}

fn b64(bytes: &[u8]) -> String {
    <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(bytes)
}

async fn genesis() -> Option<cyphr::Principal<MemoryStorage>> {
    let key = cyphr::Key::from_pub_key("Ed25519", vec![7; 32]).ok()?;
    cyphr::Principal::implicit(key).await.ok()
}

// Mode 0 feeds an arbitrary JSON item to the parser and both verifiers.
// Modes 1 and 2 build an item of each kind around fuzzer-chosen bytes and
// integers, since blind mutation of the b64 and JSON grammar almost never
// gets past the first field.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };
    let mut u = Unstructured::new(rest);
    let item = match mode % 3 {
        0 => match serde_json::from_slice::<Value>(rest) {
            Ok(v) => v,
            Err(_) => return,
        },
        1 => {
            let blob = |u: &mut Unstructured| {
                let n = usize::from(u8::arbitrary(u).unwrap_or(0) % 64);
                b64(u.bytes(n).unwrap_or(&[]))
            };
            json!({
                "kind": "principal-fork",
                "pg": b64(&[7; 32]),
                "height": u64::arbitrary(&mut u).unwrap_or_default() % 4,
                "pre": if bool::arbitrary(&mut u).unwrap_or(false) { Value::Null } else { json!(blob(&mut u)) },
                "a": {"txs": [[blob(&mut u)]]},
                "b": {"txs": [[blob(&mut u)], [blob(&mut u)]]},
            })
        },
        _ => {
            let stmt = |u: &mut Unstructured| {
                json!({
                    "pay": {
                        "typ": "cyphr-server/view",
                        "pr": b64(&[7; 32]),
                        "tree_size": u64::arbitrary(u).unwrap_or_default(),
                        "index": u64::arbitrary(u).unwrap_or_default(),
                        "now": i64::arbitrary(u).unwrap_or_default(),
                        "tmb": b64(&[7; 32]),
                    },
                    "sig": b64(&[0; 64]),
                })
            };
            json!({"kind": "peer-equivocation", "pg": b64(&[7; 32]),
                   "peer": "p", "a": stmt(&mut u), "b": stmt(&mut u)})
        },
    };

    let _ = EvidenceItem::parse(&item);
    runtime().block_on(async {
        let Some(base) = genesis().await else {
            return;
        };
        let history = KeyHistory::of(&[], &base);
        let _ = verify_principal_fork(&item, &b64(&[7; 32]), base, &[]).await;
        let pr = coz::Thumbprint::from_bytes(vec![7; 32]);
        let _ = verify_peer_equivocation::<MemoryStorage>(&item, &pr, &history, None);
    });
});
