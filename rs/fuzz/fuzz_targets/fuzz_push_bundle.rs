#![no_main]

use std::sync::OnceLock;

use coz::{ES256, SigningKey};
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{StorageEngine, genesis_principal_id};
use cyphr_storage::index::MemoryIndexer;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build runtime")
    })
}

/// One real ES256 keypair per fuzzer process.
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

/// 2^53 - 1, the largest integer JSON carries exactly and the bound the
/// protocol's other timestamp (`rvk`) validator uses. The push path has no
/// range check on `now` itself (only chain ordering), so these are the
/// plausible edges rather than a validator's.
const RVK_UPPER: i64 = (1 << 53) - 1;

/// An integer field chosen by a selector byte, so the fuzzer can steer to
/// the validator's edges without losing the full range:
/// (a) the boundary values of a timestamp (each bound, bound +/- 1, 0, -1,
///     `i64::MIN`/`MAX`), (b) a small-int domain, (c) any `i64`.
/// Mutating a full-range `i64` alone almost never lands on an exact edge.
fn int_field(u: &mut Unstructured<'_>) -> i64 {
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

/// Splits the input into u16-length-prefixed chunks: one chunk per blob of
/// the pushed commit bundle.
fn split_bundle(mut rest: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    while rest.len() >= 2 {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2..];
        if rest.len() < len {
            chunks.push(rest);
            break;
        }
        let (chunk, remaining) = rest.split_at(len);
        chunks.push(chunk);
        rest = remaining;
    }
    chunks
}

/// A `commit/create` blob carrying the process key as its genesis key, with a
/// fuzzer-chosen payload field. Blind mutation cannot produce a `key` whose
/// `tmb` is the hash of its `pub`, so without this no input gets past
/// genesis resolution into the blob-parsing and chain-verification code.
fn genesis_blob(u: &mut Unstructured<'_>) -> Option<Vec<u8>> {
    let (prv, pubk) = keypair();
    let tmb = coz::compute_thumbprint_for_alg("ES256", pubk)?;
    let pay = json!({
        "typ": "cyphr.me/cyphr/commit/create",
        "alg": "ES256",
        "tmb": tmb,
        "now": int_field(u),
        "pad": String::arbitrary(u).ok()?,
    });
    let (sig, _cad) = coz::sign_json(&serde_json::to_vec(&pay).ok()?, "ES256", prv, pubk)?;
    let b64 =
        |b: &[u8]| <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(b);
    serde_json::to_vec(&json!({
        "pay": pay,
        "sig": b64(&sig),
        "key": { "alg": "ES256", "pub": b64(pubk), "tmb": tmb },
    }))
    .ok()
}

// Mode 0 treats the input as the raw bundle. Mode 1 prepends a
// genesis-bearing blob (see `genesis_blob`) to the fuzzer's remaining blobs.
// Either way the principal id is derived from the bundle's own genesis, as a
// legitimate client would, so inputs get past the id-binding check.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let owned;
    let mut blobs: Vec<&[u8]> = Vec::new();
    if mode % 2 == 1 {
        let mut u = Unstructured::new(rest);
        let Some(blob) = genesis_blob(&mut u) else {
            return;
        };
        owned = blob;
        blobs.push(&owned);
        // Remaining unstructured bytes become the following blobs.
        let consumed = rest.len() - u.len();
        blobs.extend(split_bundle(&rest[consumed..]));
    } else {
        blobs = split_bundle(rest);
    }
    if blobs.is_empty() {
        return;
    }

    runtime().block_on(async {
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        let principal_id = match engine.resolve_genesis("fuzz", &blobs).await {
            Ok(genesis) => genesis_principal_id(&genesis).unwrap_or_else(|_| "fuzz".into()),
            Err(_) => "fuzz".into(),
        };
        let _ = engine.submit_commit(&principal_id, None, &blobs).await;
    });
});
