#![no_main]

use std::sync::OnceLock;

use coz::{ES256, SigningKey};
use cyphr::replay::{KeyEntry, WireBundle};
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

/// Splits the input into u16-prefixed chunks, one per coz of the pushed
/// bundle: the low 15 bits are the chunk's length, and a set high bit
/// starts a new transaction, so the fuzzer steers the grouping (SPEC 4.6.2)
/// as well as the bytes.
fn split_bundle(mut rest: &[u8]) -> Vec<Vec<Vec<u8>>> {
    let mut txs: Vec<Vec<Vec<u8>>> = Vec::new();
    while rest.len() >= 2 {
        let prefix = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(prefix & 0x7fff);
        rest = &rest[2..];
        let chunk = if rest.len() < len {
            let all = rest;
            rest = &[];
            all
        } else {
            let (chunk, remaining) = rest.split_at(len);
            rest = remaining;
            chunk
        };
        match txs.last_mut() {
            Some(tx) if prefix & 0x8000 == 0 => tx.push(chunk.to_vec()),
            _ => txs.push(vec![chunk.to_vec()]),
        }
    }
    txs
}

/// The self-signed `key/create` of the process key, a genesis transaction,
/// with a fuzzer-chosen `now` and payload field, and the key's `keys`
/// entry. Blind mutation cannot produce a key entry whose `tmb` is the hash
/// of its `pub`, so without this no input gets past genesis resolution
/// into the blob-parsing and chain-verification code.
fn genesis_tx(u: &mut Unstructured<'_>) -> Option<(Vec<u8>, KeyEntry)> {
    let (prv, pubk) = keypair();
    let tmb = coz::compute_thumbprint_for_alg("ES256", pubk)?;
    let pay = json!({
        "typ": "cyphr.me/cyphr/key/create",
        "alg": "ES256",
        "tmb": tmb,
        "id": tmb,
        "now": int_field(u),
        "pad": String::arbitrary(u).ok()?,
    });
    let (sig, _cad) = coz::sign_json(&serde_json::to_vec(&pay).ok()?, "ES256", prv, pubk)?;
    let b64 =
        |b: &[u8]| <coz::base64ct::Base64UrlUnpadded as coz::base64ct::Encoding>::encode_string(b);
    let blob = serde_json::to_vec(&json!({ "pay": pay, "sig": b64(&sig) })).ok()?;
    let entry = KeyEntry {
        alg: "ES256".into(),
        pub_key: b64(pubk),
        tmb: tmb.to_string(),
        tag: None,
        now: None,
    };
    Some((blob, entry))
}

// Mode 0 treats the input as the raw bundle's transactions. Mode 1 opens the
// bundle with a genesis transaction (see `genesis_tx`) before the fuzzer's
// own. Either way the principal id is derived from the bundle's own
// genesis, as a legitimate client would, so inputs get past the id-binding
// check.
fuzz_target!(|data: &[u8]| {
    let Some((mode, rest)) = data.split_first() else {
        return;
    };

    let mut bundle = WireBundle::default();
    if mode % 2 == 1 {
        let mut u = Unstructured::new(rest);
        let Some((blob, entry)) = genesis_tx(&mut u) else {
            return;
        };
        bundle.txs.push(vec![blob]);
        bundle.keys.push(entry);
        // Remaining unstructured bytes become the following transactions.
        let consumed = rest.len() - u.len();
        bundle.txs.extend(split_bundle(&rest[consumed..]));
    } else {
        bundle.txs = split_bundle(rest);
    }
    if bundle.is_empty() {
        return;
    }

    runtime().block_on(async {
        let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
        // A placeholder id for a bundle that derives none.
        let fallback =
            cyphr::PrincipalGenesis::from_digest(cyphr::state::HashAlg::Sha256, vec![0; 32])
                .expect("a 32-byte digest is a SHA-256 width");
        let principal_id = match engine
            .resolve_genesis(&fallback, std::slice::from_ref(&bundle))
            .await
        {
            Ok(genesis) => genesis_principal_id(&genesis).unwrap_or(fallback),
            Err(_) => fallback,
        };
        let _ = engine.submit_commit(&principal_id, None, &bundle).await;
    });
});
