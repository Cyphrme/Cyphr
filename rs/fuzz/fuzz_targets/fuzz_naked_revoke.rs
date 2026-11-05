#![no_main]

use std::sync::OnceLock;

use coz::{ES256, SigningKey};
use cyphr::state::TaggedDigest;
use cyphr_server::revoke::{DisclosedKey, NakedRevokeEnvelope, interpret};
use cyphr_storage::blob::Blake3Hash;
use cyphr_storage::index::{
    CommitRef, EntityRef, Indexer, IndexerError, PrincipalSummary, PublicKeyInfo, TipState,
};
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

/// An index that reports every thumbprint as present.
///
/// `interpret` stops at its presence fence for any key the index has not
/// seen, which is every key against an empty index. Answering "present"
/// lets inputs reach the thumbprint bind and signature check behind it; the
/// presence fence itself is a single `is_none` branch with nothing to fuzz.
struct EveryKeyIndexed;

impl Indexer for EveryKeyIndexed {
    async fn get_tip(&self, _: &str) -> Result<Option<TipState>, IndexerError> {
        Ok(None)
    }

    // `interpret` never asks about PGs. `false` ("no PG established") is the
    // answer for an index that holds no commits, which this stub's other
    // methods already claim.
    async fn is_pg_established(&self, _: &str) -> Result<bool, IndexerError> {
        Ok(false)
    }

    async fn get_commit_chain(
        &self,
        _: &str,
        _: Option<u64>,
        _: Option<u64>,
    ) -> Result<Vec<CommitRef>, IndexerError> {
        Ok(Vec::new())
    }

    async fn resolve_digest(&self, _: &TaggedDigest) -> Result<Option<EntityRef>, IndexerError> {
        Ok(None)
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError> {
        Ok(Vec::new())
    }

    async fn is_blob_indexed(&self, _: &Blake3Hash) -> Result<bool, IndexerError> {
        Ok(false)
    }

    async fn get_key(&self, thumbprint: &str) -> Result<Option<PublicKeyInfo>, IndexerError> {
        Ok(Some(PublicKeyInfo {
            thumbprint: thumbprint.to_string(),
            algorithm: "ES256".into(),
            public_key: String::new(),
        }))
    }
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
// `NakedRevokeEnvelope` and handed to `interpret`.
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
        match serde_json::from_slice::<NakedRevokeEnvelope>(rest) {
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
        NakedRevokeEnvelope {
            pay,
            sig,
            key: Some(DisclosedKey {
                alg: "ES256".into(),
                pub_key: pubk.clone(),
            }),
        }
    };

    let _ = runtime().block_on(interpret(&envelope, &EveryKeyIndexed));
});
