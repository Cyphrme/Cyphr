//! Unit tests for the principal modules.

mod apply;
mod lifecycle;
mod proofs;
mod tree;

use coz::Thumbprint;

use super::*;
use crate::commit_root::MaltHasher;
use crate::key::Key;
use crate::state::StateDigest;

/// Claim (I2, single writer per principal; the "No `Clone`" note on
/// [`Principal`]): a principal is not `Clone`, so two writers of one log
/// cannot be made by copying a handle. Red if `Principal<MemoryStorage>`
/// ever implements `Clone`, by derive or by hand: the assertion stops
/// compiling because the call below is then ambiguous. Compile-time
/// assertion; no scenario reaches a trait bound.
const _: () = {
    trait AmbiguousIfClone<A> {
        fn assert() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}
    let _ = <Principal<eml::MemoryStorage> as AmbiguousIfClone<_>>::assert;
};

fn make_test_key(id: u8) -> Key {
    Key::from_pub_key("ES256", vec![id; 64])
        .expect("dummy key")
        .with_first_seen(1000)
}

/// Create a dummy CozJson for test cozies.
/// The payload content doesn't need to match the ParsedCoz kind
/// since tests bypass signature verification.
fn dummy_coz_json() -> coz::CozJson {
    coz::CozJson {
        pay: serde_json::json!({
            "typ": "cyphr.me/test",
            "alg": "ES256",
            "now": 1000
        }),
        sig: vec![0; 64],
    }
}

/// Helper: build a principal with its genesis commit and then N commits via
/// key/create transactions.
/// Returns the principal and the list of keys (genesis + added).
async fn build_principal_with_commits(n_commits: usize) -> (Principal, Vec<Key>) {
    use coz::Czd;

    use crate::parsed_coz::{CozKind, ParsedCoz};
    let mut keys = vec![make_test_key(0x01)];
    let mut principal = Principal::implicit(keys[0].clone()).await.unwrap();
    principal.genesis_test(Vec::new()).await.unwrap();

    for i in 0..n_commits {
        let new_key = make_test_key((i + 2) as u8);
        let signer = keys.last().unwrap().tmb().clone();

        let cz = ParsedCoz {
            kind: CozKind::KeyCreate {
                id: new_key.tmb().clone(),
            },
            signer: signer.clone(),
            now: (1000 + (i as i64 + 1) * 1000),
            czd: Czd::from_bytes(vec![0xA0 + i as u8; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        principal
            .apply_transaction_test(cz, Some(new_key.clone()))
            .await
            .unwrap();
        keys.push(new_key);
    }

    (principal, keys)
}

fn make_key_add_tx(new_key: &Key, signer: &Thumbprint) -> crate::parsed_coz::ParsedCoz {
    use coz::Czd;
    use serde_json::json;

    use crate::parsed_coz::{CozKind, ParsedCoz};

    // Create dummy raw CozJson for test cozies
    let raw = coz::CozJson {
        pay: json!({
            "typ": "cyphr.me/key/create",
            "alg": "ES256",
            "now": 2000,
            "tmb": signer.to_b64(),
            "id": new_key.tmb().to_b64()
        }),
        sig: vec![0; 64],
    };

    ParsedCoz {
        kind: CozKind::KeyCreate {
            id: new_key.tmb().clone(),
        },
        signer: signer.clone(),
        now: 2000,
        czd: Czd::from_bytes(vec![0xAB; 32]),
        hash_alg: crate::state::HashAlg::Sha256,
        arrow: None,
        raw,
    }
}

fn make_test_action(signer: &Thumbprint) -> Action {
    use coz::{Czd, PayBuilder};

    let pay = PayBuilder::new()
        .typ("cyphr.me/comment/create")
        .alg("ES256")
        .now(3000)
        .tmb(signer.clone())
        .msg("Test action")
        .build();

    let raw = coz::CozJson {
        pay: serde_json::to_value(&pay).unwrap(),
        sig: vec![0; 64],
    };
    let czd = Czd::from_bytes(vec![0xCC; 32]);

    Action::from_pay(&pay, czd, raw).unwrap()
}

/// A key using a different algorithm/thumbprint length than `make_test_key`
/// (which is always ES256/SHA-256), so a two-key principal registers two
/// distinct hash algorithms from genesis.
fn make_test_key_ed25519(id: u8) -> Key {
    Key::from_pub_key("Ed25519", vec![id; 32])
        .expect("dummy key")
        .with_first_seen(1000)
}
