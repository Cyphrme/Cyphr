//! The seam's contract: a signature produced through the signer a backend
//! hands out verifies against the public key the same backend reports, for
//! every supported algorithm, and the key survives a reopen of its file.

use coz::{Cad, canonical_hash_for_alg, verify_json};
use cyphr::signer::Signer;
use cyphr_keystore::{JsonKeyStore, KeyBackend};
use proptest::prelude::*;

const ALGS: [&str; 4] = ["ES256", "ES384", "ES512", "Ed25519"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Spec: a Coz signature over a pay verifies under the signer's
    /// reported public key (Coz verification, SPEC section on signing).
    #[test]
    fn signature_through_seam_verifies_against_reported_key(
        alg in 0usize..4,
        msg in "[a-z ]{0,24}",
    ) {
        let alg = ALGS[alg];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut ks = JsonKeyStore::open(&path).unwrap();
        let info = ks.generate(alg, Some("t")).unwrap();

        // Reopen: the persisted key, not the in-memory one, must sign.
        let ks = JsonKeyStore::open(&path).unwrap();
        let reported = ks.public(&info.tmb).unwrap();
        prop_assert_eq!(&reported, &info);
        let signer = ks.signer(&info.tmb).unwrap();
        prop_assert_eq!(signer.pub_key(), &reported.pub_key[..]);

        let pay = serde_json::to_vec(&serde_json::json!({"alg": alg, "msg": msg})).unwrap();
        let cad: Cad = canonical_hash_for_alg(&pay, alg, None).unwrap();
        let sig = signer.sign_now(&cad).unwrap();
        prop_assert_eq!(verify_json(&pay, &sig, alg, &reported.pub_key), Some(true));
    }
}
