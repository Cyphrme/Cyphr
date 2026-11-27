//! A principal that removed its last key and holds no data has no State
//! Root. The first cell of its Principal Tree is then the Commit Root and
//! not the State Root, and a certificate cannot say which cell is which, so
//! the prover refuses to open such a root. Every log that does not end there
//! is provable, including through that commit's predecessors. A question
//! the log cannot answer, not a failure of the server: `Question`, a 422.

use coz::base64ct::Encoding;
use cyphr::proof::{Anchor, Claim, ProveError, verify};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

#[tokio::test]
async fn a_log_ending_with_no_key_and_no_data_has_no_certificate() {
    let k = coz::Alg::Ed25519.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    let key = Key::new(k.alg.name().to_string(), tmb.clone(), k.pub_bytes.clone()).expect("key");
    let signer = SoftwareSigner::new(k.alg.name(), &k.prv_bytes, &k.pub_bytes, &tmb);
    let mut p = Principal::implicit(key).await.expect("open");
    p.commit_genesis(&signer, &[], T, AUTHORITY)
        .await
        .expect("genesis");

    // The principal removes its only key: no keys, no data, no State Root.
    let id = coz::base64ct::Base64UrlUnpadded::encode_string(tmb.as_bytes());
    let mut pay = json!({"alg": k.alg.name(), "id": id, "now": T + 10, "tmb": id,
                         "typ": format!("{AUTHORITY}/cyphr/key/delete")});
    pay.as_object_mut().expect("object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, k.alg.name(), &k.prv_bytes, &k.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, k.alg.name()).expect("czd");
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&v, &sig, czd, None).expect("delete");
    scope
        .finalize_with_software(&signer, T + 11, AUTHORITY)
        .await
        .expect("commit");
    assert!(
        p.commit_at(1).expect("commit").sr().is_none(),
        "setup: the last commit left no State Root"
    );

    // The log of one commit still has one.
    let member = |index| Claim::Member {
        index,
        commit: cyphr::replay::WireBundle::of_commit(p.commit_at(index as usize).expect("commit"))
            .expect("bundle"),
    };
    let cert = p.prove(1, &member(0)).await.expect("the genesis log");
    assert_eq!(
        verify(&Anchor::of_chain(p.state()), &cert, 1, &member(0)),
        Ok(())
    );
    // A log that ends in the keyless commit has none, whatever is asked.
    for (index, size) in [(0, 2), (1, 2)] {
        let r = p.prove(size, &member(index)).await;
        assert!(
            matches!(&r, Err(ProveError::Question(_))),
            "membership {index} of {size}: {r:?}"
        );
    }
    let r = p
        .prove(
            2,
            &Claim::Extends {
                from: 1,
                head: p.root_at(2).expect("a head").pr,
            },
        )
        .await;
    assert!(
        matches!(&r, Err(ProveError::Question(_))),
        "extension 1 to 2: {r:?}"
    );
}
