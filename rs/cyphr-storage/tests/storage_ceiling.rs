//! The storage ceiling holds every write but the revoke of a key a stored
//! principal holds (SPEC 6.4): that one is recorded whatever the ceiling.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_storage::engine::EngineError;

mod common;
use common::*;

fn naked_revoke(k: &Kp, rvk: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": k.alg, "now": rvk, "rvk": rvk, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &k.alg, &k.prv, &k.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay json"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": k.alg, "pub": Base64UrlUnpadded::encode_string(&k.pubb)},
    })
}

/// Claim: with the ceiling exactly reached, the naked revoke of a key the
/// engine does not hold is refused `StorageFull` and stores nothing, while
/// the revoke of a held key is recorded. Turns red if the held-key revoke
/// is refused, or an unheld key's revoke is let past the ceiling.
/// End-to-end scenario: yes (a real principal and engine).
#[tokio::test]
async fn only_the_revoke_of_a_held_key_passes_a_full_ceiling() {
    let rig = Rig::new(2).await;
    let mut e = rig.fed(1).await;
    let held = &rig.keys[0];
    let stranger = fresh_kp();
    e.set_storage_ceiling(Some(e.stored_bytes()));
    let before = e.stored_bytes();

    let refused = e
        .record_revoke(&naked_revoke(&stranger, NOW + 5), NOW + 5)
        .await;
    assert!(
        matches!(refused, Err(EngineError::StorageFull { .. })),
        "{refused:?}"
    );
    assert_eq!(e.stored_bytes(), before, "a refusal stores nothing");
    assert!(!e.is_revoked(&stranger.tmb.to_b64()).await.expect("verdict"));

    e.record_revoke(&naked_revoke(held, NOW + 6), NOW + 6)
        .await
        .expect("a held key's revoke is recorded past the ceiling");
    assert!(e.is_revoked(&held.tmb.to_b64()).await.expect("verdict"));
}
