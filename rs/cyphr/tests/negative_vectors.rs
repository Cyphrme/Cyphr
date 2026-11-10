//! Negative vectors: inputs the protocol must reject, each pinned to the
//! exact `Error` variant so a change of rejection path turns the test red.
//!
//! Claims backed here:
//! - C1: an ES256 signature with high `S` is rejected (signature malleability would let a third
//!   party mint a second `czd` for the same signed action).
//! - C2: an Ed25519 signature with non-canonical `s` (`s + L`) is rejected, for the same reason.
//! - C3: a key removed by `key/delete` cannot sign an accepted data action, whether the action is
//!   dated inside its old active period, after the delete, or spliced into history before the
//!   delete commit. An action recorded before the delete stays recorded after it (C3a asserts
//!   this); only new actions by the deleted key are refused.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::{Error, Key, Principal};
use test_fixtures::Pool;

struct Signer {
    alg: String,
    prv: Vec<u8>,
    pub_key: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn signer(name: &str) -> Signer {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = Pool::load(&path).expect("pool.toml loads");
    let pk = pool
        .get(name)
        .unwrap_or_else(|| panic!("pool key {name} missing"));
    Signer {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("pool key has prv"))
            .expect("prv base64"),
        pub_key: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub base64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn domain_key(s: &Signer) -> Key {
    Key::new(s.alg.clone(), s.tmb.clone(), s.pub_key.clone())
        .expect("key binds its tmb")
        .with_first_seen(1_700_000_000)
}

/// `p` with its genesis committed (SPEC 5.1: a commit chain begins with the
/// genesis key's `key/create` of itself, the `principal/create` and the
/// `commit/create`), signed by its genesis key `k`, which creates
/// each of `others` after itself.
async fn genesis_of(mut p: Principal, k: &Signer, others: &[Key]) -> Principal {
    p.commit_genesis(
        &cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pub_key, &k.tmb),
        others,
        1,
        "cyphr.me",
    )
    .await
    .expect("genesis commit");
    p
}

type Signed = (Vec<u8>, Vec<u8>, coz::Czd);

fn sign_with_cad(s: &Signer, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Cad) {
    let bytes = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&bytes, &s.alg, &s.prv, &s.pub_key).expect("sign_json");
    (bytes, sig, cad)
}

fn sign(s: &Signer, pay: serde_json::Value) -> Signed {
    let (bytes, sig, cad) = sign_with_cad(s, pay);
    let czd = coz::czd_for_alg(&cad, &sig, &s.alg).expect("czd");
    (bytes, sig, czd)
}

fn action_pay(s: &Signer, now: i64, msg: &str) -> serde_json::Value {
    serde_json::json!({"alg": s.alg, "tmb": s.tmb.to_b64(),
        "typ": "cyphr.me/comment/create", "now": now, "msg": msg})
}

fn action(s: &Signer, now: i64, msg: &str) -> Signed {
    sign(s, action_pay(s, now, msg))
}

fn record(p: &mut Principal, (pay, sig, czd): Signed) -> Result<(), Error> {
    p.verify_and_record_action(&pay, &sig, czd).map(|_| ())
}

// ---------------------------------------------------------------------------
// C1 / C2: signature malleability
// ---------------------------------------------------------------------------

/// P-256 group order n, big-endian.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Ed25519 group order L, little-endian.
const ED25519_L: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `a - b` over 32-byte big-endian integers; caller guarantees `a >= b`.
fn sub_be(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(d < 0);
        out[i] = (d & 0xFF) as u8;
    }
    out
}

/// `a + b` over 32-byte little-endian integers; caller guarantees no overflow.
fn add_le(a: &[u8], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let t = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = (t & 0xFF) as u8;
        carry = t >> 8;
    }
    out
}

fn replace_s(sig: &[u8], s: &[u8]) -> Vec<u8> {
    let mut v = sig[..32].to_vec();
    v.extend_from_slice(s);
    v
}

// Practice: https://www.bitcoin.org/bip-0062 section "Low S values in signatures" (BIP-0062 rule 5) requires S <= n/2 so an ECDSA signature has one valid encoding; BIP-0062 is secp256k1 and is applied here by analogy to P-256, since SEC 1 v2 itself does not mandate low-S. The attacker is a relay that flips S to n-S: the flipped signature still verifies, but the coz digest `czd` covers `sig`, so the relay mints a second identity for one signed action.
// The direct source of the rule is the Coz spec's low-S requirement, enforced in coz-rs 0.4.1
// key.rs (ES256 verify, "Coz spec requires low-S only"); BIP-0062 is the cited external practice.
// Claim C1. Mutation that turns this red: dropping the low-S check in coz-rs verify (coz-rs key.rs)
// or swapping to a verifier that accepts both S and n-S.
// @docket: rv-sig-verifies :: scripts/docket-run rv-sig-verifies
#[tokio::test]
async fn es256_high_s_signature_is_rejected() {
    let key = signer("key_a");
    assert_eq!(key.alg, "ES256", "fixture precondition");
    let golden = signer("golden");
    let (pay, sig, cad) = sign_with_cad(&key, action_pay(&key, 1_700_000_010, "malleable"));
    let s = &sig[32..64];
    let s_arr: [u8; 32] = s.try_into().expect("32-byte s");
    let flipped = sub_be(&P256_N, &s_arr);
    // Exactly one of {s, n-s} is the high half; the other is the low half.
    let (low, high) = if s_arr < flipped {
        (s_arr, flipped)
    } else {
        (flipped, s_arr)
    };

    let mut p = genesis_of(
        Principal::implicit(domain_key(&golden))
            .await
            .expect("principal"),
        &golden,
        &[domain_key(&key)],
    )
    .await;

    // Control: the low-S encoding of the same signature is accepted, so the
    // rejection below can only come from the high-S rule.
    let low_sig = replace_s(&sig, &low);
    let czd = coz::czd_for_alg(&cad, &low_sig, &key.alg).expect("czd");
    record(&mut p, (pay.clone(), low_sig, czd)).expect("low-S control accepted");

    let high_sig = replace_s(&sig, &high);
    let czd = coz::czd_for_alg(&cad, &high_sig, &key.alg).expect("czd");
    let r = record(&mut p, (pay, high_sig, czd));
    assert!(
        matches!(r, Err(Error::InvalidSignature)),
        "high-S ES256 must be Err(InvalidSignature), got {r:?}"
    );
    assert_eq!(p.action_count(), 1, "rejected signature recorded nothing");
}

// Practice: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7 section 5.1.7 (Verify) requires 0 <= s < L, rejecting s + L, which would otherwise give a second valid encoding of one signature (the czd covers sig).
// Claim C2. Mutation that turns this red: building ed25519-dalek with the `legacy_compatibility`
// feature, or any verifier that reduces s mod L before checking.
#[tokio::test]
async fn ed25519_non_canonical_s_is_rejected() {
    let key = signer("eve_ed25519");
    assert_eq!(key.alg, "Ed25519", "fixture precondition");
    let golden = signer("golden");
    let (pay, sig, cad) = sign_with_cad(&key, action_pay(&key, 1_700_000_010, "malleable"));
    let czd = coz::czd_for_alg(&cad, &sig, &key.alg).expect("czd");
    let s = &sig[32..64];
    let bumped = add_le(s, &ED25519_L);
    assert_ne!(bumped.as_slice(), s, "s + L differs from s");

    let mut p = genesis_of(
        Principal::implicit(domain_key(&golden))
            .await
            .expect("principal"),
        &golden,
        &[domain_key(&key)],
    )
    .await;

    // s + L is the same scalar mod L, so only the canonicality check can
    // distinguish it from the genuine signature.
    let bad_sig = replace_s(&sig, &bumped);
    let bad_czd = coz::czd_for_alg(&cad, &bad_sig, &key.alg).expect("czd");
    let r = record(&mut p, (pay.clone(), bad_sig, bad_czd));
    assert!(
        matches!(r, Err(Error::InvalidSignature)),
        "non-canonical Ed25519 s must be Err(InvalidSignature), got {r:?}"
    );
    assert_eq!(p.action_count(), 0, "rejected signature recorded nothing");

    // Control: the canonical signature for the same payload is accepted.
    record(&mut p, (pay, sig, czd)).expect("canonical control accepted");
}

// ---------------------------------------------------------------------------
// C3: deleted-key backdating
// ---------------------------------------------------------------------------

/// The `ds/create` (SPEC 4.8.2) golden signs at t=100 to include DR, `id`
/// being the DT root of the scope it is applied in.
fn ds_create(golden: &Signer, scope: &cyphr::CommitScope<'_>) -> Signed {
    let id = scope
        .data_tree_id()
        .expect("DT id")
        .expect("DT holds an action");
    sign(
        golden,
        serde_json::json!({"alg": golden.alg, "tmb": golden.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/ds/create", "id": id, "now": 1_700_000_100}),
    )
}

/// Principal {golden, key_a}; key_a signs a genuine action at t=10; at
/// t=100 golden includes it into DR (`ds/create`) and deletes key_a in one
/// commit. Returns the principal with key_a deleted.
async fn principal_with_deleted_key(golden: &Signer, key_a: &Signer) -> Principal {
    let mut p = genesis_of(
        Principal::implicit(domain_key(golden))
            .await
            .expect("principal"),
        golden,
        &[domain_key(key_a)],
    )
    .await;
    record(&mut p, action(key_a, 1_700_000_010, "genuine")).expect("genuine action accepted");
    let (pay, sig, czd) = sign(
        golden,
        serde_json::json!({"alg": golden.alg, "tmb": golden.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/delete", "id": key_a.tmb.to_b64(), "now": 1_700_000_100}),
    );
    let mut scope = p.begin_commit();
    let (ds_pay, ds_sig, ds_czd) = ds_create(golden, &scope);
    scope
        .verify_and_apply(&ds_pay, &ds_sig, ds_czd, None)
        .expect("ds/create applies");
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("delete applies");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &golden.alg,
                &golden.prv,
                &golden.pub_key,
                &golden.tmb,
            ),
            1_700_000_100,
            "cyphr.me",
        )
        .await
        .expect("delete commit finalizes");
    assert!(!p.is_key_active(&key_a.tmb), "key_a deleted");
    p
}

// Practice: SPEC.md section 6.2 (`key/delete`) says "actions signed after it has been removed are ignored" and "Only actions signed while a ley is active in KT are interpreted", but also "Past signatures from previous active periods remain valid even after the key is no longer active". The second sentence does not say whether a signer-dated action claiming a past period is accepted on replay, and no public spec-author position exists: forge issue #200 item 1 is open with the spec author. This test therefore pins the implementation's current fail-closed behaviour (rejection by current KT membership, not by `now`), not a ruling of the spec.
// Claim C3a. Mutation that turns this red: making `verify_and_record_action` check the signer
// against the key's historical active periods by the payload `now` instead of current KT
// membership.
#[tokio::test]
async fn deleted_key_action_backdated_into_old_active_period_is_rejected() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let mut p = principal_with_deleted_key(&golden, &key_a).await;
    // The genuine pre-delete action is still recorded after the delete.
    let count = p.action_count();
    assert_eq!(count, 1, "genuine pre-delete action stays recorded");

    let r = record(
        &mut p,
        action(&key_a, 1_700_000_050, "forged, dated inside active period"),
    );
    assert!(
        matches!(r, Err(Error::UnknownKey)),
        "expected Err(UnknownKey), got {r:?}"
    );
    assert_eq!(p.action_count(), count, "rejection recorded nothing");
}

// Practice: SPEC.md section 6.2 (`key/delete`): "actions signed after it has been removed are
// ignored"; a deleted key has no authority after its delete commit. Claim C3b. Mutation that turns
// this red: accepting data actions from a key absent from the current KT.
// @docket: rv-key-active-gate :: scripts/docket-run rv-key-active-gate
#[tokio::test]
async fn deleted_key_action_dated_after_delete_is_rejected() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let mut p = principal_with_deleted_key(&golden, &key_a).await;
    let r = record(&mut p, action(&key_a, 1_700_000_200, "after delete"));
    assert!(
        matches!(r, Err(Error::UnknownKey)),
        "expected Err(UnknownKey), got {r:?}"
    );
}

// Practice: SPEC.md section 4.8.2 (a `ds/create` names DR = MR(DT)) with section 4.2 (`arrow`):
// the delete commit includes DR as it stood, so history rewritten to hold a later forged action
// cannot re-verify. Claim C3c. Mutation that turns this red: not checking a `ds/create`'s `id`
// against the Data Tree it is applied to.
// @docket: rv-state-recomputed :: scripts/docket-run rv-state-recomputed
#[tokio::test]
async fn forged_action_spliced_before_delete_commit_breaks_replay() {
    let (golden, key_a) = (signer("golden"), signer("key_a"));
    let honest = principal_with_deleted_key(&golden, &key_a).await;
    let cozies = honest.commits().last().expect("delete commit").all_cozies();

    // Control: an honest replay without the forged action finalizes, so the
    // failure below comes only from the spliced action.
    let mut honest_replay = genesis_of(
        Principal::implicit(domain_key(&golden))
            .await
            .expect("principal"),
        &golden,
        &[domain_key(&key_a)],
    )
    .await;
    record(&mut honest_replay, action(&key_a, 1_700_000_010, "genuine")).expect("genuine");
    let mut scope = honest_replay.begin_commit();
    for vc in &cozies {
        let raw = vc.raw();
        let bytes = serde_json::to_vec(&raw.pay).expect("serialize pay");
        scope
            .verify_and_apply(&bytes, &raw.sig, vc.czd().clone(), None)
            .expect("coz applies");
    }
    scope.finalize().await.expect("honest replay finalizes");

    // Replayer: the same genesis and genuine action, plus a forged action
    // dated inside key_a's active period, inserted before the delete commit.
    let mut p = genesis_of(
        Principal::implicit(domain_key(&golden))
            .await
            .expect("principal"),
        &golden,
        &[domain_key(&key_a)],
    )
    .await;
    record(&mut p, action(&key_a, 1_700_000_010, "genuine")).expect("genuine");
    record(
        &mut p,
        action(&key_a, 1_700_000_050, "forged, spliced before delete"),
    )
    .expect("key_a is still active at this position in the forged history");

    // The delete commit's `ds/create` named DR over the genuine action
    // alone; over the spliced DT it names a state this history is not in.
    let mut scope = p.begin_commit();
    let r = cozies.iter().try_for_each(|vc| {
        let raw = vc.raw();
        let bytes = serde_json::to_vec(&raw.pay).expect("serialize pay");
        scope.verify_and_apply(&bytes, &raw.sig, vc.czd().clone(), None)
    });
    assert!(
        matches!(r, Err(Error::StateMismatch)),
        "expected Err(StateMismatch), got {r:?}"
    );
}
