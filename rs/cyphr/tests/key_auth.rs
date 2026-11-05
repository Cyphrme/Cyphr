//! Key-authentication red tests (security sweep D1, D3, D4).
//!
//! Each test states the SPEC property it backs and the defect that turns
//! it red. All are end-to-end through the public `cyphr` API: genesis,
//! then mutations, then an independent signature check by the principal.
//!
//! - D1: a key's `tmb` must equal `thumbprint(alg, pub)` wherever a `Key` enters a principal
//!   (genesis, `key/create`, `key/replace`). The signed pay binds only the `tmb`; the `pub` travels
//!   in an unsigned sidecar, so an unchecked binding lets an attacker substitute the sidecar and
//!   leave every root unchanged.
//! - D3: a revoked key is never trusted again (SPEC 6.4); only a deleted key may be re-added (SPEC
//!   6.2).
//! - D4: `pay.alg` must equal the signing key's `alg`, and the `czd` is recomputed from the signed
//!   bytes, never trusted from the caller.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use serde_json::json;

const T: i64 = 1_700_000_000;

/// Ed25519 czds are SHA-512 digests; a wrong-length czd would be rejected
/// for the wrong reason (a digest-width error) rather than as untrusted.
const CZD_LEN: usize = 64;

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let k = coz::Alg::Ed25519.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

/// The pool's ES256 `golden` key (SPEC 15.1 principal), for non-Ed25519
/// coverage.
fn golden_es256() -> Kp {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool");
    let pk = pool.get("golden").expect("golden in pool");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("b64");
    assert_eq!(pk.alg, "ES256", "premise: golden is ES256");
    Kp {
        alg: pk.alg.clone(),
        pubb: d(&pk.pub_key),
        prv: d(pk.prv.as_ref().expect("golden prv")),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

/// Observable principal state: a rejected operation must leave all of it
/// untouched (no error variant is pinned for D1/D4 until KA1 names one).
fn snapshot(p: &Principal) -> (cyphr::PrincipalRoot, usize, usize, usize) {
    (
        p.pr().clone(),
        p.active_key_count(),
        p.action_count(),
        p.commits().count(),
    )
}

/// The honest key: `tmb` is the real thumbprint of `pub`.
fn honest(k: &Kp) -> Key {
    key_with_tmb(k, k.tmb.clone())
}

/// A key carrying `k`'s public bytes under an arbitrary claimed `tmb`.
fn key_with_tmb(k: &Kp, tmb: coz::Thumbprint) -> Key {
    Key {
        alg: k.alg.to_string(),
        tmb,
        pub_key: k.pubb.clone(),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    }
}

fn b64(t: &coz::Thumbprint) -> String {
    Base64UrlUnpadded::encode_string(t.as_bytes())
}

/// Sign `pay` (keys sorted) with `k`; returns (pay bytes, sig, true czd).
fn sign(k: &Kp, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("serialize pay");
    let (sig, cad) = coz::sign_json(&v, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (v, sig, czd)
}

fn key_create(signer: &Kp, id: &coz::Thumbprint, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/create"}),
    )
}

fn key_replace(signer: &Kp, id: &coz::Thumbprint, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/replace"}),
    )
}

fn key_delete(signer: &Kp, id: &coz::Thumbprint, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign(
        signer,
        json!({"alg": signer.alg, "id": b64(id), "now": now, "tmb": b64(&signer.tmb),
               "typ": "cyphr.me/cyphr/key/delete"}),
    )
}

fn self_revoke(k: &Kp, now: i64) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign(
        k,
        json!({"alg": k.alg, "now": now, "rvk": now, "tmb": b64(&k.tmb),
               "typ": "cyphr.me/cyphr/key/revoke"}),
    )
}

/// A data action signed by `signer`, claiming `pay.tmb = claimed_tmb`
/// and `pay.alg = alg_field`.
fn action(
    signer: &Kp,
    claimed_tmb: &coz::Thumbprint,
    now: i64,
    alg_field: &str,
) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    sign(
        signer,
        json!({"alg": alg_field, "now": now, "tmb": b64(claimed_tmb),
               "typ": "cyphr.me/cyphr/data/x"}),
    )
}

/// One finalized commit by `signer` applying a single signed coz plus an
/// optional sidecar key. Returns the apply/finalize outcome.
fn commit_one(
    p: &mut Principal,
    signer: &Kp,
    coz_parts: (Vec<u8>, Vec<u8>, coz::Czd),
    sidecar: Option<Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let (pay, sig, czd) = coz_parts;
    let mut scope = p.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, sidecar)?;
    scope
        .finalize_with_software(
            &SoftwareSigner::new(&signer.alg, &signer.prv, &signer.pubb, &signer.tmb),
            now,
            "cyphr.me",
        )
        .map(|_| ())
}

// ============================================================================
// D1 -- tmb must equal H(alg, pub)
// ============================================================================

/// Backs: a `Key` enters a principal only with `tmb == thumbprint(alg, pub)`
/// (implicit genesis). Red now because `Principal::implicit` accepts
/// `Key { tmb: victim, pub: attacker }`, letting an attacker's signature
/// verify as the victim's thumbprint.
#[test]
#[ignore = "RED(KA1): D1 tmb not bound to H(pub)"]
fn d1_implicit_genesis_rejects_unbound_key() {
    let victim = kp();
    let attacker = kp();
    let forged = key_with_tmb(&attacker, victim.tmb.clone());

    let r = Principal::implicit(forged);
    assert!(
        r.is_err(),
        "implicit genesis accepted Key{{tmb: victim, pub: attacker}}: the attacker now holds the \
         victim's identity"
    );
}

/// Backs: same binding at explicit (multi-key) genesis. Red now because
/// `Principal::explicit` does not check `tmb == H(pub)` for any member.
#[test]
#[ignore = "RED(KA1): D1 tmb not bound to H(pub)"]
fn d1_explicit_genesis_rejects_unbound_key() {
    let good = kp();
    let victim = kp();
    let attacker = kp();
    let forged = key_with_tmb(&attacker, victim.tmb.clone());

    let r = Principal::explicit(vec![honest(&good), forged]);
    assert!(
        r.is_err(),
        "explicit genesis accepted a member with tmb != H(pub)"
    );
}

/// Backs: `key/create` with `id = victim tmb` and sidecar `pub = attacker`
/// is rejected. Red now because `verify_and_apply` only compares
/// `id == key.tmb`, never `key.tmb == H(key.pub)`.
#[test]
#[ignore = "RED(KA1): D1 tmb not bound to H(pub)"]
fn d1_key_create_rejects_victim_tmb_with_attacker_pub() {
    let g = kp();
    let victim = kp();
    let attacker = kp();
    let mut p = Principal::implicit(honest(&g)).expect("honest genesis");
    let before = snapshot(&p);

    let r = commit_one(
        &mut p,
        &g,
        key_create(&g, &victim.tmb, T),
        Some(key_with_tmb(&attacker, victim.tmb.clone())),
        T + 1,
    );
    assert!(
        r.is_err(),
        "key/create id=victim tmb with pub=attacker was accepted and finalized"
    );
    assert_eq!(before, snapshot(&p), "a rejected key/create changed state");
    assert!(!p.is_key_active(&victim.tmb), "victim tmb became active");
    // End to end: the attacker cannot sign as the victim's tmb.
    let (apay, asig, aczd) = action(&attacker, &victim.tmb, T + 2, "Ed25519");
    assert!(
        p.verify_and_record_action(&apay, &asig, aczd).is_err(),
        "attacker signed an accepted action as the victim tmb"
    );
}

/// Backs: same binding for `key/replace`. Red now for the same reason as
/// the `key/create` case.
#[test]
#[ignore = "RED(KA1): D1 tmb not bound to H(pub)"]
fn d1_key_replace_rejects_victim_tmb_with_attacker_pub() {
    let g = kp();
    let victim = kp();
    let attacker = kp();
    let mut p = Principal::implicit(honest(&g)).expect("honest genesis");
    let before = snapshot(&p);

    let r = commit_one(
        &mut p,
        &g,
        key_replace(&g, &victim.tmb, T),
        Some(key_with_tmb(&attacker, victim.tmb.clone())),
        T + 1,
    );
    assert!(
        r.is_err(),
        "key/replace id=victim tmb with pub=attacker was accepted and finalized"
    );
    assert_eq!(before, snapshot(&p), "a rejected key/replace changed state");
}

/// Control (passes today and must keep passing): an honest `key/create`
/// activates K2, and K2's own signature is accepted. Without this, the
/// D1 rejections above could be satisfied by rejecting everything.
#[test]
fn d1_control_honest_key_create_activates_signer() {
    let g = kp();
    let k2 = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        key_create(&g, &k2.tmb, T),
        Some(honest(&k2)),
        T + 1,
    )
    .expect("honest key/create");
    assert!(p.is_key_active(&k2.tmb));
    let (apay, asig, aczd) = action(&k2, &k2.tmb, T + 2, "Ed25519");
    p.verify_and_record_action(&apay, &asig, aczd)
        .expect("K2 signs as K2");
}

// ============================================================================
// D3 -- revoked keys are never trusted again
// ============================================================================

/// genesis g, `key/create` K2, K2 self-revokes. Returns the principal.
fn principal_with_revoked_k2(g: &Kp, k2: &Kp) -> Principal {
    let mut p = Principal::implicit(honest(g)).expect("genesis");
    commit_one(
        &mut p,
        g,
        key_create(g, &k2.tmb, T),
        Some(honest(k2)),
        T + 1,
    )
    .expect("create K2");
    commit_one(&mut p, k2, self_revoke(k2, T + 2), None, T + 3).expect("K2 self-revoke");
    assert!(p.is_key_revoked(&k2.tmb) && !p.is_key_active(&k2.tmb));
    p
}

/// Backs SPEC 6.4 ("never trusted again") and 6.2 (re-add is for deleted
/// keys only): `key/create` of a revoked tmb is rejected. Red now because
/// the revoked key is accepted back as active.
#[test]
#[ignore = "RED(KA1): D3 revoked key re-addable"]
fn d3_revoked_key_cannot_be_readded_by_key_create() {
    let g = kp();
    let k2 = kp();
    let mut p = principal_with_revoked_k2(&g, &k2);
    let before = snapshot(&p);

    let r = commit_one(
        &mut p,
        &g,
        key_create(&g, &k2.tmb, T + 4),
        Some(honest(&k2)),
        T + 5,
    );
    assert!(
        matches!(r, Err(cyphr::error::Error::KeyRevoked)),
        "key/create of a revoked key must fail with KeyRevoked, got {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a rejected re-add changed state");
}

/// Backs SPEC 6.4 for `key/replace`: replacing onto a revoked tmb is
/// rejected. Red now for the same reason as the `key/create` case.
#[test]
#[ignore = "RED(KA1): D3 revoked key re-addable"]
fn d3_revoked_key_cannot_be_readded_by_key_replace() {
    let g = kp();
    let k2 = kp();
    let mut p = principal_with_revoked_k2(&g, &k2);
    let before = snapshot(&p);

    let r = commit_one(
        &mut p,
        &g,
        key_replace(&g, &k2.tmb, T + 4),
        Some(honest(&k2)),
        T + 5,
    );
    assert!(
        matches!(r, Err(cyphr::error::Error::KeyRevoked)),
        "key/replace onto a revoked key must fail with KeyRevoked, got {r:?}"
    );
    assert_eq!(before, snapshot(&p), "a rejected replace changed state");
}

/// Backs SPEC 6.4 end to end: whatever the re-add does, the revoked key
/// must neither be active nor able to sign afterwards. Red now because the
/// re-add succeeds and K2's action is then accepted.
#[test]
#[ignore = "RED(KA1): D3 revoked key re-addable"]
fn d3_revoked_key_cannot_sign_after_readd_attempt() {
    let g = kp();
    let k2 = kp();
    let mut p = principal_with_revoked_k2(&g, &k2);

    let _ = commit_one(
        &mut p,
        &g,
        key_create(&g, &k2.tmb, T + 4),
        Some(honest(&k2)),
        T + 5,
    );

    assert!(
        p.is_key_revoked(&k2.tmb) && !p.is_key_active(&k2.tmb),
        "revoked key is active again after key/create"
    );
    let (apay, asig, aczd) = action(&k2, &k2.tmb, T + 6, "Ed25519");
    let r = p.verify_and_record_action(&apay, &asig, aczd);
    assert!(
        matches!(r, Err(cyphr::error::Error::KeyRevoked)),
        "a revoked key's action must fail with KeyRevoked, got {:?}",
        r.map(|_| ())
    );
}

/// Control (SPEC 6.2: re-add of a DELETED key is permitted; must keep
/// passing so the D3 fix does not over-reject).
#[test]
fn d3_control_deleted_key_may_be_readded() {
    let g = kp();
    let k2 = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    commit_one(
        &mut p,
        &g,
        key_create(&g, &k2.tmb, T),
        Some(honest(&k2)),
        T + 1,
    )
    .expect("create");
    commit_one(&mut p, &g, key_delete(&g, &k2.tmb, T + 2), None, T + 3).expect("delete");
    commit_one(
        &mut p,
        &g,
        key_create(&g, &k2.tmb, T + 4),
        Some(honest(&k2)),
        T + 5,
    )
    .expect("re-add of a deleted key is permitted by SPEC 6.2");
    assert!(p.is_key_active(&k2.tmb));
}

// ============================================================================
// D4 -- pay.alg == key.alg; czd recomputed, not trusted
// ============================================================================

/// Backs: an Ed25519-signed action claiming `"alg":"ES256"` is rejected
/// and not recorded. Red now because `verify_and_record_action` verifies
/// with the key's alg and never compares it to `pay.alg`.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_action_pay_alg_must_equal_key_alg() {
    let g = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let (pay, sig, czd) = action(&g, &g.tmb, T, "ES256");

    let before = snapshot(&p);
    let r = p.verify_and_record_action(&pay, &sig, czd);
    assert!(
        r.is_err(),
        "action with pay.alg=ES256 on an Ed25519 key accepted"
    );
    assert_eq!(before, snapshot(&p), "a rejected action changed state");
    assert_eq!(p.action_count(), 0, "mismatched-alg action was recorded");
}

/// Backs: same `pay.alg == key.alg` rule on the commit path. Red now
/// because `verify_and_apply` accepts an Ed25519-signed `key/create`
/// whose pay claims `"alg":"ES256"`.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_commit_coz_pay_alg_must_equal_key_alg() {
    let g = kp();
    let k2 = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let parts = sign(
        &g,
        json!({"alg": "ES256", "id": b64(&k2.tmb), "now": T, "tmb": b64(&g.tmb),
               "typ": "cyphr.me/cyphr/key/create"}),
    );

    let r = commit_one(&mut p, &g, parts, Some(honest(&k2)), T + 1);
    assert!(
        r.is_err(),
        "key/create with pay.alg=ES256 signed by an Ed25519 key accepted"
    );
}

/// Backs: a wrong caller-supplied czd is never recorded. The recorded czd
/// must be the one recomputed from the signed bytes, or the call must
/// fail. Red now because the bogus czd is stored verbatim as the action's
/// identity.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_wrong_caller_czd_is_not_recorded_for_actions() {
    let g = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let (pay, sig, true_czd) = action(&g, &g.tmb, T, "Ed25519");
    let bogus = coz::Czd::from_bytes(vec![7u8; CZD_LEN]);
    assert_ne!(bogus.as_bytes(), true_czd.as_bytes(), "premise");

    let _ = p.verify_and_record_action(&pay, &sig, bogus.clone());

    for a in p.actions() {
        assert_ne!(
            a.czd().as_bytes(),
            bogus.as_bytes(),
            "caller-supplied czd was recorded verbatim"
        );
    }
}

/// Backs: a wrong caller czd on the commit path is never recorded in the
/// committed coz. Red now because `verify_and_apply` stores the caller's
/// czd.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_wrong_caller_czd_is_not_recorded_for_commit_cozies() {
    let g = kp();
    let k2 = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let (pay, sig, true_czd) = key_create(&g, &k2.tmb, T);
    let bogus = coz::Czd::from_bytes(vec![7u8; CZD_LEN]);
    assert_ne!(bogus.as_bytes(), true_czd.as_bytes(), "premise");

    let r = commit_one(
        &mut p,
        &g,
        (pay, sig, bogus.clone()),
        Some(honest(&k2)),
        T + 1,
    );
    if r.is_ok() {
        assert!(
            p.iter_all_cozies().count() > 0,
            "premise: a finalized commit holds cozies"
        );
    }

    for v in p.iter_all_cozies() {
        assert_ne!(
            v.coz().czd().as_bytes(),
            bogus.as_bytes(),
            "caller-supplied czd was recorded verbatim in a committed coz"
        );
    }
}

// ============================================================================
// Corpus vector (D3): tests/golden/key_auth/revoked_key_readd_fails.json
// ============================================================================

/// Replays the language-agnostic corpus vector `revoked_key_readd_fails`
/// (generated from `tests/intents/key_auth.toml`): a principal with a
/// pre-revoked key, then `key/create` of that key, which must fail with
/// the vector's `expected.error`.
///
/// Red now because the re-add is accepted. This test exists because
/// `golden_fixtures.rs` has no `key_auth` directory runner yet; once one
/// is added there this replay is redundant and may be cut.
#[test]
#[ignore = "RED(KA1): D3 revoked key re-addable"]
fn d3_corpus_vector_revoked_key_readd_fails() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("tests/golden/key_auth/revoked_key_readd_fails.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let fx: serde_json::Value = serde_json::from_str(&text).expect("fixture json");
    let d = |s: &str| Base64UrlUnpadded::decode_vec(s).expect("base64url");
    let key_of_json = |k: &serde_json::Value| Key {
        alg: k["alg"].as_str().expect("alg").to_string(),
        tmb: coz::Thumbprint::from_bytes(d(k["tmb"].as_str().expect("tmb"))),
        pub_key: d(k["pub"].as_str().expect("pub")),
        first_seen: 0,
        last_used: None,
        revocation: None,
        tag: None,
    };

    let genesis: Vec<Key> = fx["genesis_keys"]
        .as_array()
        .expect("genesis_keys")
        .iter()
        .map(key_of_json)
        .collect();
    let mut p = Principal::explicit(genesis.clone()).expect("explicit genesis");

    let names = fx["principal"].as_array().expect("principal");
    let revoke_name = fx["setup"]["revoke_key"].as_str().expect("revoke_key");
    let idx = names
        .iter()
        .position(|n| n == revoke_name)
        .expect("revoke_key in principal");
    p.pre_revoke_key(
        &genesis[idx].tmb,
        fx["setup"]["revoke_at"].as_i64().expect("revoke_at"),
    )
    .expect("pre-revoke");
    assert!(p.is_key_revoked(&genesis[idx].tmb), "premise: key revoked");

    let commit = &fx["commits"][0];
    let tx = &commit["txs"][0];
    let pay = serde_json::to_vec(&tx["pay"]).expect("pay");
    let sig = d(tx["sig"].as_str().expect("sig"));
    let czd = coz::Czd::from_bytes(d(fx["digests"][0].as_str().expect("digest")));
    let sidecar = key_of_json(&commit["keys"][0]);

    let mut scope = p.begin_commit();
    let r = scope.verify_and_apply(&pay, &sig, czd, Some(sidecar));
    let expected = fx["expected"]["error"].as_str().expect("expected.error");
    match r {
        Ok(()) => panic!("vector expects {expected}, but key/create of a revoked key was accepted"),
        Err(e) => assert_eq!(format!("{e:?}"), expected, "wrong rejection reason"),
    }
}

// ============================================================================
// D4 over ES256 (the pool's `golden` key)
// ============================================================================

/// Control: an ES256 action whose `pay.alg` matches its key is accepted, so
/// the ES256 rejections below cannot be an artifact of the setup.
#[test]
fn d4_control_es256_matching_alg_action_accepted() {
    let g = golden_es256();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let (pay, sig, czd) = action(&g, &g.tmb, T, "ES256");
    p.verify_and_record_action(&pay, &sig, czd)
        .expect("ES256 action with matching pay.alg");
    assert_eq!(p.action_count(), 1);
}

/// Backs: an ES256-signed action claiming `"alg":"Ed25519"` is rejected and
/// not recorded. Red now because `pay.alg` is never compared to the key's
/// alg.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_es256_action_pay_alg_must_equal_key_alg() {
    let g = golden_es256();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let (pay, sig, czd) = action(&g, &g.tmb, T, "Ed25519");
    let before = snapshot(&p);

    let r = p.verify_and_record_action(&pay, &sig, czd);
    assert!(
        r.is_err(),
        "action with pay.alg=Ed25519 on an ES256 key accepted"
    );
    assert_eq!(before, snapshot(&p), "a rejected action changed state");
}

/// Backs: same rule on the commit path for an ES256 signer. Red now because
/// `verify_and_apply` ignores `pay.alg`.
#[test]
#[ignore = "RED(KA1): D4 pay.alg/czd trusted"]
fn d4_es256_commit_coz_pay_alg_must_equal_key_alg() {
    let g = golden_es256();
    let k2 = kp();
    let mut p = Principal::implicit(honest(&g)).expect("genesis");
    let before = snapshot(&p);
    let parts = sign(
        &g,
        json!({"alg": "Ed25519", "id": b64(&k2.tmb), "now": T, "tmb": b64(&g.tmb),
               "typ": "cyphr.me/cyphr/key/create"}),
    );

    let r = commit_one(&mut p, &g, parts, Some(honest(&k2)), T + 1);
    assert!(
        r.is_err(),
        "key/create with pay.alg=Ed25519 signed by an ES256 key accepted"
    );
    assert_eq!(before, snapshot(&p), "a rejected key/create changed state");
}
