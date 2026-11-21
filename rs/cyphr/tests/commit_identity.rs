//! One signed commit has one identity. The signed `arrow` covers `pre`,
//! the state root and the TMR, not how the cozies are grouped into
//! transactions or what bytes a signature is spelled in (SPEC.md 494-497,
//! 587-590), so a holder that admits a re-bundled or re-spelled form hands
//! the same signed commit a second TR and a second PR.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::{Bundle, WireBundle, replay_bundle};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use proptest::prelude::*;
use serde_json::{Value, json};

const T: i64 = 1_700_000_000;
const AUTHORITY: &str = "cyphr.me";

struct Kp {
    alg: String,
    pubb: Vec<u8>,
    prv: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(alg: coz::Alg) -> Kp {
    let k = alg.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key")
}

fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn nonce(i: usize) -> String {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    format!("SHA-256:{}", b64(&seed))
}

/// A deterministic Ed25519 key for the `i`th created key.
fn side_key(i: usize) -> Kp {
    let alg = coz::Alg::Ed25519;
    let prv = coz::HashAlg::Sha256.hash_bytes(format!("regroup/{i}").as_bytes());
    let pubb = alg.derive_public_key(&prv).expect("derive");
    let tmb = alg.compute_thumbprint(&pubb).expect("thumbprint");
    Kp {
        alg: alg.name().to_string(),
        pubb,
        prv,
        tmb,
    }
}

/// One signed coz: its pay bytes, signature, czd and the key it introduces.
struct Coz {
    pay: Vec<u8>,
    sig: Vec<u8>,
    czd: coz::Czd,
    side: Option<Key>,
}

fn sign(by: &Kp, typ: &str, id: String, now: i64, side: Option<Key>) -> Coz {
    let mut pay = json!({"alg": by.alg, "id": id, "now": now,
        "tmb": b64(by.tmb.as_bytes()), "typ": format!("{AUTHORITY}/cyphr/{typ}")});
    pay.as_object_mut().expect("object").sort_keys();
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    Coz {
        pay,
        sig,
        czd,
        side,
    }
}

/// A mutation coz: `Some(i)` creates side key `i`, `None` is a nonce
/// numbered by its position.
fn mutation(by: &Kp, position: usize, op: Option<usize>, now: i64) -> Coz {
    match op {
        Some(i) => {
            let k = side_key(i);
            sign(
                by,
                "key/create",
                b64(k.tmb.as_bytes()),
                now,
                Some(key_of(&k)),
            )
        },
        None => sign(by, "nonce/create", nonce(position), now, None),
    }
}

/// A holder of the one genesis commit `k` signs.
async fn holder(k: &Kp) -> Principal {
    let mut p = Principal::implicit(key_of(k)).await.expect("open");
    p.commit_genesis(&signer(k), &[], T, AUTHORITY)
        .await
        .expect("genesis");
    p
}

/// The wire form of one honest commit, every mutation its own transaction
/// and the commit transaction last.
async fn honest(base: &Principal, k: &Kp, ops: &[Option<usize>]) -> WireBundle {
    let mut p = base.fork().await.expect("fork");
    let mut scope = p.begin_commit();
    for (n, op) in ops.iter().enumerate() {
        let c = mutation(k, n, *op, T + 10);
        scope
            .verify_and_apply(&c.pay, &c.sig, c.czd, c.side)
            .expect("mutation");
    }
    scope
        .finalize_with_software(&signer(k), T + 11, AUTHORITY)
        .await
        .expect("commit");
    WireBundle::of_commit(p.commit_at(1).expect("commit")).expect("bundle")
}

/// What a holder reports for an admitted commit: its TR and PR.
type Id = (Option<String>, String);

/// Offer `wire` to a fresh holder of the same genesis.
async fn admit(base: &Principal, wire: &WireBundle) -> Result<Id, String> {
    let bundle: Bundle = wire.decode().map_err(|e| e.to_string())?;
    let mut p = base.fork().await.expect("fork");
    replay_bundle(&mut p, &bundle)
        .await
        .map(|id| (id.tr.map(|t| format!("{t:?}")), format!("{:?}", id.pr)))
        .map_err(|e| e.to_string())
}

/// Every contiguous grouping of `cozies` into transactions, the commit
/// transaction appended last.
fn groupings(wire: &WireBundle) -> Vec<WireBundle> {
    let (commit, muts) = wire.txs.split_last().expect("commit transaction");
    let flat: Vec<Vec<u8>> = muts.iter().flatten().cloned().collect();
    (0..1usize << (flat.len() - 1))
        .map(|mask| {
            let mut txs: Vec<Vec<Vec<u8>>> = vec![vec![flat[0].clone()]];
            for (i, coz) in flat.iter().enumerate().skip(1) {
                if mask >> (i - 1) & 1 == 1 {
                    txs.last_mut().expect("tx").push(coz.clone());
                } else {
                    txs.push(vec![coz.clone()]);
                }
            }
            txs.push(commit.clone());
            WireBundle {
                txs,
                ..wire.clone()
            }
        })
        .collect()
}

fn op_strategy() -> impl Strategy<Value = Vec<Option<usize>>> {
    // Mixed `typ`s: a side key is `Some(distinct index)`, a nonce `None`.
    prop::collection::vec(prop::option::of(0usize..1), 1..6).prop_map(|ops| {
        let mut next = 0;
        ops.into_iter()
            .map(|op| {
                op.map(|_| {
                    next += 1;
                    next - 1
                })
            })
            .collect()
    })
}

// Catches: a holder that admits a regrouping of one signed commit under a second TR/PR
// (one arrow, two commit ids), which lets any observer mint a second "rival" for an honest commit.
#[tokio::test]
async fn regrouped_commit_is_refused_or_has_the_same_id() {
    let k = kp(coz::Alg::Ed25519);
    let base = holder(&k).await;
    let wire = honest(&base, &k, &[None, None]).await;
    assert_eq!(wire.txs.len(), 3, "two nonce transactions and the commit");
    let original = admit(&base, &wire)
        .await
        .expect("the honest commit is admitted");

    let mut regrouped = wire.clone();
    let second = regrouped.txs.remove(1);
    regrouped.txs[0].extend(second); // [[n1, n2], [commit]]
    match admit(&base, &regrouped).await {
        Err(_) => {},
        Ok(id) => assert_eq!(
            id, original,
            "regrouped bundle admitted under a different commit id (TR, PR)"
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    // Catches: any second grouping of one signed arrow's mutations that a holder admits
    // (the lone multi-coz transaction is the known one; this also hunts for others).
    #[test]
    fn one_signed_arrow_admits_exactly_one_grouping(ops in op_strategy()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let k = kp(coz::Alg::Ed25519);
            let base = holder(&k).await;
            let wire = honest(&base, &k, &ops).await;
            let mut admitted = 0;
            for g in groupings(&wire) {
                if admit(&base, &g).await.is_ok() {
                    admitted += 1;
                }
            }
            prop_assert_eq!(
                admitted, 1,
                "{} mutations: {} groupings admitted under one arrow", ops.len(), admitted
            );
            Ok(())
        })?;
    }
}

// Catches: a builder that lets a lone multi-coz mutation transaction finalize,
// minting the commit form whose regrouping shares its TMR.
#[tokio::test]
async fn builder_refuses_a_lone_grouped_mutation_transaction() {
    let k = kp(coz::Alg::Ed25519);
    let base = holder(&k).await;
    let cozies = || {
        (0..2)
            .map(|n| mutation(&k, n, None, T + 10))
            .collect::<Vec<_>>()
    };

    let mut grouped = base.fork().await.expect("fork");
    let mut scope = grouped.begin_commit();
    let verified: Vec<_> = cozies()
        .into_iter()
        .map(|c| scope.verify(&c.pay, &c.sig, c.czd, c.side).expect("verify"))
        .collect();
    scope.apply_tx(verified).expect("one transaction of two");
    let refused = scope
        .finalize_with_software(&signer(&k), T + 11, AUTHORITY)
        .await;
    assert!(
        refused.is_err(),
        "a lone two-coz mutation transaction finalized"
    );

    let mut split = base.fork().await.expect("fork");
    let mut scope = split.begin_commit();
    for c in cozies() {
        scope
            .verify_and_apply(&c.pay, &c.sig, c.czd, c.side)
            .expect("nonce");
    }
    scope
        .finalize_with_software(&signer(&k), T + 11, AUTHORITY)
        .await
        .expect("the same cozies as two transactions finalize");
}

// Catches: a commit transaction that carries a coz besides the `commit/create`
// (its TX is outside the arrow, so the extra coz would give the commit a second TR).
#[tokio::test]
async fn commit_transaction_holds_only_the_commit_create() {
    let k = kp(coz::Alg::Ed25519);
    let base = holder(&k).await;
    let wire = honest(&base, &k, &[None, None]).await;
    admit(&base, &wire).await.expect("the honest commit");

    let extra = sign(&k, "nonce/create", nonce(99), T + 10, None);
    let blob = serde_json::to_vec(&json!({"pay": serde_json::from_slice::<Value>(&extra.pay)
        .expect("pay"), "sig": b64(&extra.sig)}))
    .expect("coz");
    let mut stuffed = wire.clone();
    stuffed.txs.last_mut().expect("commit tx").insert(0, blob);
    assert_eq!(stuffed.txs.last().expect("tx").len(), 2);
    assert!(
        admit(&base, &stuffed).await.is_err(),
        "a commit transaction holding a second coz was admitted"
    );
}

/// The group orders of P-256 and P-384, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
const P384_N: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];
/// The Ed25519 group order, little-endian.
const ED_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// `n - s` over big-endian bytes.
fn negate_s(n: &[u8], s: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; n.len()];
    let mut borrow = 0i16;
    for i in (0..n.len()).rev() {
        let d = i16::from(n[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        out[i] = (d + 256) as u8;
    }
    out
}

/// `s + L` over little-endian bytes (`s < L < 2^253`, so it fits).
fn add_l(s: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let d = u16::from(s[i]) + u16::from(ED_L[i]) + carry;
        out[i] = d as u8;
        carry = d >> 8;
    }
    out
}

/// Another spelling of the same valid signature: ECDSA (r, s) as
/// (r, n - s); Ed25519 (R, S) as (R, S + L).
fn respell(alg: &str, sig: &[u8]) -> Vec<u8> {
    let (head, tail) = sig.split_at(sig.len() / 2);
    let other = match alg {
        "ES256" | "ES384" => {
            let n: &[u8] = if alg == "ES256" { &P256_N } else { &P384_N };
            let negated = negate_s(n, tail);
            // The probe is only a probe if the flip is a sound involution below n.
            assert_eq!(negate_s(n, &negated), tail, "n - (n - s) = s");
            assert!(negated.as_slice() < n, "n - s < n");
            negated
        },
        "Ed25519" => {
            let lifted = add_l(tail);
            assert_ne!(lifted, tail);
            assert_eq!(
                &lifted[31] & 0xe0,
                0,
                "S + L < 2^253: still a canonical-width scalar"
            );
            lifted
        },
        other => panic!("no re-spelling for {other}"),
    };
    [head, &other].concat()
}

/// The coz at `(tx, i)` with its signature re-spelled.
fn malleate(alg: &str, wire: &WireBundle, tx: usize, i: usize) -> WireBundle {
    let mut coz: Value = serde_json::from_slice(&wire.txs[tx][i]).expect("coz json");
    let sig = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().expect("sig")).expect("b64");
    coz["sig"] = Value::String(b64(&respell(alg, &sig)));
    let mut out = wire.clone();
    out.txs[tx][i] = serde_json::to_vec(&coz).expect("coz");
    out
}

// Catches: a holder that admits a re-spelled signature (ECDSA high-S, Ed25519 S + L) under a
// different commit id (czd covers the signature bytes; nothing the arrow covers fixes them).
// Observed result: see the report that accompanies this test.
#[tokio::test]
async fn malleated_signature_is_refused_or_has_the_same_id() {
    for alg in [coz::Alg::ES256, coz::Alg::ES384, coz::Alg::Ed25519] {
        let k = kp(alg);
        let base = holder(&k).await;
        let wire = honest(&base, &k, &[None, None]).await;
        let original = admit(&base, &wire).await.expect("the honest commit");

        let mut admitted_other = Vec::new();
        for (tx, cozies) in wire.txs.iter().enumerate() {
            for i in 0..cozies.len() {
                match admit(&base, &malleate(&k.alg, &wire, tx, i)).await {
                    Err(_) => {},
                    Ok(id) if id == original => {},
                    Ok(id) => admitted_other.push(((tx, i), id)),
                }
            }
        }
        assert!(
            admitted_other.is_empty(),
            "{}: a re-spelled signature was admitted under another commit id: {admitted_other:?}",
            k.alg
        );
    }
}

// Catches: a genesis commit admitted under two groupings of its mutation cozies
// (key/create, principal/create), the same one-arrow-two-ids defect at genesis.
#[tokio::test]
async fn one_signed_genesis_admits_exactly_one_grouping() {
    for extra in 0..=3 {
        let k = kp(coz::Alg::Ed25519);
        let others: Vec<Key> = (0..extra).map(|i| key_of(&side_key(i))).collect();
        let mut p = Principal::implicit(key_of(&k)).await.expect("open");
        p.commit_genesis(&signer(&k), &others, T, AUTHORITY)
            .await
            .expect("genesis");
        let wire = WireBundle::of_commit(p.commit_at(0).expect("genesis commit")).expect("bundle");
        let mut admitted = 0;
        for g in groupings(&wire) {
            let mut fresh = Principal::implicit(key_of(&k)).await.expect("open");
            if replay_bundle(&mut fresh, &g.decode().expect("decodes"))
                .await
                .is_ok()
            {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 1,
            "{extra} extra keys: {admitted} groupings admitted"
        );
    }
}
