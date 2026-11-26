//! Generated principals for the portable-inclusion tests: one to three
//! keys of mixed algorithms, nonces at each of the three levels, with and
//! without data, one or more commits. Everything is built through the
//! public commit API, so every root is the principal's own.
#![allow(dead_code)]

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::sha2::{Digest, Sha256};
use cyphr::signer::SoftwareSigner;
use cyphr::{Key, Principal};
use proptest::prelude::*;
use serde_json::json;

pub const T: i64 = 1_700_000_000;
pub const AUTHORITY: &str = "cyphr.me";

pub struct Kp {
    pub alg: String,
    pub pubb: Vec<u8>,
    pub prv: Vec<u8>,
    pub tmb: coz::Thumbprint,
}

pub fn kp(alg: coz::Alg) -> Kp {
    let k = alg.generate_keypair();
    let tmb = k.alg.compute_thumbprint(&k.pub_bytes).expect("thumbprint");
    Kp {
        alg: k.alg.name().to_string(),
        pubb: k.pub_bytes,
        prv: k.prv_bytes,
        tmb,
    }
}

pub fn key_of(k: &Kp) -> Key {
    Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

pub fn signer(k: &Kp) -> SoftwareSigner {
    SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

pub fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

fn signed(by: &Kp, mut pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    (v, sig, czd)
}

/// Which tree a nonce is planted in (SPEC 10.1).
#[derive(Clone, Copy, Debug)]
pub enum Level {
    Pr,
    At,
    Kt,
}

impl Level {
    fn typ(self) -> String {
        let path = match self {
            Self::Pr => "cyphr/nonce/create",
            Self::At => "cyphr/AT/nonce/create",
            Self::Kt => "cyphr/AT/KT/nonce/create",
        };
        format!("{AUTHORITY}/{path}")
    }
}

/// A distinct 32-byte nonce per (seed, level, index): high-entropy, and
/// never equal to a thumbprint.
pub fn nonce_bytes(seed: u8, level: Level, i: u8) -> Vec<u8> {
    Sha256::digest([seed, level as u8, i, 0x5a]).to_vec()
}

pub async fn commit_key(p: &mut Principal, by: &Kp, id: &Kp, now: i64) {
    let (v, sig, czd) = signed(
        by,
        json!({"alg": by.alg, "id": b64(id.tmb.as_bytes()), "now": now,
               "tmb": b64(by.tmb.as_bytes()), "typ": format!("{AUTHORITY}/cyphr/key/create")}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, Some(key_of(id)))
        .expect("key/create");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

pub async fn commit_nonce(p: &mut Principal, by: &Kp, level: Level, nonce: &[u8], now: i64) {
    let id = format!("SHA-256:{}", b64(nonce));
    let (v, sig, czd) = signed(
        by,
        json!({"alg": by.alg, "id": id, "now": now, "tmb": b64(by.tmb.as_bytes()),
               "typ": level.typ()}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&v, &sig, czd, None)
        .expect("nonce/create");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// A data action by `by`, then a `ds/create` commit over it.
pub async fn commit_data(p: &mut Principal, by: &Kp, now: i64) {
    let tmb = b64(by.tmb.as_bytes());
    let mut pay = json!({"msg": "hello", "now": now, "tmb": tmb, "alg": by.alg,
                         "typ": format!("{AUTHORITY}/comment/create")});
    pay.as_object_mut().expect("pay object").sort_keys();
    let v = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&v, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    p.verify_and_record_action(&v, &sig, czd).expect("record");

    let mut scope = p.begin_commit();
    let dr = scope.data_tree_id().expect("dr").expect("a data action");
    let (v, sig, czd) = signed(
        by,
        json!({"id": dr, "now": now + 1, "tmb": tmb, "alg": by.alg,
               "typ": format!("{AUTHORITY}/{}", cyphr::parsed_coz::typ::DS_CREATE)}),
    );
    scope
        .verify_and_apply(&v, &sig, czd, None)
        .expect("ds/create");
    scope
        .finalize_with_software(&signer(by), now + 1, AUTHORITY)
        .await
        .expect("commit");
}

/// The shape of a generated principal.
#[derive(Clone, Debug)]
pub struct Spec {
    /// One entry per key: 0 Ed25519 (SHA-512), 1 ES256 (SHA-256), 2 ES384
    /// (SHA-384). The first is the genesis key.
    pub algs: Vec<u8>,
    /// Nonces at the key-tree, auth-tree and principal-root levels.
    pub kt: u8,
    pub at: u8,
    pub pr: u8,
    pub data: bool,
    /// A seed for nonce values.
    pub seed: u8,
}

pub fn spec() -> impl Strategy<Value = Spec> {
    (
        prop::collection::vec(0u8..3, 1..4),
        0u8..3,
        0u8..3,
        0u8..3,
        any::<bool>(),
        any::<u8>(),
    )
        .prop_map(|(algs, kt, at, pr, data, seed)| Spec {
            algs,
            kt,
            at,
            pr,
            data,
            seed,
        })
}

fn alg_of(i: u8) -> coz::Alg {
    match i {
        0 => coz::Alg::Ed25519,
        1 => coz::Alg::ES256,
        _ => coz::Alg::ES384,
    }
}

pub struct World {
    pub p: Principal,
    pub keys: Vec<Kp>,
}

/// Genesis, then each further key, each nonce, and the data commit: at
/// least one commit, one per step.
pub async fn world(spec: &Spec) -> World {
    let keys: Vec<Kp> = spec.algs.iter().map(|&a| kp(alg_of(a))).collect();
    let owner = &keys[0];
    let mut p = Principal::implicit(key_of(owner)).await.expect("open");
    p.commit_genesis(&signer(owner), &[], T, AUTHORITY)
        .await
        .expect("genesis commit");
    let mut now = T;
    let mut tick = || {
        now += 10;
        now
    };
    for k in &keys[1..] {
        commit_key(&mut p, owner, k, tick()).await;
    }
    for (level, n) in [(Level::Kt, spec.kt), (Level::At, spec.at), (Level::Pr, spec.pr)] {
        for i in 0..n {
            commit_nonce(&mut p, owner, level, &nonce_bytes(spec.seed, level, i), tick()).await;
        }
    }
    if spec.data {
        commit_data(&mut p, owner, tick()).await;
    }
    World { p, keys }
}

/// Runs a future on a fresh single-thread runtime, for use inside
/// `proptest!`.
pub fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}
