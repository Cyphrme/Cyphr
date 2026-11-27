//! Fixtures shared by the client's integration suites: real chains built
//! with `cyphr`, served as `/patch` bodies by an in-memory carrier.
//!
//! Each integration crate compiles this module independently and uses only
//! the subset it needs, so per-crate `dead_code` is inherent to the pattern
//! (the same arrangement as `cyphr-server/tests/common`).
#![allow(dead_code)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_net::{ChannelBinding, ConnectError, Connector, Request};

pub fn b64(b: u8) -> String {
    Base64UrlUnpadded::encode_string(&[b; 32])
}

/// A signing key with its thumbprint.
pub struct Kp {
    pub kp: coz::KeyPair,
    pub tmb: coz::Thumbprint,
}

pub fn kp() -> Kp {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("ed25519 thumbprint");
    Kp { kp, tmb }
}

impl Kp {
    pub fn signer(&self) -> cyphr::signer::SoftwareSigner {
        cyphr::signer::SoftwareSigner::new(
            self.kp.alg.name(),
            &self.kp.prv_bytes,
            &self.kp.pub_bytes,
            &self.tmb,
        )
    }

    pub fn domain_key(&self, first_seen: i64) -> cyphr::Key {
        cyphr::Key::new(
            self.kp.alg.name().to_string(),
            self.tmb.clone(),
            self.kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(first_seen)
    }
}

/// A principal with a single-key genesis on `genesis` (its genesis commit,
/// SPEC 5.1, committed by `new`), grown one `key/create` commit at a time.
/// `commit` returns the commit's wire blobs (base64url of each coz JSON,
/// introduced keys embedded), exactly what `/patch` carries; `patch` serves
/// the genesis commit first, then the given commits.
pub struct Chain<'a> {
    pub genesis: &'a Kp,
    pub principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    /// The wire blobs of the genesis commit, the chain's first entry.
    pub genesis_commit: Vec<String>,
}

impl<'a> Chain<'a> {
    pub async fn new(genesis: &'a Kp) -> Self {
        let mut principal = cyphr::Principal::implicit(genesis.domain_key(1_700_000_000))
            .await
            .expect("implicit genesis");
        principal
            .commit_genesis(&genesis.signer(), &[], 1_700_000_000, "cyphr.me")
            .await
            .expect("genesis commit");
        let genesis_commit = wire_commit(principal.commits().last().expect("genesis commit"));
        Self {
            genesis,
            principal,
            genesis_commit,
        }
    }

    /// The PG: the genesis commit creates only the genesis key, so it is
    /// that key's thumbprint.
    pub fn pg(&self) -> String {
        self.genesis.tmb.to_b64()
    }

    /// A `/patch` body carrying the genesis commit, then `entries`.
    pub fn patch(&self, entries: &[Vec<String>]) -> Vec<u8> {
        let mut all = vec![self.genesis_commit.clone()];
        all.extend_from_slice(entries);
        patch_body(&all)
    }

    pub async fn commit(&mut self, introduce: &Kp, now: i64) -> Vec<String> {
        let g = self.genesis;
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": g.kp.alg.name(),
            "id": introduce.tmb.to_b64(),
            "now": now,
            "tmb": g.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/create",
        }))
        .expect("pay json");
        let (sig, cad) =
            coz::sign_json(&pay, g.kp.alg.name(), &g.kp.prv_bytes, &g.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, g.kp.alg.name()).expect("czd");

        let mut scope = self.principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, Some(introduce.domain_key(now)))
            .expect("key/create applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    g.kp.alg.name(),
                    &g.kp.prv_bytes,
                    &g.kp.pub_bytes,
                    &g.tmb,
                ),
                now,
                "cyphr.me",
            )
            .await
            .expect("commit finalizes");

        wire_commit(self.principal.commits().last().expect("a commit exists"))
    }
}

/// The cozies of `commit` as base64url wire blobs, each introduced key
/// carried on its coz as a `key` member for [`patch_body`] to move into the
/// entry's `keys`.
pub fn wire_commit(commit: &cyphr::Commit) -> Vec<String> {
    commit
        .iter_all_cozies()
        .map(|cz| {
            let mut coz = serde_json::to_value(cz.raw()).expect("coz json");
            if let Some(key) = cz.new_key() {
                coz["key"] = serde_json::json!({
                    "alg": key.alg(),
                    "pub": Base64UrlUnpadded::encode_string(key.pub_key()),
                    "tmb": key.tmb().to_b64(),
                });
            }
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).expect("json"))
        })
        .collect()
}

impl Chain<'_> {
    /// A commit in which `victim` revokes itself (SPEC section 4.2.4), the
    /// commit finalized by the genesis key. Returns the wire blobs.
    pub async fn revoke(&mut self, victim: &Kp, now: i64) -> Vec<String> {
        let g = self.genesis;
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": victim.kp.alg.name(),
            "now": now,
            "rvk": now,
            "tmb": victim.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/revoke",
        }))
        .expect("pay json");
        let (sig, cad) = coz::sign_json(
            &pay,
            victim.kp.alg.name(),
            &victim.kp.prv_bytes,
            &victim.kp.pub_bytes,
        )
        .expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, victim.kp.alg.name()).expect("czd");
        let mut scope = self.principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, None)
            .expect("self-revoke applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    g.kp.alg.name(),
                    &g.kp.prv_bytes,
                    &g.kp.pub_bytes,
                    &g.tmb,
                ),
                now,
                "cyphr.me",
            )
            .await
            .expect("commit finalizes");
        self.principal
            .commits()
            .last()
            .expect("a commit exists")
            .iter_all_cozies()
            .map(|cz| {
                Base64UrlUnpadded::encode_string(&serde_json::to_vec(cz.raw()).expect("coz json"))
            })
            .collect()
    }
}

impl Chain<'_> {
    /// A data action of `typ` signed by the genesis key and recorded on the
    /// local principal; returns its wire blob, to be sent before the commit
    /// it precedes.
    pub fn action(&mut self, typ: &str, now: i64) -> String {
        self.action_by(self.genesis, typ, now)
    }

    /// [`Chain::action`] signed by `g`, a key active in the chain.
    pub fn action_by(&mut self, g: &Kp, typ: &str, now: i64) -> String {
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": g.kp.alg.name(),
            "now": now,
            "tmb": g.tmb.to_b64(),
            "typ": typ,
        }))
        .expect("pay json");
        let (sig, cad) =
            coz::sign_json(&pay, g.kp.alg.name(), &g.kp.prv_bytes, &g.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, g.kp.alg.name()).expect("czd");
        self.principal
            .verify_and_record_action(&pay, &sig, czd)
            .expect("action records");
        let coz: serde_json::Value = serde_json::json!({
            "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
            "sig": Base64UrlUnpadded::encode_string(&sig),
        });
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).expect("json"))
    }
}

/// One entry's base64url cozies as the bundle `/patch` serves (SPEC
/// 4.6.2): its data actions, each transaction coz a transaction of its own,
/// and every `key` member moved to the entry's `keys`. A coz with no
/// parseable `key` member keeps its exact bytes. Actions travel before
/// the transactions, so an action listed after one is a test defect.
pub fn entry_bundle(i: usize, blobs: &[String]) -> serde_json::Value {
    let (mut actions, mut txs, mut keys) =
        (Vec::new(), Vec::new(), Vec::<serde_json::Value>::new());
    for blob in blobs {
        let mut coz: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(blob).expect("b64"))
                .unwrap_or_default();
        let mut wire = blob.clone();
        let key = coz.get("key").cloned();
        if let Some(key) = key.filter(|k| k.get("tmb").is_some() && k.get("pub").is_some()) {
            coz.as_object_mut().expect("coz object").remove("key");
            wire = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&coz).expect("json"));
            if !keys.iter().any(|k| k["tmb"] == key["tmb"]) {
                keys.push(key);
            }
        }
        let is_action = coz["pay"]["typ"]
            .as_str()
            .is_some_and(|t| !cyphr::parsed_coz::typ::is_transaction(t));
        if is_action {
            assert!(
                txs.is_empty(),
                "an entry carries its actions before its transactions"
            );
            actions.push(wire);
        } else {
            txs.push(vec![wire]);
        }
    }
    serde_json::json!({ "sequence": i, "actions": actions, "txs": txs, "keys": keys })
}

/// A `/patch` body carrying `entries` (one blob list per bundle).
pub fn patch_body(entries: &[Vec<String>]) -> Vec<u8> {
    let entries: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(i, blobs)| entry_bundle(i, blobs))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "payload": { "entries": entries },
        "statement": { "kind": "unsigned" },
    }))
    .expect("patch json")
}

/// An in-memory carrier serving whatever body is set, counting exchanges.
pub struct Pipe {
    pub body: Mutex<Vec<u8>>,
    pub exchanges: AtomicUsize,
}

impl Pipe {
    pub fn new(body: Vec<u8>) -> Self {
        Self {
            body: Mutex::new(body),
            exchanges: AtomicUsize::new(0),
        }
    }

    pub fn serve(&self, body: Vec<u8>) {
        *self.body.lock().expect("pipe lock") = body;
    }

    pub fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }
}

impl Connector for Pipe {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, _request: &Request) -> Result<Vec<u8>, ConnectError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.lock().expect("pipe lock").clone())
    }
}

pub fn sign_as(signer: &Kp, pay: serde_json::Value) -> serde_json::Value {
    let bytes = serde_json::to_vec(&pay).expect("pay json");
    let (sig, _) = coz::sign_json(
        &bytes,
        signer.kp.alg.name(),
        &signer.kp.prv_bytes,
        &signer.kp.pub_bytes,
    )
    .expect("sign");
    serde_json::json!({ "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) })
}

/// The principal a tip statement is about (not the peer's own).
pub fn subject() -> (String, coz::Thumbprint) {
    (b64(7), coz::Thumbprint::from_bytes(vec![7; 32]))
}

pub fn digest(b: u8) -> String {
    format!("SHA-256:{}", b64(b))
}

/// A `/tip` envelope signed by `signer`.
pub fn tip_envelope(signer: &Kp) -> serde_json::Value {
    let (pr, _) = subject();
    let pay = serde_json::json!({
        "alg": signer.kp.alg.name(),
        "now": 1_700_000_500,
        "tmb": signer.tmb.to_b64(),
        "typ": "cyphr-server/receipt/tip",
        "pg": pr,
        "sequence": 1,
        "commit_id": digest(9),
        "roots": { "pr": digest(1), "sr": digest(2), "ar": digest(3), "cr": digest(4) },
    });
    serde_json::json!({
        "v": 1,
        "payload": {},
        "statement": { "kind": "signed", "coz": sign_as(signer, pay) },
    })
}
