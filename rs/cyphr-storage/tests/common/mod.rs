//! The shared storage-engine rig for the fork-rule tests: a principal with
//! one genesis key and a canonical chain, lines of rival commits over any
//! state of it, and engines fed from them. Integration tests are separate
//! crates, so each pulls this in with `mod common;`; each uses a subset,
//! so `dead_code` is allowed once here.
#![allow(dead_code)]

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::{Consensus, EngineError, StorageEngine};
use cyphr_storage::index::MemoryIndexer;

pub const NOW: i64 = 1_700_500_000;

pub type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

pub struct Kp {
    pub alg: String,
    pub prv: Vec<u8>,
    pub pubb: Vec<u8>,
    pub tmb: coz::Thumbprint,
}

pub fn golden() -> Kp {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool.toml");
    let pk = pool.get("golden").expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("prv")).expect("prv b64"),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

/// A signing key that is not in the pool.
pub fn fresh_kp() -> Kp {
    let g = coz::Alg::Ed25519.generate_keypair();
    let tmb = g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb");
    Kp {
        alg: g.alg.name().to_owned(),
        prv: g.prv_bytes.clone(),
        pubb: g.pub_bytes.clone(),
        tmb,
    }
}

pub fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

pub fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// `signer` creates `new` at `now` and finalizes the commit itself.
pub async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
    let pay = serde_json::json!({
        "alg": signer.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"
    });
    let pay = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &signer.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .expect("finalize");
}

pub fn last(p: &cyphr::Principal) -> WireBundle {
    WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
}

pub fn commit_id(p: &cyphr::Principal) -> String {
    p.commits()
        .last()
        .expect("commit")
        .tr()
        .0
        .tagged_first()
        .expect("commit id")
        .to_string()
}

/// A principal with one genesis key (`golden`) and a canonical chain of
/// `len` commits: commit `i` (`i >= 1`) creates `keys[i - 1]`, so every
/// key is active from the state after its commit. `states[i]` is the
/// principal after commit `i`.
pub struct Rig {
    pub id: String,
    pub genesis: Genesis,
    pub golden: Kp,
    pub keys: Vec<Kp>,
    pub states: Vec<cyphr::Principal>,
}

impl Rig {
    pub async fn new(len: usize) -> Rig {
        let golden = golden();
        let genesis = Genesis::Implicit(key_of(&golden));
        let id = cyphr_storage::engine::genesis_principal_id(&genesis).expect("id");
        let mut cur = cyphr::Principal::implicit(key_of(&golden))
            .await
            .expect("genesis");
        cur.commit_genesis(&signer_of(&golden), &[], NOW, "cyphr.me")
            .await
            .expect("genesis commit");
        let mut states = vec![cur.fork().await.expect("fork")];
        let mut keys = Vec::new();
        for i in 1..len {
            let k = fresh_kp();
            create_key(&mut cur, &golden, &k, NOW + i as i64).await;
            keys.push(k);
            states.push(cur.fork().await.expect("fork"));
        }
        Rig {
            id,
            genesis,
            golden,
            keys,
            states,
        }
    }

    /// `n` commits by `signer` over `p`, each extending the last; the
    /// principal after each. `now` makes the line distinct.
    pub async fn ext(
        &self,
        p: &cyphr::Principal,
        n: usize,
        now: i64,
        signer: &Kp,
    ) -> Vec<cyphr::Principal> {
        let mut out = Vec::new();
        let mut cur = p.fork().await.expect("fork");
        for i in 0..n {
            create_key(&mut cur, signer, &fresh_kp(), now + i as i64).await;
            out.push(cur.fork().await.expect("fork"));
        }
        out
    }

    /// `n` commits by golden over the state after commit `over`.
    pub async fn line(&self, over: usize, n: usize, now: i64) -> Vec<cyphr::Principal> {
        self.ext(&self.states[over], n, now, &self.golden).await
    }

    pub fn engine(&self) -> Engine {
        StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
    }

    /// An engine holding the canonical chain up to commit `upto`.
    pub async fn fed(&self, upto: usize) -> Engine {
        let e = self.engine();
        for s in &self.states[..=upto] {
            self.submit(&e, &last(s)).await.expect("canonical chain");
        }
        e
    }

    pub async fn submit(&self, e: &Engine, b: &WireBundle) -> Result<(), EngineError> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), b)
            .await
            .map(|_| ())
    }

    pub async fn submit_pair(
        &self,
        e: &Engine,
        parent: &WireBundle,
        bundle: &WireBundle,
    ) -> Result<(), EngineError> {
        e.submit_pair(&self.id, Some(self.genesis.clone()), parent, bundle)
            .await
            .map(|_| ())
    }

    pub async fn holds(&self, e: &Engine, p: &cyphr::Principal) -> bool {
        e.holds_commit(&self.id, &commit_id(p))
            .await
            .expect("holds")
    }

    /// (is Error, fork point (height, pre)).
    pub async fn verdict(&self, e: &Engine) -> (bool, Option<(u64, Option<String>)>) {
        let a = e.assess(&self.id).await.expect("assess");
        (
            a.consensus == Consensus::Error,
            a.fork_point.map(|f| (f.height, f.pre)),
        )
    }
}
