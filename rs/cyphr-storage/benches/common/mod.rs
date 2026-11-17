//! Shared by the U3 scaling benches (`u3_engine` here, `u3_server` in
//! cyphr-server, which includes this file by path): a principal of any
//! history length, a junk-bundle maker, and the counting table.
#![allow(dead_code)]

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;

pub const NOW: i64 = 1_700_300_000;

pub struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    pub tmb: coz::Thumbprint,
}

pub fn kp(name: &str) -> Kp {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/keys/pool.toml");
    let pool = test_fixtures::Pool::load(&path).expect("pool.toml");
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        prv: pk
            .prv
            .as_ref()
            .map(|p| Base64UrlUnpadded::decode_vec(p).expect("prv b64"))
            .unwrap_or_default(),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// A principal whose `signer` key opens it with `added` and then toggles
/// `toggled` in and out, one commit each: unbounded history from a finite
/// key pool. Commit `i` is dated `NOW + 10 i`.
pub struct Chain {
    pub id: String,
    pub genesis: Genesis,
    shadow: cyphr::Principal,
    signer: Kp,
    toggled: Kp,
    active: bool,
    pub commits: usize,
}

impl Chain {
    pub async fn new(signer: &str, added: &str, toggled: &str) -> Self {
        let (signer, added, toggled) = (kp(signer), kp(added), kp(toggled));
        let mut shadow = cyphr::Principal::implicit(key_of(&signer))
            .await
            .expect("implicit");
        shadow
            .commit_genesis(&signer_of(&signer), &[key_of(&added)], NOW, "cyphr.me")
            .await
            .expect("genesis commit");
        let id = test_fixtures::bundle::genesis_id(&bundle_at(&shadow, 0)).expect("id");
        Self {
            id,
            genesis: Genesis::Disclosed(vec![key_of(&signer), key_of(&added)]),
            shadow,
            signer,
            toggled,
            active: false,
            commits: 1,
        }
    }

    pub fn first(&self) -> WireBundle {
        bundle_at(&self.shadow, 0)
    }

    /// The next commit, applied to the shadow chain: a create of `toggled`
    /// when it is out, a delete when it is in.
    pub async fn next(&mut self) -> WireBundle {
        let now = NOW + 10 * self.commits as i64;
        let (typ, side) = if self.active {
            ("key/delete", None)
        } else {
            ("key/create", Some(key_of(&self.toggled)))
        };
        let mut pay = serde_json::json!({
            "alg": self.signer.alg, "now": now, "tmb": self.signer.tmb.to_b64(),
            "typ": format!("cyphr.me/cyphr/{typ}"), "id": self.toggled.tmb.to_b64(),
        });
        pay.as_object_mut().expect("object").sort_keys();
        let pay = serde_json::to_vec(&pay).expect("pay");
        let s = &self.signer;
        let (sig, cad) = coz::sign_json(&pay, &s.alg, &s.prv, &s.pubb).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, &s.alg).expect("czd");
        let mut scope = self.shadow.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, side)
            .expect("toggle applies");
        scope
            .finalize_with_software(&signer_of(s), now, "cyphr.me")
            .await
            .expect("toggle finalizes");
        self.active = !self.active;
        self.commits += 1;
        bundle_at(&self.shadow, self.commits - 1)
    }
}

fn bundle_at(p: &cyphr::Principal, i: usize) -> WireBundle {
    WireBundle::of_commit(p.commits().nth(i).expect("commit")).expect("bundle")
}

/// `bundle` with one signature byte flipped: well-formed, refused on the
/// signature.
pub fn bad_signature(bundle: &WireBundle) -> WireBundle {
    let mut out = bundle.clone();
    let mut coz: serde_json::Value = serde_json::from_slice(&out.txs[0][0]).expect("coz json");
    let sig = coz["sig"].as_str().expect("a sig").to_owned();
    let first = if sig.starts_with('A') { 'B' } else { 'A' };
    coz["sig"] = format!("{first}{}", &sig[1..]).into();
    out.txs[0][0] = serde_json::to_vec(&coz).expect("coz");
    out
}

/// The sample median, for a timing that must not be one outlier.
pub fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    xs[xs.len() / 2]
}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use cyphr::state::TaggedDigest;
use cyphr_blob_fjall::{EmlLogs, FjallBlobStore};
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::blob::{Blake3Hash, BlobStore, BlobStoreError};
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::*;

// Counting wrappers over the real fjall stores, and the engine on them.
#[derive(Default)]
pub struct Ctr {
    pub blob_gets: AtomicU64,
    pub blob_bytes: AtomicU64,
    pub idx_calls: AtomicU64,
    pub idx_rows: AtomicU64,
}

#[derive(Clone)]
pub struct CBlob(Arc<FjallBlobStore>, Arc<Ctr>);

impl BlobStore for CBlob {
    async fn put(&self, data: &[u8]) -> Result<Blake3Hash, BlobStoreError> {
        self.0.put(data).await
    }
    async fn get(&self, h: &Blake3Hash) -> Result<Option<Vec<u8>>, BlobStoreError> {
        let got = self.0.get(h).await?;
        self.1.blob_gets.fetch_add(1, Relaxed);
        self.1
            .blob_bytes
            .fetch_add(got.as_ref().map_or(0, |b| b.len() as u64), Relaxed);
        Ok(got)
    }
    async fn exists(&self, h: &Blake3Hash) -> Result<bool, BlobStoreError> {
        self.0.exists(h).await
    }
    async fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>, BlobStoreError>
    {
        self.0.iter().await
    }
}

#[derive(Clone)]
pub struct CIdx(Arc<FjallIndexer>, Arc<Ctr>);

impl CIdx {
    fn read(&self, rows: usize) {
        self.1.idx_calls.fetch_add(1, Relaxed);
        self.1.idx_rows.fetch_add(rows as u64, Relaxed);
    }
}

impl Indexer for CIdx {
    async fn get_tip(&self, p: &str) -> Result<Option<TipState>, IndexerError> {
        let r = self.0.get_tip(p).await?;
        self.read(usize::from(r.is_some()));
        Ok(r)
    }
    async fn is_pg_established(&self, p: &str) -> Result<bool, IndexerError> {
        self.read(1);
        self.0.is_pg_established(p).await
    }
    async fn get_commit_chain(
        &self,
        p: &str,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<Vec<CommitRef>, IndexerError> {
        let r = self.0.get_commit_chain(p, from, to).await?;
        self.read(r.len());
        Ok(r)
    }
    async fn resolve_digest(&self, d: &TaggedDigest) -> Result<Option<EntityRef>, IndexerError> {
        let r = self.0.resolve_digest(d).await?;
        self.read(usize::from(r.is_some()));
        Ok(r)
    }
    async fn resolve_digest_holders(
        &self,
        d: &TaggedDigest,
    ) -> Result<Vec<EntityRef>, IndexerError> {
        let r = self.0.resolve_digest_holders(d).await?;
        self.read(r.len());
        Ok(r)
    }
    async fn list_principals(&self) -> Result<Vec<PrincipalSummary>, IndexerError> {
        let r = self.0.list_principals().await?;
        self.read(r.len());
        Ok(r)
    }
    async fn is_blob_indexed(&self, h: &Blake3Hash) -> Result<bool, IndexerError> {
        self.read(1);
        self.0.is_blob_indexed(h).await
    }
    async fn get_key(&self, t: &str) -> Result<Option<PublicKeyInfo>, IndexerError> {
        let r = self.0.get_key(t).await?;
        self.read(usize::from(r.is_some()));
        Ok(r)
    }
}

impl IndexerWrite for CIdx {
    async fn check_commit(&self, c: &IndexableCommit, t: &DeriveToken) -> Result<(), IndexerError> {
        self.0.check_commit(c, t).await
    }
    async fn index_commit(&self, c: &IndexableCommit, t: &DeriveToken) -> Result<(), IndexerError> {
        self.0.index_commit(c, t).await
    }
    async fn replace_chain_from(
        &self,
        p: &str,
        s: u64,
        c: &[IndexableCommit],
        t: &DeriveToken,
    ) -> Result<(), IndexerError> {
        self.0.replace_chain_from(p, s, c, t).await
    }
    async fn clear(&self, t: &DeriveToken) -> Result<(), IndexerError> {
        self.0.clear(t).await
    }
    async fn set_quarantined(
        &self,
        m: &[(Blake3Hash, String)],
        t: &DeriveToken,
    ) -> Result<(), IndexerError> {
        self.0.set_quarantined(m, t).await
    }
    async fn quarantined(&self) -> Result<Vec<(Blake3Hash, String)>, IndexerError> {
        self.0.quarantined().await
    }
}

pub type Engine = StorageEngine<CBlob, CIdx, cyphr_blob_fjall::storage_fjall::FjallStorage>;

/// The stores one data directory holds, reopenable as a fresh engine (a
/// restart: nothing kept, everything durable).
pub struct Disk {
    _dir: tempfile::TempDir,
    db: fjall::Database,
    blobs: Arc<FjallBlobStore>,
    index: Arc<FjallIndexer>,
    pub ctr: Arc<Ctr>,
}

impl Disk {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = fjall::Database::builder(dir.path().join("db"))
            .open()
            .expect("db");
        Self {
            blobs: Arc::new(FjallBlobStore::from_database(db.clone()).expect("blobs")),
            index: Arc::new(FjallIndexer::open(&dir.path().join("idx")).expect("index")),
            db,
            ctr: Arc::default(),
            _dir: dir,
        }
    }

    pub fn engine(&self) -> Engine {
        StorageEngine::with_log_factory(
            CBlob(self.blobs.clone(), self.ctr.clone()),
            CIdx(self.index.clone(), self.ctr.clone()),
            EmlLogs::new(self.db.clone()).expect("logs"),
        )
    }
}

