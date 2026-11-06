//! The PG alias table is a rebuildable cache (AGENTS.md I1).
//!
//! A principal is addressable by every hash variant of its PG (SPEC §12.1).
//! Those aliases live in the index, which `rebuild_index_from_scratch`
//! discards and re-derives from the blob store alone. The property: for
//! random principals, every alias resolves to the principal before the
//! reindex, and to the same principal (tip included) after it.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::StateDigest;
use cyphr_index_fjall::FjallIndexer;
use cyphr_storage::Genesis;
use cyphr_storage::blob::MemoryBlobStore;
use cyphr_storage::engine::StorageEngine;
use cyphr_storage::index::{Indexer, IndexerWrite, MemoryIndexer};
use proptest::prelude::*;

const NOW: i64 = 1_700_100_000;

/// Pool keys that can be added after `golden`, spanning ES256, ES384 and
/// Ed25519 so the PG gains SHA-256, SHA-384 and SHA-512 variants.
const ADDABLE: &[&str] = &["key_a", "alice", "diana_es384", "eve_ed25519"];

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn load_pool() -> test_fixtures::Pool {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rs dir")
        .parent()
        .expect("repo root")
        .join("tests/keys/pool.toml");
    test_fixtures::Pool::load(&path).expect("pool.toml")
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("private key")).expect("prv b64"),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn sign(k: &Kp, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&bytes, &k.alg, &k.prv, &k.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &k.alg).expect("czd");
    (bytes, sig, czd)
}

fn commit_one(
    p: &mut cyphr::Principal,
    signer: &Kp,
    pay: serde_json::Value,
    sidecar: Option<cyphr::Key>,
    now: i64,
) {
    let (pay, sig, czd) = sign(signer, pay);
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, sidecar)
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(
                &signer.alg,
                &signer.prv,
                &signer.pubb,
                &signer.tmb,
            ),
            now,
            "cyphr.me",
        )
        .expect("finalize");
}

/// Raw wire blobs of commit `i` of `p`: key-introducing cozies carry the
/// new key, as the engine's ingest requires, and commit 0's last blob
/// carries the `golden` genesis key (as the server's wire form does), so a
/// stored principal's genesis is recoverable from its first commit's blobs
/// -- a replay of it succeeds rather than failing on an unknown signer.
fn blobs(p: &cyphr::Principal, i: usize) -> Vec<Vec<u8>> {
    let entry = &cyphr_storage::export_commits(p).expect("export")[i];
    let mut key_idx = 0;
    let genesis_key = kp(&load_pool(), "golden");
    let last = entry.cozies.len() - 1;
    entry
        .cozies
        .iter()
        .enumerate()
        .map(|(n, c)| {
            let mut c = c.clone();
            let typ = c["pay"]["typ"].as_str().unwrap_or("").to_string();
            if cyphr::parsed_coz::typ::is_key_introducing(&typ) && key_idx < entry.keys.len() {
                let k = &entry.keys[key_idx];
                c["key"] = serde_json::json!({"alg": k.alg, "pub": k.pub_key, "tmb": k.tmb});
                key_idx += 1;
            }
            if i == 0 && n == last {
                c["key"] = serde_json::json!({
                    "alg": genesis_key.alg,
                    "pub": Base64UrlUnpadded::encode_string(&genesis_key.pubb),
                    "tmb": genesis_key.tmb.to_b64(),
                });
            }
            serde_json::to_vec(&c).expect("blob")
        })
        .collect()
}

/// A principal rooted at `golden` that adds `added` (each in its own
/// commit), then establishes its PG. Returns the principal, the genesis key
/// and the genesis-derived id.
fn build(pool: &test_fixtures::Pool, added: &[&str]) -> (cyphr::Principal, Genesis, String) {
    let g = kp(pool, "golden");
    let genesis = Genesis::Implicit(key_of(&g));
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    let id = p.pr_tagged().expect("genesis id");
    for (n, name) in added.iter().enumerate() {
        let k = kp(pool, name);
        let now = NOW + n as i64;
        commit_one(
            &mut p,
            &g,
            serde_json::json!({"alg": g.alg, "id": k.tmb.to_b64(), "now": now,
                               "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
            Some(key_of(&k)),
            now,
        );
    }
    let pr = p.pr_tagged().expect("pr");
    let now = NOW + added.len() as i64;
    commit_one(
        &mut p,
        &g,
        serde_json::json!({"alg": g.alg, "id": pr, "now": now,
                           "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        None,
        now,
    );
    (p, genesis, id)
}

/// Every PG spelling: each hash-variant label and each bare digest.
fn pg_spellings(p: &cyphr::Principal) -> Vec<String> {
    let mh = p.pg().expect("PG established").as_multihash();
    mh.algorithms()
        .flat_map(|alg| {
            let tagged = mh.tagged(alg).expect("variant").to_string();
            let bare = tagged.split_once(':').expect("tagged").1.to_string();
            [tagged, bare]
        })
        .collect()
}

/// Resolution of every alias, as `(canonical id, commit count)` per
/// spelling; what a reindex must preserve.
async fn resolve_all<B, I>(
    engine: &StorageEngine<B, I>,
    spellings: &[String],
) -> BTreeMap<String, (String, Option<u64>)>
where
    B: cyphr_storage::blob::BlobStore,
    I: Indexer + IndexerWrite,
{
    let mut out = BTreeMap::new();
    for s in spellings {
        let canonical = engine.canonical_principal_id(s).await.expect("resolve");
        let count = engine
            .get_tip(s)
            .await
            .expect("tip")
            .map(|t| t.commit_count);
        out.insert(s.clone(), (canonical, count));
    }
    out
}

/// Submit `added`-key principal, then check alias resolution before and
/// after `rebuild_index_from_scratch`.
async fn check<B, I>(engine: StorageEngine<B, I>, pool: &test_fixtures::Pool, added: &[&str])
where
    B: cyphr_storage::blob::BlobStore,
    I: Indexer + IndexerWrite,
{
    let (p, genesis, id) = build(pool, added);
    let commits = added.len() + 1;
    for i in 0..commits {
        let raw = blobs(&p, i);
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(&id, Some(genesis.clone()), &refs)
            .await
            .unwrap_or_else(|e| panic!("commit {i} of {added:?}: {e}"));
    }

    let spellings = pg_spellings(&p);
    let want = (id.clone(), Some(commits as u64));
    let before = resolve_all(&engine, &spellings).await;
    for (s, got) in &before {
        assert_eq!(got, &want, "alias {s} before reindex ({added:?})");
    }

    engine
        .rebuild_index_from_scratch()
        .await
        .expect("reindex from blobs");

    assert_eq!(
        resolve_all(&engine, &spellings).await,
        before,
        "reindex changed alias resolution ({added:?})"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Backs I1 (the alias table is a rebuildable cache): for a random
    /// subset and order of added keys (so the PG has one, two or three
    /// hash variants), every PG spelling resolves to the stored principal
    /// before `rebuild_index_from_scratch` and to the identical principal
    /// and tip after it. Turns red if an alias is never recorded (not
    /// resolvable before the reindex), is lost, or moves in the reindex.
    /// A property test over random principals, not a scenario.
    #[test]
    fn alias_resolution_survives_reindex(
        added in Just(ADDABLE.to_vec()).prop_shuffle().prop_flat_map(|v| {
            let n = v.len();
            (Just(v), 1..=n).prop_map(|(v, n)| v[..n].to_vec())
        })
    ) {
        let pool = load_pool();
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(check(
            StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new()),
            &pool,
            &added,
        ));
    }
}

/// The same property on the durable backend, whose alias partition is
/// registered in `index_meta` and must be re-derived after `clear`.
#[tokio::test]
async fn alias_resolution_survives_reindex_on_fjall() {
    let pool = load_pool();
    let dir = tempfile::tempdir().expect("tempdir");
    let indexer = FjallIndexer::open(dir.path()).expect("open indexer");
    check(
        StorageEngine::new(MemoryBlobStore::new(), indexer),
        &pool,
        &["diana_es384", "eve_ed25519"],
    )
    .await;
}

/// Backs SPEC §3.7.1: an explicit multi-algorithm genesis that establishes
/// its PG in commit 0 has, as its PG, the genesis-time PR in every hash
/// variant its keys span (ES256, ES384 and Ed25519 give SHA-256, SHA-384
/// and SHA-512). Each variant label and bare digest must resolve to the
/// one stored principal after that single commit. Turns red if only the
/// canonical (first-variant) spelling, or the post-create PR's variants,
/// resolve. End to end at the engine seam: yes.
#[tokio::test]
async fn alias_explicit_genesis_create_in_commit_zero_resolves_every_pg_variant() {
    let pool = load_pool();
    let (g, d, e) = (
        kp(&pool, "golden"),
        kp(&pool, "diana_es384"),
        kp(&pool, "eve_ed25519"),
    );
    let keys = vec![key_of(&g), key_of(&d), key_of(&e)];
    let mut p = cyphr::Principal::explicit(keys.clone()).expect("explicit genesis");
    let id = p.pr_tagged().expect("genesis id");
    commit_one(
        &mut p,
        &g,
        serde_json::json!({"alg": g.alg, "id": id, "now": NOW,
                           "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        None,
        NOW,
    );
    let spellings = pg_spellings(&p);
    assert_eq!(
        spellings.len(),
        6,
        "premise: three PG variants: {spellings:?}"
    );
    assert!(
        spellings.contains(&id),
        "premise: the PG is the genesis-time PR, so it contains the genesis id {id}"
    );

    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    let raw = blobs(&p, 0);
    let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(&id, Some(Genesis::Explicit(keys)), &refs)
        .await
        .expect("create in commit 0");

    for s in &spellings {
        assert_eq!(
            engine.canonical_principal_id(s).await.expect("resolve"),
            id,
            "PG spelling {s} does not resolve to the stored principal"
        );
        let tip = engine.get_tip(s).await.expect("tip");
        assert_eq!(tip.map(|t| t.commit_count), Some(1), "tip under {s}");
    }
}

/// Probe for the chain link the index records: commit n's `pre` is commit
/// n-1's PR (and commit 0 has none). The engine fills `pre` from
/// `principal.pr()` read after the commit is finalized, which would be the
/// commit's own post-commit PR. Turns red if any `pre` equals its own
/// commit's PR or otherwise differs from the previous commit's PR.
#[tokio::test]
async fn commit_pre_is_the_previous_commits_pr() {
    let pool = load_pool();
    let (p, genesis, id) = build(&pool, &["key_a", "diana_es384"]);
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for i in 0..3 {
        let raw = blobs(&p, i);
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(&id, Some(genesis.clone()), &refs)
            .await
            .unwrap_or_else(|e| panic!("commit {i}: {e}"));
    }
    let patch = engine.get_patch(&id, None, None).await.expect("patch");
    let chain: Vec<_> = patch.entries.iter().map(|e| &e.commit).collect();
    assert_eq!(chain.len(), 3, "control: three commits");
    assert_eq!(chain[0].pre, None, "commit 0 has no predecessor");
    for n in 1..chain.len() {
        assert_eq!(
            chain[n].pre.as_deref(),
            Some(chain[n - 1].pr.as_str()),
            "commit {n}: pre must be commit {}'s PR (own PR is {})",
            n - 1,
            chain[n].pr
        );
    }
}

/// Delegates to a [`MemoryBlobStore`], counting `get`s: replaying a
/// principal reads its blobs, so the count observes a replay.
struct CountingBlobs {
    inner: MemoryBlobStore,
    gets: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl cyphr_storage::blob::BlobStore for CountingBlobs {
    async fn put(
        &self,
        data: &[u8],
    ) -> Result<cyphr_storage::blob::Blake3Hash, cyphr_storage::blob::BlobStoreError> {
        self.inner.put(data).await
    }

    async fn get(
        &self,
        hash: &cyphr_storage::blob::Blake3Hash,
    ) -> Result<Option<Vec<u8>>, cyphr_storage::blob::BlobStoreError> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(hash).await
    }

    async fn exists(
        &self,
        hash: &cyphr_storage::blob::Blake3Hash,
    ) -> Result<bool, cyphr_storage::blob::BlobStoreError> {
        self.inner.exists(hash).await
    }

    async fn iter(
        &self,
    ) -> Result<
        Box<
            dyn Iterator<
                    Item = Result<
                        cyphr_storage::blob::Blake3Hash,
                        cyphr_storage::blob::BlobStoreError,
                    >,
                > + Send,
        >,
        cyphr_storage::blob::BlobStoreError,
    > {
        self.inner.iter().await
    }
}

/// Backs the read-path DoS bound: once a principal's PG is established, its
/// current PR (a public value an attacker can name) is refused from the
/// index alone. The refusal must not replay the principal's history, i.e.
/// must read no blobs. Turns red if resolving that id loads the principal
/// (blob reads) before refusing it. Not a scenario: the amplification is
/// only observable as a blob-read count.
#[tokio::test]
async fn established_principal_current_pr_is_refused_without_replay() {
    let pool = load_pool();
    let (p, genesis, id) = build(&pool, &["key_a", "diana_es384"]);
    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = StorageEngine::new(
        CountingBlobs {
            inner: MemoryBlobStore::new(),
            gets: gets.clone(),
        },
        MemoryIndexer::new(),
    );
    for i in 0..=2 {
        let raw = blobs(&p, i);
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        engine
            .submit_commit(&id, Some(genesis.clone()), &refs)
            .await
            .unwrap_or_else(|e| panic!("commit {i}: {e}"));
    }
    let current = p.pr_tagged().expect("current PR");
    assert!(
        !pg_spellings(&p).contains(&current),
        "premise: the current PR is not the PG"
    );

    let before = gets.load(std::sync::atomic::Ordering::SeqCst);
    for spelling in [
        current.clone(),
        cyphr_storage::engine::bare_digest(&current).to_string(),
    ] {
        let resolved = engine
            .canonical_principal_id(&spelling)
            .await
            .expect("resolve");
        assert_eq!(
            resolved, spelling,
            "the current PR must not name the principal"
        );
        assert!(engine.get_tip(&spelling).await.expect("tip").is_none());
    }
    assert_eq!(
        gets.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "refusing an established principal's current PR read its blobs (a replay)"
    );
}

/// Backs the pre-establishment DoS bound: before a principal has a PG, only
/// its current PR (the PG-to-be) may name it, and any other digest of its
/// latest commit (commit id, state root, auth root) is refused WITHOUT
/// replaying its history. Turns red if such a digest triggers a replay
/// (blob reads) before being refused. The control shows the PR itself still
/// resolves. Not a scenario: the amplification is only observable as a
/// blob-read count.
#[tokio::test]
async fn non_pr_digest_of_latest_commit_is_refused_without_replay() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let k = kp(&pool, "key_a");
    let mut p = cyphr::Principal::implicit(key_of(&g)).expect("genesis");
    let id = p.pr_tagged().expect("genesis id");
    commit_one(
        &mut p,
        &g,
        serde_json::json!({"alg": g.alg, "id": k.tmb.to_b64(), "now": NOW,
                           "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
        Some(key_of(&k)),
        NOW,
    );
    let entry = cyphr_storage::export_commits(&p).expect("export").remove(0);

    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = StorageEngine::new(
        CountingBlobs {
            inner: MemoryBlobStore::new(),
            gets: gets.clone(),
        },
        MemoryIndexer::new(),
    );
    let raw = blobs(&p, 0);
    let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(&id, None, &refs)
        .await
        .expect("commit 0");

    let before = gets.load(std::sync::atomic::Ordering::SeqCst);
    let sr = entry.sr.clone().expect("a live principal has an SR");
    let ar = entry.auth_root.clone().expect("a live principal has an AR");
    for digest in [&entry.commit_id, &sr, &ar] {
        assert_ne!(digest, &entry.pr, "premise: {digest} is not the PR");
        for spelling in [
            digest.to_string(),
            cyphr_storage::engine::bare_digest(digest).to_string(),
        ] {
            let resolved = engine
                .canonical_principal_id(&spelling)
                .await
                .expect("resolve");
            assert_eq!(resolved, spelling, "a non-PR digest named the principal");
        }
    }
    assert_eq!(
        gets.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "a non-PR digest of the latest commit replayed the principal's history"
    );
    // Control: the PG-to-be (the current PR) does name the principal.
    assert_eq!(
        engine
            .canonical_principal_id(&entry.pr)
            .await
            .expect("resolve"),
        id,
        "control: the current PR must resolve while the PG is unestablished"
    );
}
