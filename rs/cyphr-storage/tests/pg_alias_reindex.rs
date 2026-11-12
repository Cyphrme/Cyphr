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

/// Pool keys a genesis can create after `golden`, spanning ES256, ES384
/// and Ed25519 so the PG gains SHA-256, SHA-384 and SHA-512 variants.
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

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// Commit, on the established `p`, `signer`'s `key/create` of `added`.
async fn commit_key_create(p: &mut cyphr::Principal, signer: &Kp, added: &Kp, now: i64) {
    let (pay, sig, czd) = sign(
        signer,
        serde_json::json!({"alg": signer.alg, "id": added.tmb.to_b64(), "now": now,
                           "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create"}),
    );
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(added)))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(signer), now, "cyphr.me")
        .await
        .expect("finalize");
}

/// The wire bundle of commit `i` of `p` (SPEC 4.6.2): its keys travel in
/// the bundle's `keys`.
fn blobs(p: &cyphr::Principal, i: usize) -> cyphr::replay::WireBundle {
    cyphr::replay::WireBundle::of_commit(p.commits().nth(i).expect("commit")).expect("bundle")
}

/// A principal whose genesis commit (SPEC 5.1) creates `golden` and then
/// `genesis` (so its PG spans their algorithms), then adds each of `later`
/// in its own commit. Returns the principal, its genesis and its id (the
/// PG, in its first-algorithm spelling).
async fn build(
    pool: &test_fixtures::Pool,
    genesis: &[&str],
    later: &[&str],
) -> (cyphr::Principal, Genesis, String) {
    let g = kp(pool, "golden");
    let keys: Vec<cyphr::Key> = std::iter::once(key_of(&g))
        .chain(genesis.iter().map(|name| key_of(&kp(pool, name))))
        .collect();
    let mut p = cyphr::Principal::implicit(keys[0].clone())
        .await
        .expect("genesis");
    let blobs = test_fixtures::bundle::genesis_bundle(
        &mut p,
        pool.get("golden").expect("golden"),
        &keys[1..],
        NOW,
    )
    .await
    .expect("genesis commit");
    let id = test_fixtures::bundle::genesis_id(&blobs).expect("genesis id");
    for (n, name) in later.iter().enumerate() {
        commit_key_create(&mut p, &g, &kp(pool, name), NOW + 1 + n as i64).await;
    }
    (p, Genesis::Disclosed(keys), id)
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

/// Submit a principal whose genesis creates `golden` and `added`, then one
/// more commit (so the tip is past the PG), then check alias resolution
/// before and after `rebuild_index_from_scratch`.
async fn check<B, I>(engine: StorageEngine<B, I>, pool: &test_fixtures::Pool, added: &[&str])
where
    B: cyphr_storage::blob::BlobStore,
    I: Indexer + IndexerWrite,
{
    let (p, genesis, id) = build(pool, added, &["bob"]).await;
    let commits = 2;
    for i in 0..commits {
        let raw = blobs(&p, i);
        engine
            .submit_commit(&id, Some(genesis.clone()), &raw)
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
    /// subset and order of genesis keys (so the PG has one, two or three
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
    let (p, genesis, id) = build(&pool, &["diana_es384", "eve_ed25519"], &[]).await;
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
    engine
        .submit_commit(&id, Some(genesis), &raw)
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
    let (p, genesis, id) = build(&pool, &["key_a"], &["diana_es384", "bob"]).await;
    let engine = StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new());
    for i in 0..3 {
        let raw = blobs(&p, i);
        engine
            .submit_commit(&id, Some(genesis.clone()), &raw)
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
    let (p, genesis, id) = build(&pool, &["key_a"], &["diana_es384", "bob"]).await;
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
        engine
            .submit_commit(&id, Some(genesis.clone()), &raw)
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

/// Backs the read-path DoS bound for digests of the latest commit: a
/// principal's id is its PG (any variant) or storage key, and any other
/// digest of its latest commit (commit id, state root, auth root) is
/// refused WITHOUT replaying its history. The latest commit follows the
/// genesis commit: the genesis commit's own AR and SR are the PG, which
/// names the principal by right. (A principal is no longer addressable
/// before its PG: every chain begins with the genesis commit that
/// establishes it, SPEC 5.1.) Turns red if
/// such a digest triggers a replay (blob reads) or names the principal. The
/// control shows the PG still resolves. Not a scenario: the amplification
/// is only observable as a blob-read count.
#[tokio::test]
async fn non_pr_digest_of_latest_commit_is_refused_without_replay() {
    let pool = load_pool();
    let (p, _, id) = build(&pool, &["key_a"], &["bob"]).await;
    let entry = cyphr_storage::export_commits(&p).expect("export").remove(1);

    let gets = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let engine = StorageEngine::new(
        CountingBlobs {
            inner: MemoryBlobStore::new(),
            gets: gets.clone(),
        },
        MemoryIndexer::new(),
    );
    for i in 0..2 {
        let raw = blobs(&p, i);
        engine
            .submit_commit(&id, None, &raw)
            .await
            .unwrap_or_else(|e| panic!("commit {i}: {e}"));
    }

    let pg = pg_spellings(&p);
    let before = gets.load(std::sync::atomic::Ordering::SeqCst);
    let sr = entry.sr.clone().expect("a live principal has an SR");
    let ar = entry.auth_root.clone().expect("a live principal has an AR");
    for digest in [&entry.commit_id, &sr, &ar] {
        assert_ne!(digest, &entry.pr, "premise: {digest} is not the PR");
        for spelling in [
            digest.to_string(),
            cyphr_storage::engine::bare_digest(digest).to_string(),
        ] {
            assert!(!pg.contains(&spelling), "premise: {spelling} is not the PG");
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
    // Control: the PG does name the principal.
    assert_eq!(
        engine.canonical_principal_id(&id).await.expect("resolve"),
        id,
        "control: the PG must resolve"
    );
}
