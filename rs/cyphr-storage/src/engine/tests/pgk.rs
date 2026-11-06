//! Acceptance surface for keying stored principals by identity (PG, or the
//! genesis state root while nascent), not by the bare genesis-key tmb.
//!
//! Every test states the claim it backs and the defect that turns it red.
//! Unit level where stated, each for a stated reason: two principals
//! sharing a PG, or a PR, cannot be built from signed cozes (a PR commits
//! to history), so only crafted index metadata reaches them.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};

use super::*;
use crate::blob::{Blake3Hash, BlobStore, BlobStoreError};

const NOW: i64 = 1_700_100_000;
const DIGEST_A: &str = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";

// ---------------------------------------------------------------------------
// storage typ routing: derived from the core kind table
// ---------------------------------------------------------------------------

/// Every `pub const X: &str = "cyphr/..."` in the core's `typ` module, read
/// from the core source so a kind added to the table (a merge kind, a new
/// nonce path) is covered with no edit here. A hand list in a test would
/// repeat the defect it checks.
fn core_kind_suffixes() -> Vec<String> {
    include_str!("../../../../cyphr/src/parsed_coz.rs")
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("pub const ")?;
            let (_, val) = rest.split_once(": &str = \"")?;
            let val = val.strip_suffix("\";")?;
            val.starts_with("cyphr/").then(|| val.to_string())
        })
        .collect()
}

/// The core's own classification: does `typ` parse as a coz kind? A typ is
/// a transaction exactly when the core parser accepts it with some payload
/// of the shapes the kinds take (`id`, `rvk`, `arrow`, merge claim).
fn core_is_kind(typ: &str) -> bool {
    use coz::{PayBuilder, Thumbprint};
    let shapes = [
        serde_json::json!({"id": "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo"}),
        serde_json::json!({"id": DIGEST_A}),
        serde_json::json!({}),
        serde_json::json!({"arrow": DIGEST_A}),
        serde_json::json!({"merge_from": [DIGEST_A], "merge_to_pr": DIGEST_A}),
    ];
    shapes.iter().any(|extra| {
        let mut pay = PayBuilder::new()
            .typ(typ)
            .alg("ES256")
            .now(1_700_000_000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        // `rvk` is a typed field of `Pay`, not an extra: the empty shape is
        // the self-revoke payload.
        pay.rvk = Some(1_700_000_000);
        if extra.as_object().expect("object").is_empty() {
            return parses(&pay);
        }
        pay.rvk = None;
        for (k, v) in extra.as_object().expect("object") {
            pay.extra.insert(k.clone(), v.clone());
        }
        parses(&pay)
    })
}

fn parses(pay: &coz::Pay) -> bool {
    let raw = coz::CozJson {
        pay: serde_json::to_value(pay).expect("pay"),
        sig: vec![0; 64],
    };
    cyphr::parsed_coz::ParsedCoz::from_pay(
        pay,
        coz::Czd::from_bytes(vec![0; 32]),
        cyphr::state::HashAlg::Sha256,
        raw,
    )
    .is_ok()
}

/// Genuine, boundary-broken and foreign spellings of every kind suffix.
fn typ_probe_set() -> Vec<String> {
    let mut out = Vec::new();
    for s in core_kind_suffixes() {
        let rest = s.strip_prefix("cyphr/").expect("cyphr/ prefix");
        out.extend([
            format!("cyphr.me/{s}"),
            s.clone(),
            format!("a.b/c/{s}"),
            format!("cyphr.me/x{s}"),
            format!("{s}x"),
            format!("cyphr.me/{s}/x"),
            format!("/{s}"),
            format!("cyphr.me/{rest}"),
            format!("cyphr.me/app/{rest}"),
            format!("cyphr.me/myapp/{rest}"),
        ]);
    }
    out
}

/// Claim: storage routes a typ to transaction or action exactly as the
/// core kind table does, for every kind (nonce and merge kinds included)
/// and for every boundary-broken spelling. Turns red on: the hand-list
/// substring match (`contains("/key/")`, `contains("/principal/create")`),
/// which classes a nonce path as an action and `cyphr.me/myapp/key/x` or
/// `.../myapp/principal/create` as a transaction; a list that misses a
/// kind added to the core table; a prefix-only or `ends_with` match.
/// Guard against a vacuous oracle: every genuine `cyphr.me/<suffix>` must
/// parse in the core. Not end to end: a pure predicate, no scenario
/// reaches every spelling cheaply.
#[test]
fn storage_typ_routing_agrees_with_core_kind_table() {
    let suffixes = core_kind_suffixes();
    assert!(suffixes.len() >= 17, "source scan found {suffixes:?}");
    for s in &suffixes {
        assert!(core_is_kind(&format!("cyphr.me/{s}")), "oracle rejects {s}");
    }
    let mut wrong = Vec::new();
    for typ in typ_probe_set() {
        let storage = crate::import::is_transaction_typ(&typ);
        let core = core_is_kind(&typ);
        if storage != core {
            wrong.push(format!("{typ}: storage={storage} core={core}"));
        }
    }
    assert!(wrong.is_empty(), "storage disagrees with core: {wrong:#?}");
}

/// Claim: a typ that merely ends in `key/create` text (`xcyphr/key/create`)
/// is not a transaction in storage, as in the core (which refuses to parse
/// it), so a spoof cannot be applied as a key introduction during replay.
/// Turns red on `contains("/key/")` routing. Named separately so the
/// spoof the hacker will try stays pinned if the broad test is reshaped.
#[test]
fn storage_typ_routing_spoofed_key_create_is_an_action() {
    for spoof in [
        "cyphr.me/xcyphr/key/create",
        "cyphr.me/xcyphr/key/replace",
        "cyphr.me/xcyphr/principal/merge",
        "cyphr.me/cyphr/key/create/x",
    ] {
        assert!(!core_is_kind(spoof), "oracle: core parses {spoof}");
        assert!(
            !crate::import::is_transaction_typ(spoof),
            "{spoof} routed as a transaction"
        );
    }
}

/// Claim (characterization, green): the genesis-carrier predicate uses the
/// same `/` boundary as the core for `commit/create`, so PGK's routing
/// change must not loosen it. Turns red if it reverts to a substring or
/// `ends_with` match.
#[test]
fn storage_typ_routing_commit_create_carrier_matches_core_boundary() {
    for typ in typ_probe_set() {
        let core = cyphr::parsed_coz::typ::has_suffix(&typ, cyphr::parsed_coz::typ::COMMIT_CREATE);
        assert_eq!(super::super::is_commit_create_typ(&typ), core, "{typ}");
    }
}

// ---------------------------------------------------------------------------
// holders are sets, not first-found
// ---------------------------------------------------------------------------

fn meta_with_pr(id: &str, seq: u64, pr: &str) -> IndexableCommit {
    let mut m = make_meta(id, seq, 1000 + seq as i64);
    m.prs = vec![pr.to_string()];
    m
}

/// Claim: a PR held by two principals is never attributed to one of them
/// silently. `locate_by_pr` must return both holders or refuse; the
/// signature is the implementer's to change, so the result is compared
/// through its `Debug` form. Turns red on first-holder selection (today:
/// `Some(("alice", 0))`, bob unnamed), and on a lookup that returns the
/// holder that sorts first. The single-holder control must name its
/// holder, so a lookup that always refuses (or names nobody) is caught.
#[tokio::test]
async fn holders_locate_by_pr_never_picks_the_first_holder() {
    let single = test_engine();
    single
        .ingest_commit(
            &[b"{\"pay\":{\"now\":1}}"],
            meta_with_pr("alice", 0, DIGEST_A),
        )
        .await
        .expect("ingest alice");
    let one = format!("{:?}", single.locate_by_pr(DIGEST_A).await);
    assert!(one.contains("alice"), "control: sole holder unnamed: {one}");

    let engine = test_engine();
    for (who, now) in [("alice", 1), ("bob", 2)] {
        let blob = format!("{{\"pay\":{{\"now\":{now}}}}}");
        engine
            .ingest_commit(&[blob.as_bytes()], meta_with_pr(who, 0, DIGEST_A))
            .await
            .expect("ingest");
    }
    let got = format!("{:?}", engine.locate_by_pr(DIGEST_A).await);
    let names_both = got.contains("alice") && got.contains("bob");
    assert!(
        names_both || got.starts_with("Err("),
        "two holders of one PR, neither returned nor refused: {got}"
    );
}

/// Claim: addressing a principal by a PR two principals hold is a typed
/// `Ambiguous` refusal, not a pick of one of them. Turns red on first-holder
/// selection (it would resolve to "alice") or on an untyped error.
#[tokio::test]
async fn holders_address_by_shared_pr_is_typed_ambiguous() {
    let engine = test_engine();
    for (who, now) in [("alice", 1), ("bob", 2)] {
        let blob = format!("{{\"pay\":{{\"now\":{now}}}}}");
        engine
            .ingest_commit(&[blob.as_bytes()], meta_with_pr(who, 0, DIGEST_A))
            .await
            .expect("ingest");
    }
    let got = engine.canonical_principal_id(DIGEST_A).await;
    assert!(matches!(got, Err(EngineError::Ambiguous(_))), "{got:?}");
}

/// Claim: a resync anchor held only by ANOTHER principal is refused for
/// this one; the position of a foreign commit never bounds this chain
/// (the `or_else(first holder)` fallback in `resolve_anchor_position`).
/// Turns red on that fallback. Control: the same anchor on its own
/// principal resolves, so a blanket refusal fails. Scope note: forge #154
/// tracks this gap; whether PGK closes it is the dispatcher's call.
#[tokio::test]
async fn holders_patch_anchor_held_only_by_another_principal_is_refused() {
    let engine = test_engine();
    for seq in 0..3u64 {
        let blob = format!("{{\"pay\":{{\"now\":{seq}}}}}");
        engine
            .ingest_commit(
                &[blob.as_bytes()],
                make_meta("alice", seq, 1000 + seq as i64),
            )
            .await
            .expect("ingest alice");
    }
    engine
        .ingest_commit(
            &[b"{\"pay\":{\"now\":9}}"],
            meta_with_pr("bob", 0, DIGEST_A),
        )
        .await
        .expect("ingest bob");
    let anchor: cyphr::state::TaggedDigest = DIGEST_A.parse().expect("digest");
    engine
        .get_patch("bob", Some(&anchor), None)
        .await
        .expect("control: the anchor resolves on its own principal");
    let foreign = engine.get_patch("alice", Some(&anchor), None).await;
    assert!(
        foreign.is_err(),
        "bob's anchor bounded alice's chain: {:?}",
        foreign.map(|p| p.entries.len())
    );
}

// ---------------------------------------------------------------------------
// alias race: the alias claim is serialized with the durable write
// ---------------------------------------------------------------------------

/// A blob store whose first two `put`s rendezvous: each waits (by yielding
/// to the scheduler, never by the clock) until both ingests have reached
/// their first durable write, or a bounded number of yields passes. On a
/// single-threaded runtime a task that CAN progress reaches the gate within
/// one yield, so the outcome is a function of the code, not of timing: if
/// the second ingest is blocked on a lock the first holds, it never
/// arrives, the bound expires and the first proceeds.
#[derive(Clone)]
struct GatedBlobs {
    inner: MemoryBlobStore,
    arrived: Arc<AtomicUsize>,
}

impl BlobStore for GatedBlobs {
    fn put(&self, data: &[u8]) -> impl Future<Output = Result<Blake3Hash, BlobStoreError>> + Send {
        let data = data.to_vec();
        let me = self.clone();
        async move {
            let n = me.arrived.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                for _ in 0..200 {
                    if me.arrived.load(Ordering::SeqCst) >= 2 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            me.inner.put(&data).await
        }
    }

    fn get(
        &self,
        hash: &Blake3Hash,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send {
        self.inner.get(hash)
    }

    fn exists(
        &self,
        hash: &Blake3Hash,
    ) -> impl Future<Output = Result<bool, BlobStoreError>> + Send {
        self.inner.exists(hash)
    }

    fn iter(
        &self,
    ) -> impl Future<
        Output = Result<
            Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>,
            BlobStoreError,
        >,
    > + Send {
        self.inner.iter()
    }
}

fn meta_claiming_pg(id: &str) -> IndexableCommit {
    let mut m = make_meta(id, 0, 1000);
    m.pg = vec!["SHA-256:contested-pg".to_string()];
    m
}

async fn stored_count(store: &MemoryBlobStore) -> usize {
    store.iter().await.expect("iter").count()
}

/// Claim: two ingests contending for one PG alias, running concurrently,
/// leave exactly one winner, a typed `Conflict` for the loser, and NO
/// residue of the loser (blob or manifest) in the store: the alias claim
/// (`check_commit`) and the write it admits are one critical section.
/// The barrier forces both ingests past `check_commit` before either
/// writes, the interleaving the per-principal lock cannot prevent (the two
/// contenders are different principals). Turns red when `check_commit`
/// runs outside the lock that serializes the claim with the write: the
/// loser is then refused only at `index_commit`, after its blobs and
/// manifest are durable (a manifest every rebuild trips over). Exercised
/// at `ingest_commit` because equal PGs cannot be built from signed cozes;
/// a fix may serialize inside `ingest_commit` or by keying the lock on the
/// alias. Control: one ingest alone stores the same blob count.
#[tokio::test]
async fn alias_race_equal_pg_ingests_leave_one_winner_and_no_residue() {
    let control_blobs = MemoryBlobStore::new();
    let control = StorageEngine::new(
        GatedBlobs {
            inner: control_blobs.clone(),
            arrived: Arc::new(AtomicUsize::new(2)),
        },
        MemoryIndexer::new(),
    );
    control
        .ingest_commit(&[b"{\"pay\":{\"now\":1}}"], meta_claiming_pg("alice"))
        .await
        .expect("control ingest");
    let one_winner_blobs = stored_count(&control_blobs).await;
    assert!(one_winner_blobs >= 2, "control stored {one_winner_blobs}");

    let blobs = MemoryBlobStore::new();
    let engine = StorageEngine::new(
        GatedBlobs {
            inner: blobs.clone(),
            arrived: Arc::new(AtomicUsize::new(0)),
        },
        MemoryIndexer::new(),
    );
    let (a, b) = tokio::join!(
        engine.ingest_commit(&[b"{\"pay\":{\"now\":1}}"], meta_claiming_pg("alice")),
        engine.ingest_commit(&[b"{\"pay\":{\"now\":2}}"], meta_claiming_pg("bob")),
    );
    let (winner, loser) = match (&a, &b) {
        (Ok(_), Err(e)) | (Err(e), Ok(_)) => ("one", e),
        _ => panic!("expected exactly one winner: alice={a:?} bob={b:?}"),
    };
    assert_eq!(winner, "one");
    assert!(
        matches!(
            loser,
            EngineError::Indexer(crate::index::IndexerError::Conflict(_))
        ),
        "the loser must be a typed alias conflict: {loser:?}"
    );
    assert_eq!(
        stored_count(&blobs).await,
        one_winner_blobs,
        "the refused ingest left blobs or a manifest behind"
    );
    let report = engine
        .rebuild_index_with_report()
        .await
        .expect("rebuild survives");
    assert!(
        report.quarantined.is_empty(),
        "a refused ingest left a manifest the rebuild quarantines: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// N13 guarantees (characterization: green now, must stay green after rekey)
// ---------------------------------------------------------------------------

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn kp(pool: &test_fixtures::Pool, name: &str) -> Kp {
    let pk = pool.get(name).expect("pool key");
    Kp {
        alg: pk.alg.clone(),
        prv: Base64UrlUnpadded::decode_vec(pk.prv.as_ref().expect("prv")).expect("prv b64"),
        pubb: Base64UrlUnpadded::decode_vec(&pk.pub_key).expect("pub b64"),
        tmb: pk.compute_tmb().expect("tmb"),
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

/// Wire blobs of commit 0 of a principal rooted at `g` that adds `added`;
/// commit 0's last blob carries the genesis key, as the wire contract needs.
fn commit0_adding(g: &Kp, added: &Kp) -> Vec<Vec<u8>> {
    commit0_adding_with_pr(g, added).0
}

/// [`commit0_adding`] plus the principal's PR after that commit (its key,
/// and the PG if `principal/create` follows at once).
fn commit0_adding_with_pr(g: &Kp, added: &Kp) -> (Vec<Vec<u8>>, String) {
    let mut p = cyphr::Principal::implicit(key_of(g)).expect("genesis");
    let pay = serde_json::json!({
        "alg": g.alg, "id": added.tmb.to_b64(), "now": NOW, "tmb": g.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/create",
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&bytes, &g.alg, &g.prv, &g.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&bytes, &sig, czd, Some(key_of(added)))
        .expect("apply");
    scope
        .finalize_with_software(
            &cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb),
            NOW,
            "cyphr.me",
        )
        .expect("finalize");
    let pr = p.pr_tagged().expect("pr");
    let entry = &crate::export_commits(&p).expect("export")[0];
    let last = entry.cozies.len() - 1;
    let blobs: Vec<Vec<u8>> = entry
        .cozies
        .iter()
        .enumerate()
        .map(|(n, c)| {
            let mut c = c.clone();
            if n == 0 {
                c["key"] = serde_json::json!({
                    "alg": added.alg, "pub": Base64UrlUnpadded::encode_string(&added.pubb),
                    "tmb": added.tmb.to_b64(),
                });
            }
            if n == last {
                c["key"] = serde_json::json!({
                    "alg": g.alg, "pub": Base64UrlUnpadded::encode_string(&g.pubb),
                    "tmb": g.tmb.to_b64(),
                });
            }
            serde_json::to_vec(&c).expect("blob")
        })
        .collect();
    (blobs, pr)
}

/// Claim (N13, chain-position idempotency and Fork quarantine at the write
/// path): a rival commit 0 for a principal whose position 0 is taken is
/// refused, and leaves the stored chain, its tip and its commit id exactly
/// as they were; the accepted commit's resubmission adds no second
/// position. Must stay green when the storage key changes from the genesis
/// tmb to the PG or genesis state root. Turns red if the rival is accepted,
/// merged, or moves the tip. End to end through `submit_commit` with real
/// signed commits.
#[tokio::test]
async fn n13_rival_commit_at_a_taken_position_is_refused_and_tip_holds() {
    let pool = load_pool();
    let (g, k1, k2) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "alice"));
    let genesis = crate::Genesis::Implicit(key_of(&g));
    let id = genesis_principal_id(&genesis).expect("id");
    let engine = test_engine();
    let honest = commit0_adding(&g, &k1);
    let refs: Vec<&[u8]> = honest.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(&id, Some(genesis.clone()), &refs)
        .await
        .expect("honest commit 0");
    let before = engine.get_tip(&id).await.expect("tip").expect("stored");

    let rival = commit0_adding(&g, &k2);
    let refs: Vec<&[u8]> = rival.iter().map(Vec::as_slice).collect();
    let refused = engine
        .submit_commit(&id, Some(genesis.clone()), &refs)
        .await;
    assert!(refused.is_err(), "a rival at position 0 was accepted");
    // The outcome of replaying the accepted commit is not pinned (it may be
    // a no-op or a refusal); what is pinned is that it adds no position.
    let refs: Vec<&[u8]> = honest.iter().map(Vec::as_slice).collect();
    let _ = engine.submit_commit(&id, Some(genesis), &refs).await;

    let after = engine.get_tip(&id).await.expect("tip").expect("stored");
    assert_eq!(after.commit_count, 1, "a second position appeared");
    assert_eq!(after.commit_id, before.commit_id, "the tip commit moved");
    assert_eq!(after.pr, before.pr, "the tip root moved");
}

// ---------------------------------------------------------------------------
// rekeying: principals sharing a key stay distinct, and the index is a cache
// ---------------------------------------------------------------------------

/// Wire blobs of commit `i` of `p`; commit 0's last blob carries the genesis
/// key.
fn wire_blobs(p: &cyphr::Principal, i: usize, g: &Kp) -> Vec<Vec<u8>> {
    let entry = &crate::export_commits(p).expect("export")[i];
    let last = entry.cozies.len() - 1;
    entry
        .cozies
        .iter()
        .enumerate()
        .map(|(n, c)| {
            let mut c = c.clone();
            if i == 0 && n == last {
                c["key"] = serde_json::json!({
                    "alg": g.alg, "pub": Base64UrlUnpadded::encode_string(&g.pubb),
                    "tmb": g.tmb.to_b64(),
                });
            }
            serde_json::to_vec(&c).expect("blob")
        })
        .collect()
}

fn signed(g: &Kp, pay: serde_json::Value) -> (Vec<u8>, Vec<u8>, coz::Czd) {
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, cad) = coz::sign_json(&bytes, &g.alg, &g.prv, &g.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &g.alg).expect("czd");
    (bytes, sig, czd)
}

/// A principal on `g`: commit 0 inserts `nonce` at the KT root, commit 1
/// is `principal/create`. Returns it with its PG (`SHA-256:` form).
fn nonce_principal(g: &Kp, nonce: u8) -> (cyphr::Principal, String) {
    let mut p = cyphr::Principal::implicit(key_of(g)).expect("genesis");
    let soft = |g: &Kp| cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb);
    let nonce_pay = serde_json::json!({
        "alg": g.alg,
        "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[nonce; 32])),
        "now": NOW, "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
    });
    let (pay, sig, czd) = signed(g, nonce_pay);
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("nonce");
    scope
        .finalize_with_software(&soft(g), NOW, "cyphr.me")
        .expect("finalize 0");
    let pg = p.pr_tagged().expect("pr");
    let create = serde_json::json!({"alg": g.alg, "id": pg, "now": NOW + 1,
        "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"});
    let (pay, sig, czd) = signed(g, create);
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, None)
        .expect("create");
    scope
        .finalize_with_software(&soft(g), NOW + 1, "cyphr.me")
        .expect("finalize 1");
    (p, pg)
}

/// Claim (I1 and SPEC be0663f 5.1 l764): two principals on one key that
/// differ only by a nonce are two stored principals, each addressed by its
/// own PG, and the index is a cache: after `rebuild_index_from_scratch`
/// from the blobs alone both still resolve, to different ids, with their
/// own commit counts. Turns red if storage keys by the genesis-key tmb
/// (the second principal's commit 0 collides with the first's) or if the
/// rebuilt layout merges them. Control: a PG is not the key's tmb. End to
/// end through `submit_commit` with real signed commits and the durable
/// recovery path. Why storage-level too: the server tests share a red
/// prerequisite (nonce routing) that would mask a keying defect.
#[tokio::test]
async fn rekey_nonce_siblings_stay_distinct_through_a_reindex() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let genesis = crate::Genesis::Implicit(key_of(&g));
    let tmb_id = genesis_principal_id(&genesis).expect("id");
    let engine = test_engine();
    let built = [nonce_principal(&g, 0x11), nonce_principal(&g, 0x22)];
    assert_ne!(built[0].1, built[1].1, "control: nonces must differ the PG");
    assert_ne!(built[0].1, tmb_id, "control: a PG is not the key's tmb");

    for (p, pg) in &built {
        for i in 0..2 {
            let blobs = wire_blobs(p, i, &g);
            let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
            let r = engine.submit_commit(pg, Some(genesis.clone()), &refs).await;
            assert!(r.is_ok(), "commit {i} of {pg} refused: {r:?}");
        }
    }
    let pgs = [built[0].1.clone(), built[1].1.clone()];
    let before = resolve_all(&engine, &pgs).await;
    assert_ne!(before[0].0, before[1].0, "two PGs, one stored principal");
    assert!(before.iter().all(|(_, c)| *c == Some(2)), "{before:?}");
    assert!(
        engine.get_tip(&tmb_id).await.expect("tip").is_none(),
        "the bare key id names a stored principal, but none has no nonce"
    );
    engine.rebuild_index_from_scratch().await.expect("reindex");
    assert_eq!(
        resolve_all(&engine, &pgs).await,
        before,
        "the reindex changed identity"
    );
}

/// Canonical id and commit count of each of `pgs`, as the engine serves them.
async fn resolve_all(
    engine: &StorageEngine<MemoryBlobStore, MemoryIndexer>,
    pgs: &[String],
) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    for pg in pgs {
        let id = engine.canonical_principal_id(pg).await.expect("resolve");
        let count = engine
            .get_tip(pg)
            .await
            .expect("tip")
            .map(|t| t.commit_count);
        out.push((id, count));
    }
    out
}

// ---------------------------------------------------------------------------
// keying ruling: key = PR after commit 0; tmb is a lookup; PG is the report
// ---------------------------------------------------------------------------

async fn submit<B: BlobStore>(
    engine: &StorageEngine<B, MemoryIndexer, cyphr::eml::MemoryStorage>,
    claim: &str,
    g: &Kp,
    blobs: &[Vec<u8>],
) -> Result<IngestResult, EngineError> {
    let refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    engine
        .submit_commit(claim, Some(crate::Genesis::Implicit(key_of(g))), &refs)
        .await
}

/// Claim: the storage key is derived from the record (the PR after commit
/// 0), never from the spelling the push used, so one principal pushed under
/// its tmb on one server and under its PG-to-be on another gets the same
/// key, and a reindex from the blobs reproduces it. Turns red when the key
/// follows the claim (tmb on one engine, the PR on the other).
#[tokio::test]
#[ignore = "RED(PGK): the storage key follows the pushed spelling"]
async fn rekey_key_is_independent_of_the_pushed_spelling_and_survives_reindex() {
    let pool = load_pool();
    let (g, k1) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let tmb = genesis_principal_id(&crate::Genesis::Implicit(key_of(&g))).expect("id");
    let (blobs, pr) = commit0_adding_with_pr(&g, &k1);
    assert_ne!(pr, tmb, "premise: commit 0 moves the PR off the bare tmb");
    let (by_tmb, by_pr) = (test_engine(), test_engine());
    submit(&by_tmb, &tmb, &g, &blobs).await.expect("under tmb");
    submit(&by_pr, &pr, &g, &blobs).await.expect("under PR");
    let (a, b) = (
        by_tmb.canonical_principal_id(&tmb).await.expect("a"),
        by_pr.canonical_principal_id(&pr).await.expect("b"),
    );
    assert_eq!(a, b, "the key follows the pushed spelling");
    assert_eq!(a, pr, "before principal/create the reported id is the key");
    for e in [&by_tmb, &by_pr] {
        e.rebuild_index_from_scratch().await.expect("reindex");
        assert_eq!(e.canonical_principal_id(&tmb).await.expect("after"), pr);
    }
}

/// Claim: a principal pushed under its PG-to-be is found by its bare
/// genesis-key tmb while exactly one such principal is stored. Turns red
/// while the tmb is no address at all (404/None).
#[tokio::test]
#[ignore = "RED(PGK): a bare tmb does not resolve by genesis-key lookup"]
async fn rekey_pushed_under_pg_to_be_resolves_by_unambiguous_bare_tmb() {
    let pool = load_pool();
    let (g, k1) = (kp(&pool, "golden"), kp(&pool, "key_a"));
    let tmb = genesis_principal_id(&crate::Genesis::Implicit(key_of(&g))).expect("id");
    let (blobs, pr) = commit0_adding_with_pr(&g, &k1);
    let engine = test_engine();
    submit(&engine, &pr, &g, &blobs).await.expect("under PG-to-be");
    let by_tmb = engine.get_tip(&tmb).await.expect("tip").expect("stored");
    let by_pr = engine.get_tip(&pr).await.expect("tip").expect("stored");
    assert_eq!(by_tmb.commit_id, by_pr.commit_id);
    assert_eq!(
        engine.canonical_principal_id(&tmb).await.expect("tmb"),
        engine.canonical_principal_id(&pr).await.expect("pr"),
        "the two addresses name different principals"
    );
}

/// Claim: a bare tmb shared by two stored principals is a typed
/// `Ambiguous` refusal, not a pick and not "not found". Turns red on a
/// first-match or a silent miss.
#[tokio::test]
#[ignore = "RED(PGK): an ambiguous bare tmb is not refused"]
async fn rekey_ambiguous_bare_tmb_is_typed_ambiguous() {
    let pool = load_pool();
    let (g, k1, k2) = (kp(&pool, "golden"), kp(&pool, "key_a"), kp(&pool, "alice"));
    let tmb = genesis_principal_id(&crate::Genesis::Implicit(key_of(&g))).expect("id");
    let engine = test_engine();
    for k in [&k1, &k2] {
        let (blobs, pr) = commit0_adding_with_pr(&g, k);
        submit(&engine, &pr, &g, &blobs).await.expect("push");
    }
    let got = engine.get_tip(&tmb).await;
    assert!(matches!(got, Err(EngineError::Ambiguous(_))), "{got:?}");
}

/// Claim: a nonce principal claimed by its bare tmb is refused (the tmb is
/// the identity of the single-key, no-nonce principal only), and nothing
/// is stored. Turns red when it is accepted.
#[tokio::test]
#[ignore = "RED(PGK): a nonce principal is accepted under the bare tmb"]
async fn rekey_nonce_principal_claimed_by_bare_tmb_is_refused() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let tmb = genesis_principal_id(&crate::Genesis::Implicit(key_of(&g))).expect("id");
    let (p, _pg) = nonce_principal(&g, 0x55);
    let blobs = wire_blobs(&p, 0, &g);
    let engine = test_engine();
    let got = submit(&engine, &tmb, &g, &blobs).await;
    assert!(got.is_err(), "accepted: {got:?}");
    assert!(engine.indexer().list_principals().await.expect("list").is_empty());
}

/// Claim: after commits before `principal/create` the key stays the PR
/// after commit 0, and the reported id becomes the PG once established.
/// Turns red when the reported id stays the key after `principal/create`.
#[tokio::test]
#[ignore = "RED(PGK): the reported id is not the PG once established"]
async fn rekey_reported_id_is_the_pg_once_established() {
    let pool = load_pool();
    let g = kp(&pool, "golden");
    let (p, pg_after_two) = nonce_principal_with_gap(&g, 0x66);
    let engine = test_engine();
    let b0 = wire_blobs(&p, 0, &g);
    let key = submit(&engine, &pg_after_two.0, &g, &b0)
        .await
        .expect("commit 0")
        .principal_id;
    let b1 = wire_blobs(&p, 1, &g);
    submit(&engine, &pg_after_two.0, &g, &b1).await.expect("commit 1");
    assert_eq!(engine.canonical_principal_id(&key).await.expect("id"), key);
    let b2 = wire_blobs(&p, 2, &g);
    submit(&engine, &pg_after_two.0, &g, &b2).await.expect("create");
    assert_ne!(key, pg_after_two.1, "premise: the PG differs from the key");
    assert_eq!(
        engine.canonical_principal_id(&key).await.expect("after"),
        pg_after_two.1
    );
    assert_eq!(
        engine.canonical_principal_id(&pg_after_two.1).await.expect("by pg"),
        pg_after_two.1
    );
}

/// Principal on `g`: commit 0 inserts `nonce`, commit 1 inserts a second
/// nonce, commit 2 is `principal/create`. Returns it with (PR after commit
/// 0, the PG).
fn nonce_principal_with_gap(g: &Kp, nonce: u8) -> (cyphr::Principal, (String, String)) {
    let mut p = cyphr::Principal::implicit(key_of(g)).expect("genesis");
    let soft = |g: &Kp| cyphr::signer::SoftwareSigner::new(&g.alg, &g.prv, &g.pubb, &g.tmb);
    let mut apply = |p: &mut cyphr::Principal, pay: serde_json::Value, now: i64| {
        let (pay, sig, czd) = signed(g, pay);
        let mut scope = p.begin_commit();
        scope.verify_and_apply(&pay, &sig, czd, None).expect("apply");
        scope.finalize_with_software(&soft(g), now, "cyphr.me").expect("finalize");
    };
    let nonce_pay = |n: u8, now: i64| {
        serde_json::json!({
            "alg": g.alg,
            "id": format!("SHA-256:{}", Base64UrlUnpadded::encode_string(&[n; 32])),
            "now": now, "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/AT/KT/nonce/create",
        })
    };
    apply(&mut p, nonce_pay(nonce, NOW), NOW);
    let first = p.pr_tagged().expect("pr");
    apply(&mut p, nonce_pay(nonce.wrapping_add(1), NOW + 1), NOW + 1);
    let pg = p.pr_tagged().expect("pr");
    apply(
        &mut p,
        serde_json::json!({"alg": g.alg, "id": pg, "now": NOW + 2,
            "tmb": g.tmb.to_b64(), "typ": "cyphr.me/cyphr/principal/create"}),
        NOW + 2,
    );
    (p, (first, pg))
}
