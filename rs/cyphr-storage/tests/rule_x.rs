//! Rule X: a cap never refuses what would change the standing or the fork
//! point (frame section 11). When the caps would refuse an offer, the
//! engine retains it anyway if `assessment(held + offer)` differs in
//! consensus or fork point; an offer is one commit, or a line root with
//! its one extension (`submit_pair`).

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{
    BRANCH_MANIFEST_PREFIX, BRANCH_PER_KEY, Consensus, EngineError, StorageEngine,
};
use cyphr_storage::index::MemoryIndexer;
use proptest::prelude::*;

const NOW: i64 = 1_700_500_000;

type Engine = StorageEngine<MemoryBlobStore, MemoryIndexer>;

struct Kp {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn golden() -> Kp {
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
fn fresh_kp() -> Kp {
    let g = coz::Alg::Ed25519.generate_keypair();
    let tmb = g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb");
    Kp {
        alg: g.alg.name().to_owned(),
        prv: g.prv_bytes.clone(),
        pubb: g.pub_bytes.clone(),
        tmb,
    }
}

fn key_of(k: &Kp) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone()).expect("key binds its tmb")
}

fn signer_of(k: &Kp) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// `signer` creates `new` at `now` and finalizes the commit itself.
async fn create_key(p: &mut cyphr::Principal, signer: &Kp, new: &Kp, now: i64) {
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

fn last(p: &cyphr::Principal) -> WireBundle {
    WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
}

fn commit_id(p: &cyphr::Principal) -> String {
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
struct Rig {
    id: String,
    genesis: Genesis,
    golden: Kp,
    keys: Vec<Kp>,
    states: Vec<cyphr::Principal>,
}

impl Rig {
    async fn new(len: usize) -> Rig {
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
    async fn ext(
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
    async fn line(&self, over: usize, n: usize, now: i64) -> Vec<cyphr::Principal> {
        self.ext(&self.states[over], n, now, &self.golden).await
    }

    fn engine(&self) -> Engine {
        StorageEngine::new(MemoryBlobStore::new(), MemoryIndexer::new())
    }

    /// An engine holding the canonical chain up to commit `upto`.
    async fn fed(&self, upto: usize) -> Engine {
        let e = self.engine();
        for s in &self.states[..=upto] {
            self.submit(&e, &last(s)).await.expect("canonical chain");
        }
        e
    }

    async fn submit(&self, e: &Engine, b: &WireBundle) -> Result<(), EngineError> {
        e.submit_commit(&self.id, Some(self.genesis.clone()), b)
            .await
            .map(|_| ())
    }

    async fn submit_pair(
        &self,
        e: &Engine,
        parent: &WireBundle,
        bundle: &WireBundle,
    ) -> Result<(), EngineError> {
        e.submit_pair(&self.id, Some(self.genesis.clone()), parent, bundle)
            .await
            .map(|_| ())
    }

    async fn holds(&self, e: &Engine, p: &cyphr::Principal) -> bool {
        e.holds_commit(&self.id, &commit_id(p))
            .await
            .expect("holds")
    }

    /// (is Error, fork point (height, pre)).
    async fn verdict(&self, e: &Engine) -> (bool, Option<(u64, Option<String>)>) {
        let a = e.assess(&self.id).await.expect("assess");
        (
            a.consensus == Consensus::Error,
            a.fork_point.map(|f| (f.height, f.pre)),
        )
    }
}

/// How many branch manifests (retained commits) the engine's blobs hold.
async fn retained(e: &Engine) -> usize {
    let store = e.blob_store();
    let mut n = 0;
    for hash in store.iter().await.expect("iter") {
        let data = store
            .get(&hash.expect("hash"))
            .await
            .expect("get")
            .expect("stored");
        if data.starts_with(BRANCH_MANIFEST_PREFIX) {
            n += 1;
        }
    }
    n
}

/// Every order of `items` (small slices only).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

/// Catches the shared-key pre-fill: a thief fills the key's quota at one
/// holder with junk, and the owner's answer (same key, a root and its
/// extension) is then kept out, leaving that holder Active on the thief's
/// tip while a holder fed the other way round reads Error.
#[tokio::test]
async fn a_shared_key_prefill_cannot_keep_the_owners_answer_out() {
    // C_0..C_2; the thief's J_3, J_4 over C_2; junk X, Y beside C_2 over
    // C_1; the owner's answer O_3, O_4 over C_2. All signed by one key.
    let rig = Rig::new(3).await;
    let j = rig.line(2, 2, NOW + 100).await;
    let x = rig.line(1, 1, NOW + 110).await;
    let y = rig.line(1, 1, NOW + 111).await;
    let o = rig.line(2, 2, NOW + 120).await;

    let h = rig.fed(2).await;
    rig.submit(&h, &last(&j[0]))
        .await
        .expect("J_3 extends the tip");
    rig.submit(&h, &last(&j[1]))
        .await
        .expect("J_4 extends the tip");
    for junk in [&x[0], &y[0]] {
        assert!(
            rig.submit(&h, &last(junk)).await.is_err(),
            "junk is retained"
        );
    }
    assert!(
        !rig.verdict(&h).await.0,
        "premise: Active on the thief's tip"
    );
    assert!(
        matches!(
            rig.submit(&h, &last(&o[0])).await,
            Err(EngineError::BranchLimit { .. })
        ),
        "premise: the key's quota is full, so the root alone is refused"
    );
    let _ = rig.submit_pair(&h, &last(&o[0]), &last(&o[1])).await;
    let at_h = rig.verdict(&h).await;
    assert!(
        at_h.0,
        "the owner's answer pair makes both branches extended: Error"
    );

    let g = rig.fed(2).await;
    for p in [&o[0], &o[1], &j[0], &j[1]] {
        let _ = rig.submit(&g, &last(p)).await;
    }
    assert_eq!(
        rig.verdict(&g).await,
        at_h,
        "the same commits, the same verdict"
    );
}

/// Catches order-dependent standing under the per-signer quota: one key's
/// three rivals R1, R2, R3 (R3 extended by R3') below the head, or two
/// junk rivals plus one beside the unextended head, must give the same
/// Error at the same fork point in every hand-off order, with a refused
/// root re-offered together with its extension.
#[tokio::test]
async fn standing_does_not_depend_on_the_order_the_quota_saw_the_offers() {
    const { assert!(3 > BRANCH_PER_KEY, "the offers must exceed one key's quota") };
    let mut refusals = 0;

    // Below the head: C_0..C_4, rivals of C_2 over C_1, R3 extended.
    let rig = Rig::new(5).await;
    let r: Vec<_> = {
        let mut v = Vec::new();
        for i in 0..3 {
            v.push(rig.line(1, 1, NOW + 200 + 10 * i).await.remove(0));
        }
        v
    };
    let r3x = rig.ext(&r[2], 1, NOW + 300, &rig.golden).await.remove(0);
    let mut seen = None;
    for order in permutations(&[0usize, 1, 2]) {
        // R3' always follows R3 (a branch hands its root before its
        // extension); try it in every position after it.
        for after in 0..=2 {
            let mut offers: Vec<(usize, bool)> = order.iter().map(|&i| (i, false)).collect();
            let r3_at = offers.iter().position(|o| o.0 == 2).expect("R3");
            offers.insert((r3_at + 1 + after).min(offers.len()), (2, true));
            let e = rig.fed(4).await;
            let mut refused_r3 = false;
            for (i, ext) in offers {
                let res = if !ext {
                    rig.submit(&e, &last(&r[i])).await
                } else if refused_r3 {
                    rig.submit_pair(&e, &last(&r[2]), &last(&r3x)).await
                } else {
                    rig.submit(&e, &last(&r3x)).await
                };
                if matches!(res, Err(EngineError::BranchLimit { .. })) {
                    refusals += 1;
                    if !ext && i == 2 {
                        refused_r3 = true;
                    }
                }
            }
            let v = rig.verdict(&e).await;
            assert!(v.0, "R3 and R3' extend a rival of the extended C_2: Error");
            assert_eq!(v.1.as_ref().map(|f| f.0), Some(2), "at the contest of C_2");
            if let Some(first) = &seen {
                assert_eq!(&v, first, "the same offers, the same verdict");
            }
            seen = Some(v);
        }
    }
    assert!(
        refusals > 0,
        "the generator exceeded the quota, or the test is vacuous"
    );

    // Beside the head: two junk rivals of C_2, then one beside the
    // unextended head C_4.
    let rig = Rig::new(5).await;
    let x = rig.line(1, 1, NOW + 400).await.remove(0);
    let y = rig.line(1, 1, NOW + 410).await.remove(0);
    let z = rig.line(3, 1, NOW + 420).await.remove(0);
    let mut seen = None;
    for order in permutations(&[&x, &y, &z]) {
        let e = rig.fed(4).await;
        for p in order {
            let _ = rig.submit(&e, &last(p)).await;
        }
        let v = rig.verdict(&e).await;
        assert!(v.0, "a rival beside the unextended head: Error");
        assert_eq!(v.1.as_ref().map(|f| f.0), Some(4), "at the head's position");
        if let Some(first) = &seen {
            assert_eq!(&v, first, "the same offers, the same verdict");
        }
        seen = Some(v);
    }
}

/// Catches a line that grows by fan-out: a second child of a line root is
/// refused (a line holds a root and one extension), so one key cannot fill
/// the ceiling with siblings and starve a lower pair by another key, whose
/// arrival must still move the fork point.
#[tokio::test]
async fn fan_out_cannot_starve_a_lower_pair() {
    // C_0..C_5. Key K (golden) opens a line at 4: R over C_3, R' over R,
    // both branches extended: Error at 4. K2 (keys[0]) later opens a pair
    // at 2 over C_1.
    let rig = Rig::new(6).await;
    let rl = rig.line(3, 2, NOW + 500).await;
    let e = rig.fed(5).await;
    let _ = rig.submit(&e, &last(&rl[0])).await;
    let _ = rig.submit(&e, &last(&rl[1])).await;
    let at_n = rig.verdict(&e).await;
    assert_eq!(at_n.1.as_ref().map(|f| f.0), Some(4), "premise: Error at 4");
    let before = retained(&e).await;

    for i in 0..31 {
        let sibling = rig
            .ext(&rl[0], 1, NOW + 600 + i, &rig.golden)
            .await
            .remove(0);
        assert!(
            rig.submit(&e, &last(&sibling)).await.is_err(),
            "a second child of a line root is refused"
        );
    }
    assert_eq!(
        retained(&e).await,
        before,
        "the line stays a root and one extension"
    );

    let k2 = &rig.keys[0];
    let s = rig.ext(&rig.states[1], 2, NOW + 800, k2).await;
    let _ = rig.submit_pair(&e, &last(&s[0]), &last(&s[1])).await;
    assert!(rig.holds(&e, &s[0]).await, "the lower pair is retained");
    assert_eq!(
        rig.verdict(&e).await.1.as_ref().map(|f| f.0),
        Some(2),
        "the fork point moves to the lower contest"
    );
}

/// Catches unbounded retention: two signers offer more pairs than their
/// quotas allow, and retained commits must stay within the quotas plus two
/// per chain position: signers x BRANCH_PER_KEY x BRANCH_DEPTH + 2h. Every
/// case asserts it offered more commits than that bound, so an engine that
/// keeps everything fails here; rule X may add at most the 2h.
#[test]
fn retained_commits_stay_within_the_bound() {
    const H: usize = 6;
    const SIGNERS: usize = 2;
    let bound = SIGNERS * BRANCH_PER_KEY * cyphr_storage::engine::BRANCH_DEPTH + 2 * H;
    // Eleven to fourteen pairs: 22 to 28 offered commits against a bound of 20.
    let ops = proptest::collection::vec((2usize..=4, 0usize..SIGNERS), 11..=14);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 5,
        ..ProptestConfig::default()
    });
    runner
        .run(&ops, |ops| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    let offered = 2 * ops.len();
                    assert!(
                        offered > bound,
                        "{offered} offered against a bound of {bound}"
                    );
                    let rig = Rig::new(H).await;
                    let e = rig.fed(H - 1).await;
                    for (n, (pos, who)) in ops.into_iter().enumerate() {
                        let signer = if who == 0 { &rig.golden } else { &rig.keys[0] };
                        let line = rig
                            .ext(&rig.states[pos - 1], 2, NOW + 1000 + 10 * n as i64, signer)
                            .await;
                        let _ = rig.submit_pair(&e, &last(&line[0]), &last(&line[1])).await;
                    }
                    let kept = retained(&e).await;
                    assert!(kept <= bound, "{kept} retained, bound {bound}");
                });
            Ok(())
        })
        .expect("the bound holds");
}

/// Catches a half-kept pair: with the key's quota full and the standing and
/// fork point already settled lower, a pair that changes nothing is refused
/// whole (answered `Errored`: the principal is in Error), and neither
/// commit is kept.
#[tokio::test]
async fn a_pair_that_changes_nothing_is_refused_whole() {
    // C_0..C_5. Error at 2 by K's line R, R' (both branches extended);
    // K's second line is junk X at 4. K's quota is full.
    let rig = Rig::new(6).await;
    let rl = rig.line(1, 2, NOW + 700).await;
    let x = rig.line(3, 1, NOW + 720).await;
    let e = rig.fed(5).await;
    let _ = rig.submit(&e, &last(&rl[0])).await;
    let _ = rig.submit(&e, &last(&rl[1])).await;
    let _ = rig.submit(&e, &last(&x[0])).await;
    let settled = rig.verdict(&e).await;
    assert_eq!(
        settled.1.as_ref().map(|f| f.0),
        Some(2),
        "premise: fork point 2"
    );
    let kept = retained(&e).await;

    // A third line at 4 and its extension: the fork point stays at 2.
    let o = rig.line(3, 2, NOW + 740).await;
    let answer = rig.submit_pair(&e, &last(&o[0]), &last(&o[1])).await;
    assert!(
        matches!(answer, Err(EngineError::Errored { .. })),
        "refused whole, as the Error refusal (the principal is in Error): {answer:?}"
    );
    assert!(!rig.holds(&e, &o[0]).await, "the root is not kept");
    assert!(!rig.holds(&e, &o[1]).await, "the extension is not kept");
    assert_eq!(retained(&e).await, kept, "nothing was stored");
    assert_eq!(rig.verdict(&e).await, settled, "the verdict did not move");
}
