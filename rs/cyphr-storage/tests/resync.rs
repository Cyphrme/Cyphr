//! The `resync/create` exit (frame section 12, SPEC 15.8 item 2) at the
//! engine: a proof of possession (`id` = the PR of the asserted tip, signed
//! by a key active there, `now` required) selects one child at a fork, and
//! the verdict, heads and chain are `assessment` over everything held, with
//! the held PoPs asserted, in every order and after a rebuild.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::replay::WireBundle;
use cyphr_storage::Genesis;
use cyphr_storage::blob::{BlobStore, MemoryBlobStore};
use cyphr_storage::engine::{BRANCH_PER_KEY, Consensus, EngineError, StorageEngine};
use cyphr_storage::index::MemoryIndexer;

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

/// A resync PoP (SPEC 13) by `signer` at `now` over the PR `id`.
fn pop_over(signer: &Kp, id: &str, now: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": signer.alg, "id": id, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": "cyphr.me/cyphr/resync/create"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &signer.alg, &signer.prv, &signer.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
    })
}

/// A PoP asserting the tip `tip`.
fn pop(signer: &Kp, tip: &cyphr::Principal, now: i64) -> serde_json::Value {
    pop_over(signer, &tip.pr_tagged().expect("pr"), now)
}

/// A self-signed naked revoke of `k` (SPEC 6.4) as of `rvk`.
fn revoke_of(k: &Kp, rvk: i64) -> serde_json::Value {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": k.alg, "now": rvk, "rvk": rvk, "tmb": k.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke"
    }))
    .expect("pay");
    let (sig, _) = coz::sign_json(&pay, &k.alg, &k.prv, &k.pubb).expect("sign");
    serde_json::json!({
        "pay": serde_json::from_slice::<serde_json::Value>(&pay).expect("pay"),
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {"alg": k.alg, "pub": Base64UrlUnpadded::encode_string(&k.pubb)},
    })
}

fn bundles(ps: &[cyphr::Principal]) -> Vec<WireBundle> {
    ps.iter().map(last).collect()
}

impl Rig {
    /// The seam FR2 fills: `StorageEngine::submit_resync(principal_id,
    /// genesis, pop, line)` under the principal lock. `line` carries the
    /// commits from a held commit up to the asserted tip when the tip is
    /// not held.
    async fn submit_resync(
        &self,
        e: &Engine,
        pop: &serde_json::Value,
        line: &[WireBundle],
    ) -> Result<(), EngineError> {
        let _ = (e, pop, line);
        todo!("StorageEngine::submit_resync (FR2 12.3)")
    }

    /// Every blob the engine holds.
    async fn blobs(&self, e: &Engine) -> usize {
        e.blob_store().iter().await.expect("iter").count()
    }

    async fn heads(&self, e: &Engine) -> Vec<String> {
        e.assess(&self.id).await.expect("assess").heads
    }

    async fn tip_id(&self, e: &Engine) -> String {
        e.get_tip(&self.id)
            .await
            .expect("tip")
            .expect("stored")
            .commit_id
    }

    /// The canonical fork this file starts from: the chain through
    /// commit 2, then the lines `l` and `r` of two commits each over it,
    /// both extended: Error at 3.
    async fn forked(&self, l: &[cyphr::Principal], r: &[cyphr::Principal]) -> Engine {
        let e = self.fed(2).await;
        for p in l {
            self.submit(&e, &last(p))
                .await
                .expect("the first line extends the tip");
        }
        // A rival is retained and answered as a fork, so the answers are not
        // the premise: the verdict below is.
        for p in r {
            let _ = self.submit(&e, &last(p)).await;
        }
        assert!(self.verdict(&e).await.0, "premise: both extended is Error");
        e
    }
}

/// What the engine answers once everything is delivered: the verdict, its
/// fork point and, while Active, the heads and the chain's tip.
async fn standing(
    rig: &Rig,
    e: &Engine,
) -> (bool, Option<(u64, Option<String>)>, Vec<String>, String) {
    let (error, fp) = rig.verdict(e).await;
    let heads = if error {
        Vec::new()
    } else {
        rig.heads(e).await
    };
    let tip = if error {
        String::new()
    } else {
        rig.tip_id(e).await
    };
    (error, fp, heads, tip)
}

/// One step of a hand-off.
#[derive(Clone, Copy)]
enum Offer {
    /// Position `.1` of line `.0`.
    Commit(usize, usize),
    /// PoP number `.0`.
    Pop(usize),
}

/// A random interleaving that keeps each line in order (a branch hands its
/// root before its extension) and the PoPs anywhere.
fn interleave(seed: u64, lines: usize, pops: usize) -> Vec<Offer> {
    let mut next = vec![0usize; lines];
    let mut left_pops: Vec<usize> = (0..pops).collect();
    let mut out = Vec::new();
    let mut s = seed | 1;
    let mut rnd = |n: usize| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        (s % n as u64) as usize
    };
    while next.iter().any(|&n| n < 2) || !left_pops.is_empty() {
        let mut live: Vec<Option<usize>> = (0..lines).filter(|&l| next[l] < 2).map(Some).collect();
        live.extend(left_pops.iter().map(|_| None));
        match live[rnd(live.len())] {
            Some(l) => {
                out.push(Offer::Commit(l, next[l]));
                next[l] += 1;
            },
            None => out.push(Offer::Pop(left_pops.remove(rnd(left_pops.len())))),
        }
    }
    out
}

/// Hand `e` the offers in order the way carriers do: a refused extension
/// is re-offered with its root, and a PoP whose tip is not held is
/// re-offered at the end with the line up to its tip (`lines[l]` over the
/// chain, `pops[i] = (pop, l)`).
async fn deliver(
    rig: &Rig,
    e: &Engine,
    order: &[Offer],
    lines: &[Vec<cyphr::Principal>],
    pops: &[(serde_json::Value, usize)],
) {
    let mut deferred = Vec::new();
    for o in order {
        match *o {
            Offer::Commit(l, i) => {
                let b = last(&lines[l][i]);
                if rig.submit(e, &b).await.is_err() && i == 1 {
                    let _ = rig.submit_pair(e, &last(&lines[l][0]), &b).await;
                }
            },
            Offer::Pop(n) => {
                if rig.submit_resync(e, &pops[n].0, &[]).await.is_err() {
                    deferred.push(n);
                }
            },
        }
    }
    for n in deferred {
        let line = bundles(&lines[pops[n].1]);
        rig.submit_resync(e, &pops[n].0, &line)
            .await
            .expect("a PoP offered with its line is accepted");
    }
}

/// R5, selection. Three lines by one key over the tip C_2 (more rivals
/// than its quota keeps) and a PoP on the first line's tip: in every
/// hand-off order the principal is Active with that tip as its head and
/// its chain's tip, a rebuild from the blobs agrees, and so does an engine
/// fed in another order. Catches a verdict that depends on which offers
/// the caps kept, a PoP that only works when its tip arrived first, and a
/// live state a rebuild does not reproduce.
#[tokio::test]
async fn a_pop_selects_the_asserted_line_in_every_order() {
    const { assert!(3 > BRANCH_PER_KEY, "the lines must exceed one key's quota") };
    let rig = Rig::new(3).await;
    let lines = [
        rig.line(2, 2, NOW + 100).await,
        rig.line(2, 2, NOW + 200).await,
        rig.line(2, 2, NOW + 300).await,
    ];
    let want = commit_id(&lines[0][1]);
    let pops = [(pop(&rig.keys[0], &lines[0][1], NOW + 900), 0)];
    let mut seen = None;
    for seed in 1..=16u64 {
        let e = rig.fed(2).await;
        deliver(&rig, &e, &interleave(seed, 3, 1), &lines, &pops).await;
        let got = standing(&rig, &e).await;
        assert_eq!(
            got,
            (false, None, vec![want.clone()], want.clone()),
            "seed {seed}: Active on the asserted line"
        );
        e.rebuild_index_from_scratch().await.expect("rebuild");
        assert_eq!(
            standing(&rig, &e).await,
            got,
            "seed {seed}: a rebuild agrees"
        );
        assert_eq!(
            seen.get_or_insert(got.clone()),
            &got,
            "seed {seed}: order changed it"
        );
    }
}

/// R5, error for good. PoPs on two lines' tips: in every order the
/// principal is Error at the one fork point, no further commit on either
/// line or further PoP leaves it, and a rebuild agrees. Catches a PoP
/// race that the first arrival wins.
#[tokio::test]
async fn pops_in_two_lines_are_error_in_every_order() {
    let rig = Rig::new(3).await;
    let lines = [
        rig.line(2, 2, NOW + 100).await,
        rig.line(2, 2, NOW + 200).await,
        rig.line(2, 2, NOW + 300).await,
    ];
    let pops = [
        (pop(&rig.keys[0], &lines[0][1], NOW + 900), 0),
        (pop(&rig.keys[1], &lines[1][1], NOW + 901), 1),
    ];
    let fork_point = Some((3, Some(rig.states[2].pr_tagged().expect("pr"))));
    for seed in 1..=16u64 {
        let e = rig.fed(2).await;
        deliver(&rig, &e, &interleave(seed, 3, 2), &lines, &pops).await;
        assert_eq!(
            rig.verdict(&e).await,
            (true, fork_point.clone()),
            "seed {seed}"
        );
        e.rebuild_index_from_scratch().await.expect("rebuild");
        assert_eq!(
            rig.verdict(&e).await,
            (true, fork_point.clone()),
            "seed {seed}: rebuilt"
        );

        let more = rig.ext(&lines[0][1], 1, NOW + 950, &rig.golden).await;
        let _ = rig.submit(&e, &last(&more[0])).await;
        let again = pop(&rig.keys[1], &lines[0][1], NOW + 960);
        let _ = rig.submit_resync(&e, &again, &[]).await;
        assert_eq!(
            rig.verdict(&e).await,
            (true, fork_point.clone()),
            "seed {seed}: no exit"
        );
    }
}

/// R6. A PoP that must be refused stores nothing and leaves the verdict,
/// and a valid one for the same tip is accepted (so a refusal is not the
/// absent route): the signer is not active at the tip, the signer is
/// revoked at `now`, the tip is not held and no line comes, and `id` is no
/// PR of this principal.
#[tokio::test]
async fn an_unfit_pop_is_refused_and_stores_nothing() {
    let rig = Rig::new(5).await;
    let l = rig.line(2, 2, NOW + 100).await;
    let r = rig.line(2, 2, NOW + 200).await;
    let unheld = rig.line(2, 2, NOW + 300).await;
    let stranger = {
        let k = fresh_kp();
        let mut p = cyphr::Principal::implicit(key_of(&k))
            .await
            .expect("genesis");
        p.commit_genesis(&signer_of(&k), &[], NOW, "cyphr.me")
            .await
            .expect("commit");
        p.pr_tagged().expect("pr")
    };
    let tip = l[1].pr_tagged().expect("pr");
    let at = NOW + 2000;

    let e = rig.forked(&l, &r).await;
    // Premise: keys[0] and keys[1] are active at the tip; keys[2] is made
    // only by a later commit of the canonical chain.
    let fit = pop(&rig.keys[1], &l[1], at);
    let before = (rig.blobs(&e).await, rig.verdict(&e).await);
    let arms: [(&str, serde_json::Value, Vec<WireBundle>); 3] = [
        (
            "signer not active at the tip",
            pop(&rig.keys[2], &l[1], at),
            vec![],
        ),
        (
            "tip not held and no line",
            pop(&rig.keys[1], &unheld[1], at),
            vec![],
        ),
        (
            "id is no PR of this principal",
            pop_over(&rig.keys[1], &stranger, at),
            vec![],
        ),
    ];
    for (why, bad, line) in &arms {
        assert!(
            rig.submit_resync(&e, bad, line).await.is_err(),
            "{why}: refused"
        );
        assert_eq!(
            (rig.blobs(&e).await, rig.verdict(&e).await),
            before,
            "{why}: nothing stored"
        );
    }
    e.record_revoke(&revoke_of(&rig.keys[0], NOW + 1000), NOW + 1000)
        .await
        .expect("revoke");
    let revoked = pop(&rig.keys[0], &l[1], at);
    let before = (rig.blobs(&e).await, rig.verdict(&e).await);
    assert!(
        rig.submit_resync(&e, &revoked, &[]).await.is_err(),
        "a revoked signer at `now`: refused"
    );
    assert_eq!(
        (rig.blobs(&e).await, rig.verdict(&e).await),
        before,
        "revoked: nothing stored"
    );

    rig.submit_resync(&e, &fit, &[])
        .await
        .expect("the fit PoP is accepted");
    assert_eq!(
        rig.heads(&e).await,
        vec![commit_id(&l[1])],
        "it selects {tip}"
    );
}

/// R7. A tip past the retained depth is accepted with its line, the line
/// becoming the chain whether it is longer or shorter than the chain it
/// displaces, and the displaced commits are kept as evidence. Catches a
/// promotion that needs equal lengths, and a PoP the caps refuse for a
/// line they would not keep.
#[tokio::test]
async fn a_tip_past_retained_depth_is_promoted_with_its_line() {
    // (displaced chain commits above C_2, selected line commits)
    for (displaced, selected) in [(2usize, 4usize), (5, 3)] {
        let rig = Rig::new(3 + displaced).await;
        let line = rig.line(2, selected, NOW + 100).await;
        let e = rig.fed(2 + displaced).await;
        let sel = rig.keys[0].tmb.to_b64();
        let tip_pop = pop(&rig.keys[0], &line[selected - 1], NOW + 900);
        let tip_id = commit_id(&line[selected - 1]);
        assert!(
            rig.submit_resync(&e, &tip_pop, &[]).await.is_err(),
            "{displaced}/{selected}: the tip is not held and no line comes"
        );
        rig.submit_resync(&e, &tip_pop, &bundles(&line))
            .await
            .unwrap_or_else(|err| panic!("{displaced}/{selected}: {sel} with its line: {err}"));
        assert_eq!(
            rig.heads(&e).await,
            vec![tip_id.clone()],
            "{displaced}/{selected}"
        );
        assert_eq!(
            rig.tip_id(&e).await,
            tip_id,
            "{displaced}/{selected}: the line is the chain"
        );
        for s in &rig.states[3..] {
            assert!(
                rig.holds(&e, s).await,
                "{displaced}/{selected}: displaced commit kept"
            );
        }
        e.rebuild_index_from_scratch().await.expect("rebuild");
        assert_eq!(
            rig.tip_id(&e).await,
            tip_id,
            "{displaced}/{selected}: rebuilt"
        );
    }
}

/// R8. Many PoPs for one tip, by different keys at different `now`, store
/// one record: the blobs held after the first equal those after the rest.
/// Catches a store that grows with every re-sent PoP.
#[tokio::test]
async fn many_pops_for_one_tip_store_one_record() {
    let rig = Rig::new(4).await;
    let l = rig.line(2, 2, NOW + 100).await;
    let r = rig.line(2, 2, NOW + 200).await;
    let e = rig.forked(&l, &r).await;
    let first = pop(&rig.keys[0], &l[1], NOW + 900);
    let base = rig.blobs(&e).await;
    rig.submit_resync(&e, &first, &[]).await.expect("accepted");
    let one = rig.blobs(&e).await;
    assert_eq!(one, base + 1, "the first PoP is one record");
    for k in 0..6i64 {
        let signer = &rig.keys[(k % 3) as usize];
        let _ = rig
            .submit_resync(&e, &pop(signer, &l[1], NOW + 901 + k), &[])
            .await;
        let _ = rig.submit_resync(&e, &first, &[]).await;
    }
    assert_eq!(
        rig.blobs(&e).await,
        one,
        "later PoPs for the tip store nothing"
    );
}
