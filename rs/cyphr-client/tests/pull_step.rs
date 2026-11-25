//! The pull step: a verifier pulls branch heads, the patch from its own tip
//! and naked revokes from the peers it chose, replays everything from its
//! own record and classifies it (GOSSIP-MIN section 2). Peers are mirrors of
//! principal-signed objects: nothing here believes a peer's word, so every
//! scenario serves real chains built with `cyphr` from a carrier that plays
//! the peer, honest or hostile.

mod common;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};

use common::*;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::principal::Clock;
use cyphr_client::{
    Anchor, ChannelBinding, ConnectError, Connector, PeerChain, PeerFailure, PeerStanding,
    PullPeer, Record, Request, fetch_revoked, pull,
};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000;

/// Replays at a fixed "now" after every commit the fixtures sign.
fn clock() -> i64 {
    T0 + 10_000
}
const CLOCK: Clock = clock;

/// A clock the test sets, for scenarios where the receipt time of a revoke
/// is the point. Tests that use it must not run beside each other.
static RECEIPT: AtomicI64 = AtomicI64::new(0);
fn receipt_clock() -> i64 {
    RECEIPT.load(Ordering::SeqCst)
}
static RECEIPT_CLOCK_USERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One branch of a principal as a peer would hold it: each commit's blobs,
/// and the PR and commit id the chain reaches after it.
#[derive(Clone)]
struct Line {
    entries: Vec<Vec<String>>,
    prs: Vec<String>,
    ids: Vec<String>,
}

fn commit_id(p: &cyphr::Principal) -> String {
    p.commits()
        .last()
        .expect("a commit")
        .tr()
        .0
        .tagged_first()
        .expect("commit id")
        .to_string()
}

impl Line {
    fn of_genesis(chain: &Chain<'_>) -> Self {
        Self {
            entries: vec![chain.genesis_commit.clone()],
            prs: vec![chain.principal.pr_tagged().expect("pr")],
            ids: vec![commit_id(&chain.principal)],
        }
    }

    fn push(&mut self, chain: &Chain<'_>, blobs: Vec<String>) {
        self.entries.push(blobs);
        self.prs.push(chain.principal.pr_tagged().expect("pr"));
        self.ids.push(commit_id(&chain.principal));
    }

    fn tip(&self) -> &str {
        self.ids.last().expect("a commit")
    }
}

/// The genesis commit of `g`, then one `key/create` commit per `(key, now)`.
/// Ed25519 signs deterministically, so two lines built from one prefix share
/// it exactly and differ only where the caller makes them differ.
async fn line(g: &Kp, grow: &[(&Kp, i64)]) -> Line {
    let mut chain = Chain::new(g).await;
    let mut line = Line::of_genesis(&chain);
    for (key, now) in grow {
        let blobs = chain.commit(key, *now).await;
        line.push(&chain, blobs);
    }
    line
}

/// A peer: serves its canonical line, and optionally a retained rival
/// branch, fork evidence and naked revokes.
struct Fake {
    pg: String,
    line: Line,
    rival: Option<Line>,
    evidence: Vec<Value>,
    revoked: Vec<Value>,
    /// Action-only bundles, each a list of blobs, served with every patch.
    actions: Vec<Vec<String>>,
    /// Answers 404 to a patch from an anchor, as a peer that does not hold
    /// the anchor does, so only the whole chain can be compared.
    whole_only: bool,
    served: Mutex<Vec<String>>,
}

impl Fake {
    fn new(pg: &str, line: &Line) -> Self {
        Self {
            pg: pg.to_owned(),
            line: line.clone(),
            rival: None,
            evidence: Vec::new(),
            revoked: Vec::new(),
            actions: Vec::new(),
            whole_only: false,
            served: Mutex::default(),
        }
    }

    fn served(&self, path: &str) -> usize {
        let served = self.served.lock().expect("served");
        served.iter().filter(|p| p.as_str() == path).count()
    }

    fn envelope(payload: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "v": 1, "payload": payload, "statement": { "kind": "unsigned" }
        }))
        .expect("json")
    }

    fn head(line: &Line, canonical: bool) -> Value {
        let n = line.ids.len();
        json!({
            "tip": line.tip(),
            "pre": n.checked_sub(2).map(|i| line.prs[i].clone()),
            "sequence": n - 1,
            "canonical": canonical,
        })
    }
}

fn query(target: &str) -> (&str, BTreeMap<String, String>) {
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    let pairs = q
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.replace("%3A", ":")))
        .collect();
    (path, pairs)
}

impl Connector for Fake {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let (path, q) = query(&request.target);
        self.served.lock().expect("served").push(path.to_owned());
        // Revokes are asked by key; every other read names the principal.
        let asked = q.get("pg").map(String::as_str);
        assert_eq!(asked, (path != "/revoked").then_some(self.pg.as_str()));
        Ok(match path {
            "/branches" => {
                let mut heads = vec![Self::head(&self.line, true)];
                heads.extend(self.rival.iter().map(|r| Self::head(r, false)));
                Self::envelope(&json!({ "branches": heads }))
            },
            "/patch" => {
                if self.whole_only && q.contains_key("from") {
                    return Err(ConnectError::NonSuccess(404));
                }
                let from = match q.get("from") {
                    None => 0,
                    Some(anchor) => match self.line.prs.iter().position(|pr| pr == anchor) {
                        Some(p) => p + 1,
                        None => return Err(ConnectError::NonSuccess(404)),
                    },
                };
                let entries: Vec<Value> = self.line.entries[from..]
                    .iter()
                    .enumerate()
                    .map(|(i, blobs)| entry_bundle(from + i, blobs))
                    .collect();
                let actions: Vec<Value> = self
                    .actions
                    .iter()
                    .map(|blobs| json!({ "blobs": blobs }))
                    .collect();
                Self::envelope(&json!({ "entries": entries, "actions": actions }))
            },
            "/evidence" => Self::envelope(&json!({ "items": self.evidence })),
            "/revoked" => Self::envelope(&json!({ "revoked": self.revoked })),
            other => return Err(ConnectError::Unreachable(format!("no route {other}"))),
        })
    }
}

fn fork_item(pg: &str, a: &Line, b: &Line, height: usize) -> Value {
    json!({
        "kind": "principal-fork",
        "pg": pg,
        "height": height,
        "pre": height.checked_sub(1).map(|i| a.prs[i].clone()),
        "a": entry_bundle(height, &a.entries[height]),
        "b": entry_bundle(height, &b.entries[height]),
    })
}

fn naked_revoke(victim: &Kp, signer: &Kp, rvk: i64) -> Value {
    let pay = json!({
        "alg": victim.kp.alg.name(),
        "now": rvk,
        "rvk": rvk,
        "tmb": victim.tmb.to_b64(),
        "typ": "cyphr.me/cyphr/key/revoke",
    });
    let bytes = serde_json::to_vec(&pay).expect("pay");
    let (sig, _) = coz::sign_json(
        &bytes,
        signer.kp.alg.name(),
        &signer.kp.prv_bytes,
        &signer.kp.pub_bytes,
    )
    .expect("sign");
    // The envelope discloses the VICTIM's public key, as a real one does.
    json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
        "key": {
            "alg": victim.kp.alg.name(),
            "pub": Base64UrlUnpadded::encode_string(&victim.kp.pub_bytes),
        },
    })
}

fn record(pg: &str, g: &Kp) -> Record {
    Record::new(pg, Anchor::GenesisKey(g.domain_key(T0))).with_clock(CLOCK)
}

fn peer<'a>(name: &'a str, fake: &'a Fake) -> PullPeer<'a, Fake> {
    PullPeer {
        name,
        connector: fake,
    }
}

fn standing<'a>(report: &'a cyphr_client::PullReport, name: &str) -> &'a PeerStanding {
    &report
        .peers
        .iter()
        .find(|p| p.peer == name)
        .unwrap_or_else(|| panic!("no outcome for {name}"))
        .standing
}

/// Claim: the verifier decides from principal-signed objects it replayed
/// itself. Against four peers it holds a record built from one of them and
/// classifies each: the one ahead extends the record by replay (and only
/// the entries past the verifier's own tip are fetched, one `/patch`), the
/// one behind is `Behind` and the record does not regress, the one equal is
/// `Current`, and the one that serves a chain which does not replay from
/// the verifier's anchor `Failed`s without touching the record or the
/// verdict. The longest verified tip wins; no branch is merged.
///
/// Turns red if: a lower tip regresses the record; an unverified peer
/// changes the record; the tip is not the longest verified one; or the
/// pull re-fetches what the verifier already holds.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
// @docket: arch-behind-is-not-fork :: scripts/docket-run arch-behind-is-not-fork
#[tokio::test]
async fn pull_classifies_peers_from_the_own_record() {
    let (g, other, k1, k2, k3) = (kp(), kp(), kp(), kp(), kp());
    let (c1, c2, c3) = ((&k1, T0 + 100), (&k2, T0 + 200), (&k3, T0 + 300));
    let pg = g.tmb.to_b64();
    let held = line(&g, &[c1]).await;
    let ahead = line(&g, &[c1, c2, c3]).await;
    let behind = line(&g, &[]).await;
    let stranger = line(&other, &[c1, c2, c3, (&kp(), T0 + 400)]).await;

    let mut rec = record(&pg, &g);
    let first = Fake::new(&pg, &held);
    pull(&mut rec, &[peer("first", &first)]).await;
    assert_eq!(rec.tip().expect("tip").commits, 2);

    let (a, b, same, junk) = (
        Fake::new(&pg, &ahead),
        Fake::new(&pg, &behind),
        Fake::new(&pg, &held),
        Fake::new(&pg, &stranger),
    );
    let report = pull(
        &mut rec,
        &[
            peer("junk", &junk),
            peer("behind", &b),
            peer("same", &same),
            peer("ahead", &a),
        ],
    )
    .await;

    assert!(matches!(standing(&report, "junk"), PeerStanding::Failed(_)));
    assert!(matches!(
        standing(&report, "behind"),
        PeerStanding::Behind { peer_commits: 1 }
    ));
    assert!(matches!(standing(&report, "same"), PeerStanding::Current));
    assert!(matches!(
        standing(&report, "ahead"),
        PeerStanding::Extended { added: 2 }
    ));
    let tip = rec.tip().expect("tip");
    assert_eq!((tip.commits, tip.commit_id.as_str()), (4, ahead.tip()));
    assert_eq!(tip.pr, ahead.prs[3]);
    assert!(report.forks.is_empty() && report.revoked.is_empty());
    assert_eq!(a.served("/patch"), 1, "one patch, from the verifier's tip");

    // A later pull of only the lagging peer never regresses the record.
    let report = pull(&mut rec, &[peer("behind", &b)]).await;
    assert!(matches!(
        standing(&report, "behind"),
        PeerStanding::Behind { peer_commits: 1 }
    ));
    assert_eq!(rec.tip().expect("tip").commits, 4);
}

/// Claim: two commits over one `pre` are `Error` with both commits, and the
/// verifier never merges: whether the rival reaches it as another peer's
/// canonical chain or from a single peer that holds both branches
/// (`/branches` shows two heads, `/evidence` proves it), the verifier's
/// record keeps the chain it held. A peer that claims two heads and serves
/// "evidence" that does not replay produces no finding.
///
/// Turns red if: a fork is merged or the record moves; the finding lacks
/// either commit; a forged evidence item becomes a finding.
/// End-to-end scenario: yes.
#[tokio::test]
async fn pull_reports_a_fork_with_both_commits_and_keeps_the_record() {
    let (g, k1, k2, k3) = (kp(), kp(), kp(), kp());
    let c1 = (&k1, T0 + 100);
    let pg = g.tmb.to_b64();
    let main = line(&g, &[c1, (&k2, T0 + 200)]).await;
    let rival = line(&g, &[c1, (&k3, T0 + 201)]).await;
    assert_eq!(main.prs[1], rival.prs[1], "one shared pre");
    assert_ne!(main.tip(), rival.tip());

    // The rival as another peer's canonical chain.
    let (p_main, p_rival) = (Fake::new(&pg, &main), Fake::new(&pg, &rival));
    let mut rec = record(&pg, &g);
    let report = pull(&mut rec, &[peer("p1", &p_main), peer("p2", &p_rival)]).await;
    assert!(matches!(standing(&report, "p2"), PeerStanding::Forked));
    assert_eq!(report.forks.len(), 1);
    let fork = &report.forks[0];
    assert_eq!(fork.height, 2);
    assert_eq!(fork.pre.as_deref(), Some(main.prs[1].as_str()));
    let mut seen = fork.commits.clone();
    seen.sort();
    let mut want = [main.tip().to_owned(), rival.tip().to_owned()];
    want.sort();
    assert_eq!(seen, want, "both commits are named");
    assert_eq!(rec.tip().expect("tip").commit_id, main.tip());

    // One peer that holds both branches proves it without a second peer.
    let mut both = Fake::new(&pg, &main);
    both.rival = Some(rival.clone());
    both.evidence = vec![fork_item(&pg, &main, &rival, 2)];
    let mut rec = record(&pg, &g);
    let report = pull(&mut rec, &[peer("both", &both)]).await;
    assert_eq!(report.forks.len(), 1);
    assert_eq!(rec.tip().expect("tip").commit_id, main.tip());

    // Claimed heads and an item that does not replay are not evidence: the
    // rival's blobs are swapped for the genesis commit's.
    let mut liar = Fake::new(&pg, &main);
    liar.rival = Some(rival.clone());
    let mut forged = rival.clone();
    forged.entries[2] = main.entries[0].clone();
    liar.evidence = vec![fork_item(&pg, &main, &forged, 2)];
    let mut rec = record(&pg, &g);
    let report = pull(&mut rec, &[peer("liar", &liar)]).await;
    assert!(report.forks.is_empty(), "{:?}", report.forks);
    assert_eq!(rec.tip().expect("tip").commit_id, main.tip());
}

/// Claim: a verified naked revoke makes the key inactive for everything the
/// verifier judges afterwards, and a peer cannot forge one: a revoke served
/// by the peer but signed by another key is refused.
///
/// Turns red if: a revoke signed by another key marks the key dead; a
/// verified revoke leaves the key active.
/// End-to-end scenario: yes.
#[tokio::test]
async fn pull_marks_a_key_inactive_from_a_verified_naked_revoke() {
    let (g, k1) = (kp(), kp());
    let pg = g.tmb.to_b64();
    let main = line(&g, &[(&k1, T0 + 100)]).await;
    let mut rec = record(&pg, &g);

    let mut forger = Fake::new(&pg, &main);
    forger.revoked = vec![naked_revoke(&k1, &g, T0 + 500)];
    let report = pull(&mut rec, &[peer("forger", &forger)]).await;
    assert!(report.revoked.is_empty());
    assert!(rec.is_key_active(&k1.tmb), "a forged revoke kills nothing");

    let mut honest = Fake::new(&pg, &main);
    honest.revoked = vec![naked_revoke(&k1, &k1, T0 + 500)];
    let report = pull(&mut rec, &[peer("honest", &honest)]).await;
    assert_eq!(report.revoked.len(), 1);
    assert_eq!(report.revoked[0].tmb, k1.tmb);
    assert!(!rec.is_key_active(&k1.tmb), "a verified revoke kills it");
    assert!(rec.is_key_active(&g.tmb), "and only it");
}

/// Claim: a record's cutoff for a revoked key is its own clock at the first
/// revoke it accepted, one revoke per key however often a peer repeats it:
/// a peer serving two revokes of the key (the second with `rvk` 1), and
/// again on the next pull, adds neither a report entry nor a lower cutoff.
///
/// Turns red if: the cutoff is the revoke's `rvk`; a repeated revoke is
/// reported again; or a later revoke lowers the cutoff.
/// End-to-end scenario: yes (two pulls over a carrier).
#[tokio::test]
async fn record_cutoff_is_its_receipt_and_one_revoke_stands() {
    let (g, k1) = (kp(), kp());
    let pg = g.tmb.to_b64();
    let main = line(&g, &[(&k1, T0 + 100)]).await;
    let mut rec = record(&pg, &g);

    let mut relay = Fake::new(&pg, &main);
    relay.revoked = vec![
        naked_revoke(&k1, &k1, T0 + 1_000_000_000),
        naked_revoke(&k1, &k1, 1),
    ];
    let first = pull(&mut rec, &[peer("relay", &relay)]).await;
    assert_eq!(first.revoked.len(), 1, "one record per key");
    let again = pull(&mut rec, &[peer("relay", &relay)]).await;
    assert!(again.revoked.is_empty(), "a repeat adds nothing");
    assert_eq!(
        rec.dead_keys().collect::<Vec<_>>(),
        vec![(k1.tmb.to_b64().as_str(), clock())],
        "the cutoff is the record's clock, not an rvk"
    );
}

/// A genesis commit opened by `opener` over the key set `{opener} + others`:
/// its line and bare PG.
async fn genesis_over(opener: &Kp, others: &[&Kp]) -> (Line, String) {
    let mut p = cyphr::Principal::implicit(opener.domain_key(T0))
        .await
        .expect("genesis");
    let others: Vec<_> = others.iter().map(|k| k.domain_key(T0)).collect();
    p.commit_genesis(&opener.signer(), &others, T0, "cyphr.me")
        .await
        .expect("genesis commit");
    let pg = {
        use cyphr::StateDigest as _;
        let tagged = p
            .pg()
            .expect("PG")
            .as_multihash()
            .tagged_first()
            .expect("pg")
            .to_string();
        tagged.split_once(':').expect("tagged").1.to_owned()
    };
    let line = Line {
        entries: vec![wire_commit(p.commits().last().expect("commit"))],
        prs: vec![p.pr_tagged().expect("pr")],
        ids: vec![commit_id(&p)],
    };
    (line, pg)
}

/// Claim: an opener holding one genesis key cannot impersonate the anchored
/// chain. Two genesis commits over one key set, differing only in which key
/// opens, derive one PG but are different chains. A verifier anchored on
/// the genesis KEY of one, or on its genesis COMMIT id, accepts that chain
/// and refuses the other; the API has no PG-only anchor.
///
/// Turns red if: the other opener's chain passes under either anchor kind.
/// End-to-end scenario: yes.
#[tokio::test]
async fn anchor_accepts_the_anchored_opener_and_refuses_the_other() {
    let (a, b) = (kp(), kp());
    let (by_a, pg_a) = genesis_over(&a, &[&b]).await;
    let (by_b, pg_b) = genesis_over(&b, &[&a]).await;
    assert_eq!(pg_a, pg_b, "one key set, one PG");
    assert_ne!(by_a.tip(), by_b.tip(), "but different chains");
    let (anchored, impostor) = (Fake::new(&pg_a, &by_a), Fake::new(&pg_a, &by_b));

    for anchor in [
        Anchor::GenesisKey(a.domain_key(T0)),
        Anchor::GenesisCommit(by_a.tip().to_owned()),
    ] {
        let mut rec = Record::new(&pg_a, anchor).with_clock(CLOCK);
        let report = pull(
            &mut rec,
            &[peer("impostor", &impostor), peer("anchored", &anchored)],
        )
        .await;
        assert!(
            matches!(standing(&report, "impostor"), PeerStanding::Failed(_)),
            "the other opener is refused: {:?}",
            standing(&report, "impostor")
        );
        assert!(matches!(
            standing(&report, "anchored"),
            PeerStanding::Extended { added: 1 }
        ));
        assert_eq!(rec.tip().expect("tip").commit_id, by_a.tip());
    }
}

/// Claim: a revoked peer key cannot keep speaking, from the time the
/// verifier received the revoke. A peer key whose naked revoke the client
/// fetched and verified is refused for a tip statement dated at or after
/// the receipt and for the transport's key lookup, whatever `now` and `rvk`
/// the revoke declared (here a far-future one, which is Coz-valid); a
/// revoke signed by another key changes nothing; the peer's other keys
/// still speak.
///
/// Turns red if: the revoke's own `rvk` decides the cutoff (the far-future
/// `rvk` would then keep the key speaking); `active_key` still returns it;
/// a forged revoke is recorded.
/// End-to-end scenario: yes (revokes fetched over a carrier, then a tip
/// judged against the held peer chain).
#[tokio::test]
async fn naked_revoked_peer_key_is_refused_from_receipt() {
    let _clock = RECEIPT_CLOCK_USERS.lock().await;
    RECEIPT.store(T0 + 400, Ordering::SeqCst);
    let (g, k1) = (kp(), kp());
    let mut peer_chain = Chain::new(&g).await;
    let c1 = peer_chain.commit(&k1, T0 + 100).await;
    let pipe = Pipe::new(peer_chain.patch(std::slice::from_ref(&c1)));
    let mut held = PeerChain::pin(&peer_chain.pg(), g.domain_key(T0))
        .await
        .with_clock(receipt_clock);
    held.follow(&pipe).await.expect("follow");
    let (pr, _) = subject();
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());

    let main = line(&g, &[(&k1, T0 + 100)]).await;
    let mut serving = Fake::new("-", &main);
    serving.revoked = vec![
        naked_revoke(&k1, &g, T0 + 500),
        naked_revoke(&k1, &k1, T0 + 1_000_000_000),
    ];
    let served = fetch_revoked(&serving, std::slice::from_ref(&k1.tmb))
        .await
        .expect("served revokes");
    assert_eq!(served.len(), 2);
    let outcomes: Vec<_> = served
        .iter()
        .map(|e| held.observe_naked_revoke(e))
        .collect();
    assert!(outcomes[0].is_err(), "a revoke signed by another key");
    assert!(outcomes[1].is_ok());

    // The fixture's tip statement is dated 1_700_000_500, after the receipt
    // at 1_700_000_400.
    assert!(matches!(
        held.verify_tip(&tip_envelope(&k1), &pr),
        Err(PeerFailure::KeyRevoked { .. })
    ));
    assert!(matches!(
        held.active_key(&k1.tmb),
        Err(PeerFailure::KeyRevoked { .. })
    ));
    assert!(held.verify_tip(&tip_envelope(&g), &pr).is_ok());
}

/// Claim: the first accepted revoke of a key sets its cutoff, and a later
/// revoke of the same key (here with `rvk` 1, best practice for a
/// pre-signed one, received later) does not move it. The key is refused
/// for a statement dated after the first receipt, and stays refused once
/// the second revoke is received.
///
/// Turns red if: a later revoke replaces the first, which would move the
/// cutoff past the statement and let it stand. (It does not close the
/// least-`rvk` rule or the history side; the other tests do.)
/// End-to-end scenario: yes (revokes fetched over a carrier).
#[tokio::test]
async fn first_accepted_revoke_sets_the_cutoff() {
    let _clock = RECEIPT_CLOCK_USERS.lock().await;
    RECEIPT.store(T0 + 300, Ordering::SeqCst);
    let (g, k1) = (kp(), kp());
    let mut peer_chain = Chain::new(&g).await;
    let c1 = peer_chain.commit(&k1, T0 + 100).await;
    let pipe = Pipe::new(peer_chain.patch(std::slice::from_ref(&c1)));
    let mut held = PeerChain::pin(&peer_chain.pg(), g.domain_key(T0))
        .await
        .with_clock(receipt_clock);
    held.follow(&pipe).await.expect("follow");
    let (pr, _) = subject();

    let main = line(&g, &[(&k1, T0 + 100)]).await;
    let mut serving = Fake::new("-", &main);
    serving.revoked = vec![naked_revoke(&k1, &k1, T0 + 50), naked_revoke(&k1, &k1, 1)];
    let served = fetch_revoked(&serving, std::slice::from_ref(&k1.tmb))
        .await
        .expect("served revokes");

    // The tip statement is dated 1_700_000_500: after the first receipt.
    RECEIPT.store(T0 + 400, Ordering::SeqCst);
    held.observe_naked_revoke(&served[0]).expect("first");
    assert!(matches!(
        held.verify_tip(&tip_envelope(&k1), &pr),
        Err(PeerFailure::KeyRevoked { .. })
    ));
    RECEIPT.store(T0 + 700, Ordering::SeqCst);
    held.observe_naked_revoke(&served[1]).expect("second");
    assert!(
        matches!(
            held.verify_tip(&tip_envelope(&k1), &pr),
            Err(PeerFailure::KeyRevoked { .. })
        ),
        "a later revoke does not move the cutoff past the statement"
    );
}

/// Claim: a genesis-key anchor does not let a peer swap in another principal.
/// Two principals opened by one key over different key sets (the nonce
/// sibling case: same key, different PG) both replay cleanly from that key,
/// so only the check that the replayed chain derives the principal asked
/// about stops a record for `pg_v` from taking `pg_s`'s history. The peer
/// that serves the sibling's chain under `pg_v` is refused; the same peer
/// serving `pg_v`'s own chain is accepted.
///
/// Turns red if: the sibling's chain extends the record for `pg_v`, or the
/// control chain is refused.
/// End-to-end scenario: yes.
#[tokio::test]
async fn anchor_refuses_a_sibling_principal_on_the_same_key() {
    let (a, b, c) = (kp(), kp(), kp());
    let (own, pg_v) = genesis_over(&a, &[&b]).await;
    let (sibling, pg_s) = genesis_over(&a, &[&c]).await;
    assert_ne!(pg_v, pg_s, "one opener, different key sets, different PGs");

    let liar = Fake::new(&pg_v, &sibling);
    let mut rec = Record::new(&pg_v, Anchor::GenesisKey(a.domain_key(T0))).with_clock(CLOCK);
    let report = pull(&mut rec, &[peer("liar", &liar)]).await;
    assert!(
        matches!(
            standing(&report, "liar"),
            PeerStanding::Failed(PeerFailure::PrincipalMismatch { .. })
        ),
        "{:?}",
        standing(&report, "liar")
    );
    assert!(rec.tip().is_none(), "nothing of the sibling was adopted");

    let honest = Fake::new(&pg_v, &own);
    let report = pull(&mut rec, &[peer("honest", &honest)]).await;
    assert!(matches!(
        standing(&report, "honest"),
        PeerStanding::Extended { added: 1 }
    ));
    assert_eq!(rec.tip().expect("tip").commit_id, own.tip());
}

/// Claim: a verifier that keeps its record between pulls pays for what is
/// new, not for its history (SPEC 4.5: the last trusted state is the trust
/// anchor, and only the patch from it is fetched and verified). A record
/// that pulled a 3-commit chain and then a 2-commit extension replays
/// exactly 2 commits on the second pull and holds the same verified state
/// as a record that took the whole 5-commit chain in one cold pull.
///
/// Turns red if: the second pull replays the history it already verified
/// (the count exceeds the new commits), or two pulls leave a different
/// state than one pull of the union.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
#[tokio::test]
async fn a_second_pull_replays_only_what_is_new_and_agrees_with_a_cold_build() {
    let (g, k1, k2, k3, k4) = (kp(), kp(), kp(), kp(), kp());
    let grow = [
        (&k1, T0 + 100),
        (&k2, T0 + 200),
        (&k3, T0 + 300),
        (&k4, T0 + 400),
    ];
    let pg = g.tmb.to_b64();
    let short = line(&g, &grow[..2]).await;
    let long = line(&g, &grow).await;
    let (a, b) = (Fake::new(&pg, &short), Fake::new(&pg, &long));

    let mut kept = record(&pg, &g);
    pull(&mut kept, &[peer("a", &a)]).await;
    assert_eq!(kept.replayed(), 3, "the first pull replays the 3 commits");
    pull(&mut kept, &[peer("b", &b)]).await;
    assert_eq!(
        kept.replayed(),
        5,
        "the second pull replays only the 2 new commits"
    );

    let mut cold = record(&pg, &g);
    pull(&mut cold, &[peer("b", &b)]).await;
    assert_eq!(cold.replayed(), 5);
    let (kept_state, cold_state) = (
        kept.principal().expect("kept"),
        cold.principal().expect("cold"),
    );
    assert_eq!(kept_state.projection(), cold_state.projection());
    assert_eq!(kept.tip(), cold.tip());
}

/// The chain a resumed record's state covers, as a store would serve it.
struct Stored(Vec<cyphr_client::PatchEntry>);

impl cyphr_client::ChainSource for Stored {
    fn first(
        &self,
        count: usize,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<cyphr_client::PatchEntry>, String>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move { Ok(self.0[..count].to_vec()) })
    }
}

/// `held`'s verified state as a record that starts from it, with the
/// chain it covers as its store.
async fn resumed(pg: &str, held: &Record) -> Record {
    let state = held
        .principal()
        .expect("held a chain")
        .fork()
        .await
        .expect("copy");
    let store = std::sync::Arc::new(Stored(held.entries().to_vec()));
    Record::resume(pg, state, CLOCK, store).expect("resumes")
}

/// Claim: a verifier that starts from a state it already verified (SPEC
/// 4.5: the trust anchor is the last known trusted state) pulls exactly as
/// one that replayed the chain: it replays only the commits past its tip,
/// holds the state a cold pull of the union gives, and still finds a fork
/// both from a rival peer's chain and from a single peer's evidence, whose
/// proof needs the commits below the state it started from.
///
/// Turns red if: a resumed record replays the history its state covers,
/// ends in another state than a cold pull, or loses a fork finding because
/// it holds no entries below its state.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
#[tokio::test]
async fn a_record_resumed_from_a_verified_state_pulls_as_a_replayed_one_does() {
    let (g, k1, k2, k3, k4) = (kp(), kp(), kp(), kp(), kp());
    let (c1, c2) = ((&k1, T0 + 100), (&k2, T0 + 200));
    let pg = g.tmb.to_b64();
    let short = line(&g, &[c1]).await;
    let long = line(&g, &[c1, c2, (&k4, T0 + 300)]).await;
    let (a, b) = (Fake::new(&pg, &short), Fake::new(&pg, &long));

    let mut held = record(&pg, &g);
    pull(&mut held, &[peer("a", &a)]).await;
    let mut rec = resumed(&pg, &held).await;
    assert_eq!(rec.replayed(), 0, "resuming replays nothing");
    pull(&mut rec, &[peer("b", &b)]).await;
    assert_eq!(rec.replayed(), 2, "only the commits past the state");
    let mut cold = record(&pg, &g);
    pull(&mut cold, &[peer("b", &b)]).await;
    assert_eq!(
        rec.principal().expect("resumed").projection(),
        cold.principal().expect("cold").projection()
    );
    assert_eq!(rec.tip(), cold.tip());

    let main = line(&g, &[c1, c2]).await;
    let rival = line(&g, &[c1, (&k3, T0 + 201)]).await;
    let mut held = record(&pg, &g);
    pull(&mut held, &[peer("main", &Fake::new(&pg, &main))]).await;

    let mut both = Fake::new(&pg, &main);
    both.rival = Some(rival.clone());
    both.evidence = vec![fork_item(&pg, &main, &rival, 2)];
    let mut rec = resumed(&pg, &held).await;
    let report = pull(&mut rec, &[peer("both", &both)]).await;
    assert_eq!(report.forks.len(), 1, "evidence read below the state");
    assert_eq!(rec.tip().expect("tip").commit_id, main.tip());

    let p_rival = Fake::new(&pg, &rival);
    let mut rec = resumed(&pg, &held).await;
    let report = pull(&mut rec, &[peer("rival", &p_rival)]).await;
    assert!(matches!(standing(&report, "rival"), PeerStanding::Forked));
    assert_eq!(report.forks[0].height, 2);
    assert_eq!(rec.tip().expect("tip").commit_id, main.tip());
}

/// Claim: a peer serves every action bundle it holds with each patch, and a
/// verifier replays an action once: a pull that brings one commit and
/// the actions already held replays and logs that commit only; a peer that lists a head the
/// verifier already holds has no rival branch to prove, so its evidence is not fetched; and a peer
/// that cannot be asked from the verifier's tip but serves a longer chain extends the
/// record by exactly the commits past it.
///
/// Turns red if: an action is held twice or dropped, a pull of held
/// actions logs them again or replays more than the new commit, evidence is
/// fetched from a peer whose heads are all held, or the whole-chain path
/// reports the wrong number of added commits.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
#[tokio::test]
async fn held_actions_are_not_replayed_and_the_whole_chain_path_counts_what_it_adds() {
    let (g, k1, k2, k3) = (kp(), kp(), kp(), kp());
    let pg = g.tmb.to_b64();

    let mut chain = Chain::new(&g).await;
    let mut main = Line::of_genesis(&chain);
    let note = chain.action("cyphr.me/comment/create", T0 + 50);
    let blobs = chain.commit(&k1, T0 + 100).await;
    main.push(&chain, blobs);
    let mut peer_with_note = Fake::new(&pg, &main);
    peer_with_note.actions = vec![vec![note]];

    let mut rec = record(&pg, &g);
    pull(&mut rec, &[peer("p", &peer_with_note)]).await;
    let held = |r: &Record| r.principal().expect("held").actions().count();
    assert_eq!(held(&rec), 1, "the action is replayed once");

    // A peer one commit ahead serves the same action again.
    let blobs = chain.commit(&k2, T0 + 200).await;
    main.push(&chain, blobs);
    let mut ahead = Fake::new(&pg, &main);
    ahead.actions = peer_with_note.actions.clone();
    let (mark, replayed) = (rec.log_len(), rec.replayed());
    let report = pull(&mut rec, &[peer("ahead", &ahead)]).await;
    assert!(matches!(
        standing(&report, "ahead"),
        PeerStanding::Extended { added: 1 }
    ));
    assert_eq!(held(&rec), 1, "held once");
    assert_eq!(
        rec.bundles_since(mark).len(),
        1,
        "only the commit is logged"
    );
    assert_eq!(rec.replayed(), replayed + 1);

    // A rival head the verifier already holds: nothing to prove.
    let mut shallow = Fake::new(&pg, &main);
    shallow.rival = Some(line(&g, &[]).await);
    pull(&mut rec, &[peer("shallow", &shallow)]).await;
    assert_eq!(shallow.served("/evidence"), 0);

    let k4 = kp();
    let longer = line(
        &g,
        &[
            (&k1, T0 + 100),
            (&k2, T0 + 200),
            (&k3, T0 + 300),
            (&k4, T0 + 400),
        ],
    )
    .await;
    let mut whole = Fake::new(&pg, &longer);
    whole.whole_only = true;
    let mut rec = record(&pg, &g);
    pull(
        &mut rec,
        &[peer(
            "short",
            &Fake::new(&pg, &line(&g, &[(&k1, T0 + 100)]).await),
        )],
    )
    .await;
    let report = pull(&mut rec, &[peer("whole", &whole)]).await;
    assert!(
        matches!(
            standing(&report, "whole"),
            PeerStanding::Extended { added: 3 }
        ),
        "{:?}",
        standing(&report, "whole")
    );
    assert_eq!(rec.tip().expect("tip").commit_id, longer.tip());
}
