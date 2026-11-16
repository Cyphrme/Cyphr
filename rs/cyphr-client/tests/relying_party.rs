//! The separated relying party (SPEC 17.2, 17.5): it signs a principal in
//! only on the key set it replayed from its own pin, and only while its own
//! pull is recent. Peers are carriers that play honest or hostile mirrors of
//! real chains built with `cyphr`; nothing here trusts what a peer says.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use common::*;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{
    Anchor, BindingKind, ChannelBinding, ConnectError, Connector, PullPeer, Refusal, RelyingParty,
    Request, RpConfig, SessionBinding, UnmetCurrency,
};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000;
const AUDIENCE: &str = "rp.example";
const BOUND: Duration = Duration::from_secs(30);
const REFRESH: Duration = Duration::from_secs(10);

fn config() -> RpConfig {
    RpConfig {
        audience: AUDIENCE.to_owned(),
        pull_age_bound: BOUND,
        refresh_interval: REFRESH,
    }
}

/// A mirror of one chain: each commit's blobs, and the PR and commit id
/// reached after it.
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
    fn of(chain: &Chain<'_>) -> Self {
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
}

/// A peer serving one line as its canonical branch.
struct Mirror {
    line: Line,
}

impl Connector for Mirror {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let target = request.target.as_str();
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        let q: BTreeMap<_, _> = q
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.replace("%3A", ":")))
            .collect();
        let payload = match path {
            "/branches" => {
                let n = self.line.ids.len();
                json!({ "branches": [{
                    "tip": self.line.ids[n - 1],
                    "pre": n.checked_sub(2).map(|i| self.line.prs[i].clone()),
                    "sequence": n - 1,
                    "canonical": true,
                }] })
            },
            "/patch" => {
                let from = match q.get("from") {
                    None => 0,
                    Some(pr) => match self.line.prs.iter().position(|p| p == pr) {
                        Some(i) => i + 1,
                        None => return Err(ConnectError::NonSuccess(404)),
                    },
                };
                let entries: Vec<Value> = self.line.entries[from..]
                    .iter()
                    .enumerate()
                    .map(|(i, blobs)| entry_bundle(from + i, blobs))
                    .collect();
                json!({ "entries": entries })
            },
            "/evidence" => json!({ "items": [] }),
            "/revoked" => json!({ "revoked": [] }),
            other => return Err(ConnectError::Unreachable(format!("no route {other}"))),
        };
        Ok(serde_json::to_vec(
            &json!({ "v": 1, "payload": payload, "statement": { "kind": "unsigned" } }),
        )
        .expect("json"))
    }
}

fn peer<'a>(name: &'a str, m: &'a Mirror) -> PullPeer<'a, Mirror> {
    PullPeer { name, connector: m }
}

/// A login signed by `by`, the Coz the principal's device hands the
/// relying party for `challenge`.
fn login(by: &Kp, pg: &str, audience: &str, challenge: &str) -> coz::CozJson {
    let pay = json!({
        "alg": by.kp.alg.name(),
        "now": T0,
        "tmb": by.tmb.to_b64(),
        "typ": format!("{audience}/cyphr/auth/login"),
        "pr": pg,
        "challenge": challenge,
    });
    serde_json::from_value(sign_as(by, pay)).expect("coz json")
}

/// A genesis commit opened by `opener` over `{opener} + others`: its line
/// and bare PG.
async fn genesis_over(opener: &Kp, others: &[&Kp]) -> (Line, String) {
    use cyphr::StateDigest as _;
    let mut p = cyphr::Principal::implicit(opener.domain_key(T0))
        .await
        .expect("genesis");
    let others: Vec<_> = others.iter().map(|k| k.domain_key(T0)).collect();
    p.commit_genesis(&opener.signer(), &others, T0, "cyphr.me")
        .await
        .expect("genesis commit");
    let tagged = p
        .pg()
        .expect("PG")
        .as_multihash()
        .tagged_first()
        .expect("pg")
        .to_string();
    let line = Line {
        entries: vec![wire_commit(p.commits().last().expect("commit"))],
        prs: vec![p.pr_tagged().expect("pr")],
        ids: vec![commit_id(&p)],
    };
    (line, tagged.split_once(':').expect("tagged").1.to_owned())
}

static PIN_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn pin_clock() -> i64 {
    PIN_CLOCK.load(Ordering::SeqCst)
}

/// Claim: sign-on trusts only what the relying party replayed from its own
/// pin. Two genesis commits over one key set, differing only in which key
/// opens, derive one PG. A relying party pinned to the genesis key of one
/// refuses the other chain (so it holds no view and signs nobody in), and
/// accepts the pinned one; a PG given where a genesis commit id belongs is
/// no pin and fails the same way. Nothing reaches a verdict through a
/// peer's word.
///
/// Turns red if: a PG-only pin works, the other opener's chain gives the
/// relying party a view, or a sign-in succeeds without one.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
#[tokio::test]
async fn pin_decides_which_chain_the_relying_party_trusts() {
    let (a, b) = (kp(), kp());
    let (by_a, pg) = genesis_over(&a, &[&b]).await;
    let (by_b, pg_b) = genesis_over(&b, &[&a]).await;
    assert_eq!(pg, pg_b, "one key set, one PG");
    let (pinned, impostor) = (Mirror { line: by_a }, Mirror { line: by_b });
    PIN_CLOCK.store(T0 + 100, Ordering::SeqCst);

    // The PG is not a pin: handed over as a genesis commit id it matches no
    // commit, so even the honest chain gives no view.
    let mut pg_only =
        RelyingParty::new(&pg, Anchor::GenesisCommit(pg.clone()), config(), pin_clock);
    pg_only.refresh(&[peer("pinned", &pinned)]).await;
    let c = pg_only.challenge();
    assert_eq!(
        pg_only.sign_in(&login(&a, &pg, AUDIENCE, &c)),
        Err(Refusal::Stale(UnmetCurrency::NoPull)),
        "a PG-only pin must not give a view"
    );

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(a.domain_key(T0)),
        config(),
        pin_clock,
    );
    rp.refresh(&[peer("impostor", &impostor)]).await;
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &c)),
        Err(Refusal::Stale(UnmetCurrency::NoPull)),
        "the other opener's chain must give no view"
    );

    rp.refresh(&[peer("impostor", &impostor), peer("pinned", &pinned)])
        .await;
    let c = rp.challenge();
    let session = rp
        .sign_in(&login(&a, &pg, AUDIENCE, &c))
        .expect("signed in");
    assert_eq!(session.principal, pg);
    assert_eq!(session.key, a.tmb);
    assert_eq!(session.trust.tip.commits, 1);

    // A login for another service, and a replay of a spent challenge.
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&a, &pg, "other.example", &c)),
        Err(Refusal::AudienceMismatch)
    );
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &session_challenge_spent(&c))),
        Err(Refusal::ChallengeInvalid)
    );
}

fn session_challenge_spent(live: &str) -> String {
    // Any value the relying party did not issue reads as spent.
    format!("{live}x")
}

static LIFE_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn life_clock() -> i64 {
    LIFE_CLOCK.load(Ordering::SeqCst)
}

/// Claim: a revoked device loses access within a stated bound, and a view
/// older than the bound authorizes nothing. The principal adds a second key
/// and signs in with it; the relying party then holds a session. Past the
/// pull age bound with no pull the session ends and a new sign-in is refused
/// naming the pull age; once a pull replays the removal, the session ends
/// naming the key, and the removed key cannot sign in again.
///
/// Turns red if: a stale view authorizes a sign-in or keeps a session; a
/// removed key keeps its session after the pull that replayed the removal;
/// or the verdict does not name the unmet currency.
/// End-to-end scenario: yes (real chains, a removal replayed by pull).
#[tokio::test]
async fn session_ends_on_stale_view_and_on_replayed_removal() {
    let (g, device) = (kp(), kp());
    let pg = g.tmb.to_b64();
    let mut chain = Chain::new(&g).await;
    let mut line = Line::of(&chain);
    let blobs = chain.commit(&device, T0 + 50).await;
    line.push(&chain, blobs);
    let mut mirror = Mirror { line: line.clone() };
    LIFE_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        life_clock,
    );
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge();
    let session = rp
        .sign_in(&login(&device, &pg, AUDIENCE, &c))
        .expect("signed in");
    let trust = rp.check_session(&session.token).expect("live");
    assert_eq!(trust.pull_age, Duration::ZERO);
    assert_eq!(
        trust.principal_now_age,
        Some(Duration::from_secs(50)),
        "the principal's newest signed now is reported beside the pull age"
    );

    // No pull for longer than the bound: the view is stale.
    LIFE_CLOCK.store(T0 + 100 + 31, Ordering::SeqCst);
    let stale = Refusal::Stale(UnmetCurrency::PullAge {
        age: Duration::from_secs(31),
        bound: BOUND,
    });
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(stale.clone())
    );
    assert_eq!(rp.check_session(&session.token), Err(stale));

    // The principal removes the device; the peer holds the removal.
    let blobs = chain.revoke(&device, T0 + 120).await;
    line.push(&chain, blobs);
    mirror.line = line;
    rp.refresh(&[peer("p1", &mirror)]).await;
    assert_eq!(
        rp.check_session(&session.token),
        Err(Refusal::NoSession),
        "an ended session stays ended"
    );
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::KeyNotActive)
    );
}

fn noise_binding(h: u8) -> ChannelBinding {
    ChannelBinding::new(BindingKind::NoiseHandshakeHash, vec![h; 32])
}

static ANCHOR_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn anchor_clock() -> i64 {
    ANCHOR_CLOCK.load(Ordering::SeqCst)
}

/// Claim: the relying party reports the anchor it was enrolled with, and
/// the subject of a session is the principal its replayed record names,
/// never the anchor. The genesis commit opens over two keys, so the PG is
/// not the opener's thumbprint: a check that took the anchor's key
/// thumbprint for the subject (or the PG string for the anchor) fails here,
/// where on a single-key genesis the two strings are equal and every such
/// check passes.
///
/// Turns red if: the reported anchor is not the genesis key, the subject
/// equals the anchor's thumbprint, or the subject is not the replayed PG.
/// End-to-end scenario: yes (real chain over a carrier that plays a peer).
#[tokio::test]
async fn anchor_is_reported_and_subject_is_the_replayed_pg() {
    let (a, b) = (kp(), kp());
    let (line, pg) = genesis_over(&a, &[&b]).await;
    assert_ne!(
        pg,
        a.tmb.to_b64(),
        "the fixture's PG must differ from the anchor"
    );
    let mirror = Mirror { line };
    ANCHOR_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(a.domain_key(T0)),
        config(),
        anchor_clock,
    );
    match rp.anchor() {
        Anchor::GenesisKey(key) => assert_eq!(key.tmb(), &a.tmb, "the enrolled genesis key"),
        other => panic!("enrolled at the genesis key, reports {other:?}"),
    }
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge();
    let session = rp
        .sign_in(&login(&b, &pg, AUDIENCE, &c))
        .expect("signed in");
    assert_eq!(session.principal, pg, "the subject is the replayed PG");
    assert_ne!(
        session.principal,
        a.tmb.to_b64(),
        "not the anchor's thumbprint"
    );
    assert_eq!(session.trust.principal, pg);
}

static BIND_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn bind_clock() -> i64 {
    BIND_CLOCK.load(Ordering::SeqCst)
}

/// A carrier on one authenticated channel: all the relying party reads of
/// a session is the binding its carrier reports.
struct OnChannel(ChannelBinding);

impl Connector for OnChannel {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        Some(&self.0)
    }

    async fn exchange(&self, _: &Request) -> Result<Vec<u8>, ConnectError> {
        Err(ConnectError::Unreachable("no peer".into()))
    }
}

/// `by`'s login for `challenge`, signing the channel `h` into it when given.
fn login_committing(
    by: &Kp,
    pg: &str,
    challenge: &str,
    h: Option<&ChannelBinding>,
) -> coz::CozJson {
    let mut pay = json!({
        "alg": by.kp.alg.name(),
        "now": T0,
        "tmb": by.tmb.to_b64(),
        "typ": format!("{AUDIENCE}/cyphr/auth/login"),
        "pr": pg,
        "challenge": challenge,
    });
    if let Some(h) = h {
        pay["h"] = Base64UrlUnpadded::encode_string(h.as_bytes()).into();
    }
    serde_json::from_value(sign_as(by, pay)).expect("coz json")
}

/// Claim (SPEC 17.5 session binding): a native client's login commits to
/// the channel it is sent on, and the session works only there. The relying
/// party takes the channel from the carrier it is actually on, never from a
/// caller's say-so: a login signing another channel's hash, one signing
/// none, and one signing a hash sent with no channel are all refused. A
/// token on a second channel or none is refused without ending the session;
/// a browser edge, which has no channel, binds to its key.
///
/// Turns red if: a login is accepted on a channel it did not sign, a
/// channel-bound token is accepted off its channel or the refusal ends the
/// session, or a key-bound session is bound to a channel.
/// End-to-end scenario: yes (real chain, three sign-ins, two channels).
#[tokio::test]
async fn login_commits_to_its_channel_and_the_token_stays_on_it() {
    let g = kp();
    let pg = g.tmb.to_b64();
    let chain = Chain::new(&g).await;
    let mirror = Mirror {
        line: Line::of(&chain),
    };
    BIND_CLOCK.store(T0 + 100, Ordering::SeqCst);
    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        bind_clock,
    );
    rp.refresh(&[peer("p1", &mirror)]).await;

    let (here, elsewhere) = (noise_binding(1), noise_binding(2));
    let (on_here, on_elsewhere) = (OnChannel(here.clone()), OnChannel(elsewhere.clone()));

    // Refused: the login names another channel, none, or a channel with no
    // carrier channel.
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in_on(&login_committing(&g, &pg, &c, Some(&elsewhere)), &on_here),
        Err(Refusal::ChannelMismatch)
    );
    assert_eq!(
        rp.sign_in_on(&login_committing(&g, &pg, &c, None), &on_here),
        Err(Refusal::ChannelMismatch)
    );
    assert_eq!(
        rp.sign_in(&login_committing(&g, &pg, &c, Some(&here))),
        Err(Refusal::ChannelMismatch)
    );

    // Accepted on the channel it signed (the refusals above spent nothing).
    let native = rp
        .sign_in_on(&login_committing(&g, &pg, &c, Some(&here)), &on_here)
        .expect("native sign-in");
    assert_eq!(native.binding, SessionBinding::Channel(here.clone()));
    assert!(rp.check_session_on(&native.token, Some(&here)).is_ok());
    for off in [Some(&elsewhere), None] {
        assert_eq!(
            rp.check_session_on(&native.token, off),
            Err(Refusal::ChannelMismatch)
        );
    }
    assert!(
        rp.check_session_on(&native.token, Some(&here)).is_ok(),
        "a refused presentation must not end the session"
    );
    // The same login on a second channel is refused, though its challenge
    // is spent: the second sign-in needs a fresh login.
    let c = rp.challenge();
    let reposted = login_committing(&g, &pg, &c, Some(&here));
    assert_eq!(
        rp.sign_in_on(&reposted, &on_elsewhere),
        Err(Refusal::ChannelMismatch)
    );

    let c = rp.challenge();
    let browser = rp
        .sign_in(&login_committing(&g, &pg, &c, None))
        .expect("edge");
    assert_eq!(browser.binding, SessionBinding::Key);
    assert!(rp.check_session(&browser.token).is_ok());
    assert!(
        rp.check_session_on(&browser.token, Some(&elsewhere))
            .is_ok()
    );
}

/// archrev:B1. Claim: a fork the relying party has proved stays recorded
/// (SPEC 15.7.1 "Witnesses should keep such transaction as proof of
/// error"): a later pull that only the honest peer answers must not clear
/// it, or sign-in resumes just because the peer that showed the fork went
/// silent.
///
/// Turns red if the fork flag is recomputed from the latest pull alone.
/// End-to-end scenario: yes (two diverging real chains, then a pull the
/// rival peer does not answer).
#[tokio::test]
async fn archrev_b1_proved_fork_survives_a_pull_the_rival_peer_misses() {
    let (g, device, rival_key) = (kp(), kp(), kp());
    let pg = g.tmb.to_b64();
    let mut honest = Chain::new(&g).await;
    let mut honest_line = Line::of(&honest);
    let blobs = honest.commit(&device, T0 + 50).await;
    honest_line.push(&honest, blobs);
    let mut rival = Chain::new(&g).await;
    let mut rival_line = Line::of(&rival);
    let blobs = rival.commit(&rival_key, T0 + 60).await;
    rival_line.push(&rival, blobs);
    let honest_peer = Mirror { line: honest_line };
    let rival_peer = Mirror { line: rival_line };
    LIFE_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        life_clock,
    );
    let report = rp
        .refresh(&[peer("honest", &honest_peer), peer("rival", &rival_peer)])
        .await;
    assert!(!report.forks.is_empty(), "the rival peer shows a fork");
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::Forked)
    );

    // The rival peer no longer shows it; only the honest peer answers.
    let report = rp.refresh(&[peer("honest", &honest_peer)]).await;
    assert!(report.forks.is_empty(), "this pull shows no fork");
    let c = rp.challenge();
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::Forked),
        "a proved fork stays recorded until a verified resolution"
    );
}
