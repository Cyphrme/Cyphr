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
use cyphr_net::login::{self, LoginRequest, SoftwareIssuer};
use cyphr_net::{
    Anchor, BindingKind, ChannelBinding, ConnectError, Connector, PullPeer, Refusal, RelyingParty,
    Request, RpConfig, SessionBinding, UnmetCurrency,
};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000;
const AUDIENCE: &str = "rp.example";
const BOUND: Duration = Duration::from_secs(30);
const REFRESH: Duration = Duration::from_secs(10);
const SESSION_TTL: Duration =
    Duration::from_secs(cyphr_net::login::DEFAULT_SESSION_TTL_SECS.unsigned_abs());

fn config() -> RpConfig {
    let site = coz::Alg::Ed25519.generate_keypair();
    RpConfig {
        audience: AUDIENCE.to_owned(),
        issuer: std::sync::Arc::new(SoftwareIssuer::new(
            site.alg.name(),
            &site.prv_bytes,
            &site.pub_bytes,
        )),
        pull_age_bound: BOUND,
        refresh_interval: REFRESH,
        session_ttl: SESSION_TTL,
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
    /// A retained branch the peer lists beside its canonical one.
    rival: Option<Line>,
    /// The fork evidence the peer serves.
    evidence: Vec<Value>,
}

impl Mirror {
    fn of(line: Line) -> Self {
        Self {
            line,
            rival: None,
            evidence: Vec::new(),
        }
    }
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
                let head = |line: &Line, canonical| {
                    let n = line.ids.len();
                    json!({
                        "tip": line.ids[n - 1],
                        "pre": n.checked_sub(2).map(|i| line.prs[i].clone()),
                        "sequence": n - 1,
                        "canonical": canonical,
                    })
                };
                let mut heads = vec![head(&self.line, true)];
                heads.extend(self.rival.iter().map(|r| head(r, false)));
                json!({ "branches": heads })
            },
            "/patch" => {
                let from = match q.get("from") {
                    None => 0,
                    Some(pr) => match self.line.prs.iter().position(|p| p == pr) {
                        Some(i) => i + 1,
                        None => return Err(ConnectError::NonSuccess(404)),
                    },
                };
                let upto = q
                    .get("to")
                    .and_then(|t| t.parse::<usize>().ok())
                    .map_or(self.line.entries.len(), |t| t + 1);
                let entries: Vec<Value> = self.line.entries[from..upto]
                    .iter()
                    .enumerate()
                    .map(|(i, blobs)| entry_bundle(from + i, blobs))
                    .collect();
                json!({ "entries": entries })
            },
            "/evidence" => json!({ "items": self.evidence }),
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

/// A login signed by `by`, the request the principal's device hands the
/// relying party for `challenge`.
fn login(
    by: &Kp,
    pg: &cyphr::PrincipalGenesis,
    audience: &str,
    challenge: &coz::CozJson,
) -> LoginRequest {
    login_signed(by, pg, audience, challenge, None)
}

fn login_signed(
    by: &Kp,
    pg: &cyphr::PrincipalGenesis,
    audience: &str,
    challenge: &coz::CozJson,
    h: Option<&ChannelBinding>,
) -> LoginRequest {
    let mut pay = json!({
        "alg": by.kp.alg.name(),
        "now": T0,
        "tmb": by.tmb.to_b64(),
        "typ": format!("{audience}{}", login::REQUEST_TYP_SUFFIX),
        "pg": pg.to_string(),
        "challenge": challenge.pay["nonce"],
    });
    if let Some(h) = h {
        pay["h"] = Base64UrlUnpadded::encode_string(h.as_bytes()).into();
    }
    LoginRequest {
        coz: serde_json::from_value(sign_as(by, pay)).expect("coz json"),
        challenge: Some(challenge.clone()),
    }
}

/// A genesis commit opened by `opener` over `{opener} + others`: its line
/// and PG.
async fn genesis_over(opener: &Kp, others: &[&Kp]) -> (Line, cyphr::PrincipalGenesis) {
    let mut p = cyphr::Principal::implicit(opener.domain_key(T0))
        .await
        .expect("genesis");
    let others: Vec<_> = others.iter().map(|k| k.domain_key(T0)).collect();
    p.commit_genesis(&opener.signer(), &others, T0, "cyphr.me")
        .await
        .expect("genesis commit");
    let pg = p.pg().expect("PG").clone();
    let line = Line {
        entries: vec![wire_commit(p.commits().last().expect("commit"))],
        prs: vec![p.pr_tagged().expect("pr")],
        ids: vec![commit_id(&p)],
    };
    (line, pg)
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
    let (pinned, impostor) = (Mirror::of(by_a), Mirror::of(by_b));
    PIN_CLOCK.store(T0 + 100, Ordering::SeqCst);

    // The PG is not a pin: handed over as a genesis commit id it matches no
    // commit, so even the honest chain gives no view.
    let mut pg_only = RelyingParty::new(
        &pg,
        Anchor::GenesisCommit(pg.to_string()),
        config(),
        pin_clock,
    );
    pg_only.refresh(&[peer("pinned", &pinned)]).await;
    let c = pg_only.challenge().expect("challenge");
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
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &c)),
        Err(Refusal::Stale(UnmetCurrency::NoPull)),
        "the other opener's chain must give no view"
    );

    rp.refresh(&[peer("impostor", &impostor), peer("pinned", &pinned)])
        .await;
    let c = rp.challenge().expect("challenge");
    let session = rp
        .sign_in(&login(&a, &pg, AUDIENCE, &c))
        .expect("signed in");
    assert_eq!(session.principal, pg);
    assert_eq!(session.key, a.tmb);
    assert_eq!(session.trust.tip.commits, 1);
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &c)),
        Err(Refusal::ChallengeInvalid),
        "a redeemed challenge signs one login"
    );

    // A challenge another issuer signed, for this audience and fresh, is
    // refused though the login answering it is valid.
    let other = config();
    let foreign =
        login::issue_challenge(other.issuer.as_ref(), AUDIENCE, pin_clock()).expect("issues");
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &foreign)),
        Err(Refusal::ChallengeInvalid)
    );

    // A login for another service, and a replay of a spent challenge.
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&a, &pg, "other.example", &c)),
        Err(Refusal::AudienceMismatch)
    );
    assert_eq!(
        rp.sign_in(&login(&a, &pg, AUDIENCE, &session_challenge_spent(&c))),
        Err(Refusal::ChallengeInvalid)
    );
}

/// `live` altered, so it is not one the relying party signed.
fn session_challenge_spent(live: &coz::CozJson) -> coz::CozJson {
    let mut forged = live.clone();
    forged.pay["nonce"] = "not-the-nonce-it-signed".into();
    forged
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
    let pg = g.pg();
    let mut chain = Chain::new(&g).await;
    let mut line = Line::of(&chain);
    let blobs = chain.commit(&device, T0 + 50).await;
    line.push(&chain, blobs);
    let mut mirror = Mirror::of(line.clone());
    LIFE_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        life_clock,
    );
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge().expect("challenge");
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
    let c = rp.challenge().expect("challenge");
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
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::KeyNotActive)
    );
}

static TTL_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn ttl_clock() -> i64 {
    TTL_CLOCK.load(Ordering::SeqCst)
}

/// Claim: a session ends at its lifetime however current the view and
/// however active the key. A relying party that keeps pulling and whose
/// key is never removed still ends the session at `session_ttl`, drops it
/// for good, and lets the holder sign in again.
///
/// Turns red if: a session outlives `session_ttl` while the view stays
/// current; the end is early; or an expired session revives.
/// End-to-end scenario: yes (a real chain, pulls through the lifetime).
#[tokio::test]
async fn a_session_ends_at_its_lifetime_with_a_current_view() {
    let (g, device) = (kp(), kp());
    let pg = g.pg();
    let mut chain = Chain::new(&g).await;
    let mut line = Line::of(&chain);
    let blobs = chain.commit(&device, T0 + 50).await;
    line.push(&chain, blobs);
    let mirror = Mirror::of(line);
    TTL_CLOCK.store(T0 + 100, Ordering::SeqCst);
    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        ttl_clock,
    );
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge().expect("challenge");
    let session = rp
        .sign_in(&login(&device, &pg, AUDIENCE, &c))
        .expect("signed in");
    let ttl = i64::try_from(SESSION_TTL.as_secs()).expect("fits");
    assert_eq!(session.expires_at, T0 + 100 + ttl);

    TTL_CLOCK.store(T0 + 100 + ttl - 1, Ordering::SeqCst);
    rp.refresh(&[peer("p1", &mirror)]).await;
    rp.check_session(&session.token)
        .expect("live a second before its lifetime");

    TTL_CLOCK.store(T0 + 100 + ttl, Ordering::SeqCst);
    rp.refresh(&[peer("p1", &mirror)]).await;
    assert_eq!(rp.check_session(&session.token), Err(Refusal::Expired));
    assert_eq!(
        rp.check_session(&session.token),
        Err(Refusal::NoSession),
        "an expired session stays ended"
    );
    let c = rp.challenge().expect("challenge");
    rp.sign_in(&login(&device, &pg, AUDIENCE, &c))
        .expect("signing in again opens a fresh session");
}

static SWEEP_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn sweep_clock() -> i64 {
    SWEEP_CLOCK.load(Ordering::SeqCst)
}

/// Claim: a session that reached its lifetime and was never presented again
/// is dropped by the next sign-in, so abandoned sessions do not pile up.
/// Observed as the old token being unknown (`NoSession`), where presenting
/// it without the sweep would answer `Expired`.
/// Turns red if sign-in leaves expired sessions in place.
/// End-to-end scenario: yes (a real chain and two sign-ins).
#[tokio::test]
async fn an_expired_session_is_swept_at_the_next_sign_in() {
    let (g, device) = (kp(), kp());
    let pg = g.pg();
    let mut chain = Chain::new(&g).await;
    let mut line = Line::of(&chain);
    let blobs = chain.commit(&device, T0 + 50).await;
    line.push(&chain, blobs);
    let mirror = Mirror::of(line);
    SWEEP_CLOCK.store(T0 + 100, Ordering::SeqCst);
    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        sweep_clock,
    );
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge().expect("challenge");
    let first = rp
        .sign_in(&login(&device, &pg, AUDIENCE, &c))
        .expect("signed in");

    let ttl = i64::try_from(SESSION_TTL.as_secs()).expect("fits");
    SWEEP_CLOCK.store(T0 + 100 + ttl, Ordering::SeqCst);
    rp.refresh(&[peer("p1", &mirror)]).await;
    let c = rp.challenge().expect("challenge");
    rp.sign_in(&login(&device, &pg, AUDIENCE, &c))
        .expect("signed in again");
    assert_eq!(rp.check_session(&first.token), Err(Refusal::NoSession));
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
        pg.wire_digest(),
        a.tmb.to_b64(),
        "the fixture's PG must differ from the anchor"
    );
    let mirror = Mirror::of(line);
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
    let c = rp.challenge().expect("challenge");
    let session = rp
        .sign_in(&login(&b, &pg, AUDIENCE, &c))
        .expect("signed in");
    assert_eq!(session.principal, pg, "the subject is the replayed PG");
    assert_ne!(
        session.principal.wire_digest(),
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
    pg: &cyphr::PrincipalGenesis,
    challenge: &coz::CozJson,
    h: Option<&ChannelBinding>,
) -> LoginRequest {
    login_signed(by, pg, AUDIENCE, challenge, h)
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
    let pg = g.pg();
    let chain = Chain::new(&g).await;
    let mirror = Mirror::of(Line::of(&chain));
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
    let c = rp.challenge().expect("challenge");
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
    let c = rp.challenge().expect("challenge");
    let reposted = login_committing(&g, &pg, &c, Some(&here));
    assert_eq!(
        rp.sign_in_on(&reposted, &on_elsewhere),
        Err(Refusal::ChannelMismatch)
    );

    let c = rp.challenge().expect("challenge");
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

// Each test owns its clock: a `Clock` is a bare `fn`, so sharing one
// static between parallel tests lets one test's time bleed into another's.
static FORK_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn fork_clock() -> i64 {
    FORK_CLOCK.load(Ordering::SeqCst)
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
    let pg = g.pg();
    let mut honest = Chain::new(&g).await;
    let mut honest_line = Line::of(&honest);
    let blobs = honest.commit(&device, T0 + 50).await;
    honest_line.push(&honest, blobs);
    let mut rival = Chain::new(&g).await;
    let mut rival_line = Line::of(&rival);
    let blobs = rival.commit(&rival_key, T0 + 60).await;
    rival_line.push(&rival, blobs);
    let honest_peer = Mirror::of(honest_line);
    let rival_peer = Mirror::of(rival_line);
    FORK_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        fork_clock,
    );
    let report = rp
        .refresh(&[peer("honest", &honest_peer), peer("rival", &rival_peer)])
        .await;
    assert!(!report.forks.is_empty(), "the rival peer shows a fork");
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::Forked)
    );

    // The rival peer no longer shows it; only the honest peer answers.
    let report = rp.refresh(&[peer("honest", &honest_peer)]).await;
    assert!(report.forks.is_empty(), "this pull shows no fork");
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::Forked),
        "a proved fork stays recorded until a verified resolution"
    );
}

static RESOLVED_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn resolved_clock() -> i64 {
    RESOLVED_CLOCK.load(Ordering::SeqCst)
}

/// The genesis commit of `g`, then one `key/create` commit per `(key, now)`.
/// Ed25519 signs deterministically, so two lines built from one prefix
/// share it exactly and differ only where the caller makes them differ.
async fn grown(g: &Kp, grow: &[(&Kp, i64)]) -> Line {
    let mut chain = Chain::new(g).await;
    let mut line = Line::of(&chain);
    for (key, now) in grow {
        let blobs = chain.commit(key, *now).await;
        line.push(&chain, blobs);
    }
    line
}

/// A peer holding both branches of the fork at `height`, and proving it.
fn forked_peer(
    pg: &cyphr::PrincipalGenesis,
    canonical: &Line,
    rival: &Line,
    height: usize,
) -> Mirror {
    let mut peer = Mirror::of(canonical.clone());
    peer.rival = Some(rival.clone());
    peer.evidence = vec![json!({
        "kind": "principal-fork",
        "pg": pg.wire_digest(),
        "height": height,
        "pre": height.checked_sub(1).map(|i| canonical.prs[i].clone()),
        "a": entry_bundle(height, &canonical.entries[height]),
        "b": entry_bundle(height, &rival.entries[height]),
    })];
    peer
}

/// SPEC 15.6, 15.8: a fork is resolved by a commit that extends one
/// branch, and the principal is Active again. The relying party holds the
/// fork's commits from every pull and asks the protocol's own rule
/// (`cyphr::fork::assessment`), so it refuses while two branches tie and
/// signs the principal in once exactly one branch is extended, though it
/// proved the fork earlier.
///
/// Turns red if the fork is remembered as a flag no later pull can clear.
/// End-to-end scenario: yes (the same peer, first with the fork standing,
/// then with one branch extended).
#[tokio::test]
async fn a_relying_party_signs_in_after_the_fork_it_proved_is_resolved() {
    let (g, device, k2, k3, k4) = (kp(), kp(), kp(), kp(), kp());
    let pg = g.pg();
    let c1 = (&device, T0 + 50);
    let standing = grown(&g, &[c1, (&k2, T0 + 60)]).await;
    let abandoned = grown(&g, &[c1, (&k3, T0 + 61)]).await;
    let resolved = grown(&g, &[c1, (&k2, T0 + 60), (&k4, T0 + 70)]).await;
    assert_eq!(standing.prs[1], abandoned.prs[1], "one shared pre");
    RESOLVED_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        resolved_clock,
    );
    let tied = forked_peer(&pg, &standing, &abandoned, 2);
    let report = rp.refresh(&[peer("p1", &tied)]).await;
    assert_eq!(report.forks.len(), 1, "the fork is proved");
    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)),
        Err(Refusal::Forked),
        "two tied branches are an unresolved fork"
    );

    let settled = forked_peer(&pg, &resolved, &abandoned, 2);
    rp.refresh(&[peer("p1", &settled)]).await;
    let c = rp.challenge().expect("challenge");
    assert!(
        rp.sign_in(&login(&device, &pg, AUDIENCE, &c)).is_ok(),
        "only one branch is extended: the principal is Active"
    );
}

static LOST_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn lost_clock() -> i64 {
    LOST_CLOCK.load(Ordering::SeqCst)
}

/// SPEC 15.8: the abandoned branch's transactions become permanently
/// invalid, and a key only that branch added is not part of the key set. A
/// relying party whose own chain is the branch that lost the fork must not
/// sign in a key that branch alone added, though the protocol's rule now
/// reads the principal as Active.
///
/// Turns red if sign-in reads keys from a chain the fork rule discarded.
/// End-to-end scenario: yes (the record follows one peer onto the branch
/// another peer's extended chain then abandons).
#[tokio::test]
async fn a_relying_party_on_the_lost_branch_refuses_its_own_branchs_keys() {
    let (g, device, k2, thief, k4) = (kp(), kp(), kp(), kp(), kp());
    let pg = g.pg();
    let c1 = (&device, T0 + 50);
    let abandoned = grown(&g, &[c1, (&thief, T0 + 61)]).await;
    let kept = grown(&g, &[c1, (&k2, T0 + 60), (&k4, T0 + 70)]).await;
    LOST_CLOCK.store(T0 + 100, Ordering::SeqCst);

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        lost_clock,
    );
    let first = Mirror::of(abandoned);
    rp.refresh(&[peer("first", &first)]).await;
    let second = Mirror::of(kept);
    let report = rp.refresh(&[peer("second", &second)]).await;
    assert_eq!(report.forks.len(), 1, "the extended chain shows the fork");

    let c = rp.challenge().expect("challenge");
    assert_eq!(
        rp.sign_in(&login(&thief, &pg, AUDIENCE, &c)),
        Err(Refusal::LostBranch),
        "a key only the abandoned branch added"
    );
}

/// A peer that also proves its log, as a real server does: `/tip`'s
/// `root` and `/proof` come from its chain's own commit trees. It records the
/// paths asked, so a test can pin which route a pull took.
struct ProofMirror {
    mirror: Mirror,
    principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    asked: std::sync::Mutex<Vec<String>>,
    /// The whole targets asked, query included.
    targets: std::sync::Mutex<Vec<String>>,
    /// `/proof` answers that crossed an algorithm rotation.
    stitched: std::sync::atomic::AtomicUsize,
}

impl Connector for ProofMirror {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let target = request.target.as_str();
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        self.asked.lock().expect("asked").push(path.to_owned());
        self.targets
            .lock()
            .expect("targets")
            .push(target.to_owned());
        let number = |name: &str| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .find(|(k, _)| *k == name)
                .and_then(|(_, v)| v.parse::<u64>().ok())
        };
        let payload = match path {
            "/tip" => {
                let size = self.principal.commit_count() as u64;
                json!({ "root": self.principal.root_at(size).expect("a root") })
            },
            "/proof" => {
                let size = number("size").ok_or(ConnectError::NonSuccess(400))?;
                let from = q
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .find(|(k, _)| *k == "claim")
                    .and_then(|(_, v)| v.strip_prefix("extends:"))
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(ConnectError::NonSuccess(400))?;
                let certificate = self
                    .principal
                    .prove(
                        size,
                        &cyphr::proof::Claim::Extends {
                            from,
                            head: self.principal.root_at(size).expect("a head").pr,
                        },
                    )
                    .await
                    .map_err(|_| ConnectError::NonSuccess(404))?;
                let payload = json!({ "certificate": certificate });
                if payload["certificate"]["stitches"]
                    .as_array()
                    .is_some_and(|s| !s.is_empty())
                {
                    self.stitched.fetch_add(1, Ordering::SeqCst);
                }
                payload
            },
            _ => return self.mirror.exchange(request).await,
        };
        Ok(serde_json::to_vec(
            &json!({ "v": 1, "payload": payload, "statement": { "kind": "unsigned" } }),
        )
        .expect("json"))
    }
}

/// `grown`, with the chain's principal for a peer that proves its log.
async fn grown_proving(
    g: &Kp,
    grow: &[(&Kp, i64)],
) -> (Line, cyphr::Principal<cyphr::eml::MemoryStorage>) {
    let mut chain = Chain::new(g).await;
    let mut line = Line::of(&chain);
    for (key, now) in grow {
        let blobs = chain.commit(key, *now).await;
        line.push(&chain, blobs);
    }
    (line, chain.principal)
}

static LOCATED_CLOCK: AtomicI64 = AtomicI64::new(T0);
fn located_clock() -> i64 {
    LOCATED_CLOCK.load(Ordering::SeqCst)
}

/// The lost-branch scenario over peers that serve proofs, so the pull
/// finds the fork by extension proofs (`locate_fork`)
/// instead of comparing whole chains. Pins that the same refusal holds on
/// the route real servers take.
///
/// Turns red if `fork_refusal` is bypassed (the key signs in), or if the pull falls back to
/// the whole-chain path (the route assertions).
/// End-to-end scenario: yes.
#[tokio::test]
async fn a_lost_branch_is_refused_when_the_fork_is_located_by_proofs() {
    let (g, device, k2, thief, k4) = (kp(), kp(), kp(), kp(), kp());
    let pg = g.pg();
    let c1 = (&device, T0 + 50);
    let (abandoned, abandoned_log) = grown_proving(&g, &[c1, (&thief, T0 + 61)]).await;
    let (kept, kept_log) = grown_proving(&g, &[c1, (&k2, T0 + 60), (&k4, T0 + 70)]).await;
    LOCATED_CLOCK.store(T0 + 100, Ordering::SeqCst);
    let proving = |line, principal| ProofMirror {
        mirror: Mirror::of(line),
        principal,
        asked: std::sync::Mutex::default(),
        targets: std::sync::Mutex::default(),
        stitched: std::sync::atomic::AtomicUsize::default(),
    };
    let (first, second) = (proving(abandoned, abandoned_log), proving(kept, kept_log));

    let mut rp = RelyingParty::new(
        &pg,
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        located_clock,
    );
    let on = |name, p| PullPeer { name, connector: p };
    rp.refresh(&[on("first", &first)]).await;
    let report = rp.refresh(&[on("second", &second)]).await;
    assert_eq!(report.forks.len(), 1, "the fork is found");

    let asked = second.asked.lock().expect("asked");
    assert!(
        asked.iter().any(|p| p == "/proof"),
        "/proof not asked: {asked:?}"
    );
    // The locate path proves the one rival commit at the fork and fetches
    // nothing past it, so a tie at the fork's height reads as `Forked`:
    // still a refusal, as the record's key set is an abandoned branch's,
    // but not yet the exact `LostBranch`. The assertion accepts both so it
    // pins the refusal, not the label, until the locate path also fetches
    // the kept line's extension (the whole-chain path, which does, gives
    // `LostBranch`: see the test above).
    let c = rp.challenge().expect("challenge");
    let got = rp.sign_in(&login(&thief, &pg, AUDIENCE, &c));
    assert!(
        matches!(got, Err(Refusal::Forked | Refusal::LostBranch)),
        "a key only the abandoned branch added: {got:?}"
    );
}

/// A key of `alg`, in the shape the fixtures use.
fn kp_of(alg: coz::Alg) -> Kp {
    let kp = alg.generate_keypair();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("thumbprint");
    Kp { kp, tmb }
}

/// One commit of `p`: `by` signs `typ` (`create` or `replace`) of `target`.
async fn commit_key(
    p: &mut cyphr::Principal<cyphr::eml::MemoryStorage>,
    by: &Kp,
    typ: &str,
    target: &Kp,
    now: i64,
) -> Vec<String> {
    let pay = serde_json::to_vec(&json!({
        "alg": by.kp.alg.name(),
        "id": target.tmb.to_b64(),
        "now": now,
        "tmb": by.tmb.to_b64(),
        "typ": format!("cyphr.me/cyphr/key/{typ}"),
    }))
    .expect("pay");
    let (sig, cad) =
        coz::sign_json(&pay, by.kp.alg.name(), &by.kp.prv_bytes, &by.kp.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, by.kp.alg.name()).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(target.domain_key(now)))
        .expect("applies");
    scope
        .finalize_with_software(&by.signer(), now, "cyphr.me")
        .await
        .expect("commit");
    wire_commit(p.commits().last().expect("a commit"))
}

/// `keys`, each paired with its commit time.
fn timed(keys: &[Kp]) -> Vec<(&Kp, i64)> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| (k, T0 + 20 + i as i64))
        .collect()
}

/// An Ed25519 principal that rotates to ES256 at its second commit (its
/// SHA-512 tree closes there, SHA-256 carries on), then grows by one
/// `key/create` by the ES256 key for each of `grow`.
async fn rotated(
    g: &Kp,
    h: &Kp,
    grow: &[(&Kp, i64)],
) -> (Line, cyphr::Principal<cyphr::eml::MemoryStorage>) {
    let mut chain = Chain::new(g).await;
    let mut line = Line::of(&chain);
    let blobs = commit_key(&mut chain.principal, g, "replace", h, T0 + 10).await;
    line.push(&chain, blobs);
    for (key, now) in grow {
        let blobs = commit_key(&mut chain.principal, h, "create", key, *now).await;
        line.push(&chain, blobs);
    }
    (line, chain.principal)
}

/// The fork is found by extension proofs across an algorithm rotation, and
/// the pull stays on them: no whole chain is fetched, the asks are
/// logarithmic, and at least one proof crossed the rotation by a stitch.
///
/// Turns red if the search falls back to the whole chain (`/patch` without
/// an anchor), or asks linearly, or a proof across the rotation is refused.
/// End-to-end scenario: yes.
#[tokio::test]
async fn a_fork_across_a_rotation_is_located_on_the_proof_path() {
    let (g, h) = (kp(), kp_of(coz::Alg::ES256));
    let ours: Vec<Kp> = (0..4).map(|_| kp()).collect();
    let theirs: Vec<Kp> = (0..6).map(|_| kp()).collect();
    let (held_line, held_log) = rotated(&g, &h, &timed(&ours)).await;
    let (rival_line, rival_log) = rotated(&g, &h, &timed(&theirs)).await;
    LOCATED_CLOCK.store(T0 + 100, Ordering::SeqCst);
    let proving = |line, principal| ProofMirror {
        mirror: Mirror::of(line),
        principal,
        asked: std::sync::Mutex::default(),
        targets: std::sync::Mutex::default(),
        stitched: std::sync::atomic::AtomicUsize::default(),
    };
    let (first, second) = (proving(held_line, held_log), proving(rival_line, rival_log));

    let mut rp = RelyingParty::new(
        &g.pg(),
        Anchor::GenesisKey(g.domain_key(T0)),
        config(),
        located_clock,
    );
    let on = |name, p| PullPeer { name, connector: p };
    rp.refresh(&[on("first", &first)]).await;
    let report = rp.refresh(&[on("second", &second)]).await;
    assert_eq!(report.forks.len(), 1, "the fork is found");
    assert_eq!(
        report.forks[0].height, 2,
        "the logs part after the rotation"
    );

    let targets = second.targets.lock().expect("targets");
    let patches: Vec<_> = targets.iter().filter(|t| t.starts_with("/patch")).collect();
    assert!(
        patches.iter().all(|t| t.contains("&from=")),
        "the whole chain was fetched: {patches:?}"
    );
    assert_eq!(patches.len(), 1, "one rival commit: {patches:?}");
    // The pull's own ask, then the search over the six commits held: at
    // most ceil(log2 7) + 1 more.
    let proofs = targets.iter().filter(|t| t.starts_with("/proof")).count();
    assert!((2..=6).contains(&proofs), "{proofs} asks: {targets:?}");
    assert!(
        second.stitched.load(Ordering::SeqCst) >= 1,
        "no proof crossed the rotation: {targets:?}"
    );
}
