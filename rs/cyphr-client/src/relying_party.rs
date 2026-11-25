//! A separated relying party (SPEC 17.2, 17.5): a service that signs a
//! principal in only on what it replayed itself.
//!
//! The relying party holds a [`Record`] of one principal, anchored at the
//! genesis key or the genesis commit id ([`Anchor`]): never the PG alone,
//! because one key set under different openers derives one PG, so a PG
//! cannot tell the principal the relying party was pinned to from another
//! opener's chain. It keeps the record current with [`RelyingParty::refresh`]
//! (the pull step over peers it chose) and decides a login only from the
//! key set that replay produced. No peer's statement is believed.
//!
//! Currency is the relying party's own: the **pull age**, how long ago its
//! newest successful pull of the principal's chain finished, on its own
//! clock. Beyond [`RpConfig::pull_age_bound`] it refuses to sign anyone in
//! and ends the sessions it holds, naming the unmet currency
//! ([`Refusal::Stale`]). The principal's newest signed `now` is reported
//! beside it ([`Trust::principal_now_age`]) but never decides.
//!
//! A removed key leaves the key set once a pull replays the removal, so a
//! session ends within the pull age bound plus one refresh interval of the
//! removal reaching a peer the relying party pulls from.

use std::collections::BTreeMap;
use std::time::Duration;

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::principal::Clock;
use rand::RngCore;

use crate::connector::{ChannelBinding, Connector};
use crate::evidence::names_pg;
use crate::login::{self, Issuer, LoginRequest, SignError, SpentChallenges, VerifyError};
use crate::sync::{Anchor, PeerStanding, PullPeer, PullReport, Record, RecordTip, pull};

/// How many commits off the record's chain a relying party keeps (rivals
/// and the commits past them). It is the storage engine's `BRANCH_LIMIT`
/// (16 retained non-canonical commits per principal, `cyphr-storage`
/// `engine/mod.rs`), restated here because this crate does not depend on
/// storage; the unit is the same, one per commit kept off the chain. A
/// holder of one key can sign any number of rivals, so without a bound
/// that key grows a relying party's memory without limit.
///
/// The engine refuses a rival it has no slot for and tells the sender.
/// A relying party has no sender to tell, so its bound fails closed: when
/// a verified commit does not fit even after the commits the kept line
/// has passed are evicted, it refuses sign-in ([`Refusal::Forked`]) until
/// it is rebuilt from a fresh view. A fork it could not record is never
/// read as no fork.
pub const BRANCH_COMMIT_LIMIT: usize = 16;

/// How many of those commits one signing key may hold: the engine's
/// `BRANCH_PER_KEY` (2). A key that forked once is already proven to
/// equivocate, so a small quota loses no evidence. A key that floods
/// rivals can fill its own quota, so the quota bounds what is kept as
/// junk; a commit that changes the standing is still kept by the engine,
/// and here it fails closed ([`Refusal::Forked`]).
pub const BRANCH_COMMITS_PER_KEY: usize = 2;

/// A relying party's own settings.
#[derive(Debug, Clone)]
pub struct RpConfig {
    /// The service's name, the authority segment of the login `typ`. A
    /// login signed for another audience is refused.
    pub audience: String,
    /// The key this service signs its challenges with. The integrating
    /// site supplies it, as a server's operator supplies the server's
    /// signing key: the library neither generates, stores nor manages it.
    pub issuer: std::sync::Arc<dyn Issuer>,
    /// The longest the pull age may grow before the relying party refuses
    /// to sign anyone in and ends its sessions. Always stated: a relying
    /// party with no bound would trust a view of any age.
    pub pull_age_bound: Duration,
    /// How often the host is to call [`RelyingParty::refresh`]. The relying
    /// party does not run the timer; the host does, and the sign-on window
    /// is [`pull_age_bound`](Self::pull_age_bound) plus this.
    pub refresh_interval: Duration,
    /// How long a session lasts after sign-in. Never extended: a session
    /// that has reached it ends ([`Refusal::Expired`]) and the holder signs
    /// in again. The same meaning as a server's `session_ttl_secs`
    /// ([`login::DEFAULT_SESSION_TTL_SECS`] is its default).
    pub session_ttl: Duration,
}

impl RpConfig {
    /// The longest a removed key can still hold a session: the pull age
    /// bound plus one refresh interval.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.pull_age_bound + self.refresh_interval
    }
}

/// The currency a verdict needed and did not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnmetCurrency {
    /// No pull has succeeded: the relying party holds no view at all.
    NoPull,
    /// The newest successful pull is older than the bound.
    PullAge {
        /// How old it is, on the relying party's clock.
        age: Duration,
        /// The bound it exceeds.
        bound: Duration,
    },
}

/// Why a sign-in or a session was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The view is not current enough to trust ([`UnmetCurrency`]).
    #[error("the relying party's view is not current: {0:?}")]
    Stale(UnmetCurrency),
    /// The replayed chain shows two commits over one `pre`: the principal
    /// is in `Error` (SPEC 15.8) and nobody signs in.
    #[error("the principal forked; its lifecycle state is not Active")]
    Forked,
    /// A fork was resolved against the branch the relying party's own chain
    /// is on (SPEC 15.8): that branch's transactions are permanently
    /// invalid and its keys are not the principal's. Moving the record
    /// onto the kept branch is not done here, so nobody signs in until a
    /// fresh view follows it.
    #[error("the relying party's chain is a branch the principal's fork abandoned")]
    LostBranch,
    /// The login is not a login for this service and principal, or is not
    /// the shape a login has.
    #[error("malformed login: {0}")]
    Malformed(&'static str),
    /// The login's audience is not this relying party's.
    #[error("login audience does not name this service")]
    AudienceMismatch,
    /// The login's challenge was not issued by this relying party, was
    /// already redeemed, or expired.
    #[error("login challenge is unknown, used, or expired")]
    ChallengeInvalid,
    /// The login's signature does not verify under the key set the
    /// relying party replayed (or names a key it does not hold).
    #[error("login signature does not verify under the replayed key set")]
    InvalidSignature,
    /// The signing key is not active in the replayed chain, or has a
    /// verified naked revoke.
    #[error("the signing key is not active in the replayed chain")]
    KeyNotActive,
    /// The session reached its lifetime ([`RpConfig::session_ttl`]) and
    /// ended. It is dropped, never revived.
    #[error("the session reached its lifetime")]
    Expired,
    /// No session holds this token (never issued, or it already ended).
    #[error("no live session holds this token")]
    NoSession,
    /// The session is bound to the channel it was opened on, and the token
    /// arrived on another or on none. The session is not ended: the
    /// legitimate holder's channel still works.
    #[error("the token was presented off the channel its session is bound to")]
    ChannelMismatch,
}

/// What a session is tied to, so a token alone is not enough to use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionBinding {
    /// A native client signed in over an authenticated channel; the token
    /// works only on that channel (its [`ChannelBinding`], the Noise
    /// handshake hash for the principal-authenticated transport).
    Channel(ChannelBinding),
    /// A browser edge has no channel to bind to: the session is tied to the
    /// key that signed the login and ends when that key leaves the replayed
    /// chain.
    Key,
}

/// What a relying party trusted, and on what currency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    /// The principal, as the relying party was pinned to it.
    pub principal: String,
    /// The key, active in the chain the relying party replayed from its
    /// own anchor.
    pub key: Thumbprint,
    /// The tip the determination was made at.
    pub tip: RecordTip,
    /// Age of the newest successful pull, on the relying party's clock.
    pub pull_age: Duration,
    /// Age of the principal's newest signed `now`, on the same clock;
    /// reported, never decisive.
    pub principal_now_age: Option<Duration>,
}

/// A signed-in session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The opaque session token. A fresh 256-bit value, not derived from
    /// anything the principal signed.
    pub token: String,
    /// The canonical principal: the PG the relying party is pinned to,
    /// however the login spelled it.
    pub principal: String,
    /// The key that signed in.
    pub key: Thumbprint,
    /// What the session is tied to.
    pub binding: SessionBinding,
    /// What was trusted when the session opened.
    pub trust: Trust,
    /// The relying party's clock reading at which the session ends.
    pub expires_at: i64,
}

/// What a relying party holds for one live session.
#[derive(Debug, Clone)]
struct Held {
    key: Thumbprint,
    binding: SessionBinding,
    expires_at: i64,
}

/// A relying party for one principal.
pub struct RelyingParty {
    record: Record,
    config: RpConfig,
    clock: Clock,
    /// Clock reading at the newest successful pull.
    last_pull: Option<i64>,
    /// The commits pulls verified off the record's chain, by commit id: the
    /// rivals of every fork shown and the commits past them. Kept across
    /// pulls, so a pull the rival peer misses forgets nothing; whether
    /// they leave the principal in `Error` is the protocol's rule over
    /// them and the record's chain.
    branches: BTreeMap<String, cyphr::fork::Held>,
    /// The PRs of chain commits that verified resync proofs assert (SPEC
    /// 15.8 item 2), kept across pulls like the branches they decide
    /// between: a proof checked against the chain is not asked again.
    asserted: std::collections::BTreeSet<String>,
    /// The resync proofs peers served, kept so a proof that names a branch
    /// can be checked once that branch's line is at hand.
    pops: Vec<serde_json::Value>,
    /// The rival branches pulls verified, each with its extensions, kept
    /// for the same: what a proof's signer is read from on a branch.
    lines: Vec<crate::BranchLine>,
    /// Proofs that name a kept branch commit this relying party could not
    /// check the signer of. Any of them refuses sign-in: it may be the
    /// proof that makes the fork Error for good, which the servers read.
    unverified: std::collections::BTreeSet<String>,
    /// A verified commit could not be kept ([`BRANCH_COMMIT_LIMIT`]): a
    /// fork may stand that the relying party cannot see, so it refuses
    /// sign-in. Never cleared: only a rebuilt relying party starts clean.
    ///
    /// Operator action: every sign-in is refused as `Forked` until the
    /// process that holds this relying party is restarted (or the relying
    /// party rebuilt), which re-reads the principal's current rivals. The
    /// bound is a budget against a peer flooding branches, so recurring
    /// overflow means the principal is under attack or the limits are too
    /// low for its legitimate forks.
    overflowed: bool,
    /// Challenges already redeemed, so each signs one login.
    spent: SpentChallenges,
    sessions: BTreeMap<String, Held>,
}

impl RelyingParty {
    /// A relying party for the principal `principal_id` (its PG) pinned at
    /// `anchor`. It holds no view until [`refresh`](Self::refresh) succeeds.
    #[must_use]
    pub fn new(principal_id: &str, anchor: Anchor, config: RpConfig, clock: Clock) -> Self {
        Self {
            record: Record::new(principal_id, anchor).with_clock(clock),
            config,
            clock,
            last_pull: None,
            branches: BTreeMap::new(),
            asserted: std::collections::BTreeSet::new(),
            pops: Vec::new(),
            lines: Vec::new(),
            unverified: std::collections::BTreeSet::new(),
            overflowed: false,
            spent: SpentChallenges::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// The relying party's settings, for a host or a scenario that reads
    /// the bound rather than assuming one.
    #[must_use]
    pub fn config(&self) -> &RpConfig {
        &self.config
    }

    /// The anchor the relying party was enrolled with: what it replays the
    /// principal from, and the only root a verdict rests on.
    #[must_use]
    pub fn anchor(&self) -> &Anchor {
        self.record.anchor()
    }

    /// The record the relying party decides from.
    #[must_use]
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// Pull the principal's chain from `peers` into the record. The pull
    /// age restarts only when some peer answered with a chain that replayed
    /// from the pin: peers that all fail (offline, or serving another
    /// opener's chain) leave the view as old as it was.
    pub async fn refresh<C: Connector>(&mut self, peers: &[PullPeer<'_, C>]) -> PullReport {
        let report = pull(&mut self.record, peers).await;
        let answered = report
            .peers
            .iter()
            .any(|p| !matches!(p.standing, PeerStanding::Failed(_)));
        if answered && self.record.tip().is_some() {
            self.last_pull = Some((self.clock)());
            // A proved fork is the witness's proof of error (SPEC 15.7.1)
            // and stays recorded: a pull the rival peer misses must not
            // clear it. Only a commit that extends one branch and not the
            // other resolves it (SPEC 15.8), which `fork_refusal` reads from what is kept.
            // The proofs the peers hold, checked against the chain just
            // pulled: a peer that serves none or a bad one changes nothing.
            let mut pops = Vec::new();
            for peer in peers {
                match crate::fetch_resyncs(peer.connector, self.record.principal_id()).await {
                    Ok(found) => pops.extend(found),
                    Err(_) => continue,
                }
            }
            for pop in pops {
                if self.pops.len() < crate::MAX_RESYNCS && !self.pops.contains(&pop) {
                    self.pops.push(pop);
                }
            }
            for line in crate::branch_lines(&report) {
                let known = self
                    .lines
                    .iter()
                    .any(|l| l.height == line.height && l.bundles.first() == line.bundles.first());
                if known {
                    continue;
                }
                if self.lines.len() < BRANCH_COMMIT_LIMIT {
                    self.lines.push(line);
                } else {
                    // A line this relying party cannot keep may be the one a
                    // proof is signed on.
                    self.overflowed = true;
                }
            }
            let chain = self.chain_window(&report.branches);
            self.keep_branches(&report.branches, &chain);
            let branch_prs: Vec<String> = self.branches.values().map(|h| h.pr.clone()).collect();
            let found = self
                .record
                .asserted(&self.pops, &self.lines, &branch_prs)
                .await;
            self.asserted.extend(found.verified);
            self.unverified = found
                .unverified
                .into_iter()
                .filter(|id| !self.asserted.contains(id))
                .collect();
        }
        report
    }

    /// The record's commits from one position below the lowest rival, kept
    /// or `found`: all the fork rule needs to read.
    fn chain_window(&self, found: &[cyphr::fork::Held]) -> Vec<cyphr::fork::Held> {
        let lowest = self
            .branches
            .values()
            .chain(found)
            .map(|h| h.sequence)
            .min();
        let Some(last) = self
            .record
            .tip()
            .map(|t| (t.commits as u64).saturating_sub(1))
        else {
            return Vec::new();
        };
        let from = usize::try_from(cyphr::fork::assessed_from(lowest, last)).unwrap_or(usize::MAX);
        self.record.commits_from(from)
    }

    /// Keep the commits a pull verified off the record's chain, within the
    /// budget ([`BRANCH_COMMIT_LIMIT`], [`BRANCH_COMMITS_PER_KEY`]). A
    /// commit that does not fit is first made room for by evicting those
    /// the kept line has passed; one still without room is dropped only if
    /// it is itself passed, else [`overflowed`](Self::overflowed) is set.
    /// `chain` is the record's commits from the window's start.
    fn keep_branches(&mut self, found: &[cyphr::fork::Held], chain: &[cyphr::fork::Held]) {
        for held in found {
            if self.branches.contains_key(&held.id) {
                continue;
            }
            if !self.has_slot(held) {
                let passed = self.passed(chain, Some(held));
                self.branches.retain(|id, _| !passed.contains(id));
                if !self.has_slot(held) {
                    if !passed.contains(&held.id) {
                        self.overflowed = true;
                    }
                    continue;
                }
            }
            self.branches.insert(held.id.clone(), held.clone());
        }
    }

    fn has_slot(&self, held: &cyphr::fork::Held) -> bool {
        let signer = held.signed.last();
        self.branches.len() < BRANCH_COMMIT_LIMIT
            && self
                .branches
                .values()
                .filter(|h| h.signed.last() == signer)
                .count()
                < BRANCH_COMMITS_PER_KEY
    }

    /// The ids of the kept commits (and `extra`) the fork rule has chosen
    /// against: rivals at a contest the walk passes ([`assessment`]), so
    /// the fork stands resolved and they are only evidence. A commit at a
    /// contest still in Error is never passed.
    ///
    /// [`assessment`]: cyphr::fork::assessment
    fn passed(
        &self,
        chain: &[cyphr::fork::Held],
        extra: Option<&cyphr::fork::Held>,
    ) -> std::collections::BTreeSet<String> {
        let mut all: Vec<cyphr::fork::Held> = chain.to_vec();
        all.extend(self.branches.values().chain(extra).cloned());
        let asserted: Vec<String> = self.asserted.iter().cloned().collect();
        let assessed = cyphr::fork::assessment(&all, &asserted);
        let abandoned: std::collections::BTreeSet<&str> = assessed
            .forks
            .iter()
            .filter_map(|c| Some((c, c.kept.as_ref()?)))
            .flat_map(|(c, kept)| c.commits.iter().filter(move |id| *id != kept))
            .map(String::as_str)
            .collect();
        self.branches
            .values()
            .chain(extra)
            .filter(|h| abandoned.contains(h.id.as_str()))
            .map(|h| h.id.clone())
            .collect()
    }

    /// Issue a login challenge: a Coz this relying party signs over a fresh
    /// 256-bit nonce, valid for [`login::CHALLENGE_TTL_SECS`] and redeemable
    /// once. The signer returns it inside the login it signs.
    ///
    /// # Errors
    ///
    /// [`SignError`] if the configured key cannot sign.
    pub fn challenge(&self) -> Result<coz::CozJson, SignError> {
        login::issue_challenge(
            self.config.issuer.as_ref(),
            &self.config.audience,
            (self.clock)(),
        )
    }

    /// Sign the principal in on `login`, a request ([`login::sign_request`])
    /// answering a challenge this relying party issued.
    ///
    /// The decision reads only the replayed key set and this relying
    /// party's own challenge, and only while the view is current.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] naming the first condition not met. A challenge is
    /// spent last, by a login whose signature already verified
    /// ([`login::redeem_challenge`]): a misdirected or forged login burns
    /// nothing.
    pub fn sign_in(&mut self, login: &LoginRequest) -> Result<Session, Refusal> {
        self.sign_in_bound(login, SessionBinding::Key)
    }

    /// [`sign_in`](Self::sign_in) for a native client on `carrier`, binding
    /// the session to the channel the carrier reports. The login must have
    /// signed that channel's handshake hash as its `h` claim, so a login
    /// cannot be carried to another channel: a stolen token is useless off
    /// the channel it was issued on.
    ///
    /// # Errors
    ///
    /// [`Refusal::ChannelMismatch`] when the carrier has no channel binding
    /// or the login's `h` is absent or names another channel; otherwise as
    /// [`sign_in`](Self::sign_in).
    pub fn sign_in_on<C: Connector>(
        &mut self,
        login: &LoginRequest,
        carrier: &C,
    ) -> Result<Session, Refusal> {
        let channel = carrier.channel_binding().ok_or(Refusal::ChannelMismatch)?;
        self.sign_in_bound(login, SessionBinding::Channel(channel.clone()))
    }

    fn sign_in_bound(
        &mut self,
        login: &LoginRequest,
        binding: SessionBinding,
    ) -> Result<Session, Refusal> {
        let now = (self.clock)();
        // A session nobody presents again would otherwise stay for ever.
        self.sessions.retain(|_, held| now < held.expires_at);
        let parsed = login::parse_request(login).map_err(|e| match e {
            VerifyError::MissingField(name) => Refusal::Malformed(name),
            VerifyError::NotALogin | VerifyError::AudienceMissing => {
                Refusal::Malformed("typ is not a login")
            },
            VerifyError::ChannelMalformed => Refusal::Malformed("h is not base64url"),
            VerifyError::ChallengeInvalid => Refusal::ChallengeInvalid,
            VerifyError::InvalidSignature => Refusal::InvalidSignature,
        })?;
        if parsed.audience != self.config.audience {
            return Err(Refusal::AudienceMismatch);
        }
        if !names_pg(self.bare_principal(), &parsed.pg) {
            return Err(Refusal::Malformed("pg does not name the pinned principal"));
        }
        // The login names the channel it is for: the claim a native client
        // signs, absent from a browser edge's. Checked before the challenge
        // is spent, so a login carried to the wrong channel burns nothing.
        let expected = match &binding {
            SessionBinding::Channel(channel) => Some(channel.as_bytes().to_vec()),
            SessionBinding::Key => None,
        };
        if parsed.channel != expected {
            return Err(Refusal::ChannelMismatch);
        }
        if parsed.nonce.is_none() {
            return Err(Refusal::Malformed(login::field::CHALLENGE));
        }

        self.require_current(now)?;
        let tmb = parsed.tmb.clone();
        let trust = self.trust(&tmb, now)?;
        let key = self.record.key(&tmb).ok_or(Refusal::InvalidSignature)?;
        // The contract's one order: the signature first, then the spend, so
        // a junk signature cannot burn a live challenge.
        let verified = parsed
            .verify(key.alg(), key.pub_key())
            .map_err(|_| Refusal::InvalidSignature)?;
        login::redeem_challenge(self.config.issuer.as_ref(), &verified, &mut self.spent, now)
            .map_err(|_| Refusal::ChallengeInvalid)?;

        let mut raw = [0u8; login::CHALLENGE_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = Base64UrlUnpadded::encode_string(&raw);
        let principal = trust.principal.clone();
        let ttl = i64::try_from(self.config.session_ttl.as_secs()).unwrap_or(i64::MAX);
        let expires_at = now.saturating_add(ttl);
        self.sessions.insert(
            token.clone(),
            Held {
                key: tmb.clone(),
                binding: binding.clone(),
                expires_at,
            },
        );
        Ok(Session {
            token,
            principal,
            key: tmb,
            binding,
            trust,
            expires_at,
        })
    }

    /// Whether the session `token` still stands, re-decided from the
    /// current view: its key must still be active in the replayed chain and
    /// the view must still be current.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] that ended it. A session ended by a removed key or a
    /// stale view stays ended: it is dropped, never revived by a later pull.
    pub fn check_session(&mut self, token: &str) -> Result<Trust, Refusal> {
        self.check_session_on(token, None)
    }

    /// [`check_session`](Self::check_session) for a token arriving on
    /// `channel` (`None`: no authenticated channel, as at a browser edge).
    ///
    /// # Errors
    ///
    /// [`Refusal::ChannelMismatch`] for a channel-bound session presented
    /// off its channel (the session stays live); otherwise as
    /// [`check_session`](Self::check_session).
    pub fn check_session_on(
        &mut self,
        token: &str,
        channel: Option<&ChannelBinding>,
    ) -> Result<Trust, Refusal> {
        let Held {
            key,
            binding,
            expires_at,
        } = self.sessions.get(token).ok_or(Refusal::NoSession)?.clone();
        let now = (self.clock)();
        if now >= expires_at {
            self.sessions.remove(token);
            return Err(Refusal::Expired);
        }
        if let SessionBinding::Channel(bound) = &binding
            && channel != Some(bound)
        {
            return Err(Refusal::ChannelMismatch);
        }
        match self.trust(&key, now) {
            Ok(trust) => Ok(trust),
            Err(refusal) => {
                self.sessions.remove(token);
                Err(refusal)
            },
        }
    }

    fn bare_principal(&self) -> &str {
        let id = self.record.principal_id();
        id.split_once(':').map_or(id, |(_, bare)| bare)
    }

    fn require_current(&self, now: i64) -> Result<Duration, Refusal> {
        let at = self
            .last_pull
            .ok_or(Refusal::Stale(UnmetCurrency::NoPull))?;
        let age = Duration::from_secs(u64::try_from(now - at).unwrap_or(0));
        if age > self.config.pull_age_bound {
            return Err(Refusal::Stale(UnmetCurrency::PullAge {
                age,
                bound: self.config.pull_age_bound,
            }));
        }
        Ok(age)
    }

    /// What the protocol's fork rule (SPEC 15.5-15.8) says against signing
    /// in, over the record's chain and the branches the pulls verified:
    /// [`Refusal::Forked`] while the fork rule cannot choose a branch, [`Refusal::LostBranch`]
    /// when the kept line passes through a commit the record's chain does
    /// not hold, so its keys are those of an abandoned branch. It reads
    /// the chain from one position below the lowest rival, which holds the
    /// same fork state as the whole chain.
    fn fork_refusal(&self) -> Option<Refusal> {
        let Some(lowest) = self.branches.values().map(|h| h.sequence).min() else {
            return self.overflowed.then_some(Refusal::Forked);
        };
        let last = (self.record.tip()?.commits as u64).saturating_sub(1);
        let from =
            usize::try_from(cyphr::fork::assessed_from(Some(lowest), last)).unwrap_or(usize::MAX);
        self.refusal_over(self.record.commits_from(from))
    }

    /// [`fork_refusal`](Self::fork_refusal) over `chain`, the record's
    /// commits from the window's start.
    fn refusal_over(&self, chain: Vec<cyphr::fork::Held>) -> Option<Refusal> {
        if self.overflowed || !self.unverified.is_empty() {
            return Some(Refusal::Forked);
        }
        let mut held = chain.clone();
        held.extend(self.branches.values().cloned());
        let asserted: Vec<String> = self.asserted.iter().cloned().collect();
        let assessed = cyphr::fork::assessment(&held, &asserted);
        if assessed.consensus == cyphr::fork::Consensus::Error {
            return Some(Refusal::Forked);
        }
        assessed
            .forks
            .iter()
            .filter_map(|c| Some((c.sequence, c.kept.as_ref()?)))
            .any(|(at, kept)| chain.iter().find(|c| c.sequence == at).map(|c| &c.id) != Some(kept))
            .then_some(Refusal::LostBranch)
    }

    /// Whether the relying party trusts `key` for the principal now.
    fn trust(&self, key: &Thumbprint, now: i64) -> Result<Trust, Refusal> {
        let pull_age = self.require_current(now)?;
        if let Some(refusal) = self.fork_refusal() {
            return Err(refusal);
        }
        if !self.record.is_principal_active() {
            return Err(Refusal::Forked);
        }
        if !self.record.is_key_active(key) {
            return Err(Refusal::KeyNotActive);
        }
        let tip = self
            .record
            .tip()
            .ok_or(Refusal::Stale(UnmetCurrency::NoPull))?;
        Ok(Trust {
            principal: self
                .record
                .subject()
                .ok_or(Refusal::Stale(UnmetCurrency::NoPull))?,
            key: key.clone(),
            tip,
            pull_age,
            principal_now_age: self
                .record
                .latest_now()
                .map(|t| Duration::from_secs(u64::try_from(now - t).unwrap_or(0))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relying_party() -> RelyingParty {
        RelyingParty::new(
            "pg",
            Anchor::GenesisCommit("SHA-256:genesis".to_owned()),
            RpConfig {
                audience: "rp.example".to_owned(),
                issuer: std::sync::Arc::new(crate::login::SoftwareIssuer::new(
                    "Ed25519",
                    &[0x22; 32],
                    &[0u8; 32],
                )),
                pull_age_bound: Duration::from_secs(30),
                refresh_interval: Duration::from_secs(10),
                session_ttl: Duration::from_secs(900),
            },
            || 0,
        )
    }

    fn held(n: usize, signer: &str) -> cyphr::fork::Held {
        cyphr::fork::Held {
            sequence: 2,
            id: format!("commit-{n}"),
            pre: Some("pre".to_owned()),
            pr: format!("pr-{n}"),
            signed: vec![signer.to_owned()],
        }
    }

    /// A key holder can sign endless rivals at one position. The relying
    /// party keeps a bounded number, none it holds is dropped, and what it
    /// cannot keep is not read as no fork: it refuses sign-in.
    ///
    /// Turns red if the kept set grows with what peers serve, a kept
    /// commit is dropped, or a refused commit leaves sign-in open.
    #[test]
    fn kept_branch_commits_are_bounded_and_overflow_refuses() {
        let mut rp = relying_party();
        let flood: Vec<_> = (0..BRANCH_COMMIT_LIMIT + 50)
            .map(|n| held(n, &format!("key-{n}")))
            .collect();
        rp.keep_branches(&flood, &[]);
        assert_eq!(rp.branches.len(), BRANCH_COMMIT_LIMIT);
        assert!(rp.branches.contains_key("commit-0"), "the first is kept");
        assert_eq!(rp.refusal_over(Vec::new()), Some(Refusal::Forked));
        rp.keep_branches(&flood[..1], &[]);
        assert_eq!(
            rp.branches.len(),
            BRANCH_COMMIT_LIMIT,
            "a known one is a no-op"
        );
    }

    /// One key holds at most `BRANCH_COMMITS_PER_KEY`, so it cannot starve
    /// another key's rivals of slots.
    ///
    /// Turns red if the per-key quota is not applied.
    #[test]
    fn one_key_cannot_fill_the_budget() {
        let mut rp = relying_party();
        let flood: Vec<_> = (0..BRANCH_COMMIT_LIMIT).map(|n| held(n, "thief")).collect();
        rp.keep_branches(&flood, &[]);
        assert_eq!(rp.branches.len(), BRANCH_COMMITS_PER_KEY);
        rp.keep_branches(&[held(99, "owner")], &[]);
        assert!(rp.branches.contains_key("commit-99"));
    }

    /// A tie at the tip is a live fork whatever else is kept. One key's
    /// rivals at old positions, resolved long ago, fill the relying party's
    /// budget; a second key then forks at the tip, and the relying party
    /// must still refuse (SPEC 15.5): a rival it cannot keep is a fork it
    /// cannot see, and the principal is in Error.
    ///
    /// Turns red if a full budget lets a live fork go unrecorded.
    #[test]
    fn a_full_budget_does_not_hide_a_live_fork() {
        let top = BRANCH_COMMIT_LIMIT as u64 + 2;
        let at = |i: u64| cyphr::fork::Held {
            sequence: i,
            id: format!("c{i}"),
            pre: i.checked_sub(1).map(|j| format!("p{j}")),
            pr: format!("p{i}"),
            signed: vec!["owner".to_owned()],
        };
        let chain: Vec<_> = (0..=top).map(at).collect();
        let old_rival = |i: u64| cyphr::fork::Held {
            sequence: i,
            id: format!("a{i}"),
            pre: i.checked_sub(1).map(|j| format!("p{j}")),
            pr: format!("q{i}"),
            signed: vec![format!("thief-{i}")],
        };
        let mut rp = relying_party();
        let old: Vec<_> = (1..=BRANCH_COMMIT_LIMIT as u64).map(old_rival).collect();
        rp.keep_branches(&old, &chain);
        assert_eq!(rp.refusal_over(chain.clone()), None, "resolved long ago");

        rp.keep_branches(
            &[cyphr::fork::Held {
                sequence: top,
                id: "b".to_owned(),
                pre: Some(format!("p{}", top - 1)),
                pr: "qb".to_owned(),
                signed: vec!["second".to_owned()],
            }],
            &chain,
        );
        assert!(!rp.overflowed, "the resolved rivals made room");
        assert_eq!(rp.refusal_over(chain), Some(Refusal::Forked));
    }
}
