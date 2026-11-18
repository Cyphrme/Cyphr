//! A separated relying party (SPEC 17.2, 17.5): a service that signs a
//! principal in only on what it replayed itself.
//!
//! The relying party holds a [`Record`] of one principal, anchored at the
//! genesis key or the genesis commit id ([`Anchor`]): never the PG alone,
//! because one key set under different openers derives one PG, so a PG
//! cannot tell the principal the relying party was pinned to from another
//! opener's chain. It keeps the record current with [`RelyingParty::refresh`]
//! (the G2 pull step over peers it chose) and decides a login only from the
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
use serde_json::Value;

use crate::connector::{ChannelBinding, Connector};
use crate::evidence::names_pg;
use crate::sync::{Anchor, PeerStanding, PullPeer, PullReport, Record, RecordTip, pull};

/// Suffix of a login `typ`; the text before it is the audience, the
/// service the principal believes it is signing in to.
pub const LOGIN_TYP_SUFFIX: &str = "/cyphr/auth/login";

/// How long an issued challenge stays redeemable.
const CHALLENGE_TTL_SECS: i64 = 120;

/// Challenge length: 256 bits (SPEC 17.2).
const CHALLENGE_BYTES: usize = 32;

/// A relying party's own settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpConfig {
    /// The service's name, the authority segment of the login `typ`. A
    /// login signed for another audience is refused.
    pub audience: String,
    /// The longest the pull age may grow before the relying party refuses
    /// to sign anyone in and ends its sessions. Always stated: a relying
    /// party with no bound would trust a view of any age.
    pub pull_age_bound: Duration,
    /// How often the host is to call [`RelyingParty::refresh`]. The relying
    /// party does not run the timer; the host does, and the sign-on window
    /// is [`pull_age_bound`](Self::pull_age_bound) plus this.
    pub refresh_interval: Duration,
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
    /// Issued challenges, by value, with their issue time.
    challenges: BTreeMap<String, i64>,
    sessions: BTreeMap<String, (Thumbprint, SessionBinding)>,
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
            challenges: BTreeMap::new(),
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
            // clear it. Only a commit that out-extends a branch resolves
            // it (SPEC 15.8), which `fork_refusal` reads from what is kept.
            for held in &report.branches {
                self.branches
                    .entry(held.id.clone())
                    .or_insert_with(|| held.clone());
            }
        }
        report
    }

    /// Issue a login challenge: a fresh single-use 256-bit nonce.
    pub fn challenge(&mut self) -> String {
        let now = (self.clock)();
        self.challenges
            .retain(|_, at| now - *at <= CHALLENGE_TTL_SECS);
        let mut nonce = [0u8; CHALLENGE_BYTES];
        rand::thread_rng().fill_bytes(&mut nonce);
        let challenge = Base64UrlUnpadded::encode_string(&nonce);
        self.challenges.insert(challenge.clone(), now);
        challenge
    }

    /// Sign the principal in on `login`, a Coz signed over
    /// `{alg, now, tmb, typ: "<audience>/cyphr/auth/login", pr, challenge}`.
    ///
    /// The decision reads only the replayed key set and this relying
    /// party's own challenge, and only while the view is current.
    ///
    /// # Errors
    ///
    /// The [`Refusal`] naming the first condition not met. A challenge is
    /// spent only by a login whose audience and principal were right, so a
    /// misdirected login does not burn a live challenge, and a login that
    /// reaches the signature check spends it whether or not it passes.
    pub fn sign_in(&mut self, login: &coz::CozJson) -> Result<Session, Refusal> {
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
        login: &coz::CozJson,
        carrier: &C,
    ) -> Result<Session, Refusal> {
        let channel = carrier.channel_binding().ok_or(Refusal::ChannelMismatch)?;
        self.sign_in_bound(login, SessionBinding::Channel(channel.clone()))
    }

    fn sign_in_bound(
        &mut self,
        login: &coz::CozJson,
        binding: SessionBinding,
    ) -> Result<Session, Refusal> {
        let now = (self.clock)();
        let pay_bytes =
            serde_json::to_vec(&login.pay).map_err(|_| Refusal::Malformed("pay is not JSON"))?;
        let field = |name: &'static str| {
            login
                .pay
                .get(name)
                .and_then(Value::as_str)
                .ok_or(Refusal::Malformed(name))
        };
        let typ = field("typ")?;
        let audience = typ
            .strip_suffix(LOGIN_TYP_SUFFIX)
            .ok_or(Refusal::Malformed("typ is not a login"))?;
        if audience != self.config.audience {
            return Err(Refusal::AudienceMismatch);
        }
        if !names_pg(self.bare_principal(), field("pr")?) {
            return Err(Refusal::Malformed("pr does not name the pinned principal"));
        }
        // The login names the channel it is for: the claim a native client
        // signs, absent from a browser edge's. Checked before the challenge
        // is spent, so a login carried to the wrong channel burns nothing.
        let signed_channel = login.pay.get("h").and_then(Value::as_str);
        let expected = match &binding {
            SessionBinding::Channel(channel) => {
                Some(Base64UrlUnpadded::encode_string(channel.as_bytes()))
            },
            SessionBinding::Key => None,
        };
        if signed_channel != expected.as_deref() {
            return Err(Refusal::ChannelMismatch);
        }
        let challenge = field("challenge")?;
        let alg = field("alg")?;
        let tmb = Base64UrlUnpadded::decode_vec(field("tmb")?)
            .map(Thumbprint::from_bytes)
            .map_err(|_| Refusal::Malformed("tmb is not base64url"))?;

        self.require_current(now)?;
        self.challenges
            .remove(challenge)
            .filter(|at| now - *at <= CHALLENGE_TTL_SECS)
            .ok_or(Refusal::ChallengeInvalid)?;

        let trust = self.trust(&tmb, now)?;
        let key = self.record.key(&tmb).ok_or(Refusal::InvalidSignature)?;
        if alg != key.alg()
            || coz::verify_json(&pay_bytes, &login.sig, key.alg(), key.pub_key()) != Some(true)
        {
            return Err(Refusal::InvalidSignature);
        }

        let mut raw = [0u8; CHALLENGE_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = Base64UrlUnpadded::encode_string(&raw);
        let principal = trust.principal.clone();
        self.sessions
            .insert(token.clone(), (tmb.clone(), binding.clone()));
        Ok(Session {
            token,
            principal,
            key: tmb,
            binding,
            trust,
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
        let (key, binding) = self.sessions.get(token).ok_or(Refusal::NoSession)?.clone();
        if let SessionBinding::Channel(bound) = &binding
            && channel != Some(bound)
        {
            return Err(Refusal::ChannelMismatch);
        }
        match self.trust(&key, (self.clock)()) {
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
    /// [`Refusal::Forked`] while two branches tie, [`Refusal::LostBranch`]
    /// when the kept line passes through a commit the record's chain does
    /// not hold, so its keys are those of an abandoned branch. It reads
    /// the chain from one position below the lowest rival, which holds the
    /// same fork state as the whole chain.
    fn fork_refusal(&self) -> Option<Refusal> {
        let lowest = self.branches.values().map(|h| h.sequence).min()?;
        let last = (self.record.tip()?.commits as u64).saturating_sub(1);
        let from = usize::try_from(cyphr::fork::assessed_from(Some(lowest), last))
            .unwrap_or(usize::MAX);
        let mut held = self.record.commits_from(from);
        held.extend(self.branches.values().cloned());
        let assessed = cyphr::fork::assessment(&held);
        if assessed.consensus == cyphr::fork::Consensus::Error {
            return Some(Refusal::Forked);
        }
        assessed
            .forks
            .iter()
            .filter_map(|c| Some((c.sequence, c.kept.as_ref()?)))
            .any(|(at, kept)| {
                let at = usize::try_from(at).unwrap_or(usize::MAX);
                self.record.commit_id_at(at).as_ref() != Some(kept)
            })
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
