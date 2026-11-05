//! The peer-action seam: what a person (through the shipped `cyphr` CLI) or
//! an operator does, named after the protocol.
//!
//! Scenarios express their steps only through these actions and assert on
//! what they return. Today every action returns
//! [`ActionError::Unsupported`], naming the capability that must land
//! first. [`Harness::ok`] turns that into the same
//! `RED(<capability>) after-setup ...` panic the capability gate raises, so
//! a scenario can neither pass nor fail as a behaviour failure while the
//! action behind it does not exist. When a supplier lands an action, it
//! replaces the `unsupported` body by driving the real binaries over the
//! network (no in-process stand-ins), and the scenario's own assertions
//! decide the outcome.
//!
//! The data types carry only vocabulary the protocol already fixes: SPEC
//! 15.5 (principal consensus states Active and Error, fork evidence,
//! resolution) and the trust model (anchor, peers, freshness). Handles
//! (`Principal`, `KeyRef`, `Tip`) are opaque strings.

use std::time::Duration;

use crate::capability::Capability;
use crate::harness::Harness;

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// The action is not implemented; `Capability` names what must land.
    #[error("action `{action}` is unsupported until `{}` lands", .capability.name())]
    Unsupported {
        action: &'static str,
        capability: Capability,
    },
    /// The system refused the action (a verdict, not a defect).
    #[error("refused ({:?}): {}", .0.kind, .0.detail)]
    Refused(Refusal),
}

/// Why the system refused something. Must-holds assert the kind; the detail
/// is for humans only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalKind {
    /// The sender's view is behind the peer's tip; rebase and retry.
    Stale,
    /// The signer lacks authority for the action.
    Unauthorized,
    /// The signing key was revoked (`key/revoke` or a naked revoke).
    Revoked,
    /// The signing key was retired by `key/delete`: it is no longer active.
    KeyNotActive,
    /// A transaction coz already applied was submitted again (SPEC 7.6).
    /// A replayed data action is not refused: it is accepted as a no-op.
    CozReuse,
    /// The input does not parse or violates the protocol's shape.
    Malformed,
    /// The input would fork the principal.
    Forked,
    /// The input exceeds a size bound.
    TooLarge,
    /// The envelope version is not one this client understands.
    UnknownVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub kind: RefusalKind,
    pub detail: String,
}

pub type ActionResult<T> = Result<T, ActionError>;

fn unsupported<T>(action: &'static str, capability: Capability) -> ActionResult<T> {
    Err(ActionError::Unsupported { action, capability })
}

/// A principal's canonical address: the PG once it is established, or the
/// genesis tmb (equal to its PR) while it is a nascent Level 1-2 principal.
/// A principal that added keys before `principal/create` has a PG that
/// differs from its genesis tmb, so the handle can change spelling over its
/// life. Peers report it as a bare digest, so compare handles with
/// [`Principal::bare`], never as raw strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(pub String);

impl Principal {
    /// The handle without any algorithm tag (`SHA-512:abc` and `abc` are
    /// one address).
    pub fn bare(&self) -> &str {
        self.0.rsplit(':').next().unwrap_or(&self.0)
    }

    /// Whether `other` names the same principal in any spelling.
    pub fn same_as(&self, other: &str) -> bool {
        self.bare() == Principal(other.to_owned()).bare()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRef(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
/// A commit id, as a peer's `GET /tip` reports it.
pub struct Tip(pub String);

/// What a peer itself holds for a principal, read from its own `GET /tip`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTip {
    /// The principal as the peer reports it (a bare digest).
    pub principal_id: String,
    pub tip: Tip,
    pub height: u64,
    pub pr: String,
    pub ar: String,
}

impl PeerTip {
    /// Parse a `GET /tip` response envelope.
    pub fn parse(envelope: &serde_json::Value) -> Option<PeerTip> {
        let t = &envelope["payload"];
        Some(PeerTip {
            principal_id: t["principal_id"].as_str()?.to_owned(),
            tip: Tip(t["commit_id"].as_str()?.to_owned()),
            height: t["commit_count"].as_u64()?,
            pr: t["pr"].as_str()?.to_owned(),
            ar: t["ar"].as_str()?.to_owned(),
        })
    }
}

/// SPEC 15.5 principal consensus state, the two a verdict can report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    Active,
    Error,
}

/// All a client can honestly say about freshness: how old its view
/// is, and whether a peer it asked reported something newer. It cannot say
/// "current", because nothing it can ask rules out a newer unseen state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Freshness {
    /// Age of the view: time since the tip it reports was last updated.
    pub age: Duration,
    /// A peer the client asked reported a tip newer than the view's.
    pub peer_reported_newer: bool,
}

/// How a trust anchor was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorSource {
    /// A tip the client pinned earlier.
    Pinned,
    /// A genesis the client holds and trusts, obtained out of band.
    TrustedGenesis,
    /// A hint (for example a self-claim) not yet independently trusted.
    Hint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub source: AnchorSource,
    pub id: String,
}

/// Evidence a client holds. A strict prefix is not evidence, so a healed
/// partition yields none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Two commits at one height from one principal (SPEC 15.7.1).
    PrincipalFork(Principal),
    /// A peer signed conflicting views of one principal.
    PeerEquivocation { peer: String },
}

/// What a client concludes about a principal from its peers.
#[derive(Clone, Debug)]
pub struct Verdict {
    pub standing: Standing,
    pub freshness: Freshness,
    pub tip: Tip,
    /// The trust anchor the replay started from, and how it was obtained.
    pub anchor: Anchor,
    /// The peers actually used; never empty, even when the caller passed
    /// no `from` and the client chose its own.
    pub peers: Vec<String>,
    /// Every branch kept; more than one under a fork.
    pub branches: Vec<Tip>,
    pub evidence: Vec<Evidence>,
    /// The key that resolved a fork, when one did.
    pub resolved_by: Option<KeyRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted(Tip),
    Refused(Refusal),
}

impl PushOutcome {
    /// The accepted tip; any refusal fails the scenario step with its kind.
    pub fn accepted(self, what: &str) -> Tip {
        match self {
            PushOutcome::Accepted(t) => t,
            PushOutcome::Refused(r) => panic!("{what}: refused ({:?}): {}", r.kind, r.detail),
        }
    }

    /// The refusal kind, or a failure if the push was accepted.
    pub fn refused(self, what: &str) -> RefusalKind {
        match self {
            PushOutcome::Refused(r) => r.kind,
            PushOutcome::Accepted(t) => panic!("{what}: unexpectedly accepted at {t:?}"),
        }
    }
}

/// The result of presenting a session token to a relying party.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presented {
    Accepted,
    Refused(Refusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token(pub String);

/// A signed-in session: the token and the key that authenticated it.
#[derive(Clone, Debug)]
pub struct Session {
    pub token: Token,
    pub key: KeyRef,
    /// The canonical token subject: the principal, however the caller
    /// spelled it when signing in.
    pub principal: Principal,
}

/// A relying party's own configuration, read from it rather than assumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpConfig {
    /// How old the relying party's view of the principal may grow before it
    /// ends the session. `None` when the relying party states no bound.
    pub view_age_bound: Option<Duration>,
    /// How often the relying party refreshes its view.
    pub refresh_interval: Duration,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup(pub String);

/// How a token reaches a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// The authenticated channel the sign-in used.
    Original,
    Other,
}

/// A relying party kept separate from every peer.
pub struct RelyingParty<'h> {
    #[expect(
        dead_code,
        reason = "read once the relying-party actions are implemented"
    )]
    h: &'h Harness,
}

/// One person's device: a `cyphr` CLI store plus keystore, and a node name
/// the fault proxy can partition or take offline.
pub struct Client<'h> {
    #[expect(dead_code, reason = "read once the client actions are implemented")]
    h: &'h Harness,
    pub name: String,
}

impl Harness {
    pub fn client(&self, name: &str) -> Client<'_> {
        Client {
            h: self,
            name: name.to_owned(),
        }
    }

    /// Unwrap an action result; an unsupported action ends the scenario as
    /// RED for the capability it names, any other error is a defect.
    pub fn ok<T>(&self, r: ActionResult<T>) -> T {
        match r {
            Ok(v) => v,
            Err(ActionError::Unsupported { capability, .. }) => self.red(capability),
            Err(e) => panic!("scenario step failed: {e}"),
        }
    }

    pub fn red(&self, cap: Capability) -> ! {
        panic!("{}", self.red_marker(cap))
    }

    // ---- operator actions on peers ----

    pub async fn backup_peer(&self, _peer: &str) -> ActionResult<Backup> {
        unsupported("backup_peer", Capability::PeerBackup)
    }

    pub async fn restore_peer(&self, _peer: &str, _from: &Backup) -> ActionResult<()> {
        unsupported("restore_peer", Capability::PeerBackup)
    }

    pub async fn rotate_peer_key(&self, _peer: &str) -> ActionResult<KeyRef> {
        unsupported("rotate_peer_key", Capability::PeerRollover)
    }

    /// Make a peer serve `to` the given tips for `principal` instead of
    /// its real branch: a rigged, equivocating peer.
    pub async fn equivocate(
        &self,
        _peer: &str,
        _principal: &Principal,
        _tips: &[(&Client<'_>, Tip)],
    ) -> ActionResult<()> {
        unsupported("equivocate", Capability::Evidence)
    }

    /// Make a peer serve `to` an old, genuine tip of `principal`: a stale
    /// view, which is a strict prefix of the real chain and not equivocation.
    pub async fn serve_stale_view(
        &self,
        _peer: &str,
        _principal: &Principal,
        _to: &Client<'_>,
        _tip: &Tip,
    ) -> ActionResult<()> {
        unsupported("serve_stale_view", Capability::Evidence)
    }

    /// Make a peer answer with an envelope of version `v`.
    pub async fn serve_envelope_version(&self, _peer: &str, _v: u32) -> ActionResult<()> {
        unsupported("serve_envelope_version", Capability::VersionCheck)
    }

    /// Flood a peer with `count` bogus evidence submissions.
    pub async fn flood_evidence(&self, _peer: &str, _count: usize) -> ActionResult<()> {
        unsupported("flood_evidence", Capability::Evidence)
    }

    pub async fn stop_peer(&self, _peer: &str) -> ActionResult<()> {
        unsupported("stop_peer", Capability::Transport)
    }

    pub async fn start_relying_party(&self) -> ActionResult<RelyingParty<'_>> {
        unsupported("start_relying_party", Capability::RelyingParty)
    }
}

impl Client<'_> {
    // ---- principal and key lifecycle ----

    pub async fn create_principal(&self) -> ActionResult<Principal> {
        unsupported("create_principal", Capability::CliNetwork)
    }

    pub async fn add_backup_key(&self, _p: &Principal) -> ActionResult<KeyRef> {
        unsupported("add_backup_key", Capability::CliNetwork)
    }

    /// Pair another device of the same person into the principal.
    pub async fn pair_device(&self, _p: &Principal, _other: &Client<'_>) -> ActionResult<KeyRef> {
        unsupported("pair_device", Capability::KeyPairing)
    }

    /// Copy another client's key material, as a thief with the device would.
    pub async fn steal_key(&self, _from: &Client<'_>, _key: &KeyRef) -> ActionResult<()> {
        unsupported("steal_key", Capability::CliNetwork)
    }

    pub async fn rotate_key(&self, _p: &Principal) -> ActionResult<KeyRef> {
        unsupported("rotate_key", Capability::CliNetwork)
    }

    /// Revoke a key without being authorised by it (SPEC naked revoke).
    pub async fn naked_revoke(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<()> {
        unsupported("naked_revoke", Capability::CliNetwork)
    }

    pub async fn remove_key(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<()> {
        unsupported("remove_key", Capability::CliNetwork)
    }

    /// Resolve a fork by selecting a branch (SPEC 15.8).
    pub async fn resolve_fork(&self, _p: &Principal, _keep: &Tip) -> ActionResult<Tip> {
        unsupported("resolve_fork", Capability::BranchStore)
    }

    // ---- commits and publication ----

    /// Commit a data change locally, on top of this device's current local
    /// tip. It does not pull first, as an offline device would not; pulling
    /// is the separate, explicit [`Client::sync`].
    pub async fn commit_data(&self, _p: &Principal, _msg: &str) -> ActionResult<Tip> {
        unsupported("commit_data", Capability::CliNetwork)
    }

    /// Pull the peers' latest state for `p` into this device's local view.
    pub async fn sync(&self, _p: &Principal, _from: &[&str]) -> ActionResult<Tip> {
        unsupported("sync", Capability::CliNetwork)
    }

    pub async fn push(&self, _p: &Principal, _to: &[&str]) -> ActionResult<PushOutcome> {
        unsupported("push", Capability::CliNetwork)
    }

    /// Re-apply local commits on the peers' newer tip after a stale refusal.
    pub async fn rebase(&self, _p: &Principal) -> ActionResult<Tip> {
        unsupported("rebase", Capability::CliNetwork)
    }

    /// Publish a discovery self-claim naming the peers that hold the principal.
    pub async fn publish_self_claim(&self, _p: &Principal, _peers: &[&str]) -> ActionResult<()> {
        unsupported("publish_self_claim", Capability::Discovery)
    }

    // ---- knowing a principal ----

    /// Hold a principal's genesis out of band, with a hint of where to look.
    pub async fn trust_genesis(&self, _p: &Principal, _hint: &[&str]) -> ActionResult<()> {
        unsupported("trust_genesis", Capability::ChoicesFile)
    }

    /// Learn of a principal from another client, not from its owner.
    pub async fn learn_from(&self, _other: &Client<'_>, _p: &Principal) -> ActionResult<()> {
        unsupported("learn_from", Capability::ClientGossip)
    }

    /// Follow the principal's discovery self-claim to its current peers.
    pub async fn follow_claim(&self, _p: &Principal) -> ActionResult<()> {
        unsupported("follow_claim", Capability::Discovery)
    }

    pub async fn watch(&self, _p: &Principal) -> ActionResult<()> {
        unsupported("watch", Capability::Pinning)
    }

    pub async fn gossip_with(&self, _other: &Client<'_>) -> ActionResult<()> {
        unsupported("gossip_with", Capability::ClientGossip)
    }

    /// Replay the principal from the given peers and conclude. An empty
    /// `from` means the peers this client currently knows for it.
    pub async fn verdict(&self, _p: &Principal, _from: &[&str]) -> ActionResult<Verdict> {
        unsupported("verdict", Capability::CliNetwork)
    }

    pub async fn audit(&self, _p: &Principal) -> ActionResult<Verdict> {
        unsupported("audit", Capability::Audit)
    }

    // ---- data actions ----

    pub async fn data_action(&self, _p: &Principal, _msg: &str) -> ActionResult<Action> {
        unsupported("data_action", Capability::CliNetwork)
    }

    /// A data action signed by `key` but dated before `key` was retired.
    pub async fn forge_backdated(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<Action> {
        unsupported("forge_backdated", Capability::CliNetwork)
    }

    pub async fn submit(&self, _a: &Action, _to: &str) -> ActionResult<PushOutcome> {
        unsupported("submit", Capability::CliNetwork)
    }

    pub async fn repush_commit(
        &self,
        _p: &Principal,
        _to: &str,
        _height: u64,
    ) -> ActionResult<PushOutcome> {
        unsupported("repush_commit", Capability::CliNetwork)
    }

    // ---- sign-on ----

    pub async fn sign_in(&self, _rp: &RelyingParty<'_>) -> ActionResult<Session> {
        unsupported("sign_in", Capability::RelyingParty)
    }
}

impl RelyingParty<'_> {
    pub async fn session_active(&self, _t: &Token) -> ActionResult<bool> {
        unsupported("session_active", Capability::RelyingParty)
    }

    /// Present a token on a channel and learn whether it was accepted.
    pub async fn present(&self, _t: &Token, _on: Channel) -> ActionResult<Presented> {
        unsupported("present", Capability::SessionBinding)
    }

    /// Let the relying party's view catch up with the principal.
    pub async fn config(&self) -> ActionResult<RpConfig> {
        unsupported("config", Capability::RelyingParty)
    }

    pub async fn refresh_view(&self) -> ActionResult<()> {
        unsupported("refresh_view", Capability::RelyingParty)
    }
}
