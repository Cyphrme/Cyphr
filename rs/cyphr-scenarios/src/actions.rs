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
    #[error("refused: {0}")]
    Refused(String),
}

pub type ActionResult<T> = Result<T, ActionError>;

fn unsupported<T>(action: &'static str, capability: Capability) -> ActionResult<T> {
    Err(ActionError::Unsupported { action, capability })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRef(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip(pub String);

/// SPEC 15.5 principal consensus state, the two a verdict can report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    Active,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Freshness {
    Current,
    /// The view is older than the peers' latest known state by `age`.
    Stale {
        age: Duration,
    },
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
    /// The trust anchor the replay started from.
    pub anchor: String,
    /// The peers the view was built from.
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
    /// The peer already has a newer tip; the pusher must rebase.
    RefusedStale,
    Rejected(String),
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

    /// Commit a data change locally, on top of this device's current tip.
    pub async fn commit_data(&self, _p: &Principal, _msg: &str) -> ActionResult<Tip> {
        unsupported("commit_data", Capability::CliNetwork)
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
    pub async fn present(&self, _t: &Token, _on: Channel) -> ActionResult<bool> {
        unsupported("present", Capability::SessionBinding)
    }

    /// Let the relying party's view catch up with the principal.
    pub async fn refresh_view(&self) -> ActionResult<()> {
        unsupported("refresh_view", Capability::RelyingParty)
    }
}
