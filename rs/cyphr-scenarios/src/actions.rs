//! The peer-action seam: what a person (through the shipped `cyphr` CLI) or
//! an operator does, named after the protocol.
//!
//! Scenarios express their steps only through these actions and assert on
//! what they return. An action whose capability has landed drives the
//! shipped binaries: a person's steps run the `cyphr` CLI of that person's
//! device over the fault proxy, an operator's steps run `cyphr-server`
//! commands, and a read the CLI has no command for goes to the peer's own
//! route. An action whose capability has not landed returns
//! [`ActionError::Unsupported`], naming that capability, and
//! [`Harness::ok`] turns it into the same `RED(<capability>) after-setup
//! ...` panic the capability gate raises, so a scenario can neither pass
//! nor fail as a behaviour failure on a step that does not exist.
//!
//! The data types carry only vocabulary the protocol already fixes: SPEC
//! 15.5 (principal consensus states Active and Error, fork evidence,
//! resolution) and the trust model (anchor, peers, freshness). Handles
//! (`Principal`, `KeyRef`, `Tip`) are opaque strings.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::capability::Capability;
use crate::cli::{self, Device, field};
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
    /// The step itself failed: a binary crashed, answered outside its
    /// contract, or the harness could not carry the step out.
    #[error("{0}")]
    Failed(String),
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
    /// A harness-level kind: the connection failed (reset, timeout,
    /// refused). Distinct from every protocol refusal, which a peer
    /// actually sent.
    Unreachable,
    /// The peer refused to serve or sign a tip lower than one it already
    /// signed (a restored peer must not roll back).
    Rollback,
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

fn split_tag(s: &str) -> (Option<&str>, &str) {
    match s.split_once(':') {
        Some((tag, digest)) => (Some(tag), digest),
        None => (None, s),
    }
}

impl Principal {
    /// The handle without any algorithm tag (`SHA-512:abc` and `abc` are
    /// one address).
    pub fn bare(&self) -> &str {
        split_tag(&self.0).1
    }

    /// Whether `other` names the same principal in any spelling: the same
    /// digest, and the same algorithm tag when both carry one.
    pub fn same_as(&self, other: &str) -> bool {
        let ((ta, da), (tb, db)) = (split_tag(&self.0), split_tag(other));
        da == db && (ta.is_none() || tb.is_none() || ta == tb)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// A key, by thumbprint.
pub struct KeyRef(pub String);
/// A commit id, as a peer's `GET /tip` reports it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    /// `peer` is the equivocating peer's identity digest (what its
    /// `GET /server` reports), not the name a scenario gave it.
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

/// A signed statement a client holds from a peer: the signed coz bytes the
/// peer served, which the harness can verify offline, and the peer it came
/// from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub coz: Vec<u8>,
    pub peer: String,
}

/// Whom a statement is attributed to once checked against the peer's chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribution {
    /// The peer's canonical PG.
    pub peer: String,
    /// Thumbprint of the key that signed the statement.
    pub signing_key_tmb: String,
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
    h: &'h Harness,
    pub name: String,
    dev: Device,
    state: Mutex<DeviceState>,
}

/// What a device remembers beyond its store, as a person would.
#[derive(Clone, Default)]
struct DeviceState {
    /// The key this device signs with, per principal handle.
    signer: HashMap<String, String>,
    /// The peers this device knows hold a principal.
    peers: HashMap<String, Vec<String>>,
}

impl Harness {
    pub fn client(&self, name: &str) -> Client<'_> {
        Client {
            h: self,
            name: name.to_owned(),
            dev: Device::new()
                .unwrap_or_else(|e| panic!("harness defect: client `{name}` directory: {e}")),
            state: Mutex::default(),
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

    /// Rotate a peer's signing key with the shipped offline command: the
    /// peer is stopped, `cyphr-server rotate-key` runs on its data, and the
    /// peer starts again on the same address. Returns the new key.
    pub async fn rotate_peer_key(&self, peer: &str) -> ActionResult<KeyRef> {
        self.peer(peer)
            .rotate_key(self.bins)
            .await
            .map(KeyRef)
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// Make a peer serve `to` the given tips for `principal` instead of
    /// its real branch: a rigged, equivocating peer. A shipped peer cannot
    /// be rigged, so this needs a hostile responder the harness runs; it is
    /// owed with the first scenario that reaches it (S05, under G3).
    pub async fn equivocate(
        &self,
        _peer: &str,
        _principal: &Principal,
        _tips: &[(&Client<'_>, Tip)],
    ) -> ActionResult<()> {
        unsupported("equivocate", Capability::ClientGossip)
    }

    /// Make a peer serve `to` an old, genuine tip of `principal`: a stale
    /// view, which is a strict prefix of the real chain and not equivocation.
    /// A rigged peer, as [`Harness::equivocate`].
    pub async fn serve_stale_view(
        &self,
        _peer: &str,
        _principal: &Principal,
        _to: &Client<'_>,
        _tip: &Tip,
    ) -> ActionResult<()> {
        unsupported("serve_stale_view", Capability::ClientGossip)
    }

    /// Make a peer answer with an envelope of version `v`.
    ///
    /// A shipped peer cannot be rigged (the server has no hook, by design),
    /// so the hostile party is a responder the harness runs: it
    /// authenticates as a fresh principal, answers every request with
    /// envelope `v`, and a transport client must fail closed on it. The
    /// action succeeds only if that held, and otherwise panics: a client
    /// that accepted an unknown version is a defect, not a refusal to
    /// report. `_peer` names the peer the scenario means to rig.
    pub async fn serve_envelope_version(&self, _peer: &str, v: u32) -> ActionResult<()> {
        let closed = crate::transport::client_fails_closed_on_version(u64::from(v)).await;
        match closed {
            Ok(true) => Ok(()),
            Ok(false) => panic!("a transport client accepted envelope v={v}"),
            Err(e) => panic!("harness defect: the hostile responder could not run: {e}"),
        }
    }

    /// Flood a peer with `count` bogus evidence submissions. A peer takes no
    /// evidence from outside today (`/evidence` is read-only); submission
    /// between peers arrives with peer gossip (G2).
    pub async fn flood_evidence(&self, _peer: &str, _count: usize) -> ActionResult<()> {
        unsupported("flood_evidence", Capability::PeerGossip)
    }

    /// Stop a peer's server process.
    pub async fn stop_peer(&self, peer: &str) -> ActionResult<()> {
        self.peer(peer)
            .stop()
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    pub async fn start_relying_party(&self) -> ActionResult<RelyingParty<'_>> {
        unsupported("start_relying_party", Capability::RelyingParty)
    }
}

impl Client<'_> {
    async fn cyphr(&self, args: &[&str]) -> ActionResult<serde_json::Value> {
        self.dev.run(self.h.bins, args).await
    }

    /// The URL this device dials for `peer`: its own route through the
    /// fault proxy.
    async fn url(&self, peer: &str) -> String {
        format!("http://{}", self.h.route(&self.name, peer).await)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, DeviceState> {
        self.state.lock().expect("device state")
    }

    fn signer(&self, p: &Principal) -> ActionResult<String> {
        self.state().signer.get(&p.0).cloned().ok_or_else(|| {
            ActionError::Failed(format!("`{}` holds no key for {}", self.name, p.0))
        })
    }

    fn know(&self, p: &Principal, peers: &[&str]) {
        let mut st = self.state();
        let known = st.peers.entry(p.0.clone()).or_default();
        for peer in peers {
            if !known.iter().any(|k| k == peer) {
                known.push((*peer).to_owned());
            }
        }
    }

    fn known(&self, p: &Principal) -> Vec<String> {
        self.state().peers.get(&p.0).cloned().unwrap_or_default()
    }

    /// The local tip, as `cyphr verify` reports it against `peer`.
    async fn local_tip(&self, p: &Principal, peer: &str) -> ActionResult<Tip> {
        let url = self.url(peer).await;
        let v = self
            .cyphr(&["verify", "--identity", &p.0, "--peer", &url])
            .await?;
        field(&v, "tip").map(Tip)
    }

    // ---- principal and key lifecycle ----

    /// `cyphr init`, then `cyphr key add`: a new principal whose genesis
    /// key this device holds and signs with. `init` alone leaves a
    /// genesis-only state with no commit, which `cyphr push` refuses (there
    /// is nothing to send, and the CLI issues no `principal/create`), so the
    /// creation also commits one fresh key the device keeps; a peer can then
    /// hold the principal.
    pub async fn create_principal(&self) -> ActionResult<Principal> {
        // ES256, the CLI's default: `cyphr push` refuses an Ed25519
        // identity (its SHA-512 genesis digest is read as SHA-256).
        let v = self.cyphr(&["init", "--algo", "ES256"]).await?;
        let p = Principal(field(&v, "pr")?);
        let key = v["keys"][0]
            .as_str()
            .ok_or_else(|| ActionError::Failed(format!("init named no key: {v}")))?
            .to_owned();
        // The genesis public key is what a relying person holds out of
        // band; the harness keeps it so `trust_genesis` can hand it over.
        let genesis = cli::public_half(cli::key_entry(&self.dev.keystore, &key)?);
        self.h.record_genesis(&p, genesis);
        self.state().signer.insert(p.0.clone(), key);
        self.add_backup_key(&p).await?;
        Ok(p)
    }

    /// `cyphr key add`: a fresh key created and committed by this device.
    pub async fn add_backup_key(&self, p: &Principal) -> ActionResult<KeyRef> {
        let s = self.signer(p)?;
        let v = self
            .cyphr(&["key", "add", "--identity", &p.0, "--signer", &s])
            .await?;
        field(&v, "added_key").map(KeyRef)
    }

    /// Pair another device of the same person into the principal, by key
    /// create: `other` generates its own key (`cyphr key generate`; its
    /// private half never leaves it), this device commits a `key/create`
    /// naming it (`cyphr key add --key`), and `other` takes the history
    /// (`cyphr export` here, `cyphr import` there). Only public keys cross
    /// between the devices, as a pairing channel carries them; the
    /// proof-of-possession pairing request is N22's, not this.
    pub async fn pair_device(&self, p: &Principal, other: &Client<'_>) -> ActionResult<KeyRef> {
        let s = self.signer(p)?;
        let v = other
            .cyphr(&["key", "generate", "--algo", "ES256"])
            .await?;
        let tmb = field(&v, "tmb")?;
        let public = cli::public_half(cli::key_entry(&other.dev.keystore, &tmb)?);
        cli::put_key(&self.dev.keystore, &tmb, public)?;
        self.cyphr(&[
            "key",
            "add",
            "--identity",
            &p.0,
            "--key",
            &tmb,
            "--signer",
            &s,
        ])
        .await?;

        let genesis = self.h.genesis_of(p)?;
        cli::put_key(&other.dev.keystore, &p.0, genesis)?;
        let bundle = self.dev.scratch("pairing.jsonl");
        let bundle = bundle.to_string_lossy();
        self.cyphr(&["export", "--identity", &p.0, "--output", &bundle])
            .await?;
        other.cyphr(&["import", "--input", &bundle]).await?;
        other.state().signer.insert(p.0.clone(), tmb.clone());
        let peers = self.known(p);
        other.know(p, &peers.iter().map(String::as_str).collect::<Vec<_>>());
        Ok(KeyRef(tmb))
    }

    /// Copy another client's device, as a thief would: its store and the
    /// key `key` (private half included), signing with that key afterwards.
    pub async fn steal_key(&self, from: &Client<'_>, key: &KeyRef) -> ActionResult<()> {
        let entry = cli::key_entry(&from.dev.keystore, &key.0)?;
        cli::copy_tree(&from.dev.store, &self.dev.store)
            .map_err(|e| ActionError::Failed(format!("copying {}'s store: {e}", from.name)))?;
        cli::put_key(&self.dev.keystore, &key.0, entry)?;
        let theirs = from.state().clone();
        let mut mine = self.state();
        for (p, signer) in theirs.signer {
            if signer == key.0 {
                // The genesis public key lets the copied store replay.
                if let Ok(g) = self.h.genesis_of(&Principal(p.clone())) {
                    cli::put_key(&self.dev.keystore, &p, g)?;
                }
                mine.signer.insert(p.clone(), signer);
                mine.peers
                    .insert(p.clone(), theirs.peers.get(&p).cloned().unwrap_or_default());
            }
        }
        Ok(())
    }

    /// `key/replace` has no CLI command; N22 owns key replace.
    pub async fn rotate_key(&self, _p: &Principal) -> ActionResult<KeyRef> {
        unsupported("rotate_key", Capability::KeyPairing)
    }

    /// Revoke a key without being authorised by it: another active key
    /// removing a lost device, which N22 owns.
    pub async fn naked_revoke(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<()> {
        unsupported("naked_revoke", Capability::KeyPairing)
    }

    /// Retire a key with `key/delete`, which the CLI cannot sign; N22 owns
    /// removing a key by another active key.
    pub async fn remove_key(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<()> {
        unsupported("remove_key", Capability::KeyPairing)
    }

    /// Resolve a fork by selecting a branch (SPEC 15.8); the resolving key
    /// is N18b's.
    pub async fn resolve_fork(&self, _p: &Principal, _keep: &Tip) -> ActionResult<Tip> {
        unsupported("resolve_fork", Capability::Audit)
    }

    // ---- commits and publication ----

    /// Commit a data change locally, on top of this device's current local
    /// tip. It does not pull first, as an offline device would not; pulling
    /// is the separate, explicit [`Client::sync`]. The CLI signs no data
    /// commit.
    pub async fn commit_data(&self, _p: &Principal, _msg: &str) -> ActionResult<Tip> {
        unsupported("commit_data", Capability::DataCommit)
    }

    /// Pull the peers' latest state for `p` into this device's local view
    /// (`cyphr fetch` from each), and report the local tip. A peer that
    /// refuses or cannot be reached is skipped, as a device would.
    pub async fn sync(&self, p: &Principal, from: &[&str]) -> ActionResult<Tip> {
        let mut last = None;
        for peer in from {
            let url = self.url(peer).await;
            match self
                .cyphr(&["fetch", "--identity", &p.0, "--peer", &url])
                .await
            {
                Ok(_) => last = Some(*peer),
                Err(ActionError::Refused(_)) => {},
                Err(e) => return Err(e),
            }
        }
        self.know(p, from);
        let peer = last.ok_or_else(|| {
            ActionError::Refused(Refusal {
                kind: RefusalKind::Unreachable,
                detail: format!("no peer of {from:?} answered"),
            })
        })?;
        self.local_tip(p, peer).await
    }

    /// `cyphr push` to each peer in turn; the first refusal is the outcome.
    pub async fn push(&self, p: &Principal, to: &[&str]) -> ActionResult<PushOutcome> {
        self.know(p, to);
        let mut tip = None;
        for peer in to {
            let url = self.url(peer).await;
            match self
                .cyphr(&["push", "--identity", &p.0, "--peer", &url])
                .await
            {
                Ok(v) => tip = Some(field(&v, "tip")?),
                Err(ActionError::Refused(r)) => return Ok(PushOutcome::Refused(r)),
                Err(e) => return Err(e),
            }
        }
        tip.map(|t| PushOutcome::Accepted(Tip(t)))
            .ok_or_else(|| ActionError::Failed("push to no peer".into()))
    }

    /// Re-apply local commits on the peers' newer tip after a stale refusal
    /// (`cyphr rebase` onto the first peer this device knows for `p`).
    pub async fn rebase(&self, p: &Principal) -> ActionResult<Tip> {
        let peer = self.known(p).into_iter().next().ok_or_else(|| {
            ActionError::Failed(format!("`{}` knows no peer for {}", self.name, p.0))
        })?;
        let url = self.url(&peer).await;
        self.cyphr(&["rebase", "--identity", &p.0, "--peer", &url])
            .await?;
        self.local_tip(p, &peer).await
    }

    /// Publish a discovery self-claim naming the peers that hold the principal.
    pub async fn publish_self_claim(&self, _p: &Principal, _peers: &[&str]) -> ActionResult<()> {
        unsupported("publish_self_claim", Capability::Discovery)
    }

    // ---- knowing a principal ----

    /// Hold a principal's genesis out of band, with a hint of where to look:
    /// the genesis public key goes into this device's keystore, which is
    /// where `cyphr` resolves a trusted genesis from.
    pub async fn trust_genesis(&self, p: &Principal, hint: &[&str]) -> ActionResult<()> {
        cli::put_key(&self.dev.keystore, &p.0, self.h.genesis_of(p)?)?;
        self.know(p, hint);
        Ok(())
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

    /// Replay the principal from the given peers and conclude: `cyphr fetch`
    /// from each, then `cyphr verify`. An empty `from` means the peers this
    /// client currently knows for it, handed to the CLI as its choices file.
    pub async fn verdict(&self, p: &Principal, from: &[&str]) -> ActionResult<Verdict> {
        let names: Vec<String> = if from.is_empty() {
            self.known(p)
        } else {
            from.iter().map(|s| (*s).to_owned()).collect()
        };
        if names.is_empty() {
            return Err(ActionError::Failed(format!(
                "`{}` knows no peer for {}",
                self.name, p.0
            )));
        }
        let mut urls = Vec::with_capacity(names.len());
        for name in &names {
            let url = self.url(name).await;
            // A peer that refuses the pull still answers `verify`, which
            // reports it; only a failed step is a defect.
            match self
                .cyphr(&["fetch", "--identity", &p.0, "--peer", &url])
                .await
            {
                Ok(_) | Err(ActionError::Refused(_)) => {},
                Err(e) => return Err(e),
            }
            urls.push(url);
        }
        let mut args = vec!["verify".to_owned(), "--identity".into(), p.0.clone()];
        if from.is_empty() {
            let path = self.dev.scratch("choices.toml");
            let peers = serde_json::to_string(&urls).map_err(|e| ActionError::Failed(e.to_string()))?;
            std::fs::write(&path, format!("peers = {peers}\n"))
                .map_err(|e| ActionError::Failed(format!("writing choices: {e}")))?;
            args.extend(["--choices".into(), path.to_string_lossy().into_owned()]);
        } else {
            for url in &urls {
                args.extend(["--peer".into(), url.clone()]);
            }
        }
        let v = self
            .cyphr(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await?;
        self.know(p, &names.iter().map(String::as_str).collect::<Vec<_>>());
        parse_verdict(&v, p, &names, &urls)
    }

    /// Keep the signed tip report `peer` serves about `p` (`GET /tip`; the
    /// CLI keeps no statements).
    pub async fn hold_statement(&self, p: &Principal, peer: &str) -> ActionResult<Statement> {
        let v = self.get(peer, "/tip", Some(&p.0)).await?;
        if v["statement"]["kind"] != "signed" {
            return Err(ActionError::Failed(format!(
                "`{peer}` served an unsigned tip report: {v}"
            )));
        }
        let coz = serde_json::to_vec(&v["statement"]["coz"])
            .map_err(|e| ActionError::Failed(e.to_string()))?;
        Ok(Statement {
            coz,
            peer: peer.to_owned(),
        })
    }

    /// Check a held statement against the peer's current chain and say who
    /// signed it, even if the signing key has since been rotated away: the
    /// peer's own chain (`GET /patch` of the PG its `GET /server` names) is
    /// replayed, and the statement must verify under a key that chain ever
    /// introduced.
    pub async fn attribute(&self, s: &Statement) -> ActionResult<Attribution> {
        let ident = self.get(&s.peer, "/server", None).await?;
        let pg = field(&ident["payload"], "pg")?;
        // The peer's genesis as it states it; the replay accepts it only if
        // it derives the PG.
        let genesis = crate::signed::genesis_key(&ident["payload"]["genesis"])
            .ok_or_else(|| ActionError::Failed(format!("`{}` states no genesis", s.peer)))?;
        let url = format!("{}/patch", self.url(&s.peer).await);
        let body = self
            .h
            .http
            .get(url)
            .query(&[("pr", pg.as_str())])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| ActionError::Failed(format!("`{}` /patch: {e}", s.peer)))?
            .bytes()
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))?;
        let chain = crate::signed::ChainView::from_patch_with_genesis(&body, &pg, genesis)
            .map_err(|e| ActionError::Failed(format!("`{}`'s own chain: {e}", s.peer)))?;
        let coz: serde_json::Value =
            serde_json::from_slice(&s.coz).map_err(|e| ActionError::Failed(e.to_string()))?;
        let verified = crate::signed::verify(&coz, &chain.keys_ever())
            .map_err(|e| ActionError::Failed(format!("the statement is not P's: {e}")))?;
        Ok(Attribution {
            peer: pg,
            signing_key_tmb: verified.tmb,
        })
    }

    /// `GET <path>` on `peer` through this device's route, as JSON.
    async fn get(
        &self,
        peer: &str,
        path: &str,
        pr: Option<&str>,
    ) -> ActionResult<serde_json::Value> {
        let mut req = self.h.http.get(format!("{}{path}", self.url(peer).await));
        if let Some(pr) = pr {
            req = req.query(&[("pr", pr)]);
        }
        let resp = req
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| ActionError::Failed(format!("`{peer}` {path}: {e}")))?;
        resp.json()
            .await
            .map_err(|e| ActionError::Failed(format!("`{peer}` {path}: {e}")))
    }

    pub async fn audit(&self, _p: &Principal) -> ActionResult<Verdict> {
        unsupported("audit", Capability::Audit)
    }

    // ---- data actions ----

    pub async fn data_action(&self, _p: &Principal, _msg: &str) -> ActionResult<Action> {
        unsupported("data_action", Capability::DataCommit)
    }

    /// A data action signed by `key` but dated before `key` was retired.
    pub async fn forge_backdated(&self, _p: &Principal, _key: &KeyRef) -> ActionResult<Action> {
        unsupported("forge_backdated", Capability::DataCommit)
    }

    pub async fn submit(&self, _a: &Action, _to: &str) -> ActionResult<PushOutcome> {
        unsupported("submit", Capability::DataCommit)
    }

    /// Push again, verbatim, the commit at `height` (1-based) of the chain
    /// `to` serves: what an attacker replaying old material sends. The CLI
    /// pushes only what a peer lacks, so this goes to `POST /push` itself.
    pub async fn repush_commit(
        &self,
        p: &Principal,
        to: &str,
        height: u64,
    ) -> ActionResult<PushOutcome> {
        let patch = self.get(to, "/patch", Some(&p.0)).await?;
        let blobs = usize::try_from(height)
            .ok()
            .and_then(|h| h.checked_sub(1))
            .and_then(|i| patch["payload"]["entries"].get(i))
            .map(|e| e["blobs"].clone())
            .ok_or_else(|| ActionError::Failed(format!("`{to}` serves no commit {height}")))?;
        let resp = self
            .h
            .http
            .post(format!("{}/push", self.url(to).await))
            .json(&serde_json::json!({"principal_id": p.bare(), "blobs": blobs}))
            .send()
            .await
            .map_err(|e| ActionError::Failed(format!("`{to}` /push: {e}")))?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let detail = body.to_string();
        // The CLI's own reading of a push status (cyphr-cli `PeerError::kind`).
        let kind = match status {
            200..=299 => {
                return Ok(PushOutcome::Accepted(Tip(field(
                    &body["payload"],
                    "commit_id",
                )?)));
            },
            409 => RefusalKind::Stale,
            400 | 422 => RefusalKind::Malformed,
            401 | 403 => RefusalKind::Unauthorized,
            413 => RefusalKind::TooLarge,
            _ => return Err(ActionError::Failed(format!("`{to}` /push {status}: {detail}"))),
        };
        Ok(PushOutcome::Refused(Refusal { kind, detail }))
    }

    // ---- sign-on ----

    pub async fn sign_in(&self, _rp: &RelyingParty<'_>) -> ActionResult<Session> {
        unsupported("sign_in", Capability::RelyingParty)
    }
}

/// Read a `cyphr verify --output json` answer as a [`Verdict`]. `names` and
/// `urls` pair the scenario's peer names with the URLs the CLI was given.
fn parse_verdict(
    v: &serde_json::Value,
    p: &Principal,
    names: &[String],
    urls: &[String],
) -> ActionResult<Verdict> {
    let bad = |what: &str| ActionError::Failed(format!("verify answered without {what}: {v}"));
    let standing = match v["verdict"].as_str() {
        Some("Active") => Standing::Active,
        Some("Error") => Standing::Error,
        _ => return Err(bad("a verdict")),
    };
    let tip = Tip(field(v, "tip")?);
    let failed: Vec<&str> = v["peers_failed"]
        .as_array()
        .ok_or_else(|| bad("peers_failed"))?
        .iter()
        .filter_map(|f| f["peer"].as_str())
        .collect();
    let peers = names
        .iter()
        .zip(urls)
        .filter(|(_, url)| !failed.contains(&url.as_str()))
        .map(|(name, _)| name.clone())
        .collect();
    let anchor = Anchor {
        source: match v["anchor"]["source"].as_str() {
            Some("pinned") => AnchorSource::Pinned,
            Some("trusted-genesis") => AnchorSource::TrustedGenesis,
            Some("hint") => AnchorSource::Hint,
            _ => return Err(bad("an anchor source")),
        },
        id: v["anchor"]["value"]
            .as_str()
            .ok_or_else(|| bad("an anchor"))?
            .to_owned(),
    };
    // The CLI names a fork by height, not by the branch heads; it reports
    // no heads beyond its own tip.
    let forked = v["evidence"]
        .as_array()
        .is_some_and(|e| e.iter().any(|x| x["kind"] == "principal_fork"));
    Ok(Verdict {
        standing,
        freshness: Freshness {
            age: Duration::from_secs(v["view_age_secs"].as_u64().ok_or_else(|| bad("an age"))?),
            peer_reported_newer: v["newer_tip_reported"]
                .as_bool()
                .ok_or_else(|| bad("newer_tip_reported"))?,
        },
        branches: vec![tip.clone()],
        tip,
        anchor,
        peers,
        evidence: if forked {
            vec![Evidence::PrincipalFork(p.clone())]
        } else {
            Vec::new()
        },
        resolved_by: None,
    })
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
