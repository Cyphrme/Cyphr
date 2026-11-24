//! The peer-action seam: what a person (through the shipped `cyphr` CLI) or
//! an operator does, named after the protocol.
//!
//! Scenarios express their steps only through these actions and assert on
//! what they return. An action drives the
//! shipped binaries: a person's steps run the `cyphr` CLI of that person's
//! device over the fault proxy, an operator's steps run `cyphr-server`
//! commands, and a read the CLI has no command for goes to the peer's own
//! route.
//!
//! The data types carry only vocabulary the protocol already fixes: SPEC
//! 15.5 (principal consensus states Active and Error, fork evidence,
//! resolution) and the trust model (anchor, peers, freshness). Handles
//! (`Principal`, `KeyRef`, `Tip`) are opaque strings.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use cyphr_client::transport::NoiseConnector;

use crate::capability::Capability;
use crate::cli::{self, Device, field};
use crate::harness::Harness;

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
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
    /// The sender's view is behind the peer's tip or differs from it.
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

/// A principal's canonical address: the PG once it is established, or the
/// genesis tmb (equal to its PR) while it is a Level 1-2 principal that has
/// not committed. Peers report it as a bare digest, so compare handles with
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

/// What a device's own store holds for a principal (`cyphr inspect`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalView {
    pub tip: Tip,
    pub height: u64,
    pub pr: String,
    pub ar: String,
}

/// What a peer itself holds for a principal, read from its own `GET /tip`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTip {
    /// The principal as the peer reports it (a bare digest).
    pub principal_id: String,
    /// The peer's one tip while Active; while it reports Error (no single
    /// tip, SPEC 15.5) its first head, with `pr` and `ar` empty.
    pub tip: Tip,
    /// Every head the peer reports: `tip` alone while Active, each leaf
    /// above the fork point in Error.
    pub heads: Vec<Tip>,
    /// The height (commit count up to it) of each head, in `heads` order.
    pub head_heights: Vec<u64>,
    /// The peer's own consensus state, as its `/tip` says it: never read
    /// back from a head count.
    pub standing: Standing,
    /// The fork point the peer reports in Error (`height` and `pre`, as it
    /// states them); `None` while Active.
    pub fork_point: Option<serde_json::Value>,
    pub height: u64,
    pub pr: String,
    pub ar: String,
}

impl PeerTip {
    /// Parse a `GET /tip` response envelope.
    pub fn parse(envelope: &serde_json::Value) -> Option<PeerTip> {
        let t = &envelope["payload"];
        if t["state"] == "error" {
            let heads: Vec<Tip> = t["heads"]
                .as_array()?
                .iter()
                .map(|h| Some(Tip(h["commit_id"].as_str()?.to_owned())))
                .collect::<Option<_>>()?;
            return Some(PeerTip {
                principal_id: t["principal_id"].as_str()?.to_owned(),
                tip: heads.first()?.clone(),
                head_heights: t["heads"]
                    .as_array()?
                    .iter()
                    .map(|h| Some(h["sequence"].as_u64()? + 1))
                    .collect::<Option<_>>()?,
                standing: Standing::Error,
                fork_point: Some(t["fork_point"].clone()),
                height: t["heads"][0]["sequence"].as_u64()? + 1,
                heads,
                pr: String::new(),
                ar: String::new(),
            });
        }
        let tip = Tip(t["commit_id"].as_str()?.to_owned());
        Some(PeerTip {
            principal_id: t["principal_id"].as_str()?.to_owned(),
            heads: vec![tip.clone()],
            head_heights: vec![t["commit_count"].as_u64()?],
            standing: Standing::Active,
            fork_point: None,
            tip,
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
    /// The live heads: one once peers agree, more than one under a fork.
    pub branches: Vec<Tip>,
    /// The branches a resolution abandoned, kept as proof of error (SPEC
    /// 15.8), not as live heads.
    pub abandoned: Vec<Tip>,
    pub evidence: Vec<Evidence>,
    /// The key that resolved a fork, when one did.
    pub resolved_by: Option<KeyRef>,
    /// The asked peers that did not answer, each with the unix time it last
    /// answered this client (`None`: never), so "unreachable since t".
    pub unreachable: Vec<(String, Option<i64>)>,
    /// When the CLI that computed the verdict was started, so an oracle can
    /// bound the time between the CLI's reading of the peer and its own.
    pub observed_at: std::time::Instant,
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
    /// The login the client signed, kept so a scenario can carry it to
    /// another channel.
    pub login: coz::CozJson,
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
    /// How old its newest successful pull of the principal's chain may
    /// grow before it ends the session.
    pub pull_age_bound: Duration,
    /// How often the relying party pulls.
    pub refresh_interval: Duration,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup(pub String);

/// What trusting the remote left: the local tip, the local commits it
/// discarded and the czds of recorded actions it dropped because the adopted
/// history does not accept them as signed. It never re-signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adopted {
    pub tip: Tip,
    pub discarded: Vec<String>,
    pub dropped: Vec<String>,
}

/// How a token reaches a relying party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// The authenticated channel the sign-in used.
    Original,
    /// A second authenticated session.
    Other,
    /// No authenticated channel: plain HTTP, as a browser edge arrives.
    Http,
}

/// A relying party kept separate from every peer: it replays the
/// principal from its own pin and pulls from peers over its own route.
pub struct RelyingParty<'h> {
    h: &'h Harness,
    config: cyphr_client::RpConfig,
    /// The signed-in client's own Noise session, which its login was sent
    /// on: a real session with one of the peers, standing in for the
    /// session a relying party host would terminate. The relying party
    /// reads the binding from this carrier, never from a caller.
    original: Mutex<Option<NoiseConnector>>,
    /// Set at the first sign-in, which enrols the principal the way a
    /// sign-up does: the relying party is handed the genesis key out of
    /// band and the peers to pull from.
    enrolled: tokio::sync::Mutex<Option<Enrolled>>,
}

struct Enrolled {
    party: cyphr_client::RelyingParty,
    peers: Vec<String>,
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

    /// Unwrap an action result; an error is a defect.
    pub fn ok<T>(&self, r: ActionResult<T>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("scenario step failed: {e}"),
        }
    }

    pub fn red(&self, cap: Capability) -> ! {
        panic!("{}", self.red_marker(cap))
    }

    // ---- operator actions on peers ----

    /// Snapshot a peer's data with the shipped offline command
    /// (`cyphr-server backup`); the peer is stopped for it and starts again
    /// on the same address.
    pub async fn backup_peer(&self, peer: &str) -> ActionResult<Backup> {
        self.bank_running(peer).await?;
        self.peer(peer)
            .backup(self.bins)
            .await
            .map(|p| Backup(p.to_string_lossy().into_owned()))
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// Restore a peer from a backup with `cyphr-server restore`; returns
    /// the report naming the commits the restore lost.
    pub async fn restore_peer(&self, peer: &str, from: &Backup) -> ActionResult<String> {
        self.bank_running(peer).await?;
        self.peer(peer)
            .restore(self.bins, std::path::Path::new(&from.0))
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// Rotate a peer's signing key with the shipped offline command: the
    /// peer is stopped, `cyphr-server rotate-key` runs on its data, and the
    /// peer starts again on the same address. Returns the new key.
    pub async fn rotate_peer_key(&self, peer: &str) -> ActionResult<KeyRef> {
        self.bank_running(peer).await?;
        self.peer(peer)
            .rotate_key(self.bins)
            .await
            .map(KeyRef)
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// Replay every chain the peer stores with `cyphr-server verify-all`
    /// (the peer is stopped for it and starts again); returns the command's
    /// report. A chain that fails to replay is an error naming it.
    pub async fn verify_all_peer(&self, peer: &str) -> ActionResult<String> {
        self.bank_running(peer).await?;
        self.peer(peer)
            .verify_all(self.bins)
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// The offline operator commands stop the process their counters belong
    /// to, so its counters are banked first (see [`Harness::stop_peer`]).
    async fn bank_running(&self, peer: &str) -> ActionResult<()> {
        if self.peer_down(peer).await {
            return Ok(());
        }
        self.bank_counters(peer).await.map_err(ActionError::Failed)
    }

    /// Make a peer answer with an envelope of version `v`.
    ///
    /// A shipped peer cannot be rigged (the server has no hook, by design),
    /// so the hostile party is a responder the harness runs, in two forms.
    /// Over the Noise transport it authenticates as a fresh principal,
    /// answers every request with envelope `v`, and a transport client must
    /// fail closed on it; the action panics if one accepted it, since that
    /// is a defect, not a refusal to report. Over HTTP it takes the named
    /// peer's place behind the proxy, so every client that reads `peer`
    /// from now on is served `v` and the scenario sees what the CLI does
    /// with it.
    pub async fn serve_envelope_version(&self, peer: &str, v: u32) -> ActionResult<()> {
        let closed = crate::transport::client_fails_closed_on_version(u64::from(v)).await;
        match closed {
            Ok(true) => {},
            Ok(false) => panic!("a transport client accepted envelope v={v}"),
            Err(e) => panic!("harness defect: the hostile responder could not run: {e}"),
        }
        let hostile = crate::transport::serve_http_envelope_version(u64::from(v))
            .await
            .map_err(|e| ActionError::Failed(format!("hostile HTTP responder: {e}")))?;
        self.proxy.redirect(peer, hostile);
        Ok(())
    }

    /// Flood a peer with `count` requests naming principals and keys it has
    /// never seen, on the two routes a gossiping peer is asked: `/evidence`
    /// and `/revoked`. A peer must answer each (served or refused by its
    /// own limits) and never fail it: a connection that breaks or a 5xx is
    /// a defect, reported as a failed action.
    pub async fn flood_evidence(&self, peer: &str, count: usize) -> ActionResult<()> {
        let base = format!("http://{}", self.peer(peer).addr());
        let mut sent = 0;
        while sent < count {
            let batch = (count - sent).min(100);
            let mut set = tokio::task::JoinSet::new();
            for i in sent..sent + batch {
                let http = self.http.clone();
                // 43 base64url characters: the shape of a thumbprint or an
                // unpadded SHA-256 PG, which is never one a peer holds.
                let bogus = format!("{i:0>43}");
                let url = if i % 2 == 0 {
                    format!("{base}/evidence?pr={bogus}")
                } else {
                    format!("{base}/revoked?tmbs={bogus}")
                };
                set.spawn(async move { http.get(url).send().await.map(|r| r.status()) });
            }
            while let Some(answer) = set.join_next().await {
                let status = answer
                    .map_err(|e| ActionError::Failed(format!("flood task: {e}")))?
                    .map_err(|e| ActionError::Failed(format!("`{peer}` dropped a request: {e}")))?;
                if status.is_server_error() {
                    return Err(ActionError::Failed(format!(
                        "`{peer}` answered a flood request with {status}"
                    )));
                }
            }
            sent += batch;
        }
        Ok(())
    }

    /// Stop a peer's server process, keeping its counters (see
    /// [`Harness::lifetime_counters`]).
    pub async fn stop_peer(&self, peer: &str) -> ActionResult<()> {
        if !self.peer_down(peer).await {
            self.bank_counters(peer)
                .await
                .map_err(ActionError::Failed)?;
        }
        self.peer(peer)
            .stop()
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// Start a stopped peer again on its data, as an operator would.
    pub async fn start_peer(&self, peer: &str) -> ActionResult<()> {
        self.peer(peer)
            .restart(self.bins)
            .await
            .map_err(|e| ActionError::Failed(e.to_string()))
    }

    /// A relying party for the audience `rp.scenarios`, which pulls no
    /// sooner than a scenario asks it to.
    pub async fn start_relying_party(&self) -> ActionResult<RelyingParty<'_>> {
        Ok(RelyingParty {
            h: self,
            config: cyphr_client::RpConfig {
                audience: RP_AUDIENCE.to_owned(),
                pull_age_bound: Duration::from_secs(30),
                refresh_interval: Duration::from_secs(5),
            },
            original: Mutex::new(None),
            enrolled: tokio::sync::Mutex::new(None),
        })
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

    pub(crate) fn signer(&self, p: &Principal) -> ActionResult<String> {
        self.state()
            .signer
            .get(&p.0)
            .cloned()
            .ok_or_else(|| ActionError::Failed(format!("`{}` holds no key for {}", self.name, p.0)))
    }

    /// Every commit this device holds for `p`, as `cyphr export` writes
    /// them: one JSON bundle line per commit, in chain order (`txs`, `keys`,
    /// `commit_id`, roots), action-only lines left out. A scenario that must
    /// place a fork where the CLI's own push refuses to (it never sends a
    /// commit over a tip the peer holds) posts these lines to a peer itself.
    pub async fn exported_commits(&self, p: &Principal) -> ActionResult<Vec<serde_json::Value>> {
        let file = self.dev.scratch("commits.jsonl");
        let path = file.to_string_lossy();
        self.cyphr(&["export", "--identity", &p.0, "--output", &path])
            .await?;
        let text = std::fs::read_to_string(&file)
            .map_err(|e| ActionError::Failed(format!("reading {}: {e}", file.display())))?;
        let mut lines = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| ActionError::Failed(format!("export line: {e}")))?;
            if v["txs"].as_array().is_some_and(|t| !t.is_empty()) {
                lines.push(v);
            }
        }
        Ok(lines)
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

    /// The tip of this device's own store, read without asking any peer.
    async fn local_commit(&self, p: &Principal) -> ActionResult<Tip> {
        let v = self.cyphr(&["inspect", "--identity", &p.0]).await?;
        field(&v, "tip").map(Tip)
    }

    /// What this device's own store holds for `p`, read without asking any
    /// peer: the owner's side of an agreement check.
    pub async fn local_view(&self, p: &Principal) -> ActionResult<LocalView> {
        let v = self.cyphr(&["inspect", "--identity", &p.0]).await?;
        Ok(LocalView {
            tip: Tip(field(&v, "tip")?),
            height: v["commit_count"].as_u64().ok_or_else(|| {
                ActionError::Failed(format!("inspect answered without commit_count: {v}"))
            })?,
            pr: field(&v, "pr")?,
            ar: field(&v, "as")?,
        })
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

    /// `cyphr init --genesis-commit`: a new single-key principal whose
    /// genesis key this device holds and signs with, published by its
    /// genesis commit alone (SPEC 5.2: key, principal/create, commit/create,
    /// no second key).
    pub async fn create_principal(&self) -> ActionResult<Principal> {
        let v = self
            .cyphr(&["init", "--algo", "Ed25519", "--genesis-commit"])
            .await?;
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
        Ok(p)
    }

    /// `cyphr init --keys`: a new principal whose genesis commit creates two
    /// keys this device holds, so its PG is derived from the pair and is not
    /// the genesis key's thumbprint. The first key opens it and signs.
    pub async fn create_multikey_principal(&self) -> ActionResult<Principal> {
        let mut tmbs = Vec::new();
        for _ in 0..2 {
            let v = self
                .cyphr(&["key", "generate", "--algo", "Ed25519"])
                .await?;
            tmbs.push(field(&v, "tmb")?);
        }
        let keys = tmbs.join(",");
        let v = self.cyphr(&["init", "--keys", &keys]).await?;
        let p = Principal(field(&v, "pr")?);
        let genesis = cli::public_half(cli::key_entry(&self.dev.keystore, &tmbs[0])?);
        self.h.record_genesis(&p, genesis);
        self.state().signer.insert(p.0.clone(), tmbs[0].clone());
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

    /// Pair another device of the same person into the principal: `other`
    /// enrolls its own key and signs a pairing request with it
    /// (`cyphr key request`; its private half never leaves it), the request
    /// file crosses to this device as a pairing channel carries it, this
    /// device verifies it and commits the key (`cyphr key accept`), and
    /// `other` takes the history (`cyphr export` here, `cyphr import` there).
    pub async fn pair_device(&self, p: &Principal, other: &Client<'_>) -> ActionResult<KeyRef> {
        let s = self.signer(p)?;
        let request = other.dev.scratch("pairing-request.json");
        let request = request.to_string_lossy();
        let v = other
            .cyphr(&[
                "key",
                "request",
                "--identity",
                &p.0,
                "--algo",
                "ES256",
                "--file",
                &request,
            ])
            .await?;
        let tmb = field(&v, "tmb")?;
        self.cyphr(&[
            "key",
            "accept",
            "--identity",
            &p.0,
            "--signer",
            &s,
            "--file",
            &request,
        ])
        .await?;

        self.h.give_genesis(&other.dev.keystore, p)?;
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
                self.h
                    .give_genesis(&self.dev.keystore, &Principal(p.clone()))?;
                mine.signer.insert(p.clone(), signer);
                mine.peers
                    .insert(p.clone(), theirs.peers.get(&p).cloned().unwrap_or_default());
            }
        }
        Ok(())
    }

    /// `cyphr key replace`: swap the key this device signs `p` with for a
    /// fresh one in one commit (SPEC 6.3); the device signs with the new key
    /// from then on.
    pub async fn rotate_key(&self, p: &Principal) -> ActionResult<KeyRef> {
        let s = self.signer(p)?;
        let v = self
            .cyphr(&["key", "replace", "--identity", &p.0, "--signer", &s])
            .await?;
        let tmb = field(&v, "new_key")?;
        self.state().signer.insert(p.0.clone(), tmb.clone());
        Ok(KeyRef(tmb))
    }

    /// `cyphr key naked-revoke`: this device signs a revoke of `key` with
    /// `key` itself, outside any commit (SPEC 6.4), and sends it to every
    /// peer it knows for `p`. The device must hold `key`'s private half; a
    /// revoke is self-signed, so no other key can make one.
    pub async fn naked_revoke(&self, p: &Principal, key: &KeyRef) -> ActionResult<()> {
        let mut args = vec![
            "key".to_owned(),
            "naked-revoke".to_owned(),
            format!("--key={}", key.0),
        ];
        for peer in self.known(p) {
            args.push(format!("--peer={}", self.url(&peer).await));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.cyphr(&args).await?;
        Ok(())
    }

    /// `cyphr key delete`: retire `key` from `p` without marking it
    /// compromised (SPEC 6.2), signed by this device's own key.
    pub async fn remove_key(&self, p: &Principal, key: &KeyRef) -> ActionResult<()> {
        let s = self.signer(p)?;
        self.cyphr(&[
            "key",
            "delete",
            "--identity",
            &p.0,
            "--key",
            &key.0,
            "--signer",
            &s,
        ])
        .await?;
        Ok(())
    }

    /// Resolve a fork by selecting a branch (SPEC 15.8, a new commit on the
    /// chosen branch): this device's own tip is the branch it keeps, so it
    /// signs the next commit on it and pushes to every peer it knows. A peer
    /// holding the other branch refuses the push; gossip carries it there.
    pub async fn resolve_fork(&self, p: &Principal, keep: &Tip) -> ActionResult<Tip> {
        let held = self.local_commit(p).await?;
        if &held != keep {
            return Err(ActionError::Failed(format!(
                "`{}` holds {held:?}, not the branch {keep:?} to keep",
                self.name
            )));
        }
        let tip = self.commit_data(p, "resolve").await?;
        let mut accepted = false;
        for peer in self.known(p) {
            let url = self.url(&peer).await;
            match self
                .cyphr(&["push", "--identity", &p.0, "--peer", &url, "--assert-local"])
                .await
            {
                Ok(_) => accepted = true,
                Err(ActionError::Refused(_)) => {},
                Err(e) => return Err(e),
            }
        }
        if !accepted {
            return Err(ActionError::Failed(format!(
                "no peer accepted the resolution from `{}`",
                self.name
            )));
        }
        Ok(tip)
    }

    /// Resolve a fork by a resync proof of possession (SPEC 15.8 item 2):
    /// `cyphr resync` signs over this device's own tip and sends it, with
    /// the local line, to every peer it knows. The commit it asserts is
    /// this device's tip; no commit is made. A peer that is Error after it
    /// is the protocol's answer, not a refusal.
    pub async fn resync(&self, p: &Principal) -> ActionResult<Tip> {
        let tip = self.local_commit(p).await?;
        let mut accepted = false;
        for peer in self.known(p) {
            let url = self.url(&peer).await;
            match self
                .cyphr(&["resync", "--identity", &p.0, "--peer", &url])
                .await
            {
                Ok(_) => accepted = true,
                Err(ActionError::Refused(_)) => {},
                Err(e) => return Err(e),
            }
        }
        if !accepted {
            return Err(ActionError::Failed(format!(
                "no peer took the resync from `{}`",
                self.name
            )));
        }
        Ok(tip)
    }

    // ---- commits and publication ----

    /// Commit a data change locally, on top of this device's current local
    /// tip: a signed data action, then the `ds/create` that includes it
    /// (`cyphr data action`, `cyphr data commit`). It does not pull first, as
    /// an offline device would not; pulling is the separate, explicit
    /// [`Client::sync`].
    pub async fn commit_data(&self, p: &Principal, msg: &str) -> ActionResult<Tip> {
        let (id, signer) = (format!("--identity={}", p.0), self.signer(p)?);
        let signer = format!("--signer={signer}");
        self.cyphr(&["data", "action", &id, &signer, &format!("--msg={msg}")])
            .await?;
        let v = self.cyphr(&["data", "commit", &id, &signer]).await?;
        field(&v, "commit_id").map(Tip)
    }

    /// Commit the data actions recorded so far in one `ds/create` (`cyphr
    /// data commit`, no new action): what a device redoes after trusting the
    /// remote, since its recorded actions survived and only the commit went.
    pub async fn commit_recorded(&self, p: &Principal) -> ActionResult<Tip> {
        let (id, signer) = (format!("--identity={}", p.0), self.signer(p)?);
        let v = self
            .cyphr(&["data", "commit", &id, &format!("--signer={signer}")])
            .await?;
        field(&v, "commit_id").map(Tip)
    }

    /// Sign `p` with `tmb` from now on: the key a device held before an
    /// operation that replaced it was discarded with its commit.
    pub(crate) fn use_signer(&self, p: &Principal, tmb: &str) {
        self.state().signer.insert(p.0.clone(), tmb.to_owned());
    }

    /// Record a signed data action locally without committing it
    /// (`cyphr data action`, no `data commit`); returns its czd.
    pub async fn record_data(&self, p: &Principal, msg: &str) -> ActionResult<String> {
        let (id, signer) = (format!("--identity={}", p.0), self.signer(p)?);
        let v = self
            .cyphr(&[
                "data",
                "action",
                &id,
                &format!("--signer={signer}"),
                &format!("--msg={msg}"),
            ])
            .await?;
        field(&v, "czd")
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

    /// Trust the peer over local commits that diverge from it, after a
    /// stale refusal (`cyphr fetch --trust-remote` from the first peer this
    /// device knows for `p`): the local commits after the parting point are
    /// discarded and recorded data actions survive. The caller redoes what
    /// it meant to do on the adopted tip.
    pub async fn trust_remote(&self, p: &Principal) -> ActionResult<Adopted> {
        let peer = self.known(p).into_iter().next().ok_or_else(|| {
            ActionError::Failed(format!("`{}` knows no peer for {}", self.name, p.0))
        })?;
        let url = self.url(&peer).await;
        let v = self
            .cyphr(&[
                "fetch",
                "--identity",
                &p.0,
                "--peer",
                &url,
                "--trust-remote",
            ])
            .await?;
        let dropped = v["dropped_actions"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|r| field(r, "czd"))
            .collect::<ActionResult<Vec<_>>>()?;
        let discarded = v["discarded"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|d| d.as_str().map(str::to_owned))
            .collect();
        Ok(Adopted {
            tip: self.local_tip(p, &peer).await?,
            discarded,
            dropped,
        })
    }

    // ---- knowing a principal ----

    /// Hold a principal's genesis out of band, with a hint of where to look:
    /// the genesis public key goes into this device's keystore, which is
    /// where `cyphr` resolves a trusted genesis from.
    pub async fn trust_genesis(&self, p: &Principal, hint: &[&str]) -> ActionResult<()> {
        self.h.give_genesis(&self.dev.keystore, p)?;
        self.know(p, hint);
        Ok(())
    }

    /// Learn of a principal from another client, not from its owner.
    pub async fn learn_from(&self, other: &Client<'_>, p: &Principal) -> ActionResult<()> {
        let file = other.dev.scratch(&format!("bundle-{}.json", self.name));
        let path = file.to_string_lossy().into_owned();
        other
            .cyphr(&["gossip", "export", "--identity", &p.0, "--file", &path])
            .await?;
        self.cyphr(&["gossip", "import", "--identity", &p.0, "--file", &path])
            .await?;
        // The peers the other client asks are the hint of where to look.
        let hint = other.known(p);
        self.know(p, &hint.iter().map(String::as_str).collect::<Vec<_>>());
        Ok(())
    }

    /// `cyphr watch`: the verify command on a timer, here one round that
    /// must give an answer, so a watcher that cannot start is a failure.
    pub async fn watch(&self, p: &Principal) -> ActionResult<()> {
        let args = self.peer_args(p, "watch").await?;
        let mut args: Vec<&str> = args.iter().map(String::as_str).collect();
        args.extend(["--interval-secs=1", "--rounds=1"]);
        self.cyphr(&args).await.map(|_| ())
    }

    /// Hand every principal this client knows to `other`, as a bundle file.
    pub async fn gossip_with(&self, other: &Client<'_>) -> ActionResult<()> {
        let known: Vec<String> = self.state().peers.keys().cloned().collect();
        for handle in known {
            other.learn_from(self, &Principal(handle)).await?;
        }
        Ok(())
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
        let urls = self.urls(&names).await;
        let mut args = vec!["verify".to_owned(), "--identity".into(), p.0.clone()];
        for url in &urls {
            args.extend(["--peer".into(), url.clone()]);
        }
        let started = std::time::Instant::now();
        let v = self
            .cyphr(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await?;
        self.know(p, &names.iter().map(String::as_str).collect::<Vec<_>>());
        parse_verdict(&v, p, &names, &urls, started)
    }

    async fn urls(&self, names: &[String]) -> Vec<String> {
        let mut urls = Vec::with_capacity(names.len());
        for name in names {
            urls.push(self.url(name).await);
        }
        urls
    }

    /// `<command> --identity <p>` with one `--peer` per peer this client
    /// knows for `p`.
    async fn peer_args(&self, p: &Principal, command: &str) -> ActionResult<Vec<String>> {
        let names = self.known(p);
        if names.is_empty() {
            return Err(ActionError::Failed(format!(
                "`{}` knows no peer for {}",
                self.name, p.0
            )));
        }
        let mut args = vec![command.to_owned(), "--identity".into(), p.0.clone()];
        for url in self.urls(&names).await {
            args.extend(["--peer".into(), url]);
        }
        Ok(args)
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
            .await
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

    /// `cyphr audit`: the verify verdict with the evidence held in full, over
    /// the peers this client knows for `p`.
    pub async fn audit(&self, p: &Principal) -> ActionResult<Verdict> {
        let names = self.known(p);
        let args = self.peer_args(p, "audit").await?;
        let started = std::time::Instant::now();
        let v = self
            .cyphr(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .await?;
        let urls = self.urls(&names).await;
        parse_verdict(&v, p, &names, &urls, started)
    }

    // ---- data actions ----

    /// A data action signed by this device's key and not yet sent anywhere
    /// (`cyphr data action --sign-only`): the CLI's answer, which names the
    /// principal and carries the signed coz.
    pub async fn data_action(&self, p: &Principal, msg: &str) -> ActionResult<Action> {
        self.sign_action(p, &self.signer(p)?, msg, None).await
    }

    /// A data action signed by `key`, which this device holds, whatever the
    /// chain says of that key now.
    pub async fn action_by(&self, p: &Principal, key: &KeyRef, msg: &str) -> ActionResult<Action> {
        self.sign_action(p, &key.0, msg, None).await
    }

    /// A data action signed by `key` but dated an hour before now, so before
    /// `key` was retired when it was retired within the hour.
    pub async fn forge_backdated(&self, p: &Principal, key: &KeyRef) -> ActionResult<Action> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ActionError::Failed(format!("clock before the epoch: {e}")))?
            .as_secs();
        let then = now.saturating_sub(3600);
        self.sign_action(p, &key.0, "forged", Some(then)).await
    }

    async fn sign_action(
        &self,
        p: &Principal,
        signer: &str,
        msg: &str,
        now: Option<u64>,
    ) -> ActionResult<Action> {
        let mut args = vec![
            "data".to_owned(),
            "action".to_owned(),
            "--sign-only".to_owned(),
            format!("--identity={}", p.0),
            format!("--signer={signer}"),
            format!("--msg={msg}"),
        ];
        if let Some(now) = now {
            args.push(format!("--now={now}"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Ok(Action(self.cyphr(&args).await?.to_string()))
    }

    /// Send a signed action to `to` as an action-only bundle
    /// (`cyphr data submit`); the peer's refusal is the outcome.
    pub async fn submit(&self, a: &Action, to: &str) -> ActionResult<PushOutcome> {
        let signed: serde_json::Value = serde_json::from_str(&a.0)
            .map_err(|e| ActionError::Failed(format!("not a signed action ({e}): {}", a.0)))?;
        let file = self.dev.scratch("action.json");
        std::fs::write(&file, &a.0)
            .map_err(|e| ActionError::Failed(format!("writing {}: {e}", file.display())))?;
        let url = self.url(to).await;
        let identity = format!("--identity={}", field(&signed, "identity")?);
        let result = self
            .cyphr(&[
                "data",
                "submit",
                &identity,
                &format!("--peer={url}"),
                &format!("--file={}", file.display()),
            ])
            .await;
        match result {
            Ok(v) => Ok(PushOutcome::Accepted(Tip(field(&v, "tip")?))),
            Err(ActionError::Refused(r)) => Ok(PushOutcome::Refused(r)),
            Err(e) => Err(e),
        }
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
        let entry = usize::try_from(height)
            .ok()
            .and_then(|h| h.checked_sub(1))
            .and_then(|i| patch["payload"]["entries"].get(i))
            .ok_or_else(|| ActionError::Failed(format!("`{to}` serves no commit {height}")))?;
        // The commit's bundle exactly as served: `txs`, `keys`, `actions`.
        let mut body = serde_json::json!({"principal_id": p.bare()});
        for field in ["txs", "keys", "actions"] {
            if let Some(v) = entry.get(field) {
                body[field] = v.clone();
            }
        }
        let resp = self
            .h
            .http
            .post(format!("{}/push", self.url(to).await))
            .json(&body)
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
            400 => RefusalKind::Malformed,
            422 => cli::protocol_kind(body["payload"]["error"].as_str().unwrap_or_default()),
            401 | 403 => RefusalKind::Unauthorized,
            413 => RefusalKind::TooLarge,
            _ => {
                return Err(ActionError::Failed(format!(
                    "`{to}` /push {status}: {detail}"
                )));
            },
        };
        Ok(PushOutcome::Refused(Refusal { kind, detail }))
    }

    // ---- sign-on ----

    /// Sign in to `rp` as the principal this device signs for, with the
    /// key it signs with: the relying party issues a challenge, this
    /// device signs it, and the relying party decides from the chain it
    /// replayed from its pin.
    pub async fn sign_in(&self, rp: &RelyingParty<'_>) -> ActionResult<Session> {
        let (handle, key) = {
            let st = self.state();
            let mut signers = st.signer.iter();
            match (signers.next(), signers.next()) {
                (Some((p, k)), None) => (p.clone(), k.clone()),
                _ => {
                    return Err(ActionError::Failed(format!(
                        "`{}` must sign for exactly one principal to sign in",
                        self.name
                    )));
                },
            }
        };
        self.sign_in_with(rp, &Principal(handle), &KeyRef(key))
            .await
    }

    /// [`Client::sign_in`] with a key this device holds, active or not: how
    /// a scenario shows that a dead key opens nothing.
    pub async fn sign_in_with(
        &self,
        rp: &RelyingParty<'_>,
        p: &Principal,
        key: &KeyRef,
    ) -> ActionResult<Session> {
        let (p, key) = (p.clone(), key.0.clone());
        let entry = cli::key_entry(&self.dev.keystore, &key)?;
        let mut guard = rp.enrolled.lock().await;
        if guard.is_none() {
            let genesis = key_of_entry(&self.h.genesis_of(&p)?)?;
            *guard = Some(Enrolled {
                party: cyphr_client::RelyingParty::new(
                    p.bare(),
                    cyphr_client::Anchor::GenesisKey(genesis),
                    rp.config.clone(),
                    cyphr::principal::system_clock,
                ),
                peers: self.known(&p),
            });
        }
        let enrolled = guard.as_mut().expect("enrolled above");
        rp.pull(enrolled).await?;
        // A native client signs in over its own authenticated transport and
        // signs that session's handshake hash into the login.
        let conn = rp.open_channel(enrolled).await?;
        let h = cyphr_client::Connector::channel_binding(&conn)
            .ok_or_else(|| ActionError::Failed("the session exposed no binding".into()))?
            .as_bytes()
            .to_vec();
        let challenge = enrolled.party.challenge();
        let login = sign_login(
            &entry,
            &key,
            p.bare(),
            &rp.config.audience,
            &challenge,
            Some(&h),
        )?;
        let session = enrolled
            .party
            .sign_in_on(&login, &conn)
            .map_err(|r| ActionError::Refused(refusal_of(&r)))?;
        *rp.original.lock().expect("original channel") = Some(conn);
        Ok(Session {
            login,
            token: Token(session.token),
            key: KeyRef(session.key.to_b64()),
            principal: Principal(session.principal),
        })
    }
}

/// Read a `cyphr verify --output json` answer as a [`Verdict`]. `names` and
/// `urls` pair the scenario's peer names with the URLs the CLI was given.
fn parse_verdict(
    v: &serde_json::Value,
    p: &Principal,
    names: &[String],
    urls: &[String],
    started: std::time::Instant,
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
    let last_answered = |url: &str| {
        v["peers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["peer"] == url)
            .and_then(|e| e["answered_at"].as_i64())
    };
    let unreachable = names
        .iter()
        .zip(urls)
        .filter(|(_, url)| failed.contains(&url.as_str()))
        .map(|(name, url)| (name.clone(), last_answered(url)))
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
    let branches: Vec<Tip> = v["branches"]
        .as_array()
        .ok_or_else(|| bad("branches"))?
        .iter()
        .filter_map(|b| b.as_str().map(|s| Tip(s.to_owned())))
        .collect();
    let forked = v["evidence"]
        .as_array()
        .is_some_and(|e| e.iter().any(|x| x["kind"] == "principal_fork"));
    Ok(Verdict {
        observed_at: started,
        standing,
        freshness: Freshness {
            // The age of the principal's newest signed `now`, on the
            // verifier's clock; the pull age (`freshness.pull_age_secs`) is
            // the verifier's own and near zero after any pull.
            age: Duration::from_secs(
                v["freshness"]["principal_now_age_secs"]
                    .as_u64()
                    .ok_or_else(|| bad("a principal age"))?,
            ),
            // The pull adopts every longer chain that replays, so no peer
            // that answered is ahead of the verdict's tip.
            peer_reported_newer: false,
        },
        branches,
        tip,
        anchor,
        peers,
        evidence: if forked {
            vec![Evidence::PrincipalFork(p.clone())]
        } else {
            Vec::new()
        },
        resolved_by: v["resolved_by"].as_str().map(|k| KeyRef(k.to_owned())),
        unreachable,
        abandoned: v["resolved_forks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f["abandoned"].as_str().map(|t| Tip(t.to_owned())))
            .collect(),
    })
}

/// The audience the harness relying party serves.
const RP_AUDIENCE: &str = "rp.scenarios";

/// The harness name the relying party's own route to each peer goes under.
const RP_NODE: &str = "rp";

/// A public key from a keystore entry (`{alg, pub_key, ..}`).
fn key_of_entry(entry: &serde_json::Value) -> ActionResult<cyphr::Key> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let bad = |what: &str| ActionError::Failed(format!("keystore entry has no {what}: {entry}"));
    let alg = entry["alg"].as_str().ok_or_else(|| bad("alg"))?;
    let public =
        Base64UrlUnpadded::decode_vec(entry["pub_key"].as_str().ok_or_else(|| bad("pub_key"))?)
            .map_err(|e| ActionError::Failed(format!("pub_key is not base64url: {e}")))?;
    let tmb = coz::compute_thumbprint_for_alg(alg, &public).ok_or_else(|| bad("a usable key"))?;
    cyphr::Key::new(alg.to_owned(), tmb, public)
        .map_err(|e| ActionError::Failed(format!("keystore key: {e:?}")))
}

/// The login Coz (SPEC 17.2 Option A) `entry`'s key signs for `challenge`.
fn sign_login(
    entry: &serde_json::Value,
    tmb: &str,
    pr: &str,
    audience: &str,
    challenge: &str,
    h: Option<&[u8]>,
) -> ActionResult<coz::CozJson> {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    let bytes = |name: &str| {
        entry[name]
            .as_str()
            .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
            .ok_or_else(|| ActionError::Failed(format!("keystore entry has no {name}")))
    };
    let alg = entry["alg"]
        .as_str()
        .ok_or_else(|| ActionError::Failed("keystore entry has no alg".into()))?;
    let mut pay = serde_json::json!({
        "alg": alg,
        "now": cyphr::principal::system_clock(),
        "tmb": tmb,
        "typ": format!("{audience}{}", cyphr_client::LOGIN_TYP_SUFFIX),
        "pr": pr,
        "challenge": challenge,
    });
    if let Some(h) = h {
        pay["h"] = Base64UrlUnpadded::encode_string(h).into();
    }
    let pay_bytes = serde_json::to_vec(&pay).map_err(|e| ActionError::Failed(e.to_string()))?;
    let (sig, _) = coz::sign_json(&pay_bytes, alg, &bytes("prv_key")?, &bytes("pub_key")?)
        .ok_or_else(|| ActionError::Failed("signing the login failed".into()))?;
    serde_json::from_value(serde_json::json!({
        "pay": pay,
        "sig": Base64UrlUnpadded::encode_string(&sig),
    }))
    .map_err(|e| ActionError::Failed(e.to_string()))
}

fn refusal_of(r: &cyphr_client::Refusal) -> Refusal {
    use cyphr_client::Refusal as R;
    let kind = match r {
        R::KeyNotActive => RefusalKind::KeyNotActive,
        R::Malformed(_) => RefusalKind::Malformed,
        R::Stale(_) | R::Forked => RefusalKind::Stale,
        _ => RefusalKind::Unauthorized,
    };
    Refusal {
        kind,
        detail: r.to_string(),
    }
}

impl RelyingParty<'_> {
    /// Pull the principal's chain from the peers the relying party was
    /// enrolled with, over its own route to each.
    async fn pull(&self, enrolled: &mut Enrolled) -> ActionResult<()> {
        let mut connectors = Vec::new();
        for peer in &enrolled.peers {
            let url = format!("http://{}", self.h.route(RP_NODE, peer).await);
            let c = cyphr_client::HttpConnector::connect(
                &url,
                &cyphr_client::HttpOptions::new(Duration::from_secs(5)),
            )
            .map_err(|e| ActionError::Failed(format!("relying party to `{peer}`: {e}")))?;
            connectors.push((peer.clone(), c));
        }
        let peers: Vec<_> = connectors
            .iter()
            .map(|(name, connector)| cyphr_client::PullPeer { name, connector })
            .collect();
        enrolled.party.refresh(&peers).await;
        Ok(())
    }

    /// A fresh authenticated Noise session with the first peer the relying
    /// party pulls from: one more channel, with a handshake hash of its own.
    async fn open_channel(&self, enrolled: &Enrolled) -> ActionResult<NoiseConnector> {
        let name = enrolled.peers.first().ok_or_else(|| {
            ActionError::Failed("the relying party has no peer to open a channel to".into())
        })?;
        crate::transport::open_session(self.h.peer(name), &self.h.http)
            .await
            .map_err(|e| ActionError::Failed(format!("channel to `{name}`: {e}")))
    }

    /// Run `f` with the binding of the channel `on` names (`None` for
    /// plain HTTP), read from the session that carries it.
    async fn on_channel<T>(
        &self,
        on: Channel,
        f: impl FnOnce(&mut cyphr_client::RelyingParty, &NoiseConnector) -> T,
        f_http: impl FnOnce(&mut cyphr_client::RelyingParty) -> T,
    ) -> ActionResult<T> {
        let mut guard = self.enrolled.lock().await;
        let enrolled = guard
            .as_mut()
            .ok_or_else(|| ActionError::Failed("no principal is signed in".into()))?;
        match on {
            Channel::Http => Ok(f_http(&mut enrolled.party)),
            Channel::Other => {
                let conn = self.open_channel(enrolled).await?;
                Ok(f(&mut enrolled.party, &conn))
            },
            Channel::Original => {
                let held = self.original.lock().expect("original channel");
                let conn = held
                    .as_ref()
                    .ok_or_else(|| ActionError::Failed("no sign-in opened a channel yet".into()))?;
                Ok(f(&mut enrolled.party, conn))
            },
        }
    }

    /// Whether the session still stands, asked on the channel it opened on.
    pub async fn session_active(&self, t: &Token) -> ActionResult<bool> {
        self.on_channel(
            Channel::Original,
            |rp, conn| {
                rp.check_session_on(&t.0, cyphr_client::Connector::channel_binding(conn))
                    .is_ok()
            },
            |_| false,
        )
        .await
    }

    /// Present a token on a channel and learn whether it was accepted:
    /// `Original` is the channel the sign-in used, `Other` a second
    /// authenticated session opened now, `Http` no channel at all.
    pub async fn present(&self, t: &Token, on: Channel) -> ActionResult<Presented> {
        let verdict = |r: Result<cyphr_client::Trust, cyphr_client::Refusal>| match r {
            Ok(_) => Presented::Accepted,
            Err(r) => Presented::Refused(refusal_of(&r)),
        };
        self.on_channel(
            on,
            |rp, conn| {
                verdict(rp.check_session_on(&t.0, cyphr_client::Connector::channel_binding(conn)))
            },
            |rp| verdict(rp.check_session_on(&t.0, None)),
        )
        .await
    }

    /// Carry the login `s` was opened with to another channel, as a
    /// thief who captured it would: a login signed for one channel must not
    /// open a session on any other, or over HTTP.
    pub async fn replay_login(&self, s: &Session, on: Channel) -> ActionResult<Presented> {
        let verdict = |r: Result<cyphr_client::Session, cyphr_client::Refusal>| match r {
            Ok(_) => Presented::Accepted,
            Err(r) => Presented::Refused(refusal_of(&r)),
        };
        self.on_channel(
            on,
            |rp, conn| verdict(rp.sign_in_on(&s.login, conn)),
            |rp| verdict(rp.sign_in(&s.login)),
        )
        .await
    }

    /// The anchor the relying party reports it was enrolled with: the
    /// thumbprint of the genesis key it replays the principal from.
    pub async fn enrolled_anchor(&self) -> ActionResult<String> {
        let guard = self.enrolled.lock().await;
        let enrolled = guard
            .as_ref()
            .ok_or_else(|| ActionError::Failed("no principal is signed in".into()))?;
        match enrolled.party.anchor() {
            cyphr_client::Anchor::GenesisKey(key) => Ok(key.tmb().to_b64()),
            other => Err(ActionError::Failed(format!(
                "the relying party is enrolled at {other:?}, not a genesis key"
            ))),
        }
    }

    /// The relying party's own settings, read from it.
    pub async fn config(&self) -> ActionResult<RpConfig> {
        Ok(RpConfig {
            pull_age_bound: self.config.pull_age_bound,
            refresh_interval: self.config.refresh_interval,
        })
    }

    /// Let the relying party's view catch up with the principal: one pull.
    pub async fn refresh_view(&self) -> ActionResult<()> {
        let mut guard = self.enrolled.lock().await;
        let enrolled = guard
            .as_mut()
            .ok_or_else(|| ActionError::Failed("no principal is signed in to pull for".into()))?;
        self.pull(enrolled).await
    }
}

/// Observe session binding on a running peer: a fresh client signs in to a
/// relying party over a real authenticated Noise session, its token is
/// accepted on that channel and refused as `Unauthorized` on a second one.
/// `Ok(false)` when the capability is observably absent (the token works on
/// another channel).
pub async fn observe_session_binding(h: &Harness) -> ActionResult<bool> {
    let peer = h
        .peers
        .first()
        .ok_or_else(|| ActionError::Failed("no peer running".into()))?
        .name
        .clone();
    let alice = h.client("session-binding-probe");
    let rp = h.start_relying_party().await?;
    async {
        let pr = alice.create_principal().await?;
        match alice.push(&pr, &[&peer]).await? {
            PushOutcome::Accepted(_) => {},
            PushOutcome::Refused(r) => {
                return Err(ActionError::Failed(format!("probe push refused: {r:?}")));
            },
        }
        let session = alice.sign_in(&rp).await?;
        let original = rp.present(&session.token, Channel::Original).await?;
        let other = rp.present(&session.token, Channel::Other).await?;
        Ok(original == Presented::Accepted
            && matches!(other, Presented::Refused(r) if r.kind == RefusalKind::Unauthorized))
    }
    .await
}
