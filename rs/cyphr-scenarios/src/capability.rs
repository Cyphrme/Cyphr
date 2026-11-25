//! The capability table: what a scenario needs from the system, and how
//! to observe whether the shipped binaries have it yet.
//!
//! A probe asks the running binaries, never a mock. The declaration order
//! is the table order that `Harness::require` reports in.

use std::path::Path;

use crate::harness::Harness;

/// Declaration order is the fixed order of the capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Transport,
    CliNetwork,
    ChoicesFile,
    KeyPairing,
    KeyOps,
    BranchStore,
    Evidence,
    PeerGossip,
    ClientGossip,
    Audit,
    Pinning,
    Idempotency,
    VersionCheck,
    PeerBackup,
    PeerRollover,
    RelyingParty,
    SessionBinding,
    DataCommit,
}

pub const ALL: [Capability; 18] = [
    Capability::Transport,
    Capability::CliNetwork,
    Capability::ChoicesFile,
    Capability::KeyPairing,
    Capability::KeyOps,
    Capability::BranchStore,
    Capability::Evidence,
    Capability::PeerGossip,
    Capability::ClientGossip,
    Capability::Audit,
    Capability::Pinning,
    Capability::Idempotency,
    Capability::VersionCheck,
    Capability::PeerBackup,
    Capability::PeerRollover,
    Capability::RelyingParty,
    Capability::SessionBinding,
    Capability::DataCommit,
];

/// How a capability is observed.
pub enum Probe {
    /// `cyphr <args>` exits 0, and (if given) stdout contains the text.
    Cli(&'static [&'static str], Option<&'static str>),
    /// `cyphr-server <args>` exits 0.
    Server(&'static [&'static str]),
    /// `cyphr-server <args>` exits 0 and its stdout contains the text.
    ServerHelp(&'static [&'static str], &'static str),
    /// `GET <path>` on a running peer answers something other than 404.
    Route(&'static str),
    /// A peer's startup output has a line with this prefix.
    Banner(&'static str),
    /// A real client completes a Noise handshake with the first peer, both
    /// signed binding statements verifying, and is served a request.
    Handshake,
    /// A hostile responder serves this envelope version over the transport
    /// and the client fails closed on it with the typed refusal.
    VersionGate(u64),
    /// A fresh peer refuses a commit that re-includes an applied
    /// transaction coz with `COZ_REUSE`, and keeps its tip (SPEC 7.6).
    CozReuse,
    /// A client signs in to a relying party over a real authenticated
    /// Noise session; the session's token is accepted on that channel and
    /// refused (`Unauthorized`) on a second session.
    SessionBinding,
    /// A path under the workspace root exists.
    WorkspacePath(&'static [&'static str]),
}

impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::CliNetwork => "cli-network",
            Self::ChoicesFile => "choices-file",
            Self::KeyPairing => "key-pairing",
            Self::KeyOps => "key-ops",
            Self::BranchStore => "branch-store",
            Self::Evidence => "evidence",
            Self::PeerGossip => "peer-gossip",
            Self::ClientGossip => "client-gossip",
            Self::Audit => "audit",
            Self::Pinning => "pinning",
            Self::Idempotency => "idempotency",
            Self::VersionCheck => "version-check",
            Self::PeerBackup => "peer-backup",
            Self::PeerRollover => "peer-rollover",
            Self::RelyingParty => "relying-party",
            Self::SessionBinding => "session-binding",
            Self::DataCommit => "data-commit",
        }
    }

    pub fn probe(self) -> Probe {
        match self {
            // Principal-authenticated Noise (TR1): the observation is a
            // completed handshake in which both statements verify, not an
            // announcement that a listener exists.
            Self::Transport => Probe::Handshake,
            Self::CliNetwork => Probe::Cli(&["push", "--help"], None),
            Self::ChoicesFile => Probe::Cli(&["verify", "--help"], Some("--choices")),
            Self::KeyPairing => Probe::Cli(&["key", "accept", "--help"], None),
            Self::KeyOps => Probe::Cli(&["key", "naked-revoke", "--help"], None),
            // Bare, so the route answers 400 (no `pr`) where an absent route
            // answers 404; a probe with a `pr` would read a stored-branch
            // lookup's own 404 for an unknown principal as an absent route.
            Self::BranchStore => Probe::Route("/branches"),
            Self::Evidence => Probe::Route("/evidence?pg=probe"),
            // Gossip is a timer inside the server calling the client's pull
            // step, with no route of its own. Its operator surface is the
            // flag that names the peers; the scenarios that need it
            // (`gossip_timer`, S02, S03, S04) observe the behaviour itself.
            Self::PeerGossip => Probe::ServerHelp(&["serve", "--help"], "--gossip-peer"),
            Self::ClientGossip => Probe::Cli(&["gossip", "--help"], None),
            Self::Audit => Probe::Cli(&["audit", "--help"], None),
            Self::Pinning => Probe::Cli(&["watch", "--help"], None),
            // Observed on a running peer's push path: a replayed transaction
            // coz is refused as COZ_REUSE. (An earlier probe ran the library's
            // red property; it read "zero tests run" as present and never
            // touched a binary.)
            Self::Idempotency => Probe::CozReuse,
            // Every stored and wire format refuses an unknown `v`; the
            // observable form is a hostile peer serving envelope v=99 to a
            // network client, which the transport now carries.
            Self::VersionCheck => Probe::VersionGate(99),
            Self::PeerBackup => Probe::Server(&["backup", "--help"]),
            Self::PeerRollover => Probe::Server(&["rotate-key", "--help"]),
            Self::RelyingParty => {
                Probe::WorkspacePath(&["cyphr-client", "examples", "relying_party.rs"])
            },
            Self::SessionBinding => Probe::SessionBinding,
            Self::DataCommit => Probe::Cli(&["data", "commit", "--help"], None),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe for `{cap}` could not run: {reason}")]
    Run { cap: &'static str, reason: String },
}

impl Probe {
    /// `Ok(true)` if the capability is present, `Ok(false)` if observably
    /// absent, `Err` if the probe itself could not be evaluated.
    pub async fn eval(&self, h: &Harness, cap: Capability) -> Result<bool, ProbeError> {
        let run = |reason: String| ProbeError::Run {
            cap: cap.name(),
            reason,
        };
        match self {
            Probe::Cli(args, needle) => {
                let out = tokio::process::Command::new(&h.bins.cli)
                    .args(*args)
                    .output()
                    .await
                    .map_err(|e| run(e.to_string()))?;
                Ok(out.status.success()
                    && needle.is_none_or(|n| String::from_utf8_lossy(&out.stdout).contains(n)))
            },
            Probe::Server(args) => {
                let status = tokio::process::Command::new(&h.bins.server)
                    .args(*args)
                    .output()
                    .await
                    .map_err(|e| run(e.to_string()))?
                    .status;
                Ok(status.success())
            },
            Probe::ServerHelp(args, needle) => {
                let out = tokio::process::Command::new(&h.bins.server)
                    .args(*args)
                    .output()
                    .await
                    .map_err(|e| run(e.to_string()))?;
                Ok(out.status.success() && String::from_utf8_lossy(&out.stdout).contains(needle))
            },
            Probe::Route(path) => {
                // The first peer that answers: a scenario may have stopped
                // some, and a stopped peer says nothing about the route.
                let mut last = "no peer running".to_owned();
                for peer in &h.peers {
                    match h
                        .http
                        .get(format!("http://{}{path}", peer.addr()))
                        .send()
                        .await
                    {
                        Ok(resp) => return Ok(resp.status() != reqwest::StatusCode::NOT_FOUND),
                        Err(e) => last = e.to_string(),
                    }
                }
                Err(run(last))
            },
            Probe::Banner(prefix) => {
                let peer = h
                    .peers
                    .first()
                    .ok_or_else(|| run("no peer running".into()))?;
                Ok(peer.stdout_lines().iter().any(|l| l.starts_with(prefix)))
            },
            Probe::Handshake => {
                let peer = h
                    .peers
                    .first()
                    .ok_or_else(|| run("no peer running".into()))?;
                Ok(crate::transport::handshake(peer, &h.http).await.is_ok())
            },
            Probe::VersionGate(v) => crate::transport::client_fails_closed_on_version(*v)
                .await
                .map_err(run),
            Probe::CozReuse => crate::idempotency::replay_on_fresh_peer(h.bins, &h.http)
                .await
                .map(|a| a.refused_as_reuse())
                .map_err(run),
            Probe::WorkspacePath(parts) => {
                let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("crate sits in the workspace");
                Ok(parts
                    .iter()
                    .fold(root.to_path_buf(), |p, c| p.join(c))
                    .exists())
            },
            Probe::SessionBinding => crate::actions::observe_session_binding(h)
                .await
                .map_err(|e| run(e.to_string())),
        }
    }
}
