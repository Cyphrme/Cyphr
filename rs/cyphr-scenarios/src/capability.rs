//! The capability table: what a scenario needs from the system, and how
//! to observe whether the shipped binaries have it yet.
//!
//! A probe asks the running binaries, never a mock. Where a capability
//! has no observable surface yet, its probe is [`Probe::Pending`], which
//! reports absent until the supplying node replaces it with a real
//! observation. The declaration order is the table order that
//! `Harness::require` reports in.

use std::path::Path;

use crate::harness::Harness;

/// Declaration order is the fixed order of the capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Transport,
    CliNetwork,
    ChoicesFile,
    KeyPairing,
    Discovery,
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
}

pub const ALL: [Capability; 17] = [
    Capability::Transport,
    Capability::CliNetwork,
    Capability::ChoicesFile,
    Capability::KeyPairing,
    Capability::Discovery,
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
];

/// How a capability is observed.
pub enum Probe {
    /// `cyphr <args>` exits 0, and (if given) stdout contains the text.
    Cli(&'static [&'static str], Option<&'static str>),
    /// `cyphr-server <args>` exits 0.
    Server(&'static [&'static str]),
    /// `GET <path>` on a running peer answers something other than 404.
    Route(&'static str),
    /// A peer's startup output has a line with this prefix.
    Banner(&'static str),
    /// A path under the workspace root exists.
    WorkspacePath(&'static [&'static str]),
    /// No observable surface exists yet; reports absent. The named node
    /// replaces this with a real probe when it lands the capability.
    Pending(&'static str),
}

impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::CliNetwork => "cli-network",
            Self::ChoicesFile => "choices-file",
            Self::KeyPairing => "key-pairing",
            Self::Discovery => "discovery",
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
        }
    }

    /// The node whose landing makes this capability present.
    pub fn supplier(self) -> &'static str {
        match self {
            Self::Transport => "TR1",
            Self::CliNetwork | Self::ChoicesFile => "N16",
            Self::KeyPairing => "N22",
            Self::Discovery => "G4",
            Self::BranchStore => "G1",
            Self::Evidence => "N18a",
            Self::PeerGossip => "G2",
            Self::ClientGossip => "G3",
            Self::Audit => "N18b",
            Self::Pinning => "N23",
            Self::Idempotency => "N09",
            Self::VersionCheck => "N13",
            Self::PeerBackup => "N19",
            Self::PeerRollover => "N20",
            Self::RelyingParty => "SO2",
            Self::SessionBinding => "SO3",
        }
    }

    pub fn probe(self) -> Probe {
        match self {
            // The brief's probe was "peers accept the Cyphr ALPN over
            // QUIC"; transport is now decided as Noise XX, so TR1 owns the
            // final observation. Until then a peer announcing the secure
            // listener on stdout is the surface.
            Self::Transport => Probe::Banner("noise-xx listening on "),
            Self::CliNetwork => Probe::Cli(&["push", "--help"], None),
            Self::ChoicesFile => Probe::Cli(&["verify", "--help"], Some("--choices")),
            Self::KeyPairing => Probe::Cli(&["key", "accept", "--help"], None),
            Self::Discovery => Probe::Cli(&["discover", "--help"], None),
            // Observing a fork needs the fork-accepting store G1 builds.
            Self::BranchStore => Probe::Pending("G1"),
            Self::Evidence => Probe::Route("/evidence?pr=probe"),
            // The brief's probe was "config accepts [gossip] peers", but the
            // server's config does not reject unknown keys, so acceptance
            // cannot discriminate; a served route can.
            Self::PeerGossip => Probe::Route("/gossip"),
            Self::ClientGossip => Probe::Cli(&["gossip", "--help"], None),
            Self::Audit => Probe::Cli(&["audit", "--help"], None),
            Self::Pinning => Probe::Cli(&["watch", "--help"], None),
            // The observable form is a replayed data action against a running
            // peer, which needs the push path N09 and N16 provide. (An earlier
            // probe ran the library's red property; it read "zero tests run" as
            // present and never touched a binary.)
            Self::Idempotency => Probe::Pending("N09"),
            // Needs a hostile peer serving envelope v=99 and a network CLI.
            Self::VersionCheck => Probe::Pending("N13"),
            Self::PeerBackup => Probe::Server(&["backup", "--help"]),
            Self::PeerRollover => Probe::Server(&["rotate-key", "--help"]),
            Self::RelyingParty => {
                Probe::WorkspacePath(&["cyphr-client", "examples", "relying_party.rs"])
            },
            // Needs a signed-in session and a second connection.
            Self::SessionBinding => Probe::Pending("SO3"),
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
            Probe::Route(path) => {
                let peer = h
                    .peers
                    .first()
                    .ok_or_else(|| run("no peer running".into()))?;
                let resp = h
                    .http
                    .get(format!("http://{}{path}", peer.addr))
                    .send()
                    .await
                    .map_err(|e| run(e.to_string()))?;
                Ok(resp.status() != reqwest::StatusCode::NOT_FOUND)
            },
            Probe::Banner(prefix) => {
                let peer = h
                    .peers
                    .first()
                    .ok_or_else(|| run("no peer running".into()))?;
                Ok(peer.stdout_lines().iter().any(|l| l.starts_with(prefix)))
            },
            Probe::WorkspacePath(parts) => {
                let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .expect("crate sits in the workspace");
                Ok(parts
                    .iter()
                    .fold(root.to_path_buf(), |p, c| p.join(c))
                    .exists())
            },
            Probe::Pending(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: the `version-check` capability is observed, not parked behind a
    /// pending supplier. While it is `Pending` every scenario that requires
    /// it (S10) stops at the capability table and never reaches its
    /// unknown-version step. Turns red while `probe()` is
    /// `Probe::Pending(..)`. A unit test: the table is the unit, and the
    /// observation itself is exercised by `s10_hostile`.
    #[test]
    #[ignore = "RED(N13): version-check is still Probe::Pending"]
    fn version_check_probe_is_a_real_observation() {
        assert!(
            !matches!(Capability::VersionCheck.probe(), Probe::Pending(_)),
            "version-check must be observed against the shipped binaries"
        );
    }
}
