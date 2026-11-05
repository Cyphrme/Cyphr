//! The scenario harness: peers, the fault proxy, and the red gate.

use std::sync::Arc;
use std::time::Duration;

use crate::actions::ActionResult;
use crate::bins::Bins;
use crate::capability::{Capability, ProbeError};
use crate::carrier::TcpCarrier;
use crate::peer::{Peer, PeerError};
use crate::proxy::Proxy;

pub struct Harness {
    pub peers: Vec<Peer>,
    pub proxy: Proxy,
    pub bins: &'static Bins,
    pub http: reqwest::Client,
    pub seed: u64,
}

/// A client that never reuses connections, so a fault injected between two
/// requests is seen by the second one, and that bounds every request.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("static client config")
}

impl Harness {
    /// Start one fresh-keyed peer per name. The seed comes from
    /// `CYPHR_SCENARIO_SEED` when set (to replay a run), else from the
    /// clock; it is printed so any failure can be replayed.
    pub async fn start(names: &[&str]) -> Result<Harness, PeerError> {
        let seed = std::env::var("CYPHR_SCENARIO_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64)
            });
        eprintln!("scenario seed = {seed}");
        let bins = Bins::get();
        let http = http_client();
        let mut peers = Vec::with_capacity(names.len());
        for name in names {
            peers.push(Peer::start(bins, name, &http).await?);
        }
        Ok(Harness {
            peers,
            proxy: Proxy::new(Arc::new(TcpCarrier), seed),
            bins,
            http,
            seed,
        })
    }

    pub fn peer(&self, name: &str) -> &Peer {
        self.peers
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no peer named `{name}`"))
    }

    /// The address `client` must dial to reach peer `to` through the proxy.
    pub async fn route(&self, client: &str, to: &str) -> std::net::SocketAddr {
        let peer = self.peer(to);
        self.proxy
            .route(client, &peer.name, peer.addr)
            .await
            .unwrap_or_else(|e| panic!("opening route {client}->{to}: {e}"))
    }

    /// The red gate. Probes each capability in table order and panics on
    /// the first absent one; a probe that cannot run is a harness defect
    /// and panics distinctly.
    pub async fn require(&self, caps: &[Capability]) {
        let mut caps = caps.to_vec();
        caps.sort();
        for cap in caps {
            match cap.probe().eval(self, cap).await {
                Ok(true) => {},
                Ok(false) => self.red(cap),
                Err(e) => panic!("harness defect: {e}"),
            }
        }
    }

    /// Poll `f` until it yields `true` or `within` elapses; panics on timeout.
    /// Convergence (gossip, anti-entropy, session expiry) is eventual, so
    /// scenarios wait for it rather than sleeping a guessed interval.
    pub async fn eventually<F, Fut>(&self, what: &str, within: Duration, mut f: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ActionResult<bool>>,
    {
        let deadline = std::time::Instant::now() + within;
        loop {
            if self.ok(f().await) {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out after {within:?} waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The marker every red scenario ends with: the first missing
    /// capability, the peer count, and this run's peer identities.
    pub fn red_marker(&self, cap: Capability) -> String {
        format!(
            "RED({}) after-setup peers={} ids={}",
            cap.name(),
            self.peers.len(),
            self.peers
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Evaluate every probe, reporting mechanics rather than outcome.
    pub async fn probe_all(&self) -> Vec<(Capability, Result<bool, ProbeError>)> {
        let mut out = Vec::new();
        for cap in crate::capability::ALL {
            out.push((cap, cap.probe().eval(self, cap).await));
        }
        out
    }
}
