//! The scenario harness: peers, the fault proxy, and the red gate.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::actions::{ActionResult, PeerTip, Principal};
use crate::bins::Bins;
use crate::capability::{Capability, ProbeError};
use crate::carrier::TcpCarrier;
use crate::peer::{Limits, Peer, PeerError, Role};
use crate::proxy::Proxy;

pub struct Harness {
    pub peers: Vec<Peer>,
    pub proxy: Proxy,
    pub bins: &'static Bins,
    pub http: reqwest::Client,
    pub seed: u64,
    /// The body limit pinned on every peer, when the scenario set one.
    pub max_body_bytes: Option<u64>,
    /// Servers started on request (witnesses); kept alive with the harness.
    extra: Mutex<Vec<Peer>>,
    routes: Mutex<HashMap<(String, String), SocketAddr>>,
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
        Self::start_with(names, Limits::default()).await
    }

    /// Like [`Harness::start`], with server limits pinned explicitly.
    pub async fn start_with(names: &[&str], limits: Limits) -> Result<Harness, PeerError> {
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
            peers.push(Peer::start(bins, name, &http, Role::Attestor, limits).await?);
        }
        Ok(Harness {
            peers,
            proxy: Proxy::new(Arc::new(TcpCarrier), seed),
            bins,
            http,
            seed,
            max_body_bytes: limits.max_body_bytes,
            extra: Mutex::default(),
            routes: Mutex::default(),
        })
    }

    pub fn peer(&self, name: &str) -> &Peer {
        self.peers
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no peer named `{name}`"))
    }

    /// The address `client` must dial to reach `to` through the proxy. One
    /// route per (client, peer), reused, so a fault on the link applies to
    /// everything that client sends.
    pub async fn route(&self, client: &str, to: &str) -> SocketAddr {
        let key = (client.to_owned(), to.to_owned());
        if let Some(a) = self.routes.lock().expect("route cache").get(&key) {
            return *a;
        }
        let upstream = self.upstream(to);
        let addr = self
            .proxy
            .route(client, to, upstream)
            .await
            .unwrap_or_else(|e| panic!("opening route {client}->{to}: {e}"));
        self.routes.lock().expect("route cache").insert(key, addr);
        addr
    }

    fn upstream(&self, name: &str) -> SocketAddr {
        if let Some(p) = self.peers.iter().find(|p| p.name == name) {
            return p.addr;
        }
        self.extra
            .lock()
            .expect("extra servers")
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no server named `{name}`"))
            .addr
    }

    /// Start a witness named `name` that pulls from peer `of` over a proxy
    /// route, so partitioning `name` from `of` cuts the pull. Returns the
    /// witness's own address (clients may read it directly).
    pub async fn start_witness(&self, name: &str, of: &str) -> Result<SocketAddr, PeerError> {
        let authority = self.route(name, of).await;
        let w = Peer::start(
            self.bins,
            name,
            &self.http,
            Role::Witness { authority },
            Limits::default(),
        )
        .await?;
        let addr = w.addr;
        self.extra.lock().expect("extra servers").push(w);
        Ok(addr)
    }

    /// Whether `from` can complete a request to `to` through the proxy.
    pub async fn reach(&self, from: &str, to: &str) -> bool {
        let via = self.route(from, to).await;
        self.http
            .get(format!("http://{via}/server"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }

    /// Whether the peer process itself no longer answers (read directly,
    /// not through the proxy).
    pub async fn peer_down(&self, peer: &str) -> bool {
        let addr = self.upstream(peer);
        self.http
            .get(format!("http://{addr}/server"))
            .send()
            .await
            .is_err()
    }

    /// What peer `peer` itself holds for `p`, read from its own `GET /tip`
    /// directly, independent of every action under test. `None` if the peer
    /// does not know the principal.
    pub async fn peer_view(&self, peer: &str, p: &Principal) -> Option<PeerTip> {
        let addr = self.upstream(peer);
        let resp = self
            .http
            .get(format!("http://{addr}/tip"))
            .query(&[("pr", p.0.as_str())])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        let held = PeerTip::parse(&v)?;
        // The observer must be reading the principal it asked about.
        assert!(
            p.same_as(&held.principal_id),
            "peer `{peer}` answered for {}, asked about {}",
            held.principal_id,
            p.0
        );
        Some(held)
    }

    /// Read `peer`'s view of `p` until two reads 600ms apart agree, then
    /// return it. A negative claim ("nothing changed") is only meaningful
    /// once in-flight work has settled, so assert on this, never on an
    /// immediate read.
    pub async fn settled_view(&self, peer: &str, p: &Principal) -> Option<PeerTip> {
        let mut last = self.peer_view(peer, p).await;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let now = self.peer_view(peer, p).await;
            if now == last {
                return now;
            }
            last = now;
        }
        panic!("peer `{peer}` never settled");
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
