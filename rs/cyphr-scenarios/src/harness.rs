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
    /// Each principal's genesis public key (a keystore entry), as its
    /// creator made it: what a person can be handed out of band.
    genesis: Mutex<HashMap<String, serde_json::Value>>,
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
            genesis: Mutex::default(),
        })
    }

    /// Like [`Harness::start`], with every peer gossiping with every other
    /// every `interval_secs`, each over its own proxy route (`from` dials
    /// `to`), so partitioning two peers cuts their gossip link and the
    /// proxy counts the attempts.
    pub async fn start_gossiping(names: &[&str], interval_secs: u64) -> Result<Harness, PeerError> {
        let h = Self::start(names).await?;
        for from in names {
            let mut routes = Vec::new();
            for to in names.iter().filter(|to| to != &from) {
                routes.push(h.route(from, to).await);
            }
            h.peer(from)
                .enable_gossip(h.bins, &routes, interval_secs)
                .await?;
        }
        Ok(h)
    }

    /// Remember `p`'s genesis public key (a public-only keystore entry).
    pub fn record_genesis(&self, p: &Principal, entry: serde_json::Value) {
        self.genesis
            .lock()
            .expect("genesis registry")
            .insert(p.0.clone(), entry);
    }

    /// `p`'s genesis public key, as recorded when it was created.
    pub fn genesis_of(&self, p: &Principal) -> ActionResult<serde_json::Value> {
        self.genesis
            .lock()
            .expect("genesis registry")
            .get(&p.0)
            .cloned()
            .ok_or_else(|| {
                crate::actions::ActionError::Failed(format!("no client created {}", p.0))
            })
    }

    /// The thumbprint of `p`'s genesis key, the anchor a relying party is
    /// enrolled with. A principal opened by one key has that thumbprint as
    /// its PG, so a session subject that resolves under this key names the
    /// enrolled principal and not merely a handle spelled like it.
    pub fn genesis_tmb(
        &self,
        p: &crate::actions::Principal,
    ) -> crate::actions::ActionResult<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let fail = |what: String| crate::actions::ActionError::Failed(what);
        let entry = self.genesis_of(p)?;
        let alg = entry["alg"]
            .as_str()
            .ok_or_else(|| fail("genesis entry has no alg".into()))?;
        let public = entry["pub_key"]
            .as_str()
            .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
            .ok_or_else(|| fail("genesis entry has no pub_key".into()))?;
        coz::compute_thumbprint_for_alg(alg, &public)
            .map(|t| t.to_b64())
            .ok_or_else(|| fail(format!("no thumbprint for a {alg} genesis key")))
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

    /// How many data actions `peer` itself holds for `p`, read from its own
    /// `GET /patch`. An action-only bundle moves no tip, root or height, so
    /// `/tip` cannot show that one was accepted. `None` if the peer does not
    /// know the principal.
    pub async fn peer_actions(&self, peer: &str, p: &Principal) -> Option<usize> {
        let addr = self.upstream(peer);
        let resp = self
            .http
            .get(format!("http://{addr}/patch"))
            .query(&[("pr", p.0.as_str())])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        let bundles = v["payload"]["actions"].as_array()?;
        Some(
            bundles
                .iter()
                .map(|b| b["blobs"].as_array().map_or(0, Vec::len))
                .sum(),
        )
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

impl Drop for Harness {
    /// A failing scenario unwinds through here; its peers' logs live in
    /// temp dirs about to be deleted, so copy them out first and name
    /// where they went. A passing run keeps nothing.
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let test = std::thread::current()
            .name()
            .unwrap_or("scenario")
            .replace("::", "-");
        let dir = std::env::temp_dir()
            .join("cyphr-scenario-logs")
            .join(format!("{test}-seed-{}", self.seed));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("cannot keep peer logs in {}: {e}", dir.display());
            return;
        }
        let extra = self.extra.get_mut().unwrap_or_else(|e| e.into_inner());
        for p in self.peers.iter().chain(extra.iter()) {
            let to = dir.join(format!("{}.server.log", p.name));
            match std::fs::copy(p.log_path(), &to) {
                Ok(_) => eprintln!("peer `{}` log kept at {}", p.name, to.display()),
                Err(e) => eprintln!("peer `{}` log not kept ({}): {e}", p.name, to.display()),
            }
        }
    }
}

/// A golden-corpus principal with one genesis key and one commit, used to
/// give self-tests a real principal on real peers.
const SEED_FIXTURE: &str = "algorithm_diversity/ed25519_account_adds_es256_key";

impl Harness {
    /// Push the seed fixture to each of `peers` over HTTP, as a client
    /// would, and return the principal (its genesis tmb, SPEC 3.1). Used to
    /// self-test the observer and the oracle against peers that hold
    /// something; scenarios themselves go through the action seam.
    pub async fn seed_principal(&self, peers: &[&str]) -> Result<Principal, String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden")
            .join(format!("{SEED_FIXTURE}.json"));
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?,
        )
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;
        let genesis = &fixture["genesis_keys"][0];
        let id = genesis["tmb"]
            .as_str()
            .ok_or("fixture genesis has no tmb")?;
        // The fixture's genesis commit, pushed in the wire form: each coz
        // of each transaction as a base64url string, the keys as stated.
        let commit = &fixture["commits"][0];
        let txs = commit["txs"]
            .as_array()
            .ok_or("fixture commit has no txs")?
            .iter()
            .map(|tx| {
                tx.as_array()
                    .ok_or("fixture transaction is not an array")?
                    .iter()
                    .map(|coz| {
                        serde_json::to_vec(coz)
                            .map(|b| Base64UrlUnpadded::encode_string(&b))
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .collect::<Result<Vec<_>, String>>()?;
        let body = serde_json::json!({"principal_id": id, "txs": txs, "keys": commit["keys"]});
        for peer in peers {
            let addr = self.upstream(peer);
            let r = self
                .http
                .post(format!("http://{addr}/push"))
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("push to `{peer}`: {e}"))?;
            if !r.status().is_success() {
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                return Err(format!("push to `{peer}` answered {status}: {text}"));
            }
        }
        Ok(Principal(id.to_owned()))
    }
}
