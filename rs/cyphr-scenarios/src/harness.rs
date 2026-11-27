//! The scenario harness: peers, the fault proxy, and the red gate.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::actions::{ActionResult, PeerTip, Principal};
use crate::bins::Bins;
use crate::capability::{Capability, ProbeError};
use crate::carrier::TcpCarrier;
use crate::peer::{Limits, Peer, PeerError, Role};
use crate::proxy::Proxy;

/// `name{labels} value` lines of Prometheus text, as (series, value).
pub fn counters(text: &str) -> HashMap<String, u64> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.rsplit_once(' ')?;
            Some((k.to_owned(), v.parse().ok()?))
        })
        .collect()
}

pub struct Harness {
    pub peers: Vec<Peer>,
    pub proxy: Arc<Proxy>,
    pub bins: &'static Bins,
    pub http: reqwest::Client,
    pub seed: u64,
    /// The body limit pinned on every peer, when the scenario set one.
    pub max_body_bytes: Option<u64>,
    /// Servers started on request (witnesses); kept alive with the harness.
    extra: Mutex<Vec<Peer>>,
    routes: Mutex<HashMap<(String, String), SocketAddr>>,
    /// When the observer may next read each peer; see [`Harness::pace`].
    observer_slots: Mutex<HashMap<String, Instant>>,
    /// Each principal's genesis public key (a keystore entry), as its
    /// creator made it: what a person can be handed out of band.
    genesis: Mutex<HashMap<String, serde_json::Value>>,
    /// Each peer's `/metrics` counters from process lifetimes that have
    /// ended; a counter is per process, so a stop would otherwise erase it.
    banked: Mutex<HashMap<String, HashMap<String, u64>>>,
}

/// Minimum spacing of the observer's reads of one peer: 40 per second,
/// well under the server's 100 per second per-source limit.
const OBSERVER_GAP: Duration = Duration::from_millis(25);

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
        Self::start_seeded(names, limits, seed).await
    }

    /// Like [`Harness::start_with`], with the seed given by the caller (a
    /// run that owns its seed, such as NETSIM's, must not read it from the
    /// environment twice).
    pub async fn start_seeded(
        names: &[&str],
        limits: Limits,
        seed: u64,
    ) -> Result<Harness, PeerError> {
        eprintln!("scenario seed = {seed}");
        let bins = Bins::get();
        let http = http_client();
        let proxy = Arc::new(Proxy::new(Arc::new(TcpCarrier), seed));
        let mut peers = Vec::with_capacity(names.len());
        for name in names {
            peers.push(
                Peer::start(
                    bins,
                    name,
                    &http,
                    Role::Attestor,
                    limits,
                    Some(Arc::clone(&proxy)),
                )
                .await?,
            );
        }
        Ok(Harness {
            peers,
            proxy,
            bins,
            http,
            seed,
            max_body_bytes: limits.max_body_bytes,
            extra: Mutex::default(),
            routes: Mutex::default(),
            observer_slots: Mutex::default(),
            genesis: Mutex::default(),
            banked: Mutex::default(),
        })
    }

    /// Like [`Harness::start`], with every peer gossiping with every other
    /// every `interval_secs`, each over its own proxy route (`from` dials
    /// `to`), so partitioning two peers cuts their gossip link and the
    /// proxy counts the attempts.
    pub async fn start_gossiping(names: &[&str], interval_secs: u64) -> Result<Harness, PeerError> {
        Self::start_gossiping_with(names, interval_secs, Limits::default()).await
    }

    /// [`Harness::start_gossiping`] with server limits pinned explicitly.
    pub async fn start_gossiping_with(
        names: &[&str],
        interval_secs: u64,
        limits: Limits,
    ) -> Result<Harness, PeerError> {
        let h = Self::start_with(names, limits).await?;
        h.mesh(names, interval_secs).await?;
        Ok(h)
    }

    /// [`Harness::start_gossiping_with`] with the seed given by the caller.
    pub async fn start_gossiping_seeded(
        names: &[&str],
        interval_secs: u64,
        limits: Limits,
        seed: u64,
    ) -> Result<Harness, PeerError> {
        let h = Self::start_seeded(names, limits, seed).await?;
        h.mesh(names, interval_secs).await?;
        Ok(h)
    }

    async fn mesh(&self, names: &[&str], interval_secs: u64) -> Result<(), PeerError> {
        let h = self;
        for from in names {
            let mut routes = Vec::new();
            for to in names.iter().filter(|to| to != &from) {
                routes.push(h.route(from, to).await);
            }
            h.peer(from)
                .enable_gossip(h.bins, &routes, interval_secs)
                .await?;
        }
        Ok(())
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

    /// Put `p`'s genesis public key in a keystore, where `cyphr` resolves a
    /// trusted genesis from: under the key's own thumbprint, which is how the
    /// CLI looks a commit's signer up and which it checks every entry against.
    /// For a principal opened by one key that is also the principal's
    /// handle; one opened by several has a PG that is no key's thumbprint.
    pub fn give_genesis(&self, keystore: &std::path::Path, p: &Principal) -> ActionResult<()> {
        crate::cli::put_key(keystore, &self.genesis_tmb(p)?, self.genesis_of(p)?)
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

    /// Spaces the observer's direct reads of one peer at least
    /// [`OBSERVER_GAP`] apart. The observer dials from 127.0.0.1, one
    /// source for the rate limiter, and its polling loops are otherwise
    /// unthrottled, so without this the scaffolding itself trips the
    /// limit it is there to observe.
    pub async fn pace(&self, peer: &str) {
        let at = {
            let mut slots = self.observer_slots.lock().expect("observer slots");
            let now = Instant::now();
            let at = slots.get(peer).map_or(now, |next| (*next).max(now));
            slots.insert(peer.to_owned(), at + OBSERVER_GAP);
            at
        };
        tokio::time::sleep_until(at.into()).await;
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
            return p.addr();
        }
        self.extra
            .lock()
            .expect("extra servers")
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no server named `{name}`"))
            .addr()
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
            Some(Arc::clone(&self.proxy)),
        )
        .await?;
        let addr = w.addr();
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
        self.pace(peer).await;
        let addr = self.upstream(peer);
        let resp = self
            .http
            .get(format!("http://{addr}/tip"))
            .query(&[("pg", p.0.as_str())])
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
            p.pg() == held.principal_id,
            "peer `{peer}` answered for {}, asked about {}",
            held.principal_id,
            p.0
        );
        Some(held)
    }

    /// How many data actions `peer` itself holds for `p`, read from its own
    /// `GET /patch`: those carried in a commit's bundle and those in
    /// action-only bundles. An action-only bundle moves no tip, root or
    /// height, so `/tip` cannot show that one was accepted. `None` if the
    /// peer does not know the principal.
    pub async fn peer_actions(&self, peer: &str, p: &Principal) -> Option<usize> {
        let addr = self.upstream(peer);
        let resp = self
            .http
            .get(format!("http://{addr}/patch"))
            .query(&[("pg", p.0.as_str())])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        let count = |bundles: &serde_json::Value, field: &str| {
            bundles.as_array().map_or(0, |bs| {
                bs.iter()
                    .map(|b| b[field].as_array().map_or(0, Vec::len))
                    .sum::<usize>()
            })
        };
        Some(count(&v["payload"]["actions"], "blobs") + count(&v["payload"]["entries"], "actions"))
    }

    /// `peer`'s `/metrics` counters as `series -> value`, read directly. The
    /// scrape rides the per-IP bucket it may be measuring, so a refusal is
    /// retried; it is the caller's N6 that counts what the peer refused.
    pub async fn scrape(&self, peer: &str) -> Result<HashMap<String, u64>, String> {
        let url = format!("http://{}/metrics", self.upstream(peer));
        let mut last = String::new();
        for _ in 0..20 {
            match self.http.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    let text = r
                        .text()
                        .await
                        .map_err(|e| format!("`{peer}` metrics body: {e}"))?;
                    return Ok(counters(&text));
                },
                Ok(r) => last = format!("status {}", r.status()),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("metrics of `{peer}` never served: {last}"))
    }

    /// Add `peer`'s live counters to its banked total. Call it before
    /// stopping the process the counters belong to.
    pub async fn bank_counters(&self, peer: &str) -> Result<(), String> {
        let live = self.scrape(peer).await?;
        let mut banked = self.banked.lock().expect("banked counters");
        let total = banked.entry(peer.to_owned()).or_default();
        for (series, v) in live {
            *total.entry(series).or_default() += v;
        }
        Ok(())
    }

    /// `peer`'s counters summed over every process lifetime: banked, plus
    /// the live process when one is running.
    pub async fn lifetime_counters(&self, peer: &str) -> Result<HashMap<String, u64>, String> {
        let mut total = self
            .banked
            .lock()
            .expect("banked counters")
            .get(peer)
            .cloned()
            .unwrap_or_default();
        if !self.peer_down(peer).await {
            for (series, v) in self.scrape(peer).await? {
                *total.entry(series).or_default() += v;
            }
        }
        Ok(total)
    }

    /// How many gossip rounds `peer` has completed, over every process
    /// lifetime, from its `/metrics` counter. A round that found every
    /// principal idle counts too, which the `gossip: pulled` log lines
    /// (one per pull) cannot see.
    pub async fn gossip_rounds(&self, peer: &str) -> Result<u64, String> {
        Ok(self
            .lifetime_counters(peer)
            .await?
            .get("cyphr_gossip_rounds_total")
            .copied()
            .unwrap_or(0))
    }

    /// Lines of `peer`'s server log containing `needle`.
    pub fn log_lines(&self, peer: &str, needle: &str) -> Vec<String> {
        std::fs::read_to_string(self.peer(peer).log_path())
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_owned)
            .collect()
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
        // A predictable path under a shared temp dir lets another local
        // user pre-create it, or plant a symlink there, and read or
        // redirect the logs. A random name made by a fresh `mkdir` (mode
        // explicit 0700, never following a symlink) cannot be pre-empted.
        let dir = match tempfile::Builder::new()
            .prefix(&format!("cyphr-scenario-logs-{test}-seed-{}-", self.seed))
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir()
        {
            Ok(d) => d.keep(),
            Err(e) => {
                eprintln!("cannot keep peer logs: {e}");
                return;
            },
        };
        for dump in crate::cli::hang_dumps() {
            let to = dir.join(format!(
                "{}-{}",
                dump.parent()
                    .and_then(|d| d.file_name())
                    .unwrap_or_default()
                    .to_string_lossy(),
                dump.file_name().unwrap_or_default().to_string_lossy()
            ));
            match std::fs::copy(&dump, &to) {
                Ok(_) => eprintln!("hung child's thread dump kept at {}", to.display()),
                Err(e) => eprintln!("thread dump {} not kept: {e}", dump.display()),
            }
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
        let tmb = genesis["tmb"]
            .as_str()
            .ok_or("fixture genesis has no tmb")?;
        // A one-key genesis is the implicit principal: its id is the key's
        // thumbprint under the hash its own algorithm names, labelled.
        let alg = genesis["alg"]
            .as_str()
            .ok_or("fixture genesis has no alg")?;
        let hash = cyphr::state::hash_alg_from_str(alg).map_err(|e| e.to_string())?;
        let id = cyphr::PrincipalGenesis::from_digest(
            hash,
            Base64UrlUnpadded::decode_vec(tmb).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?
        .to_string();
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
        Ok(Principal(id))
    }
}
