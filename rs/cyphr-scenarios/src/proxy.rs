//! The fault-injecting proxy.
//!
//! One listener per directed (client, peer) route, each forwarding bytes
//! to the peer's real address through a [`Carrier`]. All routes share one
//! [`World`], so a partition, delay, drop or offline applies to every
//! live and future connection on the affected links. Pump cancellation
//! follows tokio's `select!` pattern for tearing down on a state change.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::carrier::{Accept, Carrier};
use crate::faults::{FaultKind, Link, Schedule, World};

type Shared = Arc<watch::Sender<World>>;

/// Connection attempts a link has seen: those forwarded to the far end and
/// those the fault state stopped. Lets a scenario prove that a fault was
/// actually exercised by traffic, not merely declared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    pub forwarded: u64,
    pub blocked: u64,
}

type Stats = Arc<Mutex<std::collections::BTreeMap<Link, LinkStats>>>;

/// The address a route currently forwards to, shared by every route to one
/// node so [`Proxy::redirect`] re-points them all at once.
type Upstream = Arc<Mutex<SocketAddr>>;

pub struct Proxy {
    upstreams: Mutex<std::collections::BTreeMap<String, Upstream>>,
    carrier: Arc<dyn Carrier>,
    world: Shared,
    rng: Arc<Mutex<ChaCha8Rng>>,
    stats: Stats,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    sources: Mutex<std::collections::BTreeMap<String, IpAddr>>,
}

impl Proxy {
    /// `seed` drives the per-connection drop decisions.
    pub fn new(carrier: Arc<dyn Carrier>, seed: u64) -> Self {
        Self {
            upstreams: Mutex::default(),
            carrier,
            world: Arc::new(watch::channel(World::default()).0),
            rng: Arc::new(Mutex::new(ChaCha8Rng::seed_from_u64(seed))),
            stats: Stats::default(),
            tasks: Mutex::default(),
            sources: Mutex::default(),
        }
    }

    /// The loopback source address `from`'s forwarded connections leave
    /// from, so each node is its own client to the rate limiter, as in a
    /// real network. All of 127.0.0.0/8 is local on Linux; elsewhere only
    /// 127.0.0.1 exists, so every node shares it.
    fn source_of(&self, from: &str) -> Option<IpAddr> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let mut sources = self.sources.lock().expect("proxy sources");
        let n = sources.len() + 2;
        // 127.0.0.2 upward; 127.0.0.1 stays the harness's own address.
        let ip = *sources
            .entry(from.to_owned())
            .or_insert_with(|| IpAddr::from([127, 0, ((n >> 8) & 0xff) as u8, (n & 0xff) as u8]));
        Some(ip)
    }

    /// Open the route by which `from` reaches `to`, whose real address is
    /// `upstream`. Returns the address `from` must dial instead.
    pub async fn route(
        &self,
        from: &str,
        to: &str,
        upstream: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let acceptor = self.carrier.bind().await?;
        let addr = acceptor.local_addr();
        let upstream = Arc::clone(
            self.upstreams
                .lock()
                .expect("proxy upstreams")
                .entry(to.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(upstream))),
        );
        let task = tokio::spawn(accept_loop(
            acceptor,
            Link::new(from, to),
            upstream,
            Egress {
                carrier: Arc::clone(&self.carrier),
                src: self.source_of(from),
            },
            Arc::clone(&self.world),
            Arc::clone(&self.rng),
            Arc::clone(&self.stats),
        ));
        self.tasks.lock().expect("proxy task list").push(task);
        Ok(addr)
    }

    /// Forward every route to `to`, existing and future, to `upstream`
    /// instead: how a scenario puts a rigged responder in a peer's place.
    pub fn redirect(&self, to: &str, upstream: SocketAddr) {
        if let Some(cell) = self.upstreams.lock().expect("proxy upstreams").get(to) {
            *cell.lock().expect("proxy upstream") = upstream;
        }
    }

    pub fn apply(&self, fault: &FaultKind) {
        self.world.send_modify(|w| w.apply(fault));
    }

    pub fn partition(&self, a: &str, b: &str) {
        self.apply(&FaultKind::Partition(Link::new(a, b)));
    }

    pub fn heal(&self, a: &str, b: &str) {
        self.apply(&FaultKind::Heal(Link::new(a, b)));
    }

    pub fn delay(&self, link: &Link, d: Duration) {
        self.apply(&FaultKind::Delay(link.clone(), d));
    }

    pub fn drop(&self, link: &Link, p: f64) {
        self.apply(&FaultKind::Drop(link.clone(), p));
    }

    pub fn offline(&self, node: &str) {
        self.apply(&FaultKind::Offline(node.to_owned()));
    }

    pub fn online(&self, node: &str) {
        self.apply(&FaultKind::Online(node.to_owned()));
    }

    pub fn stats(&self, a: &str, b: &str) -> LinkStats {
        self.stats
            .lock()
            .expect("proxy stats")
            .get(&Link::new(a, b))
            .copied()
            .unwrap_or_default()
    }

    pub fn snapshot(&self) -> World {
        self.world.borrow().clone()
    }

    /// Replay `schedule` in real time.
    pub async fn play(&self, schedule: &Schedule) {
        let mut now = Duration::ZERO;
        for e in &schedule.events {
            tokio::time::sleep(e.at.saturating_sub(now)).await;
            now = e.at;
            self.apply(&e.fault);
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        for t in self.tasks.lock().expect("proxy task list").drain(..) {
            t.abort();
        }
    }
}

/// How a route's forwarded connections leave: over which carrier, from
/// which source address.
#[derive(Clone)]
struct Egress {
    carrier: Arc<dyn Carrier>,
    src: Option<IpAddr>,
}

async fn accept_loop(
    mut acceptor: Box<dyn Accept>,
    link: Link,
    upstream: Upstream,
    egress: Egress,
    world: Shared,
    rng: Arc<Mutex<ChaCha8Rng>>,
    stats: Stats,
) {
    while let Ok((client, _)) = acceptor.accept().await {
        let (link, egress, world, rng, stats, upstream) = (
            link.clone(),
            egress.clone(),
            Arc::clone(&world),
            Arc::clone(&rng),
            Arc::clone(&stats),
            Arc::clone(&upstream),
        );
        tokio::spawn(async move {
            let fault = {
                let w = world.borrow();
                if w.blocked(&link) {
                    stats
                        .lock()
                        .expect("proxy stats")
                        .entry(link.clone())
                        .or_default()
                        .blocked += 1;
                    return;
                }
                w.fault(&link)
            };
            stats
                .lock()
                .expect("proxy stats")
                .entry(link.clone())
                .or_default()
                .forwarded += 1;
            // The lock is held only for one draw and never across an await.
            if rng
                .lock()
                .expect("proxy rng")
                .gen_bool(fault.drop.clamp(0.0, 1.0))
            {
                return;
            }
            let target = *upstream.lock().expect("proxy upstream");
            let Ok(up) = egress.carrier.connect(target, egress.src).await else {
                return;
            };
            let (cr, cw) = tokio::io::split(client);
            let (ur, uw) = tokio::io::split(up);
            let mut cut = world.subscribe();
            let flow =
                async { tokio::join!(pump(cr, uw, &world, &link), pump(ur, cw, &world, &link)) };
            tokio::select! {
                _ = flow => {},
                _ = blocked(&mut cut, &link) => {},
            }
        });
    }
}

/// Resolves once `link` becomes blocked.
async fn blocked(rx: &mut watch::Receiver<World>, link: &Link) {
    loop {
        if rx.borrow_and_update().blocked(link) {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn pump<R, W>(mut from: R, mut to: W, world: &Shared, link: &Link)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let delay = world.borrow().fault(link).delay;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}
