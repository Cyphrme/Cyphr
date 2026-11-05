//! The fault-injecting proxy.
//!
//! One listener per directed (client, peer) route, each forwarding bytes
//! to the peer's real address through a [`Carrier`]. All routes share one
//! [`World`], so a partition, delay, drop or offline applies to every
//! live and future connection on the affected links. Pump cancellation
//! follows tokio's `select!` pattern for tearing down on a state change.

use std::io;
use std::net::SocketAddr;
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

pub struct Proxy {
    carrier: Arc<dyn Carrier>,
    world: Shared,
    rng: Arc<Mutex<ChaCha8Rng>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Proxy {
    /// `seed` drives the per-connection drop decisions.
    pub fn new(carrier: Arc<dyn Carrier>, seed: u64) -> Self {
        Self {
            carrier,
            world: Arc::new(watch::channel(World::default()).0),
            rng: Arc::new(Mutex::new(ChaCha8Rng::seed_from_u64(seed))),
            tasks: Mutex::default(),
        }
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
        let task = tokio::spawn(accept_loop(
            acceptor,
            Link::new(from, to),
            upstream,
            Arc::clone(&self.carrier),
            Arc::clone(&self.world),
            Arc::clone(&self.rng),
        ));
        self.tasks.lock().expect("proxy task list").push(task);
        Ok(addr)
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

async fn accept_loop(
    mut acceptor: Box<dyn Accept>,
    link: Link,
    upstream: SocketAddr,
    carrier: Arc<dyn Carrier>,
    world: Shared,
    rng: Arc<Mutex<ChaCha8Rng>>,
) {
    while let Ok((client, _)) = acceptor.accept().await {
        let (link, carrier, world, rng) = (
            link.clone(),
            Arc::clone(&carrier),
            Arc::clone(&world),
            Arc::clone(&rng),
        );
        tokio::spawn(async move {
            let fault = {
                let w = world.borrow();
                if w.blocked(&link) {
                    return;
                }
                w.fault(&link)
            };
            // The lock is held only for one draw and never across an await.
            if rng
                .lock()
                .expect("proxy rng")
                .gen_bool(fault.drop.clamp(0.0, 1.0))
            {
                return;
            }
            let Ok(up) = carrier.connect(upstream).await else {
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
