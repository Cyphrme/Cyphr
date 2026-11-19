//! U3 cost bounds of the served operations, pinned as counts (never time):
//! what a request replays, how many proof hashes it carries, how many
//! requests a gossip round makes and what a client does to find a fork
//! must not grow with the length of the principal's history. Each runs on
//! principals of three sizes (see `suite!` below); the timed counterpart
//! is `cargo bench -p cyphr-server --bench u3_server`.
//!
//! The engines these tests build have the kept-state shadow check
//! (`CYPHR_KEPT_SHADOW`) off: it replays cold on every use and those
//! replays and reads are counted too, so with it on the counts would measure
//! the check and not the engine.
//!
//! A red test is a bound the server does not yet meet: the finding, not a
//! defect of the test.

#[path = "../../cyphr-storage/benches/common/mod.rs"]
mod common;
#[path = "../benches/support/mod.rs"]
mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use axum::http::StatusCode;
use common::Chain;
use cyphr_client::HttpConnector;
use cyphr_server::auth::principal::ServerPrincipal;
use cyphr_server::config::ServerConfig;
use cyphr_server::gossip::Gossip;
use cyphr_server::{AppState, build_router};
use support::*;
use tokio::sync::OnceCell;

const K: usize = 3;

#[derive(Debug)]
struct Obs {
    n: usize,
    write_replayed: u64,
    tip_replayed: u64,
    patch_replayed: u64,
    extends_replayed: u64,
    extends_hashes: usize,
    member_replayed: u64,
    member_hashes: usize,
    login_replayed: u64,
    session_replayed: u64,
    idle_requests: u64,
    idle_replayed: u64,
    idle_gossip_replayed: u64,
    pull_gossip_replayed: u64,
    pull_replayed: u64,
}

async fn observe(n: usize) -> Obs {
    let (a, _da) = attestor().await;
    let (b, _db) = keyless();
    let (app_a, app_b) = (build_router(a.clone()), build_router(b.clone()));
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let mut bundles = vec![chain.first()];
    while chain.commits < n {
        bundles.push(chain.next().await);
    }
    for bundle in &bundles {
        for app in [&app_a, &app_b] {
            let (st, ..) = call(app, "POST", "/push", push_body(&id, bundle)).await;
            assert_eq!(st, StatusCode::CREATED);
        }
    }

    let replayed = || a.engine.commits_replayed();
    let ok = |(st, _, body): (StatusCode, usize, Vec<u8>)| {
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")
    };
    // Hashes in an `extends` certificate: the boundary, the peak path and
    // the new peaks; in a `member` certificate: the path. A chain that never
    // rotated an algorithm has no stitch, so each is its terminal alone.
    let len = |v: &serde_json::Value| v.as_array().expect("array").len();
    let extends_hashes = |v: &serde_json::Value| {
        let p = &v["payload"]["certificate"]["terminal"];
        1 + len(&p["peak_path"]) + len(&p["new_peaks"])
    };
    let member_hashes =
        |v: &serde_json::Value| len(&v["payload"]["certificate"]["terminal"]["steps"]);

    let before = replayed();
    let w = chain.next().await;
    let (st, ..) = call(&app_a, "POST", "/push", push_body(&id, &w)).await;
    assert_eq!(st, StatusCode::CREATED);
    call(&app_b, "POST", "/push", push_body(&id, &w)).await;
    let write_replayed = replayed() - before;
    let n = chain.commits;

    let before = replayed();
    let tip = ok(call(&app_a, "GET", &format!("/tip?pr={id}"), String::new()).await);
    let tip_replayed = replayed() - before;
    let commit_id = tip["payload"]["commit_id"].as_str().expect("commit_id");

    let before = replayed();
    ok(call(
        &app_a,
        "GET",
        &format!("/patch?pr={id}&from={commit_id}"),
        String::new(),
    )
    .await);
    let patch_replayed = replayed() - before;

    let before = replayed();
    let c = ok(call(
        &app_a,
        "GET",
        &format!("/proof?pr={id}&size={n}&claim=extends:{}", n / 2),
        String::new(),
    )
    .await);
    let extends_replayed = replayed() - before;
    let before = replayed();
    let i = ok(call(
        &app_a,
        "GET",
        &format!("/proof?pr={id}&size={n}&claim=member:{}", n / 2),
        String::new(),
    )
    .await);
    let member_replayed = replayed() - before;

    let before = replayed();
    let login = ok(call(&app_a, "POST", "/auth/login", login_body(&id)).await);
    let login_replayed = replayed() - before;
    let token = login["payload"]["token"]
        .as_str()
        .expect("token")
        .to_owned();
    let before = replayed();
    ok(call(&app_a, "POST", "/auth/session", token).await);
    let session_replayed = replayed() - before;

    let (url, wire) = serve_counting(app_b.clone()).await;
    let peers = [(
        url.clone(),
        HttpConnector::with_client(a.http_client.clone(), &url, true).expect("connector"),
    )];
    let mut gossip = Gossip::default();
    gossip.round(&a, &peers).await;
    let gossiped = || series(&a, "cyphr_gossip_commits_replayed_total");
    let (r0, g0, q0) = (replayed(), gossiped(), wire.requests.load(Relaxed));
    gossip.round(&a, &peers).await;
    let idle_requests = wire.requests.load(Relaxed) - q0;
    let (idle_replayed, idle_gossip_replayed) = (replayed() - r0, gossiped() - g0);

    for _ in 0..K {
        let b2 = chain.next().await;
        call(&app_b, "POST", "/push", push_body(&id, &b2)).await;
    }
    let (r0, g0) = (replayed(), gossiped());
    gossip.round(&a, &peers).await;
    Obs {
        n,
        write_replayed,
        tip_replayed,
        patch_replayed,
        extends_replayed,
        extends_hashes: extends_hashes(&c),
        member_replayed,
        member_hashes: member_hashes(&i),
        login_replayed,
        session_replayed,
        idle_requests,
        idle_replayed,
        idle_gossip_replayed,
        pull_gossip_replayed: gossiped() - g0,
        pull_replayed: replayed() - r0,
    }
}

/// Index rows an anonymous `GET` of `path` (with `{id}` for the principal)
/// reads on a principal whose retained rival sits at position 1, the shape
/// theft recovery leaves for good.
async fn rival_get_rows(n: usize, path: &str) -> u64 {
    let (a, _da) = attestor().await;
    let app = build_router(a.clone());
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let mut bundles = vec![chain.first()];
    while chain.commits < n {
        bundles.push(chain.next().await);
    }
    for bundle in &bundles {
        let (st, ..) = call(&app, "POST", "/push", push_body(&id, bundle)).await;
        assert_eq!(st, StatusCode::CREATED);
    }
    let mut rival = Chain::new("golden", "key_a", "key_b").await;
    rival.diverge("diana_es384");
    let at_one = rival.next().await;
    let (st, ..) = call(&app, "POST", "/push", push_body(&id, &at_one)).await;
    assert_ne!(st, StatusCode::CREATED, "a rival is retained, not served");

    let before = a.engine.chain_rows_read();
    let (st, ..) = call(&app, "GET", &path.replace("{id}", &id), String::new()).await;
    assert!(st.is_success() || st == StatusCode::LOCKED, "{st}");
    a.engine.chain_rows_read() - before
}

/// Requests an idle gossip round makes of `peers` peers that all hold the
/// same principal of `n` commits as the server does, and what it replays.
async fn idle_gossip(peers: usize, n: usize) -> (u64, u64, u64) {
    let (a, _da) = attestor().await;
    let app_a = build_router(a.clone());
    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let mut bundles = vec![chain.first()];
    while chain.commits < n {
        bundles.push(chain.next().await);
    }
    let mut wires = Vec::new();
    let mut connectors = Vec::new();
    let mut held = Vec::new();
    for _ in 0..peers {
        let (b, _db) = keyless();
        let app_b = build_router(b);
        for bundle in &bundles {
            let (st, ..) = call(&app_b, "POST", "/push", push_body(&id, bundle)).await;
            assert_eq!(st, StatusCode::CREATED);
        }
        let (url, wire) = serve_counting(app_b).await;
        connectors.push((
            url.clone(),
            HttpConnector::with_client(a.http_client.clone(), &url, true).expect("connector"),
        ));
        wires.push(wire);
        held.push(_db);
    }
    for bundle in &bundles {
        let (st, ..) = call(&app_a, "POST", "/push", push_body(&id, bundle)).await;
        assert_eq!(st, StatusCode::CREATED);
    }
    let mut gossip = Gossip::default();
    gossip.round(&a, &connectors).await;
    let asked = || wires.iter().map(|w| w.requests.load(Relaxed)).sum::<u64>();
    let gossiped = || series(&a, "cyphr_gossip_commits_replayed_total");
    let (q0, r0, g0) = (asked(), a.engine.commits_replayed(), gossiped());
    gossip.round(&a, &connectors).await;
    (
        asked() - q0,
        a.engine.commits_replayed() - r0,
        gossiped() - g0,
    )
}

/// Bound: an idle gossip round (every peer already agrees) makes requests
/// linear in the peer count and replays 0 commits, at any peer count.
///
/// Slope checked: requests(P) = P x requests(2) / 2 exactly, over
/// P = 2, 4, 8 (a x4 span). A round that asks each peer about every other
/// peer (O(P^2)) would make 4x, 16x and 64x requests(1) at 2, 4 and 8:
/// the per-peer count it shows at 8 is 4x the one at 2, far outside the
/// exact-equality bound; a round with a per-round constant overhead shows
/// a per-peer count that falls with P and is red against it as well.
#[tokio::test]
async fn idle_gossip_requests_are_linear_in_peers() {
    let mut per_peer = Vec::new();
    for peers in [2usize, 4, 8] {
        let (requests, replayed, gossip_replayed) = idle_gossip(peers, 16).await;
        assert_eq!(
            (replayed, gossip_replayed),
            (0, 0),
            "{peers} peers: an idle round replayed"
        );
        assert_eq!(
            requests % peers as u64,
            0,
            "{peers} peers: {requests} requests is not a whole number per peer"
        );
        per_peer.push((peers, requests / peers as u64));
    }
    assert!(
        per_peer.iter().all(|&(_, r)| r == per_peer[0].1),
        "requests per peer at 2, 4 and 8 peers: {per_peer:?}"
    );
    assert!(per_peer[0].1 > 0, "an idle round asks each peer something");
}

/// A server on a data directory, and the router over it.
struct Rig {
    state: Arc<AppState>,
    app: axum::Router,
    config: ServerConfig,
    kept: Option<usize>,
}

impl Rig {
    /// A server on the data directory of `config`, keyed and bootstrapped
    /// as [`attestor`] is, with `kept` principals' states kept at most
    /// (the engine's default when `None`).
    async fn boot(config: ServerConfig, kept: Option<usize>) -> Self {
        let mut state = AppState::new(config.clone()).expect("state");
        if let Some(capacity) = kept {
            state.engine = state.engine.with_kept_states(capacity);
        }
        state.engine.set_kept_shadow(false);
        let identity = state.identity.clone().expect("identity");
        let key = config.signing_key_path.as_ref().expect("key");
        let sp = ServerPrincipal::bootstrap(&state.engine, identity, key, &config.data_dir)
            .await
            .expect("bootstrap");
        state.principal = Some(Arc::new(sp));
        let state = Arc::new(state);
        Self {
            app: build_router(state.clone()),
            state,
            config,
            kept,
        }
    }

    /// The same data directory under a new process: nothing kept.
    async fn restart(self) -> Self {
        let (config, kept) = (self.config.clone(), self.kept);
        // The stores open once: the old server must be gone first.
        drop(self);
        Self::boot(config, kept).await
    }

    async fn push(&self, id: &str, bundle: &cyphr::replay::WireBundle) {
        let (st, ..) = call(&self.app, "POST", "/push", push_body(id, bundle)).await;
        assert_eq!(st, StatusCode::CREATED);
    }

    fn replayed(&self) -> u64 {
        self.state.engine.commits_replayed()
    }
}

/// Commits replayed by each of a pair of identical requests, on a principal
/// that held `n` commits when the first of them was made.
#[derive(Debug)]
struct Cold {
    n: u64,
    first: u64,
    second: u64,
}

/// How a principal stops being kept.
#[derive(Clone, Copy, Debug)]
enum Cooling {
    /// The server restarts.
    Restart,
    /// Another principal's write pushes it out of a capacity-one kept set.
    Eviction,
}

/// What the first and the second write, and the first and the second
/// login, to a principal of `n` commits replay once it is cold.
async fn cold(n: usize, cooling: Cooling) -> (Cold, Cold) {
    let (first, _dir) = attestor().await;
    let config = first.config.clone();
    drop(first);
    let kept = matches!(cooling, Cooling::Eviction).then_some(1);
    let mut rig = Rig::boot(config, kept).await;

    let mut chain = Chain::new("golden", "key_a", "key_b").await;
    let id = chain.id.clone();
    let mut other = Chain::new("alice", "key_a", "key_b").await;
    let other_id = other.id.clone();
    rig.push(&id, &chain.first()).await;
    while chain.commits < n {
        rig.push(&id, &chain.next().await).await;
    }
    rig.push(&other_id, &other.first()).await;

    let cool = async |rig: Rig, other: &mut Chain| match cooling {
        Cooling::Restart => rig.restart().await,
        Cooling::Eviction => {
            rig.push(&other_id, &other.next().await).await;
            rig
        },
    };

    rig = cool(rig, &mut other).await;
    let held = chain.commits as u64;
    let mut writes = [0, 0];
    for w in &mut writes {
        let before = rig.replayed();
        rig.push(&id, &chain.next().await).await;
        *w = rig.replayed() - before;
    }
    let write = Cold {
        n: held,
        first: writes[0],
        second: writes[1],
    };

    rig = cool(rig, &mut other).await;
    let mut logins = [0, 0];
    for l in &mut logins {
        let before = rig.replayed();
        let (st, _, body) = call(&rig.app, "POST", "/auth/login", login_body(&id)).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        *l = rig.replayed() - before;
    }
    let login = Cold {
        n: chain.commits as u64,
        first: logins[0],
        second: logins[1],
    };
    (write, login)
}

/// `f(n)` for each n of `sizes`, each on a thread and a current-thread
/// runtime of its own: the chains are the cost of these tests, and the
/// sizes are independent. The runtime per thread also keeps a per-thread
/// count (the record's clock) exact.
fn per_size<T, F, Fut>(sizes: &[usize], f: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> Fut + Send + Copy + 'static,
    Fut: std::future::Future<Output = T>,
{
    let threads: Vec<_> = sizes
        .iter()
        .map(|&n| {
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime")
                    .block_on(f(n))
            })
        })
        .collect();
    threads
        .into_iter()
        .map(|t| t.join().expect("a size's thread"))
        .collect()
}

/// The bounds below, run on principals of each of the sizes `$sizes` and
/// generated twice: `fast`, in the normal test run, and `large`,
/// `#[ignore]`d for its build time.
macro_rules! suite {
    ($m:ident, $sizes:expr $(, #[$attr:meta])?) => {
        mod $m {
            use super::*;

            const SIZES: [usize; 3] = $sizes;

            static OBS: OnceCell<Vec<Obs>> = OnceCell::const_new();

            async fn obs() -> &'static [Obs] {
                OBS.get_or_init(|| async { per_size(&SIZES, observe) })
                    .await
            }

            /// Bound: a write, a tip read, a patch from the tip and a
            /// proof of either kind each replay 0 commits, at any n.
            #[tokio::test]
            $(#[$attr])?
            async fn writes_and_reads_replay_nothing() {
                for o in obs().await {
                    let r = [
                        o.write_replayed,
                        o.tip_replayed,
                        o.patch_replayed,
                        o.extends_replayed,
                        o.member_replayed,
                    ];
                    assert_eq!(r, [0; 5], "{o:?}");
                }
            }

            /// Bound: a `/proof` of `extends` or of `member` carries at most
            /// 2 ceil(log2 n) + 2 hashes (a path of at most log2 n steps,
            /// plus at most log2 n + 1 peaks): at n = 16 and at n = 256
            /// the caps are 10 and 18, where a linear certificate carries
            /// n / 2 and more.
            #[tokio::test]
            $(#[$attr])?
            async fn proofs_carry_logarithmically_many_hashes() {
                for o in obs().await {
                    let cap = 2 * (o.n as f64).log2().ceil() as usize + 2;
                    assert!(o.extends_hashes <= cap, "{o:?}");
                    assert!(o.member_hashes <= cap, "{o:?}");
                }
            }

            /// Bound: a login replays 0 commits, at any n.
            #[tokio::test]
            $(#[$attr])?
            async fn login_replays_nothing() {
                for o in obs().await {
                    assert_eq!(o.login_replayed, 0, "{o:?}");
                }
            }

            /// Bound: presenting a bearer token (POST /auth/session)
            /// replays 0 commits, at any n.
            #[tokio::test]
            $(#[$attr])?
            async fn token_check_replays_nothing() {
                for o in obs().await {
                    assert_eq!(o.session_replayed, 0, "{o:?}");
                }
            }

            /// Bound: an idle gossip round makes the same number of requests
            /// whatever n is (O(peers x principals)) and replays 0 commits.
            #[tokio::test]
            $(#[$attr])?
            async fn idle_gossip_round_is_constant() {
                let o = obs().await;
                for later in &o[1..] {
                    assert_eq!(o[0].idle_requests, later.idle_requests, "{o:?}");
                }
                for o in o {
                    assert_eq!((o.idle_replayed, o.idle_gossip_replayed), (0, 0), "{o:?}");
                }
            }

            /// Bound: pulling k new commits replays O(k) commits (at most
            /// k, none beyond them) in the gossip record and 0 in the
            /// engine's cold path.
            #[tokio::test]
            $(#[$attr])?
            async fn gossip_pull_replays_only_the_new_commits() {
                for o in obs().await {
                    assert!(o.pull_gossip_replayed <= K as u64, "{o:?}");
                    assert_eq!(o.pull_replayed, 0, "{o:?}");
                }
            }

            /// The fork heights each size is run at: the middle of the
            /// history (h = n / 2, so h grows with n) and a low one (h = 8
            /// wherever that is below n / 2, so a cost in n is not hidden
            /// in h).
            const LOW: usize = 8;

            static FORKS: OnceCell<Vec<(bool, ForkLocation)>> = OnceCell::const_new();

            /// A resumed holder (state kept, commits in a counted store, as
            /// the engine keeps them) of each size pulls from a peer on a
            /// fork at the middle, the peer's commit there a key change or
            /// a data commit (whose action the peer serves apart from it,
            /// so that the holder's fallback for a commit that names data
            /// actions is the path taken if its first verification refuses
            /// it), and on a fork at the low height with a key change.
            /// Built once for every test of the suite, a thread per size.
            /// The count is per thread, so each size's holder runs wholly
            /// on one.
            async fn forks() -> &'static [(bool, ForkLocation)] {
                FORKS
                    .get_or_init(|| async {
                        per_size(&SIZES, |n| async move {
                            // A key change at the middle and at a low
                            // height, and a data commit at the middle: the
                            // chains are the cost, so not every pair.
                            let mut configs = vec![(n / 2, false), (n / 2, true)];
                            if LOW < n / 2 {
                                configs.push((LOW, false));
                            }
                            let forks = fork_locations(n, &configs, true).await;
                            let mut all = Vec::new();
                            for (&(at, data), f) in configs.iter().zip(forks) {
                                assert!(f.forked, "n={n}: the fork at {at} was not found");
                                all.push((data, f));
                            }
                            all
                        })
                        .into_iter()
                        .flatten()
                        .collect()
                    })
                    .await
            }

            /// Bound: a holder pulling from a peer on a fork finds where the
            /// logs part with at most ceil(log2 n) + 3 /proof requests (the
            /// pull's own, then a search over the logs' overlap) and
            /// exactly one commit fetched, at any n (the peer's chain is
            /// not transferred).
            #[tokio::test]
            $(#[$attr])?
            async fn fork_location_is_logarithmic() {
                for (_, f) in forks().await {
                    let cap = (f.n as f64).log2().ceil() as usize + 3;
                    assert!(f.proof >= 1, "n={}: no proof was asked for", f.n);
                    assert!(
                        f.proof <= cap,
                        "n={}: {} proof asks, cap {cap}",
                        f.n,
                        f.proof
                    );
                    assert_eq!(
                        f.fetched, 1,
                        "n={}: commits fetched ({} /patch asks)",
                        f.n, f.patch
                    );
                }
            }

            /// Bound (issue #216, the MVP bound): the holder's own work to
            /// locate and prove a fork at height h is one replay of the
            /// h commits below it, not one of the whole chain and not two:
            /// timestamp checks <= c h + k, with c a replay's own cost per
            /// commit (measured in the same run, from building the record
            /// out of its n commits) and k = 4 c for the commits at the
            /// fork itself (measured: 3 c).
            ///
            /// Slope checked: at h = n / 2, a replay of the whole chain
            /// costs 2x the allowed c h, and a second replay of the prefix
            /// 2x it; at h = 8 and n = 128 a replay of the whole chain is
            /// 16x. Either is red; one replay of h is the allowance. The
            /// later target, O(fork depth + log n), needs a state
            /// per position that the record does not keep.
            ///
            /// Measured: a pull at h = 8, 16, 32 and 128 costs
            /// exactly 2 h + 6 checks, which is one replay at c = 2 (a
            /// commit holds two signed messages) plus 3 c, for a key
            /// change and for a data commit alike. The data commit does not
            /// reach the `CommitRefused` fallback (which would replay the
            /// prefix a second time): the core never matches a `ds/create`
            /// `id` against the actions it holds (`apply.rs`), so the
            /// commit verifies without them. The shape is kept so that the
            /// duplicate turns this red if a commit is ever refused for
            /// want of its actions.
            #[tokio::test]
            $(#[$attr])?
            async fn fork_location_client_replays_the_prefix_once() {
                for (data, f) in forks().await {
                    assert!(f.build_checks > 0, "the clock counter saw no replay");
                    let c = f.build_checks / f.n as u64;
                    let cap = c * f.height as u64 + 4 * c;
                    assert!(
                        f.client_checks <= cap,
                        "n={} fork at {} (data commit: {data}): {} timestamp checks, cap {cap} (c = {c})",
                        f.n,
                        f.height,
                        f.client_checks
                    );
                    // The counter is per thread: work that moved to another
                    // thread would read 0 and pass the cap.
                    assert!(
                        f.client_checks >= c * f.height as u64,
                        "n={} fork at {}: {} timestamp checks, fewer than the prefix's {}: \
                         the counter is not seeing the replay",
                        f.n,
                        f.height,
                        f.client_checks,
                        c * f.height as u64
                    );
                }
            }

            /// Bound (issue #216): the holder reads from its chain store
            /// the h commits below the fork and no more: reads <= h + 2.
            ///
            /// Slope checked: reading the whole stored chain, n commits, to
            /// replay h of them is 2x the allowance at h = n / 2 and 16x at
            /// h = 8, n = 128. The lower bound, reads >= h, is the
            /// positive control: a replay of h commits reads them.
            #[tokio::test]
            $(#[$attr])?
            async fn fork_location_client_reads_only_the_prefix() {
                for (data, f) in forks().await {
                    assert!(
                        f.chain_reads <= f.height + 2,
                        "n={} fork at {} (data commit: {data}): {} commits read from the chain store, cap {}",
                        f.n,
                        f.height,
                        f.chain_reads,
                        f.height + 2
                    );
                    assert!(
                        f.chain_reads >= f.height,
                        "n={} fork at {}: {} commits read from the chain store, fewer \
                         than the {} it replays",
                        f.n,
                        f.height,
                        f.chain_reads,
                        f.height
                    );
                }
            }

            static RIVAL_ROWS: OnceCell<Vec<(u64, u64)>> = OnceCell::const_new();

            /// Index rows `GET /tip` and `GET /proof` (an `extends` claim
            /// from the middle) read, per size, on a principal holding a
            /// retained rival at position 1.
            async fn rival_rows() -> &'static [(u64, u64)] {
                RIVAL_ROWS
                    .get_or_init(|| async {
                        per_size(&SIZES, |n| async move {
                            let proof = format!("/proof?pr={{id}}&size={n}&claim=extends:{}", n / 2);
                            (
                                rival_get_rows(n, "/tip?pr={id}").await,
                                rival_get_rows(n, &proof).await,
                            )
                        })
                    })
                    .await
            }

            /// Bound: an unauthenticated `GET /tip` of a principal holding a
            /// retained rival at position 1 reads the same index rows at
            /// any n.
            #[tokio::test]
            $(#[$attr])?
            async fn tip_read_rows_are_constant_with_a_rival_at_one() {
                let rows = rival_rows().await;
                assert!(rows[0].0 > 0, "GET /tip read no index row: not counting");
                for (later, n) in rows.iter().zip(SIZES).skip(1) {
                    assert_eq!(
                        rows[0].0, later.0,
                        "index rows read by GET /tip at n={} and n={n}",
                        SIZES[0]
                    );
                }
            }

            /// Bound: the same for `GET /proof` of an `extends` claim from
            /// the middle of the history, the other route that reads the
            /// fork state before it serves a proof.
            #[tokio::test]
            $(#[$attr])?
            async fn proof_read_rows_are_constant_with_a_rival_at_one() {
                let rows = rival_rows().await;
                assert!(rows[0].1 > 0, "GET /proof read no index row: not counting");
                for (later, n) in rows.iter().zip(SIZES).skip(1) {
                    assert_eq!(
                        rows[0].1, later.1,
                        "index rows read by GET /proof at n={} and n={n}",
                        SIZES[0]
                    );
                }
            }

            static RESTARTED: OnceCell<Vec<(Cold, Cold)>> = OnceCell::const_new();
            static EVICTED: OnceCell<Vec<(Cold, Cold)>> = OnceCell::const_new();

            /// The first two writes and logins after a restart, per size.
            async fn restarted() -> &'static [(Cold, Cold)] {
                RESTARTED
                    .get_or_init(|| async {
                        per_size(&SIZES, |n| cold(n, Cooling::Restart))
                    })
                    .await
            }

            /// The same after an eviction.
            async fn evicted() -> &'static [(Cold, Cold)] {
                EVICTED
                    .get_or_init(|| async {
                        per_size(&SIZES, |n| cold(n, Cooling::Eviction))
                    })
                    .await
            }

            /// Bound: after a restart the first write, and the first login,
            /// replay the principal's history once (at least n, at most n
            /// plus the commits being written); the second of each
            /// replays 0.
            ///
            /// Slope checked: the first costs at most n + 2 at every size
            /// and the second exactly 0; replaying on every request would
            /// show the second at n, and the first at more than n. The
            /// first is also at least n: the positive control that the
            /// replay counter sees a cold start at all.
            #[tokio::test(flavor = "multi_thread")]
            $(#[$attr])?
            async fn restart_replays_once_then_nothing() {
                for (write, login) in restarted().await {
                    for (what, c) in [("write", write), ("login", login)] {
                        assert!(c.first >= c.n, "{what} after restart: {c:?}");
                        assert!(c.first <= c.n + 2, "{what} after restart: {c:?}");
                        assert_eq!(c.second, 0, "{what} after restart: {c:?}");
                    }
                }
            }

            /// Bound: the same for a principal pushed out of the kept set
            /// by another's write: its next write, or login, replays its
            /// history once and the one after replays 0.
            #[tokio::test(flavor = "multi_thread")]
            $(#[$attr])?
            async fn eviction_replays_once_then_nothing() {
                for (write, login) in evicted().await {
                    for (what, c) in [("write", write), ("login", login)] {
                        assert!(c.first >= c.n, "{what} after eviction: {c:?}");
                        assert!(c.first <= c.n + 2, "{what} after eviction: {c:?}");
                        assert_eq!(c.second, 0, "{what} after eviction: {c:?}");
                    }
                }
            }
        }
    };
}

// Span 16x: n grows x16 and log n x2.3, so a count that is O(n) or O(log n)
// is red against an exact-equality bound.
suite!(fast, [8, 32, 128]);
// Span 64x: the same bounds where the gap between log n (x2.5) and n (x64)
// is not arguable. About a minute of build, ignored for it.
suite!(
    large,
    [16, 256, 1024],
    #[ignore = "large: 1024-commit principals take about a minute to build"]
);
