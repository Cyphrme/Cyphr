//! The idle predicate is exact: whenever a peer's listed heads are all
//! commits the holder has (`PeerHeads::idle`), a full pull from that peer
//! adds nothing, so a holder that skips the pull on idle loses nothing.
//!
//! The predicate reads heads only. A peer that is ahead or holds a rival
//! branch lists a head the holder lacks and must not be idle. Data actions
//! that move no head are outside it, as they are outside the pull's own
//! skip (GitHub #211).

mod common;

use std::sync::Mutex;

use common::*;
use cyphr::principal::Clock;
use cyphr_net::{
    Anchor, ChannelBinding, ConnectError, Connector, PeerStanding, PullPeer, Record, Request,
    peer_heads, pull,
};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000;

fn clock() -> i64 {
    T0 + 10_000
}
const CLOCK: Clock = clock;

/// One branch of a principal: each commit's blobs, and the commit id and
/// PR the chain reaches after it.
#[derive(Clone)]
struct Line {
    entries: Vec<Vec<String>>,
    prs: Vec<String>,
    ids: Vec<String>,
}

fn commit_id(p: &cyphr::Principal) -> String {
    p.commits()
        .last()
        .expect("a commit")
        .tr()
        .0
        .tagged_first()
        .expect("commit id")
        .to_string()
}

/// The genesis commit of `g`, then one `key/create` commit per `(key, now)`.
/// Ed25519 signs deterministically, so lines grown from one prefix share it
/// exactly and differ only where the caller makes them differ.
async fn line(g: &Kp, grow: &[(&Kp, i64)]) -> Line {
    let mut chain = Chain::new(g).await;
    let mut line = Line {
        entries: vec![chain.genesis_commit.clone()],
        prs: vec![chain.principal.pr_tagged().expect("pr")],
        ids: vec![commit_id(&chain.principal)],
    };
    for (key, now) in grow {
        let blobs = chain.commit(key, *now).await;
        line.entries.push(blobs);
        line.prs.push(chain.principal.pr_tagged().expect("pr"));
        line.ids.push(commit_id(&chain.principal));
    }
    line
}

/// A peer serving its canonical line, an optional retained rival head, and
/// no revokes; `absent` makes it answer 404 to everything (it does not
/// hold the principal).
struct Fake {
    line: Line,
    rival: Option<Line>,
    absent: bool,
    served: Mutex<Vec<String>>,
}

impl Fake {
    fn new(line: &Line) -> Self {
        Self {
            line: line.clone(),
            rival: None,
            absent: false,
            served: Mutex::default(),
        }
    }

    fn served(&self, path: &str) -> usize {
        let served = self.served.lock().expect("served");
        served.iter().filter(|p| p.as_str() == path).count()
    }
}

fn head(line: &Line, canonical: bool) -> Value {
    let n = line.ids.len();
    json!({
        "tip": line.ids[n - 1],
        "pre": n.checked_sub(2).map(|i| line.prs[i].clone()),
        "sequence": n - 1,
        "canonical": canonical,
    })
}

impl Connector for Fake {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let (path, query) = request
            .target
            .split_once('?')
            .unwrap_or((&request.target, ""));
        self.served.lock().expect("served").push(path.to_owned());
        if self.absent {
            return Err(ConnectError::NonSuccess(404));
        }
        let payload = match path {
            "/branches" => {
                let mut heads = vec![head(&self.line, true)];
                heads.extend(self.rival.iter().map(|r| head(r, false)));
                json!({ "branches": heads })
            },
            "/patch" => {
                let from = query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix("from="))
                    .map(|a| a.replace("%3A", ":"));
                let start = match from {
                    None => 0,
                    Some(anchor) => match self.line.prs.iter().position(|pr| *pr == anchor) {
                        Some(p) => p + 1,
                        None => return Err(ConnectError::NonSuccess(404)),
                    },
                };
                let entries: Vec<Value> = self.line.entries[start..]
                    .iter()
                    .enumerate()
                    .map(|(i, blobs)| entry_bundle(start + i, blobs))
                    .collect();
                json!({ "entries": entries })
            },
            "/evidence" => json!({ "items": [] }),
            "/revoked" => json!({ "revoked": [] }),
            other => return Err(ConnectError::Unreachable(format!("no route {other}"))),
        };
        Ok(serde_json::to_vec(
            &json!({ "v": 1, "payload": payload, "statement": { "kind": "unsigned" } }),
        )
        .expect("json"))
    }
}

/// A record of `held`, filled by one pull from a peer that serves it.
async fn record_of(pg: &cyphr::PrincipalGenesis, g: &Kp, held: &Line) -> Record {
    let mut rec = Record::new(pg, Anchor::GenesisKey(g.domain_key(T0))).with_clock(CLOCK);
    let source = Fake::new(held);
    pull(
        &mut rec,
        &[PullPeer {
            name: "source",
            connector: &source,
        }],
    )
    .await;
    rec
}

/// Claim: if a peer is idle for a holder (every head it lists is a commit
/// the holder has; a 404 lists none), then a full pull on a fresh record of
/// the holder's chain adds nothing, forks nothing and revokes nothing, and
/// fetches no chain. A peer that is ahead, or that holds a rival branch,
/// is not idle. The scenarios are every relation a peer can have to a
/// holder's chain.
///
/// Turns red if: the predicate calls a peer idle that a pull would extend
/// or fork against (for example `any` instead of `all` over the heads), or
/// an idle peer's pull still moves the record or fetches a patch.
/// End-to-end scenario: yes (real chains over a carrier that plays peers).
#[tokio::test]
async fn whenever_a_peer_is_idle_a_full_pull_adds_nothing() {
    let (g, k1, k2, k3, k4) = (kp(), kp(), kp(), kp(), kp());
    let pg = g.pg();
    let (c1, c2, c3) = ((&k1, T0 + 100), (&k2, T0 + 200), (&k3, T0 + 300));
    let held = line(&g, &[c1, c2]).await;
    let behind = line(&g, &[c1]).await;
    let ahead = line(&g, &[c1, c2, c3]).await;
    let rival = line(&g, &[c1, (&k4, T0 + 250)]).await;

    let mut forked = Fake::new(&held);
    forked.rival = Some(rival);
    let mut absent = Fake::new(&held);
    absent.absent = true;
    // (peer, idle expected)
    let peers = [
        ("equal", Fake::new(&held), true),
        ("behind", Fake::new(&behind), true),
        ("absent (404)", absent, true),
        ("ahead", Fake::new(&ahead), false),
        ("holds a rival branch", forked, false),
    ];

    for (name, fake, expect_idle) in &peers {
        let rec = record_of(&pg, &g, &held).await;
        let before = rec.tip().expect("tip");
        let mark = rec.log_len();

        let heads = peer_heads(fake, &pg).await.expect("heads answer");
        let idle = heads.as_ref().is_none_or(|h| {
            h.idle(|tip| (0..before.commits).any(|i| rec.commit_id_at(i).as_deref() == Some(tip)))
        });
        assert_eq!(idle, *expect_idle, "{name}: idle verdict");

        let mut fresh = record_of(&pg, &g, &held).await;
        let report = pull(
            &mut fresh,
            &[PullPeer {
                name,
                connector: fake,
            }],
        )
        .await;
        if idle {
            assert_eq!(fresh.tip().expect("tip"), before, "{name}: record moved");
            assert_eq!(fresh.log_len(), mark, "{name}: bundles gained");
            assert!(report.forks.is_empty(), "{name}: forked");
            assert!(report.revoked.is_empty(), "{name}: revoked");
            // A pull still reports a peer that lacks the principal as
            // failed; the predicate's promise is only that nothing changed.
            let ok = if fake.absent {
                matches!(report.peers[0].standing, PeerStanding::Failed(_))
            } else {
                matches!(
                    report.peers[0].standing,
                    PeerStanding::Current | PeerStanding::Behind { .. }
                )
            };
            assert!(ok, "{name}: {:?}", report.peers[0].standing);
            assert_eq!(fake.served("/patch"), 0, "{name}: a patch was fetched");
        }
    }
}
