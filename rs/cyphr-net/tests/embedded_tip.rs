//! Embedded-principal tips (SPEC be0663f §10.3, §10.7): the core asks a
//! `TipSource` for an embedded principal's tip, never a clock or a socket;
//! the gossip-backed source pulls it over the pull step from the peers the
//! verifier chose. Principal A embeds principal B (genesis `bob`, then
//! `carol`) by B's genesis PR in A's Key Tree, and `carol` signs for A.

mod common;

use common::*;
use cyphr::{EmbedStatus, Principal, Tip, TipSource, Tracking};
use cyphr_net::{
    Anchor, ChannelBinding, ConnectError, Connector, GossipTips, PullPeer, Record, Request,
};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000;

/// The verifier's clock: well after every `now` the fixtures sign, and far
/// from the system clock, so a time the core invented would show.
fn clock() -> i64 {
    T0 + 10_000
}

/// B's chain as a peer serves it.
struct Line {
    pg: String,
    entries: Vec<Vec<String>>,
    prs: Vec<String>,
    tip: String,
}

/// B: `bob`'s genesis, then a commit creating `carol` at `T0 + 10`.
async fn b_line(bob: &Kp, carol: &Kp) -> (Line, Principal) {
    let mut chain = Chain::new(bob).await;
    let mut entries = vec![chain.genesis_commit.clone()];
    let mut prs = vec![chain.principal.pr_tagged().expect("pr")];
    entries.push(chain.commit(carol, T0 + 10).await);
    prs.push(chain.principal.pr_tagged().expect("pr"));
    let tip = chain
        .principal
        .commits()
        .last()
        .expect("commit")
        .tr()
        .0
        .tagged_first()
        .expect("id")
        .to_string();
    let line = Line {
        pg: chain.pg(),
        entries,
        prs,
        tip,
    };
    (line, chain.principal)
}

/// A peer holding B's line, or (`line: None`) one that cannot be reached.
struct Peer {
    line: Option<Line>,
}

impl Connector for Peer {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, request: &Request) -> Result<Vec<u8>, ConnectError> {
        let line = self
            .line
            .as_ref()
            .ok_or_else(|| ConnectError::Unreachable("down".into()))?;
        let (path, query) = request
            .target
            .split_once('?')
            .unwrap_or((&request.target, ""));
        let from = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("from="))
            .map(|pr| pr.replace("%3A", ":"));
        let payload = match path {
            "/branches" => json!({ "branches": [{
                "tip": line.tip, "sequence": line.entries.len() - 1, "canonical": true,
            }]}),
            "/patch" => {
                let start = from.map_or(0, |pr| {
                    line.prs.iter().position(|p| *p == pr).map_or(0, |i| i + 1)
                });
                let entries: Vec<Value> = (start..line.entries.len())
                    .map(|i| entry_bundle(i, &line.entries[i]))
                    .collect();
                json!({ "entries": entries })
            },
            "/revoked" => json!({ "revoked": [] }),
            other => return Err(ConnectError::Unreachable(format!("no route {other}"))),
        };
        Ok(serde_json::to_vec(&json!({
            "v": 1, "payload": payload, "statement": { "kind": "unsigned" },
        }))
        .expect("json"))
    }
}

/// A after its genesis, with `members` in its KT (`cyphr/AT/KT/nonce/create`).
async fn a_embedding(alice: &Kp, members: &[&str]) -> Principal {
    let mut a = Principal::implicit(alice.domain_key(T0)).await.expect("A");
    a.commit_genesis(&alice.signer(), &[], T0, "cyphr.me")
        .await
        .expect("A genesis");
    for (i, m) in members.iter().enumerate() {
        let now = T0 + 1 + i64::try_from(i).expect("few");
        signed_commit(&mut a, alice, "AT/KT/nonce/create", m, None, now)
            .await
            .expect("A embeds");
    }
    a
}

/// One commit on `a`: `signer` signs `typ` naming `id`, and finalizes it.
async fn signed_commit(
    a: &mut Principal,
    signer: &Kp,
    typ: &str,
    id: &str,
    sidecar: Option<cyphr::Key>,
    now: i64,
) -> cyphr::error::Result<()> {
    let pay = serde_json::to_vec(&json!({
        "alg": signer.kp.alg.name(), "id": id, "now": now,
        "tmb": signer.tmb.to_b64(), "typ": format!("cyphr.me/cyphr/{typ}"),
    }))
    .expect("pay");
    let alg = signer.kp.alg.name();
    let (sig, cad) =
        coz::sign_json(&pay, alg, &signer.kp.prv_bytes, &signer.kp.pub_bytes).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, alg).expect("czd");
    let mut scope = a.begin_commit();
    scope.verify_and_apply(&pay, &sig, czd, sidecar)?;
    scope
        .finalize_with_software(&signer.signer(), now, "cyphr.me")
        .await
        .map(|_| ())
}

/// `carol` (a key of B) adds `new` to A.
async fn carol_adds(a: &mut Principal, carol: &Kp, new: &Kp, now: i64) -> cyphr::error::Result<()> {
    let id = new.tmb.to_b64();
    signed_commit(a, carol, "key/create", &id, Some(new.domain_key(now)), now).await
}

/// Claim (SPEC 10.3, 10.7): an embedded PR is followed by default, through
/// the gossip pull step, and the tip the core judges by carries the time
/// the verifier pulled it and B's newest `now`, never "current": the
/// report gives each answering peer's pull age, the age of B's newest
/// `now`, and which peers answered. With the followed tip, B's key signs
/// for A.
///
/// Turns red if: the core stamps the tip with a clock of its own (the
/// status would not carry the verifier's pull time); a down peer is
/// reported as answering; or the followed tip does not authorize B's key.
/// End-to-end scenario: yes (two peers, one down, real chains).
#[tokio::test]
async fn gossip_follow_reports_pull_ages_and_authorizes_b() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (line, _) = b_line(&bob, &carol).await;
    let member = line.prs[0].clone();
    let pg = line.pg.clone();
    let (up, down) = (Peer { line: Some(line) }, Peer { line: None });
    let peers = [
        PullPeer {
            name: "down",
            connector: &down,
        },
        PullPeer {
            name: "up",
            connector: &up,
        },
    ];
    let record = Record::new(&pg, Anchor::GenesisKey(bob.domain_key(T0))).with_clock(clock);
    let mut tips = GossipTips::new(&peers, clock).follow(&member, record);

    let mut a = a_embedding(&alice, &[&member]).await;
    a.reveal_embedded(&member, Tracking::Follow)
        .expect("reveal");
    let report = a.follow_embedded(&mut tips).await;
    assert_eq!(
        report[0].status,
        EmbedStatus::Followed {
            pulled_at: clock(),
            newest_now: T0 + 10,
        }
    );

    let follow = &tips.reports()[0];
    assert_eq!(follow.member, member);
    let answered: Vec<_> = follow
        .peers
        .iter()
        .map(|p| (p.peer.as_str(), p.answered))
        .collect();
    assert_eq!(answered, [("down", false), ("up", true)]);
    assert_eq!(follow.pull_ages(clock() + 60), [("up", 60)]);
    assert_eq!(follow.newest_age(clock()), Some(10_000 - 10));
    assert!(!follow.forked);

    carol_adds(&mut a, &carol, &dave, T0 + 20)
        .await
        .expect("carol signs for A through the followed tip");
    assert!(a.is_key_active(&dave.tmb));
}

/// A source that counts what it is asked and never answers.
#[derive(Default)]
struct Counting(Vec<String>);

impl TipSource for Counting {
    async fn tip(&mut self, member: &str) -> Option<Tip> {
        self.0.push(member.to_owned());
        None
    }
}

/// Claim (SPEC 10.3, 10.7, #200): a client may force-pin an embedded PR
/// to a state, and an opaque KT digest (never revealed) triggers no
/// retrieval: following asks the source for neither, reports both as
/// pinned (the opaque one as opaque), and the pinned state still
/// authorizes `carol` after B revoked it, because a pin is static.
///
/// Turns red if: a pinned or opaque digest is retrieved; either is
/// reported as followed; or a pin is updated from B's newer chain.
/// End-to-end scenario: yes (signed cozies through the commit API, with a
/// fake source driving the core).
#[tokio::test]
async fn pinned_and_opaque_digests_are_never_retrieved() {
    let (alice, bob, carol, dave) = (kp(), kp(), kp(), kp());
    let (line, mut b) = b_line(&bob, &carol).await;
    let member = line.prs[0].clone();
    let opaque = digest(0x5A);
    let mut a = a_embedding(&alice, &[&member, &opaque]).await;
    a.reveal_embedded(&member, Tracking::Pin(Box::new(Tip::new(&b, T0 + 15))))
        .expect("pin B");

    // B moves on: carol revokes itself.
    let mut chain = Chain {
        genesis: &bob,
        principal: b.fork().await.expect("fork"),
        genesis_commit: Vec::new(),
    };
    chain.revoke(&carol, T0 + 30).await;
    b = chain.principal;
    assert!(b.is_key_revoked(&carol.tmb));

    let mut source = Counting::default();
    let mut report = a.follow_embedded(&mut source).await;
    report.sort_by_key(|r| r.member != member);
    assert!(source.0.is_empty(), "nothing retrieved: {:?}", source.0);
    assert_eq!(report[0].status, EmbedStatus::Pinned { opaque: false });
    assert_eq!(report[1].member, opaque);
    assert_eq!(report[1].status, EmbedStatus::Pinned { opaque: true });

    carol_adds(&mut a, &carol, &dave, T0 + 40)
        .await
        .expect("the pinned state still holds carol");
}
