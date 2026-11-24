// Fork over an agreed history, S04's theft at depth: in both tests the
// agreed history is k = 3 commits beyond genesis (two commits, then the
// laptop's pairing) before the fork.
//
// Equal branches: every server converges on Error plus evidence, as at
// depth 0.
// One branch extended: a commit naming a fork child as its `pre` is what
// selects it (SPEC 15.8 item 1), so every server converges on Active at
// the extended tip with the other kept as evidence. A thief's stale copy
// of a device (made before the owner's later commits) forks that far
// down, and the owner's two commits against the thief's one select the
// owner's branch because only it is extended, not because it is taller.
// Both extended: the fork stays an error whatever the heights (the spec
// author on #203: "They're both out of compliance"), and no further
// commit on either side leaves it.
//
// Required capabilities: transport,cli-network,branch-store,evidence,peer-gossip,audit,data-commit.

use std::time::Duration;

use cyphr_scenarios::actions::*;
use cyphr_scenarios::oracle::Expect;
use cyphr_scenarios::{Capability, Harness};

const CONVERGE: Duration = Duration::from_secs(20);
const CAPS: &[Capability] = &[
    Capability::Transport,
    Capability::CliNetwork,
    Capability::BranchStore,
    Capability::Evidence,
    Capability::PeerGossip,
    Capability::Audit,
    Capability::DataCommit,
];

#[tokio::test(flavor = "multi_thread")]
async fn deep_fork_converges_on_error() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    // The agreed history is grown before the laptop is paired: the laptop
    // takes its copy at pairing, so what it lacks it cannot fork over.
    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.commit_data(&pr, "agreed one").await);
    h.ok(alice.add_backup_key(&pr).await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    h.ok(thief.steal_key(&laptop, &laptop_key).await);

    h.ok(alice.commit_data(&pr, "alice").await);
    h.ok(thief.commit_data(&pr, "thief").await);
    let at = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h
        .ok(thief.push(&pr, &["p3"]).await)
        .accepted("thief branch");
    assert_ne!(at, tt, "the thief must have forked");

    h.eventually(
        "every verdict to converge on Error plus evidence",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &all).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    let forked = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&forked, &pr, &Expect::new(&all, &pr.0))
        .await;
    assert!(forked.branches.contains(&at) && forked.branches.contains(&tt));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_only_extended_branch_selects_the_fork() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (thief, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(alice.create_principal().await);
    h.ok(alice.commit_data(&pr, "agreed one").await);
    h.ok(alice.add_backup_key(&pr).await);
    let laptop_key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("base push");
    // Alice goes on after the pairing, so the stolen laptop is a stale
    // copy and the fork lies below her tip.
    h.ok(alice.commit_data(&pr, "alice one").await);
    h.ok(alice.add_backup_key(&pr).await);
    h.ok(thief.steal_key(&laptop, &laptop_key).await);
    h.ok(thief.commit_data(&pr, "thief").await);
    let at = h
        .ok(alice.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h
        .ok(thief.push(&pr, &["p3"]).await)
        .accepted("thief branch");
    assert_ne!(at, tt, "the thief must have forked");

    h.eventually(
        "every server to settle on the extended branch",
        CONVERGE,
        || async {
            for peer in all {
                if h.peer_view(peer, &pr).await.map(|v| v.tip) != Some(at.clone()) {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
    .await;
    let v = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&v, &pr, &Expect::new(&all, &pr.0)).await;
    assert_eq!(
        v.standing,
        Standing::Active,
        "only the extended branch is selected"
    );
    assert_eq!(v.tip, at);
    assert!(v.evidence.contains(&Evidence::PrincipalFork(pr.clone())));
    assert!(v.abandoned.contains(&tt), "the unextended branch is kept");
}

/// Alice makes `alice` commits and the thief `thief` commits over the
/// fork, both past the agreed history; every server must read Error.
async fn both_extended(alice: usize, thief: usize) {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let (a, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (t, bob) = (h.client("thief"), h.client("bob"));
    let all = ["p1", "p2", "p3"];

    let pr = h.ok(a.create_principal().await);
    h.ok(a.commit_data(&pr, "agreed one").await);
    h.ok(a.add_backup_key(&pr).await);
    let laptop_key = h.ok(a.pair_device(&pr, &laptop).await);
    h.ok(a.push(&pr, &["p1", "p2"]).await).accepted("base push");
    // p3 is cut off for both pushes: each side's branch must reach its own
    // peers before gossip carries the other, whatever the heights, or a
    // peer already in Error answers the second push 423.
    h.proxy.partition("p1", "p3");
    h.proxy.partition("p2", "p3");
    h.ok(t.steal_key(&laptop, &laptop_key).await);
    let mut alice_line = Vec::new();
    for n in 0..alice {
        alice_line.push(h.ok(a.commit_data(&pr, &format!("alice {n}")).await).0);
    }
    let mut thief_line = Vec::new();
    for n in 0..thief {
        thief_line.push(h.ok(t.commit_data(&pr, &format!("thief {n}")).await).0);
    }
    let at = h
        .ok(a.push(&pr, &["p1", "p2"]).await)
        .accepted("alice branch");
    let tt = h.ok(t.push(&pr, &["p3"]).await).accepted("thief branch");
    h.proxy.heal("p1", "p3");
    h.proxy.heal("p2", "p3");

    // Catches tallest-wins: the taller branch must not make any server
    // Active, and no server may hold a single tip.
    h.eventually(
        "every verdict to converge on Error plus evidence",
        CONVERGE,
        || async {
            let v = bob.verdict(&pr, &all).await?;
            Ok(v.standing == Standing::Error
                && v.evidence.contains(&Evidence::PrincipalFork(pr.clone())))
        },
    )
    .await;
    // Catches split witnesses: every server itself reports state Error
    // (read from its raw `/tip`, not inferred from a head count) at the
    // same fork point, with one head per contest child, each on that
    // child's branch. Heads are holder-relative: where a server's own
    // chain is the branch its head is the true tip, otherwise the tip or
    // an ancestor within the retained depth. With no line past depth 2
    // every server holds both true tips.
    let exact = alice <= 2 && thief <= 2;
    h.eventually(
        "every server to report Error at one fork point",
        CONVERGE,
        || async {
            let mut points = Vec::new();
            for peer in all {
                let resp = h
                    .http
                    .get(format!("http://{}/tip", h.peer(peer).addr()))
                    .query(&[("pr", pr.0.as_str())])
                    .send()
                    .await;
                let Ok(resp) = resp else { return Ok(false) };
                let Ok(tip) = resp.json::<serde_json::Value>().await else {
                    return Ok(false);
                };
                let heads: Vec<String> = tip["payload"]["heads"]
                    .as_array()
                    .map(|hs| {
                        hs.iter()
                            .filter_map(|x| x["commit_id"].as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let on = |line: &[String]| heads.iter().filter(|x| line.contains(x)).count();
                // The branch this server's own chain is carries its true tip.
                let own = if peer == "p3" {
                    (&thief_line, &tt.0)
                } else {
                    (&alice_line, &at.0)
                };
                let ok = tip["payload"]["state"] == "error"
                    && heads.len() == 2
                    && on(&alice_line) == 1
                    && on(&thief_line) == 1
                    && heads.contains(own.1)
                    && (!exact || (heads.contains(&at.0) && heads.contains(&tt.0)));
                if !ok {
                    return Ok(false);
                }
                points.push(tip["payload"]["fork_point"].clone());
            }
            Ok(points.iter().all(|p| !p.is_null() && p == &points[0]))
        },
    )
    .await;
    let v = h.ok(bob.verdict(&pr, &all).await);
    h.check_verdict(&v, &pr, &Expect::new(&all, &pr.0)).await;
    assert_eq!(v.standing, Standing::Error, "{alice} vs {thief} commits");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taller_owner_branch_does_not_settle_a_both_extended_fork() {
    both_extended(3, 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taller_thief_branch_does_not_settle_a_both_extended_fork() {
    both_extended(2, 3).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_against_two_holds_both_true_tips_at_every_server() {
    both_extended(2, 2).await;
}

/// A peer's raw `/tip` answer for `pr`, or `None` while it cannot be read.
async fn raw_tip(h: &Harness, peer: &str, pr: &Principal) -> Option<serde_json::Value> {
    let resp = h
        .http
        .get(format!("http://{}/tip", h.peer(peer).addr()))
        .query(&[("pr", pr.0.as_str())])
        .send()
        .await
        .ok()?;
    resp.json::<serde_json::Value>().await.ok()
}

/// A signing key outside any pool.
struct K {
    alg: String,
    prv: Vec<u8>,
    pubb: Vec<u8>,
    tmb: coz::Thumbprint,
}

fn fresh_k() -> K {
    let g = coz::Alg::Ed25519.generate_keypair();
    let tmb = g.alg.compute_thumbprint(&g.pub_bytes).expect("tmb");
    K {
        alg: g.alg.name().to_owned(),
        prv: g.prv_bytes.clone(),
        pubb: g.pub_bytes.clone(),
        tmb,
    }
}

const T: i64 = 1_700_000_000;

fn key_of(k: &K) -> cyphr::Key {
    cyphr::Key::new(k.alg.clone(), k.tmb.clone(), k.pubb.clone())
        .expect("key binds its tmb")
        .with_first_seen(T)
}

fn signer_of(k: &K) -> cyphr::signer::SoftwareSigner {
    cyphr::signer::SoftwareSigner::new(&k.alg, &k.prv, &k.pubb, &k.tmb)
}

/// `by` creates `new` over `p` at `now`; the commit's wire bundle.
async fn create(p: &mut cyphr::Principal, by: &K, new: &K, now: i64) -> cyphr::replay::WireBundle {
    let pay = serde_json::to_vec(&serde_json::json!({
        "alg": by.alg, "id": new.tmb.to_b64(), "now": now,
        "tmb": by.tmb.to_b64(), "typ": "cyphr.me/cyphr/key/create",
    }))
    .expect("pay");
    let (sig, cad) = coz::sign_json(&pay, &by.alg, &by.prv, &by.pubb).expect("sign");
    let czd = coz::czd_for_alg(&cad, &sig, &by.alg).expect("czd");
    let mut scope = p.begin_commit();
    scope
        .verify_and_apply(&pay, &sig, czd, Some(key_of(new)))
        .expect("apply");
    scope
        .finalize_with_software(&signer_of(by), now, "cyphr.me")
        .await
        .expect("finalize");
    cyphr::replay::WireBundle::of_commit(p.commits().last().expect("commit")).expect("bundle")
}

/// POST `bundle` to peer `name` directly (the proxy carries only gossip),
/// and the status the peer answered.
async fn post(h: &Harness, name: &str, id: &str, bundle: &cyphr::replay::WireBundle) -> u16 {
    let mut body = serde_json::to_value(bundle).expect("bundle json");
    body["principal_id"] = id.into();
    h.http
        .post(format!("http://{}/push", h.peer(name).addr()))
        .json(&body)
        .send()
        .await
        .expect("push request")
        .status()
        .as_u16()
}

/// The thief and the owner sign with one key, and the thief fills that
/// key's retention quota at every server: two junk rivals X and Y beside
/// the canonical line at p1 and p2 (the owner's O_3, O_4 canonical) and the
/// same two at p3 (the thief's J_3, J_4 canonical, the tip taken). Gossip
/// then offers each side's line to the other, where the quota is full: a
/// root alone is refused by the cap, so only a root offered with its
/// extension can land. Built from signed commits pushed straight to each
/// server, since the CLI never sends a fork over a tip the peer holds.
///
/// Catches a cap that splits standing: every server must end in state
/// Error at one fork point, not Active on whichever line it saw first.
#[tokio::test(flavor = "multi_thread")]
async fn a_thief_prefilling_the_shared_keys_quota_cannot_keep_a_server_active() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let all = ["p1", "p2", "p3"];

    // One key K: the genesis key, which every line below is signed by.
    let k = fresh_k();
    let mut cur = cyphr::Principal::implicit(key_of(&k))
        .await
        .expect("genesis");
    cur.commit_genesis(&signer_of(&k), &[], T, "cyphr.me")
        .await
        .expect("genesis commit");
    let mut chain = vec![cur.fork().await.expect("fork")];
    let mut bundles = vec![
        cyphr::replay::WireBundle::of_commit(cur.commits().last().expect("commit"))
            .expect("bundle"),
    ];
    for i in 1..3 {
        bundles.push(create(&mut cur, &k, &fresh_k(), T + i).await);
        chain.push(cur.fork().await.expect("fork"));
    }
    let id = k.tmb.to_b64();
    // A line of `n` commits over chain[over]; each commit's bundle.
    let line = async |over: usize, n: usize, now: i64| {
        let mut p = chain[over].fork().await.expect("fork");
        let mut out = Vec::new();
        for i in 0..n {
            out.push(create(&mut p, &k, &fresh_k(), now + i as i64).await);
        }
        out
    };
    let (j, o) = (line(2, 2, T + 100).await, line(2, 2, T + 200).await);
    let (x, y) = (line(1, 1, T + 300).await, line(1, 1, T + 301).await);

    for name in all {
        for (i, b) in bundles.iter().enumerate() {
            assert_eq!(post(&h, name, &id, b).await, 201, "{name}: C_{i}");
        }
    }
    // Every link is cut: with p1-p2 open, gossip hands p2 the owner's
    // commits (an Extended pull) before the test posts them, and the post
    // answers 422.
    for (a, b) in [("p1", "p2"), ("p1", "p3"), ("p2", "p3")] {
        h.proxy.partition(a, b);
    }
    // p3: the thief takes the tip, then fills the quota.
    assert_eq!(post(&h, "p3", &id, &j[0]).await, 201, "J_3");
    assert_eq!(post(&h, "p3", &id, &j[1]).await, 201, "J_4");
    for junk in [&x[0], &y[0]] {
        assert_eq!(post(&h, "p3", &id, junk).await, 409, "junk is retained");
    }
    // p1, p2: the owner's answer is canonical, and the quota is filled.
    for name in ["p1", "p2"] {
        assert_eq!(post(&h, name, &id, &o[0]).await, 201, "{name}: O_3");
        assert_eq!(post(&h, name, &id, &o[1]).await, 201, "{name}: O_4");
        for junk in [&x[0], &y[0]] {
            assert_eq!(post(&h, name, &id, junk).await, 409, "{name}: junk");
        }
    }
    for (a, b) in [("p1", "p2"), ("p1", "p3"), ("p2", "p3")] {
        h.proxy.heal(a, b);
    }

    let pr = Principal(id.clone());
    h.eventually(
        "every server to read Error at one fork point",
        CONVERGE,
        || async {
            let mut points = Vec::new();
            for peer in all {
                let Some(tip) = raw_tip(&h, peer, &pr).await else {
                    return Ok(false);
                };
                if tip["payload"]["state"] != "error" {
                    return Ok(false);
                }
                points.push(tip["payload"]["fork_point"].clone());
            }
            Ok(points.iter().all(|p| !p.is_null() && p == &points[0]))
        },
    )
    .await;
}

/// The same pre-fill, with the owner's answer arriving only through the CLI
/// (the owner's `push`). The thief signs with the owner's laptop key (a
/// copy of the device): it holds the tip, J_1, J_2, at p1, p2 and p3, and
/// the key's full quota there, junk X and Y. Its commits are built with the
/// CLI and posted straight to each server from `cyphr export`, because the
/// CLI never sends a commit over a tip the peer holds, so no client can
/// place a rival beside a canonical line. The owner's A_1, A_2, signed by
/// the same key over the base, must then land at every server.
///
/// Red until the CLI sends the fork. It refuses at
/// `rs/cyphr-cli/src/commands/network.rs:92-105` (`push`): `held_position`
/// finds the peer's tip in no local history and returns `PeerError::Stale`
/// ("is not in the local history", :99-103) before sending anything; and
/// `push_commit` (:112) sends one bundle per request, with no `parent` and no
/// resend after a `branch_limit` answer, so a root a full quota refuses
/// could not land even if the tip check passed.
///
/// Catches a CLI that cannot answer a thief's tip: every server must end in
/// state Error at one fork point, not Active on the thief's line.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_answers_a_thiefs_tip_through_the_cli() {
    let h = Harness::start_gossiping(&["p1", "p2", "p3"], 1)
        .await
        .expect("start peers");
    h.require(CAPS).await;
    let servers = ["p1", "p2", "p3"];
    let (alice, laptop) = (h.client("alice"), h.client("alice-laptop"));
    let (tj, tx, ty) = (
        h.client("thief-j"),
        h.client("thief-x"),
        h.client("thief-y"),
    );

    // The owner answers from the laptop, whose key the thief copies.
    let pr = h.ok(alice.create_principal().await);
    let key = h.ok(alice.pair_device(&pr, &laptop).await);
    h.ok(alice.push(&pr, &servers).await).accepted("base push");
    let base = h.ok(laptop.exported_commits(&pr).await).len();
    for thief in [&tj, &tx, &ty] {
        h.ok(thief.steal_key(&laptop, &key).await);
    }
    for n in 0..2 {
        h.ok(tj.commit_data(&pr, &format!("thief line {n}")).await);
    }
    h.ok(tx.commit_data(&pr, "junk x").await);
    h.ok(ty.commit_data(&pr, "junk y").await);

    // The thief takes the tip and fills the key's quota at every server.
    // An export line carries each coz as a JSON object; the push body
    // carries it as the base64url of its JSON.
    let wire = |line: &serde_json::Value| {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let enc = |coz: &serde_json::Value| {
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(coz).expect("coz json"))
        };
        let txs: Vec<Vec<String>> = line["txs"]
            .as_array()
            .expect("txs")
            .iter()
            .map(|tx| tx.as_array().expect("tx").iter().map(enc).collect())
            .collect();
        serde_json::json!({"principal_id": pr.0, "txs": txs, "keys": line["keys"]})
    };
    let post = async |peer: &str, line: &serde_json::Value| {
        h.http
            .post(format!("http://{}/push", h.peer(peer).addr()))
            .json(&wire(line))
            .send()
            .await
            .expect("push request")
            .status()
            .as_u16()
    };
    let line = async |c: &Client<'_>| h.ok(c.exported_commits(&pr).await).split_off(base);
    let (j, x, y) = (line(&tj).await, line(&tx).await, line(&ty).await);
    assert_eq!(
        (j.len(), x.len(), y.len()),
        (2, 1, 1),
        "the thief's commits"
    );
    // Gossip must not hand a server the thief's commits before the test
    // posts them (it answered p3's J_1 with 422 when p1 had been given
    // them first), so every link is cut while the thief's commits go in.
    for (a, b) in [("p1", "p2"), ("p1", "p3"), ("p2", "p3")] {
        h.proxy.partition(a, b);
    }
    for peer in servers {
        assert_eq!(post(peer, &j[0]).await, 201, "{peer}: J_1");
        assert_eq!(post(peer, &j[1]).await, 201, "{peer}: J_2");
        assert_eq!(post(peer, &x[0]).await, 409, "{peer}: junk x is retained");
        assert_eq!(post(peer, &y[0]).await, 409, "{peer}: junk y is retained");
    }

    for (a, b) in [("p1", "p2"), ("p1", "p3"), ("p2", "p3")] {
        h.proxy.heal(a, b);
    }

    // The owner's answer, only by the CLI.
    for n in 0..2 {
        h.ok(laptop.commit_data(&pr, &format!("owner answer {n}")).await);
    }
    // Deliberately a fork against the peers holding the thief's branch, so
    // the user's explicit choice (`--assert-local`).
    h.ok(laptop.push_fork(&pr, &servers).await)
        .accepted("the owner's answer");

    h.eventually(
        "every server to read Error at one fork point",
        CONVERGE,
        || async {
            let mut points = Vec::new();
            for peer in servers {
                let Some(tip) = raw_tip(&h, peer, &pr).await else {
                    return Ok(false);
                };
                if tip["payload"]["state"] != "error" {
                    return Ok(false);
                }
                points.push(tip["payload"]["fork_point"].clone());
            }
            Ok(points.iter().all(|p| !p.is_null() && p == &points[0]))
        },
    )
    .await;
}
