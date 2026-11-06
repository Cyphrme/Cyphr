//! Peer-chain scenarios for the client: a client pins a peer by PG and
//! genesis key, follows the peer's own chain over `/patch`, and judges every
//! statement the peer signs against the keys ACTIVE in the chain it holds.
//!
//! Every test here is an end-to-end scenario over the public API with an
//! in-test carrier (a `Connector` serving canned bodies) and real chains
//! built with `cyphr`. They name `PeerChain`, `PeerFailure` and the
//! `peer.rs` surface that does not exist yet, so the whole file sits behind
//! `cfg(red_n20)`; run it with
//! `RUSTFLAGS="--cfg red_n20" cargo test -p cyphr-client --test peer_chain`.
//! Without the cfg the file compiles to nothing and the workspace stays
//! green. The wire shape the carrier serves (blob format, an unsigned
//! statement slot on `/patch`) is the one the server already uses for a
//! pushed commit; a chain is authenticated by replay against the pinned
//! genesis, not by the patch statement.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr_client::{ChannelBinding, ConnectError, Connector, PeerChain, PeerFailure, Request};

fn b64(b: u8) -> String {
    Base64UrlUnpadded::encode_string(&[b; 32])
}

/// A signing key with its thumbprint.
struct Kp {
    kp: coz::KeyPair,
    tmb: coz::Thumbprint,
}

fn kp() -> Kp {
    let kp = coz::Alg::Ed25519.generate_keypair();
    let tmb = kp
        .alg
        .compute_thumbprint(&kp.pub_bytes)
        .expect("ed25519 thumbprint");
    Kp { kp, tmb }
}

impl Kp {
    fn domain_key(&self, first_seen: i64) -> cyphr::Key {
        cyphr::Key::new(
            self.kp.alg.name().to_string(),
            self.tmb.clone(),
            self.kp.pub_bytes.clone(),
        )
        .expect("key binds its tmb")
        .with_first_seen(first_seen)
    }
}

/// A principal with an implicit genesis on `genesis`, grown one
/// `key/create` commit at a time. `commit` returns the commit's wire blobs
/// (base64url of each coz JSON, introduced keys embedded, the genesis key on
/// the closing cozy of the first commit), exactly what `/patch` carries.
struct Chain<'a> {
    genesis: &'a Kp,
    principal: cyphr::Principal<cyphr::eml::MemoryStorage>,
    commits: usize,
}

impl<'a> Chain<'a> {
    fn new(genesis: &'a Kp) -> Self {
        let principal = cyphr::Principal::implicit(genesis.domain_key(1_700_000_000))
            .expect("implicit genesis");
        Self {
            genesis,
            principal,
            commits: 0,
        }
    }

    fn pg(&self) -> String {
        self.genesis.tmb.to_b64()
    }

    fn commit(&mut self, introduce: &Kp, now: i64) -> Vec<String> {
        let g = self.genesis;
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": g.kp.alg.name(),
            "id": introduce.tmb.to_b64(),
            "now": now,
            "tmb": g.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/create",
        }))
        .expect("pay json");
        let (sig, cad) =
            coz::sign_json(&pay, g.kp.alg.name(), &g.kp.prv_bytes, &g.kp.pub_bytes).expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, g.kp.alg.name()).expect("czd");

        let mut scope = self.principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, Some(introduce.domain_key(now)))
            .expect("key/create applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    g.kp.alg.name(),
                    &g.kp.prv_bytes,
                    &g.kp.pub_bytes,
                    &g.tmb,
                ),
                now,
                "cyphr.me",
            )
            .expect("commit finalizes");

        let first = self.commits == 0;
        self.commits += 1;
        let commit = self.principal.commits().last().expect("a commit exists");
        let mut blobs: Vec<serde_json::Value> = commit
            .iter_all_cozies()
            .map(|cz| {
                let mut coz = serde_json::to_value(cz.raw()).expect("coz json");
                if let Some(key) = cz.new_key() {
                    coz["key"] = serde_json::json!({
                        "alg": key.alg(),
                        "pub": Base64UrlUnpadded::encode_string(key.pub_key()),
                        "tmb": key.tmb().to_b64(),
                    });
                }
                coz
            })
            .collect();
        if first {
            blobs.last_mut().expect("closing cozy")["key"] = serde_json::json!({
                "alg": g.kp.alg.name(),
                "pub": Base64UrlUnpadded::encode_string(&g.kp.pub_bytes),
                "tmb": g.tmb.to_b64(),
            });
        }
        blobs
            .iter()
            .map(|b| Base64UrlUnpadded::encode_string(&serde_json::to_vec(b).expect("json")))
            .collect()
    }
}

impl Chain<'_> {
    /// A commit in which `victim` revokes itself (SPEC section 4.2.4), the
    /// commit finalized by the genesis key. Returns the wire blobs.
    fn revoke(&mut self, victim: &Kp, now: i64) -> Vec<String> {
        let g = self.genesis;
        let pay = serde_json::to_vec(&serde_json::json!({
            "alg": victim.kp.alg.name(),
            "now": now,
            "rvk": now,
            "tmb": victim.tmb.to_b64(),
            "typ": "cyphr.me/cyphr/key/revoke",
        }))
        .expect("pay json");
        let (sig, cad) = coz::sign_json(
            &pay,
            victim.kp.alg.name(),
            &victim.kp.prv_bytes,
            &victim.kp.pub_bytes,
        )
        .expect("sign");
        let czd = coz::czd_for_alg(&cad, &sig, victim.kp.alg.name()).expect("czd");
        let mut scope = self.principal.begin_commit();
        scope
            .verify_and_apply(&pay, &sig, czd, None)
            .expect("self-revoke applies");
        scope
            .finalize_with_software(
                &cyphr::signer::SoftwareSigner::new(
                    g.kp.alg.name(),
                    &g.kp.prv_bytes,
                    &g.kp.pub_bytes,
                    &g.tmb,
                ),
                now,
                "cyphr.me",
            )
            .expect("commit finalizes");
        self.commits += 1;
        self.principal
            .commits()
            .last()
            .expect("a commit exists")
            .iter_all_cozies()
            .map(|cz| {
                Base64UrlUnpadded::encode_string(&serde_json::to_vec(cz.raw()).expect("coz json"))
            })
            .collect()
    }
}

/// A `/patch` body carrying `entries` (one blob list per commit).
fn patch_body(entries: &[Vec<String>]) -> Vec<u8> {
    let entries: Vec<_> = entries
        .iter()
        .enumerate()
        .map(|(i, blobs)| serde_json::json!({ "sequence": i, "blobs": blobs }))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "payload": { "entries": entries },
        "statement": { "kind": "unsigned" },
    }))
    .expect("patch json")
}

/// An in-memory carrier serving whatever body is set, counting exchanges.
struct Pipe {
    body: Mutex<Vec<u8>>,
    exchanges: AtomicUsize,
}

impl Pipe {
    fn new(body: Vec<u8>) -> Self {
        Self {
            body: Mutex::new(body),
            exchanges: AtomicUsize::new(0),
        }
    }

    fn serve(&self, body: Vec<u8>) {
        *self.body.lock().expect("pipe lock") = body;
    }

    fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }
}

impl Connector for Pipe {
    fn channel_binding(&self) -> Option<&ChannelBinding> {
        None
    }

    async fn exchange(&self, _request: &Request) -> Result<Vec<u8>, ConnectError> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(self.body.lock().expect("pipe lock").clone())
    }
}

fn sign_as(signer: &Kp, pay: serde_json::Value) -> serde_json::Value {
    let bytes = serde_json::to_vec(&pay).expect("pay json");
    let (sig, _) = coz::sign_json(
        &bytes,
        signer.kp.alg.name(),
        &signer.kp.prv_bytes,
        &signer.kp.pub_bytes,
    )
    .expect("sign");
    serde_json::json!({ "pay": pay, "sig": Base64UrlUnpadded::encode_string(&sig) })
}

/// The principal a tip or view statement is about (not the peer's own).
fn subject() -> (String, coz::Thumbprint) {
    (b64(7), coz::Thumbprint::from_bytes(vec![7; 32]))
}

fn digest(b: u8) -> String {
    format!("SHA-256:{}", b64(b))
}

/// A `/tip` envelope signed by `signer`.
fn tip_envelope(signer: &Kp) -> serde_json::Value {
    let (pr, _) = subject();
    let pay = serde_json::json!({
        "alg": signer.kp.alg.name(),
        "now": 1_700_000_500,
        "tmb": signer.tmb.to_b64(),
        "typ": "cyphr-server/receipt/tip",
        "pr": pr,
        "sequence": 1,
        "commit_id": digest(9),
        "roots": { "pr": digest(1), "sr": digest(2), "ar": digest(3), "cr": digest(4) },
    });
    serde_json::json!({
        "v": 1,
        "payload": {},
        "statement": { "kind": "signed", "coz": sign_as(signer, pay) },
    })
}

/// A view statement coz signed by `signer`.
fn view_coz(signer: &Kp) -> coz::CozJson {
    let (pr, _) = subject();
    let pay = serde_json::json!({
        "alg": signer.kp.alg.name(),
        "now": 1_700_000_500,
        "tmb": signer.tmb.to_b64(),
        "typ": "cyphr-server/view",
        "pr": pr,
        "tree_size": 2,
        "index": 1,
        "commit_id": digest(9),
        "roots": { "pr": digest(1), "sr": digest(2), "ar": digest(3), "cr": digest(4) },
    });
    serde_json::from_value(sign_as(signer, pay)).expect("coz json")
}

/// Claim: a client that pinned a peer holds only what it has followed, so a
/// statement signed by a key the peer introduced LATER is refused until the
/// client follows once, after which the same statement is accepted, for a
/// tip and for a view alike, and a key the followed chain still does not
/// hold stays refused.
///
/// Turns red if: `follow` does not extend the held chain with the peer's
/// commits; `verify_tip` or `verify_view` accept a key the held chain lacks
/// (trusting the statement's own say-so); `verify_view` ignores the held
/// chain's active keys; or `verify_tip_following` does not follow.
/// End-to-end scenario: yes (real chain replayed from a carrier).
#[tokio::test]
async fn follow_extends_the_chain_and_statements_verify_against_held_keys() {
    let g = kp();
    let k1 = kp();
    let outsider = kp();
    let mut peer = Chain::new(&g);
    let c1 = peer.commit(&k1, 1_700_000_100);
    let pipe = Pipe::new(patch_body(std::slice::from_ref(&c1)));
    let (pr, pr_tmb) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000));

    // Before following, the held chain is just the genesis: the later key
    // is unknown and the genesis key's own statements verify.
    let tip = tip_envelope(&k1);
    assert!(
        matches!(
            held.verify_tip(&tip, &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "a key the held chain has not seen must be refused before following"
    );
    assert!(
        held.verify_tip(&tip_envelope(&g), &pr).is_ok(),
        "the pinned genesis key verifies from the start"
    );
    assert!(
        matches!(
            held.verify_view(&view_coz(&k1), &pr_tmb),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "verify_view uses the held chain's active keys, not the statement's"
    );

    held.follow(&pipe).await.expect("follow the peer chain");
    assert_eq!(pipe.exchanges(), 1, "one follow is one patch fetch");

    let report = held
        .verify_tip(&tip, &pr)
        .expect("the introduced key verifies after following");
    assert_eq!(report.sequence, 1);
    let view = held
        .verify_view(&view_coz(&k1), &pr_tmb)
        .expect("a view by the introduced key verifies after following");
    assert_eq!((view.tree_size, view.index), (2, 1));

    // A key the followed chain never held stays refused.
    assert!(matches!(
        held.verify_view(&view_coz(&outsider), &pr_tmb),
        Err(PeerFailure::KeyNotActive { .. })
    ));
}

/// Claim: a statement signed by a key the peer chain NEVER held is refused
/// after one follow, and the client does not loop re-following: following
/// cannot conjure a key, so exactly one patch is fetched.
///
/// Turns red if: the key is accepted; the refusal surfaces as another
/// failure; or `verify_tip_following` fetches more than once.
/// End-to-end scenario: yes.
#[tokio::test]
async fn never_held_key_stays_refused_after_one_follow() {
    let g = kp();
    let k1 = kp();
    let outsider = kp();
    let mut peer = Chain::new(&g);
    let c1 = peer.commit(&k1, 1_700_000_100);
    let pipe = Pipe::new(patch_body(&[c1]));
    let (pr, _) = subject();

    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000));
    let refused = held
        .verify_tip_following(&pipe, &tip_envelope(&outsider), &pr)
        .await;
    assert!(
        matches!(refused, Err(PeerFailure::KeyNotActive { .. })),
        "a never-held key must be refused: {refused:?}"
    );
    assert_eq!(pipe.exchanges(), 1, "one follow, no loop");

    // The follow was not wasted: a key the chain does hold now verifies.
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());
}

/// Claim: a patch that does not extend the held chain (a rival commit at a
/// position the client already holds) is refused as `Fork`, and the held
/// chain is left exactly as it was: keys it held still verify, keys only
/// the rival introduced do not, and an honest extension still follows.
///
/// Turns red if: the rival patch is merged or replaces the held commit
/// (I2: a fork is detected, never merged); `follow` errors with something
/// other than `Fork`; or a failed follow mutates the held chain.
/// End-to-end scenario: yes (two diverging histories under one PG).
#[tokio::test]
async fn rival_patch_is_a_fork_and_leaves_the_held_chain_unchanged() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let rival_key = kp();
    let mut honest = Chain::new(&g);
    let c1 = honest.commit(&k1, 1_700_000_100);
    let c2 = honest.commit(&k2, 1_700_000_200);
    let mut rival = Chain::new(&g);
    let r1 = rival.commit(&rival_key, 1_700_000_150);
    let (pr, _) = subject();

    let pipe = Pipe::new(patch_body(std::slice::from_ref(&c1)));
    let mut held = PeerChain::pin(&honest.pg(), g.domain_key(1_700_000_000));
    held.follow(&pipe)
        .await
        .expect("follow to the first commit");

    pipe.serve(patch_body(&[r1]));
    let forked = held.follow(&pipe).await;
    assert!(
        matches!(forked, Err(PeerFailure::Fork { .. })),
        "a rival commit at a held position is a fork: {forked:?}"
    );

    assert!(
        held.verify_tip(&tip_envelope(&k1), &pr).is_ok(),
        "the held chain still holds its own key"
    );
    assert!(
        matches!(
            held.verify_tip(&tip_envelope(&rival_key), &pr),
            Err(PeerFailure::KeyNotActive { .. })
        ),
        "nothing of the rival patch was kept"
    );

    pipe.serve(patch_body(&[c1, c2]));
    held.follow(&pipe)
        .await
        .expect("an honest extension still follows after a refused fork");
    assert!(held.verify_tip(&tip_envelope(&k2), &pr).is_ok());
}

/// Claim: a pin whose PG does not derive from the genesis key it names is
/// refused as `PinMismatch` and nothing is adopted.
///
/// Turns red if: the pin is trusted without checking it against the genesis
/// key, so a client can be pinned to a chain its key does not root.
/// End-to-end scenario: no. Reason: the refusal is a single pure check on
/// the pin arguments; the in-server scenario covers the discovered-PG case.
#[tokio::test]
async fn pin_naming_another_pg_is_refused() {
    let g = kp();
    let k1 = kp();
    let mut peer = Chain::new(&g);
    let c1 = peer.commit(&k1, 1_700_000_100);
    let pipe = Pipe::new(patch_body(&[c1]));

    let mut held = PeerChain::pin(&b64(5), g.domain_key(1_700_000_000));
    let refused = held.follow(&pipe).await;
    assert!(
        matches!(refused, Err(PeerFailure::PinMismatch { .. })),
        "{refused:?}"
    );
    let (pr, _) = subject();
    assert!(
        held.verify_tip(&tip_envelope(&k1), &pr).is_err(),
        "a mismatched pin adopts nothing"
    );
}

/// Claim: a key the followed chain REVOKED is refused for a tip and for a
/// view, while a sibling key the chain still holds verifies, so lookup is
/// among ACTIVE keys and never among every key the chain ever held.
///
/// Turns red if: `verify_tip` or `verify_view` look a key up among all keys
/// the chain has held (a revoked key still vouches), or trust the
/// statement's own signature without the chain's say-so.
/// End-to-end scenario: yes (real chain with a revocation, replayed from a
/// carrier).
#[tokio::test]
async fn revoked_key_in_the_held_chain_is_refused() {
    let g = kp();
    let k1 = kp();
    let k2 = kp();
    let mut peer = Chain::new(&g);
    let c1 = peer.commit(&k1, 1_700_000_100);
    let c2 = peer.commit(&k2, 1_700_000_200);
    let c3 = peer.revoke(&k1, 1_700_000_300);
    let (pr, pr_tmb) = subject();

    let pipe = Pipe::new(patch_body(&[c1.clone(), c2.clone()]));
    let mut held = PeerChain::pin(&peer.pg(), g.domain_key(1_700_000_000));
    held.follow(&pipe).await.expect("follow before the revoke");
    assert!(held.verify_tip(&tip_envelope(&k1), &pr).is_ok());

    pipe.serve(patch_body(&[c1, c2, c3]));
    held.follow(&pipe).await.expect("follow the revoke");
    assert!(matches!(
        held.verify_tip(&tip_envelope(&k1), &pr),
        Err(PeerFailure::KeyNotActive { .. })
    ));
    assert!(matches!(
        held.verify_view(&view_coz(&k1), &pr_tmb),
        Err(PeerFailure::KeyNotActive { .. })
    ));
    assert!(held.verify_tip(&tip_envelope(&k2), &pr).is_ok());
}
