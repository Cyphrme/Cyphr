//! The verdict oracle: every field of a client's [`Verdict`] is checked
//! against what the peers themselves hold, never against the action that
//! produced it.
//!
//! Some checks need peer routes that do not exist yet. Until their supplier
//! lands, such a check does not pass: it ends the scenario as
//! `RED(<capability>)`, so the oracle can never accept a verdict vacuously.
//! What the signed `/tip` envelope can already answer is checked for real.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::actions::{Evidence, Principal, Standing, Tip, Verdict};
use crate::capability::Capability;
use crate::harness::Harness;
use crate::signed::{self, Keys, Proven};

/// What the scenario chose, against which the verdict is held.
pub struct Expect<'a> {
    /// The peers the verdict was asked to use.
    pub peers: &'a [&'a str],
    /// The anchor the scenario chose (its genesis handle, any spelling).
    pub anchor_id: &'a str,
    /// Chosen peers the scenario has itself taken down; every other chosen
    /// peer must answer the oracle's reads.
    pub down: &'a [&'a str],
}

impl<'a> Expect<'a> {
    pub fn new(peers: &'a [&'a str], anchor_id: &'a str) -> Self {
        Self {
            peers,
            anchor_id,
            down: &[],
        }
    }

    pub fn down(mut self, down: &'a [&'a str]) -> Self {
        self.down = down;
        self
    }
}

impl Harness {
    /// Check `v` field by field against the chosen peers' own state.
    pub async fn check_verdict(&self, v: &Verdict, p: &Principal, e: &Expect<'_>) {
        // peers: the chosen set, nothing else, never empty.
        let mut used: Vec<&str> = v.peers.iter().map(String::as_str).collect();
        let mut chosen = e.peers.to_vec();
        used.sort_unstable();
        chosen.sort_unstable();
        assert_eq!(used, chosen, "verdict peers differ from the chosen set");

        // anchor: the one the scenario chose.
        assert!(
            Principal(e.anchor_id.to_owned()).same_as(&v.anchor.id),
            "verdict anchor {} is not the chosen {}",
            v.anchor.id,
            e.anchor_id
        );

        // Every chosen peer the scenario has not taken down must answer; a
        // silent skip would let an unreachable peer vouch for nothing.
        let live: Vec<&str> = e
            .peers
            .iter()
            .copied()
            .filter(|n| !e.down.contains(n))
            .collect();
        let mut held = Vec::new();
        for name in &live {
            let Some(view) = self.peer_view(name, p).await else {
                panic!("peer `{name}` did not report a tip for the principal");
            };
            held.push((*name, view));
        }
        assert_eq!(held.len(), live.len());

        // branches and standing come from the peers' own heads. Several
        // different heads could be a fork or only one peer lagging; only the
        // peers' stored branches (with `pre`) can tell, so such a verdict is
        // held to what the peers' `/branches` route lists, exactly.
        let heads: BTreeSet<_> = held.iter().map(|(_, t)| t.tip.clone()).collect();
        let claimed_branches: BTreeSet<_> = v.branches.iter().cloned().collect();
        assert!(v.branches.contains(&v.tip), "tip is not among its branches");
        if heads.len() == 1 {
            assert_eq!(
                claimed_branches, heads,
                "verdict branches differ from the peers' observed head"
            );
            if v.evidence.is_empty() {
                assert_eq!(v.standing, Standing::Active, "one head, no evidence");
            }
        } else {
            self.require_route(Capability::BranchStore).await;
            self.require_route(Capability::Evidence).await;
            // The live heads: each peer's own head, and each rival branch's
            // tip the peers prove by evidence, less any commit a peer's
            // chain or a proved extension continues past.
            let (_, rival_tips) = self.verified_evidence(&live, p).await;
            let mut inner = BTreeSet::new();
            for name in &live {
                let chain = self.chain_read(name, p).await;
                let n = chain.commit_ids.len().saturating_sub(1);
                inner.extend(chain.commit_ids.into_iter().take(n).map(Tip));
            }
            let live_heads: BTreeSet<Tip> = heads
                .iter()
                .cloned()
                .chain(rival_tips.into_iter().map(Tip))
                .filter(|t| !inner.contains(t))
                .collect();
            assert_eq!(
                claimed_branches, live_heads,
                "verdict branches differ from the peers' live heads"
            );
            assert_eq!(v.standing, Standing::Error, "a fork is reported in Error");
        }
        if v.standing == Standing::Active && v.branches.len() > 1 {
            assert!(
                v.resolved_by.is_some(),
                "an Active verdict over several branches must name who resolved it"
            );
        }

        // evidence: re-verified offline from signed items a peer serves.
        // With no such route, even "no evidence" would be an unchecked claim.
        self.require_route(Capability::Evidence).await;
        let (proven, _) = self.verified_evidence(&live, p).await;
        let claimed: BTreeSet<Proven> = v
            .evidence
            .iter()
            .map(|x| match x {
                Evidence::PrincipalFork(pr) => Proven::PrincipalFork {
                    pg: pr.bare().to_owned(),
                },
                Evidence::PeerEquivocation { peer } => Proven::PeerEquivocation {
                    pg: p.bare().to_owned(),
                    peer: peer.clone(),
                },
            })
            .collect();
        assert_eq!(
            claimed, proven,
            "verdict evidence differs from the items the peers serve"
        );

        // freshness: the lag the oracle observes. A newer height at any
        // chosen peer than the verdict's tip means a peer reported newer.
        let verdict_height = held
            .iter()
            .find(|(_, t)| t.tip == v.tip)
            .map(|(_, t)| t.height);
        let newer = held
            .iter()
            .any(|(_, t)| verdict_height.is_none_or(|h| t.height > h));
        assert_eq!(
            v.freshness.peer_reported_newer, newer,
            "freshness.peer_reported_newer disagrees with the peers' heights"
        );
        if let Some((name, _)) = held.iter().find(|(_, t)| t.tip == v.tip) {
            // The peer's age is whole seconds (truncated, so up to 1s low)
            // and is read after the verdict: it can exceed the verdict's age
            // by at most the time that really passed between the two reads,
            // which is measured, not guessed, so load cannot flake it.
            let peer_s = self.peer_age(name, p).await.expect("peer reported a tip");
            let gap_ms = v.observed_at.elapsed().as_millis() as i64;
            let age_ms = peer_s * 1000;
            let verdict_ms = v.freshness.age.as_millis() as i64;
            assert!(
                age_ms >= verdict_ms - 1000 - gap_ms && age_ms <= verdict_ms + 1000 + gap_ms,
                "freshness.age {:?} vs observed lag {age_ms}ms (reads {gap_ms}ms apart)",
                v.freshness.age
            );
        }

        // resolved_by: the key that signed the resolution commit, on every
        // live chosen peer's chain.
        if let Some(k) = &v.resolved_by {
            for name in &live {
                let Some(signer) = self.last_commit_signer(name, p).await else {
                    self.red(Capability::BranchStore)
                };
                assert_eq!(
                    signer, k.0,
                    "`{name}`: resolved_by is not the key that signed the resolution"
                );
            }
        }
    }

    /// End the scenario as RED for `cap` unless its route is observable now.
    async fn require_route(&self, cap: Capability) {
        match cap.probe().eval(self, cap).await {
            Ok(true) => {},
            Ok(false) => self.red(cap),
            Err(e) => panic!("harness defect: {e}"),
        }
    }

    /// Items the chosen peers serve at `GET /evidence?pr=`, each verified
    /// offline against keys the harness read from the peers themselves. A
    /// served item that does not verify fails the scenario. PROVISIONAL: the
    /// item shape is owned by the evidence route.
    async fn verified_evidence(
        &self,
        peers: &[&str],
        p: &Principal,
    ) -> (BTreeSet<Proven>, BTreeSet<String>) {
        let mut keys = Keys::new();
        let mut by_peer = BTreeMap::new();
        let mut chains = BTreeMap::new();
        for name in peers {
            if let Some((id, alg, pub_b64, tmb)) = self.server_key(name).await {
                keys.insert(tmb.clone(), (alg, pub_b64));
                by_peer.insert(id, tmb);
            }
            chains.insert((*name).to_owned(), self.chain_read(name, p).await);
        }
        let mut out = BTreeSet::new();
        let mut tips = BTreeSet::new();
        for name in peers {
            let Some(addr) = self.peers.iter().find(|x| x.name == *name).map(|x| x.addr) else {
                continue;
            };
            // Every chosen peer must answer 2xx with the expected shape; a
            // failed read is not "no evidence".
            let resp = self
                .http
                .get(format!("http://{addr}/evidence"))
                .query(&[("pr", p.0.as_str())])
                .send()
                .await
                .unwrap_or_else(|e| panic!("peer `{name}`: evidence read failed: {e}"));
            let status = resp.status().as_u16();
            let bytes = resp
                .bytes()
                .await
                .unwrap_or_else(|e| panic!("peer `{name}`: evidence body: {e}"));
            let items = signed::evidence_items(status, &bytes)
                .unwrap_or_else(|why| panic!("peer `{name}`: {why}"));
            match signed::verify_evidence_set(&items, p.bare(), &keys, &by_peer, &chains[*name])
                .await
            {
                Ok(set) => {
                    out.extend(set.proven);
                    tips.extend(set.rival_tips);
                },
                Err(why) => panic!("peer `{name}` served evidence that does not verify: {why}"),
            }
        }
        (out, tips)
    }

    /// A peer's identity, algorithm, public key and key thumbprint, from its
    /// own `GET /server`.
    async fn server_key(&self, peer: &str) -> Option<(String, String, String, String)> {
        let addr = self.peers.iter().find(|x| x.name == peer)?.addr;
        let resp = self
            .http
            .get(format!("http://{addr}/server"))
            .send()
            .await
            .ok()?;
        let v: Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        let t = &v["payload"];
        Some((
            t["pg"].as_str()?.to_owned(),
            t["alg"].as_str()?.to_owned(),
            t["pub"].as_str()?.to_owned(),
            t["tmb"].as_str()?.to_owned(),
        ))
    }

    /// A peer's chain for `p`, replayed from its `/patch` (see
    /// [`signed::ChainView`]). The empty view when the route cannot
    /// answer; a patch that answers but does not replay fails the scenario.
    async fn chain_read(&self, peer: &str, p: &Principal) -> signed::ChainView {
        let Some(addr) = self.peers.iter().find(|x| x.name == peer).map(|x| x.addr) else {
            return signed::ChainView::default();
        };
        let Ok(resp) = self
            .http
            .get(format!("http://{addr}/patch"))
            .query(&[("pr", p.0.as_str())])
            .send()
            .await
        else {
            return signed::ChainView::default();
        };
        if !resp.status().is_success() {
            return signed::ChainView::default();
        }
        let Ok(bytes) = resp.bytes().await else {
            return signed::ChainView::default();
        };
        signed::ChainView::from_patch(&bytes, p.bare())
            .await
            .unwrap_or_else(|why| panic!("peer `{peer}`'s chain does not replay: {why}"))
    }

    /// Seconds since the tip a peer reports was last updated, by the peer's
    /// own clock (`now - last_updated` in its `/tip`).
    pub async fn peer_age(&self, peer: &str, p: &Principal) -> Option<i64> {
        let addr = self.peers.iter().find(|x| x.name == peer)?.addr;
        let resp = self
            .http
            .get(format!("http://{addr}/tip"))
            .query(&[("pr", p.0.as_str())])
            .send()
            .await
            .ok()?;
        let v: serde_json::Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        Some(v["payload"]["now"].as_i64()? - v["payload"]["last_updated"].as_i64()?)
    }


    /// The thumbprint that signed the peer's last `commit/create`, read from
    /// the replayed chain (so every signature up to it verified). `None`
    /// when the patch route cannot answer; a patch that does not replay
    /// fails the scenario.
    async fn last_commit_signer(&self, peer: &str, p: &Principal) -> Option<String> {
        self.chain_read(peer, p).await.last_signer
    }
}
