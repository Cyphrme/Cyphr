//! The verdict oracle: every field of a client's [`Verdict`] is checked
//! against what the peers themselves hold, never against the action that
//! produced it.
//!
//! Some checks need peer routes that do not exist yet. Until their supplier
//! lands, such a check does not pass: it ends the scenario as
//! `RED(<capability>)`, so the oracle can never accept a verdict vacuously.
//! What the signed `/tip` envelope can already answer is checked for real.

use std::collections::BTreeSet;

use crate::actions::{Principal, Standing, Verdict};
use crate::capability::Capability;
use crate::harness::Harness;

/// What the scenario chose, against which the verdict is held.
pub struct Expect<'a> {
    /// The peers the verdict was asked to use.
    pub peers: &'a [&'a str],
    /// The anchor the scenario chose (its genesis handle, any spelling).
    pub anchor_id: &'a str,
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

        // tip and branches: each chosen peer's own tip is a branch head the
        // verdict must carry, and the verdict's tip must be one of them.
        let mut held = Vec::new();
        for name in e.peers {
            if let Some(view) = self.peer_view(name, p).await {
                assert!(
                    v.branches.contains(&view.tip),
                    "peer `{name}` holds {:?}, absent from the verdict's branches {:?}",
                    view.tip,
                    v.branches
                );
                held.push((*name, view));
            }
        }
        assert!(v.branches.contains(&v.tip), "tip is not among its branches");

        // standing: a single branch with no evidence is Active. Anything
        // else is a fork claim, which only the peers' stored branches can
        // confirm, and that route (branches with `pre`) does not exist yet.
        if v.branches.len() == 1 && v.evidence.is_empty() {
            assert_eq!(v.standing, Standing::Active, "one branch, no evidence");
        } else {
            assert_eq!(v.standing, Standing::Error, "a fork is reported in Error");
            self.require_route(Capability::BranchStore).await;
        }

        // evidence: re-verified offline from signed items a peer serves.
        // With no such route, even "no evidence" would be an unchecked claim.
        self.require_route(Capability::Evidence).await;
        let served = self.served_evidence(e.peers, p).await;
        assert_eq!(
            served > 0,
            !v.evidence.is_empty(),
            "verdict evidence {:?} disagrees with the {served} item(s) the peers serve",
            v.evidence
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
            let age = self.peer_age(name, p).await.expect("peer reported a tip");
            let diff = (age - v.freshness.age.as_secs() as i64).abs();
            assert!(
                diff <= 2,
                "freshness.age {:?} vs observed lag {age}s",
                v.freshness.age
            );
        }

        // resolved_by: the key that signed the resolution commit, read from
        // the peer's patch. A fork-keeping store is the supplier of that route.
        if let Some(k) = &v.resolved_by {
            let Some(signer) = self.last_commit_signer(e.peers[0], p).await else {
                self.red(Capability::BranchStore)
            };
            assert_eq!(
                signer, k.0,
                "resolved_by is not the key that signed the resolution"
            );
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

    /// Items the chosen peers serve at `GET /evidence?pr=`; the item shape
    /// is provisional until the evidence route exists.
    async fn served_evidence(&self, peers: &[&str], p: &Principal) -> usize {
        let mut n = BTreeSet::new();
        for name in peers {
            let addr = self.peers.iter().find(|x| x.name == *name).map(|x| x.addr);
            let Some(addr) = addr else { continue };
            let body = self
                .http
                .get(format!("http://{addr}/evidence"))
                .query(&[("pr", p.0.as_str())])
                .send()
                .await
                .ok();
            let Some(resp) = body.filter(|r| r.status().is_success()) else {
                continue;
            };
            let Ok(bytes) = resp.bytes().await else {
                continue;
            };
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            for item in v["payload"]["items"].as_array().into_iter().flatten() {
                n.insert(item.to_string());
            }
        }
        n.len()
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

    /// The thumbprint that signed the last blob of the peer's last commit.
    /// `None` when the patch route cannot answer, which ends the scenario as
    /// RED for the branch store that owns it.
    async fn last_commit_signer(&self, peer: &str, p: &Principal) -> Option<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};
        let addr = self.peers.iter().find(|x| x.name == peer)?.addr;
        let resp = self
            .http
            .get(format!("http://{addr}/patch"))
            .query(&[("pr", p.0.as_str())])
            .send()
            .await
            .ok()?;
        let v: serde_json::Value = serde_json::from_slice(&resp.bytes().await.ok()?).ok()?;
        let entry = v["payload"]["entries"].as_array()?.last()?.clone();
        let blob = entry["blobs"].as_array()?.last()?.as_str()?.to_owned();
        let coz: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(&blob).ok()?).ok()?;
        let tmb = coz["pay"]["tmb"].as_str().map(str::to_owned);
        if tmb.is_none() {
            self.red(Capability::BranchStore);
        }
        tmb
    }
}
