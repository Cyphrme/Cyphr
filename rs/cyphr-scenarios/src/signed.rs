//! Offline verification of signed coz objects, independent of any action
//! under test. A statement, a commit or an evidence item is only believed
//! once its signature checks under a key the verifier already holds.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::eml::MemoryStorage;
use cyphr::state::{HashAlg, TaggedDigest};
use cyphr::{Key, Principal};
use cyphr_client::PatchEntry;
use cyphr_client::evidence::{replay_chain, verify_principal_fork};
use serde_json::Value;

/// Keys known to the verifier, by thumbprint: `tmb -> (alg, public key)`
/// with the public key base64url encoded.
pub type Keys = BTreeMap<String, (String, String)>;

/// The `pay` of a coz whose signature verified, and the signer's tmb.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    pub pay: Value,
    pub tmb: String,
}

/// Verify `coz` (`{pay, sig, ...}`) under the key `keys` holds for its own
/// `pay.tmb`. The signed bytes are the compact `pay` exactly as it appears.
pub fn verify(coz: &Value, keys: &Keys) -> Result<Verified, String> {
    let pay = coz.get("pay").ok_or("coz has no pay")?;
    let tmb = pay["tmb"].as_str().ok_or("pay has no tmb")?.to_owned();
    let (alg, pub_b64) = keys
        .get(&tmb)
        .ok_or_else(|| format!("no known key for tmb {tmb}"))?;
    let sig = Base64UrlUnpadded::decode_vec(coz["sig"].as_str().ok_or("coz has no sig")?)
        .map_err(|e| format!("sig is not base64url: {e}"))?;
    let pub_bytes = Base64UrlUnpadded::decode_vec(pub_b64)
        .map_err(|e| format!("public key is not base64url: {e}"))?;
    let pay_json = serde_json::to_vec(pay).map_err(|e| e.to_string())?;
    match coz::verify_json(&pay_json, &sig, alg, &pub_bytes) {
        Some(true) => Ok(Verified {
            pay: pay.clone(),
            tmb,
        }),
        Some(false) => Err(format!("signature does not verify under key {tmb}")),
        None => Err(format!("unsupported algorithm {alg}")),
    }
}

/// A held statement: the signed coz bytes a peer served. It must verify
/// under `alg`/`pub_b64` and name `tmb` as its signer.
pub fn verify_statement(bytes: &[u8], alg: &str, pub_b64: &str, tmb: &str) -> Result<(), String> {
    let coz: Value = serde_json::from_slice(bytes).map_err(|e| format!("not json: {e}"))?;
    let mut keys = Keys::new();
    keys.insert(tmb.to_owned(), (alg.to_owned(), pub_b64.to_owned()));
    let v = verify(&coz, &keys)?;
    if v.tmb != tmb {
        return Err(format!("signed by {}, expected {tmb}", v.tmb));
    }
    Ok(())
}

/// What a served evidence item proves, once verified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proven {
    PrincipalFork { pg: String },
    PeerEquivocation { pg: String, peer: String },
}

/// What the verifier holds of a principal's chain, read from a peer's
/// `GET /patch` and REPLAYED, never trusted: every commit is verified by the
/// core from a genesis that derives the principal, so keys, roots and
/// commit ids below are what the signatures and the chain support, not
/// what the peer says about itself.
#[derive(Default)]
pub struct ChainView {
    /// The principal at its genesis state, for replays from `pre`.
    pub genesis: Option<Principal<MemoryStorage>>,
    /// The genesis key the replay started from.
    pub genesis_key: Option<Key>,
    /// The fetched commits.
    pub entries: Vec<PatchEntry>,
    /// The Principal Root after each commit, tagged.
    pub prs: Vec<String>,
    /// The commit id of each commit, tagged.
    pub commit_ids: Vec<String>,
    /// The key that signed the last commit's closing `commit/create`.
    pub last_signer: Option<String>,
}

impl ChainView {
    /// Replay the chain of a `GET /patch` body for principal `pg` (bare).
    ///
    /// The genesis is read from the first commit, the genesis commit (SPEC
    /// 5.1): the key its first `key/create` names in the bundle's `keys`,
    /// the genesis key; the
    /// replay adds the rest. It is only accepted if the replay derives
    /// `pg`. A patch that does not replay, or whose stated roots or
    /// commit ids disagree with the replay, is an error.
    pub async fn from_patch(body: &[u8], pg: &str) -> Result<Self, String> {
        let patch = cyphr_client::verify_patch_body(body, pg, None)
            .map_err(|e| format!("patch is not a patch: {e}"))?;
        let first = patch
            .entries
            .first()
            .ok_or("the patch holds no commits")?
            .bundle
            .as_ref()
            .map_err(|e| format!("first commit is undecodable: {e:?}"))?;
        let cozies: Vec<Value> = first
            .txs
            .iter()
            .flatten()
            .filter_map(|b| serde_json::from_slice::<Value>(b).ok())
            .collect();
        let named = |c: &Value| {
            let id = c["pay"]["id"].as_str()?;
            first.keys.iter().find(|k| k.tmb == id)?.to_key().ok()
        };
        let typ_is = |c: &Value, suffix: &str| {
            c["pay"]["typ"]
                .as_str()
                .is_some_and(|t| t.ends_with(suffix))
        };
        let created = cozies
            .iter()
            .position(|c| typ_is(c, "/cyphr/principal/create"))
            .ok_or("the first commit is no genesis commit")?;
        let key = cozies[..created]
            .iter()
            .find(|c| typ_is(c, "/cyphr/key/create"))
            .ok_or("the genesis commit creates no key")
            .and_then(|c| named(c).ok_or("a genesis key/create discloses no key"))?;
        let genesis = Principal::implicit(key)
            .await
            .map_err(|e| format!("genesis: {e}"))?;
        Self::replay(body, pg, genesis, patch).await
    }

    /// Replay the chain of a `GET /patch` body for principal `pg` (bare)
    /// from a genesis key the caller already holds (a peer's own chain,
    /// whose genesis its `GET /server` states), with the same checks as
    /// [`ChainView::from_patch`].
    pub async fn from_patch_with_genesis(body: &[u8], pg: &str, key: Key) -> Result<Self, String> {
        let patch = cyphr_client::verify_patch_body(body, pg, None)
            .map_err(|e| format!("patch is not a patch: {e}"))?;
        let genesis = Principal::implicit(key)
            .await
            .map_err(|e| format!("genesis: {e}"))?;
        Self::replay(body, pg, genesis, patch).await
    }

    async fn replay(
        body: &[u8],
        pg: &str,
        genesis: Principal,
        patch: cyphr_client::VerifiedPatch,
    ) -> Result<Self, String> {
        let cyphr_client::VerifiedPatch {
            entries, actions, ..
        } = patch;
        let stated: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        // The genesis key: the one whose `key/create` opens the genesis
        // commit (SPEC 5.1).
        let key = Base64UrlUnpadded::decode_vec(genesis.genesis_key())
            .ok()
            .and_then(|tmb| genesis.get_key(&coz::Thumbprint::from_bytes(tmb)).cloned())
            .ok_or("the genesis holds no genesis key")?;
        let base = genesis
            .fork()
            .await
            .map_err(|e| format!("genesis does not fork: {e}"))?;
        let mut chain = replay_chain(base, &entries)
            .await
            .map_err(|e| format!("the patch does not replay from its genesis: {e}"))?;
        // The served actions hold no chain position: each is verified
        // once the commits are in, at its own `now` (SPEC 4.8.1, 6.5).
        for held in actions {
            let blobs = held
                .blobs
                .map_err(|defect| format!("a served action bundle is undecodable: {defect:?}"))?;
            let bundle = cyphr::replay::WireBundle::actions(blobs)
                .decode()
                .map_err(|e| format!("a served action bundle is malformed: {e}"))?;
            cyphr::replay::replay_bundle(&mut chain, &bundle)
                .await
                .map_err(|e| format!("a served action does not verify: {e}"))?;
        }
        // A genesis commit names the principal by its PG; a chain with none
        // by its genesis key's PR (SPEC 5.1).
        let derived = match chain.pg() {
            Some(g) => cyphr::StateDigest::as_multihash(g)
                .tagged_first()
                .map(|t| t.to_string())
                .map_err(|e| e.to_string()),
            None => genesis.pr_tagged().map_err(|e| e.to_string()),
        };
        let derives =
            derived.is_ok_and(|g| g == pg || g.split_once(':').is_some_and(|(_, bare)| bare == pg));
        if !derives {
            return Err("the first commit's genesis does not derive the principal".into());
        }

        let tagged = |m: &cyphr::MultihashDigest| -> Vec<String> {
            [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
                .into_iter()
                .filter_map(|a| {
                    TaggedDigest::new(a, m.get(a)?.to_vec())
                        .ok()
                        .map(|t| t.to_string())
                })
                .collect()
        };
        let stated_col = |field: &str| -> Vec<String> {
            stated["payload"]["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| e[field].as_str().unwrap_or_default().to_owned())
                .collect()
        };
        let (mut prs, mut commit_ids) = (Vec::new(), Vec::new());
        for ((c, pr), id) in chain
            .commits()
            .zip(stated_col("pr"))
            .zip(stated_col("commit_id"))
        {
            let (held_pr, held_id) = (tagged(&c.pr().0), tagged(&c.tr().0));
            if !held_pr.contains(&pr) || !held_id.contains(&id) {
                return Err("a stated root or commit id disagrees with the replay".into());
            }
            prs.push(pr);
            commit_ids.push(id);
        }
        let last_signer = entries
            .last()
            .and_then(|e| e.bundle.as_ref().ok())
            .and_then(|bundle| {
                bundle
                    .txs
                    .iter()
                    .flatten()
                    .filter_map(|b| serde_json::from_slice::<Value>(b).ok())
                    .rfind(|c| {
                        c["pay"]["typ"]
                            .as_str()
                            .is_some_and(|t| t.ends_with("/cyphr/commit/create"))
                    })
                    .and_then(|c| c["pay"]["tmb"].as_str().map(str::to_owned))
            });
        Ok(Self {
            genesis: Some(genesis),
            genesis_key: Some(key),
            entries,
            prs,
            commit_ids,
            last_signer,
        })
    }
}

impl ChainView {
    /// Every key the replayed chain ever introduced (its genesis key and
    /// each commit's `keys`), revoked or not: what a statement signed before
    /// a rotation is checked against. Each entry must bind its thumbprint.
    pub fn keys_ever(&self) -> Keys {
        let mut keys = Keys::new();
        if let Some(g) = &self.genesis_key {
            keys.insert(
                g.tmb().to_b64(),
                (
                    g.alg().to_owned(),
                    Base64UrlUnpadded::encode_string(g.pub_key()),
                ),
            );
        }
        let entries = self
            .entries
            .iter()
            .filter_map(|e| e.bundle.as_ref().ok())
            .flat_map(|b| &b.keys);
        for entry in entries {
            if let Ok(k) = entry.to_key() {
                keys.insert(
                    k.tmb().to_b64(),
                    (
                        k.alg().to_owned(),
                        Base64UrlUnpadded::encode_string(k.pub_key()),
                    ),
                );
            }
        }
        keys
    }
}

/// A genesis key from a coz `key` sidecar; `Key::new` refuses a thumbprint
/// that is not the key's own.
pub fn genesis_key(k: &Value) -> Option<Key> {
    let b64 = |name: &str| Base64UrlUnpadded::decode_vec(k.get(name)?.as_str()?).ok();
    Key::new(
        k.get("alg")?.as_str()?,
        coz::Thumbprint::from_bytes(b64("tmb")?),
        b64("pub")?,
    )
    .ok()
}

/// `(size, commit_id, roots)` a peer statement claims: a view statement's
/// tree size, or a tip report's sequence plus one.
fn claimed_extent(pay: &Value) -> Result<(u64, String, Value), String> {
    let size = match pay["typ"].as_str() {
        Some("cyphr-server/view") => pay["tree_size"].as_u64(),
        Some("cyphr-server/receipt/tip") => pay["sequence"].as_u64().map(|s| s + 1),
        other => {
            return Err(format!(
                "statement typ {other:?} is not a view or tip report"
            ));
        },
    }
    .filter(|n| *n > 0)
    .ok_or("statement has no usable size")?;
    let commit_id = pay["commit_id"]
        .as_str()
        .ok_or("statement has no commit_id")?;
    Ok((size, commit_id.to_owned(), pay["roots"].clone()))
}

/// Verify one served evidence item offline. `requested` is the principal
/// asked about (bare) and `chain` the verifier's own read of its chain.
///
/// A `principal-fork` item (`{pg, height, pre, a, b}`, `a` and `b` each
/// a commit bundle) is checked by [`verify_principal_fork`] against the replayed
/// `chain`: both commits must replay from the chain's state at `pre`, so
/// only keys the principal held there vouch (a serving peer's key never
/// does) and two copies of one commit are not a fork.
///
/// A `peer-equivocation` item (`{pg, peer, a, b}`, statements) must name
/// `requested`, and both statements must be signed by the accused peer's key.
/// At one size they conflict if they differ; at different sizes the lower
/// one is a prefix, and so no evidence, when both sit on `chain`.
pub async fn verify_evidence(
    item: &Value,
    requested: &str,
    keys: &Keys,
    peers: &BTreeMap<String, String>,
    chain: &ChainView,
) -> Result<Proven, String> {
    let pg = item["pg"].as_str().ok_or("item has no pg")?.to_owned();
    if pg != requested {
        return Err(format!("item names {pg}, not the requested {requested}"));
    }
    let (a, b) = (&item["a"], &item["b"]);
    if a.is_null() || b.is_null() {
        return Err("item lacks one of its two objects".into());
    }
    if a == b {
        return Err("the two objects are identical, so they do not conflict".into());
    }
    match item["kind"].as_str() {
        Some("principal-fork") => {
            // The client's own verifier: replays both commits from `pre` on
            // the chain read, so only keys the chain held at `pre` count
            // (a serving peer's key is never among them) and two copies of
            // one commit are not a fork.
            let genesis = chain
                .genesis
                .as_ref()
                .ok_or("no chain to replay from")?
                .fork()
                .await
                .map_err(|e| e.to_string())?;
            let proof = verify_principal_fork(item, requested, genesis, &chain.entries)
                .await
                .map_err(|e| e.to_string())?;
            Ok(Proven::PrincipalFork { pg: proof.pg })
        },
        Some("peer-equivocation") => {
            let peer = item["peer"]
                .as_str()
                .ok_or("equivocation names no peer")?
                .to_owned();
            let want = peers
                .get(&peer)
                .ok_or_else(|| format!("unknown peer {peer}"))?;
            let (va, vb) = (verify(a, keys)?, verify(b, keys)?);
            if &va.tmb != want || &vb.tmb != want {
                return Err(format!("objects are not both signed by peer {peer}"));
            }
            let (ea, eb) = (claimed_extent(&va.pay)?, claimed_extent(&vb.pay)?);
            let (lo, hi) = if ea.0 <= eb.0 { (&ea, &eb) } else { (&eb, &ea) };
            if lo.0 == hi.0 {
                if lo.1 == hi.1 && lo.2 == hi.2 {
                    return Err("the statements agree".into());
                }
            } else {
                let on_chain = |(size, id, _): &(u64, String, Value)| {
                    usize::try_from(size - 1)
                        .ok()
                        .and_then(|i| chain.commit_ids.get(i))
                        .is_some_and(|c| c == id)
                };
                if !on_chain(hi) {
                    return Err("the higher statement is not on the chain read".into());
                }
                if on_chain(lo) {
                    return Err("the lower statement is a prefix of the higher".into());
                }
            }
            Ok(Proven::PeerEquivocation { pg, peer })
        },
        other => Err(format!("unknown evidence kind {other:?}")),
    }
}

/// The `payload.items` of an evidence response. Anything but a 2xx with an
/// items array is an error, never "no evidence".
pub fn evidence_items(status: u16, body: &[u8]) -> Result<Vec<Value>, String> {
    if !(200..300).contains(&status) {
        return Err(format!("evidence read answered {status}"));
    }
    let v: Value =
        serde_json::from_slice(body).map_err(|e| format!("evidence is not json: {e}"))?;
    v["payload"]["items"]
        .as_array()
        .cloned()
        .ok_or_else(|| "evidence has no payload.items array".to_owned())
}
