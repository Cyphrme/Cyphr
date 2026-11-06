//! Offline verification of signed coz objects, independent of any action
//! under test. A statement, a commit or an evidence item is only believed
//! once its signature checks under a key the verifier already holds.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
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

/// The tmb that signed the last `.../commit/create` coz of a `GET /patch`
/// payload, chosen by `typ`, not position, and verified against the keys
/// the chain has introduced up to and including that entry.
pub fn commit_signer_from_patch(patch: &Value) -> Result<String, String> {
    let mut keys = Keys::new();
    let mut signer = None;
    for entry in patch["payload"]["entries"].as_array().ok_or("no entries")? {
        let cozies: Vec<Value> = entry["blobs"]
            .as_array()
            .ok_or("entry has no blobs")?
            .iter()
            .map(|b| {
                let raw = Base64UrlUnpadded::decode_vec(b.as_str().ok_or("blob is not a string")?)
                    .map_err(|e| format!("blob is not base64url: {e}"))?;
                serde_json::from_slice(&raw).map_err(|e| format!("blob is not json: {e}"))
            })
            .collect::<Result<_, String>>()?;
        for c in &cozies {
            if let (Some(k), Some(tmb)) = (c.get("key"), c["key"]["tmb"].as_str()) {
                if let (Some(alg), Some(p)) = (k["alg"].as_str(), k["pub"].as_str()) {
                    keys.insert(tmb.to_owned(), (alg.to_owned(), p.to_owned()));
                }
            }
        }
        for c in &cozies {
            if c["pay"]["typ"]
                .as_str()
                .is_some_and(|t| t.ends_with("/commit/create"))
            {
                signer = Some(verify(c, &keys)?.tmb);
            }
        }
    }
    signer.ok_or_else(|| "no commit/create coz in the patch".to_owned())
}

/// What a served evidence item proves, once verified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proven {
    PrincipalFork { pg: String },
    PeerEquivocation { pg: String, peer: String },
}

/// What the verifier holds of the principal's chain, read from a peer's
/// `GET /patch`: the Principal Root and commit id after each commit. An
/// item is checked against this, never against its own say-so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainView {
    pub prs: Vec<String>,
    pub commit_ids: Vec<String>,
}

impl ChainView {
    /// The chain of a `GET /patch` body (`payload.entries[].{pr, commit_id}`).
    pub fn from_patch(patch: &Value) -> Self {
        let col = |field: &str| -> Vec<String> {
            patch["payload"]["entries"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e[field].as_str().map(str::to_owned))
                .collect()
        };
        Self {
            prs: col("pr"),
            commit_ids: col("commit_id"),
        }
    }
}

/// The coz objects of a served commit (`{blobs: [base64url coz]}`).
fn commit_cozies(commit: &Value) -> Result<Vec<Value>, String> {
    commit["blobs"]
        .as_array()
        .filter(|b| !b.is_empty())
        .ok_or("commit has no blobs")?
        .iter()
        .map(|b| {
            let raw = Base64UrlUnpadded::decode_vec(b.as_str().ok_or("blob is not a string")?)
                .map_err(|e| format!("blob is not base64url: {e}"))?;
            serde_json::from_slice(&raw).map_err(|e| format!("blob is not json: {e}"))
        })
        .collect()
}

/// Verify one served commit of a fork against the keys the principal's
/// chain introduced, and return its raw blobs. Every coz must verify, and
/// the commit must close with a `commit/create` (the typ is matched as an
/// authority-qualified suffix, never a substring).
fn verified_commit(commit: &Value, keys: &Keys) -> Result<Vec<Value>, String> {
    let cozies = commit_cozies(commit)?;
    for c in &cozies {
        verify(c, keys)?;
    }
    let closes = cozies
        .last()
        .and_then(|c| c["pay"]["typ"].as_str())
        .is_some_and(|t| t.ends_with("/cyphr/commit/create"));
    if !closes {
        return Err("a commit must close with a commit/create coz".into());
    }
    Ok(cozies)
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
/// `{blobs}`) must name `requested`; its `height` must lie on the chain and
/// its `pre` be the chain's root after the commit before it (the ancestor);
/// each commit must verify and close with a `commit/create`; the two must
/// differ. The serving peers' own keys are removed from `keys` first, so a
/// peer cannot vouch for a fork it fabricated: only keys the principal's
/// chain introduced count.
///
/// A `peer-equivocation` item (`{pg, peer, a, b}`, statements) must name
/// `requested`, and both statements must be signed by the accused peer's key.
/// At one size they conflict if they differ; at different sizes the lower
/// one is a prefix, and so no evidence, when both sit on `chain`.
pub fn verify_evidence(
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
            let mut principal_keys = keys.clone();
            principal_keys.retain(|tmb, _| !peers.values().any(|p| p == tmb));
            let height = item["height"]
                .as_u64()
                .and_then(|h| usize::try_from(h).ok())
                .ok_or("a fork needs its height")?;
            let ancestor = match height.checked_sub(1) {
                None => None,
                Some(i) => Some(
                    chain
                        .prs
                        .get(i)
                        .ok_or_else(|| format!("height {height} is beyond the chain"))?,
                ),
            };
            if item["pre"].as_str() != ancestor.map(String::as_str) {
                return Err("pre is not the chain's root before the fork".into());
            }
            verified_commit(a, &principal_keys)?;
            verified_commit(b, &principal_keys)?;
            Ok(Proven::PrincipalFork { pg })
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
