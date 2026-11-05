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

/// Verify one served evidence item offline. PROVISIONAL shape, owned by the
/// evidence route: a `kind` (`principal-fork` or `peer-equivocation`), the
/// principal's canonical `pg`, two conflicting signed objects `a` and `b`,
/// the shared `ancestor` for a principal fork, and the culprit's identity
/// `peer` for peer equivocation. `peers` maps a peer identity to its key tmb.
pub fn verify_evidence(
    item: &Value,
    keys: &Keys,
    peers: &BTreeMap<String, String>,
) -> Result<Proven, String> {
    let pg = item["pg"].as_str().ok_or("item has no pg")?.to_owned();
    let (a, b) = (&item["a"], &item["b"]);
    if a.is_null() || b.is_null() {
        return Err("item lacks one of its two signed objects".into());
    }
    if a == b {
        return Err("the two objects are identical, so they do not conflict".into());
    }
    let (va, vb) = (verify(a, keys)?, verify(b, keys)?);
    match item["kind"].as_str() {
        Some("principal-fork") => {
            let ancestor = item
                .get("ancestor")
                .filter(|x| !x.is_null())
                .ok_or("a fork needs its shared ancestor")?;
            verify(ancestor, keys)?;
            if va.pay["pre"].is_null() || va.pay["pre"] != vb.pay["pre"] {
                return Err("the two commits do not share a predecessor".into());
            }
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
            if &va.tmb != want || &vb.tmb != want {
                return Err(format!("objects are not both signed by peer {peer}"));
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
