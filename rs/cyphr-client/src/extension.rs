//! Extension proofs: whether an offered tip's commit log extends the one
//! held, from a consistency proof over the Commit Root (SPEC 4.4) and not
//! from the commits themselves.
//!
//! The verifier takes the older size and root from the principal it holds,
//! whose commits it replayed, and the newer size and root from the offer.
//! Nothing in the proof states a size or a root, so a proof cannot vouch
//! for itself. The offer is a claim until the commits it covers replay, and
//! [`Record`](crate::Record) confirms it against the replayed log then.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::eml::{ConsistencyProof, InclusionProof, ProofStep, Storage};
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, MaltHasher, Principal};
use serde_json::{Value, json};

/// Most peaks a frontier holds: one per set bit of a `u64` size.
const MAX_PEAKS: usize = 64;

/// Most levels a peak's path climbs, and (at arity 2) siblings per level.
const MAX_DEPTH: usize = 64;
const MAX_SIBLINGS: usize = 1;

/// An offered tip's claim to extend a held one: the offer's size and
/// Commit Root, and the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The offered log's size, in commits.
    pub size: u64,
    /// The offered log's Commit Root, under the algorithm the proof is over.
    pub cr: TaggedDigest,
    /// The consistency proof from the older log to the offered one.
    pub proof: ConsistencyProof,
}

/// Why an offer is not an extension, or cannot be judged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionFailure {
    /// The payload is not the wire shape, or exceeds what a log can need.
    #[error("extension payload is malformed: {0}")]
    Malformed(String),
    /// The offer is no longer than the held log, so it extends nothing.
    #[error("the offer is not longer than the held log")]
    NotLonger,
    /// The proof does not connect the held root to the offered one.
    #[error("the offered log does not extend the held one")]
    NotAnExtension,
    /// The held principal has no commit log under the offer's algorithm, so
    /// there is nothing to judge the offer against.
    #[error("the held principal has no commit log under {0}")]
    NothingHeld(HashAlg),
    /// The commits the offer covered replayed to another size or root than
    /// it stated.
    #[error("the replayed log is not the one the offer stated")]
    Unconfirmed,
    /// The proof could not be made.
    #[error("no proof: {0}")]
    Unprovable(String),
}

impl Extension {
    /// The proof, from the log of `from` commits to `principal`'s current
    /// log, with the size and root it is over.
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Unprovable`] if `from` is not a size the log
    /// has passed, or the log cannot be read.
    pub async fn of<S: Storage>(
        principal: &Principal<S>,
        from: u64,
    ) -> Result<Self, ExtensionFailure> {
        let unprovable = |e: String| ExtensionFailure::Unprovable(e);
        let alg = principal.hash_alg();
        let alg_id = cyphr::commit_root::hash_alg_to_u64(alg);
        let trees = principal.commit_trees();
        let size = trees
            .tree_size(alg_id)
            .map_err(|e| unprovable(e.to_string()))?;
        let root = trees.root(alg_id).map_err(|e| unprovable(e.to_string()))?;
        let proof = principal
            .consistency_proof(alg, from)
            .await
            .map_err(|e| unprovable(e.to_string()))?;
        let cr = TaggedDigest::new(alg, root).map_err(|e| unprovable(e.to_string()))?;
        Ok(Self { size, cr, proof })
    }

    /// The wire form: `{size, cr, proof}`, every hash base64url.
    #[must_use]
    pub fn to_payload(&self) -> Value {
        let b64 = |b: &[u8]| Base64UrlUnpadded::encode_string(b);
        json!({
            "size": self.size,
            "cr": self.cr.to_string(),
            "proof": {
                "boundary_hash": b64(&self.proof.boundary_hash),
                "peak_path": steps_to_json(&self.proof.peak_path),
                "new_peaks": self.proof.new_peaks.iter().map(|h| b64(h)).collect::<Vec<_>>(),
                "split_index": self.proof.split_index,
            },
        })
    }

    /// Parse the wire form, refusing a shape no honest log produces: a
    /// hash of the wrong width, more peaks or levels than a `u64`-sized log
    /// has, a split outside the peaks.
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Malformed`].
    pub fn from_payload(payload: &Value) -> Result<Self, ExtensionFailure> {
        let bad = |what: &str| ExtensionFailure::Malformed(what.to_owned());
        let size = payload
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("size is not an integer"))?;
        let cr: TaggedDigest = payload
            .get("cr")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("cr is missing"))?
            .parse()
            .map_err(|e: cyphr::Error| ExtensionFailure::Malformed(format!("cr: {e}")))?;
        let width = cr.alg().digest_size();
        let hash = |v: &Value, what: &str| -> Result<Vec<u8>, ExtensionFailure> {
            let s = v.as_str().ok_or_else(|| bad(what))?;
            let bytes = Base64UrlUnpadded::decode_vec(s).map_err(|_| bad(what))?;
            (bytes.len() == width)
                .then_some(bytes)
                .ok_or_else(|| bad(what))
        };
        let list =
            |v: Option<&Value>, what: &str, max: usize| -> Result<Vec<Value>, ExtensionFailure> {
                let items = v.and_then(Value::as_array).ok_or_else(|| bad(what))?;
                (items.len() <= max)
                    .then(|| items.clone())
                    .ok_or_else(|| bad(what))
            };
        let p = payload
            .get("proof")
            .ok_or_else(|| bad("proof is missing"))?;
        let boundary_hash = hash(
            p.get("boundary_hash").unwrap_or(&Value::Null),
            "proof.boundary_hash",
        )?;
        let new_peaks = list(p.get("new_peaks"), "proof.new_peaks", MAX_PEAKS)?
            .iter()
            .map(|h| hash(h, "proof.new_peaks"))
            .collect::<Result<Vec<_>, _>>()?;
        let peak_path = parse_steps(p.get("peak_path"), "proof.peak_path", width)?;
        let split_index = p
            .get("split_index")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&i| i < new_peaks.len())
            .ok_or_else(|| bad("proof.split_index"))?;
        Ok(Self {
            size,
            cr,
            proof: ConsistencyProof {
                boundary_hash,
                peak_path,
                new_peaks,
                split_index,
            },
        })
    }
}

/// Whether `offer` extends the commit log of `held`: the held size and
/// root from `held` itself, the offered size and root from `offer`, never
/// from `offer.proof`.
///
/// # Errors
///
/// [`ExtensionFailure::NothingHeld`] if `held` has no commit log under the
/// offer's algorithm, [`ExtensionFailure::NotLonger`] if the offer is not
/// longer than it, [`ExtensionFailure::NotAnExtension`] if the proof does
/// not connect the two roots.
pub fn verify_extension<S: Storage>(
    held: &Principal<S>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    let alg = offer.cr.alg();
    let alg_id = cyphr::commit_root::hash_alg_to_u64(alg);
    let trees = held.commit_trees();
    let (Ok(old_size), Ok(old_root)) = (trees.tree_size(alg_id), trees.root(alg_id)) else {
        return Err(ExtensionFailure::NothingHeld(alg));
    };
    if old_size == 0 {
        return Err(ExtensionFailure::NothingHeld(alg));
    }
    if offer.size <= old_size {
        return Err(ExtensionFailure::NotLonger);
    }
    if cyphr::verify_consistency(
        &MaltHasher::new(alg),
        old_size,
        offer.size,
        &offer.proof,
        &old_root,
        offer.cr.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(ExtensionFailure::NotAnExtension)
    }
}

/// Whether `held`, after the offered commits replayed, is the log `offer`
/// stated: the offer's size and root are claims until then.
///
/// # Errors
///
/// [`ExtensionFailure::Unconfirmed`] if the size or root differ.
pub fn confirm_extension<S: Storage>(
    held: &Principal<S>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    let alg_id = cyphr::commit_root::hash_alg_to_u64(offer.cr.alg());
    let trees = held.commit_trees();
    match (trees.tree_size(alg_id), trees.root(alg_id)) {
        (Ok(size), Ok(root)) if size == offer.size && root == offer.cr.as_bytes() => Ok(()),
        _ => Err(ExtensionFailure::Unconfirmed),
    }
}

/// An offered log's claim to hold a given commit at a given position: the
/// leaf, and the inclusion proof of it under the offered Commit Root.
///
/// Used to locate where an offered log leaves the held one. Any statement
/// of it is a claim until the fork it points at is proved by signatures
/// ([`crate::evidence`]); the proof only keeps the peer to one log while it
/// is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    /// The position asked about.
    pub index: u64,
    /// The offered log's size, in commits.
    pub size: u64,
    /// The offered log's Commit Root.
    pub cr: TaggedDigest,
    /// The commit id (its transaction root) the log holds at `index`.
    pub leaf: TaggedDigest,
    /// The inclusion proof of `leaf` at `index`.
    pub proof: InclusionProof,
}

impl Inclusion {
    /// The proof that `principal`'s commit at `index` is in its current log.
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Unprovable`] if `index` is past the log.
    pub async fn of<S: Storage>(
        principal: &Principal<S>,
        index: u64,
    ) -> Result<Self, ExtensionFailure> {
        let unprovable = |e: String| ExtensionFailure::Unprovable(e);
        let alg = principal.hash_alg();
        let alg_id = cyphr::commit_root::hash_alg_to_u64(alg);
        let trees = principal.commit_trees();
        let size = trees
            .tree_size(alg_id)
            .map_err(|e| unprovable(e.to_string()))?;
        let root = trees.root(alg_id).map_err(|e| unprovable(e.to_string()))?;
        let commit = usize::try_from(index)
            .ok()
            .and_then(|i| principal.commit_at(i))
            .ok_or_else(|| unprovable("no commit at that position".into()))?;
        let leaf = commit
            .tr()
            .0
            .get(alg)
            .ok_or_else(|| unprovable("commit has no digest under the log's algorithm".into()))?
            .to_vec();
        let proof = principal
            .inclusion_proof(alg, index)
            .await
            .map_err(|e| unprovable(e.to_string()))?;
        Ok(Self {
            index,
            size,
            cr: TaggedDigest::new(alg, root).map_err(|e| unprovable(e.to_string()))?,
            leaf: TaggedDigest::new(alg, leaf).map_err(|e| unprovable(e.to_string()))?,
            proof,
        })
    }

    /// The wire form: `{index, size, cr, leaf, proof:{path}}`.
    #[must_use]
    pub fn to_payload(&self) -> Value {
        json!({
            "index": self.index,
            "size": self.size,
            "cr": self.cr.to_string(),
            "leaf": self.leaf.to_string(),
            "proof": { "path": steps_to_json(&self.proof.path) },
        })
    }

    /// Parse the wire form under the same shape limits as [`Extension`].
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Malformed`].
    pub fn from_payload(payload: &Value) -> Result<Self, ExtensionFailure> {
        let bad = |what: &str| ExtensionFailure::Malformed(what.to_owned());
        let number = |field: &str| {
            payload
                .get(field)
                .and_then(Value::as_u64)
                .ok_or_else(|| bad(field))
        };
        let digest = |field: &str| -> Result<TaggedDigest, ExtensionFailure> {
            payload
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| bad(field))?
                .parse()
                .map_err(|e: cyphr::Error| ExtensionFailure::Malformed(format!("{field}: {e}")))
        };
        let (cr, leaf) = (digest("cr")?, digest("leaf")?);
        if cr.alg() != leaf.alg() {
            return Err(bad("leaf and cr are under different algorithms"));
        }
        let path = parse_steps(
            payload.get("proof").and_then(|p| p.get("path")),
            "proof.path",
            cr.alg().digest_size(),
        )?;
        Ok(Self {
            index: number("index")?,
            size: number("size")?,
            cr,
            leaf,
            proof: InclusionProof { path },
        })
    }

    /// Whether the proof puts `leaf` at `index` under `cr` for a log of
    /// `size`, as this statement itself says. The caller holds `size` and
    /// `cr` to the claim it is asking about.
    #[must_use]
    pub fn holds(&self) -> bool {
        let alg = self.cr.alg();
        cyphr::verify_inclusion(
            &MaltHasher::new(alg),
            self.leaf.as_bytes(),
            self.index,
            self.size,
            &self.proof,
            self.cr.as_bytes(),
        )
    }
}

fn steps_to_json(steps: &[ProofStep]) -> Vec<Value> {
    steps
        .iter()
        .map(|s| {
            json!({
                "position": s.position,
                "siblings": s.siblings.iter().map(|h| Base64UrlUnpadded::encode_string(h)).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn parse_steps(
    value: Option<&Value>,
    what: &str,
    width: usize,
) -> Result<Vec<ProofStep>, ExtensionFailure> {
    let bad = |what: &str| ExtensionFailure::Malformed(what.to_owned());
    let steps = value
        .and_then(Value::as_array)
        .filter(|a| a.len() <= MAX_DEPTH)
        .ok_or_else(|| bad(what))?;
    steps
        .iter()
        .map(|step| {
            let position = step
                .get("position")
                .and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| bad(what))?;
            let siblings = step
                .get("siblings")
                .and_then(Value::as_array)
                .filter(|a| a.len() <= MAX_SIBLINGS)
                .ok_or_else(|| bad(what))?
                .iter()
                .map(|h| {
                    let bytes = h
                        .as_str()
                        .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                        .filter(|b| b.len() == width);
                    bytes.ok_or_else(|| bad(what))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ProofStep { siblings, position })
        })
        .collect()
}
