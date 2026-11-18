//! Extension proofs: whether an offered tip's commit log extends the one
//! held, from the proof of [`cyphr::proof`] over the Commit Root (SPEC 4.4)
//! and not from the commits themselves.
//!
//! The verifier takes the older log from the principal it holds, whose
//! commits it replayed, and the newer head from the offer. The offer is a
//! claim in one hash family: it becomes trusted only by
//! [`cyphr::proof::verify_extension`], which checks it against the held log
//! through every algorithm rotation between the two, and nothing in the
//! proof states a size or a root, so a proof cannot vouch for itself. The
//! offer's size and root are held to the replayed log by
//! [`confirm_extension`] once the commits they cover replay.

use cyphr::eml::Storage;
use cyphr::proof::legacy::{AnyFamilyRoot, Claimed, ExtensionProof, FullCr, Rooted, Trusted};
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, Principal};
use serde_json::{Value, json};

/// An offered tip's claim to extend a held one: the offer's size and
/// head in one family, and the proof.
#[derive(Debug, Clone)]
pub struct Extension {
    /// The offered log's size, in commits.
    pub size: u64,
    /// The offered log's Commit Root in the family the proof starts in.
    pub cr: TaggedDigest,
    /// The proof from the older log to the offered one.
    pub proof: ExtensionProof,
}

/// Why an offer is not an extension, or cannot be judged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionFailure {
    /// The payload is not the wire shape.
    #[error("extension payload is malformed: {0}")]
    Malformed(String),
    /// The offer is no longer than the held log, so it extends nothing.
    #[error("the offer is not longer than the held log")]
    NotLonger,
    /// The proof does not connect the held log to the offered head.
    #[error("the offered log does not extend the held one")]
    NotAnExtension,
    /// The held principal has no commit log to judge the offer against.
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
    /// log, with the size and head it is over.
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
        let head = principal
            .legacy_head_root()
            .ok_or_else(|| unprovable("the log has no commit root".into()))?;
        let proof = principal
            .legacy_prove_extension(from)
            .await
            .map_err(|e| unprovable(e.to_string()))?;
        let cr = TaggedDigest::new(head.alg(), head.bytes().to_vec())
            .map_err(|e| unprovable(e.to_string()))?;
        Ok(Self {
            size: head.size(),
            cr,
            proof,
        })
    }

    /// The wire form: `{size, cr, proof}`.
    #[must_use]
    pub fn to_payload(&self) -> Value {
        json!({
            "size": self.size,
            "cr": self.cr.to_string(),
            "proof": self.proof,
        })
    }

    /// Parse the wire form.
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
        let proof = ExtensionProof::from_payload(
            payload
                .get("proof")
                .ok_or_else(|| bad("proof is missing"))?,
        )
        .map_err(|e| ExtensionFailure::Malformed(format!("proof: {e}")))?;
        Ok(Self { size, cr, proof })
    }

    /// Whether this offer's head is `other`'s: the same size and root.
    #[must_use]
    pub fn same_head(&self, other: &Self) -> bool {
        self.size == other.size && self.cr == other.cr
    }
}

/// Whether `offer` extends the log whose Commit Root `old` is, trusted
/// as the holder's own.
///
/// # Errors
///
/// [`ExtensionFailure::NotLonger`] if the offer is no longer than `old`,
/// [`ExtensionFailure::NotAnExtension`] if the proof does not connect them,
/// [`ExtensionFailure::Malformed`] for a head of the wrong width.
pub fn verify_extension_from(
    old: &Rooted<Trusted, FullCr>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    if offer.size <= old.get().size {
        return Err(ExtensionFailure::NotLonger);
    }
    let head = AnyFamilyRoot::new(offer.cr.alg(), offer.size, offer.cr.as_bytes())
        .map_err(|e| ExtensionFailure::Malformed(format!("cr: {e}")))?;
    cyphr::proof::legacy::verify_extension(
        old,
        Rooted::<Claimed, AnyFamilyRoot>::claim(head),
        &offer.proof,
    )
    .map(|_| ())
    .map_err(|_| ExtensionFailure::NotAnExtension)
}

/// Whether `offer` extends the commit log of `held`: the held log from
/// `held` itself, the offered head from `offer`, never from `offer.proof`.
///
/// # Errors
///
/// [`ExtensionFailure::NothingHeld`] if `held` has no commit log,
/// otherwise as [`verify_extension_from`].
pub fn verify_extension<S: Storage>(
    held: &Principal<S>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    let old = Rooted::<Trusted, FullCr>::of_principal(held)
        .ok_or(ExtensionFailure::NothingHeld(offer.cr.alg()))?;
    verify_extension_from(&old, offer)
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
    // The size is the chain's own count: a log reopened from a frontier
    // ([`Principal::detach`]) holds no leaves and does not count them.
    match trees.root(alg_id) {
        Ok(root) if held.commit_count() as u64 == offer.size && root == offer.cr.as_bytes() => {
            Ok(())
        },
        _ => Err(ExtensionFailure::Unconfirmed),
    }
}
