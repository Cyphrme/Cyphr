//! Extension certificates: whether an offered head's commit log extends the
//! one held, from a certificate over the Principal Root (SPEC 4.4) and not
//! from the commits themselves.
//!
//! The verifier takes the older log from the principal it holds, whose
//! commits it replayed, and the newer head from the offer. The head is the
//! peer's claim and stays one: [`cyphr::proof::verify_extension`] returns no
//! root and grants no trust, so an `Ok` here only steers what is fetched
//! next. A head becomes believed when the commits it covers replay, and
//! [`confirm_extension`] holds the offer to the replayed log then. Nothing
//! here pins a peer's root.

use cyphr::Principal;
use cyphr::eml::Storage;
use cyphr::proof::{Anchor, Certificate, ProofError, Root};
use serde_json::Value;

/// An offered head's claim to extend a held log: the head, and the
/// certificate that it does.
#[derive(Debug)]
pub struct Extension {
    /// The offered log's root at its last commit: the peer's claim.
    pub head: Root,
    /// The certificate from the held log's size to the head's.
    pub certificate: Certificate,
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
    /// The certificate connects the held log to nothing the offered head
    /// continues: the head does not extend the held log.
    #[error("the offered log does not extend the held one")]
    NotAnExtension,
    /// The certificate and the head are not even consistent with each
    /// other or the held log: no verdict on whether the head extends it.
    #[error("the certificate is refused: {0}")]
    Refused(ProofError),
    /// The held principal has no commit log to judge the offer against.
    #[error("the held principal has no commit log")]
    NothingHeld,
    /// The commits the offer covered replayed to another root than it
    /// stated.
    #[error("the replayed log is not the one the offer stated")]
    Unconfirmed,
}

impl Extension {
    /// A head and the certificate that it extends a held log.
    #[must_use]
    pub fn new(head: Root, certificate: Certificate) -> Self {
        Self { head, certificate }
    }

    /// The head of an answer to `GET /head`.
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Malformed`] if the payload is not a root.
    pub fn head_from_payload(payload: &Value) -> Result<Root, ExtensionFailure> {
        serde_json::from_value(payload.clone())
            .map_err(|e| ExtensionFailure::Malformed(format!("head: {e}")))
    }

    /// The certificate of an answer to `GET /consistency` or
    /// `GET /inclusion`: `{certificate}` and nothing else.
    ///
    /// # Errors
    ///
    /// [`ExtensionFailure::Malformed`] if the payload is not that shape, or
    /// the certificate is refused at parse.
    pub fn certificate_from_payload(payload: &Value) -> Result<Certificate, ExtensionFailure> {
        let bad = |what: String| ExtensionFailure::Malformed(what);
        let object = payload
            .as_object()
            .ok_or_else(|| bad("the answer is not an object".into()))?;
        if object.len() != 1 {
            return Err(bad("the answer holds more than a certificate".into()));
        }
        let certificate = object
            .get("certificate")
            .ok_or_else(|| bad("certificate is missing".into()))?;
        serde_json::from_value(certificate.clone()).map_err(|e| bad(format!("certificate: {e}")))
    }
}

/// Whether `head` extends the log of `from` commits of `held`: the held
/// log from `held` itself, the head from the offer, never from the
/// certificate. A verdict that steers (see the module docs).
///
/// # Errors
///
/// [`ExtensionFailure::NothingHeld`] if `held` has no commit log,
/// [`ExtensionFailure::NotLonger`] if the head is no longer than `from`,
/// [`ExtensionFailure::NotAnExtension`] if the certificate does not connect
/// them.
pub fn verify_extension_at<S: Storage>(
    held: &Principal<S>,
    from: u64,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    if from == 0 || from > held.commit_count() as u64 {
        return Err(ExtensionFailure::NothingHeld);
    }
    if offer.head.size <= from {
        return Err(ExtensionFailure::NotLonger);
    }
    cyphr::proof::verify_extension(
        &Anchor::of_chain(held.state()),
        &offer.certificate,
        from,
        &offer.head,
    )
    .map_err(|e| match e {
        ProofError::NotAnExtension => ExtensionFailure::NotAnExtension,
        other => ExtensionFailure::Refused(other),
    })
}

/// Whether `offer` extends the whole commit log of `held`.
///
/// # Errors
///
/// As [`verify_extension_at`].
pub fn verify_extension<S: Storage>(
    held: &Principal<S>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    verify_extension_at(held, held.commit_count() as u64, offer)
}

/// Whether `held`, after the offered commits replayed, is the log `offer`
/// stated: the offer's head is a claim until then.
///
/// # Errors
///
/// [`ExtensionFailure::Unconfirmed`] if the root differs.
pub fn confirm_extension<S: Storage>(
    held: &Principal<S>,
    offer: &Extension,
) -> Result<(), ExtensionFailure> {
    if held.root_at(offer.head.size).as_ref() == Some(&offer.head) {
        Ok(())
    } else {
        Err(ExtensionFailure::Unconfirmed)
    }
}
