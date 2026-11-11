//! Nonces (SPEC be0663f §10.1, §10.2).
//!
//! A nonce is an opaque, high-entropy digest inserted at a tree level by a
//! `*/nonce/create` and removed by the matching `*/nonce/delete`. The
//! protocol reads no meaning from it: it is indistinguishable from a key
//! thumbprint and only changes the digests of the level it sits at.
//!
//! The `typ` names the level (§10.1); the `id` is the nonce, either bare
//! (taken to be under the signing key's own hash algorithm) or labelled
//! `<alg>:<b64ut>` (§10.2). Either way its byte length must equal the output
//! size of the algorithm it is under, the only strength check possible.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::{Error, Result};
use crate::state::{HashAlg, TaggedDigest};

/// The tree level a nonce is inserted at (SPEC §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NonceLevel {
    /// The Principal Root (`cyphr/nonce/...`).
    Pr,
    /// The root of AT, an input of the Auth Root (`cyphr/AT/nonce/...`).
    At,
    /// The root of KT, an input of the Key Root (`cyphr/AT/KT/nonce/...`).
    Kt,
}

impl NonceLevel {
    /// The protocol path a `typ` carries for this level, without authority.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Pr => "cyphr",
            Self::At => "cyphr/AT",
            Self::Kt => "cyphr/AT/KT",
        }
    }
}

/// A validated nonce: digest bytes whose length is the output size of the
/// algorithm it is under. Identity is the bytes alone, so one value named
/// under two labels is the same nonce; the algorithm is kept so a tree of
/// another algorithm converts it from the one it is in.
#[derive(Debug, Clone)]
pub struct Nonce {
    bytes: Vec<u8>,
    alg: HashAlg,
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Nonce {}

impl Nonce {
    /// Parse a coz `id` signed by a key whose hash algorithm is
    /// `signer_alg`.
    ///
    /// A labelled `id` (`SHA-256:<b64ut>`) names its own algorithm, which
    /// need not be the signer's; a bare `id` is under `signer_alg`.
    ///
    /// # Errors
    ///
    /// `MalformedPayload` if the label is unknown, the value is not base64url,
    /// or its length differs from the algorithm's output size. This matches
    /// how every other digest-valued `id` is refused.
    pub fn parse(id: &str, signer_alg: HashAlg) -> Result<Self> {
        if id.contains(':') {
            let tagged: TaggedDigest = id.parse().map_err(|_| Error::MalformedPayload)?;
            return Ok(Self {
                bytes: tagged.as_bytes().to_vec(),
                alg: tagged.alg(),
            });
        }
        let bytes = Base64UrlUnpadded::decode_vec(id).map_err(|_| Error::MalformedPayload)?;
        if bytes.len() != TaggedDigest::expected_len(signer_alg) {
            return Err(Error::MalformedPayload);
        }
        Ok(Self {
            bytes,
            alg: signer_alg,
        })
    }

    /// The nonce's digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The hash algorithm the nonce is under.
    #[must_use]
    pub fn alg(&self) -> HashAlg {
        self.alg
    }
}

/// The nonces a principal currently holds, per level, each with the
/// algorithm it is under. Ordered by bytes, so the derived roots do not
/// depend on creation order.
#[derive(Debug, Clone, Default)]
pub(crate) struct NonceSets {
    pr: BTreeMap<Vec<u8>, HashAlg>,
    at: BTreeMap<Vec<u8>, HashAlg>,
    kt: BTreeMap<Vec<u8>, HashAlg>,
}

impl NonceSets {
    fn level_mut(&mut self, level: NonceLevel) -> &mut BTreeMap<Vec<u8>, HashAlg> {
        match level {
            NonceLevel::Pr => &mut self.pr,
            NonceLevel::At => &mut self.at,
            NonceLevel::Kt => &mut self.kt,
        }
    }

    /// Nonces at `level` with their algorithms, in ascending byte order.
    pub(crate) fn at_level(&self, level: NonceLevel) -> Vec<(&[u8], HashAlg)> {
        let set = match level {
            NonceLevel::Pr => &self.pr,
            NonceLevel::At => &self.at,
            NonceLevel::Kt => &self.kt,
        };
        set.iter().map(|(n, &alg)| (n.as_slice(), alg)).collect()
    }

    /// Whether `level` holds the digest `bytes`.
    pub(crate) fn holds(&self, level: NonceLevel, bytes: &[u8]) -> bool {
        match level {
            NonceLevel::Pr => &self.pr,
            NonceLevel::At => &self.at,
            NonceLevel::Kt => &self.kt,
        }
        .contains_key(bytes)
    }

    /// Insert `nonce` at `level`.
    ///
    /// # Errors
    ///
    /// `DuplicateNonce` if the level already holds it (SPEC §7.6).
    pub(crate) fn insert(&mut self, level: NonceLevel, nonce: &Nonce) -> Result<()> {
        match self.level_mut(level).entry(nonce.bytes.clone()) {
            std::collections::btree_map::Entry::Occupied(_) => Err(Error::DuplicateNonce),
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(nonce.alg);
                Ok(())
            },
        }
    }

    /// Remove `nonce` from `level`.
    ///
    /// # Errors
    ///
    /// `UnknownNonce` if the level does not hold it.
    pub(crate) fn remove(&mut self, level: NonceLevel, nonce: &Nonce) -> Result<()> {
        if self.level_mut(level).remove(&nonce.bytes).is_some() {
            Ok(())
        } else {
            Err(Error::UnknownNonce)
        }
    }
}

// A unit test is allowed here because the signed wire scenarios
// (`tests/nonce.rs`, `tests/spec_conformance.rs`) always sign a labelled
// `id`; the bare form and the duplicate/absent refusals are reached cheaply
// only below the wire.
#[cfg(test)]
mod tests {
    use super::*;

    const B64_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// Backs SPEC 10.2 ("labelled with an algorithm or multihash") and the
    /// width rule for the bare form: a bare `id` is under the signer's
    /// algorithm, a label may name another one, and every width mismatch is
    /// refused. Turns red if the bare form skips the length check, if the
    /// label is ignored, or if a label of another algorithm is rejected.
    #[test]
    fn parse_bare_labelled_and_widths() {
        let bare = Nonce::parse(B64_32, HashAlg::Sha256).unwrap();
        let labelled = Nonce::parse(&format!("SHA-256:{B64_32}"), HashAlg::Sha384).unwrap();
        assert_eq!(bare, labelled, "one value is one nonce whatever its label");
        assert_eq!(bare.as_bytes().len(), 32);

        assert!(
            Nonce::parse(B64_32, HashAlg::Sha384).is_err(),
            "bare 32 under SHA-384"
        );
        assert!(Nonce::parse(&format!("SHA-384:{B64_32}"), HashAlg::Sha256).is_err());
        let wide = format!("A{B64_32}"); // 33 bytes: one too many
        assert!(
            Nonce::parse(&wide, HashAlg::Sha256).is_err(),
            "bare 33 under SHA-256"
        );
        assert!(Nonce::parse("SHA-256:", HashAlg::Sha256).is_err());
        assert!(Nonce::parse("MD5:AAAA", HashAlg::Sha256).is_err());
        assert!(Nonce::parse("!!!", HashAlg::Sha256).is_err());
    }

    /// Backs SPEC 7.6 / 10.1: the same nonce twice at one level is a typed
    /// duplicate, the same nonce at another level is a different entry, and
    /// deleting an absent nonce is a typed refusal that leaves the set
    /// unchanged. Turns red if a repeat is silently accepted, if levels
    /// share a set, or if an absent delete succeeds.
    #[test]
    fn duplicate_and_absent_are_typed_and_levels_are_independent() {
        let n = Nonce::parse(B64_32, HashAlg::Sha256).unwrap();
        let mut sets = NonceSets::default();
        sets.insert(NonceLevel::Kt, &n).unwrap();
        assert!(matches!(
            sets.insert(NonceLevel::Kt, &n),
            Err(Error::DuplicateNonce)
        ));
        sets.insert(NonceLevel::At, &n).unwrap();
        assert!(matches!(
            sets.remove(NonceLevel::Pr, &n),
            Err(Error::UnknownNonce)
        ));
        sets.remove(NonceLevel::Kt, &n).unwrap();
        assert!(sets.at_level(NonceLevel::Kt).is_empty());
        assert_eq!(
            sets.at_level(NonceLevel::At),
            vec![(n.as_bytes(), HashAlg::Sha256)]
        );
    }
}
