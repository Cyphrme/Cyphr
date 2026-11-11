//! The verifier's embedded-principal view of a principal (SPEC be0663f
//! §10.3, §10.7); the rules are in [`crate::embedded`].

use super::Principal;
use crate::embedded::{EmbedReport, TipSource, Tracking};
use crate::error::{Error, Result};
use crate::nonce::NonceLevel;
use crate::state::TaggedDigest;

impl<S: eml::Storage> Principal<S> {
    /// Reveal the KT digest `member` (tagged `ALG:digest`) as an embedded
    /// principal, its PG or a PR it held, tracked by `tracking`. The digest
    /// need not be in KT yet: it authorizes only while it is.
    ///
    /// # Errors
    ///
    /// `MalformedPayload` if `member` is not a tagged digest;
    /// `StateMismatch` if a pinned tip is not a state of `member`.
    pub fn reveal_embedded(&mut self, member: &str, tracking: Tracking) -> Result<()> {
        let id: TaggedDigest = member.parse().map_err(|_| Error::MalformedPayload)?;
        self.state.core_mut().embedded.reveal(id, tracking)
    }

    /// Ask `source` for the tip of every followed embedding in KT, and
    /// report how every KT digest stands. Pinned and opaque digests are
    /// not retrieved. The commits already held are not judged again.
    pub async fn follow_embedded<T: TipSource>(&mut self, source: &mut T) -> Vec<EmbedReport> {
        let kt: Vec<_> = self
            .nonces
            .at_level(NonceLevel::Kt)
            .into_iter()
            .filter_map(|(bytes, alg)| {
                TaggedDigest::new(alg, bytes.to_vec())
                    .ok()
                    .map(|t| (bytes.to_vec(), t))
            })
            .collect();
        self.state.core_mut().embedded.follow(&kt, source).await
    }
}
