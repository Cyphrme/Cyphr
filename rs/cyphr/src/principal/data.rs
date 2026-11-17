//! Data-layer action recording (Level 4).

use super::{Principal, PrincipalState};
use crate::action::Action;
use crate::error::{Error, Result};
use crate::state::PrincipalRoot;

/// How an action reached this principal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// A new submission: refused unless its signer authorizes it now.
    Submitted,
    /// History already admitted elsewhere (a store, a peer, an export): the
    /// signature is checked, and whether the action counts is left to
    /// the view ([`PrincipalState::actions`]).
    Held,
}

impl PrincipalState {
    /// Whether the action of `tmb` dated `now` counts: the key that
    /// authorizes it, or why none does. This is the one judgment of a data
    /// action, for admission and for every read of DT alike: the signer's key
    /// active at `now` in the principal's key history (SPEC 6.2, 6.5), the
    /// principal not frozen (SPEC 14.9) or deleted (SPEC 11.4) at `now`, and
    /// the key not cut off by a naked revoke (SPEC 6.4). A commit dated
    /// before `now` can change the answer, in either direction, so it is
    /// never stored.
    ///
    /// A naked revoke gates admission only: it cuts off what is submitted
    /// after it was noted and re-judges nothing already held (SPEC 14.12;
    /// the spec author on #203, "Retrospection isn't supported"). So what DT
    /// shows ([`Arrival::Held`]) is a function of the commits and the held
    /// actions alone.
    ///
    /// Pending the spec author's ruling on the same-second tie (forge #214),
    /// an action dated exactly at a removal is judged after it.
    ///
    /// A key of an embedded principal is judged the same way, by that
    /// principal's key history at `now` (SPEC 10.3). A principal with no
    /// genesis commit has no history to authorize from.
    ///
    /// # Errors
    ///
    /// `GenesisIncomplete` before the genesis commit; `AlreadyDeleted` or
    /// `Frozen` when the principal was not taking actions at `now`;
    /// `KeyRevoked` for a key revoked at or before `now`; `EmbeddedErrored`
    /// for a key of an embedded principal in Error; `UnknownKey` otherwise.
    pub(super) fn judge(
        &self,
        tmb: &coz::Thumbprint,
        now: i64,
        arrival: Arrival,
    ) -> Result<&crate::key::Key> {
        if self.pg().is_none() {
            return Err(Error::GenesisIncomplete);
        }
        self.key_timeline.open_at(now)?;
        let verdict = match arrival {
            Arrival::Submitted => self.key_timeline.authorize(tmb, now),
            Arrival::Held => self.key_timeline.authorize_by_commits(tmb, now),
        };
        if let Some(verdict) = verdict {
            return verdict;
        }
        if self.auth.revoked.contains_key(&tmb.to_b64()) {
            return Err(Error::KeyRevoked);
        }
        self.embedded_signer(tmb, now)
    }

    /// The key of an embedded principal that signs for `tmb` at `now`.
    fn embedded_signer(&self, tmb: &coz::Thumbprint, now: i64) -> Result<&crate::key::Key> {
        self.embedded
            .signer_at(tmb, now, |d| {
                self.nonces.holds(crate::nonce::NonceLevel::Kt, d)
            })
            .unwrap_or(Err(Error::UnknownKey))
    }

    /// The key whose signature a held action of `tmb` is checked against:
    /// any key this principal has held under that thumbprint. Whether the
    /// action counts is [`Self::judge`]'s, at read.
    fn held_signer(&self, tmb: &coz::Thumbprint, now: i64) -> Result<&crate::key::Key> {
        if self.pg().is_none() {
            return Err(Error::GenesisIncomplete);
        }
        if let Some(key) = self.key_timeline.key_of(tmb) {
            return Ok(key);
        }
        if let Some(key) = self.auth.revoked.get(&tmb.to_b64()) {
            return Ok(key);
        }
        self.embedded_signer(tmb, now)
    }

    /// Hold `action`: the one insertion into DT, for a submission and for
    /// held history alike. Idempotent (SPEC 7.6), and commutative with
    /// every other insertion and with every commit.
    pub(crate) fn insert_action(&mut self, action: Action) {
        let tmb = action.signer.to_b64();
        let core = self.core_mut();
        core.included_czds.insert(action.czd.as_bytes().to_vec());
        let latest = core
            .data
            .last_signed
            .entry(tmb.clone())
            .or_insert(action.now);
        *latest = (*latest).max(action.now);
        for key in core
            .auth
            .keys
            .get_mut(&tmb)
            .into_iter()
            .chain(core.auth.revoked.get_mut(&tmb))
        {
            key.set_last_used(action.now);
        }
        core.data
            .actions
            .insert((action.now, action.czd.as_bytes().to_vec()), action);
    }

    /// Record an action in the Data Tree (Level 4+), judged as a new
    /// submission.
    ///
    /// The action enters DT only: DR, and so SR and PR, change only by a
    /// `ds/create` (SPEC 4.8.2), and the action is no part of the chain.
    ///
    /// For unit tests that drive the state's transitions with a prepared
    /// action; every other path goes through `verify_and_record_action`,
    /// which verifies the signature.
    ///
    /// # Errors
    ///
    /// - `TimestampFuture`: Action timestamp is too far in the future
    /// - as [`Self::judge`]
    #[cfg(test)]
    pub(crate) fn record_action(&mut self, action: Action) -> Result<&PrincipalRoot> {
        self.check_now(action.now)?;
        self.judge(&action.signer, action.now, Arrival::Submitted)?;
        self.insert_action(action);
        Ok(&self.pr)
    }

    /// Verify signature and record an action in one step, as a new
    /// submission.
    ///
    /// This is the primary method for processing incoming actions.
    /// It verifies the signature, parses the action, and records it.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this action
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `GenesisIncomplete`, `UnknownKey`, `KeyRevoked`, `AlreadyDeleted`, `Frozen`: the signer
    ///   did not authorize the action at its `now` (SPEC 6.5)
    /// - `TimestampFuture`: Action timestamp is too far in the future
    pub(crate) fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> Result<&PrincipalRoot> {
        if let Some(action) = self.prepare_action(pay_json, sig, czd, Arrival::Submitted)? {
            self.insert_action(action);
        }
        Ok(&self.pr)
    }

    /// The action `pay_json` and `sig` carry, verified and ready to insert
    /// ([`Self::insert_action`]), or `None` if this principal already holds
    /// it (SPEC 7.6). Nothing is changed, so a bundle of actions can be
    /// prepared whole before any of it is held.
    ///
    /// # Errors
    ///
    /// As [`Self::verify_and_record_action`], the authorization of a
    /// [`Arrival::Held`] action excepted.
    pub(crate) fn prepare_action(
        &self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        arrival: Arrival,
    ) -> Result<Option<Action>> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        // Parse as Value and extract only what we need (avoids requiring all coz::Pay fields)
        let pay_value: serde_json::Value =
            serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;

        // Extract tmb for signer lookup
        let tmb_str = pay_value["tmb"].as_str().ok_or(Error::MalformedPayload)?;
        let tmb_bytes =
            Base64UrlUnpadded::decode_vec(tmb_str).map_err(|_| Error::MalformedPayload)?;
        let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

        // Extract typ and now for Action construction
        let typ = pay_value["typ"]
            .as_str()
            .ok_or(Error::MalformedPayload)?
            .to_string();
        let now = pay_value["now"].as_i64().ok_or(Error::MalformedPayload)?;

        // A transaction typ is applied through a commit. Recording it here
        // would put its czd in `included_czds`, and the real transaction
        // would then be refused as COZ_REUSE.
        if crate::parsed_coz::typ::is_transaction(&typ) {
            return Err(Error::MalformedPayload);
        }
        self.check_now(now)?;

        // SPEC §7.6: replaying an applied data action is ignored. Decided
        // before the signer is resolved, since a commit dated the same
        // second may have retired that signer (the key timeline judges a
        // signature dated at a removal as after it; forge #213), and from
        // the action's own bytes, never
        // the caller's `czd`: a match means these are the held bytes.
        if let Some(own) = pay_value["alg"]
            .as_str()
            .and_then(|alg| crate::parsed_coz::compute_czd(pay_json, sig, alg))
            && self.included_czds.contains(own.as_bytes())
        {
            return Ok(None);
        }

        let signer_key = match arrival {
            Arrival::Submitted => self.judge(&signer_tmb, now, Arrival::Submitted)?,
            Arrival::Held => self.held_signer(&signer_tmb, now)?,
        };

        // The signed pay must name the key that actually verifies it.
        // An absent `alg` is malformed (SPEC 2.3.1), as `verify_coz` rules.
        let alg = pay_value["alg"].as_str().ok_or(Error::MalformedPayload)?;
        if alg != signer_key.alg() {
            return Err(Error::AlgMismatch);
        }

        // Verify signature
        let valid = coz::verify_json(pay_json, sig, signer_key.alg(), signer_key.pub_key())
            .unwrap_or(false);
        if !valid {
            return Err(Error::InvalidSignature);
        }

        // The czd identifies the action; it is derived from the signed
        // bytes, never trusted from the caller.
        let computed = crate::parsed_coz::compute_czd(pay_json, sig, signer_key.alg())
            .ok_or_else(|| Error::UnsupportedAlgorithm(signer_key.alg().to_owned()))?;
        if computed.as_bytes() != czd.as_bytes() {
            return Err(Error::CzdMismatch);
        }

        // Construct CozJson for storage
        let raw = coz::CozJson {
            pay: pay_value,
            sig: sig.to_vec(),
        };
        Ok(Some(Action::new(
            typ,
            signer_tmb,
            now,
            czd,
            signer_key.hash_alg(),
            raw,
        )))
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Hold actions [`PrincipalState::prepare_action`] prepared.
    pub(crate) fn hold_actions(&mut self, actions: Vec<Action>) {
        for action in actions {
            self.state.insert_action(action);
        }
    }

    /// Whether `tmb` was ever a key of this principal: in its key history,
    /// or revoked.
    pub fn held_key(&self, tmb: &coz::Thumbprint) -> bool {
        self.key_timeline.knows(tmb) || self.auth.revoked.contains_key(&tmb.to_b64())
    }

    /// Whether this principal has included the coz with digest `czd`, a data
    /// action it holds or a transaction it applied (SPEC 7.6).
    pub fn has_included(&self, czd: &[u8]) -> bool {
        self.included_czds.contains(czd)
    }

    /// Take in a naked revoke of `tmb` that the caller has verified (SPEC
    /// 6.4), cutting the key off at `cutoff`: from then on, the key
    /// authorizes no data action. The caller chooses the cutoff; a witness
    /// passes its own receipt time of the revoke, not the revoke's `now` or
    /// `rvk` (the spec author on #203). It changes no root: a naked revoke
    /// does not mutate PR.
    pub fn note_naked_revoke(&mut self, tmb: &coz::Thumbprint, cutoff: i64) {
        self.state.core_mut().key_timeline.revoke(tmb, cutoff);
    }

    /// Verify signature and record an action in one step.
    ///
    /// This is the primary method for processing incoming actions. An
    /// action enters DT only, in memory: nothing reaches the commit log.
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `GenesisIncomplete`, `UnknownKey`, `KeyRevoked`, `AlreadyDeleted`, `Frozen`: the signer
    ///   did not authorize the action at its `now` (SPEC 6.5)
    /// - `TimestampFuture`: Action timestamp is too far in the future
    pub fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> Result<&PrincipalRoot> {
        self.state.verify_and_record_action(pay_json, sig, czd)
    }
}
