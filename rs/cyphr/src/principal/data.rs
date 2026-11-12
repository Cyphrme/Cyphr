//! Data-layer action recording (Level 4).

use super::{Principal, PrincipalState};
use crate::action::Action;
use crate::error::{Error, Result};
use crate::state::PrincipalRoot;

impl PrincipalState {
    /// The key that authorizes a data action signed by `tmb` and dated
    /// `now`: the key active at `now` in the principal's key history
    /// (SPEC 6.2, 6.5), not the key set at the tip. A principal with no
    /// genesis commit has no history to authorize from.
    ///
    /// A key of an embedded principal is judged the same way, by that
    /// principal's key history at `now` (SPEC 10.3).
    ///
    /// # Errors
    ///
    /// `GenesisIncomplete` before the genesis commit; `KeyRevoked` for a
    /// key revoked at or before `now`; `EmbeddedErrored` for a key of an
    /// embedded principal in Error; `UnknownKey` otherwise.
    fn action_signer(&self, tmb: &coz::Thumbprint, now: i64) -> Result<&crate::key::Key> {
        if self.pg().is_none() {
            return Err(Error::GenesisIncomplete);
        }
        if let Some(verdict) = self.key_timeline.authorize(tmb, now) {
            return verdict;
        }
        if self.auth.revoked.contains_key(&tmb.to_b64()) {
            return Err(Error::KeyRevoked);
        }
        self.embedded
            .signer_at(tmb, now, |d| {
                self.nonces.holds(crate::nonce::NonceLevel::Kt, d)
            })
            .unwrap_or(Err(Error::UnknownKey))
    }

    /// Record an action in the Data Tree (Level 4+).
    ///
    /// The action enters DT only: DR, and so SR and PR, change only by a
    /// `ds/create` (SPEC 4.8.2), and the action is no part of the chain.
    ///
    /// This is internal-only. External code must use `verify_and_record_action`
    /// which enforces signature verification.
    ///
    /// # Errors
    ///
    /// - `TimestampFuture`: Action timestamp is too far in the future
    /// - as [`Self::action_signer`]
    pub(crate) fn record_action(&mut self, action: Action) -> Result<&PrincipalRoot> {
        self.check_now(action.now)?;
        self.action_signer(&action.signer, action.now)?;

        // Update signer's last_used timestamp
        self.update_last_used(&action.signer, action.now);

        let core = self.core_mut();
        core.included_czds.insert(action.czd.as_bytes().to_vec());
        core.data.actions.push(action);

        Ok(&self.pr)
    }

    /// Verify signature and record an action in one step.
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
    /// - `GenesisIncomplete`, `UnknownKey`, `KeyRevoked`: the signer did not authorize the action
    ///   at its `now` (SPEC 6.5)
    /// - `TimestampFuture`: Action timestamp is too far in the future
    pub(crate) fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> Result<&PrincipalRoot> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        use crate::action::Action;

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

        // [no-transactions-on-deleted]: SPEC §11.4 -- "no transactions or
        // actions are possible on a closed account". Data actions have no
        // same-commit-finalizer exemption analogous to CommitCreate's, so
        // this is an unconditional gate.
        if self.deleted {
            return Err(Error::AlreadyDeleted);
        }

        // SPEC §2.3.2, §11: a frozen principal changes only by being
        // unfrozen, and a data action changes DT.
        if self.frozen {
            return Err(Error::Frozen);
        }

        let signer_key = self.action_signer(&signer_tmb, now)?;

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

        // SPEC §7.6: replaying an applied data action is ignored and
        // produces no state change. Checked only after the czd is proven
        // derived from verified bytes, so it cannot be spoofed.
        if self.included_czds.contains(computed.as_bytes()) {
            return Ok(&self.pr);
        }

        // Construct CozJson for storage
        let raw = coz::CozJson {
            pay: pay_value,
            sig: sig.to_vec(),
        };

        // Construct Action directly from extracted values
        let action = Action::new(typ, signer_tmb, now, czd, signer_key.hash_alg(), raw);

        // Record the action
        self.record_action(action)
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Whether `tmb` was ever a key of this principal: in its key history,
    /// or revoked.
    pub(crate) fn held_key(&self, tmb: &coz::Thumbprint) -> bool {
        self.key_timeline.knows(tmb) || self.auth.revoked.contains_key(&tmb.to_b64())
    }

    /// Take in a naked revoke of `tmb` dated `now` that the caller has
    /// verified (SPEC 6.4): from `now` on, the key authorizes no data
    /// action. It changes no root: a naked revoke does not mutate PR.
    pub fn note_naked_revoke(&mut self, tmb: &coz::Thumbprint, now: i64) {
        self.state.core_mut().key_timeline.revoke(tmb, now);
    }

    /// Verify signature and record an action in one step.
    ///
    /// This is the primary method for processing incoming actions. An
    /// action enters DT only, in memory: nothing reaches the commit log.
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `GenesisIncomplete`, `UnknownKey`, `KeyRevoked`: the signer did not authorize the action
    ///   at its `now` (SPEC 6.5)
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
