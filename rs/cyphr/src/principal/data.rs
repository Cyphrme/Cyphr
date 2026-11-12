//! Data-layer action recording (Level 4).

use super::{Principal, PrincipalState};
use crate::action::Action;
use crate::error::{Error, Result};
use crate::state::PrincipalRoot;

impl PrincipalState {
    /// Record an action in the Data Tree (Level 4+).
    ///
    /// The action enters DT only: DR, and so SR and PR, change when a
    /// `ds/create` includes it (SPEC 4.8.2).
    ///
    /// This is internal-only. External code must use `verify_and_record_action`
    /// which enforces signature verification.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Action timestamp is older than latest seen
    /// - `TimestampFuture`: Action timestamp is too far in the future
    /// - `UnknownKey`: Signer's key not in current KS
    pub(crate) fn record_action(&mut self, mut action: Action) -> Result<&PrincipalRoot> {
        // Validate timestamp is not in the past (SPEC §14.1)
        if action.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        self.check_now(action.now)?;

        // Verify signer is an active key
        self.active_signer(&action.signer)?;

        // Update signer's last_used timestamp
        self.update_last_used(&action.signer, action.now);

        let core = self.core_mut();
        if action.now > core.latest_timestamp {
            core.latest_timestamp = action.now;
        }
        core.included_czds.insert(action.czd.as_bytes().to_vec());
        action.recorded_after = core.auth.commits.len();
        action.bundle = core.data.bundle_for_next();
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
    /// - `UnknownKey`: Signer not in active key set
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `TimestampPast`: Action timestamp is older than latest seen
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

        // [data-action-no-pre]: Data action cozies MUST NOT contain pre.
        if pay_value.get("pre").is_some() {
            return Err(Error::MalformedPayload);
        }

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

        // Signer must be an ACTIVE key
        let signer_key = self.active_signer(&signer_tmb)?;

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
    /// Record the actions of one accepted bundle: those recorded until
    /// [`Self::close_action_bundle`] are one bundle, which a `ds/create`
    /// includes or leaves out whole (SPEC 4.8.2).
    pub(crate) fn open_action_bundle(&mut self) {
        self.state.core_mut().data.open_bundle();
    }

    /// End the bundle [`Self::open_action_bundle`] opened.
    pub(crate) fn close_action_bundle(&mut self) {
        self.state.core_mut().data.close_bundle();
    }

    /// Verify signature and record an action in one step.
    ///
    /// This is the primary method for processing incoming actions. An
    /// action enters DT only, in memory: nothing reaches the commit log.
    /// Each call records its own bundle (SPEC 4.8.2).
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `TimestampPast`: Action timestamp is older than latest seen
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
