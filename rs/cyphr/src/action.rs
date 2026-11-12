//! Action types for Data State (Level 4+).
//!
//! Per SPEC §4.3, actions are signed Coz messages representing user actions.
//! They are recorded in the Data State (DS) for Authenticated Atomic Actions (AAA).

use coz::{Czd, Thumbprint};

use crate::state::HashAlg;

/// A verified action (Level 4+).
///
/// Actions are arbitrary signed Coz messages that represent user actions.
/// Unlike cozies which mutate Auth State, actions are recorded in
/// Data State and can represent any application-specific operation.
///
/// This struct can only be created through verification. Fields are
/// crate-internal to prevent external direct construction.
#[derive(Debug, Clone)]
pub struct Action {
    /// Action type from `typ` field (e.g., "cyphr.me/comment/create").
    pub(crate) typ: String,
    /// Signer's thumbprint.
    pub(crate) signer: Thumbprint,
    /// Action timestamp.
    pub(crate) now: i64,
    /// Coz digest (unique identifier).
    pub(crate) czd: Czd,
    /// The hash algorithm `czd` is in: the signing key's.
    pub(crate) hash_alg: HashAlg,
    /// Raw Coz message: the signed payload (including application-specific
    /// fields) and signature, for storage/export.
    pub(crate) raw: coz::CozJson,
    /// How many commits the principal held when it recorded the action.
    pub(crate) recorded_after: usize,
    /// The action bundle it was recorded in: a `ds/create` includes or
    /// leaves out whole bundles (SPEC 4.8.2).
    pub(crate) bundle: usize,
    /// Whether a `ds/create` has included it yet.
    pub(crate) inclusion: Inclusion,
}

/// Where a recorded action stands in DR (SPEC 4.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inclusion {
    /// Recorded since the last `ds/create`: the next one may include it.
    Pending,
    /// A `ds/create` included it in DR.
    Included,
    /// A `ds/create` was signed while it was pending and left it out: it
    /// is not part of this chain's DR, and never becomes part of it.
    NotIncluded,
}

impl Action {
    /// Create an action from already-verified, extracted values (internal).
    ///
    /// Used when we extract fields from raw JSON rather than parsing into coz::Pay.
    /// The raw CozJson preserves the original message for storage/export and
    /// is the source of [`Action::get_field`] and [`Action::msg`].
    pub(crate) fn new(
        typ: String,
        signer: Thumbprint,
        now: i64,
        czd: Czd,
        hash_alg: HashAlg,
        raw: coz::CozJson,
    ) -> Self {
        Self {
            typ,
            signer,
            now,
            czd,
            hash_alg,
            raw,
            recorded_after: 0,
            bundle: 0,
            inclusion: Inclusion::Pending,
        }
    }

    /// Create an action from an already-verified Pay message (internal).
    #[cfg(test)]
    pub(crate) fn from_pay(pay: &coz::Pay, czd: Czd, raw: coz::CozJson) -> Option<Self> {
        let signer = pay.tmb.clone()?;
        let now = pay.now?;
        let typ = pay.typ.clone()?;
        let hash_alg = coz::Alg::from_str(pay.alg.as_deref()?)?.hash_alg();

        Some(Self {
            typ,
            signer,
            now,
            czd,
            hash_alg,
            raw,
            recorded_after: 0,
            bundle: 0,
            inclusion: Inclusion::Pending,
        })
    }

    /// Get the action type.
    pub fn typ(&self) -> &str {
        &self.typ
    }

    /// Get the signer's thumbprint.
    pub fn signer(&self) -> &Thumbprint {
        &self.signer
    }

    /// Get the action timestamp.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Get the Coz digest.
    pub fn czd(&self) -> &Czd {
        &self.czd
    }

    /// The hash algorithm the Coz digest is in.
    pub fn hash_alg(&self) -> HashAlg {
        self.hash_alg
    }

    /// How many commits the principal held when it recorded this action:
    /// its place in history, which an export needs to replay it where it
    /// was recorded (a `ds/create` includes exactly the actions recorded
    /// before it, SPEC 4.8.2).
    pub fn recorded_after(&self) -> usize {
        self.recorded_after
    }

    /// Whether a `ds/create` signed while this action was pending left it
    /// out of DR (SPEC 4.8.2): it stays recorded, never included.
    pub fn is_not_included(&self) -> bool {
        self.inclusion == Inclusion::NotIncluded
    }

    /// Get the raw Coz message for storage/export.
    pub fn raw(&self) -> &coz::CozJson {
        &self.raw
    }

    /// Get a field (standard or application-specific) from the signed payload.
    pub fn get_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.raw.pay.get(key)
    }

    /// Get the message content if present.
    pub fn msg(&self) -> Option<&str> {
        self.get_field("msg")?.as_str()
    }
}
