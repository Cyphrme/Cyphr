//! Action types for Data State (Level 4+).
//!
//! Per SPEC §4.3, actions are signed Coz messages representing user actions.
//! They are recorded in the Data State (DS) for Authenticated Atomic Actions (AAA).

use coz::{Czd, Thumbprint};

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
    /// Raw Coz message: the signed payload (including application-specific
    /// fields) and signature, for storage/export.
    pub(crate) raw: coz::CozJson,
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
        raw: coz::CozJson,
    ) -> Self {
        Self {
            typ,
            signer,
            now,
            czd,
            raw,
        }
    }

    /// Create an action from an already-verified Pay message (internal).
    #[cfg(test)]
    pub(crate) fn from_pay(pay: &coz::Pay, czd: Czd, raw: coz::CozJson) -> Option<Self> {
        let signer = pay.tmb.clone()?;
        let now = pay.now?;
        let typ = pay.typ.clone()?;

        Some(Self {
            typ,
            signer,
            now,
            czd,
            raw,
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::{Pay, PayBuilder, Thumbprint};
    use serde_json::json;

    use super::*;

    /// Helper to wrap Pay in CozJson for tests.
    fn to_raw(pay: &Pay) -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::to_value(pay).unwrap(),
            sig: vec![0; 64],
        }
    }

    /// Backs the production constructor: `Action::new` (the only path
    /// `record_action` uses) must expose payload fields, not the empty
    /// placeholder it once stored. Unit level because the read accessors
    /// are pure functions of `raw`.
    #[test]
    fn action_new_exposes_payload_fields_from_raw() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/comment/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .msg("hi")
            .build();
        pay.extra.insert("custom".into(), json!(7));
        let action = Action::new(
            "cyphr.me/comment/create".into(),
            Thumbprint::from_bytes(vec![0xAA; 32]),
            1000,
            Czd::from_bytes(vec![0xBB; 32]),
            to_raw(&pay),
        );
        assert_eq!(action.msg(), Some("hi"));
        assert_eq!(action.get_field("custom"), Some(&json!(7)));
        assert_eq!(action.get_field("absent"), None);
    }
}
