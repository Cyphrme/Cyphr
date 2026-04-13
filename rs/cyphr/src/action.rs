//! Action types for Data State (Level 4+).
//!
//! Per SPEC §4.3, actions are signed Coz messages representing user actions.
//! They are recorded in the Data State (DS) for Authenticated Atomic Actions (AAA).

use coz::{Czd, Pay, Thumbprint};

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
    /// Original payload (for application-specific fields).
    pub(crate) pay: Pay,
    /// Raw Coz message for storage/export.
    pub(crate) raw: coz::CozJson,
}

impl Action {
    /// Create an action from already-verified, extracted values (internal).
    ///
    /// Used when we extract fields from raw JSON rather than parsing into coz::Pay.
    /// The raw CozJson preserves the original message for storage/export.
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
            pay: Pay::default(), // Placeholder - use raw for actual data
            raw,
        }
    }

    /// Create an action from an already-verified Pay message (internal).
    #[cfg(test)]
    pub(crate) fn from_pay(pay: &Pay, czd: Czd, raw: coz::CozJson) -> Option<Self> {
        let signer = pay.tmb.clone()?;
        let now = pay.now?;
        let typ = pay.typ.clone()?;

        Some(Self {
            typ,
            signer,
            now,
            czd,
            pay: pay.clone(),
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

    /// Get a custom field from the action payload.
    pub fn get_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.pay.extra.get(key)
    }

    /// Get the message content if present.
    pub fn msg(&self) -> Option<&str> {
        self.pay.msg.as_deref()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::{PayBuilder, Thumbprint};
    use serde_json::json;

    use super::*;

    /// Helper to wrap Pay in CozJson for tests.
    fn to_raw(pay: &Pay) -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::to_value(pay).unwrap(),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn action_from_pay_basic() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/comment/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .msg("Hello, world!")
            .build();

        let czd = Czd::from_bytes(vec![0xBB; 32]);
        let action = Action::from_pay(&pay, czd.clone(), to_raw(&pay)).unwrap();

        assert_eq!(action.typ, "cyphr.me/comment/create");
        assert_eq!(action.now, 1000);
        assert_eq!(action.msg(), Some("Hello, world!"));
        assert_eq!(action.czd.as_bytes(), czd.as_bytes());
    }

    #[test]
    fn action_from_pay_with_custom_fields() {
        let mut pay = PayBuilder::new()
            .typ("example/data")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("custom".into(), json!("value"));

        let czd = Czd::from_bytes(vec![0xDD; 32]);
        let action = Action::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert_eq!(action.get_field("custom"), Some(&json!("value")));
    }

    #[test]
    fn action_from_pay_missing_tmb_returns_none() {
        let pay = PayBuilder::new()
            .typ("example/test")
            .alg("ES256")
            .now(1000)
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        assert!(Action::from_pay(&pay, czd, to_raw(&pay)).is_none());
    }
}
