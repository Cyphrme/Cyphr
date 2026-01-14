//! Action types for Data State (Level 4+).
//!
//! Per SPEC §4.3, actions are signed Coz messages representing user actions.
//! They are recorded in the Data State (DS) for Authenticated Atomic Actions (AAA).

use coz::{Czd, Pay, Thumbprint};

/// A verified action (Level 4+).
///
/// Actions are arbitrary signed Coz messages that represent user actions.
/// Unlike transactions which mutate Auth State, actions are recorded in
/// Data State and can represent any application-specific operation.
#[derive(Debug, Clone)]
pub struct Action {
    /// Action type from `typ` field (e.g., "cyphr.me/comment/create").
    pub typ: String,
    /// Signer's thumbprint.
    pub signer: Thumbprint,
    /// Action timestamp.
    pub now: i64,
    /// Coz digest (unique identifier).
    pub czd: Czd,
    /// Original payload (for application-specific fields).
    pub pay: Pay,
}

impl Action {
    /// Create an action from a verified Coz Pay message.
    ///
    /// The signature must already be verified before calling this.
    pub fn from_pay(pay: Pay, czd: Czd) -> Option<Self> {
        let signer = pay.tmb.clone()?;
        let now = pay.now?;
        let typ = pay.typ.clone()?;

        Some(Self {
            typ,
            signer,
            now,
            czd,
            pay,
        })
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
    use coz::PayBuilder;
    use serde_json::json;

    use super::*;

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

        let action = Action::from_pay(pay, czd.clone()).unwrap();

        assert_eq!(action.typ, "cyphr.me/comment/create");
        assert_eq!(action.now, 1000);
        assert_eq!(action.msg(), Some("Hello, world!"));
        assert_eq!(action.czd.as_bytes(), czd.as_bytes());
    }

    #[test]
    fn action_from_pay_with_custom_fields() {
        let pay = PayBuilder::new()
            .typ("example/data")
            .alg("ES256")
            .now(2000)
            .tmb(Thumbprint::from_bytes(vec![0xCC; 32]))
            .field("custom", json!("value"))
            .build();
        let czd = Czd::from_bytes(vec![0xDD; 32]);

        let action = Action::from_pay(pay, czd).unwrap();

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

        assert!(Action::from_pay(pay, czd).is_none());
    }
}
