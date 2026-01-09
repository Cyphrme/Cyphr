//! Transaction types for Auth State mutations.
//!
//! Per SPEC §4.2, transactions are signed Coz messages that mutate Auth State.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::{Czd, Pay, Thumbprint};

use crate::error::{Error, Result};
use crate::key::Key;
use crate::state::AuthState;

// ============================================================================
// Transaction Types (SPEC §4.2)
// ============================================================================

/// Type path suffixes for Cyphrpass transactions.
pub mod typ {
    /// `<authority>/key/add` - Add a new key (Level 3+)
    pub const KEY_ADD: &str = "key/add";
    /// `<authority>/key/delete` - Remove key without invalidation (Level 3+)
    pub const KEY_DELETE: &str = "key/delete";
    /// `<authority>/key/replace` - Atomic key swap (Level 2+)
    pub const KEY_REPLACE: &str = "key/replace";
    /// `<authority>/key/revoke` - Revoke a key (Level 1+ self, Level 3+ other)
    pub const KEY_REVOKE: &str = "key/revoke";
}

/// Transaction kind variants (SPEC §4.2).
#[derive(Debug, Clone)]
pub enum TransactionKind {
    /// Add a new key (Level 3+) - SPEC §4.2.1
    KeyAdd {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key being added.
        id: Thumbprint,
    },

    /// Remove key without invalidation (Level 3+) - SPEC §4.2.2
    KeyDelete {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key being deleted.
        id: Thumbprint,
    },

    /// Atomic key swap (Level 2+) - SPEC §4.2.3
    KeyReplace {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of new key.
        id: Thumbprint,
    },

    /// Self-revoke (Level 1+) - SPEC §4.2.4
    SelfRevoke {
        /// Revocation timestamp.
        rvk: i64,
    },

    /// Other-revoke (Level 3+) - SPEC §4.2.5
    OtherRevoke {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key to revoke.
        id: Thumbprint,
        /// Revocation timestamp.
        rvk: i64,
    },
}

// ============================================================================
// Transaction
// ============================================================================

/// A verified transaction.
///
/// This struct is created after successfully parsing and verifying a signed
/// Coz message as a Cyphrpass transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction kind.
    pub kind: TransactionKind,
    /// Signer's thumbprint.
    pub signer: Thumbprint,
    /// Transaction timestamp.
    pub now: i64,
    /// Coz digest (unique identifier).
    pub czd: Czd,
}

impl Transaction {
    /// Parse a transaction from a Coz Pay message.
    ///
    /// Extracts transaction type from `typ` field and required fields
    /// based on transaction kind.
    ///
    /// # Errors
    ///
    /// Returns `Error::MalformedPayload` if required fields are missing.
    pub fn parse(pay: &Pay, czd: Czd) -> Result<Self> {
        let signer = pay.tmb.clone().ok_or(Error::MalformedPayload)?;
        let now = pay.now.ok_or(Error::MalformedPayload)?;
        let typ = pay.typ.as_ref().ok_or(Error::MalformedPayload)?;

        let kind = Self::parse_kind(pay, typ, &signer)?;

        Ok(Self {
            kind,
            signer,
            now,
            czd,
        })
    }

    /// Parse the transaction kind from typ and payload fields.
    fn parse_kind(pay: &Pay, typ: &str, signer: &Thumbprint) -> Result<TransactionKind> {
        // Check if typ ends with a known transaction type
        if typ.ends_with(typ::KEY_ADD) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyAdd { pre, id })
        } else if typ.ends_with(typ::KEY_DELETE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyDelete { pre, id })
        } else if typ.ends_with(typ::KEY_REPLACE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyReplace { pre, id })
        } else if typ.ends_with(typ::KEY_REVOKE) {
            let rvk = pay.rvk.ok_or(Error::MalformedPayload)?;

            // Distinguish self-revoke from other-revoke
            if let Some(id) = Self::try_extract_id(pay) {
                // Other-revoke: has `id` field different from signer
                if id.to_b64() != signer.to_b64() {
                    let pre = Self::extract_pre(pay)?;
                    return Ok(TransactionKind::OtherRevoke { pre, id, rvk });
                }
            }
            // Self-revoke: no `id` or `id` == signer
            Ok(TransactionKind::SelfRevoke { rvk })
        } else {
            Err(Error::MalformedPayload)
        }
    }

    /// Extract `pre` field (previous Auth State) from pay.extra.
    fn extract_pre(pay: &Pay) -> Result<AuthState> {
        let pre_value = pay.extra.get("pre").ok_or(Error::MalformedPayload)?;
        let pre_str = pre_value.as_str().ok_or(Error::MalformedPayload)?;
        let pre_bytes =
            Base64UrlUnpadded::decode_vec(pre_str).map_err(|_| Error::MalformedPayload)?;
        Ok(AuthState(coz::Cad::from_bytes(pre_bytes)))
    }

    /// Extract `id` field (target key thumbprint) from pay.extra.
    fn extract_id(pay: &Pay) -> Result<Thumbprint> {
        Self::try_extract_id(pay).ok_or(Error::MalformedPayload)
    }

    /// Try to extract `id` field, returning None if not present.
    fn try_extract_id(pay: &Pay) -> Option<Thumbprint> {
        let id_value = pay.extra.get("id")?;
        let id_str = id_value.as_str()?;
        let id_bytes = Base64UrlUnpadded::decode_vec(id_str).ok()?;
        Some(Thumbprint::from_bytes(id_bytes))
    }
}

// ============================================================================
// Transaction Verification
// ============================================================================

/// Verify a transaction signature against a key.
///
/// Uses coz-rs runtime verification with the key's algorithm.
pub fn verify_signature(pay_json: &[u8], sig: &[u8], key: &Key) -> bool {
    coz::verify_json(pay_json, sig, &key.alg, &key.pub_key).unwrap_or(false)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::{PayBuilder, Thumbprint};
    use serde_json::json;

    use super::*;

    // Valid base64url for 32 bytes (use golden thumbprint from Coz spec)
    const TEST_PRE: &str = "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
    const TEST_ID: &str = "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo";

    fn make_pay_with_extra(typ: &str, extra: serde_json::Value) -> Pay {
        let mut pay = PayBuilder::new()
            .typ(typ)
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();

        // Merge extra fields
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                pay.extra.insert(k.clone(), v.clone());
            }
        }
        pay
    }

    #[test]
    fn parse_key_add() {
        let pay = make_pay_with_extra(
            "cyphr.me/key/add",
            json!({
                "pre": TEST_PRE,
                "id": TEST_ID
            }),
        );
        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::parse(&pay, czd).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyAdd { .. }));
        assert_eq!(tx.now, 1000);
    }

    #[test]
    fn parse_key_delete() {
        let pay = make_pay_with_extra(
            "cyphr.me/key/delete",
            json!({
                "pre": TEST_PRE,
                "id": TEST_ID
            }),
        );
        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::parse(&pay, czd).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyDelete { .. }));
    }

    #[test]
    fn parse_key_replace() {
        let pay = make_pay_with_extra(
            "cyphr.me/key/replace",
            json!({
                "pre": TEST_PRE,
                "id": TEST_ID
            }),
        );
        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::parse(&pay, czd).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyReplace { .. }));
    }

    #[test]
    fn parse_self_revoke() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(1000)
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::parse(&pay, czd).unwrap();

        assert!(matches!(tx.kind, TransactionKind::SelfRevoke { rvk: 1000 }));
    }

    #[test]
    fn parse_other_revoke() {
        let mut pay = make_pay_with_extra(
            "cyphr.me/key/revoke",
            json!({
                "pre": TEST_PRE,
                "id": TEST_ID
            }),
        );
        pay.rvk = Some(2000);

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::parse(&pay, czd).unwrap();

        assert!(matches!(
            tx.kind,
            TransactionKind::OtherRevoke { rvk: 2000, .. }
        ));
    }

    #[test]
    fn parse_missing_typ_fails() {
        let pay = PayBuilder::new()
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::parse(&pay, czd);

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_missing_pre_fails() {
        let pay = make_pay_with_extra(
            "cyphr.me/key/add",
            json!({
                "id": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            }),
        );
        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::parse(&pay, czd);

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_unknown_typ_fails() {
        let pay = make_pay_with_extra("cyphr.me/unknown/action", json!({}));
        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::parse(&pay, czd);

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }
}
