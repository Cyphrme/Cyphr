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
/// This struct can only be created through `verify_transaction()` which
/// ensures the signature is valid. Fields are crate-internal to prevent
/// external code from constructing unverified transactions.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction kind.
    pub(crate) kind: TransactionKind,
    /// Signer's thumbprint.
    pub(crate) signer: Thumbprint,
    /// Transaction timestamp.
    pub(crate) now: i64,
    /// Coz digest (unique identifier).
    pub(crate) czd: Czd,
    /// Raw Coz message for storage/export.
    pub(crate) raw: coz::CozJson,
    /// Whether this transaction finalizes a commit (`commit: true` in pay).
    pub(crate) is_finalizer: bool,
}

impl Transaction {
    /// Parse a transaction from an already-verified Pay message.
    ///
    /// The `pay` must already be parsed and verified. The `raw` CozJson
    /// is stored for export/re-verification.
    ///
    /// Note: Prefer using `verify_transaction` which ensures consistency.
    ///
    /// # Errors
    ///
    /// Returns `Error::MalformedPayload` if required fields are missing.
    pub fn from_pay(pay: &Pay, czd: Czd, raw: coz::CozJson) -> Result<Self> {
        let signer = pay.tmb.clone().ok_or(Error::MalformedPayload)?;
        let now = pay.now.ok_or(Error::MalformedPayload)?;
        let typ = pay.typ.as_ref().ok_or(Error::MalformedPayload)?;

        let kind = Self::parse_kind(pay, typ, &signer)?;
        let is_finalizer = Self::parse_commit_finalize(pay);

        Ok(Self {
            kind,
            signer,
            now,
            czd,
            raw,
            is_finalizer,
        })
    }

    /// Get the transaction kind.
    pub fn kind(&self) -> &TransactionKind {
        &self.kind
    }

    /// Get the signer's thumbprint.
    pub fn signer(&self) -> &Thumbprint {
        &self.signer
    }

    /// Get the transaction timestamp.
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

    /// Check if this transaction finalizes a commit.
    ///
    /// Per SPEC §4.2.1, a transaction with `commit: true` in its payload
    /// signals the end of an atomic commit bundle.
    pub fn is_finalizer(&self) -> bool {
        self.is_finalizer
    }

    /// Parse the `commit` field from pay to determine if this is a finalizer.
    ///
    /// Returns `true` if `pay.commit == true`, false otherwise.
    fn parse_commit_finalize(pay: &Pay) -> bool {
        pay.extra
            .get("commit")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
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
// Verified Transaction
// ============================================================================

/// A transaction that has been cryptographically verified.
///
/// This type can only be constructed through [`verify`] or the unsafe
/// [`VerifiedTransaction::from_transaction_unsafe`], ensuring that
/// `Principal::apply_verified` can never receive an unverified transaction.
#[derive(Debug, Clone)]
pub struct VerifiedTransaction {
    /// The verified transaction (private - cannot be constructed directly).
    tx: Transaction,
    /// New key for add/replace operations.
    new_key: Option<Key>,
}

impl VerifiedTransaction {
    /// Get a reference to the underlying transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// Get the new key if present (for add/replace operations).
    pub fn new_key(&self) -> Option<&Key> {
        self.new_key.as_ref()
    }

    /// Create a VerifiedTransaction without signature verification.
    ///
    /// # Safety
    ///
    /// This method bypasses signature verification and should ONLY be used
    /// for testing or when signatures are validated externally.
    /// Production code should use [`verify`] instead.
    #[cfg(test)]
    pub(crate) fn from_transaction_unsafe(tx: Transaction, new_key: Option<Key>) -> Self {
        Self { tx, new_key }
    }
}

impl std::ops::Deref for VerifiedTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

/// Verify a transaction signature and return a VerifiedTransaction.
///
/// Uses coz-rs runtime verification with the key's algorithm.
pub fn verify_transaction(
    pay_json: &[u8],
    sig: &[u8],
    key: &Key,
    czd: Czd,
    new_key: Option<Key>,
) -> Result<VerifiedTransaction> {
    // Verify the signature
    let valid = coz::verify_json(pay_json, sig, &key.alg, &key.pub_key).unwrap_or(false);
    if !valid {
        return Err(Error::InvalidSignature);
    }

    // Parse Pay from JSON bytes
    let pay: Pay = serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;

    // Create the raw CozJson for storage
    let pay_value: serde_json::Value =
        serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;
    let raw = coz::CozJson {
        pay: pay_value,
        sig: sig.to_vec(),
    };

    // Create transaction from parsed Pay
    let tx = Transaction::from_pay(&pay, czd, raw)?;

    Ok(VerifiedTransaction { tx, new_key })
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

    /// Helper to wrap Pay in CozJson for tests.
    fn to_raw(pay: &Pay) -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::to_value(pay).unwrap(),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn parse_key_add() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/add")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyAdd { .. }));
        assert_eq!(tx.now, 1000);
    }

    #[test]
    fn parse_key_delete() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/delete")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyDelete { .. }));
    }

    #[test]
    fn parse_key_replace() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/replace")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

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
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::SelfRevoke { rvk: 1000 }));
    }

    #[test]
    fn parse_other_revoke() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(2000)
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

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
        let result = Transaction::from_pay(&pay, czd, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_missing_pre_fails() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/add")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::from_pay(&pay, czd, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_unknown_typ_fails() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/unknown/action")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::from_pay(&pay, czd, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_commit_finalizer_true() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/add")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));
        pay.extra.insert("commit".into(), json!(true));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(tx.is_finalizer());
    }

    #[test]
    fn parse_commit_finalizer_false() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/add")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));
        pay.extra.insert("commit".into(), json!(false));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(!tx.is_finalizer());
    }

    #[test]
    fn parse_commit_finalizer_missing() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/add")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));
        // No "commit" field

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, to_raw(&pay)).unwrap();

        assert!(!tx.is_finalizer());
    }
}
