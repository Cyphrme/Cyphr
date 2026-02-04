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
    /// `<authority>/key/create` - Create a new key (Level 3+)
    pub const KEY_CREATE: &str = "key/create";
    /// `<authority>/key/delete` - Remove key without invalidation (Level 3+)
    pub const KEY_DELETE: &str = "key/delete";
    /// `<authority>/key/replace` - Atomic key swap (Level 2+)
    pub const KEY_REPLACE: &str = "key/replace";
    /// `<authority>/key/revoke` - Revoke a key (Level 1+ self, Level 3+ other)
    pub const KEY_REVOKE: &str = "key/revoke";
    /// `<authority>/principal/create` - Explicit genesis finalization (Level 3+)
    pub const PRINCIPAL_CREATE: &str = "principal/create";
}

/// Transaction kind variants (SPEC §4.2).
#[derive(Debug, Clone)]
pub enum TransactionKind {
    /// Create a new key (Level 3+) - SPEC §4.2.1
    KeyCreate {
        /// Previous Auth State.
        pre: AuthState,
        /// Thumbprint of key being created.
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
    /// Per protocol simplification, revoke requires `pre` like all other coz.
    SelfRevoke {
        /// Previous Auth State.
        pre: AuthState,
        /// Revocation timestamp.
        rvk: i64,
    },

    /// Principal creation (explicit genesis finalization) - SPEC §5.1
    ///
    /// Finalizes explicit genesis. `pre` references current Auth State.
    PrincipalCreate {
        /// Previous Auth State (required per implicit first key model).
        pre: AuthState,
        /// Final Auth State bundle identifier (becomes PR).
        id: AuthState,
    },
}

impl std::fmt::Display for TransactionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionKind::KeyCreate { .. } => write!(f, "key/create"),
            TransactionKind::KeyDelete { .. } => write!(f, "key/delete"),
            TransactionKind::KeyReplace { .. } => write!(f, "key/replace"),
            TransactionKind::SelfRevoke { .. } => write!(f, "key/revoke"),
            TransactionKind::PrincipalCreate { .. } => write!(f, "principal/create"),
        }
    }
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
    /// Hash algorithm associated with the signing key.
    /// Used for cross-algorithm state computation (MHMR).
    pub(crate) hash_alg: crate::state::HashAlg,
    /// Raw Coz message for storage/export.
    pub(crate) raw: coz::CozJson,
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
    pub fn from_pay(
        pay: &Pay,
        czd: Czd,
        hash_alg: crate::state::HashAlg,
        raw: coz::CozJson,
    ) -> Result<Self> {
        let signer = pay.tmb.clone().ok_or(Error::MalformedPayload)?;
        let now = pay.now.ok_or(Error::MalformedPayload)?;
        let typ = pay.typ.as_ref().ok_or(Error::MalformedPayload)?;

        let kind = Self::parse_kind(pay, typ, &signer)?;
        Ok(Self {
            kind,
            signer,
            now,
            czd,
            hash_alg,
            raw,
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

    /// Get the hash algorithm associated with the signing key.
    pub fn hash_alg(&self) -> crate::state::HashAlg {
        self.hash_alg
    }

    /// Parse the transaction kind from typ and payload fields.
    fn parse_kind(pay: &Pay, typ: &str, _signer: &Thumbprint) -> Result<TransactionKind> {
        // Check if typ ends with a known transaction type
        if typ.ends_with(typ::KEY_CREATE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyCreate { pre, id })
        } else if typ.ends_with(typ::KEY_DELETE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyDelete { pre, id })
        } else if typ.ends_with(typ::KEY_REPLACE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(TransactionKind::KeyReplace { pre, id })
        } else if typ.ends_with(typ::KEY_REVOKE) {
            // Per protocol simplification, revoke requires pre like all other coz
            let pre = Self::extract_pre(pay)?;
            let rvk = pay.rvk.ok_or(Error::MalformedPayload)?;
            Ok(TransactionKind::SelfRevoke { pre, rvk })
        } else if typ.ends_with(typ::PRINCIPAL_CREATE) {
            // Genesis finalization (SPEC §5.1)
            // `pre` references current AS, `id` is final AS (becomes PR)
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_as(pay)?;
            Ok(TransactionKind::PrincipalCreate { pre, id })
        } else {
            Err(Error::MalformedPayload)
        }
    }

    /// Extract `pre` field (previous Auth State) from pay.extra.
    ///
    /// Expects `alg:digest` format (e.g., `SHA-256:U5XUZots...`).
    fn extract_pre(pay: &Pay) -> Result<AuthState> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let pre_value = pay.extra.get("pre").ok_or(Error::MalformedPayload)?;
        let pre_str = pre_value.as_str().ok_or(Error::MalformedPayload)?;

        // Parse tagged digest (validates algorithm and length)
        let tagged: TaggedDigest = pre_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(AuthState(MultihashDigest::from_single(
            tagged.alg(),
            tagged.as_bytes().to_vec(),
        )))
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

    /// Extract `id` field as AuthState (for principal/create).
    ///
    /// Per SPEC §5.1, the `id` field in principal/create contains the
    /// Auth State bundle identifier. Expects `alg:digest` format.
    fn extract_as(pay: &Pay) -> Result<AuthState> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let id_value = pay.extra.get("id").ok_or(Error::MalformedPayload)?;
        let id_str = id_value.as_str().ok_or(Error::MalformedPayload)?;

        // Parse tagged digest (validates algorithm and length)
        let tagged: TaggedDigest = id_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(AuthState(MultihashDigest::from_single(
            tagged.alg(),
            tagged.as_bytes().to_vec(),
        )))
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

    // Derive hash algorithm from signing key's algorithm
    let hash_alg = crate::state::hash_alg_from_str(&key.alg)?;

    // Create transaction from parsed Pay
    let tx = Transaction::from_pay(&pay, czd, hash_alg, raw)?;

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
    use crate::state::HashAlg;

    // Valid alg:digest format for 32-byte SHA-256 digests
    const TEST_PRE: &str = "SHA-256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg";
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
            .typ("cyphr.me/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyCreate { .. }));
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
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

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
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::KeyReplace { .. }));
    }

    #[test]
    fn parse_self_revoke() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(1000)
            .build();
        // Per protocol simplification, revoke requires pre like all other coz
        pay.extra.insert("pre".into(), json!(TEST_PRE));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(
            tx.kind,
            TransactionKind::SelfRevoke { rvk: 1000, .. }
        ));
    }

    #[test]
    fn parse_principal_create() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/principal/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        // pre is the current AS before finalization (required per SPEC §5.1)
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        // id is the final AS (becomes PR)
        pay.extra.insert("id".into(), json!(TEST_PRE));
        pay.extra.insert("commit".into(), json!(true));

        let czd = Czd::from_bytes(vec![0; 32]);
        let tx = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(tx.kind, TransactionKind::PrincipalCreate { .. }));
    }

    #[test]
    fn parse_missing_typ_fails() {
        let pay = PayBuilder::new()
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_missing_pre_fails() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

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
        let result = Transaction::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }
}
