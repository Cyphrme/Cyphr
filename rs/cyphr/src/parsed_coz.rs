//! ParsedCoz types for Auth State mutations.
//!
//! Per SPEC §4.2, cozies are signed Coz messages that mutate Auth State.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use coz::{Czd, Pay, Thumbprint};

use crate::error::{Error, Result};
use crate::key::Key;
use crate::state::{AuthRoot, PrincipalRoot};

// ============================================================================
// ParsedCoz Types (SPEC §4.2)
// ============================================================================

/// Type path suffixes for Cyphr cozies (SPEC §7.2).
///
/// Each constant is a protocol-qualified suffix: `cyphr/<noun>/<verb>`.
/// The full typ is constructed at the call site as `{authority}/{suffix}`,
/// where authority is the deployment domain (e.g., `cyphr.me`).
///
/// Parsers match via `ends_with(suffix)` to remain authority-agnostic.
pub mod typ {
    /// `<authority>/cyphr/key/create` - Create a new key (Level 3+)
    pub const KEY_CREATE: &str = "cyphr/key/create";
    /// `<authority>/cyphr/key/delete` - Remove key without invalidation (Level 3+)
    pub const KEY_DELETE: &str = "cyphr/key/delete";
    /// `<authority>/cyphr/key/replace` - Atomic key swap (Level 2+)
    pub const KEY_REPLACE: &str = "cyphr/key/replace";
    /// `<authority>/cyphr/key/revoke` - Revoke a key (Level 1+ self, Level 3+ other)
    pub const KEY_REVOKE: &str = "cyphr/key/revoke";
    /// `<authority>/cyphr/principal/create` - Explicit genesis finalization (Level 3+)
    pub const PRINCIPAL_CREATE: &str = "cyphr/principal/create";
    /// `<authority>/cyphr/commit/create` - Finalize a commit (Arrow finality)
    pub const COMMIT_CREATE: &str = "cyphr/commit/create";
}

/// ParsedCoz kind variants (SPEC §4.2).
#[derive(Debug, Clone)]
pub enum CozKind {
    /// Create a new key (Level 3+) - SPEC §4.2.1
    KeyCreate {
        /// Previous Principal State.
        pre: PrincipalRoot,
        /// Thumbprint of key being created.
        id: Thumbprint,
    },

    /// Remove key without invalidation (Level 3+) - SPEC §4.2.2
    KeyDelete {
        /// Previous Principal State.
        pre: PrincipalRoot,
        /// Thumbprint of key being deleted.
        id: Thumbprint,
    },

    /// Atomic key swap (Level 2+) - SPEC §4.2.3
    KeyReplace {
        /// Previous Principal State.
        pre: PrincipalRoot,
        /// Thumbprint of new key.
        id: Thumbprint,
    },

    /// Self-revoke (Level 1+) - SPEC §4.2.4
    /// Per protocol simplification, revoke requires `pre` like all other coz.
    SelfRevoke {
        /// Previous Principal State.
        pre: PrincipalRoot,
        /// Revocation timestamp.
        rvk: i64,
    },

    /// Principal creation (explicit genesis finalization) - SPEC §5.1
    ///
    /// Finalizes explicit genesis. `pre` references current Principal State.
    PrincipalCreate {
        /// Previous Principal State (required per implicit first key model).
        pre: PrincipalRoot,
        /// Final Auth State bundle identifier (becomes PR).
        id: AuthRoot,
    },
    /// Commit finality (Arrow) - SPEC §4.4
    CommitCreate {
        /// The arrow field = MR(pre, fwd_SR, TMR)
        arrow: crate::multihash::MultihashDigest,
    },
}

impl std::fmt::Display for CozKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CozKind::KeyCreate { .. } => write!(f, "{}", typ::KEY_CREATE),
            CozKind::KeyDelete { .. } => write!(f, "{}", typ::KEY_DELETE),
            CozKind::KeyReplace { .. } => write!(f, "{}", typ::KEY_REPLACE),
            CozKind::SelfRevoke { .. } => write!(f, "{}", typ::KEY_REVOKE),
            CozKind::PrincipalCreate { .. } => write!(f, "{}", typ::PRINCIPAL_CREATE),
            CozKind::CommitCreate { .. } => write!(f, "{}", typ::COMMIT_CREATE),
        }
    }
}

// ============================================================================
// ParsedCoz
// ============================================================================

/// A verified coz.
///
/// This struct can only be created through `verify_coz()` which
/// ensures the signature is valid. Fields are crate-internal to prevent
/// external code from constructing unverified cozies.
#[derive(Debug, Clone)]
pub struct ParsedCoz {
    /// ParsedCoz kind.
    pub(crate) kind: CozKind,
    /// Signer's thumbprint.
    pub(crate) signer: Thumbprint,
    /// ParsedCoz timestamp.
    pub(crate) now: i64,
    /// Coz digest (unique identifier).
    pub(crate) czd: Czd,
    /// Hash algorithm associated with the signing key.
    /// Used for cross-algorithm state computation (MHMR).
    pub(crate) hash_alg: crate::state::HashAlg,
    /// Arrow field from `arrow` field (present on terminal commit coz only).
    ///
    /// Per SPEC §4.4, the last coz in a commit contains `"arrow":<MR(pre, fwd, TMR)>`.
    pub(crate) arrow: Option<crate::multihash::MultihashDigest>,
    /// Raw Coz message for storage/export.
    pub(crate) raw: coz::CozJson,
}

impl ParsedCoz {
    /// Parse a coz from an already-verified Pay message.
    ///
    /// The `pay` must already be parsed and verified. The `raw` CozJson
    /// is stored for export/re-verification.
    ///
    /// Note: Prefer using `verify_coz` which ensures consistency.
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
        let arrow = Self::extract_arrow(pay)?;
        Ok(Self {
            kind,
            signer,
            now,
            czd,
            hash_alg,
            arrow,
            raw,
        })
    }

    /// Get the coz kind.
    pub fn kind(&self) -> &CozKind {
        &self.kind
    }

    /// Get the signer's thumbprint.
    pub fn signer(&self) -> &Thumbprint {
        &self.signer
    }

    /// Get the coz timestamp.
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

    /// Get the arrow if this is a terminal (finalizing) coz.
    ///
    /// Per SPEC §4.4, only the last coz in a commit has `"arrow":<Digest>`.
    pub fn arrow(&self) -> Option<&crate::multihash::MultihashDigest> {
        self.arrow.as_ref()
    }

    /// Parse the coz kind from typ and payload fields.
    fn parse_kind(pay: &Pay, typ: &str, _signer: &Thumbprint) -> Result<CozKind> {
        // Check if typ ends with a known coz type
        if typ.ends_with(typ::KEY_CREATE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyCreate { pre, id })
        } else if typ.ends_with(typ::KEY_DELETE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyDelete { pre, id })
        } else if typ.ends_with(typ::KEY_REPLACE) {
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyReplace { pre, id })
        } else if typ.ends_with(typ::KEY_REVOKE) {
            // Per protocol simplification, revoke requires pre like all other coz
            let pre = Self::extract_pre(pay)?;
            let rvk = pay.rvk.ok_or(Error::MalformedPayload)?;
            // [no-revoke-non-self]: If id is present, it must match the signer.
            if let Some(id) = Self::try_extract_id(pay) {
                if id.to_b64() != _signer.to_b64() {
                    return Err(Error::MalformedPayload);
                }
            }
            Ok(CozKind::SelfRevoke { pre, rvk })
        } else if typ.ends_with(typ::PRINCIPAL_CREATE) {
            // Genesis finalization (SPEC §5.1)
            // `pre` references current AS, `id` is final AS (becomes PR)
            let pre = Self::extract_pre(pay)?;
            let id = Self::extract_as(pay)?;
            Ok(CozKind::PrincipalCreate { pre, id })
        } else if typ.ends_with(typ::COMMIT_CREATE) {
            let arrow = Self::extract_arrow(pay)?.ok_or(Error::MalformedPayload)?;
            Ok(CozKind::CommitCreate { arrow })
        } else {
            Err(Error::MalformedPayload)
        }
    }

    /// Extract `pre` field (previous Principal State) from pay.extra.
    ///
    /// Expects `alg:digest` format (e.g., `SHA-256:U5XUZots...`).
    fn extract_pre(pay: &Pay) -> Result<PrincipalRoot> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let pre_value = pay.extra.get("pre").ok_or(Error::MalformedPayload)?;
        let pre_str = pre_value.as_str().ok_or(Error::MalformedPayload)?;

        // Parse tagged digest (validates algorithm and length)
        let tagged: TaggedDigest = pre_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(PrincipalRoot(MultihashDigest::from_single(
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

    /// Extract `id` field as AuthRoot (for principal/create).
    ///
    /// Per SPEC §5.1, the `id` field in principal/create contains the
    /// Auth State bundle identifier. Expects `alg:digest` format.
    fn extract_as(pay: &Pay) -> Result<AuthRoot> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let id_value = pay.extra.get("id").ok_or(Error::MalformedPayload)?;
        let id_str = id_value.as_str().ok_or(Error::MalformedPayload)?;

        // Parse tagged digest (validates algorithm and length)
        let tagged: TaggedDigest = id_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(AuthRoot(MultihashDigest::from_single(
            tagged.alg(),
            tagged.as_bytes().to_vec(),
        )))
    }

    // Extract optional `arrow` field.
    ///
    /// Per SPEC §4.4, the last coz in a commit contains `"arrow":<Digest>`
    /// in `alg:digest` format. Returns `Ok(None)` if the field is absent.
    fn extract_arrow(pay: &Pay) -> Result<Option<crate::multihash::MultihashDigest>> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let Some(arrow_value) = pay.extra.get("arrow") else {
            return Ok(None);
        };

        if arrow_value.is_boolean() {
            return Ok(None);
        }

        let arrow_str = arrow_value.as_str().ok_or(Error::MalformedPayload)?;
        let tagged: TaggedDigest = arrow_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(Some(MultihashDigest::from_single(
            tagged.alg(),
            tagged.as_bytes().to_vec(),
        )))
    }
}

// ============================================================================
// Verified ParsedCoz
// ============================================================================

/// A coz that has been cryptographically verified.
///
/// This type can only be constructed through [`verify`] or the unsafe
/// [`VerifiedCoz::from_transaction_unsafe`], ensuring that
/// `Principal::apply_verified` can never receive an unverified coz.
#[derive(Debug, Clone)]
pub struct VerifiedCoz {
    /// The verified coz (private - cannot be constructed directly).
    cz: ParsedCoz,
    /// New key for add/replace operations.
    new_key: Option<Key>,
}

impl VerifiedCoz {
    /// Get a reference to the underlying coz.
    pub fn coz(&self) -> &ParsedCoz {
        &self.cz
    }

    /// Get the new key if present (for add/replace operations).
    pub fn new_key(&self) -> Option<&Key> {
        self.new_key.as_ref()
    }

    /// Create a VerifiedCoz from its constituent parts.
    ///
    /// This is used by the creation path (`CommitScope::finalize_with_commit`)
    /// where the coz is signed internally by the builder.
    /// The caller is responsible for ensuring the coz is valid.
    pub(crate) fn from_parts(cz: ParsedCoz, new_key: Option<Key>) -> Self {
        Self { cz, new_key }
    }

    /// Create a VerifiedCoz without signature verification.
    ///
    /// # Safety
    ///
    /// This method bypasses signature verification and should ONLY be used
    /// for testing. Production code should use [`verify`] or [`from_parts`].
    #[cfg(test)]
    pub(crate) fn from_transaction_unsafe(cz: ParsedCoz, new_key: Option<Key>) -> Self {
        Self::from_parts(cz, new_key)
    }
}

impl std::ops::Deref for VerifiedCoz {
    type Target = ParsedCoz;

    fn deref(&self) -> &Self::Target {
        &self.cz
    }
}

/// Verify a coz signature and return a VerifiedCoz.
///
/// Uses coz-rs runtime verification with the key's algorithm.
pub fn verify_coz(
    pay_json: &[u8],
    sig: &[u8],
    key: &Key,
    czd: Czd,
    new_key: Option<Key>,
) -> Result<VerifiedCoz> {
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

    // Create coz from parsed Pay
    let cz = ParsedCoz::from_pay(&pay, czd, hash_alg, raw)?;

    Ok(VerifiedCoz { cz, new_key })
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
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::KeyCreate { .. }));
        assert_eq!(cz.now, 1000);
    }

    #[test]
    fn parse_key_delete() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/delete")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::KeyDelete { .. }));
    }

    #[test]
    fn parse_key_replace() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/replace")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("pre".into(), json!(TEST_PRE));
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::KeyReplace { .. }));
    }

    #[test]
    fn parse_self_revoke() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(1000)
            .build();
        // Per protocol simplification, revoke requires pre like all other coz
        pay.extra.insert("pre".into(), json!(TEST_PRE));

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::SelfRevoke { rvk: 1000, .. }));
    }

    #[test]
    fn parse_principal_create() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/principal/create")
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
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::PrincipalCreate { .. }));
    }

    #[test]
    fn parse_missing_typ_fails() {
        let pay = PayBuilder::new()
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }

    #[test]
    fn parse_missing_pre_fails() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

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
        let result = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

        assert!(matches!(result, Err(Error::MalformedPayload)));
    }
}
