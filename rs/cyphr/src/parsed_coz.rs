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
    /// `<authority>/cyphr/principal/delete` - Close a principal (Level 3+, SPEC §11.4)
    pub const PRINCIPAL_DELETE: &str = "cyphr/principal/delete";
    /// `<authority>/cyphr/freeze/create` - Self-freeze (SPEC §14.9.1)
    pub const FREEZE_CREATE: &str = "cyphr/freeze/create";
    /// `<authority>/cyphr/freeze/delete` - Thaw (SPEC §14.9.3)
    pub const FREEZE_DELETE: &str = "cyphr/freeze/delete";

    /// Returns true if `typ` introduces new key material into the Auth State
    /// (`key/create` or `key/replace`).
    ///
    /// Canonical predicate: callers MUST use this rather than re-deriving the
    /// same classification from hardcoded typ substrings.
    pub fn is_key_introducing(typ: &str) -> bool {
        typ.ends_with(KEY_CREATE) || typ.ends_with(KEY_REPLACE)
    }
}

/// ParsedCoz kind variants (SPEC §4.2).
#[derive(Debug, Clone)]
pub enum CozKind {
    /// Create a new key (Level 3+) - SPEC §4.2.1
    KeyCreate {
        /// Thumbprint of key being created.
        id: Thumbprint,
    },

    /// Remove key without invalidation (Level 3+) - SPEC §4.2.2
    KeyDelete {
        /// Thumbprint of key being deleted.
        id: Thumbprint,
    },

    /// Atomic key swap (Level 2+) - SPEC §4.2.3
    KeyReplace {
        /// Thumbprint of new key.
        id: Thumbprint,
    },

    /// Self-revoke (Level 1+) - SPEC §4.2.4
    SelfRevoke {
        /// Revocation timestamp.
        rvk: i64,
    },

    /// Principal creation (explicit genesis finalization) - SPEC §5.1
    PrincipalCreate {
        /// Final Auth State bundle identifier (becomes PR).
        id: AuthRoot,
    },
    /// Commit finality (Arrow) - SPEC §4.4
    CommitCreate {
        /// The arrow field = MR(pre, fwd_SR, TMR)
        arrow: crate::multihash::MultihashDigest,
    },

    /// Close (Level 3+) - SPEC §11.4
    PrincipalDelete {
        /// Target Principal Root (the signer's own PR).
        id: PrincipalRoot,
    },

    /// Self-freeze - SPEC §14.9.1
    FreezeCreate {
        /// Targeted Principal Root (the signer's own PR).
        id: PrincipalRoot,
    },

    /// Thaw - SPEC §14.9.3
    FreezeDelete {
        /// Targeted Principal Root (the signer's own PR).
        id: PrincipalRoot,
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
            CozKind::PrincipalDelete { .. } => write!(f, "{}", typ::PRINCIPAL_DELETE),
            CozKind::FreezeCreate { .. } => write!(f, "{}", typ::FREEZE_CREATE),
            CozKind::FreezeDelete { .. } => write!(f, "{}", typ::FREEZE_DELETE),
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
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyCreate { id })
        } else if typ.ends_with(typ::KEY_DELETE) {
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyDelete { id })
        } else if typ.ends_with(typ::KEY_REPLACE) {
            let id = Self::extract_id(pay)?;
            Ok(CozKind::KeyReplace { id })
        } else if typ.ends_with(typ::KEY_REVOKE) {
            // Self-revoke: signer revokes itself. `id` MUST be absent — the
            // signer IS the revoked key. Presence of `id` is a malformed payload.
            // [no-revoke-non-self]: non-self revoke is not permitted at any level.
            let rvk = pay.rvk.ok_or(Error::MalformedPayload)?;
            if Self::try_extract_id(pay).is_some() {
                return Err(Error::MalformedPayload);
            }
            Ok(CozKind::SelfRevoke { rvk })
        } else if typ.ends_with(typ::PRINCIPAL_CREATE) {
            // Genesis finalization (SPEC §5.1)
            // `id` is final AS (becomes PR)
            let id = Self::extract_as(pay)?;
            Ok(CozKind::PrincipalCreate { id })
        } else if typ.ends_with(typ::COMMIT_CREATE) {
            let arrow = Self::extract_arrow(pay)?.ok_or(Error::MalformedPayload)?;
            Ok(CozKind::CommitCreate { arrow })
        } else if typ.ends_with(typ::PRINCIPAL_DELETE) {
            let id = Self::extract_pr(pay)?;
            Ok(CozKind::PrincipalDelete { id })
        } else if typ.ends_with(typ::FREEZE_CREATE) {
            let id = Self::extract_pr(pay)?;
            Ok(CozKind::FreezeCreate { id })
        } else if typ.ends_with(typ::FREEZE_DELETE) {
            let id = Self::extract_pr(pay)?;
            Ok(CozKind::FreezeDelete { id })
        } else {
            Err(Error::MalformedPayload)
        }
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

        Ok(AuthRoot(
            MultihashDigest::from_single(tagged.alg(), tagged.as_bytes().to_vec())
                .map_err(|_| Error::MalformedPayload)?,
        ))
    }

    /// Extract `id` field as PrincipalRoot (for the lifecycle transactions:
    /// `principal/delete`, `freeze/create`, `freeze/delete`).
    ///
    /// Per SPEC §11.4/§14.9, the `id` field on these three transactions is
    /// the signer's own target/targeted PR, in the same `alg:digest` tagged
    /// format as `principal/create`'s `id` -- this mirrors `extract_as`
    /// exactly, differing only in the wrapper type returned (`PrincipalRoot`
    /// rather than `AuthRoot`, matching what these transactions actually
    /// reference).
    fn extract_pr(pay: &Pay) -> Result<PrincipalRoot> {
        use crate::multihash::MultihashDigest;
        use crate::state::TaggedDigest;

        let id_value = pay.extra.get("id").ok_or(Error::MalformedPayload)?;
        let id_str = id_value.as_str().ok_or(Error::MalformedPayload)?;

        let tagged: TaggedDigest = id_str.parse().map_err(|_| Error::MalformedPayload)?;

        Ok(PrincipalRoot(
            MultihashDigest::from_single(tagged.alg(), tagged.as_bytes().to_vec())
                .map_err(|_| Error::MalformedPayload)?,
        ))
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

        Ok(Some(
            MultihashDigest::from_single(tagged.alg(), tagged.as_bytes().to_vec())
                .map_err(|_| Error::MalformedPayload)?,
        ))
    }
}

// ============================================================================
// Key-agnostic header parsing
// ============================================================================

/// A minimal, key-agnostic view of a coz's `typ`/`tmb`/`now` header fields.
///
/// [`verify_coz`] requires the signer's [`Key`] up front (to verify the
/// signature and derive `hash_alg` from `key.alg`), and its internal call
/// into [`ParsedCoz::from_pay`] additionally requires `hash_alg` and a
/// [`Czd`] the caller has not necessarily computed yet. A caller that only
/// needs to classify an untrusted coz -- e.g. a storage engine deciding
/// how to route a submitted blob before it has resolved a `Key` at all --
/// has no lighter-weight primitive to reach for, and ends up hand-rolling
/// `pay.get("typ").and_then(...).unwrap_or(...)`-style extraction instead,
/// which silently substitutes a default for a missing or malformed field
/// rather than rejecting it.
#[derive(Debug, Clone)]
pub struct CozHeader {
    /// The coz's `typ` field, verbatim.
    pub typ: String,
    /// The coz's `tmb` field: the claimed signer's thumbprint. Not yet
    /// verified against any signature -- this is metadata extraction, not
    /// authentication.
    pub tmb: Thumbprint,
    /// The coz's `now` field: the claimed signing timestamp.
    pub now: i64,
}

impl CozHeader {
    /// Parse `typ`/`tmb`/`now` from a coz's `pay` JSON value, without
    /// requiring the signer's [`Key`] or any other prerequisite
    /// [`verify_coz`] needs.
    ///
    /// Reuses [`coz::Pay`]'s own `Deserialize` impl (the same one
    /// [`ParsedCoz::from_pay`]'s caller feeds), so the accepted shape
    /// matches the rest of this crate exactly -- this is a narrower
    /// read of the same structure, not a second parser.
    ///
    /// # Errors
    ///
    /// Returns `Error::MalformedPayload` if `pay` does not deserialize as
    /// a [`coz::Pay`], or if `typ`, `tmb`, or `now` is missing. There is
    /// no default for a missing field: at the trust boundary this exists
    /// for, a caller must not mistake "absent" for "empty" or "zero".
    pub fn parse(pay: &serde_json::Value) -> Result<Self> {
        let pay: Pay = serde_json::from_value(pay.clone()).map_err(|_| Error::MalformedPayload)?;
        Ok(Self {
            typ: pay.typ.ok_or(Error::MalformedPayload)?,
            tmb: pay.tmb.ok_or(Error::MalformedPayload)?,
            now: pay.now.ok_or(Error::MalformedPayload)?,
        })
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

/// Compute a coz's `czd` (canonical hash + digest) from its payload,
/// signature, and signing algorithm.
///
/// Wraps `coz::canonical_hash_for_alg` + `coz::czd_for_alg` — the two-step
/// computation every trust-boundary call site needs — into a single call.
/// Returns `None` for an unrecognized algorithm, matching the underlying
/// primitives' own idiom.
pub fn compute_czd(pay_json: &[u8], sig: &[u8], alg: &str) -> Option<Czd> {
    let cad = coz::canonical_hash_for_alg(pay_json, alg, None)?;
    coz::czd_for_alg(&cad, sig, alg)
}

/// Verify a coz signature and return a VerifiedCoz.
///
/// Uses coz-rs runtime verification with the key's algorithm. The signed
/// pay must name the verifying key (`pay.alg == key.alg`,
/// `pay.tmb == key.tmb`), and `czd` must equal the digest recomputed from
/// the signed bytes under the key's algorithm: the caller's value is
/// checked, never recorded on trust.
///
/// # Errors
///
/// - `MalformedPayload`: `pay` does not parse
/// - `AlgMismatch`: `pay.alg` is absent or differs from `key.alg`
/// - `UnknownKey`: `pay.tmb` is absent or differs from `key.tmb`
/// - `InvalidSignature`: the signature does not verify
/// - `CzdMismatch`: `czd` is not the digest of (`pay`, `sig`)
pub fn verify_coz(
    pay_json: &[u8],
    sig: &[u8],
    key: &Key,
    czd: Czd,
    new_key: Option<Key>,
) -> Result<VerifiedCoz> {
    let pay: Pay = serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;
    if pay.alg.as_deref() != Some(key.alg()) {
        return Err(Error::AlgMismatch);
    }
    if pay.tmb.as_ref() != Some(key.tmb()) {
        return Err(Error::UnknownKey);
    }

    // Verify the signature
    let valid = coz::verify_json(pay_json, sig, key.alg(), key.pub_key()).unwrap_or(false);
    if !valid {
        return Err(Error::InvalidSignature);
    }

    let computed = compute_czd(pay_json, sig, key.alg())
        .ok_or_else(|| Error::UnsupportedAlgorithm(key.alg().to_owned()))?;
    if computed.as_bytes() != czd.as_bytes() {
        return Err(Error::CzdMismatch);
    }

    // Create the raw CozJson for storage
    let pay_value: serde_json::Value =
        serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;
    let raw = coz::CozJson {
        pay: pay_value,
        sig: sig.to_vec(),
    };

    // Derive hash algorithm from signing key's algorithm
    let hash_alg = crate::state::hash_alg_from_str(key.alg())?;

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

    /// F29: `CozHeader::parse` must reject a coz missing `typ`, `tmb`, or
    /// `now` -- not silently substitute a default -- since callers use it
    /// at a trust boundary specifically to avoid that failure mode.
    #[test]
    fn coz_header_parse_rejects_missing_typ() {
        let mut pay = PayBuilder::new()
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        pay.typ = None;
        let value = serde_json::to_value(&pay).unwrap();

        assert!(matches!(
            CozHeader::parse(&value),
            Err(Error::MalformedPayload)
        ));
    }

    #[test]
    fn coz_header_parse_rejects_missing_tmb() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .now(1000)
            .build();
        let value = serde_json::to_value(&pay).unwrap();

        assert!(matches!(
            CozHeader::parse(&value),
            Err(Error::MalformedPayload)
        ));
    }

    #[test]
    fn coz_header_parse_rejects_missing_now() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
        let value = serde_json::to_value(&pay).unwrap();

        assert!(matches!(
            CozHeader::parse(&value),
            Err(Error::MalformedPayload)
        ));
    }

    #[test]
    fn coz_header_parse_accepts_well_formed_pay() {
        let tmb = Thumbprint::from_bytes(vec![0xAA; 32]);
        let pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(tmb.clone())
            .build();
        let value = serde_json::to_value(&pay).unwrap();

        let header = CozHeader::parse(&value).expect("well-formed pay should parse");
        assert_eq!(header.typ, "cyphr.me/cyphr/key/create");
        assert_eq!(header.tmb, tmb);
        assert_eq!(header.now, 1000);
    }

    #[test]
    fn coz_header_parse_rejects_non_object_pay() {
        let value = serde_json::json!("not an object");
        assert!(matches!(
            CozHeader::parse(&value),
            Err(Error::MalformedPayload)
        ));
    }

    #[test]
    fn parse_key_add() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
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
        pay.extra.insert("id".into(), json!(TEST_ID));

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::KeyReplace { .. }));
    }

    #[test]
    fn parse_self_revoke() {
        let pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(1000)
            .build();

        let czd = Czd::from_bytes(vec![0; 32]);
        let cz = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay)).unwrap();

        assert!(matches!(cz.kind, CozKind::SelfRevoke { rvk: 1000, .. }));
    }

    #[test]
    fn parse_self_revoke_with_id_fails() {
        // id MUST be absent on a self-revoke; its presence is a parse-time error.
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/key/revoke")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .rvk(1000)
            .build();
        pay.extra.insert("id".into(), json!(TEST_ID)); // forbidden

        let czd = Czd::from_bytes(vec![0; 32]);
        let result = ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay));

        assert!(
            matches!(result, Err(Error::MalformedPayload)),
            "expected MalformedPayload when id present on self-revoke, got {:?}",
            result
        );
    }

    #[test]
    fn parse_principal_create() {
        let mut pay = PayBuilder::new()
            .typ("cyphr.me/cyphr/principal/create")
            .alg("ES256")
            .now(1000)
            .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
            .build();
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

    #[test]
    fn typ_is_key_introducing() {
        assert!(typ::is_key_introducing("cyphr.me/cyphr/key/create"));
        assert!(typ::is_key_introducing("cyphr.me/cyphr/key/replace"));
        assert!(!typ::is_key_introducing("cyphr.me/cyphr/key/delete"));
        assert!(!typ::is_key_introducing("cyphr.me/cyphr/key/revoke"));
        assert!(!typ::is_key_introducing("cyphr.me/cyphr/principal/create"));
        assert!(!typ::is_key_introducing("cyphr.me/cyphr/commit/create"));
    }

    /// Backs the typ-classification boundary (SPEC 4.2: typ is
    /// `<authority>/cyphr/...`). Defect that turns it red: classification by
    /// bare `ends_with`, so a typ whose last segment merely ends in the
    /// suffix text (`.../xcyphr/key/create`) is read as `key/create`. Unit
    /// level because the predicate is a pure function and no scenario
    /// reaches every spoof shape cheaply. Not end to end. A lying
    /// implementation that special-cases one spoof string, or that adds the
    /// boundary to `is_key_introducing` only, is caught by the other test.
    /// RED: `is_key_introducing` uses `ends_with` with no `/` boundary.
    #[test]
    #[ignore = "RED(N08): typ suffix match has no path boundary"]
    fn typ_boundary_key_introducing_requires_slash_before_suffix() {
        for spoof in [
            "cyphr.me/xcyphr/key/create",
            "cyphr.me/xcyphr/key/replace",
            "evilcyphr/key/create",
            "a.b/Xcyphr/key/replace",
        ] {
            assert!(
                !typ::is_key_introducing(spoof),
                "{spoof} was classified as key-introducing"
            );
        }
        for ok in ["cyphr.me/cyphr/key/create", "a.b/c/cyphr/key/replace"] {
            assert!(typ::is_key_introducing(ok), "control: {ok} must classify");
        }
    }

    /// Same boundary at the parse site (`ParsedCoz::from_pay`, which every
    /// applied coz passes through). Each spoofed typ carries a well-formed
    /// `id` so the only reason to refuse it is the typ; the genuine typ with
    /// the same payload is the control and must parse to the same kind.
    /// Turns red if a spoofed suffix parses as `KeyCreate`, `KeyDelete` or
    /// `KeyReplace`. Only the three kinds needing nothing but `id` are
    /// exercised: the others could be refused for a missing field, which
    /// would make the assertion hold by construction. Not end to end.
    /// RED: `parse_kind` matches by bare `ends_with`.
    #[test]
    #[ignore = "RED(N08): typ suffix match has no path boundary"]
    fn typ_boundary_spoofed_suffix_does_not_parse_as_a_key_coz() {
        for suffix in [typ::KEY_CREATE, typ::KEY_DELETE, typ::KEY_REPLACE] {
            let parse = |typ_str: String| {
                let mut pay = PayBuilder::new()
                    .typ(typ_str)
                    .alg("ES256")
                    .now(1000)
                    .tmb(Thumbprint::from_bytes(vec![0xAA; 32]))
                    .build();
                pay.extra.insert("id".into(), json!(TEST_ID));
                let czd = Czd::from_bytes(vec![0; 32]);
                ParsedCoz::from_pay(&pay, czd, HashAlg::Sha256, to_raw(&pay))
            };
            parse(format!("cyphr.me/{suffix}"))
                .unwrap_or_else(|e| panic!("control: genuine {suffix} must parse: {e:?}"));
            let spoof = parse(format!("cyphr.me/x{suffix}"));
            assert!(
                matches!(spoof, Err(Error::MalformedPayload)),
                "x{suffix} parsed: {spoof:?}"
            );
        }
    }
}
