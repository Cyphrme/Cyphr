//! Versioned HTTP response envelope (`docs/specs/http-envelope.md`).
//!
//! Every JSON response body is an [`Envelope`]: an explicit wire
//! [version](ENVELOPE_VERSION), the endpoint payload, and an always-present
//! [`Statement`] slot. The statement is tagged by `kind`, so a signed
//! response (`{"kind":"signed","coz":{...}}`) and an unsigned one
//! (`{"kind":"unsigned"}`) are distinguishable by structure, never by the
//! absence of a signature a client could misread as attestation.
//!
//! This module is the container only. It does not wrap any handler's
//! response, does not sign anything, and does not define what a signed
//! statement's payload claims -- the golden-vector signed `pay` is
//! illustrative. See `docs/specs/http-envelope.md`.

use serde::{Deserialize, Serialize};

/// The current envelope wire version.
///
/// Clients gate on this integer and treat an unrecognized value as the
/// migration signal (`docs/specs/http-envelope.md`, ruling
/// `[envelope-r-migration]`); every future envelope change bumps it.
pub const ENVELOPE_VERSION: u32 = 1;

/// A versioned HTTP response envelope wrapping an endpoint `payload`.
///
/// Construct with [`Envelope::unsigned`] or [`Envelope::signed`]; both
/// stamp the current [`ENVELOPE_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// Wire version, present in both signed and unsigned forms.
    pub v: u32,
    /// The endpoint-specific response payload.
    pub payload: T,
    /// The server statement slot, always present and explicitly tagged.
    pub statement: Statement,
}

/// The server statement over a response.
///
/// Present in every envelope and discriminated by `kind`, so trust is
/// decided by reading the tag, never by probing for a signature. The
/// signed form nests a pristine coz (`{pay, sig}`) under `coz`, byte
/// identical to a standalone coz so a verifier can lift it out unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "coz", rename_all = "lowercase")]
pub enum Statement {
    /// No server attestation -- an affirmative marker, not an absence.
    Unsigned,
    /// A server-signed coz (`{pay, sig}`) over the response.
    Signed(coz::CozJson),
}

impl<T> Envelope<T> {
    /// Wrap `payload` at the current version with no server statement.
    pub fn unsigned(payload: T) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            payload,
            statement: Statement::Unsigned,
        }
    }

    /// Wrap `payload` at the current version with a server-signed coz.
    pub fn signed(payload: T, coz: coz::CozJson) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            payload,
            statement: Statement::Signed(coz),
        }
    }

    /// Whether this envelope carries a server statement.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        matches!(self.statement, Statement::Signed(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dummy coz for structural tests: a valid `{pay, sig}` shape whose
    /// signature is not checked here (byte-exact signing is the golden
    /// vectors' job).
    fn dummy_coz() -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::json!({ "typ": "cyphr-server/statement", "now": 1 }),
            sig: vec![0xAB, 0xCD, 0xEF],
        }
    }

    #[test]
    fn both_forms_are_constructible_and_distinguishable() {
        let unsigned = Envelope::unsigned("payload");
        let signed = Envelope::signed("payload", dummy_coz());

        assert!(
            !unsigned.is_signed(),
            "unsigned envelope must report unsigned"
        );
        assert!(signed.is_signed(), "signed envelope must report signed");
    }

    #[test]
    fn version_is_present_in_both_forms() {
        let unsigned = serde_json::to_value(Envelope::unsigned("p")).unwrap();
        let signed = serde_json::to_value(Envelope::signed("p", dummy_coz())).unwrap();

        assert_eq!(unsigned["v"], serde_json::json!(ENVELOPE_VERSION));
        assert_eq!(signed["v"], serde_json::json!(ENVELOPE_VERSION));
    }

    #[test]
    fn forms_differ_by_explicit_kind_not_by_omission() {
        let unsigned = serde_json::to_value(Envelope::unsigned("p")).unwrap();
        let signed = serde_json::to_value(Envelope::signed("p", dummy_coz())).unwrap();

        // A client decides trust by reading statement.kind, never by
        // probing for a sig: the unsigned form carries an affirmative
        // "unsigned" marker, not a missing field.
        assert_eq!(unsigned["statement"]["kind"], serde_json::json!("unsigned"));
        assert_eq!(signed["statement"]["kind"], serde_json::json!("signed"));

        // The unsigned form is not merely the signed form with its coz
        // stripped: it has no coz slot at all, and its kind stands on its
        // own.
        assert!(
            unsigned["statement"]["coz"].is_null(),
            "unsigned statement must not carry a coz"
        );
        assert!(
            signed["statement"]["coz"].is_object(),
            "signed statement must nest a coz object"
        );
    }

    #[test]
    fn signed_coz_is_lifted_out_unchanged() {
        let coz = dummy_coz();
        let signed = serde_json::to_value(Envelope::signed("p", coz.clone())).unwrap();

        // The nested coz is a pristine {pay, sig}: byte-identical to a
        // standalone coz, so a verifier can extract it directly.
        let nested = &signed["statement"]["coz"];
        assert_eq!(nested["pay"], coz.pay);
        assert!(nested["sig"].is_string(), "coz sig serializes as base64url");
    }
}
