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

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

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
#[derive(Debug, Clone, Serialize)]
pub struct Envelope<T> {
    /// Wire version, present in both signed and unsigned forms.
    pub v: u32,
    /// The endpoint-specific response payload.
    pub payload: T,
    /// The server statement slot, always present and explicitly tagged.
    pub statement: Statement,
}

// The statement slot is defined once, in the client crate every verifier
// already depends on, so the wire type the server writes and the one a
// client reads cannot drift apart.
pub use cyphr_client::Statement;

/// Why an envelope could not be read.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// The envelope states a wire version this build does not read; nothing
    /// of its payload was decoded. The text names the variant so a refusal
    /// that crosses a serde boundary (flattened to a message) stays
    /// identifiable.
    #[error(
        "UnsupportedVersion: envelope version {found} is not the supported {supported}; refusing \
         to read it"
    )]
    UnsupportedVersion {
        /// The version the document states.
        found: u64,
        /// The one version this build reads.
        supported: u32,
    },
    /// The document is not an envelope of the expected shape.
    #[error("malformed envelope: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// The envelope body without its version, which is checked first so a
/// future version's differently shaped payload reads as an unsupported
/// version, never as a malformed one.
#[derive(Deserialize)]
struct Body<T> {
    payload: T,
    statement: Statement,
}

impl<T: DeserializeOwned> Envelope<T> {
    /// Read an envelope from a JSON value, refusing any version other than
    /// [`ENVELOPE_VERSION`] before the payload is decoded.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnsupportedVersion`] for an unknown `v`;
    /// [`EnvelopeError::Malformed`] when `v` is missing or the document has
    /// the wrong shape.
    pub fn from_value(value: serde_json::Value) -> Result<Self, EnvelopeError> {
        let found = value
            .get("v")
            .ok_or_else(|| <serde_json::Error as serde::de::Error>::missing_field("v"))?
            .as_u64()
            .ok_or_else(|| {
                <serde_json::Error as serde::de::Error>::custom("`v` is not an unsigned integer")
            })?;
        if found != u64::from(ENVELOPE_VERSION) {
            return Err(EnvelopeError::UnsupportedVersion {
                found,
                supported: ENVELOPE_VERSION,
            });
        }
        let Body { payload, statement } = serde_json::from_value(value)?;
        Ok(Self {
            v: ENVELOPE_VERSION,
            payload,
            statement,
        })
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Envelope<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
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

    // ====================================================================
    // Round-trip properties (proptest)
    // ====================================================================

    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    /// A stand-in payload for round-trip coverage. The envelope is generic
    /// over its payload; a small concrete type exercises the container
    /// without coupling these tests to any route's response struct.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct DemoPayload {
        principal_id: String,
        commit_count: u64,
    }

    prop_compose! {
        /// An arbitrary coz `{pay, sig}`: a small object payload and
        /// arbitrary signature bytes (base64url on the wire).
        fn arb_coz()(
            typ in ".*",
            now in any::<i64>(),
            sig in prop::collection::vec(any::<u8>(), 0..80),
        ) -> coz::CozJson {
            coz::CozJson {
                pay: serde_json::json!({ "typ": typ, "now": now }),
                sig,
            }
        }
    }

    fn arb_statement() -> impl Strategy<Value = Statement> {
        prop_oneof![
            Just(Statement::Unsigned),
            arb_coz().prop_map(Statement::Signed)
        ]
    }

    prop_compose! {
        fn arb_envelope()(
            v in Just(ENVELOPE_VERSION),
            principal_id in ".*",
            commit_count in any::<u64>(),
            statement in arb_statement(),
        ) -> Envelope<DemoPayload> {
            Envelope {
                v,
                payload: DemoPayload { principal_id, commit_count },
                statement,
            }
        }
    }

    proptest! {
        /// Serializing then parsing then re-serializing is the identity on
        /// the wire, for both forms. Wire idempotence is the meaningful
        /// property (coz carries no `PartialEq`, so value equality is not
        /// available); it catches any asymmetry between the serialize and
        /// deserialize paths.
        #[test]
        fn envelope_round_trips_on_the_wire(env in arb_envelope()) {
            let wire = serde_json::to_string(&env).unwrap();
            let parsed: Envelope<DemoPayload> = serde_json::from_str(&wire).unwrap();
            let rewire = serde_json::to_string(&parsed).unwrap();
            prop_assert_eq!(wire, rewire);
        }

        /// Any version other than the current one is refused, whatever the
        /// payload, as the typed variant carrying the offending number.
        #[test]
        fn envelope_of_another_version_is_refused(
            mut env in arb_envelope(),
            v in any::<u32>().prop_filter("the current version", |v| *v != ENVELOPE_VERSION),
        ) {
            env.v = v;
            let wire = serde_json::to_value(&env).unwrap();
            let refused = Envelope::<DemoPayload>::from_value(wire).err();
            prop_assert!(
                matches!(
                    refused,
                    Some(EnvelopeError::UnsupportedVersion { found, .. }) if found == u64::from(v)
                ),
                "{:?}", refused
            );
        }

        /// The load-bearing fields -- the version and the signed/unsigned
        /// discriminant -- survive a round trip unchanged.
        #[test]
        fn version_and_signed_flag_survive_round_trip(env in arb_envelope()) {
            let wire = serde_json::to_string(&env).unwrap();
            let parsed: Envelope<DemoPayload> = serde_json::from_str(&wire).unwrap();
            prop_assert_eq!(parsed.v, env.v);
            prop_assert_eq!(parsed.is_signed(), env.is_signed());
            prop_assert_eq!(parsed.payload, env.payload);
        }
    }
}
