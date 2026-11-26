//! `Error::name` is the one vocabulary for refusal names (the golden
//! corpus, the storage e2e table, the fixture generator all read it).
//!
//! Property: for every variant, the name is the variant's own identifier,
//! whatever its payload. That ties the name to the enum itself instead of
//! to a second table, so a table that drifts from the enum (as the two
//! hand-kept `match`es with a catch-all arm do) fails here.
//! The exhaustiveness half (a new variant must not compile without a
//! name) is the missing-wildcard-arm in `Error::name`; no test outside
//! the crate can observe it.
//!
//! Red before K1: `Error::name` does not exist.

use cyphr::Error;
use cyphr::state::HashAlg;

/// One value of every variant, with the payloads that exist. A new
/// variant is added here by hand.
fn variants() -> Vec<Error> {
    vec![
        Error::Signer(cyphr::signer::SignerError::Backend("x".into())),
        Error::InvalidSignature,
        Error::UnknownKey,
        Error::UnknownAlg,
        Error::TimestampPast,
        Error::TimestampFuture,
        Error::KeyRevoked,
        Error::MalformedPayload,
        Error::TmbMismatch,
        Error::AlgMismatch,
        Error::CzdMismatch,
        Error::DuplicateKey,
        Error::DuplicatePrincipal,
        Error::DuplicateNonce,
        Error::UnknownNonce,
        Error::CozReuse,
        Error::StateMismatch,
        Error::EmptyMultihash,
        Error::MissingVariant(HashAlg::Sha256),
        Error::NoActiveKeys,
        Error::AlreadyDeleted,
        Error::AlreadyFrozen,
        Error::NotFrozen,
        Error::Frozen,
        Error::EmbeddedErrored,
        Error::MixedTransactionTyp,
        Error::LoneGroupedTransaction,
        Error::UnsupportedAlgorithm("x".into()),
        Error::Storage("x".into()),
        Error::EmptyCommit,
        Error::GenesisIncomplete,
        Error::CommitNotLast,
        Error::MissingCommit,
        Error::CommitMismatch,
        Error::DurableLeafMismatch(7),
        Error::MalformedDigest("x"),
        Error::DigestLengthMismatch {
            alg: HashAlg::Sha256,
            expected: 32,
            actual: 1,
        },
        Error::Coz(coz::Error::SignatureVerification),
    ]
}

/// The variant identifier from a `Debug` rendering: everything before the
/// first payload delimiter.
fn identifier(e: &Error) -> String {
    format!("{e:?}")
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_name_is_the_variants_own_identifier() {
    for e in variants() {
        assert_eq!(e.name(), identifier(&e), "{e:?}");
    }
}

#[test]
fn names_are_distinct() {
    let names: Vec<&str> = variants().iter().map(Error::name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "two variants share a name");
}

/// The name does not depend on the payload (metamorphic: same variant,
/// different payload, same name).
#[test]
fn a_name_ignores_the_payload() {
    assert_eq!(
        Error::UnsupportedAlgorithm("a".into()).name(),
        Error::UnsupportedAlgorithm("b".into()).name()
    );
    assert_eq!(
        Error::DurableLeafMismatch(1).name(),
        Error::DurableLeafMismatch(2).name()
    );
}
