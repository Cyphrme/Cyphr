//! One principal-id spelling: `PrincipalGenesis` parses and prints the
//! labelled form `ALG:digest` and nothing else (CLOSE-DECISIONS D5/Q1:
//! "labelled only ... a bare id is refused ... no width-guessing").
//!
//! Properties, for every supported hash algorithm and arbitrary digest
//! bytes of its width:
//! - print then parse is the identity, and the printed form is the label, a colon and the unpadded
//!   base64url digest, computed here without the code under test;
//! - the same digest without its label is refused, as is a label the digest's width does not match
//!   and a label that names no algorithm (the guess a bare normalizer makes from the width must
//!   never be made by the parser).
//!
//! The architect's exact contracts (FIX-FRAME 2.2) add:
//! - a string with no `:` is refused with exactly `MalformedDigest("unlabelled principal id:
//!   ...")`, before any decoding;
//! - `Display` of a value holding several variants prints the first in `HashAlg` order (SHA-256,
//!   SHA-384, SHA-512);
//! - equality across spellings is `MultihashDigest::matches`: a value printed and parsed back
//!   matches the original, and a different digest does not.
//!
//! Red before K1: `PrincipalGenesis` has neither `FromStr` nor `Display`.

use std::collections::BTreeMap;

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::{HASH_ALGS, HashAlg};
use cyphr::{Error, MultihashDigest, PrincipalGenesis, StateDigest};
use proptest::prelude::*;

fn digest(alg: HashAlg) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), alg.digest_size())
}

fn algs() -> impl Strategy<Value = HashAlg> {
    proptest::sample::select(HASH_ALGS.to_vec())
}

proptest! {
    #[test]
    fn print_then_parse_is_the_identity(
        (alg, bytes) in algs().prop_flat_map(|a| (Just(a), digest(a)))
    ) {
        let pg = PrincipalGenesis::from_digest(alg, bytes.clone()).expect("right width");
        let text = pg.to_string();
        prop_assert_eq!(&text, &format!("{}:{}", alg, Base64UrlUnpadded::encode_string(&bytes)));
        prop_assert_eq!(text.parse::<PrincipalGenesis>().expect("parses"), pg);
    }

    #[test]
    fn a_bare_or_mislabelled_id_is_refused(
        (alg, bytes) in algs().prop_flat_map(|a| (Just(a), digest(a))),
        other in algs(),
    ) {
        let b64 = Base64UrlUnpadded::encode_string(&bytes);
        prop_assert!(b64.parse::<PrincipalGenesis>().is_err(), "bare id parsed");
        let unknown = format!("NOPE-1:{b64}");
        prop_assert!(unknown.parse::<PrincipalGenesis>().is_err());
        let empty = format!(":{b64}");
        prop_assert!(empty.parse::<PrincipalGenesis>().is_err());
        if other.digest_size() != alg.digest_size() {
            let wrong_width = format!("{other}:{b64}");
            prop_assert!(wrong_width.parse::<PrincipalGenesis>().is_err());
        }
    }
}

const UNLABELLED: &str =
    "unlabelled principal id: expected ALG:digest, for example SHA-256:<base64url>";

proptest! {
    #[test]
    fn an_unlabelled_id_is_refused_with_the_labelled_form(
        (alg, bytes) in algs().prop_flat_map(|a| (Just(a), digest(a)))
    ) {
        let bare = Base64UrlUnpadded::encode_string(&bytes);
        let _ = alg;
        let err = bare.parse::<PrincipalGenesis>().expect_err("bare id parsed");
        prop_assert!(matches!(err, Error::MalformedDigest(m) if m == UNLABELLED), "{err:?}");
    }

    /// A value holding SHA-256 and SHA-512 variants prints the SHA-256
    /// one; one holding SHA-384 and SHA-512 prints SHA-384. Parsing the
    /// printed form gives a value that matches the original, and flipping
    /// one byte of the printed digest does not.
    #[test]
    fn display_prints_the_first_variant_and_matches_across_spellings(
        d256 in digest(HashAlg::Sha256),
        d384 in digest(HashAlg::Sha384),
        d512 in digest(HashAlg::Sha512),
    ) {
        let multi = |a: (HashAlg, &Vec<u8>), b: (HashAlg, &Vec<u8>)| {
            let map: BTreeMap<HashAlg, Box<[u8]>> = [a, b]
                .into_iter()
                .map(|(alg, d)| (alg, d.clone().into_boxed_slice()))
                .collect();
            PrincipalGenesis::from_multihash(MultihashDigest::new(map).expect("variants")).expect("non-empty")
        };
        for (pg, first, first_bytes) in [
            (multi((HashAlg::Sha256, &d256), (HashAlg::Sha512, &d512)), HashAlg::Sha256, &d256),
            (multi((HashAlg::Sha384, &d384), (HashAlg::Sha512, &d512)), HashAlg::Sha384, &d384),
        ] {
            let text = pg.to_string();
            prop_assert_eq!(
                &text,
                &format!("{}:{}", first, Base64UrlUnpadded::encode_string(first_bytes))
            );
            let parsed = text.parse::<PrincipalGenesis>().expect("parses");
            prop_assert!(parsed.as_multihash().matches(pg.as_multihash()));
            let mut other = first_bytes.clone();
            other[0] ^= 1;
            let other = PrincipalGenesis::from_digest(first, other).expect("width");
            prop_assert!(!other.as_multihash().matches(pg.as_multihash()));
        }
    }
}

/// A genesis holding a SHA-256 and a SHA-512 variant (a mixed-algorithm
/// keyset): the digests are fixed bytes so the printed id is pinned.
fn mixed() -> PrincipalGenesis {
    let map: BTreeMap<HashAlg, Box<[u8]>> = [
        (HashAlg::Sha256, vec![1u8; 32].into_boxed_slice()),
        (HashAlg::Sha512, vec![2u8; 64].into_boxed_slice()),
    ]
    .into_iter()
    .collect();
    PrincipalGenesis::from_multihash(MultihashDigest::new(map).expect("variants"))
        .expect("non-empty")
}

/// The canonical spelling of a mixed-algorithm genesis, by value: the
/// first variant in `HashAlg`'s order, SHA-256 here. A change of this
/// string changes every stored and printed id of such a principal.
#[test]
fn a_mixed_algorithm_genesis_prints_its_sha256_variant() {
    assert_eq!(
        mixed().to_string(),
        "SHA-256:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    );
}

/// Equality, hash and order are on the canonical spelling: the value equals
/// the id parsed from its own printed form, and the two hash alike.
#[test]
fn a_mixed_algorithm_genesis_equals_its_printed_then_parsed_form() {
    use std::hash::{BuildHasher, RandomState};
    let pg = mixed();
    let parsed: PrincipalGenesis = pg.to_string().parse().expect("parses");
    assert_eq!(pg, parsed);
    assert_eq!(pg.cmp(&parsed), std::cmp::Ordering::Equal);
    let state = RandomState::new();
    assert_eq!(state.hash_one(&pg), state.hash_one(&parsed));
    // The SHA-512 variant alone is another id, not this one.
    let second = PrincipalGenesis::from_digest(HashAlg::Sha512, vec![2u8; 64]).expect("width");
    assert_ne!(pg, second);
}
