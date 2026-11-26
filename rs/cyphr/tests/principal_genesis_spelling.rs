//! One principal-id spelling: `PrincipalGenesis` parses and prints the
//! labelled form `ALG:digest` and nothing else (CLOSE-DECISIONS D5/Q1:
//! "labelled only ... a bare id is refused ... no width-guessing").
//!
//! Properties, for every supported hash algorithm and arbitrary digest
//! bytes of its width:
//! - print then parse is the identity, and the printed form is the label,
//!   a colon and the unpadded base64url digest, computed here without the
//!   code under test;
//! - the same digest without its label is refused, as is a label the
//!   digest's width does not match and a label that names no algorithm
//!   (the guess a bare normalizer makes from the width must never be made
//!   by the parser).
//!
//! The text of the refusal ("shows the labelled form") is not pinned: the
//! frame gives no wording.
//!
//! Red before K1: `PrincipalGenesis` has neither `FromStr` nor `Display`.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::{HASH_ALGS, HashAlg};
use cyphr::PrincipalGenesis;
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
