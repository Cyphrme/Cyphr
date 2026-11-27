//! No constructor of `PrincipalGenesis` yields a value with no variants
//! (FIX-FRAME node ID: the field is private and every constructor refuses
//! an empty value, so `Display` never prints an empty string).
//!
//! The constructors are `from_digest`, `from_initial` and `FromStr`. The
//! first and last reach an empty value only through an empty digest, which
//! the width check refuses. `from_initial` is the one that can be handed a
//! `PrincipalRoot` with no variants (`PrincipalRoot::default()` is empty),
//! so it must return a `Result` and refuse it with `EmptyMultihash`.
//!
//! The "cannot be written from outside the crate" half is the
//! `compile_fail` doctests on `PrincipalGenesis` in `src/state.rs`.
//!
//! Red before ID: `from_initial` returns `Self`, so the `Result` methods
//! used below do not exist (a compile error naming `from_initial`'s
//! return type).

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::state::{HASH_ALGS, HashAlg};
use cyphr::{Error, MultihashDigest, PrincipalGenesis, PrincipalRoot};
use proptest::prelude::*;

fn algs() -> impl Strategy<Value = HashAlg> {
    proptest::sample::select(HASH_ALGS.to_vec())
}

#[test]
fn from_initial_refuses_a_root_with_no_variants() {
    let err = PrincipalGenesis::from_initial(&PrincipalRoot::default())
        .expect_err("an empty root must not become a genesis");
    assert!(matches!(err, Error::EmptyMultihash), "{err:?}");
}

proptest! {
    /// From any non-empty root the genesis is built, prints a labelled
    /// non-empty id, and that id parses back to an equal value.
    #[test]
    fn from_initial_on_a_real_root_prints_a_non_empty_id_that_round_trips(
        (alg, bytes) in algs().prop_flat_map(|a| {
            (Just(a), proptest::collection::vec(any::<u8>(), a.digest_size()))
        })
    ) {
        let root = PrincipalRoot(MultihashDigest::from_single(alg, bytes.clone()).expect("width"));
        let pg = PrincipalGenesis::from_initial(&root).expect("a non-empty root");
        let text = pg.to_string();
        prop_assert_eq!(
            &text,
            &format!("{}:{}", alg, Base64UrlUnpadded::encode_string(&bytes))
        );
        prop_assert_eq!(text.parse::<PrincipalGenesis>().expect("parses"), pg);
    }

    /// A digest of any width but the algorithm's, the empty one included,
    /// is refused by `from_digest`; so is the labelled spelling of it by
    /// `FromStr`. Neither can yield a value, so none prints as empty.
    #[test]
    fn from_digest_and_from_str_refuse_any_wrong_width_digest(
        alg in algs(),
        len in 0usize..130,
    ) {
        prop_assume!(len != alg.digest_size());
        let bytes = vec![7u8; len];
        prop_assert!(PrincipalGenesis::from_digest(alg, bytes.clone()).is_err());
        let text = format!("{}:{}", alg, Base64UrlUnpadded::encode_string(&bytes));
        prop_assert!(text.parse::<PrincipalGenesis>().is_err(), "{text}");
    }
}

#[test]
fn from_str_refuses_the_empty_and_the_label_only_spellings() {
    for text in ["", ":", "SHA-256:", "SHA-512:", "ALG:"] {
        assert!(text.parse::<PrincipalGenesis>().is_err(), "{text:?}");
    }
}
