//! The signer of a commit is the closing `commit/create`'s, and nothing
//! else: a bundle with no `commit/create` has no commit signer (SPEC has
//! no "else the last coz" rule), so no caller can index or judge it under
//! a signer the protocol never named.
//!
//! Property: over any sequence of cozies, `commit_signer` is the signer of
//! the last `commit/create` among them, and `None` when there is none.
//!
//! Red before the fallback is cut: a sequence with no `commit/create`
//! returns the last coz's signer.

use cyphr::replay::commit_signer;
use proptest::prelude::*;

const TYPS: [&str; 5] = [
    "cyphr.me/cyphr/key/create",
    "cyphr.me/cyphr/key/revoke",
    "cyphr.me/cyphr/principal/create",
    "cyphr.me/cyphr/commit/create",
    "cyphr.me/cyphr/nonce/create",
];

proptest! {
    #[test]
    fn the_signer_is_the_last_commit_create_or_none(
        kinds in prop::collection::vec(0..TYPS.len(), 0..8)
    ) {
        let cozies: Vec<(&str, usize)> =
            kinds.iter().enumerate().map(|(i, &k)| (TYPS[k], i)).collect();
        let expected = cozies
            .iter()
            .rev()
            .find(|(typ, _)| typ.ends_with("/commit/create"))
            .map(|&(_, signer)| signer);
        prop_assert_eq!(commit_signer(cozies.iter().copied()), expected);
    }
}
