//! Completeness of `docs/architecture/record-verification.md`, checked
//! against the code instead of by hand.
//!
//! Claim: the page lists every error the core apply, finalize and record
//! paths can raise, each under the claim that governs it, and every claim is
//! either bound to a runnable test or declared unbound in its own text.
//!
//! Defects that turn it red, each checked by a mutant (see the report of the
//! change that added this file):
//! - a new `cyphr::Error` variant: the exhaustive `match` in [`classify`] stops compiling, and
//!   [`variants`] fails the source count if it is not also constructed there;
//! - a reachable variant with no row in the page's "Errors by claim" table;
//! - a row naming a variant that does not exist, or one classified as outside the core paths;
//! - a row pointing to a claim the page does not define, or pointing to a different claim than
//!   [`classify`] assigns;
//! - a claim marked `evaluator: test` with no `scripts/docket-run` entry or no `@docket:` marker,
//!   or one marked `evaluator: none` that does not declare itself unbound.
//!
//! End to end: no. This is a consistency check between the error enum, the
//! page and the docket wiring; no protocol scenario reaches it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use cyphr::Error;
use cyphr::signer::SignerError;
use cyphr::state::HashAlg;

/// Where a variant stands relative to the core apply, finalize and record
/// paths. The `&str` of `Core` is the id of the page claim that governs it.
enum Reach {
    Core(&'static str),
    Outside(&'static str),
}

/// Exhaustive on purpose: no wildcard arm, so a new `Error` variant fails to
/// compile here until someone classifies it.
fn classify(e: &Error) -> Reach {
    use Reach::{Core, Outside};
    match e {
        Error::Signer(_) => Core("rv-signer-faults"),
        Error::InvalidSignature => Core("rv-sig-verifies"),
        Error::UnknownKey => Core("rv-key-active-gate"),
        Error::UnknownAlg => Core("rv-alg-support"),
        Error::TimestampPast => Core("rv-timestamp-monotone"),
        Error::TimestampFuture => Core("rv-timestamp-future"),
        Error::KeyRevoked => Core("rv-key-active-gate"),
        Error::MalformedPayload => Core("rv-coz-wellformed"),
        Error::TmbMismatch => Core("rv-key-material"),
        Error::AlgMismatch => Core("rv-alg-alignment"),
        Error::CzdMismatch => Core("rv-alg-alignment"),
        Error::DuplicateKey => Core("rv-key-set"),
        Error::CozReuse => Core("rv-no-coz-reuse"),
        Error::StateMismatch => Core("rv-genesis-immutable"),
        Error::EmptyMultihash => Core("rv-internal-invariants"),
        Error::MissingVariant(_) => Core("rv-internal-invariants"),
        Error::NoActiveKeys => Core("rv-key-set"),
        Error::AlreadyDeleted => Core("rv-lifecycle-gate"),
        Error::AlreadyFrozen => Core("rv-lifecycle-transitions"),
        Error::NotFrozen => Core("rv-lifecycle-transitions"),
        Error::Frozen => Core("rv-lifecycle-gate"),
        Error::MixedTransactionTyp => Core("rv-intra-commit-shape"),
        Error::UnsupportedAlgorithm(_) => Core("rv-alg-support"),
        Error::Storage(_) => Core("rv-storage-backend"),
        Error::CollectionArityExceeded(_) => Core("rv-key-arity"),
        Error::EmptyCommit => Core("rv-commit-nonempty"),
        Error::CommitNotLast => Core("rv-intra-commit-shape"),
        Error::MissingCommit => Core("rv-commit-nonempty"),
        Error::CommitMismatch => Core("rv-arrow-chain"),
        Error::DurableLeafMismatch(_) => Core("rv-storage-backend"),
        Error::MalformedDigest(_) => Core("rv-digest-wellformed"),
        Error::DigestLengthMismatch { .. } => Core("rv-digest-wellformed"),
        // The `From<coz::Error>` impl exists for callers. Removing its
        // `#[from]` attribute leaves `cargo check -p cyphr` clean, so no
        // `?` in the core converts a coz error into this variant.
        Error::Coz(_) => Outside("no core path converts a coz::Error"),
    }
}

/// One instance of every variant. [`variants_cover_the_enum_source`] checks
/// this list against the enum's source text, so an unlisted variant fails
/// there even though the exhaustive match above already refuses to compile.
fn variants() -> Vec<Error> {
    vec![
        Error::Signer(SignerError::Backend(String::new())),
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
        Error::CozReuse,
        Error::StateMismatch,
        Error::EmptyMultihash,
        Error::MissingVariant(HashAlg::Sha256),
        Error::NoActiveKeys,
        Error::AlreadyDeleted,
        Error::AlreadyFrozen,
        Error::NotFrozen,
        Error::Frozen,
        Error::MixedTransactionTyp,
        Error::UnsupportedAlgorithm(String::new()),
        Error::Storage(String::new()),
        Error::CollectionArityExceeded(0),
        Error::EmptyCommit,
        Error::CommitNotLast,
        Error::MissingCommit,
        Error::CommitMismatch,
        Error::DurableLeafMismatch(0),
        Error::MalformedDigest(""),
        Error::DigestLengthMismatch {
            alg: HashAlg::Sha256,
            expected: 0,
            actual: 0,
        },
        Error::Coz(coz::Error::SignatureVerification),
    ]
}

/// The variant's name: its `Debug` text up to the first field.
fn name(e: &Error) -> String {
    let d = format!("{e:?}");
    d.split(['(', ' ', '{']).next().unwrap_or("").to_owned()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

const PAGE: &str = "docs/architecture/record-verification.md";

/// `variant name -> claim id` from the page's "Errors by claim" table.
fn page_rows(page: &str) -> Vec<(String, String)> {
    let start = page
        .find("\n## Errors by claim")
        .expect("page has an 'Errors by claim' section");
    let rest = &page[start + 1..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    rest[..end]
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let ticked = |c: &str| c.trim_matches('`').to_owned();
            (ticked(cells[1]), ticked(cells[2]))
        })
        .collect()
}

/// `claim id -> evaluator` and the claim's section text, for every
/// `#### [id]` heading on the page.
fn page_claims(page: &str) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    let heads: Vec<(usize, String)> = page
        .match_indices("\n#### [")
        .map(|(i, _)| {
            let id: String = page[i + 7..].chars().take_while(|c| *c != ']').collect();
            (i, id)
        })
        .collect();
    for (i, id) in &heads {
        // A claim's section ends at the next heading of any level.
        let end = ["\n#### ", "\n### ", "\n## "]
            .iter()
            .filter_map(|h| page[*i + 1..].find(h).map(|k| i + 1 + k))
            .min()
            .unwrap_or(page.len());
        let body = &page[*i..end];
        let ev = body
            .lines()
            .find_map(|l| l.strip_prefix("evaluator: "))
            .unwrap_or_else(|| panic!("claim {id} has no evaluator line"))
            .trim()
            .to_owned();
        out.insert(id.clone(), (ev, body.to_owned()));
    }
    out
}

#[test]
fn variants_cover_the_enum_source() {
    let src = read("rs/cyphr/src/error.rs");
    let body = src
        .split("pub enum Error {")
        .nth(1)
        .and_then(|b| b.split("\n}\n").next())
        .expect("error.rs defines `pub enum Error`");
    let declared: BTreeSet<String> = body
        .lines()
        .filter(|l| l.starts_with("    ") && l[4..].starts_with(|c: char| c.is_ascii_uppercase()))
        .map(|l| {
            l[4..]
                .split(['(', ' ', '{', ','])
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    let listed: BTreeSet<String> = variants().iter().map(name).collect();
    assert_eq!(
        declared, listed,
        "variants() must construct exactly the variants error.rs declares"
    );
}

#[test]
fn every_reachable_error_has_a_row_and_every_row_names_one() {
    let page = read(PAGE);
    let rows = page_rows(&page);
    let claims = page_claims(&page);

    let mut expected: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut outside: BTreeMap<String, &'static str> = BTreeMap::new();
    for e in variants() {
        match classify(&e) {
            Reach::Core(id) => {
                expected.insert(name(&e), id);
            },
            Reach::Outside(why) => {
                assert!(!why.is_empty(), "{} is outside with no reason", name(&e));
                outside.insert(name(&e), why);
            },
        }
    }

    let mut seen = BTreeSet::new();
    for (variant, claim) in &rows {
        assert!(
            !outside.contains_key(variant),
            "row `{variant}` is for an error classified outside the core paths ({})",
            outside[variant]
        );
        let want = expected
            .get(variant)
            .unwrap_or_else(|| panic!("row `{variant}` names no cyphr::Error variant"));
        assert_eq!(
            claim, want,
            "row `{variant}` points to `{claim}`, classify() assigns `{want}`"
        );
        assert!(
            claims.contains_key(claim),
            "row `{variant}` points to `{claim}`, which the page does not define"
        );
        assert!(
            seen.insert(variant.clone()),
            "duplicate row for `{variant}`"
        );
    }
    for variant in expected.keys() {
        assert!(
            seen.contains(variant),
            "reachable error `{variant}` has no row in 'Errors by claim'"
        );
    }
}

#[test]
fn every_claim_is_bound_or_declared_unbound() {
    let page = read(PAGE);
    let script = read("scripts/docket-run");
    let markers = {
        let dir = repo_root().join("rs/cyphr/tests");
        let mut all = String::new();
        for entry in fs::read_dir(&dir).expect("tests dir") {
            let p = entry.expect("entry").path();
            if p.extension().is_some_and(|x| x == "rs") {
                all.push_str(&fs::read_to_string(&p).expect("read test file"));
            }
        }
        all
    };

    for (id, (evaluator, body)) in page_claims(&page) {
        match evaluator.as_str() {
            "test" => {
                assert!(
                    script.contains(&format!("[{id}]=")),
                    "claim {id} is `evaluator: test` but scripts/docket-run has no entry"
                );
                assert!(
                    markers.contains(&format!("// @docket: {id} :: scripts/docket-run {id}")),
                    "claim {id} is `evaluator: test` but no test carries its @docket marker"
                );
            },
            "none" => assert!(
                body.contains("Unbound."),
                "claim {id} is `evaluator: none` but does not declare itself unbound"
            ),
            other => panic!("claim {id} has unexpected evaluator {other}"),
        }
    }
}
