//! Acceptance test suite for Node ND: Typed Witness-Surface Domain.
//!
//! Evaluates criteria ND.1, ND.2a, ND.2b, ND.2c, ND.4
//! (`.scratch/campaigns/server-witness-remediation/ibcs/ND-typed-witness-domain.md`,
//! S5):
//! - `sequence_canonicalizes_across_representations` (ND.1): `sequence` canonicalizes across JSON
//!   number/string representations; a `pr` genesis-identifier string parses to `coz::Thumbprint`.
//! - `malformed_report_is_not_a_silent_escape` (ND.2a): the boundary-side property -- a
//!   validly-signed report that fails to canonicalize is REJECTED AND DIAGNOSED as a verdict
//!   distinct from every "no equivocation occurred" outcome an honest pair can produce.
//! - `canonical_pair_compared_by_value` (ND.2b): the passing-through property -- everything that
//!   clears the boundary is compared by typed value, regardless of JSON representation.
//! - `pr_array_wrap_is_loud_not_unwrapped` (ND.2c): the field-disposition ruling for
//!   `pr`/`commit_id` -- non-digest encodings (array-wrap, number, null) are rejected loudly, never
//!   unwrapped.
//! - `receipt_rejects_malformed_digest` (ND.4): receipt construction cannot sign a malformed digest
//!   into `pr`/`commit_id`/`roots`.
//!
//! **Amendment A2 (`ND-typed-witness-domain.md`) retypes `pr`:** the
//! top-level `pr` is the attested principal's GENESIS IDENTIFIER, SPEC
//! §2.2.3's DEFAULT (untagged) identifier form -- NOT a `TaggedDigest`,
//! which remains `commit_id`/`roots`'s labeled exemption. This file's
//! fixtures use [`principal_digest`] (bare) for `pr` and [`digest_string`]
//! (tagged) for `commit_id`/`roots`; the two are never interchangeable.
//!
//! This node introduces `cyphr_server::receipt::TipReport` (a typed
//! tip-report with a canonical parse, S3) and a new, distinct
//! "malformed" outcome from `check_equivocation`; NEITHER exists in the
//! implementation these tests run against, so the whole file is RED via
//! compile failure until the implementation walk lands them, EXCEPT
//! `receipt_rejects_malformed_digest`, which references only the
//! currently-existing `receipt::tip_report`/`Roots` and was empirically
//! confirmed to fail at RUNTIME against the unmodified implementation
//! (scratch check, not committed: `tip_report` returns `Some` for a
//! `Roots.pr` of `"not-a-digest-at-all"`) before this test was written.
//!
//! Design choices this node's test-worker made (S6 DELEGATED items,
//! reasoning logged per the IBC's requirement):
//! - `TipReport` and its parse live in `cyphr_server::receipt` (S4's first option), as a plain
//!   struct with public fields: `pr: coz::Thumbprint` (A2), `commit_id: TaggedDigest`, `sequence:
//!   u64`, `roots: TipReportRoots { pr, sr, ar, cr: TaggedDigest }` -- the minimal shape S3/A2
//!   name, nothing added. `TipReport::parse(&coz::CozJson) -> Result<TipReport, _>` is PINNED by S3
//!   itself, not delegated; only the struct's field layout and error type are this file's choice.
//! - The distinct malformed outcome's EXACT name is deliberately left unpinned here:
//!   `is_an_honest_pair_verdict` below asserts only that a malformed pair's verdict is NONE OF the
//!   four an honest pair (proven or not) can produce -- never that it equals one specific new
//!   variant name. S3 offers a new `EquivocationVerdict` variant or a `TipReport::parse` error the
//!   caller handles as equally valid FORMs; `check_equivocation` keeping its `&coz::CozJson` in /
//!   `EquivocationVerdict` out signature (S3's second bullet: "it parses both reports ... and
//!   compares typed values", i.e. the parse is absorbed internally) makes a new variant the natural
//!   choice, but this test does not require that specific choice -- only the distinctness property
//!   S3 rules on.
//! - `Roots` stays `String`-typed (unchanged struct) and validates its four fields as
//!   `TaggedDigest` at the point `sign_receipt` consumes them, rather than becoming
//!   `TaggedDigest`-typed itself: `Roots` is constructed at the `/tip` and `/push` handlers
//!   directly from storage's `String` fields (P4's containment claim -- nothing in `cyphr-storage`
//!   changes), so keeping its public shape `String` avoids forcing every call site to parse before
//!   it can even attempt construction, while `tip_report`/`commit_receipt` still refuse (return
//!   `None`) on a malformed field (ND.4). This is the minimal-diff reading of S3's "(or parse
//!   String->TaggedDigest at construction)" alternative.
//!
//! These are DELEGATED choices (S6), not RESERVED ones: the implementation
//! walk may rename/reshape them with its own logged reasoning as long as
//! the two RULED properties (S3: boundary-side rejection-and-diagnosis,
//! passing-through typed comparison) and the RULED field dispositions
//! (`sequence` canonicalizes, `pr`/`commit_id` reject-loudly) hold -- which
//! is exactly what these tests check, independent of the exact names.

use cyphr::HashAlg;
use cyphr::state::TaggedDigest;
use cyphr_server::auth::ServerIdentity;
use cyphr_server::receipt::{self, EquivocationVerdict, Roots, TipReport};
use proptest::prelude::*;

// ========================================================================
// Fixture helpers (mirrored from tests/equivocation.rs / cross_witness.rs,
// which are separate integration-test crates and cannot be imported here)
// ========================================================================

/// Write a fresh signing key file for a fixed 32-byte Ed25519 seed and load
/// it -- deterministic, reproducible identities (mirrors `tests/
/// equivocation.rs`/`tests/cross_witness.rs`'s `identity_with_seed`).
fn identity_with_seed(seed: u8) -> (tempfile::TempDir, ServerIdentity) {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("signing-key.json");

    let prv_key = [seed; 32];
    let pub_key = coz::Alg::Ed25519
        .derive_public_key(&prv_key)
        .expect("derive public key from fixed seed");

    let file = serde_json::json!({
        "alg": coz::Alg::Ed25519.name(),
        "pub_key": Base64UrlUnpadded::encode_string(&pub_key),
        "prv_key": Base64UrlUnpadded::encode_string(&prv_key),
    });
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let identity = ServerIdentity::load_from_path(&path).expect("load signing key");
    (dir, identity)
}

/// A generator for exactly-32-byte digest material (SHA-256's expected
/// length): the full byte-space, no filtering.
fn arb_digest_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 32)
}

/// Render digest bytes as the TAGGED wire form (`SHA-256:<base64url>`) via
/// the SAME `TaggedDigest` this node adopts -- never a hand-rolled
/// encoding. For `commit_id`/`roots.<field>` ONLY -- `pr` is untagged
/// (A2), see [`principal_digest`].
fn digest_string(bytes: &[u8]) -> String {
    TaggedDigest::new(HashAlg::Sha256, bytes.to_vec())
        .expect("32 bytes matches SHA-256's expected digest length")
        .to_string()
}

/// Render digest bytes as a receipt's top-level `pr`: a BARE genesis
/// identifier, SPEC §2.2.3's DEFAULT (untagged) identifier form (A2) --
/// via the SAME strict `Base64UrlUnpadded` encoder `TaggedDigest::to_string`
/// uses internally, just without the `ALG:` prefix. Distinct from
/// [`digest_string`], which tags `commit_id`/`roots`.
fn principal_digest(bytes: &[u8]) -> String {
    use coz::base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(bytes)
}

/// Flip every bit of the first byte -- a digest DERIVED to be genuinely,
/// deterministically different from its input, never left to a
/// probabilistic hope that two independently generated 32-byte values
/// happen to differ. `b ^ 0xFF != b` for every `u8` value of `b`, so this
/// is a guarantee, not a likelihood.
fn differing_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0] ^= 0xFF;
    out
}

/// A string GUARANTEED to fail malformed-field parsing, for BOTH
/// dispositions this file exercises: `TaggedDigest::from_str`
/// (`commit_id`/`roots.<field>`) rejects it because it contains no `:` at
/// all, so `split_once(':')` always fails at the first parse step; the
/// bare genesis-identifier parse (`pr`, A2) rejects it because a 1-24
/// character base64url string can never decode to a supported digest
/// length (32/48/64 bytes -- the longest possible decode here is ~18
/// bytes). Both are guaranteed by construction, never by chance that a
/// random string happens to be malformed.
fn arb_malformed_digest_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9]{1,24}"
}

/// A `sequence` string GUARANTEED to fail integer parsing -- the exact
/// three shapes S3's field-disposition ruling names verbatim ("a
/// `sequence` string that does NOT parse as an integer (`"5x"`, `"5.0"`,
/// empty) is malformed"): trailing garbage, a decimal point, or empty.
/// Each is malformed by its shape, not by chance.
fn arb_malformed_sequence_string() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<u64>().prop_map(|n| format!("{n}x")),
        any::<u64>().prop_map(|n| format!("{n}.0")),
        Just(String::new()),
    ]
}

/// The three non-digest encodings S3's ruling names for a digest-bearing
/// field: array-wrapped, a bare JSON number, and JSON null. `ArrayWrapSelf`
/// wraps the CALLER's own valid value at that field (handed in explicitly,
/// not independently generated) so it exercises the exact trap S0.1 names:
/// an implementation that "helpfully" unwraps a 1-element array would
/// otherwise recover a perfectly valid digest and pass. Shared across
/// every digest-bearing field (`pr`, `commit_id`, `roots.{pr,sr,ar,cr}`) --
/// not `pr`-specific, since all six reject non-string JSON identically.
#[derive(Debug, Clone)]
enum MalformedShape {
    ArrayWrapSelf,
    Null,
    Number(i64),
}

fn arb_malformed_shape() -> impl Strategy<Value = MalformedShape> {
    prop_oneof![
        Just(MalformedShape::ArrayWrapSelf),
        Just(MalformedShape::Null),
        any::<i64>().prop_map(MalformedShape::Number),
    ]
}

fn roots_from(pr: &str, sr: &str, ar: &str, cr: &str) -> Roots {
    Roots {
        pr: pr.to_string(),
        sr: sr.to_string(),
        ar: ar.to_string(),
        cr: cr.to_string(),
    }
}

/// Overwrite one payload field -- top-level (`"pr"`, `"commit_id"`,
/// `"sequence"`) or one level nested (`"roots.<field>"`) -- on an
/// already-signed report and re-sign under the SAME identity -- the
/// "dishonest signer hand-crafts its own report" pattern already
/// established ad hoc in `tests/equivocation.rs` and `tests/
/// cross_witness.rs`, lifted into a shared helper since every
/// malformed-field property in this file needs it.
fn resign_with_field(
    identity: &ServerIdentity,
    mut coz: coz::CozJson,
    field: &str,
    value: serde_json::Value,
) -> coz::CozJson {
    match field.split_once('.') {
        Some((parent, child)) => coz.pay[parent][child] = value,
        None => coz.pay[field] = value,
    }
    let pay_bytes = serde_json::to_vec(&coz.pay).expect("serialize restamped pay");
    let (sig, _cad) = identity.sign(&pay_bytes).expect("re-sign restamped pay");
    coz.sig = sig;
    coz
}

/// The set of verdicts an HONEST pair (conflicting or not) can produce
/// under the pinned predicate, checked in the ORDER `check_equivocation`
/// checks them: `Proven` (a genuine conflict) and the three "no standing
/// claim" diagnoses (`IdenticalClaims`, `DifferentPrincipal`,
/// `DifferentSequence`). A malformed report's verdict must be NONE of
/// these -- landing in any of them is exactly the silent-escape/relocated-
/// evasion trap S0.1 names, whichever direction it falls.
fn is_an_honest_pair_verdict(verdict: EquivocationVerdict) -> bool {
    matches!(
        verdict,
        EquivocationVerdict::Proven
            | EquivocationVerdict::IdenticalClaims
            | EquivocationVerdict::DifferentPrincipal
            | EquivocationVerdict::DifferentSequence
    )
}

proptest! {
    /// ND.1: `sequence_canonicalizes_across_representations`
    ///
    /// `sequence` CANONICALIZES (S3's field-disposition ruling): a JSON
    /// number and the JSON string of its digits denote the SAME integer.
    /// Two reports sharing `pr` and this logical `sequence` but with a
    /// GENUINELY conflicting `commit_id` (guaranteed unequal via
    /// `differing_bytes`, never left to chance) MUST be detected as
    /// equivocation regardless of which side used which JSON
    /// representation -- this is the exact F1 evasion the campaign found
    /// (`5` to one witness, `"5"` to another). Each side's representation
    /// is drawn INDEPENDENTLY (`a_as_string`, `b_as_string` are separate
    /// generated booleans, never one flag reused for both) -- the prior
    /// generator-reachability defect this campaign found twice (N1, N4):
    /// stamping one drawn value into both pair members makes the
    /// asymmetric shape unreachable at any case count.
    #[test]
    fn sequence_canonicalizes_across_representations(
        seq in 0u64..1_000_000_000u64,
        pr_bytes in arb_digest_bytes(),
        commit_a_bytes in arb_digest_bytes(),
        a_as_string in any::<bool>(),
        b_as_string in any::<bool>(),
    ) {
        let (_dir, identity) = identity_with_seed(0x11);
        let pr_root = digest_string(&pr_bytes);
        let pr = principal_digest(&pr_bytes);
        let commit_a = digest_string(&commit_a_bytes);
        let commit_b = digest_string(&differing_bytes(&commit_a_bytes));
        let roots = roots_from(&pr_root, &pr_root, &pr_root, &pr_root);

        let mut a = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), seq, commit_a, &roots, seq + 1, 1_700_000_000,
        )
        .expect("compose report a");
        let mut b = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), seq, commit_b, &roots, seq + 1, 1_700_000_000,
        )
        .expect("compose report b");

        if a_as_string {
            a = resign_with_field(&identity, a, "sequence", serde_json::json!(seq.to_string()));
        }
        if b_as_string {
            b = resign_with_field(&identity, b, "sequence", serde_json::json!(seq.to_string()));
        }

        let parsed_a = TipReport::parse(&a).expect("canonical report a parses");
        prop_assert_eq!(
            parsed_a.pr.to_string(), pr.clone(),
            "a pr genesis-identifier string MUST parse to the equal identifier"
        );

        let verdict = receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key());
        prop_assert_eq!(
            verdict, EquivocationVerdict::Proven,
            "sequence {} (a_as_string={}, b_as_string={}) with conflicting commit_id MUST \
             canonicalize to the same position and be detected, not evade as DifferentSequence: \
             got {:?}",
            seq, a_as_string, b_as_string, verdict
        );
    }

    /// ND.2a: `malformed_report_is_not_a_silent_escape`
    ///
    /// The boundary-side property (S3): a validly-signed report that fails
    /// to canonicalize is REJECTED AND DIAGNOSED as a DISTINCT outcome --
    /// never silently compared into one of the "no equivocation occurred"
    /// verdicts an honest non-conflicting pair also produces, and never
    /// silently proven either. Without this, a rejecting parse RELOCATES
    /// the F1 evasion instead of closing it (S0.1's "the trap"): an
    /// attacker makes one report fail to parse and the caller reads that
    /// as an honest disagreement or, worse, a false proof.
    ///
    /// Corrupts exactly ONE field (`sequence`, `pr`, or `commit_id`,
    /// chosen independently per case) on an otherwise-canonical,
    /// GENUINELY conflicting pair. `TipReport::parse` on the malformed
    /// side MUST error, and `check_equivocation` on the pair MUST NOT
    /// return any of the four verdicts an honest pair can produce.
    ///
    /// Reachability: today, corrupting `pr` makes the raw `!=` comparison
    /// see unequal strings -> `DifferentPrincipal` (an honest-pair
    /// verdict, in the excluded set); corrupting `sequence` similarly ->
    /// `DifferentSequence`; corrupting `commit_id` leaves `pr`/`sequence`
    /// equal and `commit_id` unequal -> `Proven` (also excluded). All
    /// three arms are reachable and each is presently wrong under this
    /// property -- the property is red for a genuine reason on every arm,
    /// not just one.
    #[test]
    fn malformed_report_is_not_a_silent_escape(
        pr_bytes in arb_digest_bytes(),
        commit_bytes in arb_digest_bytes(),
        malformed_field in prop_oneof![Just("sequence"), Just("pr"), Just("commit_id")],
        malformed_sequence in arb_malformed_sequence_string(),
        malformed_digest in arb_malformed_digest_string(),
    ) {
        let (_dir, identity) = identity_with_seed(0x33);
        let pr_root = digest_string(&pr_bytes);
        let pr = principal_digest(&pr_bytes);
        let commit_a = digest_string(&commit_bytes);
        let commit_b = digest_string(&differing_bytes(&commit_bytes));
        let roots = roots_from(&pr_root, &pr_root, &pr_root, &pr_root);

        let a = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), 5u64, commit_a, &roots, 6, 1_700_000_000,
        )
        .expect("compose report a");
        let b = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), 5u64, commit_b, &roots, 6, 1_700_000_000,
        )
        .expect("compose report b");

        let malformed_value = match malformed_field {
            "sequence" => serde_json::json!(malformed_sequence),
            "pr" | "commit_id" => serde_json::json!(malformed_digest),
            _ => unreachable!("prop_oneof exhausts exactly these three field names"),
        };
        let b = resign_with_field(&identity, b, malformed_field, malformed_value.clone());

        prop_assert!(
            TipReport::parse(&b).is_err(),
            "TipReport::parse MUST reject a report with a malformed {}={:?}",
            malformed_field, malformed_value
        );

        let verdict = receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key());
        prop_assert!(
            !is_an_honest_pair_verdict(verdict),
            "a malformed {}={:?} MUST NOT be silently compared into any 'no equivocation \
             occurred' verdict, nor silently proven -- got {:?}",
            malformed_field, malformed_value, verdict
        );
    }

    /// ND.2b: `canonical_pair_compared_by_value`
    ///
    /// The passing-through property (S3): every report that clears the
    /// boundary is compared by TYPED value, not by its JSON shape. Holds
    /// `pr` fixed; draws `sequence`'s JSON representation (number vs
    /// string) INDEPENDENTLY per side; and varies `commit_id` and
    /// `roots.cr` independently as "same" or "genuinely different"
    /// (guaranteed via `differing_bytes`, never by chance). The verdict
    /// tracks the CANONICAL values exactly: `IdenticalClaims` iff both
    /// canonical fields match, `Proven` iff either differs -- regardless
    /// of which JSON representation either side used for `sequence`. This
    /// is the metamorphic dual of ND.1: ND.1 shows representation
    /// variance does not cause a MISS; this shows it does not cause a
    /// false ALARM either.
    #[test]
    fn canonical_pair_compared_by_value(
        seq in 0u64..1_000_000_000u64,
        pr_bytes in arb_digest_bytes(),
        commit_bytes in arb_digest_bytes(),
        cr_bytes in arb_digest_bytes(),
        a_as_string in any::<bool>(),
        b_as_string in any::<bool>(),
        same_commit in any::<bool>(),
        same_roots in any::<bool>(),
    ) {
        let (_dir, identity) = identity_with_seed(0x22);
        let pr_root = digest_string(&pr_bytes);
        let pr = principal_digest(&pr_bytes);
        let commit_a = digest_string(&commit_bytes);
        let commit_b = if same_commit {
            commit_a.clone()
        } else {
            digest_string(&differing_bytes(&commit_bytes))
        };
        let cr_a = digest_string(&cr_bytes);
        let cr_b = if same_roots {
            cr_a.clone()
        } else {
            digest_string(&differing_bytes(&cr_bytes))
        };
        let roots_a = roots_from(&pr_root, &pr_root, &pr_root, &cr_a);
        let roots_b = roots_from(&pr_root, &pr_root, &pr_root, &cr_b);

        let mut a = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), seq, commit_a, &roots_a, seq + 1, 1_700_000_000,
        )
        .expect("compose report a");
        let mut b = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), seq, commit_b, &roots_b, seq + 1, 1_700_000_000,
        )
        .expect("compose report b");

        if a_as_string {
            a = resign_with_field(&identity, a, "sequence", serde_json::json!(seq.to_string()));
        }
        if b_as_string {
            b = resign_with_field(&identity, b, "sequence", serde_json::json!(seq.to_string()));
        }

        let verdict = receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key());
        let expected = if same_commit && same_roots {
            EquivocationVerdict::IdenticalClaims
        } else {
            EquivocationVerdict::Proven
        };
        prop_assert_eq!(
            verdict, expected,
            "canonical comparison must track typed value regardless of JSON representation: \
             same_commit={} same_roots={} a_as_string={} b_as_string={}, got={:?}",
            same_commit, same_roots, a_as_string, b_as_string, verdict
        );
    }

    /// ND.2c: `pr_array_wrap_is_loud_not_unwrapped`
    ///
    /// The RULING (S3, field-disposition): every digest-bearing field --
    /// `pr`, `commit_id`, and each `roots.{pr,sr,ar,cr}` -- REJECTS-LOUDLY
    /// non-digest encodings; there is no ambiguity to canonicalize away.
    /// `["digest"]` (array-wrapped), a bare JSON number, and JSON `null`
    /// are the three shapes S3 names. Exercised across ALL SIX fields, not
    /// just `pr`: `commit_id`/`roots.<field>` parse through a DIFFERENT
    /// function (`parse_digest_field`) than `pr` does (`parse_genesis_id`),
    /// and the two are documented as rejecting these shapes identically --
    /// a claim this property now checks on every field that makes it,
    /// rather than on `pr` alone. The array variant wraps the corrupted
    /// side's OWN valid value at that field, handed in explicitly rather
    /// than independently generated, so it exercises the exact trap
    /// S0.1/S3 names: an implementation that "helpfully" unwraps a
    /// 1-element array would recover a perfectly valid, MATCHING digest
    /// and treat the pair as non-conflicting -- silently reopening the
    /// evasion one layer down. `TipReport::parse` MUST reject every shape
    /// on every field, and `check_equivocation` MUST NOT fold any of them
    /// into `Proven` nor any other honest-pair verdict.
    #[test]
    fn pr_array_wrap_is_loud_not_unwrapped(
        pr_bytes in arb_digest_bytes(),
        commit_bytes in arb_digest_bytes(),
        malformed_field in prop_oneof![
            Just("pr"), Just("commit_id"),
            Just("roots.pr"), Just("roots.sr"), Just("roots.ar"), Just("roots.cr"),
        ],
        shape in arb_malformed_shape(),
    ) {
        let (_dir, identity) = identity_with_seed(0x44);
        let pr_root = digest_string(&pr_bytes);
        let pr = principal_digest(&pr_bytes);
        let commit_a = digest_string(&commit_bytes);
        let commit_b = digest_string(&differing_bytes(&commit_bytes));
        let roots = roots_from(&pr_root, &pr_root, &pr_root, &pr_root);

        let a = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), 5u64, commit_a, &roots, 6, 1_700_000_000,
        )
        .expect("compose report a");
        let b = receipt::tip_report(
            &identity, 1_700_000_000, pr.clone(), 5u64, commit_b.clone(), &roots, 6, 1_700_000_000,
        )
        .expect("compose report b");

        // The value legitimately sitting at `malformed_field` on `b`
        // before corruption -- what an array-unwrap bug would recover.
        let own_value = match malformed_field {
            "pr" => pr.clone(),
            "commit_id" => commit_b.clone(),
            "roots.pr" | "roots.sr" | "roots.ar" | "roots.cr" => pr_root.clone(),
            _ => unreachable!("prop_oneof exhausts exactly these six field names"),
        };

        let malformed_value = match &shape {
            MalformedShape::ArrayWrapSelf => serde_json::json!([own_value]),
            MalformedShape::Null => serde_json::Value::Null,
            MalformedShape::Number(n) => serde_json::json!(n),
        };
        let b = resign_with_field(&identity, b, malformed_field, malformed_value.clone());

        prop_assert!(
            TipReport::parse(&b).is_err(),
            "{}={:?} (shape={:?}) MUST fail TipReport::parse -- not a digest encoding, and the \
             array case MUST NOT be unwrapped to its inner string",
            malformed_field, malformed_value, shape
        );

        let verdict = receipt::check_equivocation(&a, identity.pub_key(), &b, identity.pub_key());
        prop_assert!(
            !is_an_honest_pair_verdict(verdict),
            "{}={:?} (shape={:?}) MUST NOT be silently unwrapped/compared into any honest-pair \
             verdict -- got {:?}",
            malformed_field, malformed_value, shape, verdict
        );
    }

    /// ND.4: `receipt_rejects_malformed_digest`
    ///
    /// Receipt CONSTRUCTION cannot sign a malformed digest (survey finding
    /// #6): `receipt::tip_report` validates `commit_id` and every `Roots`
    /// field as `TaggedDigest`, and `pr` as a bare genesis identifier (A2),
    /// and refuses (returns `None`) rather than silently signing an
    /// unvalidated value. EMPIRICALLY confirmed
    /// RED before this test was written: a scratch check (not committed)
    /// against the unmodified implementation showed `tip_report` returns
    /// `Some` for a `Roots.pr` of `"not-a-digest-at-all"`, with no
    /// validation performed anywhere in `sign_receipt`. Which
    /// digest-bearing parameter is corrupted is drawn independently per
    /// case across all six (`pr`, `commit_id`, and each of the four
    /// `Roots` fields) so the property covers the whole parameter surface,
    /// not one hardcoded field.
    #[test]
    fn receipt_rejects_malformed_digest(
        pr_bytes in arb_digest_bytes(),
        commit_bytes in arb_digest_bytes(),
        malformed_field in prop_oneof![
            Just("pr"), Just("commit_id"),
            Just("roots.pr"), Just("roots.sr"), Just("roots.ar"), Just("roots.cr"),
        ],
        malformed_digest in arb_malformed_digest_string(),
    ) {
        let (_dir, identity) = identity_with_seed(0x55);
        let pr_root = digest_string(&pr_bytes);
        let pr = principal_digest(&pr_bytes);
        let commit_id = digest_string(&commit_bytes);
        let mut roots = roots_from(&pr_root, &pr_root, &pr_root, &pr_root);

        let (arg_pr, arg_commit) = match malformed_field {
            "pr" => (malformed_digest.clone(), commit_id.clone()),
            "commit_id" => (pr.clone(), malformed_digest.clone()),
            "roots.pr" => {
                roots.pr = malformed_digest.clone();
                (pr.clone(), commit_id.clone())
            },
            "roots.sr" => {
                roots.sr = malformed_digest.clone();
                (pr.clone(), commit_id.clone())
            },
            "roots.ar" => {
                roots.ar = malformed_digest.clone();
                (pr.clone(), commit_id.clone())
            },
            "roots.cr" => {
                roots.cr = malformed_digest.clone();
                (pr.clone(), commit_id.clone())
            },
            _ => unreachable!("prop_oneof exhausts exactly these six field names"),
        };

        let result = receipt::tip_report(
            &identity, 1_700_000_000, arg_pr, 5u64, arg_commit, &roots, 6, 1_700_000_000,
        );
        prop_assert!(
            result.is_none(),
            "tip_report MUST refuse to sign a malformed {}={:?}, not silently build the receipt",
            malformed_field, malformed_digest
        );
    }
}

/// `genesis_commit_root_is_accepted`
///
/// A principal that has been key-established but has not yet finalized a
/// data commit has no commit root: storage's re-derivation returns `""`
/// for `cr` in exactly that state, while every other root (`pr`/`sr`/`ar`)
/// already carries a genuine value. `""` is the wire sentinel for "no
/// commit root yet," not a malformed digest -- `receipt::tip_report`/
/// `commit_receipt` MUST sign a genesis-stage report rather than refusing
/// the whole receipt over one legitimately-absent field, and the parse
/// MUST canonicalize that absence to `None`, never reject it.
///
/// EMPIRICALLY confirmed RED before this fix: `tip_report` with
/// `roots.cr == ""` returned `None` under the unmodified `sign_receipt`,
/// which validated `cr` identically to `pr`/`sr`/`ar` (an unconditional
/// `TaggedDigest` parse) -- refusing to sign an entirely valid genesis
/// report.
#[test]
fn genesis_commit_root_is_accepted() {
    let (_dir, identity) = identity_with_seed(0x66);
    let pr_root = digest_string(&[0x77; 32]);
    let pr = principal_digest(&[0x77; 32]);
    let commit_id = digest_string(&[0x88; 32]);
    // `cr` empty -- storage's sentinel for "no commit root yet."
    let roots = roots_from(&pr_root, &pr_root, &pr_root, "");

    let coz = receipt::tip_report(
        &identity,
        1_700_000_000,
        pr.clone(),
        0u64,
        commit_id,
        &roots,
        1,
        1_700_000_000,
    )
    .expect(
        "tip_report MUST sign a genesis-stage report whose commit root is legitimately absent",
    );

    assert_eq!(
        coz.pay["roots"]["cr"], "",
        "wire bytes MUST be unchanged -- the empty cr sentinel serializes back as an empty string"
    );

    let parsed = TipReport::parse(&coz).expect("a genesis-stage report MUST canonicalize");
    assert_eq!(
        parsed.roots.cr, None,
        "an empty wire cr MUST parse to None (\"no commit root yet\"), never a malformed digest"
    );
}
