//! Acceptance test suite for Node N4: Cross-Witness Consistency.
//!
//! Evaluates criteria N4.1 – N4.4, N4.6 & N4.7, plus the N1 property suite that
//! replaces the narrow N4.1c regression and grounds N4.1/N4.2 by generation
//! instead of one hand-picked case:
//! - `conflicting_tips_yield_evidence` (N4.1): Conflicting tip reports from distinct witnesses
//!   yield portable equivocation evidence.
//! - `evidence_verifies_offline` (N4.2): Equivocation evidence is self-contained and verifies
//!   offline without server cooperation.
//! - `evidence_offline_false_path` (N4.2b): `verify_evidence_offline` returns `Some(false)` for an
//!   agreeing pair -- the false path the domain wrapper itself was never exercised on.
//! - `key_validity_interval` (N4.3): Witness key validity is strictly bounded by [first_seen,
//!   revocation) interval.
//! - `key_validity_from_portable_proof` (N4.3a): Key validity is verified using portable
//!   key-inclusion proof, NOT in-memory Principal, on the valid AND both failure paths.
//! - `fork_detection_ignores_self_assertion` (N4.4): Fork detection ignores unverified
//!   self-assertions and unauthenticated reports.
//! - `agreement_produces_no_standing_claim` (N4.6): Agreement across queried witnesses produces no
//!   standing claim or alert.
//! - `golden_disagreement_artifact_byte_stable` (N4.7): Disagreement evidence serializes
//!   deterministically matching golden vector.
//!
//! `equivocation_conflict_yields_evidence_property`,
//! `equivocation_agreement_yields_none_property`, and
//! `equivocation_invalid_sig_not_counted_property` generate over the `pr`/`sequence`
//! JSON-type space (string, integer, null, array) and witness counts N∈[2,5] --
//! the N1 audit's decorrelated check on `check_cross_witness_consistency`,
//! superseding the single hand-picked case `non_standard_json_types_surfaced_by_consistency_check`
//! used to cover it alone. Each of the conflicting pair's two positions draws
//! its representation INDEPENDENTLY, so representation asymmetry across the
//! pair (`5` vs `"5"` for the same logical value) is reachable -- the shape of
//! the live evasion the first, symmetric-stamping revision of this suite was
//! structurally unable to produce.
//! `equivocation_asymmetric_type_still_detected_property` (F1) forces that
//! asymmetry on every case, and `evidence_names_exactly_the_conflicting_pair`
//! (F2) pins the evidence bundle to exactly the two conflicting reports. No
//! witness threshold (N4.5): removed per Zami #139 -- a quorum threshold is a
//! provable-consistency claim, not proof-of-error.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::principal_tree::PrincipalTree;
use cyphr::semantic_tree::{AuthTree, KeyTree, StateTree};
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, LeafProof};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::receipt::{self, Roots};
use proptest::prelude::*;

mod common;

/// Render a distinct, valid TAGGED SHA-256 digest string from a repeated
/// seed byte -- the same convention `roots_a`/`roots_b` already use
/// (all-`A`/`B`/`C`/`D`/`E` blocks), extended to every `commit_id`/`roots`
/// fixture in this file. `check_equivocation` parses `commit_id`/`roots`
/// as `TaggedDigest`, so a human-readable placeholder like `"commit-a"`
/// no longer round-trips through `receipt::tip_report` -- every fixture
/// here must be a digest that genuinely parses. `pr` is NOT tagged -- see
/// [`principal_digest`].
fn digest(byte: u8) -> String {
    TaggedDigest::new(HashAlg::Sha256, vec![byte; 32])
        .expect("32 bytes is SHA-256's expected digest length")
        .to_string()
}

/// Render a distinct, valid BARE genesis-identifier string from a
/// repeated seed byte -- the untagged counterpart to [`digest`]. A
/// receipt's top-level `pr` is the attested principal's genesis
/// identifier: SPEC §2.2.3's DEFAULT (untagged) identifier form, not the
/// `TaggedDigest` `roots`/`commit_id` use under their labeled exemption.
/// Every `pr` fixture in this suite uses this helper, never [`digest`].
fn principal_digest(byte: u8) -> String {
    Base64UrlUnpadded::encode_string(&[byte; 32])
}

/// Read a committed golden vector, trimming a trailing newline so the
/// file can end in one.
fn golden(name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .trim_end()
        .to_string()
}

/// Generate deterministic identity for testing cross-witness reports.
fn identity_with_seed(seed: u8) -> (tempfile::TempDir, ServerIdentity) {
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

/// Two root sets that differ only in `cr`, standing in for a conflicting
/// commit outcome at the same chain position. Generated via [`digest`]
/// rather than hand-typed repeated-letter literals: a repeated-letter
/// base64url block is canonical only when the letter's value is zero
/// (`A`) -- `B`/`C`/`D`/`E` blocks of the same shape leave nonzero
/// trailing bits in the final character, which `TaggedDigest::from_str`'s
/// strict decoder rejects even though a lenient decoder would accept them.
fn roots_a() -> Roots {
    Roots {
        pr: digest(0xa1),
        sr: digest(0xa2),
        ar: digest(0xa3),
        cr: digest(0xa4),
    }
}

fn roots_b() -> Roots {
    Roots {
        cr: digest(0xa5),
        ..roots_a()
    }
}

/// Builds the 4-hop KT -> AR-node -> SR-node -> PT chain for non-trivial
/// portable key inclusion testing (N4.3a).
fn build_key_inclusion_material(
    alg: HashAlg,
) -> (Vec<cyphr::LeafProof>, Vec<Vec<u8>>, Thumbprint, Thumbprint) {
    let alg_id = hash_alg_to_u64(alg);
    let tmb_a = Thumbprint::from_bytes(vec![0x01; 32]);
    let tmb_b = Thumbprint::from_bytes(vec![0x02; 32]);
    let thumbprints = vec![&tmb_a, &tmb_b];

    let kt = KeyTree::build_tree(&thumbprints, &[alg]).unwrap();
    let kr = kt.root(&[alg]).unwrap();
    let ar_node = AuthTree::build_tree(&kr, &[alg]).unwrap();
    let ar = ar_node.root(&[alg]).unwrap();
    let sr_node = StateTree::build_tree(&ar, None, &[alg]).unwrap();
    let sr = sr_node.root(&[alg]).unwrap();
    let mut pt = PrincipalTree::new();
    pt.set_sr(&sr, &[alg]).unwrap();
    let pr = pt.pr(&[alg]).unwrap();

    let mut sorted: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
    sorted.sort();
    let index = sorted.iter().position(|&b| b == tmb_a.as_bytes()).unwrap() as u64;

    let hops = vec![
        kt.thumbprint_inclusion_proof(alg_id, index).unwrap(),
        ar_node.kr_inclusion_proof(alg_id).unwrap(),
        sr_node.ar_inclusion_proof(alg_id).unwrap(),
        pt.sr_inclusion_proof(alg_id).unwrap(),
    ];
    let roots = vec![
        kr.0.get(alg).unwrap().to_vec(),
        ar.0.get(alg).unwrap().to_vec(),
        sr.0.get(alg).unwrap().to_vec(),
        pr.0.get(alg).unwrap().to_vec(),
    ];

    (hops, roots, tmb_a, tmb_b)
}

// ========================================================================
// Acceptance Criteria N4.1 – N4.6 & N4.7
// ========================================================================

/// N4.1: `conflicting_tips_yield_evidence`
///
/// Verifies that when two conflicting signed tip reports for the same principal
/// and sequence position are reported by distinct witnesses, cross-witness consistency
/// checking detects the fork and yields portable equivocation evidence.
#[tokio::test]
async fn conflicting_tips_yield_evidence() {
    let (_dir_a, identity_a) = identity_with_seed(0x11);
    let (_dir_b, identity_b) = identity_with_seed(0x22);

    let pr = principal_digest(0x10);
    let seq = 5;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(&identity_a, now, &pr, seq, digest(0x1a), &roots_a(), 6, now)
        .expect("compose tip A");

    let tip_b = receipt::tip_report(&identity_b, now, &pr, seq, digest(0x1b), &roots_b(), 6, now)
        .expect("compose tip B");

    let verdict =
        receipt::check_equivocation(&tip_a, identity_a.pub_key(), &tip_b, identity_b.pub_key());

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::Proven,
        "conflicting signed tip reports from distinct witnesses MUST yield proven equivocation \
         evidence"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let claim = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&tip_a, identity_a.pub_key()),
        (&tip_b, identity_b.pub_key()),
    ])
    .expect("standing claim MUST be present on conflicting tips");
    assert_eq!(claim["kind"], "equivocation_evidence");
}

/// N4.1b: `three_plus_witness_array_scan`
///
/// Verifies that check_cross_witness_consistency scans all pairs in a 3+ witness slice
/// and detects equivocation even when the conflicting pair is not at index 0 (e.g. index 1 vs index
/// 2).
#[tokio::test]
async fn three_plus_witness_array_scan() {
    let (_dir_w0, identity_w0) = identity_with_seed(0x11);
    let (_dir_w1, identity_w1) = identity_with_seed(0x22);
    let (_dir_w2, identity_w2) = identity_with_seed(0x33);

    let pr_other = principal_digest(0x20);
    let pr_target = principal_digest(0x21);
    let seq = 5;
    let now = 1_700_000_000;

    let tip_w0 = receipt::tip_report(
        &identity_w0,
        now,
        &pr_other,
        seq,
        digest(0x2a),
        &roots_a(),
        6,
        now,
    )
    .expect("compose tip W0");

    let tip_w1 = receipt::tip_report(
        &identity_w1,
        now,
        &pr_target,
        seq,
        digest(0x2b),
        &roots_a(),
        6,
        now,
    )
    .expect("compose tip W1");

    let tip_w2 = receipt::tip_report(
        &identity_w2,
        now,
        &pr_target,
        seq,
        digest(0x2c),
        &roots_b(),
        6,
        now,
    )
    .expect("compose tip W2");

    let claim = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&tip_w0, identity_w0.pub_key()),
        (&tip_w1, identity_w1.pub_key()),
        (&tip_w2, identity_w2.pub_key()),
    ])
    .expect(
        "check_cross_witness_consistency MUST detect conflict between index 1 and index 2 in 3+ \
         witness array",
    );

    assert_eq!(claim["kind"], "equivocation_evidence");
    assert_eq!(claim["principal_id"], pr_target);
    assert_eq!(claim["sequence"], seq);
}

/// N4.2: `evidence_verifies_offline`
///
/// Verifies that equivocation evidence produced by cross-witness checking is completely
/// self-contained and can be verified entirely offline (using plain coz signature verification
/// and check_equivocation without relying on any active server or network connection).
#[tokio::test]
async fn evidence_verifies_offline() {
    let (_dir_a, identity_a) = identity_with_seed(0x33);
    let (_dir_b, identity_b) = identity_with_seed(0x44);

    let pr = principal_digest(0x40);
    let seq = 10;
    let now = 1_700_050_000;

    let tip1 = receipt::tip_report(
        &identity_a,
        now,
        &pr,
        seq,
        digest(0x4a),
        &roots_a(),
        11,
        now,
    )
    .expect("compose tip 1");

    let tip2 = receipt::tip_report(
        &identity_b,
        now,
        &pr,
        seq,
        digest(0x4b),
        &roots_b(),
        11,
        now,
    )
    .expect("compose tip 2");

    let verdict =
        receipt::check_equivocation(&tip1, identity_a.pub_key(), &tip2, identity_b.pub_key());

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::Proven,
        "offline verification of cross-witness evidence MUST yield Proven"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let verified_offline = cyphr_server::consistency::verify_evidence_offline(
        &tip1,
        identity_a.pub_key(),
        &tip2,
        identity_b.pub_key(),
    );
    assert_eq!(
        verified_offline,
        Some(true),
        "cross-witness evidence MUST verify offline without server cooperation"
    );
}

/// N4.2b: `evidence_offline_false_path` (n4-audit F5)
///
/// `evidence_verifies_offline` above only ever exercises the domain wrapper's TRUE
/// path (a genuine conflict). Verifies the false path directly: an agreeing pair
/// MUST verify offline to `Some(false)`, through `verify_evidence_offline` itself, not
/// only through the `check_equivocation` primitive it wraps.
#[tokio::test]
async fn evidence_offline_false_path() {
    let (_dir_a, identity_a) = identity_with_seed(0x33);
    let (_dir_b, identity_b) = identity_with_seed(0x44);

    let pr = principal_digest(0x41);
    let seq = 20;
    let now = 1_700_060_000;

    let tip_a = receipt::tip_report(
        &identity_a,
        now,
        &pr,
        seq,
        digest(0x4c),
        &roots_a(),
        21,
        now,
    )
    .expect("compose tip A");

    let tip_b = receipt::tip_report(
        &identity_b,
        now,
        &pr,
        seq,
        digest(0x4c),
        &roots_a(),
        21,
        now,
    )
    .expect("compose tip B");

    let verified_offline = cyphr_server::consistency::verify_evidence_offline(
        &tip_a,
        identity_a.pub_key(),
        &tip_b,
        identity_b.pub_key(),
    );
    assert_eq!(
        verified_offline,
        Some(false),
        "verify_evidence_offline MUST return Some(false) for agreeing tip reports, not just \
         Some(true) for conflicting ones"
    );
}

/// N4.3: `key_validity_interval`
///
/// Verifies that witness key validity for signing tip reports is strictly bounded by the
/// key's validity interval [first_seen, revocation). Signatures or tip reports produced by
/// a key outside its validity interval (before first_seen or after revocation) MUST be rejected.
#[tokio::test]
async fn key_validity_interval() {
    let first_seen: i64 = 1_700_100_000;
    let revocation = Some(cyphr::key::Revocation {
        rvk: 1_700_200_000,
        by: None,
    });

    let key = cyphr::Key {
        alg: coz::Alg::Ed25519.name().to_string(),
        tmb: coz::Thumbprint::from_bytes(vec![0xaa; 32]),
        pub_key: vec![0xbb; 32],
        first_seen,
        last_used: None,
        revocation,
        tag: None,
    };

    assert!(
        !cyphr_server::consistency::verify_key_validity_interval(&key, 1_700_099_999),
        "key MUST NOT be valid before first_seen timestamp"
    );

    assert!(
        cyphr_server::consistency::verify_key_validity_interval(&key, 1_700_150_000),
        "key MUST be valid within [first_seen, revocation) interval"
    );

    assert!(
        !cyphr_server::consistency::verify_key_validity_interval(&key, 1_700_200_000),
        "key MUST NOT be valid at or after revocation timestamp"
    );
}

/// N4.3a: `key_validity_from_portable_proof` (n4-audit F4)
///
/// Verifies key validity using a portable key-inclusion proof
/// (`consistency::verify_key_portable_proof`), NOT an in-memory `Principal` object. Ensures that
/// offline cross-witness verification can establish key validity purely from self-contained proof
/// material and a trusted Principal Root.
///
/// All three cases -- the valid proof AND both failure paths -- call the domain
/// wrapper under test directly. The prior version asserted its two failure cases
/// against the raw `cyphr::inclusion::verify_key_inclusion` primitive and called
/// the wrapper only for the positive case, so a defect introduced in the wrapper
/// itself (as opposed to the primitive it delegates to) could pass its failure
/// paths unexercised.
#[tokio::test]
async fn key_validity_from_portable_proof() {
    let alg = HashAlg::Sha256;
    let (hops, roots, tmb_a, tmb_b) = build_key_inclusion_material(alg);
    let root_refs: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();

    // 1. Portable key inclusion verification against non-trivial, valid proof MUST succeed
    assert!(
        cyphr_server::consistency::verify_key_portable_proof(alg, &tmb_a, &hops, &root_refs),
        "valid portable key inclusion proof MUST verify successfully through the domain wrapper"
    );

    // 2. Mismatched thumbprint MUST fail verification, through the domain wrapper
    assert!(
        !cyphr_server::consistency::verify_key_portable_proof(alg, &tmb_b, &hops, &root_refs),
        "portable proof verification with mismatched thumbprint MUST fail through the domain \
         wrapper"
    );

    // 3. Empty / invalid proof material MUST fail verification, through the domain wrapper
    let empty_hops: Vec<LeafProof> = vec![];
    let empty_roots: Vec<&[u8]> = vec![];
    assert!(
        !cyphr_server::consistency::verify_key_portable_proof(
            alg,
            &tmb_a,
            &empty_hops,
            &empty_roots
        ),
        "empty or invalid proof material MUST return false through the domain wrapper"
    );
}

/// N4.4: `fork_detection_ignores_self_assertion`
///
/// Verifies that fork detection ignores self-assertions and unverified reports from unauthenticated
/// sources. An unverified report or report signed by an untrusted key MUST NOT trigger a false
/// equivocation/fork alert against a valid witness report.
#[tokio::test]
async fn fork_detection_ignores_self_assertion() {
    let (_dir_valid, valid_identity) = identity_with_seed(0x55);
    let (_dir_untrusted, untrusted_identity) = identity_with_seed(0x66);

    let pr = principal_digest(0x70);
    let seq = 7;
    let now = 1_700_000_000;

    let valid_tip = receipt::tip_report(
        &valid_identity,
        now,
        &pr,
        seq,
        digest(0x7a),
        &roots_a(),
        8,
        now,
    )
    .expect("compose valid tip");

    let self_asserted_tip = receipt::tip_report(
        &untrusted_identity,
        now,
        &pr,
        seq,
        digest(0x7b),
        &roots_b(),
        8,
        now,
    )
    .expect("compose self-asserted tip");

    let wrong_pub_key = vec![0xff; 32];
    let verdict = receipt::check_equivocation(
        &valid_tip,
        valid_identity.pub_key(),
        &self_asserted_tip,
        &wrong_pub_key,
    );

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::InvalidSignature,
        "fork detection MUST reject unverified self-assertions (InvalidSignature)"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let fork_detected_for_unverified = cyphr_server::consistency::detect_fork_unverified(
        &valid_tip,
        valid_identity.pub_key(),
        &self_asserted_tip,
        &wrong_pub_key,
    );
    assert_eq!(
        fork_detected_for_unverified,
        Some(false),
        "unverified self-assertion MUST NOT trigger fork evidence"
    );

    let claim_unverified = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&valid_tip, valid_identity.pub_key()),
        (&self_asserted_tip, wrong_pub_key.as_slice()),
    ]);
    assert!(
        claim_unverified.is_none(),
        "unauthenticated/forged tip reports MUST NOT produce standing claim in \
         check_cross_witness_consistency"
    );
}

/// N4.6: `agreement_produces_no_standing_claim`
///
/// Verifies that when all queried witness nodes agree on the principal tip state (identical
/// commit_id, sequence, and roots), cross-witness consistency evaluation produces NO standing
/// claim and NO equivocation evidence.
#[tokio::test]
async fn agreement_produces_no_standing_claim() {
    let (_dir_a, identity_a) = identity_with_seed(0x77);
    let (_dir_b, identity_b) = identity_with_seed(0x88);

    let pr = principal_digest(0x90);
    let commit_id = digest(0x9a);
    let seq = 12;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(&identity_a, now, &pr, seq, &commit_id, &roots_a(), 13, now)
        .expect("compose tip A");

    let tip_b = receipt::tip_report(&identity_b, now, &pr, seq, &commit_id, &roots_a(), 13, now)
        .expect("compose tip B");

    let verdict =
        receipt::check_equivocation(&tip_a, identity_a.pub_key(), &tip_b, identity_b.pub_key());

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::IdenticalClaims,
        "agreeing tip reports MUST yield IdenticalClaims verdict"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let standing_claim_on_agreement =
        cyphr_server::consistency::check_cross_witness_consistency(&[
            (&tip_a, identity_a.pub_key()),
            (&tip_b, identity_b.pub_key()),
        ]);
    assert!(
        standing_claim_on_agreement.is_none(),
        "cross-witness agreement MUST produce NO standing claim"
    );
}

/// N4.7: `golden_disagreement_artifact_byte_stable`
///
/// Verifies that disagreement evidence serializes deterministically and matches
/// the committed golden vector `rs/cyphr-server/tests/golden/witness_disagreement.json`.
#[tokio::test]
async fn golden_disagreement_artifact_byte_stable() {
    let (_dir_a, identity_a) = identity_with_seed(0x11);
    let (_dir_b, identity_b) = identity_with_seed(0x22);

    let pr = principal_digest(0x10);
    let seq = 5;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(&identity_a, now, &pr, seq, digest(0x1a), &roots_a(), 6, now)
        .expect("compose tip A");

    let tip_b = receipt::tip_report(&identity_b, now, &pr, seq, digest(0x1b), &roots_b(), 6, now)
        .expect("compose tip B");

    let evidence_json = serde_json::json!({
        "kind": "equivocation_evidence",
        "principal_id": &pr,
        "sequence": seq,
        "reports": [tip_a.clone(), tip_b.clone()],
    });

    let wire = serde_json::to_string_pretty(&evidence_json).unwrap();
    assert_eq!(wire, golden("witness_disagreement.json"));

    // Call domain consistency module (cyphr_server::consistency)
    let formatted =
        cyphr_server::consistency::format_disagreement_evidence(pr, seq, &[tip_a, tip_b]);
    let domain_wire = serde_json::to_string_pretty(&formatted).unwrap();
    assert_eq!(domain_wire, golden("witness_disagreement.json"));
}

/// N4.1a: `unauthenticated_tips_rejected_by_consistency_check`
///
/// Verifies that when unauthenticated or forged-signature tip reports are passed to
/// `check_cross_witness_consistency`, signature verification rejects them upfront
/// and no false equivocation evidence claim is produced.
#[tokio::test]
async fn unauthenticated_tips_rejected_by_consistency_check() {
    let (_dir_valid, valid_identity) = identity_with_seed(0x55);
    let (_dir_untrusted, untrusted_identity) = identity_with_seed(0x66);

    let pr = principal_digest(0xb0);
    let seq = 7;
    let now = 1_700_000_000;

    let valid_tip = receipt::tip_report(
        &valid_identity,
        now,
        &pr,
        seq,
        digest(0xba),
        &roots_a(),
        8,
        now,
    )
    .expect("compose valid tip");

    let forged_tip = receipt::tip_report(
        &untrusted_identity,
        now,
        &pr,
        seq,
        digest(0xbb),
        &roots_b(),
        8,
        now,
    )
    .expect("compose forged tip");

    let wrong_pub_key = vec![0xff; 32];

    let claim_forged = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&valid_tip, valid_identity.pub_key()),
        (&forged_tip, wrong_pub_key.as_slice()),
    ]);
    assert!(
        claim_forged.is_none(),
        "forged tip report with invalid public key MUST NOT produce equivocation claim"
    );

    let claim_both_forged = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&valid_tip, wrong_pub_key.as_slice()),
        (&forged_tip, wrong_pub_key.as_slice()),
    ]);
    assert!(
        claim_both_forged.is_none(),
        "unauthenticated tip reports MUST NOT produce equivocation claim"
    );
}

// ========================================================================
// N1: equivocation property suite (audit of
// `non_standard_json_types_surfaced_by_consistency_check`)
// ========================================================================
//
// The replaced test hand-picked ONE atypical shape (integer `pr`, string
// `sequence`) at N=2. Neither axis of the invariant -- the `pr`/`sequence` JSON
// type space, nor witness counts beyond the single possible pair at N=2 -- was
// swept. These properties are derived from what `pr` and `sequence` structurally
// ARE (signer-controlled JSON claims about one logical chain position), not
// from which branches the implementation happens to take, so they do not
// inherit the implementation's blind spots.
//
// REDIRECTED against the landed typed-domain contract (ND, `2ebb37a`): a
// report's `pr`/`sequence`/`commit_id`/`roots` no longer reach the comparison
// as raw `Value`s -- `receipt::TipReport::parse` canonicalizes or REJECTS-LOUD
// each field first (`EquivocationVerdict::Malformed`), and `receipt::tip_report`
// itself now refuses to CONSTRUCT a report around a malformed `pr`/digest
// (construction-time validation). That changes what "vary the representation"
// means per field:
// - `sequence` CANONICALIZES across two JSON shapes (a raw number and its decimal string denote the
//   same integer) -- see [`canonical_sequence_pair_strategy`]. This is the ONLY field with
//   representation variety to draw independently across a conflicting pair's two positions; F1's
//   evasion (`5` vs `"5"`) lives here.
// - `pr` has exactly ONE canonical encoding per identity (a bare b64ut string of a supported digest
//   length) -- an array-wrapped or re-encoded digest is REJECTED, not accepted as an alternate
//   spelling (ND's field-disposition ruling). A conflicting pair's two positions therefore share
//   the identical `pr` string, exactly as an honest signer's two reports about the same principal
//   would -- see [`valid_pr_strategy`]. There is no F1-shaped asymmetry left to test for `pr`
//   specifically; the type closes it.
// A generated shape that fails to canonicalize on EITHER field is a different
// property's territory (the boundary-side "malformed input is never a silent
// escape" guarantee ND's own suite closes, and the consumer-visibility gap
// N1's dispatch flags in `equivocation.rs`) -- these properties only generate
// shapes valid `TipReport::parse` accepts, so every generated case remains
// inside the passing-through half of S3's two-sided contract.

/// A distinguishable, VALID genesis identifier that no generated `pr` value
/// can equal (an astronomically improbable byte collision -- the same
/// standard the fixed `roots_a`/`roots_b` byte patterns already rely on).
/// Used to build distractor witnesses that can never accidentally equivocate
/// with the generated target principal. Unlike the pre-typed-domain suite's
/// sentinel (a bare unicode string), this MUST be a valid genesis identifier:
/// `receipt::tip_report`'s construction-time validation refuses to sign a
/// malformed `pr` into a fixture at all, so an invalid distractor `pr` would
/// make the fixture itself fail to construct, not merely fail to conflict.
fn distractor_pr() -> String {
    principal_digest(0xee)
}

/// The two attested representations of one non-negative integer: the raw
/// JSON number, or its decimal string -- the two shapes `sequence`
/// canonicalizes across (ND's field-disposition ruling).
fn int_rep(n: u64, as_string: bool) -> serde_json::Value {
    if as_string {
        serde_json::Value::from(n.to_string())
    } else {
        serde_json::Value::from(n)
    }
}

/// An arbitrary VALID genesis identifier: a bare b64ut string over 32 random
/// bytes (SHA-256's length, one of the three lengths `parse_genesis_id_str`
/// accepts). `pr` has exactly one canonical encoding per identity, so unlike
/// [`canonical_sequence_pair_strategy`] there is no per-position
/// representation to draw independently -- a conflicting pair's two
/// positions use the SAME drawn string, exactly as an honest signer's two
/// reports about one principal would.
fn valid_pr_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 32)
        .prop_map(|bytes| Base64UrlUnpadded::encode_string(&bytes))
}

/// One logical `sequence` value as a PAIR of per-position JSON
/// representations, each drawn independently.
///
/// The first revision of this suite generated a single value and stamped it
/// into BOTH members of the conflicting pair, so the type varied across cases
/// but never across positions within a case -- representation asymmetry (`5`
/// in one report, `"5"` in the other), the exact shape of the F1 evasion, was
/// structurally unreachable at any case count. A property about a pair must
/// vary independently across every position it quantifies over: this draws
/// each position's representation (raw JSON number vs its decimal string) as
/// a separate draw, so the asymmetric pairing is a routine case, not an
/// unreachable one.
fn canonical_sequence_pair_strategy()
-> impl Strategy<Value = (serde_json::Value, serde_json::Value)> {
    (any::<u64>(), any::<bool>(), any::<bool>())
        .prop_map(|(n, rep_a, rep_b)| (int_rep(n, rep_a), int_rep(n, rep_b)))
}

/// Total witness count N∈[2,5] and the two positions among them that carry
/// the conflicting pair. For N=2 the pair is trivially `(0, 1)` -- there is no
/// other position it could occupy. For N≥3 the pair is confined to positions
/// `[1, N)`, so position 0 is always a distractor that can never be part of
/// the detected conflict: a regression that scans only `(reports[0],
/// reports[1])` instead of every pair would see nothing but disagreements
/// that never actually occur at that position, and would wrongly report no
/// evidence.
fn conflict_layout_strategy() -> impl Strategy<Value = (usize, usize, usize)> {
    (2usize..=5).prop_flat_map(|n| {
        if n == 2 {
            Just((n, 0usize, 1usize)).boxed()
        } else {
            (1usize..n - 1)
                .prop_flat_map(move |i| (i + 1..n).prop_map(move |j| (n, i, j)))
                .boxed()
        }
    })
}

/// Re-stamps a signed tip report's `pr`/`sequence` claims to arbitrary JSON
/// values and re-signs, mirroring the mutate-then-resign pattern the deleted
/// `non_standard_json_types_surfaced_by_consistency_check` used for its one
/// hand-picked pair -- `receipt::tip_report`'s public constructor only ever
/// composes a string `pr` and a `u64` `sequence`, so reaching the other type
/// families requires stamping the pay directly, exactly as that test did.
fn restamp_pr_sequence(
    mut tip: coz::CozJson,
    identity: &ServerIdentity,
    p: &serde_json::Value,
    s: &serde_json::Value,
) -> coz::CozJson {
    tip.pay["pr"] = p.clone();
    tip.pay["sequence"] = s.clone();
    let pay_bytes = serde_json::to_vec(&tip.pay).expect("serialize restamped pay");
    let (sig, _cad) = identity.sign(&pay_bytes).expect("re-sign restamped pay");
    tip.sig = sig;
    tip
}

/// Memoized deterministic identities for the property suite: the same three
/// fixed-seed signers as the file's other tests, built once and reused across
/// generated cases instead of re-deriving key material (tempdir + Ed25519
/// derivation) on every one of proptest's ~256 iterations per property.
fn property_identity(seed: u8) -> &'static ServerIdentity {
    use std::sync::OnceLock;
    static IDENTITY_A: OnceLock<(tempfile::TempDir, ServerIdentity)> = OnceLock::new();
    static IDENTITY_B: OnceLock<(tempfile::TempDir, ServerIdentity)> = OnceLock::new();
    static DISTRACTOR: OnceLock<(tempfile::TempDir, ServerIdentity)> = OnceLock::new();
    match seed {
        0x11 => &IDENTITY_A.get_or_init(|| identity_with_seed(0x11)).1,
        0x22 => &IDENTITY_B.get_or_init(|| identity_with_seed(0x22)).1,
        0x33 => &DISTRACTOR.get_or_init(|| identity_with_seed(0x33)).1,
        _ => unreachable!("property_identity: undeclared seed {seed:#x}"),
    }
}

proptest! {
    /// N1.1: `equivocation_conflict_yields_evidence_property`
    ///
    /// The invariant under test: when two witness reports about the same
    /// principal are Proven-eligible and disagree (same logical `pr`/`sequence`,
    /// differing `commit_id`), the check reports a standing claim naming that
    /// `pr`/`sequence` -- regardless of `pr`/`sequence`'s JSON type, regardless
    /// of which representation EACH report independently carries for the same
    /// logical value, regardless of how many OTHER witnesses (all distractors
    /// for an unrelated principal) share the slice, and regardless of where in
    /// that slice the conflicting pair sits.
    #[test]
    fn equivocation_conflict_yields_evidence_property(
        p in valid_pr_strategy(),
        (s_a, s_b) in canonical_sequence_pair_strategy(),
        (n, conflict_i, conflict_j) in conflict_layout_strategy(),
    ) {
        let (p_a, p_b) = (serde_json::Value::from(p.clone()), serde_json::Value::from(p.clone()));
        let now = 1_700_000_000;
        let identity_a = property_identity(0x11);
        let identity_b = property_identity(0x22);
        let distractor = property_identity(0x33);

        let base_a = receipt::tip_report(identity_a, now, &p, 0, digest(0x5a), &roots_a(), 1, now)
            .expect("compose conflict report A");
        let report_a = restamp_pr_sequence(base_a, identity_a, &p_a, &s_a);

        let base_b = receipt::tip_report(identity_b, now, &p, 0, digest(0x5b), &roots_a(), 1, now)
            .expect("compose conflict report B");
        let report_b = restamp_pr_sequence(base_b, identity_b, &p_b, &s_b);

        // A different principal entirely (`distractor_pr()` never equals the
        // generated `p`, an astronomically improbable byte collision), so
        // every pair touching a distractor slot is a non-conflict -- the
        // only detectable conflict in the whole slice is (conflict_i,
        // conflict_j).
        let distractor_report = receipt::tip_report(
            distractor,
            now,
            distractor_pr(),
            0,
            digest(0x5c),
            &roots_a(),
            1,
            now,
        )
        .expect("compose distractor report");

        let mut reports: Vec<(&coz::CozJson, &[u8])> = Vec::with_capacity(n);
        for idx in 0..n {
            if idx == conflict_i {
                reports.push((&report_a, identity_a.pub_key()));
            } else if idx == conflict_j {
                reports.push((&report_b, identity_b.pub_key()));
            } else {
                reports.push((&distractor_report, distractor.pub_key()));
            }
        }

        let claim = cyphr_server::consistency::check_cross_witness_consistency(&reports);
        prop_assert!(
            claim.is_some(),
            "a conflicting pair at positions ({conflict_i}, {conflict_j}) of {n} witnesses MUST \
             yield evidence, p_a={p_a:?} p_b={p_b:?} s_a={s_a:?} s_b={s_b:?}"
        );
        let claim = claim.unwrap();
        prop_assert_eq!(claim["kind"].clone(), serde_json::json!("equivocation_evidence"));
        // The evidence labels the claimed position in one of the pair's own
        // attested representations (`receipts.md`: the bundled reports are the
        // proof; the top-level fields are the label). Either member's
        // representation is a faithful label; a value matching neither is not.
        let pid = claim["principal_id"].clone();
        prop_assert!(
            pid == p_a || pid == p_b,
            "evidence principal_id {pid:?} MUST be one of the pair's attested representations \
             ({p_a:?} / {p_b:?})"
        );
        let seq = claim["sequence"].clone();
        prop_assert!(
            seq == s_a || seq == s_b,
            "evidence sequence {seq:?} MUST be one of the pair's attested representations \
             ({s_a:?} / {s_b:?})"
        );
    }

    /// N1.2: `equivocation_agreement_yields_none_property`
    ///
    /// The invariant under test: N∈[2,5] witness reports that all agree (same
    /// logical `pr`/`sequence`, same `commit_id`/`roots`) yield NO evidence and
    /// NO standing claim (K1) -- regardless of `pr`/`sequence`'s JSON type,
    /// regardless of which representation each report independently carries
    /// for the same logical value, and regardless of how many witnesses attest
    /// it.
    #[test]
    fn equivocation_agreement_yields_none_property(
        p in valid_pr_strategy(),
        (s_a, s_b) in canonical_sequence_pair_strategy(),
        n in 2usize..=5,
    ) {
        let (p_a, p_b) = (serde_json::Value::from(p.clone()), serde_json::Value::from(p.clone()));
        let now = 1_700_000_000;
        let identity_a = property_identity(0x11);
        let identity_b = property_identity(0x22);

        let base_a = receipt::tip_report(identity_a, now, &p, 0, digest(0x6a), &roots_a(), 1, now)
            .expect("compose agreeing report A");
        let report_a = restamp_pr_sequence(base_a, identity_a, &p_a, &s_a);

        let base_b = receipt::tip_report(identity_b, now, &p, 0, digest(0x6a), &roots_a(), 1, now)
            .expect("compose agreeing report B");
        let report_b = restamp_pr_sequence(base_b, identity_b, &p_b, &s_b);

        // Alternate signers across positions (tmb/alg differ, not part of the
        // comparison) so agreement is exercised across distinct witnesses --
        // each carrying its OWN independently drawn representation of the same
        // logical claim -- not one witness's report duplicated.
        let reports: Vec<(&coz::CozJson, &[u8])> = (0..n)
            .map(|idx| {
                if idx % 2 == 0 {
                    (&report_a, identity_a.pub_key())
                } else {
                    (&report_b, identity_b.pub_key())
                }
            })
            .collect();

        let claim = cyphr_server::consistency::check_cross_witness_consistency(&reports);
        prop_assert!(
            claim.is_none(),
            "{n} agreeing tip reports MUST produce no standing claim, p_a={p_a:?} p_b={p_b:?} \
             s_a={s_a:?} s_b={s_b:?}"
        );
    }

    /// N1.3: `equivocation_invalid_sig_not_counted_property`
    ///
    /// The invariant under test: a report whose signature does not verify under
    /// the caller-supplied key is never counted toward an equivocation, even
    /// when its claimed content would otherwise conflict -- regardless of
    /// `pr`/`sequence`'s JSON type, regardless of which representation each
    /// report independently carries for the same logical value, regardless of
    /// witness count N∈[2,5], and regardless of which of the two
    /// otherwise-conflicting reports carries the bad signature.
    #[test]
    fn equivocation_invalid_sig_not_counted_property(
        p in valid_pr_strategy(),
        (s_a, s_b) in canonical_sequence_pair_strategy(),
        n in 2usize..=5,
        corrupt_a in any::<bool>(),
    ) {
        let (p_a, p_b) = (serde_json::Value::from(p.clone()), serde_json::Value::from(p.clone()));
        let now = 1_700_000_000;
        let identity_a = property_identity(0x11);
        let identity_b = property_identity(0x22);
        let distractor = property_identity(0x33);
        let wrong_key: Vec<u8> = vec![0xff; 32];

        let base_a = receipt::tip_report(identity_a, now, &p, 0, digest(0x7a), &roots_a(), 1, now)
            .expect("compose conflict report A");
        let report_a = restamp_pr_sequence(base_a, identity_a, &p_a, &s_a);

        let base_b = receipt::tip_report(identity_b, now, &p, 0, digest(0x7b), &roots_a(), 1, now)
            .expect("compose conflict report B");
        let report_b = restamp_pr_sequence(base_b, identity_b, &p_b, &s_b);

        let distractor_report = receipt::tip_report(
            distractor,
            now,
            distractor_pr(),
            0,
            digest(0x7c),
            &roots_a(),
            1,
            now,
        )
        .expect("compose distractor report");

        let (key_a, key_b): (&[u8], &[u8]) = if corrupt_a {
            (wrong_key.as_slice(), identity_b.pub_key())
        } else {
            (identity_a.pub_key(), wrong_key.as_slice())
        };

        let mut reports: Vec<(&coz::CozJson, &[u8])> = vec![(&report_a, key_a), (&report_b, key_b)];
        for _ in 2..n {
            reports.push((&distractor_report, distractor.pub_key()));
        }

        let claim = cyphr_server::consistency::check_cross_witness_consistency(&reports);
        prop_assert!(
            claim.is_none(),
            "an invalid signature on one of the two otherwise-conflicting reports MUST prevent \
             the pair from counting as equivocation, corrupt_a={corrupt_a}, n={n}, \
             p_a={p_a:?} p_b={p_b:?} s_a={s_a:?} s_b={s_b:?}"
        );
    }
}

// ========================================================================
// F1/F2 acceptance (N1.9, N1.11): the security lens's live evasion and
// the evidence-hygiene contract
// ========================================================================

/// Total witness count N∈[3,5] and the two positions among them carrying the
/// conflicting pair, positions [1, N) -- position 0 is always a distractor.
/// N starts at 3 (unlike `conflict_layout_strategy`) because at N=2 the whole
/// slice IS the conflicting pair and whole-slice bundling would be
/// indistinguishable from pair-only evidence.
fn pair_among_distractors_strategy() -> impl Strategy<Value = (usize, usize, usize)> {
    (3usize..=5).prop_flat_map(|n| {
        (1usize..n - 1).prop_flat_map(move |i| (i + 1..n).prop_map(move |j| (n, i, j)))
    })
}

proptest! {
    /// N1.9 (F1): `equivocation_asymmetric_type_still_detected_property`
    ///
    /// The invariant under test: a dishonest signer that hand-crafts its two
    /// reports so the SAME logical `sequence` arrives as a raw JSON number at
    /// one witness and as its decimal string at the other -- with genuinely
    /// conflicting `commit_id` -- is still detected. Representation asymmetry
    /// is signer-controlled bytes, not a different logical claim; letting it
    /// read as "different sequence" silently discards a provable equivocation
    /// and defeats the non-repudiation this node exists to provide. Unlike
    /// N1.1 (where asymmetry is reachable), every case here IS asymmetric.
    #[test]
    fn equivocation_asymmetric_type_still_detected_property(
        seq in any::<u64>(),
        string_side_a in any::<bool>(),
    ) {
        let now = 1_700_000_000;
        let identity_a = property_identity(0x11);
        let identity_b = property_identity(0x22);

        let seq_num = serde_json::Value::from(seq);
        let seq_str = serde_json::Value::from(seq.to_string());
        let (s_a, s_b) = if string_side_a {
            (seq_str, seq_num)
        } else {
            (seq_num, seq_str)
        };
        let pr = principal_digest(0x91);
        let p = serde_json::Value::from(pr.clone());

        let base_a = receipt::tip_report(identity_a, now, &pr, 0, digest(0x9a), &roots_a(), 1, now)
            .expect("compose conflict report A");
        let report_a = restamp_pr_sequence(base_a, identity_a, &p, &s_a);

        let base_b = receipt::tip_report(identity_b, now, &pr, 0, digest(0x9b), &roots_a(), 1, now)
            .expect("compose conflict report B");
        let report_b = restamp_pr_sequence(base_b, identity_b, &p, &s_b);

        let claim = cyphr_server::consistency::check_cross_witness_consistency(&[
            (&report_a, identity_a.pub_key()),
            (&report_b, identity_b.pub_key()),
        ]);
        prop_assert!(
            claim.is_some(),
            "the same logical sequence {seq} claimed as {s_a:?} to one witness and {s_b:?} to \
             another, with conflicting commit_id, MUST still yield equivocation evidence"
        );
    }

    /// N1.11 (F2): `evidence_names_exactly_the_conflicting_pair`
    ///
    /// The invariant under test: the evidence bundle contains EXACTLY the two
    /// conflicting reports, in scan order -- not the whole queried slice
    /// (`receipts.md`: equivocation evidence is "exactly two things, nothing
    /// else"). Bundling unrelated witnesses' reports about other principals
    /// pollutes a portable proof with third-party statements and grows
    /// evidence O(N) with the query size.
    #[test]
    fn evidence_names_exactly_the_conflicting_pair(
        (n, conflict_i, conflict_j) in pair_among_distractors_strategy(),
    ) {
        let now = 1_700_000_000;
        let identity_a = property_identity(0x11);
        let identity_b = property_identity(0x22);
        let distractor = property_identity(0x33);

        let pr = principal_digest(0xa1);
        let report_a =
            receipt::tip_report(identity_a, now, &pr, 5, digest(0xa2), &roots_a(), 6, now)
                .expect("compose conflict report A");
        let report_b =
            receipt::tip_report(identity_b, now, &pr, 5, digest(0xa3), &roots_b(), 6, now)
                .expect("compose conflict report B");
        let distractor_report = receipt::tip_report(
            distractor,
            now,
            distractor_pr(),
            0,
            digest(0xa4),
            &roots_a(),
            1,
            now,
        )
        .expect("compose distractor report");

        let mut reports: Vec<(&coz::CozJson, &[u8])> = Vec::with_capacity(n);
        for idx in 0..n {
            if idx == conflict_i {
                reports.push((&report_a, identity_a.pub_key()));
            } else if idx == conflict_j {
                reports.push((&report_b, identity_b.pub_key()));
            } else {
                reports.push((&distractor_report, distractor.pub_key()));
            }
        }

        let claim = cyphr_server::consistency::check_cross_witness_consistency(&reports)
            .expect("conflicting pair MUST yield evidence");
        let bundled = claim["reports"]
            .as_array()
            .expect("evidence reports MUST be an array")
            .clone();
        prop_assert_eq!(
            bundled.len(),
            2,
            "evidence MUST bundle exactly the conflicting pair, not all {} queried reports",
            n
        );
        prop_assert_eq!(
            bundled[0].clone(),
            serde_json::to_value(&report_a).expect("serialize report A"),
            "first bundled report MUST be conflicting report A"
        );
        prop_assert_eq!(
            bundled[1].clone(),
            serde_json::to_value(&report_b).expect("serialize report B"),
            "second bundled report MUST be conflicting report B"
        );
    }
}
