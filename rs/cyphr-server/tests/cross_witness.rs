//! Acceptance test suite for Node N4: Cross-Witness Consistency.
//!
//! Evaluates criteria N4.1 – N4.6 & N4.7:
//! - `conflicting_tips_yield_evidence` (N4.1): Conflicting tip reports from distinct witnesses
//!   yield portable equivocation evidence.
//! - `evidence_verifies_offline` (N4.2): Equivocation evidence is self-contained and verifies
//!   offline without server cooperation.
//! - `key_validity_interval` (N4.3): Witness key validity is strictly bounded by [first_seen,
//!   revocation) interval.
//! - `key_validity_from_portable_proof` (N4.3a): Key validity is verified using portable
//!   key-inclusion proof, NOT in-memory Principal.
//! - `fork_detection_ignores_self_assertion` (N4.4): Fork detection ignores unverified
//!   self-assertions and unauthenticated reports.
//! - `principal_settable_threshold` (N4.5): Principal can configure a settable witness threshold.
//! - `agreement_produces_no_standing_claim` (N4.6): Agreement across queried witnesses produces no
//!   standing claim or alert.
//! - `golden_disagreement_artifact_byte_stable` (N4.7): Disagreement evidence serializes
//!   deterministically matching golden vector.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::principal_tree::PrincipalTree;
use cyphr::semantic_tree::{AuthTree, KeyTree, StateTree};
use cyphr::state::TaggedDigest;
use cyphr::{HashAlg, LeafProof};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::receipt::{self, Roots};

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

/// `non_standard_json_types_surfaced_by_consistency_check`
///
/// Verifies that a `pr` restamped to a non-standard JSON type (an integer,
/// which is not a digest encoding at all) is neither silently compared
/// nor silently proven: `check_equivocation` diagnoses it as `Malformed`
/// (`receipt::TipReport::parse`'s typed-domain boundary), and
/// `check_cross_witness_consistency` -- which forwards a claim only on
/// `Proven` -- produces no claim for the pair. This test previously
/// asserted the opposite (a restamped-integer `pr` still reached `Proven`
/// and a forwarded claim); that assertion is now wrong by construction,
/// since an integer `pr` fails to parse as a `TaggedDigest` on either
/// side -- see `receipt::TipReport::parse`'s field-disposition rule.
#[tokio::test]
async fn non_standard_json_types_surfaced_by_consistency_check() {
    let (_dir_a, identity_a) = identity_with_seed(0x11);
    let (_dir_b, identity_b) = identity_with_seed(0x22);

    let now = 1_700_000_000;
    let pr = principal_digest(0x30);

    let mut tip_a = receipt::tip_report(&identity_a, now, &pr, 1, digest(0x3a), &roots_a(), 6, now)
        .expect("compose tip A");

    let mut tip_b = receipt::tip_report(&identity_b, now, &pr, 1, digest(0x3b), &roots_b(), 6, now)
        .expect("compose tip B");

    tip_a.pay["pr"] = serde_json::json!(9999);
    tip_a.pay["sequence"] = serde_json::json!("42");
    let pay_bytes_a = serde_json::to_vec(&tip_a.pay).unwrap();
    let (sig_bytes_a, _cad) = identity_a.sign(&pay_bytes_a).unwrap();
    tip_a.sig = sig_bytes_a;

    tip_b.pay["pr"] = serde_json::json!(9999);
    tip_b.pay["sequence"] = serde_json::json!("42");
    let pay_bytes_b = serde_json::to_vec(&tip_b.pay).unwrap();
    let (sig_bytes_b, _cad) = identity_b.sign(&pay_bytes_b).unwrap();
    tip_b.sig = sig_bytes_b;

    let verdict =
        receipt::check_equivocation(&tip_a, identity_a.pub_key(), &tip_b, identity_b.pub_key());
    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::Malformed,
        "an integer `pr` is not a digest encoding on either side -- MALFORMED, not silently Proven"
    );

    let claim = cyphr_server::consistency::check_cross_witness_consistency(&[
        (&tip_a, identity_a.pub_key()),
        (&tip_b, identity_b.pub_key()),
    ]);
    assert!(
        claim.is_none(),
        "check_cross_witness_consistency forwards a claim only on a Proven verdict; a malformed \
         pair yields none here. This documents TODAY's behavior, not a closed guarantee: the \
         distinct Malformed diagnostic exists at check_equivocation, but no consumer currently \
         reads it as distinct from an honest non-conflict -- closing that gap needs a consumer \
         that treats Malformed specially and an ingestion gate that refuses a malformed report \
         before it is ever retained as a claim"
    );
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
    assert!(
        verified_offline,
        "cross-witness evidence MUST verify offline without server cooperation"
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

/// N4.3a: `key_validity_from_portable_proof`
///
/// Verifies key validity using a portable key-inclusion proof
/// (`cyphr::inclusion::verify_key_inclusion`), NOT an in-memory `Principal` object. Ensures that
/// offline cross-witness verification can establish key validity purely from self-contained proof
/// material and a trusted Principal Root.
#[tokio::test]
async fn key_validity_from_portable_proof() {
    let alg = HashAlg::Sha256;
    let (hops, roots, tmb_a, tmb_b) = build_key_inclusion_material(alg);
    let root_refs: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();

    // 1. Portable key inclusion verification against non-trivial, valid proof MUST succeed
    assert!(
        cyphr::inclusion::verify_key_inclusion(alg, &tmb_a, &hops, &root_refs),
        "valid portable key inclusion proof MUST verify successfully"
    );

    // 2. Mismatched thumbprint MUST fail verification
    assert!(
        !cyphr::inclusion::verify_key_inclusion(alg, &tmb_b, &hops, &root_refs),
        "portable proof verification with mismatched thumbprint MUST fail"
    );

    // 3. Empty / invalid proof material MUST fail verification
    let empty_hops: Vec<LeafProof> = vec![];
    let empty_roots: Vec<&[u8]> = vec![];
    assert!(
        !cyphr::inclusion::verify_key_inclusion(alg, &tmb_a, &empty_hops, &empty_roots),
        "empty or invalid proof material MUST return false"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let portable_proof_result =
        cyphr_server::consistency::verify_key_portable_proof(alg, &tmb_a, &hops, &root_refs);
    assert!(
        portable_proof_result,
        "portable key inclusion proof MUST verify witness key validity offline without in-memory \
         Principal"
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
    assert!(
        !fork_detected_for_unverified,
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

/// N4.5: `principal_settable_threshold`
///
/// Verifies that a principal can specify a settable witness threshold (e.g. M-of-N agreement
/// threshold for cross-witness confirmation).
#[tokio::test]
async fn principal_settable_threshold() {
    // Call domain consistency module (cyphr_server::consistency)
    let threshold_unmet = cyphr_server::consistency::check_witness_threshold(3, 2);
    assert!(!threshold_unmet, "actual < required MUST return false");

    let threshold_boundary = cyphr_server::consistency::check_witness_threshold(2, 2);
    assert!(
        threshold_boundary,
        "actual == required MUST satisfy threshold"
    );

    let threshold_exceeded = cyphr_server::consistency::check_witness_threshold(2, 3);
    assert!(
        threshold_exceeded,
        "actual > required MUST satisfy threshold"
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
