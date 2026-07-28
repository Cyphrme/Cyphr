//! Acceptance test suite for Node N4: Cross-Witness Consistency.
//!
//! Evaluates criteria N4.1 – N4.6 & N4.7:
//! - `conflicting_tips_yield_evidence` (N4.1): Conflicting tip reports from distinct witnesses yield portable equivocation evidence.
//! - `evidence_verifies_offline` (N4.2): Equivocation evidence is self-contained and verifies offline without server cooperation.
//! - `key_validity_interval` (N4.3): Witness key validity is strictly bounded by [first_seen, revocation) interval.
//! - `key_validity_from_portable_proof` (N4.3a): Key validity is verified using portable key-inclusion proof, NOT in-memory Principal.
//! - `fork_detection_ignores_self_assertion` (N4.4): Fork detection ignores unverified self-assertions and unauthenticated reports.
//! - `principal_settable_threshold` (N4.5): Principal can configure a settable witness threshold.
//! - `agreement_produces_no_standing_claim` (N4.6): Agreement across queried witnesses produces no standing claim or alert.
//! - `golden_disagreement_artifact_byte_stable` (N4.7): Disagreement evidence serializes deterministically matching golden vector.

use coz::Thumbprint;
use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::commit_root::hash_alg_to_u64;
use cyphr::principal_tree::PrincipalTree;
use cyphr::semantic_tree::{AuthTree, KeyTree, StateTree};
use cyphr::{HashAlg, LeafProof};
use cyphr_server::auth::ServerIdentity;
use cyphr_server::receipt::{self, Roots};

mod common;

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

fn roots_a() -> Roots {
    Roots {
        pr: "SHA-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        sr: "SHA-256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        ar: "SHA-256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
        cr: "SHA-256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_string(),
    }
}

fn roots_b() -> Roots {
    Roots {
        cr: "SHA-256:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE".to_string(),
        ..roots_a()
    }
}

/// Builds the 4-hop KT -> AR-node -> SR-node -> PT chain for non-trivial
/// portable key inclusion testing (N4.3a).
fn build_key_inclusion_material(
    alg: HashAlg,
) -> (
    Vec<cyphr::LeafProof>,
    Vec<Vec<u8>>,
    Thumbprint,
    Thumbprint,
) {
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

    let pr = "n4-principal-conflicting-tips";
    let seq = 5;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(
        &identity_a,
        now,
        pr,
        seq,
        "SHA-256:commit_id_aaaaa",
        &roots_a(),
        6,
        now,
    )
    .expect("compose tip A");

    let tip_b = receipt::tip_report(
        &identity_b,
        now,
        pr,
        seq,
        "SHA-256:commit_id_bbbbb",
        &roots_b(),
        6,
        now,
    )
    .expect("compose tip B");

    let verdict = receipt::check_equivocation(
        &tip_a,
        identity_a.pub_key(),
        &tip_b,
        identity_b.pub_key(),
    );

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::Proven,
        "conflicting signed tip reports from distinct witnesses MUST yield proven equivocation evidence"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let claim = cyphr_server::consistency::check_cross_witness_consistency(&[tip_a, tip_b])
        .expect("cross-witness consistency check MUST yield standing evidence claim on conflicting tips");
    assert_eq!(claim["kind"], "equivocation_evidence");
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

    let pr = "n4-principal-offline-verification";
    let seq = 10;
    let now = 1_700_050_000;

    let tip1 = receipt::tip_report(
        &identity_a,
        now,
        pr,
        seq,
        "SHA-256:commit_id_11111",
        &roots_a(),
        11,
        now,
    )
    .expect("compose tip 1");

    let tip2 = receipt::tip_report(
        &identity_b,
        now,
        pr,
        seq,
        "SHA-256:commit_id_22222",
        &roots_b(),
        11,
        now,
    )
    .expect("compose tip 2");

    let verdict = receipt::check_equivocation(
        &tip1,
        identity_a.pub_key(),
        &tip2,
        identity_b.pub_key(),
    );

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
        verified_offline.expect("offline evidence verifier MUST evaluate and confirm evidence validity"),
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

    let is_key_valid_at = |k: &cyphr::Key, t: i64| -> bool {
        if t < k.first_seen {
            return false;
        }
        if let Some(rev) = &k.revocation {
            if t >= rev.rvk {
                return false;
            }
        }
        true
    };

    assert!(
        !is_key_valid_at(&key, 1_700_099_999),
        "key MUST NOT be valid before first_seen timestamp"
    );

    assert!(
        is_key_valid_at(&key, 1_700_150_000),
        "key MUST be valid within [first_seen, revocation) interval"
    );

    assert!(
        !is_key_valid_at(&key, 1_700_200_000),
        "key MUST NOT be valid at or after revocation timestamp"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let evaluated_interval_validity = cyphr_server::consistency::verify_key_validity_interval(&key, 1_700_150_000);
    assert!(
        evaluated_interval_validity.expect("cross-witness key validity evaluator MUST enforce validity interval"),
        "key validity interval evaluation MUST pass for active key"
    );
}

/// N4.3a: `key_validity_from_portable_proof`
///
/// Verifies key validity using a portable key-inclusion proof (`cyphr::inclusion::verify_key_inclusion`),
/// NOT an in-memory `Principal` object. Ensures that offline cross-witness verification can establish
/// key validity purely from self-contained proof material and a trusted Principal Root.
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
    let portable_proof_result = cyphr_server::consistency::verify_key_portable_proof(alg, &tmb_a, &hops, &root_refs);
    assert!(
        portable_proof_result.expect("cross-witness evaluator MUST verify key validity from portable proof"),
        "portable key inclusion proof MUST verify witness key validity offline without in-memory Principal"
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

    let pr = "n4-principal-fork-self-assertion";
    let seq = 7;
    let now = 1_700_000_000;

    let valid_tip = receipt::tip_report(
        &valid_identity,
        now,
        pr,
        seq,
        "SHA-256:valid_commit_id",
        &roots_a(),
        8,
        now,
    )
    .expect("compose valid tip");

    let self_asserted_tip = receipt::tip_report(
        &untrusted_identity,
        now,
        pr,
        seq,
        "SHA-256:self_asserted_conflicting_commit",
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
        !fork_detected_for_unverified.expect("cross-witness evaluator MUST ignore unverified self-assertions"),
        "unverified self-assertion MUST NOT trigger fork evidence"
    );
}

/// N4.5: `principal_settable_threshold`
///
/// Verifies that a principal can specify a settable witness threshold (e.g. M-of-N agreement
/// threshold for cross-witness confirmation).
#[tokio::test]
async fn principal_settable_threshold() {
    let pr = "n4-principal-settable-threshold";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct WitnessThresholdConfig {
        principal_id: String,
        required_witnesses: usize,
        total_witnesses: usize,
    }

    let config = WitnessThresholdConfig {
        principal_id: pr.to_string(),
        required_witnesses: 2,
        total_witnesses: 3,
    };

    assert_eq!(config.required_witnesses, 2);
    assert_eq!(config.total_witnesses, 3);

    // Call domain consistency module (cyphr_server::consistency)
    let threshold_satisfied = cyphr_server::consistency::check_witness_threshold(config.required_witnesses, 2);
    assert!(
        threshold_satisfied.expect("cross-witness evaluator MUST enforce principal-settable threshold"),
        "cross-witness agreement MUST satisfy principal settable witness threshold"
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

    let pr = "n4-principal-agreement";
    let seq = 12;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(
        &identity_a,
        now,
        pr,
        seq,
        "SHA-256:agreeing_commit_id",
        &roots_a(),
        13,
        now,
    )
    .expect("compose tip A");

    let tip_b = receipt::tip_report(
        &identity_b,
        now,
        pr,
        seq,
        "SHA-256:agreeing_commit_id",
        &roots_a(),
        13,
        now,
    )
    .expect("compose tip B");

    let verdict = receipt::check_equivocation(
        &tip_a,
        identity_a.pub_key(),
        &tip_b,
        identity_b.pub_key(),
    );

    assert_eq!(
        verdict,
        receipt::EquivocationVerdict::IdenticalClaims,
        "agreeing tip reports MUST yield IdenticalClaims verdict"
    );

    // Call domain consistency module (cyphr_server::consistency)
    let standing_claim_on_agreement = cyphr_server::consistency::check_cross_witness_consistency(&[tip_a, tip_b]);
    let claim = standing_claim_on_agreement.expect("cross-witness evaluator MUST evaluate agreeing reports");
    assert!(
        claim.is_none(),
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

    let pr = "n4-principal-conflicting-tips";
    let seq = 5;
    let now = 1_700_000_000;

    let tip_a = receipt::tip_report(
        &identity_a,
        now,
        pr,
        seq,
        "SHA-256:commit_id_aaaaa",
        &roots_a(),
        6,
        now,
    )
    .expect("compose tip A");

    let tip_b = receipt::tip_report(
        &identity_b,
        now,
        pr,
        seq,
        "SHA-256:commit_id_bbbbb",
        &roots_b(),
        6,
        now,
    )
    .expect("compose tip B");

    let evidence_json = serde_json::json!({
        "kind": "equivocation_evidence",
        "principal_id": pr,
        "sequence": seq,
        "reports": [tip_a.clone(), tip_b.clone()],
    });

    let wire = serde_json::to_string(&evidence_json).unwrap();
    assert_eq!(wire, golden("witness_disagreement.json"));

    // Call domain consistency module (cyphr_server::consistency)
    let domain_evidence = cyphr_server::consistency::format_disagreement_evidence(pr, seq, &[tip_a, tip_b]);
    let formatted = domain_evidence.expect("consistency module MUST format disagreement evidence");
    let domain_wire = serde_json::to_string(&formatted).unwrap();
    assert_eq!(domain_wire, golden("witness_disagreement.json"));
}
