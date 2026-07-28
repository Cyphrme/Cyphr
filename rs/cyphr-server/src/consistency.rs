//! Cross-witness consistency evaluation and disagreement evidence formatting
//! (`docs/specs/receipts.md`).

use crate::receipt;

/// Evaluates cross-witness consistency over a set of signed tip reports and their public keys.
///
/// If any pair of signed tip reports for the same principal (`pr`) and sequence
/// position (`sequence`) pass signature verification and contain conflicting tip state (`commit_id`
/// or `roots`), a fork/equivocation is detected and disagreement evidence is formatted (N4.1).
/// Unauthenticated or forged tip reports fail signature verification and are rejected upfront.
///
/// If all reports for matching principal/sequence agree (or no matching pair exists),
/// no standing claim or alert is produced (N4.6), returning `None`.
pub fn check_cross_witness_consistency(
    reports: &[(&coz::CozJson, &[u8])],
) -> Option<serde_json::Value> {
    for i in 0..reports.len() {
        for j in (i + 1)..reports.len() {
            let (a, a_pub_key) = reports[i];
            let (b, b_pub_key) = reports[j];

            let verdict = receipt::check_equivocation(a, a_pub_key, b, b_pub_key);
            if verdict == receipt::EquivocationVerdict::Proven {
                let pr_a = a.pay["pr"].clone();
                let seq_a = a.pay["sequence"].clone();
                let coz_reports: Vec<coz::CozJson> =
                    reports.iter().map(|(r, _)| (*r).clone()).collect();
                let evidence = format_disagreement_evidence(pr_a, seq_a, &coz_reports);
                return Some(evidence);
            }
        }
    }

    None
}

/// Offline verification of equivocation evidence (N4.2).
///
/// Verifies that evidence produced by cross-witness checking is completely
/// self-contained and verifies offline without relying on any active server connection.
pub fn verify_evidence_offline(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> bool {
    let verdict = receipt::check_equivocation(a, a_pub_key, b, b_pub_key);
    verdict == receipt::EquivocationVerdict::Proven
}

/// Verifies that witness key validity for signing tip reports is strictly bounded
/// by the key's validity interval `[first_seen, revocation)` (N4.3).
pub fn verify_key_validity_interval(key: &cyphr::Key, at_timestamp: i64) -> bool {
    if at_timestamp < key.first_seen {
        return false;
    }
    if let Some(rev) = &key.revocation {
        if at_timestamp >= rev.rvk {
            return false;
        }
    }
    true
}

/// Verifies key validity using a portable key-inclusion proof (N4.3a).
///
/// Delegates to `cyphr::inclusion::verify_key_inclusion` to establish key validity
/// offline without requiring an in-memory `Principal` object.
pub fn verify_key_portable_proof(
    alg: cyphr::HashAlg,
    thumbprint: &coz::Thumbprint,
    hops: &[cyphr::LeafProof],
    roots: &[&[u8]],
) -> bool {
    cyphr::inclusion::verify_key_inclusion(alg, thumbprint, hops, roots)
}

/// Fork detection ignoring unverified self-assertions and unauthenticated reports (N4.4).
///
/// Returns `true` if and only if both reports pass signature verification and
/// constitute a proven fork/equivocation. Unverified self-assertions or invalid signatures
/// return `false`.
pub fn detect_fork_unverified(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> bool {
    let verdict = receipt::check_equivocation(a, a_pub_key, b, b_pub_key);
    verdict == receipt::EquivocationVerdict::Proven
}

/// Checks whether cross-witness agreement satisfies a principal-settable threshold (N4.5).
pub fn check_witness_threshold(required_witnesses: usize, actual_witnesses: usize) -> bool {
    actual_witnesses >= required_witnesses
}

/// Formats disagreement evidence for conflicting tip reports (N4.7).
///
/// The output matches the golden vector `witness_disagreement.json`.
/// Note that monotone disagreement artifacts carry no `now`/expiry.
pub fn format_disagreement_evidence(
    principal_id: impl Into<serde_json::Value>,
    sequence: impl Into<serde_json::Value>,
    reports: &[coz::CozJson],
) -> serde_json::Value {
    serde_json::json!({
        "kind": "equivocation_evidence",
        "principal_id": principal_id.into(),
        "sequence": sequence.into(),
        "reports": reports,
    })
}
