//! Cross-witness consistency evaluation and disagreement evidence formatting
//! (`docs/specs/receipts.md`).

use thiserror::Error;

use crate::receipt;

/// Errors returned by cross-witness consistency operations.
#[derive(Debug, Error)]
pub enum ConsistencyError {
    /// Invalid receipt format encountered during consistency evaluation.
    #[error("invalid receipt format: {0}")]
    InvalidReceiptFormat(String),
}

/// Evaluates cross-witness consistency over a set of tip reports.
///
/// If any pair of signed tip reports for the same principal (`pr`) and sequence
/// position (`sequence`) contain conflicting tip state (`commit_id` or `roots`),
/// a fork/equivocation is detected and disagreement evidence is formatted (N4.1).
///
/// If all reports for matching principal/sequence agree (or no matching pair exists),
/// no standing claim or alert is produced (N4.6), returning `Ok(None)`.
pub fn check_cross_witness_consistency(
    reports: &[coz::CozJson],
) -> Result<Option<serde_json::Value>, ConsistencyError> {
    let tip_typ = serde_json::Value::String(receipt::TIP_REPORT_TYP.to_string());

    for i in 0..reports.len() {
        for j in (i + 1)..reports.len() {
            let a = &reports[i];
            let b = &reports[j];

            if a.pay["typ"] != tip_typ || b.pay["typ"] != tip_typ {
                continue;
            }

            let (Some(pr_a), Some(pr_b)) = (a.pay["pr"].as_str(), b.pay["pr"].as_str()) else {
                continue;
            };
            let (Some(seq_a), Some(seq_b)) =
                (a.pay["sequence"].as_u64(), b.pay["sequence"].as_u64())
            else {
                continue;
            };

            if pr_a == pr_b
                && seq_a == seq_b
                && (a.pay["commit_id"] != b.pay["commit_id"] || a.pay["roots"] != b.pay["roots"])
            {
                let evidence = format_disagreement_evidence(pr_a, seq_a, reports)?;
                return Ok(Some(evidence));
            }
        }
    }

    Ok(None)
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
) -> Result<bool, ConsistencyError> {
    let verdict = receipt::check_equivocation(a, a_pub_key, b, b_pub_key);
    Ok(verdict == receipt::EquivocationVerdict::Proven)
}

/// Verifies that witness key validity for signing tip reports is strictly bounded
/// by the key's validity interval `[first_seen, revocation)` (N4.3).
pub fn verify_key_validity_interval(
    key: &cyphr::Key,
    at_timestamp: i64,
) -> Result<bool, ConsistencyError> {
    if at_timestamp < key.first_seen {
        return Ok(false);
    }
    if let Some(rev) = &key.revocation {
        if at_timestamp >= rev.rvk {
            return Ok(false);
        }
    }
    Ok(true)
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
) -> Result<bool, ConsistencyError> {
    Ok(cyphr::inclusion::verify_key_inclusion(
        alg, thumbprint, hops, roots,
    ))
}

/// Fork detection ignoring unverified self-assertions and unauthenticated reports (N4.4).
///
/// Returns `Ok(true)` if and only if both reports pass signature verification and
/// constitute a proven fork/equivocation. Unverified self-assertions or invalid signatures
/// return `Ok(false)`.
pub fn detect_fork_unverified(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> Result<bool, ConsistencyError> {
    let verdict = receipt::check_equivocation(a, a_pub_key, b, b_pub_key);
    Ok(verdict == receipt::EquivocationVerdict::Proven)
}

/// Checks whether cross-witness agreement satisfies a principal-settable threshold (N4.5).
pub fn check_witness_threshold(
    required_witnesses: usize,
    actual_witnesses: usize,
) -> Result<bool, ConsistencyError> {
    Ok(actual_witnesses >= required_witnesses)
}

/// Formats disagreement evidence for conflicting tip reports (N4.7).
///
/// The output matches the golden vector `witness_disagreement.json`.
/// Note that monotone disagreement artifacts carry no `now`/expiry.
pub fn format_disagreement_evidence(
    principal_id: impl Into<String>,
    sequence: u64,
    reports: &[coz::CozJson],
) -> Result<serde_json::Value, ConsistencyError> {
    Ok(serde_json::json!({
        "kind": "equivocation_evidence",
        "principal_id": principal_id.into(),
        "sequence": sequence,
        "reports": reports,
    }))
}
