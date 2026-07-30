//! Cross-witness consistency evaluation and disagreement evidence formatting
//! (`docs/specs/receipts.md`).

use crate::receipt;

/// Why [`check_cross_witness_consistency`] produced no equivocation
/// evidence.
///
/// Kept distinct from the `Ok` evidence case so a report that fails to
/// canonicalize can never silently read as an honest, agreeing pair --
/// the fold [`receipt::EquivocationVerdict::Malformed`]'s own doc names as
/// still open at this consumer. Deliberately NOT folded into the evidence
/// `Value` itself: `receipts.md`'s wire vocabulary defines no claim kind
/// for "a report was malformed," so fabricating one here would put a
/// synthetic claim on the wire that no golden vector or spec section
/// authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoEvidence {
    /// Every evaluated pair canonicalized and none conflicted (or fewer
    /// than two reports were supplied) -- a genuine non-conflict; no
    /// standing claim (N4.6).
    NoConflict,
    /// At least one evaluated pair had a report that failed to
    /// canonicalize ([`receipt::EquivocationVerdict::Malformed`]), and no
    /// pair proved equivocation. Distinct from `NoConflict`: the check
    /// could not rule the set out, it only failed to prove it in.
    Malformed,
}

/// Evaluates cross-witness consistency over a set of signed tip reports and their public keys.
///
/// If any pair of signed tip reports for the same principal (`pr`) and sequence
/// position (`sequence`) pass signature verification and contain conflicting tip state (`commit_id`
/// or `roots`), a fork/equivocation is detected and disagreement evidence -- naming
/// exactly that conflicting pair, nothing else (`receipts.md:267-269`) -- is
/// formatted (N4.1). Unauthenticated or forged tip reports fail signature
/// verification and are rejected upfront.
///
/// If all reports for matching principal/sequence agree (or no matching pair exists),
/// no standing claim or alert is produced (N4.6), returning `Err(NoEvidence::NoConflict)`.
/// If no pair proves equivocation but some evaluated pair contained a report that
/// failed to canonicalize, returns `Err(NoEvidence::Malformed)` -- distinct from
/// `NoConflict` so a malformed report can never silently read as honest agreement.
pub fn check_cross_witness_consistency(
    reports: &[(&coz::CozJson, &[u8])],
) -> Result<serde_json::Value, NoEvidence> {
    let mut any_malformed = false;

    for i in 0..reports.len() {
        for j in (i + 1)..reports.len() {
            let (a, a_pub_key) = reports[i];
            let (b, b_pub_key) = reports[j];

            match receipt::check_equivocation(a, a_pub_key, b, b_pub_key) {
                receipt::EquivocationVerdict::Proven => {
                    let pr_a = a.pay["pr"].clone();
                    let seq_a = a.pay["sequence"].clone();
                    let evidence =
                        format_disagreement_evidence(pr_a, seq_a, &[a.clone(), b.clone()]);
                    return Ok(evidence);
                },
                receipt::EquivocationVerdict::Malformed => any_malformed = true,
                _ => {},
            }
        }
    }

    if any_malformed {
        Err(NoEvidence::Malformed)
    } else {
        Err(NoEvidence::NoConflict)
    }
}

/// Offline verification of equivocation evidence (N4.2).
///
/// Verifies that evidence produced by cross-witness checking is completely
/// self-contained and verifies offline without relying on any active server connection.
///
/// `Some(true)` -- proven equivocation. `Some(false)` -- the reports
/// canonicalize and verify but do not conflict (or a signature/typ check
/// failed outright). `None` -- at least one report failed to canonicalize
/// ([`receipt::EquivocationVerdict::Malformed`]): the predicate has no
/// answer, distinct from the `Some(false)` "verified, no conflict" case,
/// so a malformed report can never read as verified honest agreement.
pub fn verify_evidence_offline(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> Option<bool> {
    match receipt::check_equivocation(a, a_pub_key, b, b_pub_key) {
        receipt::EquivocationVerdict::Malformed => None,
        verdict => Some(verdict == receipt::EquivocationVerdict::Proven),
    }
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
/// Returns `Some(true)` if and only if both reports pass signature verification and
/// constitute a proven fork/equivocation. Unverified self-assertions or invalid signatures
/// return `Some(false)`.
///
/// As [`verify_evidence_offline`]: `None` marks a report that failed to
/// canonicalize, distinct from `Some(false)`.
pub fn detect_fork_unverified(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> Option<bool> {
    match receipt::check_equivocation(a, a_pub_key, b, b_pub_key) {
        receipt::EquivocationVerdict::Malformed => None,
        verdict => Some(verdict == receipt::EquivocationVerdict::Proven),
    }
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
