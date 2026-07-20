//! Signed server receipts: commit-acceptance and tip attestations
//! (`docs/specs/receipts.md`).
//!
//! A receipt is a Coz message the server signs with its own
//! [`ServerIdentity`], exactly the compose-and-sign pattern
//! [`ServerIdentity::issue_token`](super::auth::token) uses for bearer
//! tokens: `coz::Pay::new()`, a dedicated `typ` constant, extra claims,
//! serde to bytes, `identity.sign`, `coz::CozJson{pay, sig}`. Each kind
//! gets its own `typ` so no signature can be replayed across purposes,
//! the same replay-across-purposes closure bearer tokens already apply.
//!
//! Issuance is stateless (decision D2, `docs/specs/receipts.md`): nothing
//! here persists a receipt or a received-at time. The recipient holds the
//! trust object; the server signs and forgets.

use serde_json::Value;

use crate::auth::ServerIdentity;

/// The `typ` a signed commit-acceptance receipt (the `/push` statement
/// slot) is stamped with.
pub const COMMIT_RECEIPT_TYP: &str = "cyphr-server/receipt/commit";

/// The `typ` a signed tip report (the `/tip` statement slot) is stamped
/// with.
pub const TIP_REPORT_TYP: &str = "cyphr-server/receipt/tip";

/// The post-commit roots a receipt attests, exactly as the tip payload
/// carries them (`docs/specs/http-envelope.md` `[envelope-r-cr]`).
///
/// Nested under the `roots` claim so its `pr` (the post-commit Principal
/// Root) never collides with the receipt's top-level `pr` claim (the
/// attested principal's genesis identifier) -- the two are different
/// facts that happen to share a SPEC field name.
#[derive(Debug, Clone)]
pub struct Roots {
    pub pr: String,
    pub sr: String,
    pub ar: String,
    pub cr: String,
}

impl Roots {
    fn to_value(&self) -> Value {
        serde_json::json!({
            "pr": self.pr,
            "sr": self.sr,
            "ar": self.ar,
            "cr": self.cr,
        })
    }
}

/// Compose and sign a commit-acceptance receipt for `/push`'s statement
/// slot.
///
/// `pr` is the attested principal's genesis identifier; `sequence` is the
/// accepted commit's 0-indexed position (the post-state tip's
/// `commit_count - 1`); `roots` is the post-state roots exactly as the
/// tip payload carries them. Returns `None` if coz rejects the payload or
/// this identity's key (mirrors [`ServerIdentity::sign`]).
pub fn commit_receipt(
    identity: &ServerIdentity,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
) -> Option<coz::CozJson> {
    sign_receipt(
        identity,
        now,
        COMMIT_RECEIPT_TYP,
        pr,
        sequence,
        commit_id,
        roots,
        None,
    )
}

/// Compose and sign a tip report for `/tip`'s statement slot.
///
/// As [`commit_receipt`], plus the tip payload's `commit_count` and
/// `last_updated`, since a tip report attests the whole principal's
/// current state, not just the one commit that produced it.
#[allow(clippy::too_many_arguments)]
pub fn tip_report(
    identity: &ServerIdentity,
    now: i64,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
    commit_count: u64,
    last_updated: i64,
) -> Option<coz::CozJson> {
    sign_receipt(
        identity,
        now,
        TIP_REPORT_TYP,
        pr,
        sequence,
        commit_id,
        roots,
        Some((commit_count, last_updated)),
    )
}

/// Shared composition core for both receipt kinds: everything but `typ`
/// and the tip-only extra claims is identical, so the two public
/// constructors differ only in what they pass here.
#[allow(clippy::too_many_arguments)]
fn sign_receipt(
    identity: &ServerIdentity,
    now: i64,
    typ: &str,
    pr: impl Into<String>,
    sequence: u64,
    commit_id: impl Into<String>,
    roots: &Roots,
    tip_extra: Option<(u64, i64)>,
) -> Option<coz::CozJson> {
    let tmb = identity.alg().compute_thumbprint(identity.pub_key())?;

    let mut pay = coz::Pay::new();
    pay.alg = Some(identity.alg().name().to_string());
    pay.now = Some(now);
    pay.tmb = Some(tmb);
    pay.typ = Some(typ.to_string());
    pay.extra.insert("pr".to_string(), Value::String(pr.into()));
    pay.extra
        .insert("sequence".to_string(), Value::from(sequence));
    pay.extra
        .insert("commit_id".to_string(), Value::String(commit_id.into()));
    pay.extra.insert("roots".to_string(), roots.to_value());
    if let Some((commit_count, last_updated)) = tip_extra {
        pay.extra
            .insert("commit_count".to_string(), Value::from(commit_count));
        pay.extra
            .insert("last_updated".to_string(), Value::from(last_updated));
    }

    let pay_json = serde_json::to_vec(&pay).ok()?;
    let (sig, _cad) = identity.sign(&pay_json)?;
    let pay_value = serde_json::to_value(&pay).ok()?;

    Some(coz::CozJson {
        pay: pay_value,
        sig,
    })
}

/// The outcome of checking two signed tip reports for equivocation
/// (`docs/specs/receipts.md`'s equivocation section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationVerdict {
    /// Both reports carry a valid signature under their own
    /// caller-supplied key, share `pr` and `sequence`, and differ in
    /// `commit_id` or `roots` -- proven equivocation.
    Proven,
    /// One or both cozies are not stamped `typ == TIP_REPORT_TYP`.
    WrongTyp,
    /// One or both signatures fail to verify under the caller-supplied
    /// key.
    InvalidSignature,
    /// The two reports attest different principals (`pr`).
    DifferentPrincipal,
    /// The two reports attest different sequence positions.
    DifferentSequence,
    /// The two reports are claim-identical -- not a conflict.
    IdenticalClaims,
}

/// Check whether two signed tip reports constitute proven equivocation.
///
/// Pure: a function over the two raw coz values plus caller-supplied key
/// material only -- no engine, no `AppState`, no I/O, no clock, so a
/// verifier anywhere can run it on retained bytes. `a_pub_key` verifies
/// `a`'s signature and `b_pub_key` verifies `b`'s -- they may be
/// identical (the degenerate same-key case) or different (a
/// cross-key-rotation pair), since the server's identity is its chain,
/// not any single key.
///
/// The caller MUST have already established that both keys are active
/// keys of the SAME server principal's chain at each receipt's `now`
/// (`docs/specs/receipts.md`'s offline verification procedure) -- this
/// helper never resolves or chain-checks keys itself, which is what
/// keeps it pure while still covering the cross-rotation case.
///
/// The pinned predicate, checked in order: (1) both pays carry `typ ==
/// TIP_REPORT_TYP`; (2) each signature verifies under its own
/// caller-supplied key; (3) both claim the same `pr` and the same
/// `sequence`; (4) they differ in `commit_id` or in any `roots` field.
/// Anything else is a diagnosed non-equivocation.
pub fn check_equivocation(
    a: &coz::CozJson,
    a_pub_key: &[u8],
    b: &coz::CozJson,
    b_pub_key: &[u8],
) -> EquivocationVerdict {
    let tip_typ = Value::String(TIP_REPORT_TYP.to_string());
    if a.pay["typ"] != tip_typ || b.pay["typ"] != tip_typ {
        return EquivocationVerdict::WrongTyp;
    }

    if !receipt_signature_verifies(a, a_pub_key) || !receipt_signature_verifies(b, b_pub_key) {
        return EquivocationVerdict::InvalidSignature;
    }

    if a.pay["pr"] != b.pay["pr"] {
        return EquivocationVerdict::DifferentPrincipal;
    }
    if a.pay["sequence"] != b.pay["sequence"] {
        return EquivocationVerdict::DifferentSequence;
    }
    if a.pay["commit_id"] == b.pay["commit_id"] && a.pay["roots"] == b.pay["roots"] {
        return EquivocationVerdict::IdenticalClaims;
    }

    EquivocationVerdict::Proven
}

/// Verify one receipt cozy's signature against a caller-supplied key,
/// using only the `alg` the pay itself claims -- plain `coz::verify_json`,
/// no bespoke crypto.
fn receipt_signature_verifies(coz: &coz::CozJson, pub_key: &[u8]) -> bool {
    let Some(alg) = coz.pay["alg"].as_str() else {
        return false;
    };
    let Ok(pay_json) = serde_json::to_vec(&coz.pay) else {
        return false;
    };
    coz::verify_json(&pay_json, &coz.sig, alg, pub_key) == Some(true)
}
