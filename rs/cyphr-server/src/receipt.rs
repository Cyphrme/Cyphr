//! Signed server receipts: commit-acceptance and tip attestations
//! (`docs/specs/receipts.md`).
//!
//! A receipt is a Coz message the server signs with its own
//! [`ServerIdentity`], exactly the compose-and-sign pattern
//! [`ServerIdentity::issue_token`](super::auth::token) uses for bearer
//! tokens: `coz::Pay::new()`, a dedicated `typ` constant, extra claims,
//! serde to bytes, `identity.sign`, `coz::CozJson{pay, sig}`. Each kind
//! gets its own `typ` so no signature can be replayed across purposes
//! (the F22 lesson bearer tokens already close).
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
