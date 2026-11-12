//! The key timeline table (SPEC 6.5): which key was authorized at which
//! timestamp, derived from the commit chain and the naked revokes a
//! verifier holds.

use std::collections::HashMap;

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::key::Key;

/// Every key's active periods (SPEC 6.2: a key may have several). A
/// period opens at the commit that leaves the key in KT and closes at the
/// commit that takes it out, each dated by the commit's `now`, or at a
/// revoke's own `now` (SPEC 6.4).
#[derive(Debug, Clone, Default)]
pub(crate) struct KeyTimeline {
    periods: Vec<Period>,
    /// Naked revokes by key: each takes effect from its own `now`.
    revoked_from: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct Period {
    key: Key,
    from: i64,
    until: Option<i64>,
    revoked: bool,
}

impl KeyTimeline {
    /// Record a commit dated `now` that leaves `active` in KT and `revoked`
    /// revoked: close the open period of every key it removed, open one
    /// for every key it added. A key a naked revoke already took out opens
    /// no authority past that revoke.
    pub(crate) fn record_commit(
        &mut self,
        active: &IndexMap<String, Key>,
        revoked: &IndexMap<String, Key>,
        now: i64,
    ) {
        for p in self.periods.iter_mut().filter(|p| p.until.is_none()) {
            let tmb = p.key.tmb().to_b64();
            if !active.contains_key(&tmb) {
                p.until = Some(now);
                p.revoked = revoked.contains_key(&tmb);
            }
        }
        for (tmb, key) in active {
            if self.open(key.tmb()).is_none() {
                let from_revoke = self.revoked_from.get(tmb).copied();
                self.periods.push(Period {
                    key: key.clone(),
                    from: now,
                    until: from_revoke.map(|r| r.max(now)),
                    revoked: from_revoke.is_some(),
                });
            }
        }
    }

    /// A naked revoke of `tmb` dated `now` (SPEC 6.4): every period of the
    /// key ends at `now` at the latest.
    pub(crate) fn revoke(&mut self, tmb: &Thumbprint, now: i64) {
        let at = self.revoked_from.entry(tmb.to_b64()).or_insert(now);
        *at = (*at).min(now);
        let at = *at;
        for p in self.periods.iter_mut().filter(|p| p.key.tmb() == tmb) {
            if p.until.is_none_or(|u| u > at) {
                p.until = Some(at.max(p.from));
                p.revoked = true;
            }
        }
    }

    /// Whether `tmb` authorized a signature dated `now`: `None` if it was
    /// never a key of this principal; otherwise the key if a commit dated
    /// at or before `now` left it in KT and nothing removed it by then.
    /// A signature dated exactly at a removal is judged after it; one
    /// dated before genesis finds no key.
    ///
    /// # Errors
    ///
    /// `KeyRevoked` if a revoke took the key out at or before `now`;
    /// `UnknownKey` if it was not active at `now` otherwise.
    pub(crate) fn authorize(&self, tmb: &Thumbprint, now: i64) -> Option<Result<&Key>> {
        let mut periods = self
            .periods
            .iter()
            .filter(|p| p.key.tmb() == tmb)
            .peekable();
        periods.peek()?;
        let mut refusal = Error::UnknownKey;
        for p in periods {
            if p.from <= now && p.until.is_none_or(|u| now < u) {
                return Some(Ok(&p.key));
            }
            if p.revoked && p.until.is_some_and(|u| u <= now) {
                refusal = Error::KeyRevoked;
            }
        }
        Some(Err(refusal))
    }

    fn open(&self, tmb: &Thumbprint) -> Option<&Period> {
        self.periods
            .iter()
            .find(|p| p.until.is_none() && p.key.tmb() == tmb)
    }
}
