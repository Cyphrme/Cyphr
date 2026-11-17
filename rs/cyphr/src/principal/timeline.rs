//! The key timeline table (SPEC 6.5): which key was authorized at which
//! timestamp, derived from the commit chain and the naked revokes a
//! verifier holds, with the spans the principal was frozen and the time it
//! was deleted, so a data action is judged at its own `now`.

use std::collections::BTreeMap;

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::key::Key;

/// Every key's active periods (SPEC 6.2: a key may have several). A
/// period opens at the commit that leaves the key in KT and closes at the
/// commit that takes it out, each dated by the commit's `now`, or at a
/// naked revoke's cutoff (SPEC 6.4).
///
/// The periods are those of the commits alone, and a naked revoke is held
/// beside them and applied when a period is read. So the timeline is the
/// same whether a revoke arrived before a later commit (a live
/// principal) or after every commit (a replay), and a state kept past a
/// revoke equals the replay of its history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyTimeline {
    periods: Vec<Period>,
    /// Naked revokes by key: each takes effect from the cutoff it was
    /// noted with.
    revoked_from: BTreeMap<String, i64>,
    /// The spans the principal was frozen (SPEC 14.9), by commit `now`.
    frozen: Vec<(i64, Option<i64>)>,
    /// The `now` of the commit that deleted the principal (SPEC 11.4).
    deleted_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Period {
    key: Key,
    from: i64,
    until: Option<i64>,
    revoked: bool,
}

impl KeyTimeline {
    /// Record a commit dated `now` that leaves `active` in KT and `revoked`
    /// revoked: close the open period of every key it removed, open one
    /// for every key it added. Naked revokes are not applied here: see the
    /// type's docs.
    pub(crate) fn record_commit(
        &mut self,
        active: &IndexMap<String, Key>,
        revoked: &IndexMap<String, Key>,
        (frozen, deleted): (bool, bool),
        now: i64,
    ) {
        match (frozen, self.frozen.last_mut()) {
            (true, Some((_, None))) | (false, None | Some((_, Some(_)))) => {},
            (true, _) => self.frozen.push((now, None)),
            (false, Some((_, until @ None))) => *until = Some(now),
        }
        if deleted && self.deleted_at.is_none() {
            self.deleted_at = Some(now);
        }
        for p in self.periods.iter_mut().filter(|p| p.until.is_none()) {
            let tmb = p.key.tmb().to_b64();
            if !active.contains_key(&tmb) {
                p.until = Some(now);
                p.revoked = revoked.contains_key(&tmb);
            }
        }
        for key in active.values() {
            if self.open(key.tmb()).is_none() {
                self.periods.push(Period {
                    key: key.clone(),
                    from: now,
                    until: None,
                    revoked: false,
                });
            }
        }
    }

    /// A naked revoke of `tmb` cutting the key off at `cutoff` (SPEC 6.4;
    /// the caller's choice, a witness's receipt time): every period of the
    /// key ends at `cutoff` at the latest.
    pub(crate) fn revoke(&mut self, tmb: &Thumbprint, cutoff: i64) {
        let at = self.revoked_from.entry(tmb.to_b64()).or_insert(cutoff);
        *at = (*at).min(cutoff);
    }

    /// `p` as a naked revoke leaves it, if `cut` applies them: ended at the
    /// revoke's cutoff, no earlier than it began, if it would run past it.
    fn effective(&self, p: &Period, cut: bool) -> (Option<i64>, bool) {
        match self.revoked_from.get(&p.key.tmb().to_b64()) {
            Some(&cutoff) if cut && p.until.is_none_or(|u| u > cutoff) => {
                (Some(cutoff.max(p.from)), true)
            },
            _ => (p.until, p.revoked),
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
        self.authorize_with(tmb, now, true)
    }

    /// [`Self::authorize`] by the commits alone, naked revokes left out.
    pub(crate) fn authorize_by_commits(&self, tmb: &Thumbprint, now: i64) -> Option<Result<&Key>> {
        self.authorize_with(tmb, now, false)
    }

    fn authorize_with(&self, tmb: &Thumbprint, now: i64, cut: bool) -> Option<Result<&Key>> {
        let mut periods = self
            .periods
            .iter()
            .filter(|p| p.key.tmb() == tmb)
            .peekable();
        periods.peek()?;
        let mut refusal = Error::UnknownKey;
        for p in periods {
            let (until, revoked) = self.effective(p, cut);
            if p.from <= now && until.is_none_or(|u| now < u) {
                return Some(Ok(&p.key));
            }
            if revoked && until.is_some_and(|u| u <= now) {
                refusal = Error::KeyRevoked;
            }
        }
        Some(Err(refusal))
    }

    /// The key `tmb` named in any period of this principal, whether or not
    /// the key was active at any particular time.
    pub(crate) fn key_of(&self, tmb: &Thumbprint) -> Option<&Key> {
        self.periods
            .iter()
            .find(|p| p.key.tmb() == tmb)
            .map(|p| &p.key)
    }

    /// Whether `tmb` was ever a key of this principal.
    pub(crate) fn knows(&self, tmb: &Thumbprint) -> bool {
        self.periods.iter().any(|p| p.key.tmb() == tmb)
    }

    /// Whether the principal took data actions at `now`: not yet deleted,
    /// and not frozen then.
    ///
    /// # Errors
    ///
    /// `AlreadyDeleted` at or after the deleting commit; `Frozen` inside a
    /// frozen span.
    pub(crate) fn open_at(&self, now: i64) -> Result<()> {
        if self.deleted_at.is_some_and(|d| d <= now) {
            return Err(Error::AlreadyDeleted);
        }
        if self
            .frozen
            .iter()
            .any(|(from, until)| *from <= now && until.is_none_or(|u| now < u))
        {
            return Err(Error::Frozen);
        }
        Ok(())
    }

    fn open(&self, tmb: &Thumbprint) -> Option<&Period> {
        self.periods
            .iter()
            .find(|p| p.until.is_none() && p.key.tmb() == tmb)
    }
}
