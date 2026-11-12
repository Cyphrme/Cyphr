//! The key timeline table (SPEC 6.5): which key was authorized at which
//! timestamp, derived from the commit chain.

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::key::Key;

/// Every key's active periods (SPEC 6.2: a key may have several). A
/// period opens at the commit that leaves the key in KT and closes at the
/// commit that takes it out, each dated by the commit's `now`.
#[derive(Debug, Clone, Default)]
pub(crate) struct KeyTimeline {
    periods: Vec<Period>,
}

#[derive(Debug, Clone)]
struct Period {
    key: Key,
    from: i64,
    until: Option<i64>,
}

impl KeyTimeline {
    /// Record a commit dated `now` that leaves `active` in KT: close the
    /// open period of every key it removed, open one for every key it
    /// added.
    pub(crate) fn record_commit(&mut self, active: &IndexMap<String, Key>, now: i64) {
        for p in self.periods.iter_mut().filter(|p| p.until.is_none()) {
            if !active.contains_key(&p.key.tmb().to_b64()) {
                p.until = Some(now);
            }
        }
        for key in active.values() {
            if self.open(key.tmb()).is_none() {
                self.periods.push(Period {
                    key: key.clone(),
                    from: now,
                    until: None,
                });
            }
        }
    }

    /// End `tmb`'s open period at `now` outside a commit (a revocation
    /// applied directly, as test setup does).
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn close(&mut self, tmb: &Thumbprint, now: i64) {
        let open = self
            .periods
            .iter_mut()
            .find(|p| p.until.is_none() && p.key.tmb() == tmb);
        if let Some(p) = open {
            p.until = Some(now);
        }
    }

    /// The key `tmb` names if it was active at `now`: the commits dated at
    /// or before `now` left it in KT. An action dated exactly at a
    /// removal is judged after it; one dated before genesis finds none.
    pub(crate) fn active_at(&self, tmb: &Thumbprint, now: i64) -> Option<&Key> {
        self.periods
            .iter()
            .find(|p| p.key.tmb() == tmb && p.from <= now && p.until.is_none_or(|u| now < u))
            .map(|p| &p.key)
    }

    fn open(&self, tmb: &Thumbprint) -> Option<&Period> {
        self.periods
            .iter()
            .find(|p| p.until.is_none() && p.key.tmb() == tmb)
    }
}
