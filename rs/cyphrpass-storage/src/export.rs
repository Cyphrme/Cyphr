//! Export/import utilities for Principal storage.
//!
//! These functions bridge the `cyphrpass` Principal type with the storage layer,
//! enabling faithful round-trip serialization of identity state.

use crate::{Entry, Store};
use cyphrpass::Principal;

/// Export all entries from a Principal for storage.
///
/// Returns an iterator of `Entry` that can be persisted to any `Store`.
/// The order is: transactions first (in apply order), then actions.
///
/// # Example
///
/// ```ignore
/// let entries: Vec<Entry> = export_entries(&principal).collect();
/// for entry in entries {
///     store.append_entry(principal.pr(), &entry)?;
/// }
/// ```
pub fn export_entries(principal: &Principal) -> impl Iterator<Item = Entry> + '_ {
    let txs = principal.transactions().map(|t| Entry {
        raw: t.raw.pay.clone(),
        now: t.now,
    });
    let actions = principal.actions().map(|a| Entry {
        raw: a.raw.pay.clone(),
        now: a.now,
    });
    txs.chain(actions)
}

/// Export entries and persist them to storage.
///
/// This is a convenience function that combines export and storage.
pub fn persist_entries<S: Store>(store: &S, principal: &Principal) -> Result<usize, S::Error> {
    let mut count = 0;
    for entry in export_entries(principal) {
        store.append_entry(principal.pr(), &entry)?;
        count += 1;
    }
    Ok(count)
}
