//! Per-thread counters of the work the core does, for tests that pin its
//! cost (U3): a count is the one evaluator for "this write copies nothing
//! held" and "this read judges nothing again", which no end-to-end
//! scenario can observe. Per thread, so parallel tests do not see one
//! another's work; test-only, never compiled into a release.

use std::cell::Cell;

thread_local! {
    static ACTION_CLONES: Cell<u64> = const { Cell::new(0) };
    static COMMIT_CLONES: Cell<u64> = const { Cell::new(0) };
    static VIEW_JUDGMENTS: Cell<u64> = const { Cell::new(0) };
    static SIGNATURES_CHECKED: Cell<u64> = const { Cell::new(0) };
    static HASHES: Cell<u64> = const { Cell::new(0) };
    static COMMITS_READ: Cell<u64> = const { Cell::new(0) };
}

/// Held actions copied by a clone of one (a state clone copies every
/// action it holds).
pub fn action_clones() -> u64 {
    ACTION_CLONES.with(Cell::get)
}

/// Finalized commits copied by a clone of one (a state clone copies every
/// commit it holds).
pub fn commit_clones() -> u64 {
    COMMIT_CLONES.with(Cell::get)
}

/// Held actions judged for DT's view of them ([`crate::PrincipalState::actions`]).
pub fn view_judgments() -> u64 {
    VIEW_JUDGMENTS.with(Cell::get)
}

/// Data-action signatures checked.
pub fn signatures_checked() -> u64 {
    SIGNATURES_CHECKED.with(Cell::get)
}

/// Digests computed (every hash the core takes of a node, leaf or
/// concatenation): the unit of "reads or hashes" in a cost bound.
pub fn hashes() -> u64 {
    HASHES.with(Cell::get)
}

/// Commits read out of a principal's chain by position or by iteration:
/// what a scan of history costs.
pub fn commits_read() -> u64 {
    COMMITS_READ.with(Cell::get)
}

pub(crate) fn hashed() {
    HASHES.with(|c| c.set(c.get() + 1));
}

pub(crate) fn commit_read() {
    COMMITS_READ.with(|c| c.set(c.get() + 1));
}

pub(crate) fn action_cloned() {
    ACTION_CLONES.with(|c| c.set(c.get() + 1));
}

pub(crate) fn commit_cloned() {
    COMMIT_CLONES.with(|c| c.set(c.get() + 1));
}

pub(crate) fn view_judged() {
    VIEW_JUDGMENTS.with(|c| c.set(c.get() + 1));
}

pub(crate) fn signature_checked() {
    SIGNATURES_CHECKED.with(|c| c.set(c.get() + 1));
}

/// Run `f` with the counters as they were: work that checks the core is not
/// work the core did.
pub(crate) fn uncounted<T>(f: impl FnOnce() -> T) -> T {
    let saved = (
        ACTION_CLONES.with(Cell::get),
        COMMIT_CLONES.with(Cell::get),
        VIEW_JUDGMENTS.with(Cell::get),
        SIGNATURES_CHECKED.with(Cell::get),
    );
    let out = f();
    ACTION_CLONES.with(|c| c.set(saved.0));
    COMMIT_CLONES.with(|c| c.set(saved.1));
    VIEW_JUDGMENTS.with(|c| c.set(saved.2));
    SIGNATURES_CHECKED.with(|c| c.set(saved.3));
    out
}
