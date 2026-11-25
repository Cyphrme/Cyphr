//! # Kept state and counters
//!
//! What the engine keeps between uses of a principal: the verified state
//! a write resumes from ([`KeptStates`]), the roots memo
//! ([`BoundedCache`]) and the cost counters tests pin ([`Counters`]). All of
//! it is a cache of what a replay of the blob store derives (I1): losing
//! any of it costs a recomputation, never an answer.

use std::collections::HashMap;

use super::EngineError;
use super::ingest::WriteLock;
/// A small insertion-ordered cache that never holds more than `capacity`
/// entries: when full, the oldest insertion is evicted.
///
/// Used only for memoizing replay-derived answers under keys that name the
/// exact tip they were derived at, so an entry can never be stale (a new
/// commit changes the key) and eviction costs only a recomputation.
pub(super) struct BoundedCache<K, V> {
    capacity: usize,
    entries: std::sync::Mutex<(HashMap<K, V>, std::collections::VecDeque<K>)>,
}

impl<K: Clone + Eq + std::hash::Hash, V: Clone> BoundedCache<K, V> {
    /// An empty cache holding at most `capacity` entries.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: std::sync::Mutex::new((HashMap::new(), std::collections::VecDeque::new())),
        }
    }

    /// The value stored under `key`, if still held.
    pub fn get(&self, key: &K) -> Option<V> {
        let guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.get(key).cloned()
    }

    /// Store `value` under `key`, evicting the oldest entry if over capacity.
    pub fn insert(&self, key: K, value: V) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.insert(key.clone(), value).is_none() {
            order.push_back(key);
            while map.len() > self.capacity {
                match order.pop_front() {
                    Some(oldest) => {
                        map.remove(&oldest);
                    },
                    None => break,
                }
            }
        }
    }
}

/// A principal's verified state kept between its uses, so a write checks
/// only what arrives and a read checks nothing, not the history before it.
/// A cache of what a replay of the blob store derives (I1), never
/// authoritative and never persisted: losing it costs one replay.
///
/// It is the state at the commit `tip`, and is used only while the index
/// names that commit as the principal's tip, read fresh under the
/// principal's write lock. Nothing else is part of what it was folded
/// from. Every held action is stored by a write that holds the state under
/// the same lock, so a state kept after it holds it too. A naked revoke
/// gates what arrives after it and judges nothing held (SPEC 6.4, 14.12),
/// so it is checked against each arriving bundle ([`dead_key_in`]) and
/// never folded into a state: one revoke, of any key, leaves every kept
/// state as good as it was.
///
/// A principal whose history carries an embedded principal's pin or Key
/// Tree digest (`embeds`) is kept as its replay built it and no further: a
/// write follows each embedded principal to the tip held now, where a
/// replay pins it at the tip each commit was admitted against, so the
/// state a write leaves is not the replay's. The replay itself reads only
/// the principal's own stored record (a pin names the embedded state by
/// its root, read from that commit's ancestry whatever the embedded
/// principal did since), so it stays good until the next write.
#[derive(Debug, Clone)]
pub(super) struct Kept {
    pub(super) state: cyphr::PrincipalState,
    pub(super) tip: String,
    pub(super) embeds: bool,
}

/// A principal verified at its tip ([`StorageEngine::verified`]).
pub(super) struct Verified<S: cyphr::eml::Storage> {
    pub(super) principal: cyphr::Principal<S>,
    /// [`Kept::embeds`] of its state.
    pub(super) embeds: bool,
}

/// A stored principal, verified, at its tip ([`StorageEngine::at_tip`]):
/// its state, over the engine's own durable commit log. It hands out only
/// a shared reference, so a holder can read state, roots and proofs of any
/// past log size and cannot append to the engine's log.
///
/// It is also what [`StorageEngine::load_principal`] returns: the same
/// read-only view, replayed from the store instead of read from the kept
/// state.
pub struct AtTip<S: cyphr::eml::Storage>(cyphr::Principal<S>);

impl<S: cyphr::eml::Storage> std::ops::Deref for AtTip<S> {
    type Target = cyphr::Principal<S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: cyphr::eml::Storage> AtTip<S> {
    pub(super) fn new(principal: cyphr::Principal<S>) -> Self {
        Self(principal)
    }

    /// The principal over an in-memory commit log
    /// ([`cyphr::Principal::detach`]), for a holder that verifies commits
    /// against it, as a pull does, without writing to the engine's log.
    /// The engine admits what that holder verified only through
    /// [`StorageEngine::submit_commit`], which checks it again. Costs the
    /// state's unshared part and O(log n) commit-log nodes, never the
    /// history.
    ///
    /// # Errors
    ///
    /// [`EngineError::Protocol`] if the log's frontier cannot be read.
    pub async fn detach(self) -> Result<cyphr::Principal<cyphr::eml::MemoryStorage>, EngineError> {
        self.0.detach().await.map_err(EngineError::Protocol)
    }
}

/// The kept states, at most `capacity` of them, the least recently used
/// evicted first (a read stores its principal's again).
///
/// Every access takes the principal's write-lock guard as a witness and
/// names its principal through it, so an entry can be read or written only
/// by the one writer of its principal (I2), and no call can pair one
/// principal's guard with another's id; the map's own mutex only orders the
/// map, and is never held across an `.await`.
pub(super) struct KeptStates {
    capacity: usize,
    /// Replay cold and compare with a kept state at every use
    /// ([`StorageEngine::with_kept_shadow`]).
    shadow: bool,
    entries: std::sync::Mutex<(HashMap<String, Kept>, std::collections::VecDeque<String>)>,
}

/// [`StorageEngine::verified`]'s boxed future.
pub(super) type VerifiedFuture<'a, S> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Verified<S>, EngineError>> + Send + 'a>,
>;

impl KeptStates {
    pub(super) fn new(capacity: usize, shadow: bool) -> Self {
        Self {
            capacity,
            shadow,
            entries: std::sync::Mutex::default(),
        }
    }

    /// A copy of the entry of the principal `write` locks, for a test's
    /// reader that must leave it in place ([`StorageEngine::kept_state`]).
    #[cfg(any(test, feature = "test-utils"))]
    pub(super) fn copy(&self, write: &WriteLock<'_>) -> Option<Kept> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .get(write.principal())
            .cloned()
    }

    /// Move the entry out for the one holder of `write`: a writer applies
    /// a bundle to it in place, and [`Self::put`] stores it again only if
    /// it is still a state of the stored chain.
    pub(super) fn take(&self, write: &WriteLock<'_>) -> Option<Kept> {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.1.retain(|id| id != write.principal());
        guard.0.remove(write.principal())
    }

    pub(super) fn put(&self, kept: Kept, write: &WriteLock<'_>) {
        if self.capacity == 0 {
            return;
        }
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let (map, order) = &mut *guard;
        if map.insert(write.principal().to_string(), kept).is_some() {
            order.retain(|id| id != write.principal());
        }
        order.push_back(write.principal().to_string());
        while map.len() > self.capacity {
            match order.pop_front() {
                Some(oldest) => {
                    map.remove(&oldest);
                },
                None => break,
            }
        }
    }

    /// Whether anything is kept at all: a capacity of 0 keeps nothing.
    pub(super) fn enabled(&self) -> bool {
        self.capacity > 0
    }

    pub(super) fn shadow(&self) -> bool {
        self.shadow
    }

    pub(super) fn set_shadow(&mut self, on: bool) {
        self.shadow = on;
    }

    /// The same cache holding at most `capacity` states, now empty, with
    /// shadow checking as it was.
    pub(super) fn resized(&self, capacity: usize) -> Self {
        Self::new(capacity, self.shadow)
    }

    /// Forget everything: a rebuild re-derives the engine's caches from
    /// the blobs, and so must the states folded from the old ones.
    pub(super) fn clear(&self) {
        let mut guard = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        guard.0.clear();
        guard.1.clear();
    }
}

/// Kept states an engine holds unless told otherwise. Each is the size of
/// its principal's history, so the bound is on memory; an evicted
/// principal's next use replays once and is kept again.
pub(super) const DEFAULT_KEPT_CAPACITY: usize = 128;

/// Derived-roots entries an engine memoizes by commit.
pub(super) const ROOTS_MEMO_CAPACITY: usize = 1024;

/// One of the engine's cost counters.
#[derive(Debug, Clone, Copy)]
pub(super) enum Counter {
    /// Stored commits retention has replayed, ever. Retention is paid by
    /// refused bundles, so its cost is the quantity tests pin.
    RetentionReplays,
    /// Candidate positions retention has tried a bundle at.
    RetentionTrials,
    /// Commits whose manifest was stored but whose commit-log append
    /// failed: the log is behind until the next load repairs it.
    LogAppendFailures,
    /// Writes served from a kept state.
    KeptHits,
    /// Writes that replayed.
    KeptMisses,
    /// Shadow checks where the kept state was not the replayed one.
    KeptDivergences,
    /// Stored commits re-applied by any replay path, ever. Not counted:
    /// commits re-applied while following embedded principals, and the
    /// re-application a rebuild of the index does.
    CommitsReplayed,
    /// Commit records read from the index, ever.
    ChainRowsRead,
}

/// The engine's counters, each only ever added to.
#[derive(Debug, Default)]
pub(super) struct Counters {
    cells: [std::sync::atomic::AtomicU64; 8],
}

impl Counters {
    pub(super) fn add(&self, counter: Counter, n: u64) {
        self.cells[counter as usize].fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub(super) fn bump(&self, counter: Counter) {
        self.add(counter, 1);
    }

    pub(super) fn get(&self, counter: Counter) -> u64 {
        self.cells[counter as usize].load(std::sync::atomic::Ordering::Relaxed)
    }
}
