//! Genesis constructors, and the genesis finalization
//! (`principal/create`) that freezes PG.

use super::{Principal, PrincipalCore, PrincipalState, StartingRoots, open_commit_trees};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::semantic_tree::{derive_state_roots, key_leaf};
use crate::state::{PrincipalGenesis, derive_hash_algs};

// ============================================================================
// Genesis constructors (default in-memory storage)
// ============================================================================
//
// An inherent method on the concrete `Principal<eml::MemoryStorage>` so the
// bare `Principal` (the type parameter's default) resolves it without a
// storage argument. The storage-parameterised constructor, `open`, lives on
// the generic impl block below.
impl Principal<eml::MemoryStorage> {
    /// Create a principal from its genesis key: the only constructor;
    /// Levels 1-2 are this with no commit, Level 3+ commit their genesis
    /// from it.
    ///
    /// Per SPEC §3.2: "Identity emerges from first key possession"
    /// - `PR = AR = KR = tmb` (fully promoted)
    /// - PG is absent until a genesis commit's `principal/create` (SPEC 5.1)
    ///
    /// A principal is its genesis key: every further key, those of a
    /// multi-key genesis included, arrives by `key/create` (SPEC 5.1 step
    /// 2, 5.3; see [`Principal::commit_genesis`]).
    ///
    /// # Errors
    ///
    /// Returns `KeyRevoked` if the key carries a revocation: every key,
    /// the first included, enters through a `key/create` (SPEC §7.7), and
    /// a revoked key is never trusted again (SPEC §6.4).
    pub async fn implicit(key: Key) -> Result<Self> {
        Self::open(key, eml::MemoryStorage::new()).await
    }
}

impl PrincipalState {
    /// The state of the principal of genesis key `key` before any commit:
    /// `PR = AR = KR = tmb` (SPEC 3.2), with no log. Everything a
    /// principal at genesis answers without reading storage (its id, its
    /// keys) reads from this; [`Principal::open`] pairs it with a log.
    ///
    /// # Errors
    ///
    /// `KeyRevoked` if the key carries a revocation.
    pub fn genesis(key: Key) -> Result<Self> {
        if !key.is_active() {
            return Err(Error::KeyRevoked);
        }
        let active_algs = derive_hash_algs(&[&key]);

        // KT → AR-node → SR-node (no DR at genesis); PR = SR (no CR yet).
        let (kr, ar, sr) = derive_state_roots(&[key_leaf(&key)], None, &active_algs)?;
        let roots = StartingRoots::new(kr, ar, sr, None, &active_algs)?;
        Ok(Self {
            core: PrincipalCore::new(key, roots),
            pg: None,
            hidden: Default::default(),
        })
    }

    /// Transition from Nascent to Established by freezing PG.
    ///
    /// This is the only code path that can create an Established principal.
    /// Called exclusively from the PrincipalCreate coz handler, which
    /// refuses a repeat (`DuplicatePrincipal`) before reaching it.
    pub(super) fn establish_pg(&mut self, pg: PrincipalGenesis) {
        self.pg = Some(pg);
        self.hidden.clear();
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Open the principal of genesis key `key` over `storage`: its state at
    /// genesis, and its commit log as `storage` holds it (empty for fresh
    /// storage, a prior session's leaves otherwise, which replay then
    /// confirms).
    ///
    /// See [`Principal::implicit`] for the SPEC-level contract; this is the
    /// same construction with the storage backend named explicitly.
    ///
    /// # Errors
    ///
    /// `KeyRevoked` if the key carries a revocation; `Storage` if the log
    /// cannot be read.
    pub async fn open(key: Key, storage: S) -> Result<Self> {
        let state = PrincipalState::genesis(key)?;
        let log = open_commit_trees(storage).await?;
        Ok(Self { state, log })
    }

    /// Resume the principal whose verified `state` is held, over the
    /// durable `storage` that is its commit log: no commit is replayed.
    ///
    /// The state is the fold of every commit already verified, so a holder
    /// that kept it applies only what arrives after it. The check that the log is the one the state
    /// was folded from is constant-size: the log holds as many commits as the state
    /// and its Commit Root is the state's.
    ///
    /// # Errors
    ///
    /// `Storage` if the log cannot be read, or is not that state's: it holds
    /// another number of commits or another Commit Root.
    pub async fn resume(state: PrincipalState, storage: S) -> Result<Self> {
        let log = open_commit_trees(storage).await?;
        let commits = state.commits().count() as u64;
        let same = log.global_size() == commits
            && match state.cr() {
                None => commits == 0,
                Some(cr) => {
                    let algs: Vec<_> = cr.as_multihash().algorithms().collect();
                    crate::commit_root::commit_root_from_trees(&log, &algs)
                        .is_ok_and(|root| &root == cr)
                },
            };
        if !same {
            return Err(Error::Storage(format!(
                "commit log of {} leaves does not match the state's {commits} commits and Commit \
                 Root",
                log.global_size()
            )));
        }
        Ok(Self { state, log })
    }
}
