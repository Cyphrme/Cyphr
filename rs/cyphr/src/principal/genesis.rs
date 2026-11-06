//! Genesis constructors, and the genesis finalization
//! (`principal/create`) that freezes PG.

use coz::Thumbprint;

use super::{Principal, PrincipalCore, PrincipalKind, StartingRoots, open_commit_trees};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::semantic_tree::derive_state_roots;
use crate::state::{PrincipalGenesis, derive_hash_algs, hash_alg_from_str};

// ============================================================================
// Genesis constructors (default in-memory storage)
// ============================================================================
//
// These are inherent methods on the concrete `Principal<eml::MemoryStorage>`
// rather than on the generic `impl<S: eml::Storage> Principal<S>` block, so
// every pre-existing call site that spells the bare `Principal` (which means
// `Principal<eml::MemoryStorage>` via the type parameter's default) keeps
// resolving to exactly these signatures with zero source changes. The
// storage-parameterised siblings — `implicit_with_storage`,
// `explicit_with_storage` — live on the generic impl block below.
impl Principal<eml::MemoryStorage> {
    /// Create a principal with implicit genesis (single key).
    ///
    /// Per SPEC §3.2: "Identity emerges from first key possession"
    /// - `PR = AR = KR = tmb` (fully promoted)
    /// - PG is absent (L1/L2 have no PG per SPEC §5.1)
    ///
    /// This is the Level 1/2 genesis path.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedAlgorithm` if the key's algorithm is not recognized.
    pub fn implicit(key: Key) -> Result<Self> {
        Self::implicit_with_storage(key, eml::MemoryStorage::new())
    }

    /// Create a principal with explicit genesis (multiple keys).
    ///
    /// Per SPEC §3.2: Multi-key accounts require explicit genesis
    /// - PR is absent at construction (established by principal/create)
    ///
    /// This is the Level 3+ genesis path.
    pub fn explicit(keys: Vec<Key>) -> Result<Self> {
        Self::explicit_with_storage(keys, eml::MemoryStorage::new())
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Transition from Nascent to Established by freezing PG.
    ///
    /// This is the only code path that can create an Established principal.
    /// Called exclusively from the PrincipalCreate coz handler.
    ///
    /// # Why `Option::take`, not `std::mem::take`
    ///
    /// The obvious implementation — `std::mem::take(&mut self.0)` swapping in
    /// `PrincipalKind::default()` — requires `PrincipalKind<S>: Default`,
    /// which (transitively, via a `PrincipalCore<S>: Default` impl) requires
    /// `S: Default`. `eml::MemoryStorage` derives `Default` trivially, but
    /// `storage_fjall::FjallStorage` cannot reasonably implement it —
    /// construction always requires either a filesystem path or an
    /// already-open `fjall::Database` handle, so there is no meaningful
    /// "empty" instance to hand back on the swap-out. Wrapping `Principal`'s
    /// inner kind in `Option` sidesteps this entirely: `Option::take` swaps
    /// in `None`, which needs no bound on `S` at all.
    pub(super) fn establish_pg(&mut self, pg: PrincipalGenesis) -> Result<()> {
        let old = self
            .0
            .take()
            .expect("Principal's inner kind is only None transiently inside establish_pg");
        match old {
            PrincipalKind::Nascent(core) => {
                self.0 = Some(PrincipalKind::Established { core, pg });
                Ok(())
            },
            est @ PrincipalKind::Established { .. } => {
                self.0 = Some(est); // restore
                Err(Error::StateMismatch) // already established
            },
        }
    }

    // ========================================================================
    // Genesis constructors (explicit storage)
    // ========================================================================

    /// Create a principal with implicit genesis (single key), backed by the
    /// given storage instance.
    ///
    /// See [`Principal::implicit`] for the SPEC-level contract; this is the
    /// same construction with the storage backend threaded through
    /// explicitly instead of defaulting to [`eml::MemoryStorage`].
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedAlgorithm` if the key's algorithm is not recognized.
    pub fn implicit_with_storage(key: Key, storage: S) -> Result<Self> {
        let hash_alg = hash_alg_from_str(key.alg())?;

        // Derive active algorithms from genesis key
        let active_algs = vec![hash_alg];

        // KT → AR-node → SR-node (no DR at genesis); PR = SR (no CR yet).
        let (kr, ar, sr) = derive_state_roots(&[key.tmb()], None, &active_algs)?;
        let roots = StartingRoots::new(kr, ar, sr, None, &active_algs)?;
        let core = PrincipalCore::new(vec![key], roots, open_commit_trees(storage)?);
        Ok(Self(Some(PrincipalKind::Nascent(core))))
    }

    /// Create a principal with explicit genesis (multiple keys), backed by
    /// the given storage instance.
    ///
    /// See [`Principal::explicit`] for the SPEC-level contract; this is the
    /// same construction with the storage backend threaded through
    /// explicitly instead of defaulting to [`eml::MemoryStorage`].
    pub fn explicit_with_storage(keys: Vec<Key>, storage: S) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let _ = hash_alg_from_str(keys[0].alg())?;

        // Derive active algorithms from all keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // KT → AR-node → SR-node (no DR at genesis); PR = SR (no CR yet).
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| k.tmb()).collect();
        let (kr, ar, sr) = derive_state_roots(&thumbprints, None, &active_algs)?;
        let roots = StartingRoots::new(kr, ar, sr, None, &active_algs)?;
        let core = PrincipalCore::new(keys, roots, open_commit_trees(storage)?);
        Ok(Self(Some(PrincipalKind::Nascent(core))))
    }
}
