//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphr protocol.
use std::collections::BTreeMap;

use coz::Thumbprint;
use indexmap::IndexMap;

use crate::action::Action;
use crate::commit::{Commit, CommitScope, PendingCommit};
use crate::error::{Error, Result};
use crate::key::Key;
use crate::multihash::MultihashDigest;
use crate::parsed_coz::VerifiedCoz;
use crate::principal_tree::PrincipalTree;
use crate::semantic_tree::{AuthTree, KeyTree, StateTree, derive_state_roots};
use crate::state::{
    AuthRoot, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot, compute_dr,
    derive_hash_algs, hash_alg_from_str,
};

/// Get current unix timestamp in seconds.
/// Separated for testability.
fn current_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64
}

// ============================================================================
// AuthLedger
// ============================================================================

/// Auth ledger holding keys and commits.
#[derive(Debug, Clone, Default)]
pub struct AuthLedger {
    /// Active keys (tmb b64 string → Key).
    pub keys: IndexMap<String, Key>,
    /// Revoked keys for historical verification.
    pub revoked: IndexMap<String, Key>,
    /// Finalized commits (atomic coz bundles).
    pub commits: Vec<Commit>,
}

/// Data ledger holding actions (Level 4+).
#[derive(Debug, Clone, Default)]
pub struct DataLedger {
    /// All recorded actions.
    pub actions: Vec<Action>,
}

// ============================================================================
// Feature Levels
// ============================================================================

/// Feature level of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Single static key.
    L1 = 1,
    /// Key replacement.
    L2 = 2,
    /// Multi-key.
    L3 = 3,
    /// Data layer (AAA).
    L4 = 4,
}

// ============================================================================
// Principal — Enum-based type safety for PR (Approach C)
// ============================================================================

/// Shared internal state for all Principal variants, generic over the
/// storage backend `S` backing [`Self::commit_trees`].
///
/// Every field *except* PR lives here. PR is structurally absent for Nascent
/// principals and structurally present for Established ones — invalid states
/// are unrepresentable.
///
/// # Visibility
///
/// `pub` to satisfy `Deref<Target = PrincipalCore<S>>` on `Principal<S>`.
/// All fields are `pub(crate)` — external code cannot access them.
///
/// # Manual `Debug`/`Clone`
///
/// Implemented by hand below rather than derived: `#[derive(...)]` would add
/// an `S: Debug`/`S: Clone` bound that isn't actually needed (both traits
/// pass straight through to [`crate::commit_root::CommitTrees`], which
/// already implements them unconditionally for any `S: eml::Storage`), and
/// `storage_fjall::FjallStorage` deliberately implements neither — a derived
/// bound would make `PrincipalCore<FjallStorage>` uninstantiable.
#[doc(hidden)]
pub struct PrincipalCore<S: eml::Storage = eml::MemoryStorage> {
    /// Current Principal State.
    pub(crate) pr: PrincipalRoot,
    /// Current Key State.
    pub(crate) kr: KeyRoot,
    /// Current Commit ID (Merkle root of last commit's cozies).
    pub(crate) tr: Option<crate::transaction_root::TransactionRoot>,
    /// Per-algorithm MALT trees for computing Commit Root (CR).
    pub(crate) commit_trees: crate::commit_root::CommitTrees<S>,
    /// Principal Tree (PT): the `EpochTree` backing PR. Cell 0 = SR, cell 1 =
    /// CR. The source of truth for PR; `sr`/`cr` below are a cache mirroring
    /// its cell contents (kept in lockstep by [`PrincipalCore::write_pt_sr`]
    /// and [`PrincipalCore::write_pt_sr_cr`]) so existing accessors
    /// (`Principal::sr()`/`cr()`) don't need to deserialize a cell payload on
    /// every call.
    pub(crate) pt: PrincipalTree,
    /// Current Commit Root (CR). Mirrors `pt`'s cell 1.
    pub(crate) cr: Option<crate::commit_root::CommitRoot>,
    /// Current State Root: SR = MR(AR, DR?, embedding?). Mirrors `pt`'s cell 0.
    pub(crate) sr: Option<StateRoot>,
    /// Current Auth State.
    pub(crate) ar: AuthRoot,
    /// Current Data State (Level 4+).
    pub(crate) dr: Option<DataRoot>,
    /// Auth ledger.
    pub(crate) auth: AuthLedger,
    /// Data ledger (Level 4+).
    pub(crate) data: DataLedger,
    /// Latest timestamp seen (SPEC §14.1).
    pub(crate) latest_timestamp: i64,
    /// Maximum allowed future timestamp (seconds from server time).
    pub(crate) max_clock_skew: i64,
    /// Base64 thumbprints of the genesis keys (keys present at construction).
    pub(crate) genesis_keys: Vec<String>,
    /// `principal/delete` has been signed (SPEC.md §11.1 `Deleted`). No
    /// transaction sets this yet — the field exists for the derivation in
    /// [`crate::lifecycle`] to read; it is always `false` at this node's tip.
    pub(crate) deleted: bool,
    /// `true` from the moment a `principal/delete` cozy is applied until
    /// the commit carrying it is successfully finalized (cleared at the
    /// end of `finalize_commit`). Scopes the `CommitCreate` exemption
    /// from [no-transactions-on-deleted] to same-commit finalization
    /// only: a commit/create finalizing a delete applied earlier in this
    /// same, still-open commit is exempt; a commit/create in a later,
    /// separately-finalized commit against an already-deleted principal
    /// is not.
    pub(crate) deleted_pending: bool,
    /// `freeze/create` is active and `freeze/delete` has not yet been signed
    /// (SPEC.md §11.1 `Frozen`). No transaction sets this yet — see `deleted`.
    pub(crate) frozen: bool,
    /// A fork or invalid chain has been detected (SPEC.md §11.1 `Errored`).
    /// Orthogonal to the base lifecycle state. No detector sets this yet
    /// (fork/chain-invalid detection is out of scope for this node); always
    /// `false` at this node's tip.
    pub(crate) errored: bool,
}

impl<S: eml::Storage> Clone for PrincipalCore<S> {
    fn clone(&self) -> Self {
        Self {
            pr: self.pr.clone(),
            kr: self.kr.clone(),
            tr: self.tr.clone(),
            commit_trees: self.commit_trees.clone(),
            pt: self.pt.clone(),
            cr: self.cr.clone(),
            sr: self.sr.clone(),
            ar: self.ar.clone(),
            dr: self.dr.clone(),
            auth: self.auth.clone(),
            data: self.data.clone(),
            latest_timestamp: self.latest_timestamp,
            max_clock_skew: self.max_clock_skew,
            genesis_keys: self.genesis_keys.clone(),
            deleted: self.deleted,
            deleted_pending: self.deleted_pending,
            frozen: self.frozen,
            errored: self.errored,
        }
    }
}

impl<S: eml::Storage> std::fmt::Debug for PrincipalCore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalCore")
            .field("pr", &self.pr)
            .field("kr", &self.kr)
            .field("tr", &self.tr)
            .field("commit_trees", &self.commit_trees)
            .field("pt", &self.pt)
            .field("cr", &self.cr)
            .field("sr", &self.sr)
            .field("ar", &self.ar)
            .field("dr", &self.dr)
            .field("auth", &self.auth)
            .field("data", &self.data)
            .field("latest_timestamp", &self.latest_timestamp)
            .field("max_clock_skew", &self.max_clock_skew)
            .field("genesis_keys", &self.genesis_keys)
            .field("deleted", &self.deleted)
            .field("deleted_pending", &self.deleted_pending)
            .field("frozen", &self.frozen)
            .field("errored", &self.errored)
            .finish()
    }
}

/// Internal variant: tracks whether PG has been established.
///
/// - **Nascent**: L1/L2 — no PG exists. Cannot fabricate one.
/// - **Established**: L3+ — PG is frozen from the initial PR. Cannot remove it.
enum PrincipalKind<S: eml::Storage = eml::MemoryStorage> {
    /// Pre-genesis-finalization: no PG field at all.
    Nascent(PrincipalCore<S>),
    /// Post-principal/create: PG is structurally required.
    Established {
        core: PrincipalCore<S>,
        pg: PrincipalGenesis,
    },
}

impl<S: eml::Storage> Clone for PrincipalKind<S> {
    fn clone(&self) -> Self {
        match self {
            Self::Nascent(core) => Self::Nascent(core.clone()),
            Self::Established { core, pg } => Self::Established {
                core: core.clone(),
                pg: pg.clone(),
            },
        }
    }
}

impl<S: eml::Storage> std::fmt::Debug for PrincipalKind<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nascent(core) => f.debug_tuple("Nascent").field(core).finish(),
            Self::Established { core, pg } => f
                .debug_struct("Established")
                .field("core", core)
                .field("pg", pg)
                .finish(),
        }
    }
}

/// A Cyphr Principal (self-sovereign identity), generic over the storage
/// backend `S` backing its Commit Tree (defaults to
/// [`eml::MemoryStorage`], so every pre-existing use of the bare
/// `Principal` type continues to mean exactly what it meant before this
/// type became generic).
///
/// # Type Safety
///
/// PG is represented via an internal enum:
/// - **Nascent** (L1/L2): PG does not exist — cannot be forged.
/// - **Established** (L3+): PG is frozen — cannot be removed.
///
/// All shared state is accessed via `Deref<Target = PrincipalCore<S>>`, so
/// `self.pr`, `self.kr`, etc. work transparently in all code paths.
///
/// # `Option`-wrapped inner kind
///
/// The inner [`PrincipalKind<S>`] is wrapped in `Option` solely so
/// [`Self::establish_pg`] can `.take()` it by value without requiring
/// `S: Default` (which `storage_fjall::FjallStorage` cannot reasonably
/// implement — see that method's doc comment). The `Option` is `None` only
/// for the instant inside `establish_pg` between the `.take()` and the
/// following assignment; every other method observes it as always `Some`.
pub struct Principal<S: eml::Storage = eml::MemoryStorage>(Option<PrincipalKind<S>>);

impl<S: eml::Storage> Clone for Principal<S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S: eml::Storage> std::fmt::Debug for Principal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Principal").field(&self.0).finish()
    }
}

impl<S: eml::Storage> Principal<S> {
    /// Borrow the inner kind.
    ///
    /// Panics only if called while a `establish_pg` call is itself
    /// mid-flight on the same value, which cannot happen — `establish_pg`
    /// takes `&mut self` and never calls back out to any other `Principal`
    /// method before restoring `self.0` to `Some`.
    fn kind(&self) -> &PrincipalKind<S> {
        self.0
            .as_ref()
            .expect("Principal's inner kind is only None transiently inside establish_pg")
    }
}

// Deref delegates field access to PrincipalCore transparently.
// This means `self.pr`, `self.kr`, `self.ar`, etc. all
// resolve automatically — zero changes needed in existing methods.
impl<S: eml::Storage> std::ops::Deref for Principal<S> {
    type Target = PrincipalCore<S>;

    fn deref(&self) -> &PrincipalCore<S> {
        match self.kind() {
            PrincipalKind::Nascent(core) => core,
            PrincipalKind::Established { core, .. } => core,
        }
    }
}

impl<S: eml::Storage> PrincipalCore<S> {
    pub(crate) fn active_algs(&self) -> Vec<HashAlg> {
        let key_refs: Vec<&crate::key::Key> = self.auth.keys.values().collect();
        crate::state::derive_hash_algs(&key_refs)
    }

    /// Write a new State Root into the Principal Tree's cell 0, leaving
    /// cell 1 (Commit Root) untouched, and return the recomputed Principal
    /// Root. Used outside commit finalization (e.g. `record_action`), where
    /// only SR changes.
    fn write_pt_sr(&mut self, sr: &StateRoot, algs: &[HashAlg]) -> Result<PrincipalRoot> {
        self.pt.set_sr(sr, algs)?;
        self.sr = Some(sr.clone());
        self.pt.pr(algs)
    }

    /// Write a new State Root into cell 0 and Commit Root into cell 1, and
    /// return the recomputed Principal Root. Used at commit finalization,
    /// where both SR and CR change together.
    fn write_pt_sr_cr(
        &mut self,
        sr: &StateRoot,
        cr: &crate::commit_root::CommitRoot,
        algs: &[HashAlg],
    ) -> Result<PrincipalRoot> {
        self.pt.set_sr(sr, algs)?;
        self.pt.set_cr(cr, algs)?;
        self.sr = Some(sr.clone());
        self.cr = Some(cr.clone());
        self.pt.pr(algs)
    }
}

impl<S: eml::Storage> Principal<S> {
    fn core_mut(&mut self) -> &mut PrincipalCore<S> {
        match self
            .0
            .as_mut()
            .expect("Principal's inner kind is only None transiently inside establish_pg")
        {
            PrincipalKind::Nascent(core) => core,
            PrincipalKind::Established { core, .. } => core,
        }
    }
}

// ============================================================================
// NodePath: chained multi-hop inclusion proofs
// ============================================================================

/// One hop of a chained inclusion proof: a self-contained leaf proof for a
/// specific level's cell, verified against that level's own root.
///
/// Crate-internal only (see [`NodePath`]'s note on why this isn't a public
/// portable proof type yet).
#[derive(Debug, Clone)]
pub(crate) struct NodePathHop {
    /// The leaf proof for this hop.
    pub(crate) proof: polydigest::LeafProof,
}

/// A top-down chain of inclusion hops used internally by
/// [`Principal::verify_key_inclusion`] — the generalization of
/// [`Principal::verify_transaction_inclusion`]'s 2-hop CR-in-PR chain into a
/// sequence of hops verified top-down from a trusted PR.
/// [`Principal::key_inclusion_proof`] produces the concrete
/// 4-hop instance chaining a key's thumbprint through KT -> AR-node ->
/// SR-node -> PT.
///
/// **Not a portable external proof type (crate-internal only).**
/// [`Self::verify`] requires the caller to already supply every
/// intermediate root (KR/AR/SR), and never binds the target leaf itself —
/// it proves "some leaf at `hops[0]`'s position sits under `roots`", not
/// "thumbprint T is included." In its one current use
/// ([`Principal::verify_key_inclusion`]) that's the right shape: generation
/// is keyed on the target thumbprint and the roots come from the
/// principal's own trusted cache, so it functions correctly as an
/// internal proof/cache cross-check. The genuinely portable proof — one a
/// remote verifier holding only a published PR and a thumbprint can check
/// unassisted — is [`crate::inclusion::verify_key_inclusion`], which adds
/// the missing thumbprint-to-leaf binding this type's `verify` alone does
/// not provide, rather than widening this type itself.
#[derive(Debug, Clone)]
pub(crate) struct NodePath {
    /// Hops in leaf-to-root order.
    pub(crate) hops: Vec<NodePathHop>,
}

impl NodePath {
    /// Verify every hop against its own level's authenticated root
    /// (`roots`, ordered leaf-to-root, one entry per hop), and every
    /// consecutive bridge — hop `i`'s proven leaf value must equal hop
    /// `i - 1`'s authenticated root — mirroring
    /// [`Principal::verify_transaction_inclusion`]'s single bridge check,
    /// scaled to an arbitrary-length chain.
    ///
    /// A promoted (single-cell) level's hop is not special-cased: its
    /// `LeafProof` carries an empty skeleton (a 1-cell tree's root is its
    /// sole leaf verbatim — see [`crate::principal_tree`]'s module docs),
    /// so `verify` reduces to a direct byte-equality check against `roots`
    /// through the same code path every other hop uses.
    #[must_use]
    pub(crate) fn verify(&self, hasher: &dyn eml::Hasher, roots: &[&[u8]]) -> bool {
        if self.hops.len() != roots.len() || self.hops.is_empty() {
            return false;
        }
        for (hop, &root) in self.hops.iter().zip(roots.iter()) {
            let Some(skeleton) = polydigest::rebalanced_skeleton(
                hop.proof.tree_size,
                hop.proof.arity,
                hop.proof.index,
            ) else {
                return false;
            };
            if !hop.proof.verify(hasher, &skeleton, root) {
                return false;
            }
        }
        for i in 1..self.hops.len() {
            if self.hops[i].proof.leaf_hash != roots[i - 1] {
                return false;
            }
        }
        true
    }
}

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

    /// Create a principal from a trusted checkpoint.
    ///
    /// This is used by storage import when loading from a checkpoint
    /// rather than replaying full history from genesis.
    ///
    /// When `trees` is `Some`, the MALT state is restored from the provided
    /// `CommitTrees`, enabling proof generation from the checkpoint forward.
    /// When `trees` is `None`, empty trees are initialized (backward-compatible
    /// for callers without MALT state).
    ///
    /// # Security
    ///
    /// The caller must establish trust in the checkpoint before calling this.
    /// The `pg` is accepted as-is (cannot be computed from checkpoint alone).
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `keys` is empty.
    /// Returns `UnsupportedAlgorithm` if key algorithm is unknown.
    pub fn from_checkpoint(
        pg: Option<PrincipalGenesis>,
        ar: AuthRoot,
        keys: Vec<Key>,
        trees: Option<crate::commit_root::CommitTrees>,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let _ = hash_alg_from_str(&keys[0].alg)?;

        // Derive active algorithms from checkpoint keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Compute KR from provided keys
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let kr = KeyTree::build(&thumbprints, &active_algs)?;

        // Restore MALT state if provided, otherwise start fresh.
        let (commit_trees, cr) = match trees {
            Some(t) => {
                let cr = crate::commit_root::commit_root_from_trees(&t, &active_algs)?;
                (t, Some(cr))
            },
            None => (
                crate::commit_root::CommitTrees::new(eml::MemoryStorage::new()),
                None,
            ),
        };

        // SR and PR: derive_state_roots is not used here because `ar` is
        // provided by the checkpoint, not derived from `kr`. We enter the
        // chain at SR-node directly.
        let sr = StateTree::build(&ar, None, &active_algs)?;
        // PR = EpochTree::root(alg_id): rebuild the Principal Tree from the
        // checkpoint's SR and (if restored) CR.
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &active_algs)?;
        if let Some(ref cr_val) = cr {
            pt.set_cr(cr_val, &active_algs)?;
        }
        let pr = pt.pr(&active_algs)?;

        let genesis_keys: Vec<String> = keys.iter().map(|k| k.tmb.to_b64()).collect();
        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }
        let core = PrincipalCore {
            pr,
            kr,
            tr: None,
            commit_trees,
            pt,
            cr,
            sr: Some(sr),
            ar,
            dr: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            latest_timestamp: 0,
            max_clock_skew: 0,
            genesis_keys,
            deleted: false,
            deleted_pending: false,
            frozen: false,
            errored: false,
        };

        Ok(match pg {
            Some(pg) => Self(Some(PrincipalKind::Established { core, pg })),
            None => Self(Some(PrincipalKind::Nascent(core))),
        })
    }
}

impl<S: eml::Storage> Principal<S> {
    // ========================================================================
    // Internal helpers
    // ========================================================================

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
    fn establish_pg(&mut self, pg: PrincipalGenesis) -> Result<()> {
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
        let hash_alg = hash_alg_from_str(&key.alg)?;
        let tmb_b64 = key.tmb.to_b64();

        // Derive active algorithms from genesis key
        let active_algs = vec![hash_alg];

        // KT → AR-node → SR-node (no DR at genesis)
        let (kr, ar, sr) = derive_state_roots(&[&key.tmb], None, &active_algs)?;
        // PR = SR (no CR at genesis): the tree's native singleton promotion.
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &active_algs)?;
        let pr = pt.pr(&active_algs)?;

        let mut keys = IndexMap::new();
        keys.insert(tmb_b64.clone(), key);

        Ok(Self(Some(PrincipalKind::Nascent(PrincipalCore {
            pr,
            kr,
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::open(storage)
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?,
            pt,
            cr: None,
            sr: Some(sr),
            ar,
            dr: None,
            auth: AuthLedger {
                keys,
                ..Default::default()
            },
            data: DataLedger::default(),
            latest_timestamp: 0,
            max_clock_skew: 0,
            genesis_keys: vec![tmb_b64],
            deleted: false,
            deleted_pending: false,
            frozen: false,
            errored: false,
        }))))
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

        let _ = hash_alg_from_str(&keys[0].alg)?;

        // Derive active algorithms from all keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Collect thumbprints for KR computation
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let genesis_keys: Vec<String> = thumbprints.iter().map(|t| t.to_b64()).collect();
        // KT → AR-node → SR-node (no DR at genesis)
        let (kr, ar, sr) = derive_state_roots(&thumbprints, None, &active_algs)?;
        // PR = SR (no CR at genesis): the tree's native singleton promotion.
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &active_algs)?;
        let pr = pt.pr(&active_algs)?;

        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }

        Ok(Self(Some(PrincipalKind::Nascent(PrincipalCore {
            pr,
            kr,
            tr: None,
            commit_trees: crate::commit_root::CommitTrees::open(storage)
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?,
            pt,
            cr: None,
            sr: Some(sr),
            ar,
            dr: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            latest_timestamp: 0,
            max_clock_skew: 0,
            genesis_keys,
            deleted: false,
            deleted_pending: false,
            frozen: false,
            errored: false,
        }))))
    }

    /// Create a principal from a trusted checkpoint, with its Commit Tree
    /// state restored from `trees` — the storage-generic sibling of
    /// [`Principal::from_checkpoint`].
    ///
    /// Unlike `from_checkpoint`, `trees` is not `Option`: a storage backend
    /// with no `Default` (e.g. `storage_fjall::FjallStorage`) has no
    /// meaningful "empty" instance to construct in a `None` branch, so the
    /// caller must always supply an already-constructed `CommitTrees<S>`
    /// (e.g. via [`crate::commit_root::CommitTrees::open`] against a
    /// durable backend that may already carry prior state).
    ///
    /// # Security
    ///
    /// The caller must establish trust in the checkpoint before calling this.
    /// The `pg` is accepted as-is (cannot be computed from checkpoint alone).
    ///
    /// # Errors
    ///
    /// Returns `NoActiveKeys` if `keys` is empty.
    /// Returns `UnsupportedAlgorithm` if key algorithm is unknown.
    pub fn from_checkpoint_with_trees(
        pg: Option<PrincipalGenesis>,
        ar: AuthRoot,
        keys: Vec<Key>,
        trees: crate::commit_root::CommitTrees<S>,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }

        let _ = hash_alg_from_str(&keys[0].alg)?;

        // Derive active algorithms from checkpoint keys (SPEC §14)
        let key_refs: Vec<&Key> = keys.iter().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Compute KR from provided keys
        let thumbprints: Vec<&Thumbprint> = keys.iter().map(|k| &k.tmb).collect();
        let kr = KeyTree::build(&thumbprints, &active_algs)?;

        // A restored, non-empty log yields a CR; a genuinely empty one
        // (e.g. a fresh backend with no prior commits) does not — mirrors
        // `from_checkpoint`'s `Some`/`None` split, decided here by the
        // tree's own emptiness rather than by an `Option` at the API
        // boundary.
        let cr = if trees.is_empty() {
            None
        } else {
            Some(crate::commit_root::commit_root_from_trees(
                &trees,
                &active_algs,
            )?)
        };

        // SR and PR: derive_state_roots is not used here because `ar` is
        // provided by the checkpoint, not derived from `kr`. We enter the
        // chain at SR-node directly.
        let sr = StateTree::build(&ar, None, &active_algs)?;
        // PR = EpochTree::root(alg_id): rebuild the Principal Tree from the
        // checkpoint's SR and (if restored) CR.
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &active_algs)?;
        if let Some(ref cr_val) = cr {
            pt.set_cr(cr_val, &active_algs)?;
        }
        let pr = pt.pr(&active_algs)?;

        let genesis_keys: Vec<String> = keys.iter().map(|k| k.tmb.to_b64()).collect();
        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb.to_b64(), k);
        }
        let core = PrincipalCore {
            pr,
            kr,
            tr: None,
            commit_trees: trees,
            pt,
            cr,
            sr: Some(sr),
            ar,
            dr: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            latest_timestamp: 0,
            max_clock_skew: 0,
            genesis_keys,
            deleted: false,
            deleted_pending: false,
            frozen: false,
            errored: false,
        };

        Ok(match pg {
            Some(pg) => Self(Some(PrincipalKind::Established { core, pg })),
            None => Self(Some(PrincipalKind::Nascent(core))),
        })
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Get the Principal Genesis, or None if not yet established (L1/L2).
    ///
    /// PG is only set when principal/create is processed (Level 3+, SPEC §5.1).
    /// For Established principals, this always returns `Some`.
    pub fn pg(&self) -> Option<&PrincipalGenesis> {
        match self.kind() {
            PrincipalKind::Established { pg, .. } => Some(pg),
            PrincipalKind::Nascent(_) => None,
        }
    }

    /// Get the current Principal Root.
    pub fn pr(&self) -> &PrincipalRoot {
        &self.pr
    }

    /// Get the current Auth State.
    pub fn auth_root(&self) -> &AuthRoot {
        &self.ar
    }

    /// Get the current Principal State as a tagged digest string (alg:digest format).
    ///
    /// Uses the lexicographically first algorithm from active_algs for deterministic output.
    /// This is the canonical tagged-digest format used e.g. for `principal/create`'s
    /// `id` field (SPEC §4.3, §5.1).
    ///
    /// # Errors
    ///
    /// Returns `EmptyMultihash` if the state digest has no variants.
    pub fn pr_tagged(&self) -> Result<String> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        let first_alg = self
            .active_algs()
            .first()
            .copied()
            .unwrap_or_else(|| self.hash_alg());
        let bytes = self.pr.0.get_or_err(first_alg)?;

        Ok(format!(
            "{}:{}",
            first_alg,
            Base64UrlUnpadded::encode_string(bytes)
        ))
    }

    /// Get the current Key State.
    pub fn key_root(&self) -> &KeyRoot {
        &self.kr
    }

    /// Get the hash algorithm used by this principal.
    pub fn hash_alg(&self) -> HashAlg {
        self.active_algs()
            .first()
            .copied()
            .unwrap_or(HashAlg::Sha256)
    }

    /// Get the active hash algorithms derived from current active keys (SPEC §14).
    pub fn active_algs(&self) -> Vec<HashAlg> {
        match self.kind() {
            PrincipalKind::Nascent(core) => core.active_algs(),
            PrincipalKind::Established { core, .. } => core.active_algs(),
        }
    }

    /// Get the genesis keys of this principal.
    pub fn genesis_keys(&self) -> &[String] {
        match self.kind() {
            PrincipalKind::Nascent(core) => &core.genesis_keys,
            PrincipalKind::Established { core, .. } => &core.genesis_keys,
        }
    }

    /// Get a key by thumbprint.
    pub fn get_key(&self, tmb: &Thumbprint) -> Option<&Key> {
        let key = tmb.to_b64();
        self.auth
            .keys
            .get(&key)
            .or_else(|| self.auth.revoked.get(&key))
    }

    /// Check if a key is currently active.
    pub fn is_key_active(&self, tmb: &Thumbprint) -> bool {
        self.auth.keys.contains_key(&tmb.to_b64())
    }

    /// Get all active keys.
    pub fn active_keys(&self) -> impl Iterator<Item = &Key> {
        self.auth.keys.values()
    }

    /// Get mutable access to all active keys.
    ///
    /// This is primarily for test setup (e.g., pre-revoking keys).
    /// Use with caution - direct mutation bypasses state recomputation.
    pub fn active_keys_mut(&mut self) -> impl Iterator<Item = &mut Key> {
        self.core_mut().auth.keys.values_mut()
    }

    /// Get number of active keys.
    pub fn active_key_count(&self) -> usize {
        self.auth.keys.len()
    }

    /// Check if a key has been revoked.
    pub fn is_key_revoked(&self, tmb: &Thumbprint) -> bool {
        self.auth.revoked.contains_key(&tmb.to_b64())
    }

    /// Pre-revoke a key (for test setup).
    ///
    /// This moves the key from active to revoked set WITHOUT recomputing state.
    /// Used for setting up error condition tests where we need a revoked key.
    ///
    /// # Errors
    ///
    /// Returns `UnknownKey` if the key is not found in the active set.
    pub fn pre_revoke_key(&mut self, tmb: &Thumbprint, rvk: i64) -> Result<()> {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();
        let mut key = core
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .ok_or(Error::UnknownKey)?;
        key.revocation = Some(Revocation { rvk, by: None });
        core.auth.revoked.insert(tmb_b64, key);
        Ok(())
    }

    /// Get all cozies (across all commits).
    pub fn iter_all_cozies(&self) -> impl Iterator<Item = &VerifiedCoz> {
        self.auth.commits.iter().flat_map(|c| c.iter_all_cozies())
    }

    /// Get all finalized commits.
    pub fn commits(&self) -> impl Iterator<Item = &Commit> {
        self.auth.commits.iter()
    }

    /// Get the TR of the current commit (if any).
    pub fn current_tr(&self) -> Option<&crate::transaction_root::TransactionRoot> {
        self.tr.as_ref()
    }

    /// Get the current Commit Root (CR).
    pub fn cr(&self) -> Option<&crate::commit_root::CommitRoot> {
        self.cr.as_ref()
    }

    /// Get a reference to the per-algorithm MALT trees.
    ///
    /// Used by checkpoint export to persist MALT state for later
    /// restoration via `Principal::from_checkpoint`.
    pub fn commit_trees(&self) -> &crate::commit_root::CommitTrees<S> {
        &self.commit_trees
    }

    /// Get the current State Root.
    ///
    /// Returns `None` only if no state has been computed (shouldn't happen
    /// after genesis). At genesis, SR is promoted from AR.
    pub fn sr(&self) -> Option<&StateRoot> {
        self.sr.as_ref()
    }

    // ========================================================================
    // MALT Proof Generation
    // ========================================================================

    /// Generate an inclusion proof for the commit at `index` in the
    /// per-algorithm MALT for `alg`.
    ///
    /// The returned proof can be verified standalone with
    /// [`malt::verify_inclusion`] using the tree's root and the
    /// corresponding [`CyphrHasher`](crate::commit_root::CyphrHasher).
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT.
    /// - Propagates [`malt::Error`] for empty tree or out-of-bounds index.
    pub fn inclusion_proof(&self, alg: HashAlg, index: u64) -> Result<crate::InclusionProof> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        if !self.commit_trees.has_algorithm(alg_id) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }
        self.commit_trees
            .inclusion_proof(alg_id, index)
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))
    }

    /// Generate a consistency proof from `old_size` to the current tree
    /// size for the per-algorithm MALT at `alg`.
    ///
    /// The returned proof can be verified standalone with
    /// [`verify_consistency`] using the old and new roots and the
    /// corresponding [`MaltHasher`](crate::commit_root::MaltHasher).
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT.
    /// - Propagates [`Error`] for invalid old_size.
    pub fn consistency_proof(
        &self,
        alg: HashAlg,
        old_size: u64,
    ) -> Result<crate::ConsistencyProof> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        if !self.commit_trees.has_algorithm(alg_id) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }
        self.commit_trees
            .consistency_proof(alg_id, old_size)
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))
    }

    /// Verify that transaction `tr`, claimed at commit `index`, is really
    /// included under this principal's *current* Principal Root (PR), for
    /// hash algorithm `alg` — by chaining two independent, already-existing
    /// inclusion proofs. No new composite proof type is introduced:
    ///
    /// 1. **Hop 1** — `tr` included in the Commit Root (CR): the commit log's own inclusion proof
    ///    ([`Self::inclusion_proof`], verified with [`crate::verify_inclusion`]).
    /// 2. **Hop 2** — CR, as PT cell 1's payload, included in PR: the Principal Tree's own
    ///    inclusion proof ([`PrincipalTree::cr_inclusion_proof`], verified with
    ///    [`polydigest::LeafProof::verify`]).
    ///
    /// The hops are bridged explicitly: hop 2's proven leaf value must equal
    /// hop 1's proven CR root. Without that check the two hops would each
    /// verify independently true facts about two *unrelated* trees; the
    /// bridge is what makes them jointly prove `tr` sits under the current
    /// PR specifically.
    ///
    /// # Errors
    ///
    /// - [`Error::UnsupportedAlgorithm`] if `alg` has no MALT/PT registration, or has no committed
    ///   CR yet (a genesis principal has nothing to chain through PT cell 1 — there is no valid
    ///   `index` to call this with).
    /// - Propagates [`Error`] for an out-of-bounds commit `index`.
    pub fn verify_transaction_inclusion(
        &self,
        alg: HashAlg,
        index: u64,
        tr: &MultihashDigest,
    ) -> Result<bool> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);

        // Hop 1 material: tr's claimed inclusion in CR.
        let hop1_proof = self.inclusion_proof(alg, index)?;
        let tree_size = self
            .commit_trees
            .tree_size(alg_id)
            .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
        let cr = self
            .cr
            .as_ref()
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let cr_bytes = cr
            .as_multihash()
            .get(alg)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        // Hop 2 material: CR's (PT cell 1) claimed inclusion in PR.
        let hop2_proof = self
            .pt
            .cr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let pr_bytes = self
            .pr
            .0
            .get(alg)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        Ok(crate::inclusion::verify_transaction_inclusion(
            alg,
            tr,
            &crate::inclusion::TransactionHop1 {
                index,
                tree_size,
                proof: &hop1_proof,
                cr_root: cr_bytes,
            },
            &crate::inclusion::TransactionHop2 {
                proof: &hop2_proof,
                pr_root: pr_bytes,
            },
        ))
    }

    /// Prove that the currently active key with thumbprint `tmb` is
    /// included under this principal's *current* Principal Root (PR), for
    /// hash algorithm `alg` — a 4-hop generalization of
    /// [`Self::verify_transaction_inclusion`]'s 2-hop CR-in-PR chain over
    /// the full identity hierarchy: thumbprint -> KT -> AR-node -> SR-node
    /// -> PT.
    ///
    /// Rebuilds KT/AR-node/SR-node fresh from the principal's current key
    /// set and Data Root — none of the three keep long-lived state on
    /// `Principal` (see [`crate::semantic_tree`]'s module docs); `PT` is the
    /// one node type that does, so its hop reuses `self.pt` directly.
    ///
    /// Crate-internal only (returns [`NodePath`], which is not a public
    /// type — see its doc comment). [`Self::verify_key_inclusion`] is the
    /// public entry point.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] if `alg` is not currently active, or
    /// `tmb` does not name a currently active key.
    pub(crate) fn key_inclusion_proof(&self, alg: HashAlg, tmb: &Thumbprint) -> Result<NodePath> {
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let active_algs = self.active_algs();
        if !active_algs.contains(&alg) {
            return Err(Error::UnsupportedAlgorithm(alg.to_string()));
        }

        // Lexical-sort position, matching KeyTree::build_tree's own sort.
        let thumbprints: Vec<&Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        let mut sorted: Vec<&[u8]> = thumbprints.iter().map(|t| t.as_bytes()).collect();
        sorted.sort();
        let index = sorted
            .iter()
            .position(|&b| b == tmb.as_bytes())
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?
            as u64;

        let kt = KeyTree::build_tree(&thumbprints, &active_algs)?;
        let kr = kt.root(&active_algs)?;
        let ar_node = AuthTree::build_tree(&kr, &active_algs)?;
        let ar = ar_node.root(&active_algs)?;
        let sr_node = StateTree::build_tree(&ar, self.dr.as_ref(), &active_algs)?;

        let hop1 = kt
            .thumbprint_inclusion_proof(alg_id, index)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop2 = ar_node
            .kr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop3 = sr_node
            .ar_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;
        let hop4 = self
            .pt
            .sr_inclusion_proof(alg_id)
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?;

        Ok(NodePath {
            hops: vec![
                NodePathHop { proof: hop1 },
                NodePathHop { proof: hop2 },
                NodePathHop { proof: hop3 },
                NodePathHop { proof: hop4 },
            ],
        })
    }

    /// Generate and verify, in one call, that the currently active key with
    /// thumbprint `tmb` is included under this principal's current PR — see
    /// [`Self::key_inclusion_proof`] for the chain this checks.
    ///
    /// Verifies each hop against `self.kr`/`self.ar`/`self.sr`/`self.pr` —
    /// the principal's independently-maintained root cache (kept in
    /// lockstep with every mutation) — rather than re-deriving the roots
    /// from the same freshly-rebuilt trees the proof itself was generated
    /// from; a staleness bug in either path would then show up as a
    /// verification failure instead of silently self-confirming.
    ///
    /// # Errors
    ///
    /// See [`Self::key_inclusion_proof`].
    pub fn verify_key_inclusion(&self, alg: HashAlg, tmb: &Thumbprint) -> Result<bool> {
        let path = self.key_inclusion_proof(alg, tmb)?;

        let kr_bytes = self.kr.0.get_or_err(alg)?;
        let ar_bytes = self.ar.0.get_or_err(alg)?;
        let sr_bytes = self
            .sr
            .as_ref()
            .ok_or_else(|| Error::UnsupportedAlgorithm(alg.to_string()))?
            .0
            .get_or_err(alg)?;
        let pr_bytes = self.pr.0.get_or_err(alg)?;

        let hops: Vec<polydigest::LeafProof> = path.hops.iter().map(|h| h.proof.clone()).collect();
        let roots: [&[u8]; 4] = [kr_bytes, ar_bytes, sr_bytes, pr_bytes];

        Ok(crate::inclusion::verify_key_inclusion(
            alg, tmb, &hops, &roots,
        ))
    }

    /// Begin a new commit scope.
    ///
    /// Returns a `CommitScope` that holds an exclusive borrow of this principal.
    /// Transactions are applied via `CommitScope::apply()`, and the commit is
    /// finalized by calling `CommitScope::finalize()` which consumes the scope.
    ///
    /// The borrow checker ensures no external code can observe the principal's
    /// intermediate state during the commit.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut scope = principal.begin_commit();
    /// scope.apply(vtx1)?;
    /// scope.apply(vtx2)?;
    /// let commit = scope.finalize()?;
    /// ```
    pub fn begin_commit(&mut self) -> CommitScope<'_, S> {
        CommitScope::new(self)
    }

    /// Apply a single verified coz as an atomic commit.
    ///
    /// This is the convenience method for the common single-coz case.
    /// It internally creates a commit scope, applies the coz, and
    /// finalizes the commit in one call.
    ///
    /// For multi-coz commits, use `begin_commit()` instead.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub fn apply_transaction(&mut self, vtx: crate::parsed_coz::VerifiedCoz) -> Result<&Commit> {
        let mut scope = self.begin_commit();
        scope.apply(vtx)?;
        scope.finalize()
    }

    /// Get all actions.
    pub fn actions(&self) -> impl Iterator<Item = &Action> {
        self.data.actions.iter()
    }

    /// Determine the current feature level.
    pub fn level(&self) -> Level {
        // Level 4: has actions
        if !self.data.actions.is_empty() {
            return Level::L4;
        }
        // Level 3: multiple keys or has commits
        if self.auth.keys.len() > 1 || !self.auth.commits.is_empty() {
            return Level::L3;
        }
        // Level 2 if any key/replace occurred (detected by commit history)
        // For now, single key with no commits = Level 1
        Level::L1
    }

    /// Whether `principal/delete` has been signed (SPEC.md §11.1 `Deleted`).
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Whether `freeze/create` is active and not yet undone by
    /// `freeze/delete` (SPEC.md §11.1 `Frozen`).
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Whether a fork or invalid chain has been detected (SPEC.md §11.1
    /// `Errored`). Orthogonal to [`Principal::lifecycle_state`]: any base
    /// state may be errored (SPEC.md §11.1).
    pub fn is_errored(&self) -> bool {
        self.errored
    }

    /// Derive the current lifecycle base state (SPEC.md §11.2).
    ///
    /// `CanDataAction` is wired as `level() >= L4 && HasActiveKeys` — the
    /// active-keys conjunct is non-load-bearing for any state reachable
    /// below Level 5 (see [`crate::lifecycle::derive_lifecycle_state`]'s doc
    /// comment): `CanDataAction` only distinguishes Zombie from Dead, and
    /// Zombie is unreachable below Level 5.
    pub fn lifecycle_state(&self) -> crate::lifecycle::LifecycleState {
        let has_active_keys = self.active_key_count() > 0;
        let can_data_action = self.level() >= Level::L4 && has_active_keys;
        crate::lifecycle::derive_lifecycle_state(
            self.deleted,
            self.frozen,
            has_active_keys,
            can_data_action,
        )
    }

    /// Configure the maximum allowed clock skew for future timestamps.
    ///
    /// Transactions with `now > server_time + max_clock_skew` will be rejected
    /// with `TimestampFuture` error. Set to 0 to disable future timestamp checking (default).
    ///
    /// Recommended value: 300 (5 minutes).
    pub fn set_max_clock_skew(&mut self, seconds: i64) {
        self.core_mut().max_clock_skew = seconds;
    }

    // ========================================================================
    // Action recording (Level 4)
    // ========================================================================

    /// Record an action to the Data State (Level 4+).
    ///
    /// This is internal-only. External code must use `verify_and_record_action`
    /// which enforces signature verification.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: Action timestamp is older than latest seen
    /// - `TimestampFuture`: Action timestamp is too far in the future
    /// - `UnknownKey`: Signer's key not in current KS
    pub(crate) fn record_action(&mut self, action: Action) -> Result<&PrincipalRoot> {
        // Validate timestamp is not in the past (SPEC §14.1)
        if action.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        // Validate timestamp is not too far in the future (SPEC §14.1)
        if self.max_clock_skew > 0 {
            let server_time = current_time();
            if action.now > server_time + self.max_clock_skew {
                return Err(Error::TimestampFuture);
            }
        }

        // Verify signer is an active key
        if !self.is_key_active(&action.signer) {
            // Check if key exists but is revoked
            if self.auth.revoked.values().any(|k| k.tmb == action.signer) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Update signer's last_used timestamp
        self.update_last_used(&action.signer, action.now);

        let active_algs = self.active_algs();
        let core = self.core_mut();

        // Update latest timestamp
        if action.now > core.latest_timestamp {
            core.latest_timestamp = action.now;
        }

        // Record action
        core.data.actions.push(action);

        // Recompute DS
        let actions: Vec<&Action> = core.data.actions.iter().collect();
        core.dr = compute_dr(&actions, None, &active_algs)?;

        // Recompute SR-node: cell 0 = AR (unchanged), cell 1 = DR (may have
        // just appeared/changed above).
        let sr = StateTree::build(&core.ar, core.dr.as_ref(), &active_algs)?;

        // Write SR into the Principal Tree (cell 1/CR is untouched) and
        // recompute PR from the tree.
        core.pr = core.write_pt_sr(&sr, &active_algs)?;

        Ok(&self.pr)
    }

    /// Verify signature and record an action in one step.
    ///
    /// This is the primary method for processing incoming actions.
    /// It verifies the signature, parses the action, and records it.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this action
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `KeyRevoked`: Signer key has been revoked
    /// - `TimestampPast`: Action timestamp is older than latest seen
    /// - `TimestampFuture`: Action timestamp is too far in the future
    pub fn verify_and_record_action(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
    ) -> Result<&PrincipalRoot> {
        use coz::base64ct::{Base64UrlUnpadded, Encoding};

        use crate::action::Action;

        // Parse as Value and extract only what we need (avoids requiring all coz::Pay fields)
        let pay_value: serde_json::Value =
            serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;

        // Extract tmb for signer lookup
        let tmb_str = pay_value["tmb"].as_str().ok_or(Error::MalformedPayload)?;
        let tmb_bytes =
            Base64UrlUnpadded::decode_vec(tmb_str).map_err(|_| Error::MalformedPayload)?;
        let signer_tmb = coz::Thumbprint::from_bytes(tmb_bytes);

        // Extract typ and now for Action construction
        let typ = pay_value["typ"]
            .as_str()
            .ok_or(Error::MalformedPayload)?
            .to_string();
        let now = pay_value["now"].as_i64().ok_or(Error::MalformedPayload)?;

        // [data-action-no-pre]: Data action cozies MUST NOT contain pre.
        if pay_value.get("pre").is_some() {
            return Err(Error::MalformedPayload);
        }

        // [no-transactions-on-deleted]: SPEC §11.4 -- "no transactions or
        // actions are possible on a closed account". Data actions have no
        // same-commit-finalizer exemption analogous to CommitCreate's, so
        // this is an unconditional gate.
        if self.deleted {
            return Err(Error::AlreadyDeleted);
        }

        // Signer must be an ACTIVE key
        if !self.is_key_active(&signer_tmb) {
            if self.auth.revoked.contains_key(&signer_tmb.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Look up signer key
        let signer_key = self.get_key(&signer_tmb).ok_or(Error::UnknownKey)?;

        // Verify signature
        let valid =
            coz::verify_json(pay_json, sig, &signer_key.alg, &signer_key.pub_key).unwrap_or(false);
        if !valid {
            return Err(Error::InvalidSignature);
        }

        // Construct CozJson for storage
        let raw = coz::CozJson {
            pay: pay_value,
            sig: sig.to_vec(),
        };

        // Construct Action directly from extracted values
        let action = Action::new(typ, signer_tmb, now, czd, raw);

        // Record the action
        self.record_action(action)
    }

    /// Get the current Data State (None if no actions).
    pub fn data_root(&self) -> Option<&DataRoot> {
        self.dr.as_ref()
    }

    /// Get the number of recorded actions.
    pub fn action_count(&self) -> usize {
        self.data.actions.len()
    }

    // ========================================================================
    // ParsedCoz application (internal)
    // ========================================================================

    /// Apply a verified coz to mutate principal state (internal).
    ///
    /// Called by `CommitScope::apply()`. This mutates the principal eagerly;
    /// the commit scope holds `&mut self` preventing external observation
    /// of intermediate state.
    ///
    /// # Errors
    ///
    /// - `TimestampPast`: ParsedCoz timestamp is older than latest seen
    /// - `TimestampFuture`: ParsedCoz timestamp is too far in the future
    /// - `NoActiveKeys`: Would leave principal with no active keys
    /// - `DuplicateKey`: Adding key already in KS
    pub(crate) fn apply_verified_internal(
        &mut self,
        vtx: crate::parsed_coz::VerifiedCoz,
    ) -> Result<()> {
        self.apply_transaction_internal(vtx)?;
        Ok(())
    }

    /// Apply a coz without prior signature verification (test-only).
    ///
    /// Pushes the mutation coz to `transactions` (without arrow), then
    /// creates a separate synthetic `commit/create` coz with the correctly
    /// computed arrow and pushes it to `commit_tx`. This mirrors the
    /// protocol structure per SPEC §4.4.
    #[cfg(test)]
    pub(crate) fn apply_transaction_test(
        &mut self,
        cz: crate::parsed_coz::ParsedCoz,
        new_key: Option<Key>,
    ) -> Result<&Commit> {
        use crate::commit::PendingCommit;
        use crate::multihash::MultihashDigest;
        use crate::parsed_coz::{CozKind, ParsedCoz, VerifiedCoz};
        use crate::state::derive_hash_algs;

        // Apply mutation eagerly (same as apply_verified_internal)
        let mutation_vtx = VerifiedCoz::from_transaction_unsafe(cz.clone(), new_key);
        self.apply_verified_internal(mutation_vtx)?;

        // Push mutation coz to transactions (no arrow)
        let mut pending = PendingCommit::new();
        let mutation_vtx2 = VerifiedCoz::from_transaction_unsafe(cz.clone(), None);
        pending.push_tx(crate::transaction::Transaction(vec![mutation_vtx2]));

        // KT → AR-node → SR-node from post-mutation key set (local, does not
        // mutate self). DR is refreshed to the current active_algs rather
        // than trusting the cached value, which may predate a key of a new
        // algorithm (see finalize_commit's identical refresh).
        let key_refs: Vec<&Key> = self.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);
        let thumbprints: Vec<&coz::Thumbprint> = self.auth.keys.values().map(|k| &k.tmb).collect();
        let action_refs: Vec<&Action> = self.data.actions.iter().collect();
        let dr = compute_dr(&action_refs, None, &active_algs)?;
        let (_kr, _ar, sr) = derive_state_roots(&thumbprints, dr.as_ref(), &active_algs)?;

        // Prefer the signer's own algorithm for the arrow, but a self-revoke
        // of the last key of that algorithm retires it from active_algs —
        // `sr` (rebuilt just above from the post-mutation key set) then has
        // no variant for it. Fall back to a surviving algorithm so the
        // arrow's three components (pre, sr, tmr) always share one that
        // `sr` actually has, rather than hitting `get_or_err`'s
        // `MissingVariant` on an algorithm this commit just retired.
        let tx_alg = if active_algs.contains(&cz.hash_alg) {
            cz.hash_alg
        } else {
            active_algs.first().copied().unwrap_or(cz.hash_alg)
        };

        // Compute TMR from pending transactions
        let (tmr_opt, _tcr, _tr) = pending.compute_roots(&[tx_alg]);
        let tmr = tmr_opt.ok_or(Error::EmptyCommit)?;

        // Compute arrow = hash_sorted_concat(pre, sr, tmr)
        let pre = &self.pr;
        let pre_bytes = pre.0.get_or_err(tx_alg)?;
        let sr_bytes = sr.0.get_or_err(tx_alg)?;
        let tmr_bytes = tmr.0.get(tx_alg).ok_or(Error::EmptyCommit)?;

        let arrow_digest =
            crate::state::hash_sorted_concat_bytes(tx_alg, &[pre_bytes, sr_bytes, tmr_bytes]);
        let arrow_md = MultihashDigest::from_single(tx_alg, arrow_digest)?;
        // Create synthetic commit/create coz with arrow
        let commit_coz = ParsedCoz {
            kind: CozKind::CommitCreate {
                arrow: arrow_md.clone(),
            },
            signer: cz.signer.clone(),
            now: cz.now,
            czd: cz.czd.clone(),
            hash_alg: cz.hash_alg,
            arrow: Some(arrow_md),
            raw: cz.raw.clone(),
        };
        let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);
        pending.push_tx(crate::transaction::Transaction(vec![commit_vtx]));

        self.finalize_commit(pending)
    }

    /// Internal coz application logic.
    fn apply_transaction_internal(
        &mut self,
        vtx: crate::parsed_coz::VerifiedCoz,
    ) -> Result<&AuthRoot> {
        use crate::parsed_coz::CozKind;

        // Access the underlying ParsedCoz via Deref
        let cz = &*vtx;

        // Validate timestamp is not in the past (SPEC §14.1)
        if cz.now < self.latest_timestamp {
            return Err(Error::TimestampPast);
        }

        // Validate timestamp is not too far in the future (SPEC §14.1)
        if self.max_clock_skew > 0 {
            let server_time = current_time();
            if cz.now > server_time + self.max_clock_skew {
                return Err(Error::TimestampFuture);
            }
        }

        // Verify signer is an active key.
        // Exceptions:
        //   - SelfRevoke: handled specially (revoking oneself)
        //   - CommitCreate: finality marker; authorization was already verified against the
        //     pre-commit key snapshot in CommitScope::verify_and_apply. The signer may have been
        //     replaced by a prior mutation in this commit.
        let skip_active_check = matches!(
            &cz.kind,
            CozKind::SelfRevoke { .. } | CozKind::CommitCreate { .. }
        );
        if !skip_active_check && !self.is_key_active(&cz.signer) {
            // Check if key exists but is revoked
            if self.auth.revoked.contains_key(&cz.signer.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // [no-transactions-on-deleted]: SPEC §11.4 -- "no transactions or
        // actions are possible on a closed account". PrincipalDelete,
        // FreezeCreate, and FreezeDelete manage their own deleted/frozen PRE
        // checks in their match arms below (untouched by this gate).
        // CommitCreate is conditionally exempted (F35 narrowing): it is the
        // mandatory finalizer every commit must carry (finalize_commit
        // rejects a commit whose last cozy lacks the arrow) and its own arm
        // is a pure no-op that grants no mutation power (principal.rs, the
        // CommitCreate match arm below). CommitScope applies cozies
        // sequentially to a projected principal within one commit
        // (commit.rs:319-383), so a commit whose own earlier transaction is
        // principal/delete has already set `self.deleted` by the time its
        // own commit/create finalizer runs here -- rejecting it would make
        // a principal impossible to ever actually close. But that
        // necessity holds only for THIS SAME, still-open commit:
        // `deleted_pending` is true exactly while such a commit is open
        // (set by the PrincipalDelete arm, cleared at the end of a
        // successful `finalize_commit`), so a commit/create in a LATER,
        // separately-finalized commit against an already-deleted principal
        // -- where `deleted` is true but `deleted_pending` is false -- is
        // not exempted. Every other variant has no such mandatory-
        // finalizer property, so is gated by default.
        //
        // Exhaustive by construction, not `matches!` over an allow-list: a
        // future 10th CozKind variant must be classified HERE explicitly
        // (compile error otherwise) rather than silently inheriting
        // "gated" from an unmatched wildcard on this security-critical
        // check.
        let skip_deleted_check = match &cz.kind {
            CozKind::PrincipalDelete { .. }
            | CozKind::FreezeCreate { .. }
            | CozKind::FreezeDelete { .. } => true,
            CozKind::CommitCreate { .. } => self.deleted_pending,
            CozKind::KeyCreate { .. }
            | CozKind::KeyDelete { .. }
            | CozKind::KeyReplace { .. }
            | CozKind::SelfRevoke { .. }
            | CozKind::PrincipalCreate { .. } => false,
        };
        if self.deleted && !skip_deleted_check {
            return Err(Error::AlreadyDeleted);
        }

        match &cz.kind {
            CozKind::KeyCreate { id } => {
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Verify algorithm is supported
                let _ = hash_alg_from_str(&key.alg)?;
                // Check for duplicate key
                if self.auth.keys.contains_key(&id.to_b64()) {
                    return Err(Error::DuplicateKey);
                }
                self.add_key(key, cz.now);
            },
            CozKind::KeyDelete { id } => {
                self.remove_key(id)?;
            },
            CozKind::KeyReplace { id } => {
                let key = vtx.new_key().cloned().ok_or(Error::MalformedPayload)?;
                if key.tmb.to_b64() != id.to_b64() {
                    return Err(Error::MalformedPayload);
                }
                // Verify algorithm is supported
                let _ = hash_alg_from_str(&key.alg)?;
                // Atomic swap: add new key first, then remove signer
                // This allows Level 2 single-key accounts to replace their key
                self.add_key(key, cz.now);
                // Use shift_remove directly to bypass NoActiveKeys check
                // (we just added a key, so this is safe)
                self.core_mut().auth.keys.shift_remove(&cz.signer.to_b64());
            },
            CozKind::SelfRevoke { rvk } => {
                self.revoke_key(&cz.signer, *rvk, None)?;
            },
            CozKind::PrincipalCreate { id } => {
                // Genesis finalization (SPEC §5.1)
                // Verify signer is a genesis key
                let signer_b64 = cz.signer.to_b64();
                if !self.genesis_keys.contains(&signer_b64) {
                    return Err(Error::UnknownKey);
                }
                // Verify that `id` matches the computed PR (SPEC §5.1 step 3:
                // `id` equals the future SR, which equals the current PR here
                // since no CR exists yet)
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                // Freeze PG at the current PR (SPEC §5.1 step 3: "principal/create ... establishes
                // PG") establish_pg() is the ONLY code path that transitions
                // Nascent → Established.
                self.establish_pg(PrincipalGenesis::from_initial(&self.pr))?;
            },
            CozKind::CommitCreate { .. } => {
                // Finalize commit marker does not mutate state other than marking completion
                // State references are verified during commit finalization
            },
            CozKind::PrincipalDelete { id } => {
                // Close (SPEC §11.4, R1/F5 ruling): permitted from Active or
                // Frozen, rejected if already Deleted
                // ([no-transactions-on-deleted] applied to itself).
                if self.deleted {
                    return Err(Error::AlreadyDeleted);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                let core = self.core_mut();
                core.deleted = true;
                core.deleted_pending = true;
                // Deleted subsumes Frozen (SPEC.md:1974-1978 mutual
                // exclusivity; R1/F5): unconditionally clear frozen even if
                // it was set going in.
                core.frozen = false;
            },
            CozKind::FreezeCreate { id } => {
                // Self-freeze (SPEC §14.9.1, R1/F5 ruling): rejected if
                // already Deleted or already Frozen.
                if self.deleted {
                    return Err(Error::AlreadyDeleted);
                }
                if self.frozen {
                    return Err(Error::AlreadyFrozen);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                self.core_mut().frozen = true;
            },
            CozKind::FreezeDelete { id } => {
                // Thaw (SPEC §14.9.3, R1/F5 ruling): requires currently
                // Frozen.
                if !self.frozen {
                    return Err(Error::NotFrozen);
                }
                if !id.0.matches(&self.pr.0) {
                    return Err(Error::StateMismatch);
                }
                self.core_mut().frozen = false;
            },
        }

        // Update signer's last_used timestamp
        self.update_last_used(&cz.signer, cz.now);

        // Update latest timestamp
        let core = self.core_mut();
        if cz.now > core.latest_timestamp {
            core.latest_timestamp = cz.now;
        }

        Ok(&self.ar)
    }

    /// Finalize a commit with proper state recomputation.
    ///
    /// This is called by `CommitScope::finalize()` with the accumulated
    /// `PendingCommit`. Recomputes all state digests and appends the
    /// finalized commit to the auth ledger.
    pub(crate) fn finalize_commit(&mut self, pending: PendingCommit) -> Result<&Commit> {
        if pending.is_empty() {
            return Err(Error::EmptyCommit);
        }

        // Validate arrow field placement: only last cz may have it,
        // and last cz MUST have it (SPEC §4.4).
        let cozies = pending.all_cozies();
        for (i, vtx) in cozies.iter().enumerate() {
            let is_last = i == cozies.len() - 1;
            if vtx.arrow().is_some() && !is_last {
                return Err(Error::CommitNotLast);
            }
            if vtx.arrow().is_none() && is_last {
                return Err(Error::MissingCommit);
            }
        }

        let core = self.core_mut();

        // Re-derive active algorithms from post-mutation key set.
        // Per [alg-set-evolution], state digests for this commit use the
        // algorithms supported by the post-mutation key set.
        let key_refs: Vec<&Key> = core.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);

        // Extract tx algorithm set from the commit coz (independent of state chain).
        // TX extraction reads only cozies/pending — no dependency on KR/AR/SR —
        // so it is hoisted here; its prior placement between KR+AR and SR was incidental.
        let tx_algs: Vec<coz::HashAlg> = if let Some(last_coz) = cozies.last() {
            if let Some(arrow) = last_coz.arrow() {
                arrow.algorithms().collect()
            } else {
                vec![last_coz.hash_alg()]
            }
        } else {
            vec![active_algs.first().copied().unwrap_or(HashAlg::Sha256)]
        };

        // Compute TR from pending commit
        let tr = pending.compute_tr(&tx_algs).ok_or(Error::EmptyCommit)?;
        core.tr = Some(tr.clone());

        // Refresh DR's algorithm coverage to the post-mutation active_algs
        // before folding it into SR-node. DR was cached by record_action
        // under whatever active_algs were live at the time; a key of a NEW
        // algorithm added since then would otherwise leave DR missing that
        // algorithm's variant, and StateTree::build's cell payload would hit
        // MultihashDigest::get_or_err's `MissingVariant` error for the new
        // algorithm (unlike the old flat formula, which had no per-algorithm
        // variant to be missing in the first place).
        let actions: Vec<&Action> = core.data.actions.iter().collect();
        core.dr = compute_dr(&actions, None, &active_algs)?;

        // KT → AR-node → SR-node (post-mutation key set, refreshed DR).
        // PR is computed below, after Arrow validation and CR assembly.
        let thumbprints: Vec<&Thumbprint> = core.auth.keys.values().map(|k| &k.tmb).collect();
        let (kr, ar, sr) = derive_state_roots(&thumbprints, core.dr.as_ref(), &active_algs)?;
        core.kr = kr;
        core.ar = ar;
        // core.sr/core.pt are NOT written yet — the arrow validation below
        // uses the local `sr`, and core.pr must still hold the pre-commit
        // value (see the comment there). Both are written together with CR
        // at the end of this function, via write_pt_sr_cr.

        // Validate arrow field matches independently computed Arrow.
        // Arrow = MR(pre, fwd_SR, TMR)
        // Compare at the signer's specific algorithm, mirroring Go.
        let last_coz = cozies.last().ok_or(Error::EmptyCommit)?;
        if let Some(claimed_arrow) = last_coz.arrow() {
            let (tmr, _tcr, _tr) = pending.compute_roots(&tx_algs);
            let tmr = tmr.ok_or(Error::EmptyCommit)?;

            // pre is the PR *before* this commit. core.pr has not been updated
            // yet (that happens at the end of this function), so it correctly
            // holds the prior value.
            let tx_alg = tx_algs[0];
            let pre_bytes = core.pr.0.arrow_component_bytes(tx_alg)?;
            let sr_bytes = sr.0.arrow_component_bytes(tx_alg)?;
            let tmr_bytes = tmr.0.get(tx_alg).ok_or(Error::EmptyCommit)?;

            let computed_digest = crate::state::hash_sorted_concat_bytes(
                tx_alg,
                &[pre_bytes.as_ref(), sr_bytes.as_ref(), tmr_bytes],
            );

            let claimed_digest = claimed_arrow.get(tx_alg).ok_or(Error::CommitMismatch)?;
            if claimed_digest != computed_digest.as_slice() {
                return Err(Error::CommitMismatch);
            }
        }

        // Ensure all active algorithms are registered in the unified EML Log.
        let algs = active_algs.clone();
        for &alg in &algs {
            let alg_id = crate::commit_root::hash_alg_to_u64(alg);
            if !core.commit_trees.has_algorithm(alg_id) {
                let hasher = Box::new(crate::commit_root::MaltHasher::new(alg));
                core.commit_trees
                    .add_algorithm(alg_id, hasher)
                    .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
            }
        }

        // This commit's 0-based position in the append-only commit
        // sequence. For a live/first-time commit this always equals the
        // durable log's current leaf count (each call appends exactly one
        // leaf in lockstep with `core.auth.commits`), so `already_durable`
        // is always false on that path — replay is the only path where a
        // durable log opened via `CommitTrees::open` can already carry
        // this leaf from a prior session.
        let leaf_index = core.auth.commits.len() as u64;
        let already_durable = leaf_index < core.commit_trees.global_size();

        // Serialize this commit's TR once — used both to append a fresh
        // leaf and, on the already_durable path, as the value to
        // byte-compare a pre-existing leaf against.
        let mut mapped_variants = BTreeMap::new();
        for (&alg, val) in tr.0.variants() {
            let alg_id = crate::commit_root::hash_alg_to_u64(alg);
            mapped_variants.insert(alg_id, val.clone());
        }
        let serialized =
            serde_json::to_vec(&mapped_variants).map_err(|_| Error::MalformedPayload)?;

        let cr = if already_durable {
            // A prior durable session already appended a leaf at this
            // position — re-appending would duplicate it. But a crash
            // between a prior `finalize_commit`'s durable EML append and
            // its index write can leave an ORPHAN leaf here instead of
            // this commit's own TR: byte-compare before trusting it,
            // rather than silently deriving CR from whatever leaf already
            // occupies the position.
            let stored = core
                .commit_trees
                .get_leaf(leaf_index)
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;
            if stored != serialized {
                return Err(Error::DurableLeafMismatch(leaf_index));
            }

            // Read the historical root as of this leaf's position instead.
            crate::commit_root::commit_root_from_trees_at(
                &core.commit_trees,
                &algs,
                leaf_index + 1,
            )?
        } else {
            // Append current TR once to the unified EML Log.
            core.commit_trees
                .append(&serialized)
                .map_err(|e| Error::UnsupportedAlgorithm(e.to_string()))?;

            // Assemble CR from the EML Log for all active algorithms.
            crate::commit_root::commit_root_from_trees(&core.commit_trees, &algs)?
        };

        // Write SR into cell 0 and CR into cell 1 of the Principal Tree, and
        // recompute PR from the tree (EpochTree::root(alg_id) per algorithm).
        core.pr = core.write_pt_sr_cr(&sr, &cr, &active_algs)?;

        // Finalize the pending commit with computed states
        let commit = pending.finalize(core.ar.clone(), sr, core.pr.clone(), &tx_algs)?;

        core.auth.commits.push(commit);

        // This commit is now durably finalized: any principal/delete it
        // carried is no longer "this commit's own pending delete" for a
        // future commit's CommitCreate exemption (skip_deleted_check).
        core.deleted_pending = false;

        // The borrow is safe: we just pushed, so last() is guaranteed Some.
        core.auth.commits.last().ok_or(Error::EmptyCommit)
    }

    /// Verify signature and apply a coz as an atomic commit.
    ///
    /// This is the primary method for processing incoming single-coz
    /// commits. It verifies the signature, parses the coz, applies
    /// the mutation, and finalizes the commit in one call.
    ///
    /// For multi-coz commits, use `begin_commit()` with manual
    /// scope control.
    ///
    /// # Arguments
    ///
    /// * `pay_json` - Raw JSON bytes of the Pay object
    /// * `sig` - Signature bytes
    /// * `czd` - Coz digest for this coz
    /// * `new_key` - New key to add (required for KeyCreate/KeyReplace)
    ///
    /// # Errors
    ///
    /// - `InvalidSignature`: Signature doesn't verify
    /// - `UnknownKey`: Signer not in active key set
    /// - `MalformedPayload`: Missing required fields
    /// - `NoActiveKeys`: Would leave principal with no keys
    #[must_use = "coz application may fail; handle the Result"]
    pub fn verify_and_apply_transaction(
        &mut self,
        pay_json: &[u8],
        sig: &[u8],
        czd: coz::Czd,
        new_key: Option<Key>,
    ) -> Result<&Commit> {
        use crate::parsed_coz::verify_coz;

        // Parse Pay to get signer thumbprint
        let pay: coz::Pay =
            serde_json::from_slice(pay_json).map_err(|_| Error::MalformedPayload)?;
        let signer_tmb = pay.tmb.as_ref().ok_or(Error::MalformedPayload)?;

        // Signer must be an ACTIVE key (not revoked)
        if !self.is_key_active(signer_tmb) {
            // Check if it's revoked vs unknown
            if self.auth.revoked.contains_key(&signer_tmb.to_b64()) {
                return Err(Error::KeyRevoked);
            }
            return Err(Error::UnknownKey);
        }

        // Look up signer key (guaranteed active now)
        let signer_key = self.get_key(signer_tmb).ok_or(Error::UnknownKey)?;

        // Verify signature and parse coz
        let vtx = verify_coz(pay_json, sig, signer_key, czd, new_key)?;

        // Apply as single-cz atomic commit
        self.apply_transaction(vtx)
    }

    /// Add a key to the active key set.
    ///
    /// Sets `first_seen` to the given timestamp.
    fn add_key(&mut self, mut key: Key, first_seen: i64) {
        key.first_seen = first_seen;
        let tmb_b64 = key.tmb.to_b64();
        self.core_mut().auth.keys.insert(tmb_b64, key);
    }

    /// Remove a key from the active key set (delete, not revoke).
    fn remove_key(&mut self, tmb: &Thumbprint) -> Result<()> {
        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();
        if core.auth.keys.shift_remove(&tmb_b64).is_none() {
            return Err(Error::UnknownKey);
        }
        if core.auth.keys.is_empty() {
            return Err(Error::NoActiveKeys);
        }
        Ok(())
    }

    /// Revoke a key (marks as revoked, moves to revoked set).
    ///
    /// # Errors
    ///
    /// - `UnknownKey`: Key not found in active set
    /// - `NoActiveKeys`: Would leave principal with no active keys
    fn revoke_key(&mut self, tmb: &Thumbprint, rvk: i64, by: Option<Thumbprint>) -> Result<()> {
        use crate::key::Revocation;

        let tmb_b64 = tmb.to_b64();
        let core = self.core_mut();

        // Check if key exists
        if !core.auth.keys.contains_key(&tmb_b64) {
            return Err(Error::UnknownKey);
        }

        // Check BEFORE mutation: would this leave us with no keys?
        if core.auth.keys.len() == 1 {
            return Err(Error::NoActiveKeys);
        }

        // Safe to proceed - remove and revoke.
        let mut key = core
            .auth
            .keys
            .shift_remove(&tmb_b64)
            .ok_or(Error::UnknownKey)?;
        key.revocation = Some(Revocation { rvk, by });

        // Move to revoked set for historical verification
        core.auth.revoked.insert(tmb_b64, key);

        Ok(())
    }

    /// Update a key's last_used timestamp.
    ///
    /// Called after successful coz or action signing.
    fn update_last_used(&mut self, tmb: &Thumbprint, timestamp: i64) {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.core_mut().auth.keys.get_mut(&tmb_b64) {
            key.last_used = Some(timestamp);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use coz::Thumbprint;
    use eml::Hasher;

    use super::*;
    use crate::commit_root::MaltHasher;
    use crate::key::Key;
    use crate::state::StateDigest;

    fn make_test_key(id: u8) -> Key {
        Key {
            alg: "ES256".to_string(),
            tmb: Thumbprint::from_bytes(vec![id; 32]),
            pub_key: vec![id; 64],
            first_seen: 1000,
            last_used: None,
            revocation: None,
            tag: None,
        }
    }

    /// Create a dummy CozJson for test cozies.
    /// The payload content doesn't need to match the ParsedCoz kind
    /// since tests bypass signature verification.
    fn dummy_coz_json() -> coz::CozJson {
        coz::CozJson {
            pay: serde_json::json!({
                "typ": "cyphr.me/test",
                "alg": "ES256",
                "now": 1000
            }),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn implicit_genesis_single_key() {
        let key = make_test_key(0xAA);
        let principal = Principal::implicit(key.clone()).unwrap();

        // Level 1: PR is None (no principal/create at L1)
        assert!(principal.pg().is_none(), "PR should be None at Level 1");
        assert_eq!(
            principal.pr().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
        assert_eq!(
            principal.auth_root().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
        assert_eq!(
            principal.key_root().get(principal.hash_alg()).unwrap(),
            key.tmb.as_bytes()
        );
    }

    #[test]
    fn implicit_genesis_has_one_active_key() {
        let key = make_test_key(0xBB);
        let tmb = key.tmb.clone();
        let principal = Principal::implicit(key).unwrap();

        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&tmb));
        assert_eq!(principal.level(), Level::L1);
    }

    #[test]
    fn explicit_genesis_multi_key() {
        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        // PR should be None (not yet established — needs principal/create)
        assert!(
            principal.pg().is_none(),
            "PR should be None before principal/create"
        );

        // Should have 2 active keys
        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key1.tmb));
        assert!(principal.is_key_active(&key2.tmb));

        // Level 3 due to multiple keys
        assert_eq!(principal.level(), Level::L3);
    }

    #[test]
    fn explicit_genesis_empty_keys_errors() {
        let result = Principal::explicit(vec![]);
        assert!(matches!(result, Err(Error::NoActiveKeys)));
    }

    #[test]
    fn pg_is_none_at_level1() {
        let key = make_test_key(0xCC);
        let principal = Principal::implicit(key).unwrap();

        // PG is None at Level 1 (no principal/create)
        assert!(principal.pg().is_none(), "PG should be None at Level 1");

        // PR still exists and is stable
        let pr_bytes = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
        assert!(!pr_bytes.is_empty());
    }

    // ========================================================================
    // Lifecycle state (SPEC.md §11)
    // ========================================================================

    #[test]
    fn fresh_implicit_principal_derives_active() {
        let key = make_test_key(0xD0);
        let principal = Principal::implicit(key).unwrap();

        assert!(!principal.is_deleted());
        assert!(!principal.is_frozen());
        assert!(!principal.is_errored());
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Active
        );
    }

    #[test]
    fn checkpoint_restored_principal_derives_active() {
        // ac-field-threading: a checkpoint-restored principal must not be
        // spuriously Frozen/Deleted — the new fields must default cleanly
        // through `from_checkpoint`, not just the constructors that build a
        // principal directly.
        let (principal, keys) = build_principal_with_commits(2);
        let trees = principal.commit_trees().clone();

        let restored = Principal::from_checkpoint(
            principal.pg().cloned(),
            principal.auth_root().clone(),
            keys,
            Some(trees),
        )
        .unwrap();

        assert!(!restored.is_deleted());
        assert!(!restored.is_frozen());
        assert_eq!(
            restored.lifecycle_state(),
            crate::lifecycle::LifecycleState::Active
        );
    }

    #[test]
    fn principal_with_no_active_keys_derives_dead() {
        let key = make_test_key(0xD1);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        principal.pre_revoke_key(&tmb, 1000).unwrap();

        assert_eq!(principal.active_key_count(), 0);
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Dead,
            "a principal with zero active keys and Level < L4 must derive Dead"
        );
    }

    /// c-zombie-unreachable (integration level): across every principal
    /// shape this node can actually construct (varying key counts, with and
    /// without revocation, with and without commits), `lifecycle_state()`
    /// never returns Zombie. `CanMutateAR` is wired as `== HasActiveKeys`
    /// below Level 5 (SPEC.md:1990-1992; this crate's `Level` enum has no
    /// L5+ variant — see `rs/cyphr/src/principal.rs`'s `Level` definition),
    /// so `¬CanMutateAR ∧ CanDataAction` can never hold and Zombie is
    /// unreachable for any principal reachable through the public API.
    #[test]
    fn zombie_unreachable_across_constructed_principals() {
        let single = Principal::implicit(make_test_key(0xD2)).unwrap();
        assert_ne!(
            single.lifecycle_state(),
            crate::lifecycle::LifecycleState::Zombie
        );

        let multi =
            Principal::explicit(vec![make_test_key(0xD3), make_test_key(0xD4)]).unwrap();
        assert_ne!(
            multi.lifecycle_state(),
            crate::lifecycle::LifecycleState::Zombie
        );

        let mut revoked = Principal::implicit(make_test_key(0xD5)).unwrap();
        let tmb = revoked.active_keys().next().unwrap().tmb.clone();
        revoked.pre_revoke_key(&tmb, 2000).unwrap();
        assert_ne!(
            revoked.lifecycle_state(),
            crate::lifecycle::LifecycleState::Zombie
        );

        let (with_commits, _keys) = build_principal_with_commits(3);
        assert_ne!(
            with_commits.lifecycle_state(),
            crate::lifecycle::LifecycleState::Zombie
        );
    }

    // ========================================================================
    // Lifecycle transactions (SPEC.md §11.4 Close, §14.9 Freeze)
    // ========================================================================

    /// Build a lifecycle-transaction `ParsedCoz` (`PrincipalDelete`,
    /// `FreezeCreate`, or `FreezeDelete`) signed by `signer`. Bypasses
    /// signature verification, matching every other mutator test in this
    /// module (`self_revoke_last_key_prevented` et al.).
    fn make_lifecycle_cz(
        kind: crate::parsed_coz::CozKind,
        signer: &Thumbprint,
        now: i64,
    ) -> crate::parsed_coz::ParsedCoz {
        use coz::Czd;

        use crate::parsed_coz::ParsedCoz;

        ParsedCoz {
            kind,
            signer: signer.clone(),
            now,
            czd: Czd::from_bytes(vec![now as u8; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        }
    }

    #[test]
    fn principal_delete_from_frozen_succeeds_and_clears_frozen() {
        use crate::parsed_coz::CozKind;

        let key = make_test_key(0xE1);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        let freeze_cz = make_lifecycle_cz(
            CozKind::FreezeCreate {
                id: principal.pr().clone(),
            },
            &tmb,
            2000,
        );
        principal.apply_transaction_test(freeze_cz, None).unwrap();
        assert!(principal.is_frozen());

        let delete_cz = make_lifecycle_cz(
            CozKind::PrincipalDelete {
                id: principal.pr().clone(),
            },
            &tmb,
            2001,
        );
        principal.apply_transaction_test(delete_cz, None).unwrap();

        assert!(principal.is_deleted());
        assert!(
            !principal.is_frozen(),
            "delete must clear frozen (mutual exclusivity, SPEC.md:1974-1978)"
        );
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Deleted
        );
    }

    #[test]
    fn freeze_create_on_deleted_is_rejected() {
        use crate::parsed_coz::CozKind;

        let key = make_test_key(0xE2);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        let delete_cz = make_lifecycle_cz(
            CozKind::PrincipalDelete {
                id: principal.pr().clone(),
            },
            &tmb,
            2000,
        );
        principal.apply_transaction_test(delete_cz, None).unwrap();
        assert!(principal.is_deleted());

        let freeze_cz = make_lifecycle_cz(
            CozKind::FreezeCreate {
                id: principal.pr().clone(),
            },
            &tmb,
            2001,
        );
        let result = principal.apply_transaction_test(freeze_cz, None);
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
        assert!(!principal.is_frozen());
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Deleted,
            "[no-both-deleted-and-frozen]: a rejected freeze/create must \
             not perturb the Deleted state"
        );
    }

    #[test]
    fn freeze_create_on_already_frozen_is_rejected() {
        use crate::parsed_coz::CozKind;

        let key = make_test_key(0xE3);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        let freeze_cz = make_lifecycle_cz(
            CozKind::FreezeCreate {
                id: principal.pr().clone(),
            },
            &tmb,
            2000,
        );
        principal.apply_transaction_test(freeze_cz, None).unwrap();
        assert!(principal.is_frozen());

        let freeze_again_cz = make_lifecycle_cz(
            CozKind::FreezeCreate {
                id: principal.pr().clone(),
            },
            &tmb,
            2001,
        );
        let result = principal.apply_transaction_test(freeze_again_cz, None);
        assert!(matches!(result, Err(Error::AlreadyFrozen)));
    }

    #[test]
    fn freeze_delete_on_non_frozen_is_rejected() {
        use crate::parsed_coz::CozKind;

        let key = make_test_key(0xE4);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        assert!(!principal.is_frozen());

        let thaw_cz = make_lifecycle_cz(
            CozKind::FreezeDelete {
                id: principal.pr().clone(),
            },
            &tmb,
            2000,
        );
        let result = principal.apply_transaction_test(thaw_cz, None);
        assert!(matches!(result, Err(Error::NotFrozen)));
    }

    #[test]
    fn freeze_create_then_freeze_delete_thaws_to_active() {
        use crate::parsed_coz::CozKind;

        let key = make_test_key(0xE5);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        let freeze_cz = make_lifecycle_cz(
            CozKind::FreezeCreate {
                id: principal.pr().clone(),
            },
            &tmb,
            2000,
        );
        principal.apply_transaction_test(freeze_cz, None).unwrap();
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Frozen
        );

        let thaw_cz = make_lifecycle_cz(
            CozKind::FreezeDelete {
                id: principal.pr().clone(),
            },
            &tmb,
            2001,
        );
        principal.apply_transaction_test(thaw_cz, None).unwrap();

        assert!(!principal.is_frozen());
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Active
        );
    }

    // ========================================================================
    // Blanket deleted-principal gate (SPEC.md §11.4, F23, N11)
    //
    // [no-transactions-on-deleted] applied to the six non-lifecycle CozKind
    // variants (KeyCreate, KeyDelete, KeyReplace, SelfRevoke,
    // PrincipalCreate, CommitCreate) plus data actions. CommitCreate is
    // exempted (its own commit's finalizer must complete even when an
    // earlier transaction in the same commit was the delete itself, see
    // `same_commit_delete_and_own_finalizer_succeeds` below).
    // FreezeDelete is exempted from this gate too, but for a structural
    // reason rather than a same-commit one: it requires `self.frozen`,
    // and Deleted/Frozen are mutually exclusive (SPEC.md:1974-1978), so
    // FreezeDelete can never be reachable on a Deleted principal in the
    // first place -- `freeze_delete_on_deleted_still_rejected_as_not_frozen`
    // confirms this rather than adding a redundant check.
    // ========================================================================

    /// Build a genuinely Deleted principal via a real `principal/delete`
    /// transaction (not a mocked flag), with two active keys so KeyDelete/
    /// SelfRevoke have a legal target/signer to attempt against it.
    fn build_deleted_principal() -> (Principal, Key, Key) {
        use crate::parsed_coz::CozKind;

        let key1 = make_test_key(0xD1);
        let key2 = make_test_key(0xD2);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        let delete_cz = make_lifecycle_cz(
            CozKind::PrincipalDelete {
                id: principal.pr().clone(),
            },
            &key1.tmb,
            2000,
        );
        principal.apply_transaction_test(delete_cz, None).unwrap();
        assert!(principal.is_deleted(), "setup: principal must be Deleted");

        (principal, key1, key2)
    }

    #[test]
    fn key_create_on_deleted_principal_is_rejected() {
        let (mut principal, key1, _key2) = build_deleted_principal();

        let new_key = make_test_key(0xD3);
        let cz = make_key_add_tx(&new_key, &key1.tmb);

        let result = principal.apply_transaction_test(cz, Some(new_key));
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
    }

    #[test]
    fn key_delete_on_deleted_principal_is_rejected() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let (mut principal, key1, key2) = build_deleted_principal();

        let cz = ParsedCoz {
            kind: CozKind::KeyDelete {
                id: key2.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 2001,
            czd: Czd::from_bytes(vec![0xD4; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, None);
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
    }

    #[test]
    fn key_replace_on_deleted_principal_is_rejected() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let (mut principal, key1, _key2) = build_deleted_principal();

        let new_key = make_test_key(0xD5);
        let cz = ParsedCoz {
            kind: CozKind::KeyReplace {
                id: new_key.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 2001,
            czd: Czd::from_bytes(vec![0xD6; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, Some(new_key));
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
    }

    /// SelfRevoke DOES mutate state (revokes the signer's own key) and has
    /// no same-commit-completion necessity the way CommitCreate does, so
    /// SPEC.md §11.4's "no further transactions" is not exempted here --
    /// unlike CommitCreate, gating SelfRevoke does not reopen the ability
    /// to ever close a principal.
    #[test]
    fn self_revoke_on_deleted_principal_is_rejected() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let (mut principal, _key1, key2) = build_deleted_principal();

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 2001 },
            signer: key2.tmb.clone(),
            now: 2001,
            czd: Czd::from_bytes(vec![0xD7; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, None);
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
        assert!(
            principal.is_key_active(&key2.tmb),
            "rejected self-revoke must not mutate the key set"
        );
    }

    #[test]
    fn principal_create_on_deleted_principal_is_rejected() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let (mut principal, key1, _key2) = build_deleted_principal();

        let cz = ParsedCoz {
            kind: CozKind::PrincipalCreate {
                id: principal.auth_root().clone(),
            },
            signer: key1.tmb.clone(),
            now: 2001,
            czd: Czd::from_bytes(vec![0xD8; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, None);
        assert!(
            matches!(result, Err(Error::AlreadyDeleted)),
            "the blanket gate must reject PrincipalCreate before genesis-key/id \
             validation ever runs, since a Deleted principal is by definition \
             already Established and genesis finalization can never legitimately \
             be reachable here"
        );
    }

    /// Confirms the reasoning in this node's non-goals: FreezeDelete
    /// requires `self.frozen`, and Deleted/Frozen are mutually exclusive,
    /// so FreezeDelete on a genuinely Deleted principal is already
    /// unreachable via its own existing check (`NotFrozen`) -- no new gate
    /// entry is needed, and the blanket gate must not shadow this error
    /// with `AlreadyDeleted`.
    #[test]
    fn freeze_delete_on_deleted_still_rejected_as_not_frozen() {
        let (mut principal, key1, _key2) = build_deleted_principal();
        assert!(!principal.is_frozen());

        let thaw_cz = make_lifecycle_cz(
            crate::parsed_coz::CozKind::FreezeDelete {
                id: principal.pr().clone(),
            },
            &key1.tmb,
            2001,
        );
        let result = principal.apply_transaction_test(thaw_cz, None);
        assert!(matches!(result, Err(Error::NotFrozen)));
    }

    #[test]
    fn data_action_on_deleted_principal_is_rejected() {
        let (mut principal, key1, _key2) = build_deleted_principal();

        let pay = serde_json::json!({
            "alg": key1.alg,
            "now": 2001,
            "tmb": key1.tmb.to_b64(),
            "typ": "cyphr.me/comment",
        });
        let pay_json = serde_json::to_vec(&pay).unwrap();
        let sig = vec![0u8; 64];
        let czd = coz::Czd::from_bytes(vec![0xD9; 32]);

        let result = principal.verify_and_record_action(&pay_json, &sig, czd);
        assert!(matches!(result, Err(Error::AlreadyDeleted)));
    }

    /// c-same-commit-delete-still-finalizes: the load-bearing test for this
    /// node. A commit whose own transaction is `principal/delete`, followed
    /// by that SAME commit's `commit/create` finalizer, must still finalize
    /// successfully -- the finalizer is applied through
    /// `apply_transaction_internal` exactly as the real per-cozy commit
    /// ingestion path does (see `CommitScope::verify_and_apply` ->
    /// `CommitScope::apply` -> `apply_verified_internal`), at a point where
    /// `self.deleted` is already `true` from the earlier delete in this
    /// same commit. Get the exemption wrong (too narrow) and this test
    /// fails with `AlreadyDeleted`, meaning a principal could never
    /// actually be closed.
    #[test]
    fn same_commit_delete_and_own_finalizer_succeeds() {
        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key = make_test_key(0xDA);
        let tmb = key.tmb.clone();
        let mut principal = Principal::implicit(key).unwrap();

        let delete_cz = ParsedCoz {
            kind: CozKind::PrincipalDelete {
                id: principal.pr().clone(),
            },
            signer: tmb.clone(),
            now: 2000,
            czd: coz::Czd::from_bytes(vec![0xDB; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        // Apply principal/delete eagerly -- self.deleted is now true,
        // exactly as it would be on CommitScope's projected principal
        // mid-commit.
        let delete_vtx = VerifiedCoz::from_transaction_unsafe(delete_cz.clone(), None);
        principal.apply_verified_internal(delete_vtx).unwrap();
        assert!(principal.is_deleted());

        let mut pending = PendingCommit::new();
        let delete_vtx2 = VerifiedCoz::from_transaction_unsafe(delete_cz.clone(), None);
        pending.push_tx(crate::transaction::Transaction(vec![delete_vtx2]));

        // Compute the correct arrow for the finalizer -- same technique as
        // `apply_transaction_test`.
        let key_refs: Vec<&Key> = principal.auth.keys.values().collect();
        let active_algs = derive_hash_algs(&key_refs);
        let thumbprints: Vec<&coz::Thumbprint> =
            principal.auth.keys.values().map(|k| &k.tmb).collect();
        let action_refs: Vec<&Action> = principal.data.actions.iter().collect();
        let dr = compute_dr(&action_refs, None, &active_algs).unwrap();
        let (_kr, _ar, sr) =
            derive_state_roots(&thumbprints, dr.as_ref(), &active_algs).unwrap();

        let tx_alg = delete_cz.hash_alg;
        let (tmr_opt, _tcr, _tr) = pending.compute_roots(&[tx_alg]);
        let tmr = tmr_opt.unwrap();

        let pre = &principal.pr;
        let pre_bytes = pre.0.get_or_err(tx_alg).unwrap();
        let sr_bytes = sr.0.get_or_err(tx_alg).unwrap();
        let tmr_bytes = tmr.0.get(tx_alg).unwrap();

        let arrow_digest =
            crate::state::hash_sorted_concat_bytes(tx_alg, &[pre_bytes, sr_bytes, tmr_bytes]);
        let arrow_md = MultihashDigest::from_single(tx_alg, arrow_digest).unwrap();

        let commit_coz = ParsedCoz {
            kind: CozKind::CommitCreate {
                arrow: arrow_md.clone(),
            },
            signer: tmb.clone(),
            now: 2000,
            czd: coz::Czd::from_bytes(vec![0xDC; 32]),
            hash_alg: tx_alg,
            arrow: Some(arrow_md),
            raw: dummy_coz_json(),
        };
        let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);

        // The load-bearing assertion: this must NOT be rejected by
        // [no-transactions-on-deleted] despite self.deleted already being
        // true from the delete applied moments ago in this same commit.
        principal
            .apply_verified_internal(commit_vtx.clone())
            .expect(
                "commit/create finalizing its own commit's principal/delete \
                 must not be rejected by the blanket deleted gate",
            );

        pending.push_tx(crate::transaction::Transaction(vec![commit_vtx]));

        principal.finalize_commit(pending).unwrap();

        assert!(
            principal.is_deleted(),
            "principal must still be Deleted after its own delete-commit finalizes"
        );
        assert_eq!(
            principal.lifecycle_state(),
            crate::lifecycle::LifecycleState::Deleted
        );
    }

    /// c-later-commit-now-rejected (F35 narrowing, this node): unlike
    /// `same_commit_delete_and_own_finalizer_succeeds` above, this
    /// principal was deleted in an EARLIER, separately-finalized commit
    /// -- `self.deleted` is already `true` BEFORE this new commit/create
    /// is applied, not made `true` by this commit's own transaction. A
    /// bare `commit/create` (no other transaction in this commit) must
    /// now be rejected by [no-transactions-on-deleted], not silently
    /// exempted the way N11's original, unconditional exemption allowed.
    #[test]
    fn later_commit_bare_finalizer_on_already_deleted_is_rejected() {
        use crate::parsed_coz::{CozKind, ParsedCoz};

        let (mut principal, key1, _key2) = build_deleted_principal();
        assert!(
            principal.is_deleted(),
            "setup: principal must already be Deleted"
        );

        // A brand-new commit/create finalizer with no other transaction
        // in this commit. The arrow's exact bytes are irrelevant here --
        // [no-transactions-on-deleted] is enforced in
        // `apply_transaction_internal`, before any arrow is validated
        // (arrow validation happens later, in `finalize_commit`).
        let arrow_md = MultihashDigest::from_single(HashAlg::Sha256, vec![0u8; 32]).unwrap();
        let commit_coz = ParsedCoz {
            kind: CozKind::CommitCreate {
                arrow: arrow_md.clone(),
            },
            signer: key1.tmb.clone(),
            now: 3000,
            czd: coz::Czd::from_bytes(vec![0xE9; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: Some(arrow_md),
            raw: dummy_coz_json(),
        };
        let commit_vtx = VerifiedCoz::from_transaction_unsafe(commit_coz, None);

        let result = principal.apply_verified_internal(commit_vtx);
        assert!(
            matches!(result, Err(Error::AlreadyDeleted)),
            "a bare commit/create against a principal deleted in an earlier, \
             separately-finalized commit must be rejected, got {result:?}"
        );
    }

    // ========================================================================
    // ParsedCoz application tests
    // ========================================================================

    fn make_key_add_tx(new_key: &Key, signer: &Thumbprint) -> crate::parsed_coz::ParsedCoz {
        use coz::Czd;
        use serde_json::json;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        // Create dummy raw CozJson for test cozies
        let raw = coz::CozJson {
            pay: json!({
                "typ": "cyphr.me/key/create",
                "alg": "ES256",
                "now": 2000,
                "tmb": signer.to_b64(),
                "id": new_key.tmb.to_b64()
            }),
            sig: vec![0; 64],
        };

        ParsedCoz {
            kind: CozKind::KeyCreate {
                id: new_key.tmb.clone(),
            },
            signer: signer.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xAB; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw,
        }
    }

    #[test]
    fn apply_key_add_increases_key_count() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&key2, &key1.tmb);

        principal
            .apply_transaction_test(cz, Some(key2.clone()))
            .unwrap();

        assert_eq!(principal.active_key_count(), 2);
        assert!(principal.is_key_active(&key2.tmb));
        assert_eq!(principal.level(), Level::L3);
    }

    #[test]
    fn apply_key_add_changes_state() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let old_as = principal
            .auth_root()
            .get(principal.hash_alg())
            .unwrap()
            .to_vec();
        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&key2, &key1.tmb);

        principal.apply_transaction_test(cz, Some(key2)).unwrap();
        // apply_transaction_test auto-finalizes the commit

        let new_as = principal
            .auth_root()
            .get(principal.hash_alg())
            .unwrap()
            .to_vec();
        // Auth state must change after adding key
        assert_ne!(old_as, new_as);
    }

    #[test]
    fn pr_still_none_after_transaction() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // PR is None at L1
        assert!(
            principal.pg().is_none(),
            "PR should be None before principal/create"
        );

        let key2 = make_test_key(0x22);
        let cz = make_key_add_tx(&key2, &key1.tmb);

        principal.apply_transaction_test(cz, Some(key2)).unwrap();

        // PR should still be None (no principal/create was issued)
        assert!(
            principal.pg().is_none(),
            "PR should still be None without principal/create"
        );
    }

    // ========================================================================
    // Action recording tests (Level 4)
    // ========================================================================

    fn make_test_action(signer: &Thumbprint) -> Action {
        use coz::{Czd, PayBuilder};

        let pay = PayBuilder::new()
            .typ("cyphr.me/comment/create")
            .alg("ES256")
            .now(3000)
            .tmb(signer.clone())
            .msg("Test action")
            .build();

        let raw = coz::CozJson {
            pay: serde_json::to_value(&pay).unwrap(),
            sig: vec![0; 64],
        };
        let czd = Czd::from_bytes(vec![0xCC; 32]);

        Action::from_pay(&pay, czd, raw).unwrap()
    }

    #[test]
    fn record_action_upgrades_to_level_4() {
        let key = make_test_key(0xAA);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        assert_eq!(principal.level(), Level::L1);
        assert!(principal.data_root().is_none());

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        assert_eq!(principal.level(), Level::L4);
        assert!(principal.data_root().is_some());
        assert_eq!(principal.action_count(), 1);
    }

    #[test]
    fn record_action_changes_ps() {
        let key = make_test_key(0xBB);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        let pr_before = principal.pr().get(principal.hash_alg()).unwrap().to_vec();

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();

        let pr_after = principal.pr().get(principal.hash_alg()).unwrap().to_vec();
        // PR changes when DS is added
        assert_ne!(pr_before, pr_after);
    }

    #[test]
    fn record_action_unknown_signer_fails() {
        let key = make_test_key(0xCC);
        let mut principal = Principal::implicit(key).unwrap();

        // Try to record action from unknown key
        let unknown_tmb = Thumbprint::from_bytes(vec![0xFF; 32]);
        let action = make_test_action(&unknown_tmb);

        let result = principal.record_action(action);
        assert!(matches!(result, Err(Error::UnknownKey)));
    }

    // ========================================================================
    // Self-revoke guard tests (C12)
    // ========================================================================

    #[test]
    fn self_revoke_last_key_prevented() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key = make_test_key(0xDD);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        // Level 1: single key, self-revoke should fail
        assert_eq!(principal.level(), Level::L1);

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 2000 },
            signer: key.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xEE; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        let result = principal.apply_transaction_test(cz, None);
        assert!(matches!(result, Err(Error::NoActiveKeys)));

        // Key should still be active (no mutation occurred)
        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&key.tmb));
    }

    #[test]
    fn revoke_allowed_when_multiple_keys() {
        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        assert_eq!(principal.active_key_count(), 2);

        // Revoke key2 via self-revoke (key2 revokes itself)
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 2000 },
            signer: key2.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![0xFF; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };

        principal.apply_transaction_test(cz, None).unwrap();

        assert_eq!(principal.active_key_count(), 1);
        assert!(principal.is_key_active(&key1.tmb));
        assert!(!principal.is_key_active(&key2.tmb));
    }

    // ========================================================================
    // Key first_seen tests (C14)
    // ========================================================================

    #[test]
    fn key_add_sets_first_seen_from_tx_now() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let mut key2 = make_test_key(0x22);
        key2.first_seen = 0; // Caller may not set this

        // ParsedCoz has now=2000
        let cz = make_key_add_tx(&key2, &key1.tmb);
        assert_eq!(cz.now, 2000);

        principal
            .apply_transaction_test(cz, Some(key2.clone()))
            .unwrap();

        // New key's first_seen should be set from cz.now
        let added_key = principal.get_key(&key2.tmb).unwrap();
        assert_eq!(added_key.first_seen, 2000);
    }

    // ========================================================================
    // Revoked key guard tests (C15)
    // ========================================================================

    #[test]
    fn revoked_key_in_revoked_set() {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key1 = make_test_key(0x11);
        let key2 = make_test_key(0x22);
        let mut principal = Principal::explicit(vec![key1.clone(), key2.clone()]).unwrap();

        // Revoke key2 (self-revoke)
        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 1500 },
            signer: key2.tmb.clone(),
            now: 1500,
            czd: Czd::from_bytes(vec![0xAA; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, None).unwrap();

        // key2 should be in revoked set, not active
        assert!(!principal.is_key_active(&key2.tmb));
        assert!(principal.auth.revoked.contains_key(&key2.tmb.to_b64()));

        // get_key still finds it (for historical verification)
        assert!(principal.get_key(&key2.tmb).is_some());
    }

    // ========================================================================
    // Last-used tracking tests (C17)
    // ========================================================================

    #[test]
    fn transaction_updates_signer_last_used() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        // Initially, last_used should be None
        assert!(principal.get_key(&key1.tmb).unwrap().last_used.is_none());

        // Apply a key/create coz with now=5000
        let key2 = make_test_key(0x22);

        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};
        let cz = ParsedCoz {
            kind: CozKind::KeyCreate {
                id: key2.tmb.clone(),
            },
            signer: key1.tmb.clone(),
            now: 5000,
            czd: Czd::from_bytes(vec![0xBB; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, Some(key2)).unwrap();

        // Signer's last_used should now be 5000
        assert_eq!(principal.get_key(&key1.tmb).unwrap().last_used, Some(5000));
    }

    #[test]
    fn action_updates_signer_last_used() {
        let key = make_test_key(0xAA);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        assert!(principal.get_key(&key.tmb).unwrap().last_used.is_none());

        // Record action with now=7000
        let action = make_test_action(&key.tmb);
        // Our test helper uses now=3000, let's verify that
        assert_eq!(action.now, 3000);

        principal.record_action(action).unwrap();

        assert_eq!(principal.get_key(&key.tmb).unwrap().last_used, Some(3000));
    }

    // ========================================================================
    // MALT Proof Generation Tests
    // ========================================================================

    /// Helper: build a principal with N commits via key/create transactions.
    /// Returns the principal and the list of keys (genesis + added).
    fn build_principal_with_commits(n_commits: usize) -> (Principal, Vec<Key>) {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};
        let mut keys = vec![make_test_key(0x01)];
        let mut principal = Principal::implicit(keys[0].clone()).unwrap();

        for i in 0..n_commits {
            let new_key = make_test_key((i + 2) as u8);
            let signer = keys.last().unwrap().tmb.clone();

            let cz = ParsedCoz {
                kind: CozKind::KeyCreate {
                    id: new_key.tmb.clone(),
                },
                signer: signer.clone(),
                now: (1000 + (i as i64 + 1) * 1000),
                czd: Czd::from_bytes(vec![0xA0 + i as u8; 32]),
                hash_alg: HashAlg::Sha256,
                arrow: None,
                raw: dummy_coz_json(),
            };

            principal
                .apply_transaction_test(cz, Some(new_key.clone()))
                .unwrap();
            keys.push(new_key);
        }

        (principal, keys)
    }

    #[test]
    fn inclusion_proof_verifies() {
        let (principal, _keys) = build_principal_with_commits(4);

        let alg = principal.hash_alg();
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let root = principal.commit_trees().root(alg_id).unwrap();
        let hasher = MaltHasher::new(alg);
        let size = principal.commit_trees().tree_size(alg_id).unwrap();

        // Verify inclusion for every committed leaf.
        for i in 0..size {
            let proof = principal.inclusion_proof(alg, i).unwrap();
            let commit_tr = principal.commits().nth(i as usize).unwrap().tr();
            let mut mapped_variants = BTreeMap::new();
            for (&a, val) in commit_tr.0.variants() {
                let a_id = crate::commit_root::hash_alg_to_u64(a);
                mapped_variants.insert(a_id, val.clone());
            }
            let serialized = serde_json::to_vec(&mapped_variants).unwrap();
            let leaf_hash = hasher.leaf(&serialized);
            assert!(
                crate::verify_inclusion(&hasher, &leaf_hash, i, size, &proof, &root),
                "inclusion proof failed for index {i}"
            );
        }
    }

    // ========================================================================
    // Two-step transaction inclusion verification (composite hop 1 + hop 2)
    // ========================================================================

    /// Helper: build a multi-algorithm principal (ES256/SHA-256 +
    /// Ed25519/SHA-512) with N commits via key/create transactions —
    /// mirrors `build_principal_with_commits` but drives two active hash
    /// algorithms from genesis, so per-algorithm coverage is observable (a
    /// single-algorithm principal cannot distinguish `root(alg_id)` from
    /// `combined_root()`, per `multi_alg_genesis_pg_equals_sr_for_every_algorithm`).
    fn build_multi_alg_principal_with_commits(n_commits: usize) -> (Principal, Vec<Key>) {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        let mut keys = vec![make_test_key(0x01), make_test_key_ed25519(0x02)];
        let mut principal = Principal::explicit(keys.clone()).unwrap();
        let signer = keys[0].tmb.clone();

        for i in 0..n_commits {
            let new_key = make_test_key((i + 3) as u8);

            let cz = ParsedCoz {
                kind: CozKind::KeyCreate {
                    id: new_key.tmb.clone(),
                },
                signer: signer.clone(),
                now: (1000 + (i as i64 + 1) * 1000),
                czd: Czd::from_bytes(vec![0xC0 + i as u8; 32]),
                hash_alg: HashAlg::Sha256,
                arrow: None,
                raw: dummy_coz_json(),
            };

            principal
                .apply_transaction_test(cz, Some(new_key.clone()))
                .unwrap();
            keys.push(new_key);
        }

        (principal, keys)
    }

    /// c2/a2 — the composite two-step verification accepts every real
    /// committed transaction, under every active hash algorithm, for a
    /// multi-algorithm principal — proving the transaction is really
    /// included under the *current* Principal Root, not just under some CR.
    #[test]
    fn two_step_verification_accepts_every_commit_every_algorithm() {
        let (principal, _keys) = build_multi_alg_principal_with_commits(4);

        for alg in [HashAlg::Sha256, HashAlg::Sha512] {
            let alg_id = crate::commit_root::hash_alg_to_u64(alg);
            let size = principal.commit_trees().tree_size(alg_id).unwrap();
            for i in 0..size {
                let tr = principal.commits().nth(i as usize).unwrap().tr().0.clone();
                assert!(
                    principal.verify_transaction_inclusion(alg, i, &tr).unwrap(),
                    "composite verification failed for alg {alg:?} index {i}"
                );
            }
        }
    }

    /// c3/a3 — a genuine transaction claimed at the wrong index must be
    /// rejected (not silently accepted, not panic).
    #[test]
    fn two_step_verification_rejects_wrong_index() {
        let (principal, _keys) = build_multi_alg_principal_with_commits(3);
        let alg = HashAlg::Sha256;

        // tr0 genuinely sits at index 0, not 1.
        let tr0 = principal.commits().next().unwrap().tr().0.clone();
        let ok = principal
            .verify_transaction_inclusion(alg, 1, &tr0)
            .unwrap();
        assert!(!ok, "wrong index must not verify");
    }

    /// c3/a3 — a forged transaction (wrong claimed leaf value) must be
    /// rejected at the claimed index.
    #[test]
    fn two_step_verification_rejects_forged_transaction() {
        let (principal, _keys) = build_multi_alg_principal_with_commits(3);
        let alg = HashAlg::Sha256;

        let forged = MultihashDigest::from_single(alg, vec![0xEE; 32]).unwrap();
        let ok = principal
            .verify_transaction_inclusion(alg, 0, &forged)
            .unwrap();
        assert!(!ok, "forged transaction must not verify");
    }

    /// c3 attempted the mandatory "wrong skeleton function for a hop"
    /// negative test — but empirically, `mountain_skeleton` and
    /// `rebalanced_skeleton` are byte-identical for every `(arity, size,
    /// index)` this sweeps, at every arity from 2 through 8, not just the
    /// arity-2 this crate actually uses for both CT and PT. This is not a
    /// coincidence: `cml::mountain::bag_peaks`'s doc comment
    /// (`../eml/cml/src/mountain.rs:15-17`) states outright that "`bag_peaks`
    /// is byte-identical to that [`fold_frontier`] fold at every arity" —
    /// the same fold `cmt::shape::build`/`rebalanced_skeleton` use. Both
    /// skeleton generators are built from the same shared
    /// `frontier_for_size` and `fold_frontier` primitives
    /// (`../eml/cml/src/mountain.rs:51`, `../eml/cmt/src/shape.rs:20`), so
    /// their output cannot diverge.
    ///
    /// PLAN.md's mandatory negative test — "deliberately compute hop 1's
    /// skeleton with rebalanced_skeleton instead of mountain_skeleton...
    /// and confirm verification fails" — therefore cannot be constructed:
    /// there is no "wrong" skeleton to substitute, so no false-accept is
    /// possible via this specific substitution, at any arity. This is an
    /// architecture-level finding (a premise refuted by the current `eml`
    /// library, post-MMR-migration), not a gap this node's code introduces
    /// or can route around — flagged in the node report for the lead
    /// maintainer/architect seat to judge, per the "constraint cannot
    /// actually be satisfied as specified" reserved-predicate class.
    ///
    /// This test still records the actual (surprising, load-bearing)
    /// invariant as a regression guard: if a future `eml` change ever makes
    /// these two functions diverge, this test starts failing and the
    /// composite's topology-pinning assumption needs re-examination.
    #[test]
    fn mountain_and_rebalanced_skeletons_are_identical_at_every_arity() {
        for k in [2u64, 3, 4, 5, 8] {
            for size in [2u64, 3, 4, 7, 11, 13, 15, 20, 31, 100] {
                for idx in 0..size {
                    assert_eq!(
                        eml::mountain_skeleton(k, size, idx),
                        polydigest::rebalanced_skeleton(size, k, idx),
                        "k={k} size={size} idx={idx}: mountain_skeleton and rebalanced_skeleton \
                         diverged — if this fires, the wrong-topology negative test PLAN.md \
                         mandates is constructible again and should be added"
                    );
                }
            }
        }
    }

    // ========================================================================
    // Key-membership inclusion verification (chained 4-hop NodePath)
    // ========================================================================

    /// c3/a3 — the chained 4-hop key-membership proof accepts every active
    /// key, under every active hash algorithm, for a multi-algorithm
    /// principal — proving each key's thumbprint is really included under
    /// the *current* Principal Root via KT -> AR-node -> SR-node -> PT.
    #[test]
    fn key_inclusion_accepts_every_active_key_every_algorithm() {
        let (principal, keys) = build_multi_alg_principal_with_commits(4);

        for alg in [HashAlg::Sha256, HashAlg::Sha512] {
            for key in &keys {
                assert!(
                    principal.verify_key_inclusion(alg, &key.tmb).unwrap(),
                    "key inclusion failed for alg {alg:?} tmb {:?}",
                    key.tmb
                );
            }
        }
    }

    /// c3/a3 — a claimed thumbprint that does not name any currently active
    /// key cannot even produce a proof (there is no lexical-sort position to
    /// chain from), so generation itself must reject it.
    #[test]
    fn key_inclusion_rejects_thumbprint_of_inactive_key() {
        let (principal, _keys) = build_multi_alg_principal_with_commits(2);
        let alg = HashAlg::Sha256;

        let never_active = Thumbprint::from_bytes(vec![0xEE; 32]);
        let result = principal.key_inclusion_proof(alg, &never_active);
        assert!(
            result.is_err(),
            "an inactive thumbprint must not produce a proof"
        );
    }

    /// c3/a3 — a genuine proof for a real key, with hop 1's proven leaf
    /// value tampered (as if a different thumbprint were being claimed at
    /// that same lexical position), must be rejected by verification even
    /// though every other hop and bridge in the chain is untouched and
    /// genuinely valid.
    #[test]
    fn key_inclusion_rejects_forged_leaf_at_real_position() {
        let (principal, keys) = build_multi_alg_principal_with_commits(2);
        let alg = HashAlg::Sha256;
        let genuine_tmb = keys[0].tmb.clone();

        let mut path = principal.key_inclusion_proof(alg, &genuine_tmb).unwrap();
        path.hops[0].proof.leaf_hash = vec![0xEE; 32];

        let hasher = MaltHasher::new(alg);
        let kr_bytes = principal.key_root().get(alg).unwrap();
        let ar_bytes = principal.auth_root().get(alg).unwrap();
        let sr_bytes = principal.sr().unwrap().get(alg).unwrap();
        let pr_bytes = principal.pr().get(alg).unwrap();

        assert!(
            !path.verify(&hasher, &[kr_bytes, ar_bytes, sr_bytes, pr_bytes]),
            "a forged hop-1 leaf value must not verify"
        );
    }

    /// c3/a3 — the promotion/genesis case: a single-key implicit-genesis
    /// principal, where KT, AR-node, SR-node, and PT are all simultaneously
    /// 1-cell promotions (KR == tmb, AR == KR, SR == AR, PR == SR, all
    /// verbatim). The chained proof must still verify correctly through
    /// every "skip" hop without any special-case code, since
    /// [`NodePath::verify`] treats a
    /// zero-sibling skeleton identically to any other.
    #[test]
    fn key_inclusion_verifies_through_genesis_promotion_chain() {
        let key = make_test_key(0xAA);
        let tmb = key.tmb.clone();
        let principal = Principal::implicit(key).unwrap();
        let alg = principal.hash_alg();

        // Every intermediate level is a verbatim promotion at genesis.
        assert_eq!(principal.key_root().get(alg), Some(tmb.as_bytes()));
        assert_eq!(principal.auth_root().get(alg), Some(tmb.as_bytes()));
        assert_eq!(principal.sr().unwrap().get(alg), Some(tmb.as_bytes()));
        assert_eq!(principal.pr().get(alg), Some(tmb.as_bytes()));

        assert!(principal.verify_key_inclusion(alg, &tmb).unwrap());
    }

    /// c3/a3 — the bridge loop itself, isolated from the hop-verify loop.
    ///
    /// Splices hop 0 from principal A's genuine key-inclusion chain with
    /// hops 1..3 from principal B's genuine (unrelated) chain. Every
    /// spliced hop is independently checked below to verify `true` against
    /// its own matched root — proving the hop-verify loop alone would
    /// accept this `NodePath` and cannot be what rejects it. Only the
    /// bridge loop — hop `i`'s proven leaf value must equal hop `i-1`'s
    /// root — can catch that hop 1's proven leaf (B's KR) does not match
    /// hop 0's root (A's KR, a different key's tmb since A and B never
    /// shared a genesis key). `key_inclusion_rejects_forged_leaf_at_real_position`
    /// (above) instead fails in the hop-verify loop before the bridge loop
    /// ever runs, so it does not cover this.
    #[test]
    fn key_inclusion_bridge_rejects_spliced_hops_that_individually_verify() {
        let key_a = make_test_key(0xAA);
        let tmb_a = key_a.tmb.clone();
        let principal_a = Principal::implicit(key_a).unwrap();

        let key_b = make_test_key(0xBB);
        let tmb_b = key_b.tmb.clone();
        let principal_b = Principal::implicit(key_b).unwrap();

        let alg = principal_a.hash_alg();
        assert_eq!(alg, principal_b.hash_alg());

        let path_a = principal_a.key_inclusion_proof(alg, &tmb_a).unwrap();
        let path_b = principal_b.key_inclusion_proof(alg, &tmb_b).unwrap();

        let kr_a = principal_a.key_root().get(alg).unwrap();
        let ar_b = principal_b.auth_root().get(alg).unwrap();
        let sr_b = principal_b.sr().unwrap().get(alg).unwrap();
        let pr_b = principal_b.pr().get(alg).unwrap();
        assert_ne!(
            kr_a,
            principal_b.key_root().get(alg).unwrap(),
            "test fixture requires A and B to have genuinely different KRs"
        );

        let spliced = NodePath {
            hops: vec![
                path_a.hops[0].clone(),
                path_b.hops[1].clone(),
                path_b.hops[2].clone(),
                path_b.hops[3].clone(),
            ],
        };

        let hasher = MaltHasher::new(alg);
        let roots: [&[u8]; 4] = [kr_a, ar_b, sr_b, pr_b];

        // The hop-verify loop alone accepts every spliced hop: each proof
        // is genuine and matched against its own originating root here.
        for (hop, &root) in spliced.hops.iter().zip(roots.iter()) {
            let skeleton = polydigest::rebalanced_skeleton(
                hop.proof.tree_size,
                hop.proof.arity,
                hop.proof.index,
            )
            .unwrap();
            assert!(
                hop.proof.verify(&hasher, &skeleton, root),
                "each spliced hop must verify in isolation against its own root"
            );
        }

        // Only the bridge loop can reject the chain as a whole: hop 1's
        // proven leaf (B's KR) does not equal hop 0's root (A's KR).
        assert!(
            !spliced.verify(&hasher, &roots),
            "spliced hops that individually verify must still be rejected by the bridge linkage \
             check"
        );
    }

    #[test]
    fn consistency_proof_verifies() {
        let (principal, _keys) = build_principal_with_commits(5);

        let alg = principal.hash_alg();
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let new_root = principal.commit_trees().root(alg_id).unwrap();
        let hasher = MaltHasher::new(alg);

        // Build a reference EML log to capture intermediate roots.
        let mut ref_log =
            futures::executor::block_on(eml::from_storage(eml::MemoryStorage::new(), Vec::new()))
                .unwrap();
        futures::executor::block_on(ref_log.add_algorithm(alg_id, Box::new(MaltHasher::new(alg))))
            .unwrap();
        let mut roots = Vec::new();
        for commit in principal.commits() {
            let mut mapped_variants = BTreeMap::new();
            for (&a, val) in commit.tr().0.variants() {
                let a_id = crate::commit_root::hash_alg_to_u64(a);
                mapped_variants.insert(a_id, val.clone());
            }
            let tr_bytes = serde_json::to_vec(&mapped_variants).unwrap();
            futures::executor::block_on(ref_log.append_leaf(&tr_bytes)).unwrap();
            roots.push(ref_log.root_for(alg_id).unwrap());
        }

        // Verify consistency from each prior size to current.
        let size = principal.commit_trees().tree_size(alg_id).unwrap();
        for old_size in 1..size {
            let proof = principal.consistency_proof(alg, old_size).unwrap();
            let old_root = &roots[(old_size - 1) as usize];
            assert!(
                crate::verify_consistency(&hasher, old_size, size, &proof, old_root, &new_root),
                "consistency proof failed for old_size {old_size}"
            );
        }
    }

    #[test]
    fn inclusion_proof_out_of_bounds() {
        let (principal, _keys) = build_principal_with_commits(3);
        let alg = principal.hash_alg();

        // Index == tree_size should fail.
        let result = principal.inclusion_proof(alg, 3);
        assert!(result.is_err(), "should reject out-of-bounds index");

        // Large index should also fail.
        let result = principal.inclusion_proof(alg, 999);
        assert!(result.is_err(), "should reject large index");
    }

    #[test]
    fn consistency_proof_invalid_old_size() {
        let (principal, _keys) = build_principal_with_commits(3);
        let alg = principal.hash_alg();

        // old_size == 0 should fail.
        let result = principal.consistency_proof(alg, 0);
        assert!(result.is_err(), "should reject old_size=0");

        // old_size >= tree_size should fail.
        let result = principal.consistency_proof(alg, 3);
        assert!(result.is_err(), "should reject old_size >= tree_size");
    }

    #[test]
    fn proof_rejects_unknown_algorithm() {
        let (principal, _keys) = build_principal_with_commits(2);

        // SHA-384 was never introduced (all test keys use ES256/SHA-256).
        let result = principal.inclusion_proof(HashAlg::Sha384, 0);
        assert!(result.is_err(), "should reject unknown algorithm");

        let result = principal.consistency_proof(HashAlg::Sha384, 1);
        assert!(result.is_err(), "should reject unknown algorithm");
    }

    #[test]
    fn checkpoint_round_trip_preserves_malt_state() {
        let (principal, keys) = build_principal_with_commits(4);

        let alg = principal.hash_alg();
        let original_cr = principal.cr().cloned();
        let original_trees = principal.commit_trees().clone();

        // Round-trip: extract MALT state → from_checkpoint → verify.
        let restored = Principal::from_checkpoint(
            principal.pg().cloned(),
            principal.auth_root().clone(),
            keys,
            Some(original_trees),
        )
        .unwrap();

        // CR must match.
        assert_eq!(
            restored.cr().map(|c| c.as_multihash().clone()),
            original_cr.map(|c| c.as_multihash().clone()),
            "checkpoint round-trip must preserve CR"
        );

        // Proof generation must still work on the restored principal.
        let proof = restored.inclusion_proof(alg, 0).unwrap();
        let alg_id = crate::commit_root::hash_alg_to_u64(alg);
        let root = restored.commit_trees().root(alg_id).unwrap();
        let size = restored.commit_trees().tree_size(alg_id).unwrap();
        let hasher = MaltHasher::new(alg);
        let commit_tr = principal.commits().next().unwrap().tr();
        let mut mapped_variants = BTreeMap::new();
        for (&a, val) in commit_tr.0.variants() {
            let a_id = crate::commit_root::hash_alg_to_u64(a);
            mapped_variants.insert(a_id, val.clone());
        }
        let serialized = serde_json::to_vec(&mapped_variants).unwrap();
        let leaf_hash = hasher.leaf(&serialized);
        assert!(
            crate::verify_inclusion(&hasher, &leaf_hash, 0, size, &proof, &root),
            "inclusion proof must verify on checkpoint-restored principal"
        );
    }

    #[test]
    fn checkpoint_without_trees_has_no_cr() {
        let (principal, keys) = build_principal_with_commits(3);

        // from_checkpoint with None trees should yield cr() == None
        // (backward-compatible behavior).
        let restored = Principal::from_checkpoint(
            principal.pg().cloned(),
            principal.auth_root().clone(),
            keys,
            None,
        )
        .unwrap();

        assert!(
            restored.cr().is_none(),
            "from_checkpoint without trees must have no CR"
        );
        assert!(
            restored.commit_trees().is_empty(),
            "from_checkpoint without trees must have empty commit_trees"
        );
    }

    #[test]
    fn checkpoint_pr_includes_cr_when_trees_provided() {
        let (principal, keys) = build_principal_with_commits(3);
        let trees = principal.commit_trees().clone();

        // Restore with trees: PR should be MR(SR, CR), not just SR.
        let with_trees = Principal::from_checkpoint(
            principal.pg().cloned(),
            principal.auth_root().clone(),
            keys.clone(),
            Some(trees),
        )
        .unwrap();

        // Restore without trees: PR should be MR(SR), with CR absent.
        let without_trees = Principal::from_checkpoint(
            principal.pg().cloned(),
            principal.auth_root().clone(),
            keys,
            None,
        )
        .unwrap();

        // The two PRs must differ because CR is present in one and not the other.
        let pr_with = with_trees.pr().get(with_trees.hash_alg()).unwrap().to_vec();
        let pr_without = without_trees
            .pr()
            .get(without_trees.hash_alg())
            .unwrap()
            .to_vec();

        assert_ne!(
            pr_with, pr_without,
            "PR must differ when CR is present vs absent"
        );
    }

    // ========================================================================
    // Principal Tree (PT) genesis invariance and isolation tests
    // ========================================================================

    /// A key using a different algorithm/thumbprint length than `make_test_key`
    /// (which is always ES256/SHA-256), so a two-key principal registers two
    /// distinct hash algorithms from genesis.
    fn make_test_key_ed25519(id: u8) -> Key {
        Key {
            alg: "Ed25519".to_string(),
            tmb: Thumbprint::from_bytes(vec![id; 64]), // SHA-512 digest length
            pub_key: vec![id; 32],
            first_seen: 1000,
            last_used: None,
            revocation: None,
            tag: None,
        }
    }

    /// c2/a2 — the correctness pivot of this node: for a principal with 2+
    /// registered hash algorithms, `pg()` (frozen at `principal/create`,
    /// while the Commit Tree/cell-1 is still empty) must equal `sr()`
    /// byte-for-byte for EVERY registered algorithm, not just one.
    ///
    /// A single-algorithm principal cannot distinguish `EpochTree::root(alg_id)`
    /// (correct) from `combined_root()` (folds every other algorithm's root
    /// in, wrong) — both coincide when only one algorithm is registered. This
    /// test's ES256 (SHA-256) + Ed25519 (SHA-512) key set is what makes the
    /// distinction observable.
    #[test]
    fn multi_alg_genesis_pg_equals_sr_for_every_algorithm() {
        use crate::parsed_coz::{CozKind, ParsedCoz, VerifiedCoz};

        let key_es256 = make_test_key(0x11);
        let key_ed25519 = make_test_key_ed25519(0x22);

        let mut principal =
            Principal::explicit(vec![key_es256.clone(), key_ed25519.clone()]).unwrap();
        assert!(
            principal.pg().is_none(),
            "PR should be None before principal/create"
        );
        assert_eq!(
            principal.active_algs(),
            vec![HashAlg::Sha256, HashAlg::Sha512]
        );

        let id = principal.auth_root().clone();
        let cz = ParsedCoz {
            kind: CozKind::PrincipalCreate { id },
            signer: key_es256.tmb.clone(),
            now: 2000,
            czd: coz::Czd::from_bytes(vec![0x33; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        };
        let vtx = VerifiedCoz::from_transaction_unsafe(cz, None);
        principal.apply_verified_internal(vtx).unwrap();

        let pg = principal.pg().expect("principal/create must establish PG");
        let sr = principal.sr().expect("SR must exist after genesis");
        for alg in [HashAlg::Sha256, HashAlg::Sha512] {
            assert_eq!(
                pg.get(alg),
                sr.get(alg),
                "PG must equal SR byte-for-byte for algorithm {alg:?} at genesis (cell 1/CR still \
                 empty) — a mismatch here means root(alg_id) and combined_root() diverged, i.e. \
                 combined_root leaked in"
            );
        }
    }

    /// c6/a6 — an abandoned `CommitScope` (dropped without `finalize()`) must
    /// not leak any state into the live principal: not the key set (already
    /// covered structurally by the borrow checker + explicit copy-back), and
    /// not PR/SR/PT, which is the new hazard this node introduces (SR now
    /// lives inside a PT cell that would be shared state if `PrincipalTree`
    /// were `Arc`-wrapped like `CommitTrees`/`CloneableLog`).
    #[test]
    fn abandoned_commit_scope_does_not_leak_state() {
        let key1 = make_test_key(0x11);
        let mut principal = Principal::implicit(key1.clone()).unwrap();

        let pr_before = principal.pr().clone();
        let sr_before = principal.sr().cloned();
        let key_count_before = principal.active_key_count();

        {
            let mut scope = principal.begin_commit();
            let key2 = make_test_key(0x22);
            let cz = make_key_add_tx(&key2, &key1.tmb);
            let vtx = crate::parsed_coz::VerifiedCoz::from_transaction_unsafe(cz, Some(key2));
            scope.apply(vtx).unwrap();
            // Deliberately dropped here without calling finalize().
        }

        assert_eq!(
            principal.pr(),
            &pr_before,
            "abandoned scope must not mutate the live PR"
        );
        assert_eq!(
            principal.sr().cloned(),
            sr_before,
            "abandoned scope must not mutate the live SR"
        );
        assert_eq!(
            principal.active_key_count(),
            key_count_before,
            "abandoned scope must not mutate the live key set"
        );
    }

    /// c7/a7 — PR's variant set must track the *current* `active_algs`, not
    /// the Principal Tree's cumulative registered-algorithm set.
    ///
    /// `PrincipalTree::ensure_algorithm` only ever adds algorithms to the
    /// underlying `EpochTree` — there is no de-registration API. If PR were
    /// assembled from the tree's registered algorithms instead of being
    /// re-derived from `active_algs` on every mutation (see
    /// `finalize_commit`'s `[alg-set-evolution]` comment), revoking a
    /// principal's only SHA-512 key would leave a stale SHA-512 entry in PR
    /// forever, since the tree itself never forgets it was once registered.
    #[test]
    fn revoked_key_algorithm_drops_from_pr_variants() {
        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key_es256 = make_test_key(0x11);
        let key_ed25519 = make_test_key_ed25519(0x22);

        let mut principal =
            Principal::explicit(vec![key_es256.clone(), key_ed25519.clone()]).unwrap();
        assert_eq!(
            principal.active_algs(),
            vec![HashAlg::Sha256, HashAlg::Sha512]
        );
        assert!(
            principal.pr().get(HashAlg::Sha512).is_some(),
            "PR must have a SHA-512 variant while the Ed25519 key is active"
        );

        // Ed25519 key self-revokes; ES256 remains, so this is not a
        // last-active-key revoke (which would be rejected).
        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 2000 },
            signer: key_ed25519.tmb.clone(),
            now: 2000,
            czd: coz::Czd::from_bytes(vec![0x44; 64]),
            hash_alg: HashAlg::Sha512,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, None).unwrap();

        assert!(
            !principal.is_key_active(&key_ed25519.tmb),
            "Ed25519 key must be revoked"
        );
        assert_eq!(
            principal.active_algs(),
            vec![HashAlg::Sha256],
            "SHA-512 must drop out of active_algs once its only key is revoked"
        );
        assert!(
            principal.pr().get(HashAlg::Sha512).is_none(),
            "PR must not retain a stale SHA-512 variant after its only key is revoked — this only \
             holds if PR is assembled from live active_algs rather than the tree's cumulative \
             registered-algorithm set"
        );
        assert!(
            principal.pr().get(HashAlg::Sha256).is_some(),
            "PR must still have a SHA-256 variant for the surviving ES256 key"
        );
    }

    /// c-liveness-shrinkage-rebuild — extends
    /// `revoked_key_algorithm_drops_from_pr_variants`'s metamorphic pattern
    /// to every new tree level, not just PR: KT, AR-node, and SR-node are
    /// rebuilt fresh from the post-revocation key set on every mutation, so
    /// a dropped algorithm cannot survive in KR/AR/SR either.
    #[test]
    fn revoked_key_algorithm_drops_from_kr_ar_sr_too() {
        use crate::parsed_coz::{CozKind, ParsedCoz};

        let key_es256 = make_test_key(0x11);
        let key_ed25519 = make_test_key_ed25519(0x22);

        let mut principal =
            Principal::explicit(vec![key_es256.clone(), key_ed25519.clone()]).unwrap();
        assert_eq!(
            principal.active_algs(),
            vec![HashAlg::Sha256, HashAlg::Sha512]
        );
        assert!(principal.key_root().get(HashAlg::Sha512).is_some());
        assert!(principal.auth_root().get(HashAlg::Sha512).is_some());
        assert!(principal.sr().unwrap().get(HashAlg::Sha512).is_some());

        let cz = ParsedCoz {
            kind: CozKind::SelfRevoke { rvk: 2000 },
            signer: key_ed25519.tmb.clone(),
            now: 2000,
            czd: coz::Czd::from_bytes(vec![0x44; 64]),
            hash_alg: HashAlg::Sha512,
            arrow: None,
            raw: dummy_coz_json(),
        };
        principal.apply_transaction_test(cz, None).unwrap();

        assert_eq!(principal.active_algs(), vec![HashAlg::Sha256]);
        assert!(
            principal.key_root().get(HashAlg::Sha512).is_none(),
            "KR must not retain a stale SHA-512 variant — KT must be rebuilt with only live \
             algorithms registered, not masked"
        );
        assert!(
            principal.auth_root().get(HashAlg::Sha512).is_none(),
            "AR must not retain a stale SHA-512 variant — AR-node must be rebuilt with only live \
             algorithms registered, not masked"
        );
        assert!(
            principal.sr().unwrap().get(HashAlg::Sha512).is_none(),
            "SR must not retain a stale SHA-512 variant — SR-node must be rebuilt with only live \
             algorithms registered, not masked"
        );
        assert!(principal.key_root().get(HashAlg::Sha256).is_some());
        assert!(principal.auth_root().get(HashAlg::Sha256).is_some());
        assert!(principal.sr().unwrap().get(HashAlg::Sha256).is_some());
    }

    /// Reproduces a proptest-discovered defect: a `DataRoot` cached from
    /// `record_action` under a narrower `active_algs` set must not be
    /// reused unrefreshed once a later key of a NEW algorithm expands
    /// `active_algs` — the stale DR is missing a variant for the new
    /// algorithm, and `MultihashDigest::get_or_err`'s "first available
    /// variant" fallback silently substitutes a wrong-width value, which
    /// the tree's width-uniform fold contract correctly rejects.
    #[test]
    fn adding_new_algorithm_key_after_action_recorded_does_not_panic() {
        use coz::Czd;
        use serde_json::json;

        use crate::parsed_coz::CozKind;

        let key = make_test_key(0x11);
        let mut principal = Principal::implicit(key.clone()).unwrap();

        let action = make_test_action(&key.tmb);
        principal.record_action(action).unwrap();
        assert_eq!(principal.active_algs(), vec![HashAlg::Sha256]);

        // A key/create tx timestamped after the action (make_test_action
        // uses now=3000; make_key_add_tx's fixed now=2000 would fail
        // timestamp ordering, so this is constructed inline instead).
        let key2 = make_test_key_ed25519(0x22);
        let raw = coz::CozJson {
            pay: json!({
                "typ": "cyphr.me/key/create",
                "alg": "Ed25519",
                "now": 4000,
                "tmb": key.tmb.to_b64(),
                "id": key2.tmb.to_b64()
            }),
            sig: vec![0; 64],
        };
        let cz = crate::parsed_coz::ParsedCoz {
            kind: CozKind::KeyCreate {
                id: key2.tmb.clone(),
            },
            signer: key.tmb.clone(),
            now: 4000,
            czd: Czd::from_bytes(vec![0xAB; 32]),
            hash_alg: HashAlg::Sha256,
            arrow: None,
            raw,
        };
        principal
            .apply_transaction_test(cz, Some(key2.clone()))
            .unwrap();

        assert_eq!(
            principal.active_algs(),
            vec![HashAlg::Sha256, HashAlg::Sha512]
        );
        assert!(principal.sr().unwrap().get(HashAlg::Sha512).is_some());
    }

    /// c2/a2 — the recursive singleton-promotion property, extended through
    /// the FULL new chain (`genesis_pr_equals_sr_verbatim` already proves it
    /// at PT's root alone): for a single-key, no-data-action, no-commit
    /// principal, `tmb == KR == AR == SR == PR`, byte-for-byte, for every
    /// registered algorithm. Every hop is the same native 1-cell promotion
    /// mechanism, composed recursively — no special-case machinery.
    #[test]
    fn genesis_recursive_promotion_tmb_equals_kr_ar_sr_pr() {
        let key = make_test_key_ed25519(0xCC);
        let tmb_bytes = key.tmb.as_bytes().to_vec();
        let principal = Principal::implicit(key).unwrap();

        let alg = principal.hash_alg();
        assert_eq!(principal.active_algs(), vec![alg]);

        assert_eq!(principal.key_root().get(alg).unwrap(), tmb_bytes.as_slice());
        assert_eq!(
            principal.auth_root().get(alg).unwrap(),
            tmb_bytes.as_slice()
        );
        assert_eq!(
            principal.sr().unwrap().get(alg).unwrap(),
            tmb_bytes.as_slice()
        );
        assert_eq!(principal.pr().get(alg).unwrap(), tmb_bytes.as_slice());
    }

    // ========================================================================
    // c3/a3 — establish_pg works for any storage backend
    // ========================================================================

    /// Build an explicit-genesis `principal/create` coz for `key`, signed
    /// against `id` taken from the given principal — the minimal mutation
    /// that drives `establish_pg`'s Nascent → Established transition.
    fn make_principal_create_tx<S: eml::Storage>(
        principal: &Principal<S>,
        key: &Key,
        czd_byte: u8,
    ) -> crate::parsed_coz::ParsedCoz {
        use coz::Czd;

        use crate::parsed_coz::{CozKind, ParsedCoz};

        ParsedCoz {
            kind: CozKind::PrincipalCreate {
                id: principal.auth_root().clone(),
            },
            signer: key.tmb.clone(),
            now: 2000,
            czd: Czd::from_bytes(vec![czd_byte; 32]),
            hash_alg: crate::state::HashAlg::Sha256,
            arrow: None,
            raw: dummy_coz_json(),
        }
    }

    /// c3/a3 — `establish_pg` (reached via a `principal/create` coz) must
    /// work correctly for `Principal<storage_fjall::FjallStorage>` — a
    /// storage backend with no `Default` impl — without requiring `S:
    /// Default` and without a fake/panicking `Default` on `FjallStorage`.
    /// PG must be set exactly once, and byte-identical to what the same
    /// operations produce under `Principal<eml::MemoryStorage>`.
    #[test]
    fn establish_pg_works_for_disk_backed_storage() {
        use crate::parsed_coz::VerifiedCoz;

        let key = make_test_key(0x11);

        // Disk-backed principal.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = storage_fjall::FjallStorage::open(dir.path()).expect("open fjall storage");
        let mut disk_principal =
            Principal::explicit_with_storage(vec![key.clone()], storage).unwrap();
        assert!(
            disk_principal.pg().is_none(),
            "PG must be absent before principal/create"
        );

        let cz = make_principal_create_tx(&disk_principal, &key, 0x44);
        let vtx = VerifiedCoz::from_transaction_unsafe(cz, None);
        disk_principal.apply_verified_internal(vtx).unwrap();
        let pg_disk = disk_principal
            .pg()
            .expect("establish_pg must set PG for a disk-backed Principal")
            .clone();

        // The equivalent in-memory principal, driven through the identical
        // sequence of operations.
        let mut mem_principal = Principal::explicit(vec![key.clone()]).unwrap();
        let mem_cz = make_principal_create_tx(&mem_principal, &key, 0x44);
        let mem_vtx = VerifiedCoz::from_transaction_unsafe(mem_cz, None);
        mem_principal.apply_verified_internal(mem_vtx).unwrap();
        let pg_mem = mem_principal
            .pg()
            .expect("establish_pg must set PG for an in-memory Principal")
            .clone();

        assert_eq!(
            pg_disk.as_multihash(),
            pg_mem.as_multihash(),
            "PG must be byte-identical between a disk-backed and an in-memory storage backend"
        );

        // PG is set exactly once: a second principal/create must fail, not
        // silently re-establish or panic.
        let second_cz = make_principal_create_tx(&disk_principal, &key, 0x55);
        let second_vtx = VerifiedCoz::from_transaction_unsafe(second_cz, None);
        let result = disk_principal.apply_verified_internal(second_vtx);
        assert!(
            matches!(result, Err(Error::StateMismatch)),
            "a second principal/create must fail — PG is already established"
        );
    }
}
