//! Principal (identity) types.
//!
//! A Principal is a self-sovereign identity in the Cyphr protocol.
//!
//! The type, its shared state ([`PrincipalCore`]) and the one place that
//! state is assembled live here; behaviour is split by concern:
//! `genesis` (construction and genesis finalization), `accessors`
//! (read-only views and configuration), `proofs` (inclusion and
//! consistency proofs), `data` (Level 4 action recording) and `apply`
//! (transaction application and commit finalization).

mod accessors;
mod apply;
mod data;
mod genesis;
mod proofs;
#[cfg(test)]
mod tests;

use std::collections::HashSet;

use coz::Thumbprint;
use indexmap::IndexMap;
pub(crate) use proofs::{NodePath, NodePathHop};

use crate::action::Action;
use crate::commit::Commit;
use crate::error::{Error, Result};
use crate::key::Key;
use crate::nonce::{NonceLevel, NonceSets};
use crate::principal_tree::PrincipalTree;
use crate::state::{
    AuthRoot, DataRoot, HashAlg, KeyRoot, PrincipalGenesis, PrincipalRoot, StateRoot,
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
    /// Every PR this principal has held, oldest first: the PR it was born
    /// with, then the PR after each commit and each recorded action. A PR
    /// is a point-in-time snapshot (SPEC 3.7.1), so merge matching
    /// (SPEC 11.5.1) needs the history, not only the current PR. Rebuilt
    /// by replaying history.
    pub(crate) held_prs: Vec<PrincipalRoot>,
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
    /// Full czd bytes of every transaction coz and data action this
    /// principal has included (SPEC §7.6). Keyed on the whole digest, not a
    /// prefix: czd width follows the signing algorithm (ES384 = 48 bytes).
    /// Rebuilt by replaying history; there is no checkpoint restore.
    pub(crate) included_czds: HashSet<Vec<u8>>,
    /// Nonces held at the PR, AT and KT levels (SPEC §10.1).
    pub(crate) nonces: NonceSets,
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

impl<S: eml::Storage> PrincipalCore<S> {
    /// Copy with the commit log aliased, not duplicated; see
    /// [`crate::commit_root::CloneableLog`].
    pub(crate) fn share(&self) -> Self {
        self.with_trees(self.commit_trees.share())
    }
}

impl<S: eml::Storage + Clone> Clone for PrincipalCore<S> {
    fn clone(&self) -> Self {
        self.with_trees(self.commit_trees.clone())
    }
}

impl<S: eml::Storage> PrincipalCore<S> {
    /// Clone every field except the commit log, which the caller supplies.
    fn with_trees(&self, commit_trees: crate::commit_root::CommitTrees<S>) -> Self {
        Self {
            pr: self.pr.clone(),
            held_prs: self.held_prs.clone(),
            kr: self.kr.clone(),
            tr: self.tr.clone(),
            commit_trees,
            pt: self.pt.clone(),
            cr: self.cr.clone(),
            sr: self.sr.clone(),
            ar: self.ar.clone(),
            dr: self.dr.clone(),
            auth: self.auth.clone(),
            data: self.data.clone(),
            included_czds: self.included_czds.clone(),
            nonces: self.nonces.clone(),
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
            .field("held_prs", &self.held_prs)
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
            .field("nonces", &self.nonces)
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

impl<S: eml::Storage> PrincipalKind<S> {
    fn share(&self) -> Self {
        match self {
            Self::Nascent(core) => Self::Nascent(core.share()),
            Self::Established { core, pg } => Self::Established {
                core: core.share(),
                pg: pg.clone(),
            },
        }
    }
}

impl<S: eml::Storage + Clone> Clone for PrincipalKind<S> {
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

impl<S: eml::Storage> Principal<S> {
    /// Copy that aliases this principal's commit log; used by
    /// [`crate::commit::CommitScope`] to record to its own principal.
    pub(crate) fn share(&self) -> Self {
        Self(self.0.as_ref().map(PrincipalKind::share))
    }
}

impl<S: eml::Storage + Clone> Clone for Principal<S> {
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

/// The roots a newly constructed principal starts from: KR, AR and SR,
/// the Commit Root of a restored commit log (if any), and the Principal
/// Tree built over them with its PR.
struct StartingRoots {
    kr: KeyRoot,
    ar: AuthRoot,
    sr: StateRoot,
    cr: Option<crate::commit_root::CommitRoot>,
    pt: PrincipalTree,
    pr: PrincipalRoot,
}

impl StartingRoots {
    /// Build the Principal Tree over `sr` (cell 0) and, when a commit log
    /// was restored, `cr` (cell 1), and derive PR from it. With no CR the
    /// tree's singleton promotion makes PR = SR.
    fn new(
        kr: KeyRoot,
        ar: AuthRoot,
        sr: StateRoot,
        cr: Option<crate::commit_root::CommitRoot>,
        algs: &[HashAlg],
    ) -> Result<Self> {
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, algs)?;
        if let Some(ref cr_val) = cr {
            pt.set_cr(cr_val, algs)?;
        }
        let pr = pt.pr(algs)?;
        Ok(Self {
            kr,
            ar,
            sr,
            cr,
            pt,
            pr,
        })
    }
}

/// Validate the keys a principal is born with. Genesis is the one place a
/// key enters the active set without a `key/create` replay, so it applies
/// the refusals `key/create` gives: a revoked key is `KeyRevoked` (SPEC
/// §7.7 requires a `key/create` for every key including the first; §6.4
/// never trusts a revoked key again) and a repeated key is `DuplicateKey`,
/// not silently collapsed. Revocation is checked for every key before
/// duplication so both genesis paths report the same error for the same
/// key. (An unsupported algorithm cannot reach here: [`Key`] has no
/// constructor for one.)
fn validate_genesis_keys(keys: &[Key]) -> Result<()> {
    if keys.is_empty() {
        return Err(Error::NoActiveKeys);
    }
    if keys.iter().any(|k| !k.is_active()) {
        return Err(Error::KeyRevoked);
    }
    let mut seen = HashSet::with_capacity(keys.len());
    if !keys.iter().all(|k| seen.insert(k.tmb().to_b64())) {
        return Err(Error::DuplicateKey);
    }
    Ok(())
}

/// Open the Commit Tree over a caller-supplied storage backend.
fn open_commit_trees<S: eml::Storage>(storage: S) -> Result<crate::commit_root::CommitTrees<S>> {
    crate::commit_root::CommitTrees::open(storage).map_err(|e| Error::Storage(e.to_string()))
}

impl<S: eml::Storage> PrincipalCore<S> {
    /// Assemble a principal's state from its keys, starting roots and
    /// Commit Tree. Callers pass keys that [`validate_genesis_keys`]
    /// accepted, so the active set never holds a revoked or repeated key.
    /// Every constructor ends here, so a field added to
    /// `PrincipalCore` or a change to how a fresh principal is filled is
    /// made once. `keys` become both the active set and the genesis-key
    /// list, in the order given.
    fn new(
        keys: Vec<Key>,
        roots: StartingRoots,
        commit_trees: crate::commit_root::CommitTrees<S>,
    ) -> Self {
        debug_assert!(validate_genesis_keys(&keys).is_ok());
        let genesis_keys: Vec<String> = keys.iter().map(|k| k.tmb().to_b64()).collect();
        let mut key_map = IndexMap::new();
        for k in keys {
            key_map.insert(k.tmb().to_b64(), k);
        }
        let StartingRoots {
            kr,
            ar,
            sr,
            cr,
            pt,
            pr,
        } = roots;
        PrincipalCore {
            held_prs: vec![pr.clone()],
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
            included_czds: HashSet::new(),
            nonces: NonceSets::default(),
            latest_timestamp: 0,
            max_clock_skew: 0,
            genesis_keys,
            deleted: false,
            deleted_pending: false,
            frozen: false,
            errored: false,
        }
    }

    /// Resolve `tmb` to the active key that may sign for this principal.
    ///
    /// The single signer lookup every verification path uses, so a key is
    /// classified the same way wherever it signs: an active key resolves,
    /// a revoked key (SPEC §6.4, never trusted again) is `KeyRevoked`, and
    /// anything else is `UnknownKey`.
    ///
    /// # Errors
    ///
    /// `KeyRevoked` or `UnknownKey` as above.
    pub(crate) fn active_signer(&self, tmb: &Thumbprint) -> Result<&Key> {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.auth.keys.get(&tmb_b64) {
            return Ok(key);
        }
        if self.auth.revoked.contains_key(&tmb_b64) {
            Err(Error::KeyRevoked)
        } else {
            Err(Error::UnknownKey)
        }
    }

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
        self.pt
            .set_nonces(&self.nonces.at_level(NonceLevel::Pr), algs)?;
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
        self.pt
            .set_nonces(&self.nonces.at_level(NonceLevel::Pr), algs)?;
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
