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
mod embedded;
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

/// The verifier's clock: Unix seconds, injected so the core never reads
/// ambient time on a platform that has none (wasm32-unknown-unknown).
pub type Clock = fn() -> i64;

/// Default tolerance for a `now` ahead of the verifier clock: the +-360 s of
/// SPEC 15.9. A `now` past `clock() + max_clock_skew` is `TimestampFuture`.
pub const DEFAULT_MAX_CLOCK_SKEW: u64 = 360;

/// Largest valid `now`, 2^53 - 1 (SPEC 6.4: an integer in `1..2^53-1`, the
/// range every JSON consumer reads exactly). Spec 4.1 states no range for a
/// coz `now`; applying the 6.4 range to every coz is the implementation's
/// reading, pending the spec author's answer.
pub const MAX_NOW: i64 = (1 << 53) - 1;

/// Wall-clock Unix seconds. A clock before the epoch reads 0, which refuses
/// every `now` as future, so a broken clock fails closed. Without ambient
/// time (wasm32-unknown-unknown, where `SystemTime::now` panics) it also
/// reads 0 until the host installs a clock with `Principal::set_clock`.
pub fn system_clock() -> i64 {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0)
    }
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        0
    }
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

/// Data ledger holding actions (Level 4+): the Data Tree (DT).
///
/// A data action is recorded in DT and nowhere else: DT is a point-in-time
/// snapshot with no chain (SPEC 2.3.3), and DR enters the Principal Tree
/// only as the `id` a `ds/create` signs (SPEC 4.8.2).
#[derive(Debug, Clone, Default)]
pub struct DataLedger {
    /// All recorded actions, in recording order.
    pub actions: Vec<Action>,
}

impl DataLedger {
    /// MR over every held action: the `id` a `ds/create` signed now would
    /// name.
    pub(crate) fn tree_root(&self, algs: &[HashAlg]) -> Result<Option<DataRoot>> {
        let actions: Vec<&Action> = self.actions.iter().collect();
        crate::state::compute_dr(&actions, None, algs)
    }
}

// ============================================================================
// Feature Levels
// ============================================================================

/// Feature level of a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
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

/// Shared internal state for all Principal variants: everything but the
/// commit log, which [`Principal`] owns beside it.
///
/// Every field *except* PR lives here. PR is structurally absent for Nascent
/// principals and structurally present for Established ones — invalid states
/// are unrepresentable.
///
/// # Visibility
///
/// `pub` to satisfy `Deref<Target = PrincipalCore>` on [`PrincipalState`].
/// All fields are `pub(crate)` — external code cannot access them.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PrincipalCore {
    /// Current Principal State.
    pub(crate) pr: PrincipalRoot,
    /// Every PR this principal has held, oldest first: the PR it was born
    /// with, then the PR after each commit and each recorded action. A PR
    /// is a point-in-time snapshot (SPEC 3.7.1), so merge matching
    /// (SPEC 11.5.1) needs the history, not only the current PR. Rebuilt
    /// by replaying history.
    pub(crate) held_prs: Vec<PrincipalRoot>,
    /// Current Key Root; `None` once no key remains (SPEC 3.7: an empty
    /// component is omitted, so a Dead principal has no KT).
    pub(crate) kr: Option<KeyRoot>,
    /// Current Commit ID (Merkle root of last commit's cozies).
    pub(crate) tr: Option<crate::transaction_root::TransactionRoot>,
    /// Principal Tree (PT): the `EpochTree` backing PR. Cell 0 = SR, cell 1 =
    /// CR. The source of truth for PR; `sr`/`cr` below are a cache mirroring
    /// its cell contents (kept in lockstep by
    /// [`PrincipalCore::write_pt_sr_cr`]) so existing accessors
    /// (`Principal::sr()`/`cr()`) don't need to deserialize a cell payload on
    /// every call.
    pub(crate) pt: PrincipalTree,
    /// Current Commit Root (CR). Mirrors `pt`'s cell 1.
    pub(crate) cr: Option<crate::commit_root::CommitRoot>,
    /// Current State Root: SR = MR(AR, DR?, embedding?). Mirrors `pt`'s cell 0.
    pub(crate) sr: Option<StateRoot>,
    /// Current Auth Root; `None` once no key remains (see `kr`).
    pub(crate) ar: Option<AuthRoot>,
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
    /// Latest timestamp of the chain (SPEC §14.1): its commits' cozies.
    pub(crate) latest_timestamp: i64,
    /// Maximum allowed future timestamp (seconds from verifier time).
    pub(crate) max_clock_skew: u64,
    /// Verifier time source for the future-timestamp bound.
    pub(crate) clock: Clock,
    /// Base64 thumbprint of the genesis key, the key the principal was
    /// constructed from.
    pub(crate) genesis_key: String,
    /// Whether the genesis key's own `key/create` has been applied. Every
    /// key enters through a `key/create`, the genesis key included (SPEC
    /// 5.1 step 1, 7.7 Example 1); the genesis key sits in the KT from
    /// construction so a principal that never commits (Levels 1 and 2)
    /// still has one, and this tells the two apart.
    pub(crate) genesis_created: bool,
    /// `principal/delete` has been signed (SPEC.md §11.1 `Deleted`). No
    /// transaction sets this yet — the field exists for the derivation in
    /// [`crate::lifecycle`] to read; it is always `false` at this node's tip.
    pub(crate) deleted: bool,
    /// `true` from the moment a `principal/delete` cozy is applied until
    /// the commit carrying it is successfully finalized (cleared when the
    /// commit is staged, on the projected state the commit adopts). Scopes
    /// the `CommitCreate` exemption from [no-transactions-on-deleted] to
    /// same-commit finalization only: a commit/create finalizing a delete
    /// applied earlier in this same, still-open commit is exempt; a
    /// commit/create in a later, separately-finalized commit against an
    /// already-deleted principal is not.
    pub(crate) deleted_pending: bool,
    /// `true` from an applied `principal/create` until the genesis commit
    /// carrying it is finalized. The PG is the state at the
    /// `principal/create`, so only the `commit/create` may follow it in
    /// that commit (SPEC 5.1 steps 3-4).
    pub(crate) genesis_pending: bool,
    /// `freeze/create` is active and `freeze/delete` has not yet been signed
    /// (SPEC.md §11.1 `Frozen`). No transaction sets this yet — see `deleted`.
    pub(crate) frozen: bool,
    /// A fork or invalid chain has been detected (SPEC.md §11.1 `Errored`).
    /// Orthogonal to the base lifecycle state. No detector sets this yet
    /// (fork/chain-invalid detection is out of scope for this node); always
    /// `false` at this node's tip.
    pub(crate) errored: bool,
    /// The KT digests the verifier revealed as embedded principals, with
    /// the tip each is judged against (SPEC §10.3). Verifier knowledge:
    /// never hashed into a root.
    pub(crate) embedded: crate::embedded::Members,
}

/// The state of a principal: everything but its commit log.
///
/// A [`CommitScope`](crate::commit::CommitScope) applies a commit's cozies
/// to a copy of this state (the projected state) and the commit adopts it
/// whole, so a refused commit leaves the principal as it was. Copying it
/// never copies or aliases the log, which only [`Principal`] holds.
///
/// All shared fields are reached via `Deref<Target = PrincipalCore>`.
///
/// # Nascent and Established
///
/// A principal is Nascent (Levels 1 and 2) until its `principal/create`
/// applies, then Established (Level 3+): `pg` is `None`, then frozen at
/// `Some`. `establish_pg` is the only writer and refuses a second call, so
/// a PG can be neither fabricated for a Nascent principal nor removed from
/// an Established one. This is a struct with an `Option`, not a two-variant
/// enum, because both states carry the same core and the transition runs
/// through `&mut self`: an enum would have to move the core out by value,
/// which needs a placeholder core or a `None` state to swap in.
#[derive(Debug, Clone)]
pub struct PrincipalState {
    core: PrincipalCore,
    pg: Option<PrincipalGenesis>,
}

impl PrincipalState {
    fn core_mut(&mut self) -> &mut PrincipalCore {
        &mut self.core
    }
}

impl std::ops::Deref for PrincipalState {
    type Target = PrincipalCore;

    fn deref(&self) -> &PrincipalCore {
        &self.core
    }
}

/// A Cyphr Principal (self-sovereign identity): its state and the commit
/// log it owns, generic over the storage backend `S` of that log (defaults
/// to [`eml::MemoryStorage`]).
///
/// The principal is the one writer of its log. Every read accessor is on
/// [`PrincipalState`], reached through `Deref`; mutation goes through the
/// principal's own methods, so state and log cannot be separated or swapped.
///
/// # Async and `Send`
///
/// Everything that reads or writes the log is `async`. The storage bound
/// `eml::Storage: Send + Sync` makes those futures `Send` whenever `S` is,
/// so a multi-threaded runtime can drive them. A [`crate::signer::Signer`]'s
/// `sign` future is deliberately not `Send`; the prepare, sign, finish
/// split keeps it out of every core future except the generic
/// conveniences that await it.
///
/// # No `Clone`
///
/// A principal is copied only by [`Self::fork`], where its storage copies
/// into an independent store ([`crate::commit_root::ForkStorage`]). Cloning
/// a handle to a shared durable store would make two writers of one log.
pub struct Principal<S: eml::Storage = eml::MemoryStorage> {
    state: PrincipalState,
    log: crate::commit_root::CommitTrees<S>,
}

impl<S: eml::Storage> std::fmt::Debug for Principal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("state", &self.state)
            .field("log", &self.log)
            .finish()
    }
}

impl<S: eml::Storage> std::ops::Deref for Principal<S> {
    type Target = PrincipalState;

    fn deref(&self) -> &PrincipalState {
        &self.state
    }
}

impl<S: crate::commit_root::ForkStorage> Principal<S> {
    /// An independent copy of this principal over a forked store: two
    /// principals from one ancestor can each commit without perturbing the
    /// other (SPEC 15.8: witnesses hold both branches of a fork).
    ///
    /// # Errors
    ///
    /// `Storage` if the store cannot be copied or the copy does not reopen.
    pub async fn fork(&self) -> Result<Self> {
        let log = self
            .log
            .fork()
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Self {
            state: self.state.clone(),
            log,
        })
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

/// Open the Commit Tree over a caller-supplied storage backend.
async fn open_commit_trees<S: eml::Storage>(
    storage: S,
) -> Result<crate::commit_root::CommitTrees<S>> {
    crate::commit_root::CommitTrees::open(storage)
        .await
        .map_err(|e| Error::Storage(e.to_string()))
}

impl PrincipalCore {
    /// Assemble a principal's state from its genesis key and starting
    /// roots. The caller has refused a revoked key, so the
    /// active set never holds one. Every construction ends here, so a
    /// field added to `PrincipalCore` or a change to how a fresh principal
    /// is filled is made once.
    fn new(key: Key, roots: StartingRoots) -> Self {
        let genesis_key = key.tmb().to_b64();
        let mut key_map = IndexMap::new();
        key_map.insert(genesis_key.clone(), key);
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
            kr: Some(kr),
            tr: None,
            pt,
            cr,
            sr: Some(sr),
            ar: Some(ar),
            dr: None,
            auth: AuthLedger {
                keys: key_map,
                ..Default::default()
            },
            data: DataLedger::default(),
            included_czds: HashSet::new(),
            nonces: NonceSets::default(),
            latest_timestamp: 0,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            clock: system_clock,
            genesis_key,
            genesis_created: false,
            deleted: false,
            deleted_pending: false,
            genesis_pending: false,
            frozen: false,
            errored: false,
            embedded: crate::embedded::Members::default(),
        }
    }

    /// Resolve `tmb` to the active key that may sign for this principal.
    ///
    /// The single signer lookup every verification path uses, so a key is
    /// classified the same way wherever it signs: an active key resolves,
    /// a revoked key (SPEC §6.4, never trusted again) is `KeyRevoked`, a
    /// key of an embedded principal in KT is judged by that principal's tip
    /// ([`crate::embedded`]), and anything else is `UnknownKey`.
    ///
    /// # Errors
    ///
    /// `KeyRevoked` or `UnknownKey` as above; `EmbeddedErrored` for a key
    /// of an embedded principal in `Error`.
    pub(crate) fn active_signer(&self, tmb: &Thumbprint) -> Result<&Key> {
        let tmb_b64 = tmb.to_b64();
        if let Some(key) = self.auth.keys.get(&tmb_b64) {
            return Ok(key);
        }
        if self.auth.revoked.contains_key(&tmb_b64) {
            return Err(Error::KeyRevoked);
        }
        self.embedded
            .signer(tmb, |d| self.nonces.holds(NonceLevel::Kt, d))
            .unwrap_or(Err(Error::UnknownKey))
    }

    /// The algorithm set the principal's roots hash under: that of its
    /// active keys. A principal with no key has none, so the set stays the
    /// one its PR was last hashed under (SPEC 3.7: the dying commit hashes
    /// under the set in force before it). Read mid-commit, `pr` is still
    /// the pre-commit PR, so the same rule gives the dying commit its set.
    /// The `pre` the arrow of the commit being formed binds (SPEC 4.2): the
    /// PR before it, except in the genesis commit, whose `pre` references
    /// the genesis key (SPEC 5.1 step 4): that key's own PR, its `tmb` by
    /// singleton promotion (3.1), whatever other keys the genesis commit
    /// creates.
    ///
    /// # Errors
    ///
    /// `UnknownKey` if the genesis key left the key set within the genesis
    /// commit; a root derivation error otherwise.
    pub(crate) fn arrow_pre(&self) -> Result<PrincipalRoot> {
        if !self.genesis_pending {
            return Ok(self.pr.clone());
        }
        let genesis = self
            .auth
            .keys
            .get(&self.genesis_key)
            .ok_or(Error::UnknownKey)?;
        let algs = self.active_algs();
        let (_, _, sr) = crate::semantic_tree::derive_state_roots(
            &[crate::semantic_tree::key_leaf(genesis)],
            None,
            &algs,
        )?;
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &algs)?;
        pt.pr(&algs)
    }

    /// The PR the principal would have if its genesis committed now: the
    /// Principal Tree over the current SR (keys, nonces, data) and the PR
    /// nonces, with no CR. This is the PG a `principal/create` establishes
    /// (SPEC 5.1 step 3: `id` is the future SR; 3.3: with no CR, SR is
    /// promoted to PR, which is PG).
    pub(crate) fn genesis_pr(&self) -> Result<PrincipalRoot> {
        let algs = self.active_algs();
        let leaves: Vec<_> = self
            .auth
            .keys
            .values()
            .map(crate::semantic_tree::key_leaf)
            .collect();
        let (_, _, sr) = crate::semantic_tree::derive_state_roots_with_nonces(
            &leaves,
            self.dr.as_ref(),
            &self.nonces,
            &algs,
        )?;
        let sr = sr.ok_or(Error::NoActiveKeys)?;
        let mut pt = PrincipalTree::new();
        pt.set_sr(&sr, &algs)?;
        pt.set_nonces(&self.nonces.at_level(NonceLevel::Pr), &algs)?;
        pt.pr(&algs)
    }

    pub(crate) fn active_algs(&self) -> Vec<HashAlg> {
        let key_refs: Vec<&crate::key::Key> = self.auth.keys.values().collect();
        let algs = crate::state::derive_hash_algs(&key_refs);
        if algs.is_empty() {
            return self.pr.0.algorithms().collect();
        }
        algs
    }

    /// Write a new State Root into cell 0 (or remove it, when the commit
    /// left none) and Commit Root into the next cell, and return the
    /// recomputed Principal Root. Used at commit finalization, the only
    /// place SR changes (a data action reaches SR only through a
    /// `ds/create`).
    fn write_pt_sr_cr(
        &mut self,
        sr: Option<&StateRoot>,
        cr: &crate::commit_root::CommitRoot,
        algs: &[HashAlg],
    ) -> Result<PrincipalRoot> {
        match sr {
            Some(sr) => self.pt.set_sr(sr, algs)?,
            None => self.pt.clear_sr(algs)?,
        }
        self.pt.set_cr(cr, algs)?;
        self.pt
            .set_nonces(&self.nonces.at_level(NonceLevel::Pr), algs)?;
        self.sr = sr.cloned();
        self.cr = Some(cr.clone());
        self.pt.pr(algs)
    }
}

impl<S: eml::Storage> Principal<S> {
    fn core_mut(&mut self) -> &mut PrincipalCore {
        self.state.core_mut()
    }

    /// The principal's state, without its log.
    pub(crate) fn state(&self) -> &PrincipalState {
        &self.state
    }

    /// The principal's state, mutable, for unit tests that drive the
    /// state's internal transitions directly.
    #[cfg(test)]
    pub(crate) fn state_mut(&mut self) -> &mut PrincipalState {
        &mut self.state
    }

    /// Make a staged commit durable and adopt its state: the second phase
    /// of [`crate::commit::StagedCommit::commit`]. The one log write comes
    /// first; the state is adopted in the same poll the write returns in,
    /// with no `.await` between, so a dropped future either wrote nothing
    /// or has adopted. A failed write leaves both unchanged.
    pub(crate) async fn adopt(
        &mut self,
        state: PrincipalState,
        staged: Option<polydigest::Staged<S>>,
    ) -> Result<&Commit> {
        if let Some(staged) = staged {
            self.log
                .commit(staged)
                .await
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        self.state = state;
        self.state.auth.commits.last().ok_or(Error::EmptyCommit)
    }
}
