//! Offline verification of evidence: proof, checkable by anyone from
//! signatures and the chain alone, that a principal forked.
//!
//! Nothing here asks to be believed. A served item names claims; this
//! module replays or re-verifies every one of them from keys the caller's
//! own replayed chain holds, so a serving peer can neither fabricate
//! evidence nor erase it (`arch-evidence-is-portable`).
//!
//! # Items
//!
//! Each item is self-describing, with a `kind` and the principal's `pg`.
//! The one kind is `principal-fork`: `{pg, height, pre, a, b}` where `a`
//! and `b` are commit bundles (SPEC 4.6.2), two distinct commits that both
//! verify against the principal's state at `pre`, the Principal Root after
//! commit `height - 1` (`null` at height 0). Checked by
//! [`verify_principal_fork`], which replays the commits from that state; no
//! server signature takes part, so it convicts no server
//! (`arch-principal-fork-evidence`).
//!
//! # Replay copy
//!
//! [`replay_chain`] replays commits onto a principal the way `peer.rs`
//! and `cyphr-storage` do; the core has no public replay entry point, so
//! this is a third copy of that rule. HA1 replaces all three with one core
//! function.

use std::collections::BTreeMap;

use cyphr::eml::MemoryStorage;
use cyphr::replay::WireBundle;
use cyphr::{Commit, Principal};
use serde::Deserialize as _;
use serde_json::Value;

use crate::patch::{ActionBundle, PatchEntry, Step, replay_order};

/// The most coz blobs one served commit may carry; a bound on what an
/// untrusted item can make the verifier decode.
const MAX_COMMIT_BLOBS: usize = 1024;

/// Why an item is not evidence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvidenceFailure {
    /// The item is not the shape evidence has.
    #[error("malformed evidence item: {0}")]
    Malformed(&'static str),
    /// The item is about another principal.
    #[error("the item is about another principal")]
    OtherPrincipal,
    /// The chain the caller holds is shorter than the item's height.
    #[error("the held chain has {have} commits but the item forks at {need}")]
    ChainTooShort {
        /// Commits the item needs.
        need: u64,
        /// Commits held.
        have: usize,
    },
    /// A commit of the held chain fails replay.
    #[error("held commit {commit} fails replay: {source}")]
    Replay {
        /// The commit's position.
        commit: usize,
        /// The core's refusal.
        source: cyphr::Error,
    },
    /// A held or served commit is not the shape a coz commit has.
    #[error("commit {commit} is malformed: {what}")]
    BadCommit {
        /// The commit's position (the item's height for a rival).
        commit: usize,
        /// What is wrong with it.
        what: &'static str,
    },
    /// The genesis the caller supplied does not derive the principal the
    /// item is about, so replaying from it proves nothing about that
    /// principal.
    #[error("the supplied genesis does not derive the principal")]
    GenesisMismatch,
    /// The held chain's root at the item's height is not the item's `pre`.
    #[error("the held chain's root at the fork is not the item's pre")]
    PreMismatch,
    /// A served commit does not verify from the state at `pre`.
    #[error("commit {which} does not verify at pre: {source}")]
    CommitRefused {
        /// `a` or `b`.
        which: &'static str,
        /// The core's refusal.
        source: cyphr::Error,
    },
    /// The two commits do not conflict.
    #[error("the two do not conflict: {0}")]
    NotConflicting(&'static str),
}

/// A parsed evidence item, not yet verified.
#[derive(Debug, Clone)]
pub enum EvidenceItem {
    /// Two commits at one position of one principal.
    PrincipalFork {
        /// The principal's bare genesis identifier.
        pg: String,
        /// The position both commits take.
        height: u64,
        /// The Principal Root both extend; `None` at height 0.
        pre: Option<String>,
        /// The first commit's bundle.
        a: WireBundle,
        /// The second commit's bundle.
        b: WireBundle,
    },
}

impl EvidenceItem {
    /// Parse a served item. Never panics on any input (fuzzed:
    /// `fuzz_evidence`).
    ///
    /// # Errors
    ///
    /// [`EvidenceFailure::Malformed`] for anything that is not an item.
    pub fn parse(item: &Value) -> Result<Self, EvidenceFailure> {
        let text = |field: &str, what: &'static str| {
            item.get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(EvidenceFailure::Malformed(what))
        };
        let pg = text("pg", "no pg")?;
        match item.get("kind").and_then(Value::as_str) {
            Some("principal-fork") => {
                let height = item
                    .get("height")
                    .and_then(Value::as_u64)
                    .ok_or(EvidenceFailure::Malformed("height is not an integer"))?;
                let pre = match item.get("pre") {
                    Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    _ => return Err(EvidenceFailure::Malformed("pre is neither string nor null")),
                };
                if pre.is_none() != (height == 0) {
                    return Err(EvidenceFailure::Malformed(
                        "pre is null exactly at height 0",
                    ));
                }
                Ok(Self::PrincipalFork {
                    pg,
                    height,
                    pre,
                    a: commit_blobs(item.get("a"))?,
                    b: commit_blobs(item.get("b"))?,
                })
            },
            _ => Err(EvidenceFailure::Malformed("unknown kind")),
        }
    }
}

fn commit_blobs(commit: Option<&Value>) -> Result<WireBundle, EvidenceFailure> {
    let commit = commit
        .filter(|c| c.get("txs").is_some_and(Value::is_array))
        .ok_or(EvidenceFailure::Malformed("commit has no txs array"))?;
    let bundle = WireBundle::deserialize(commit)
        .map_err(|_| EvidenceFailure::Malformed("commit is not a bundle of base64url cozies"))?;
    let count = bundle.cozies().count();
    if count == 0 || count > MAX_COMMIT_BLOBS {
        return Err(EvidenceFailure::Malformed("commit blob count out of range"));
    }
    Ok(bundle)
}

/// What a verified principal fork proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProof {
    /// The principal's bare genesis identifier, as the item named it.
    pub pg: String,
    /// The position both commits take.
    pub height: u64,
    /// The Principal Root both extend; `None` at height 0.
    pub pre: Option<String>,
    /// The ids of the two commits, in the order the item named them.
    pub commits: [String; 2],
}

/// Replay `entries` onto `base` (a principal at its genesis state) and
/// return the result. The core verifies every signature, arrow and state
/// transition; nothing the entries say is trusted beyond that.
///
/// # Errors
///
/// [`EvidenceFailure::BadCommit`] or [`EvidenceFailure::Replay`] naming
/// the first commit that fails.
pub async fn replay_chain(
    base: Principal<MemoryStorage>,
    entries: &[PatchEntry],
) -> Result<Principal<MemoryStorage>, EvidenceFailure> {
    replay_chain_with_actions(base, entries, &[]).await
}

/// [`replay_chain`] with the action-only bundles a patch serves beside its
/// commits, replayed in the order they were accepted: a data commit needs
/// the actions before it.
///
/// # Errors
///
/// As [`replay_chain`]; an undecodable action bundle is a
/// [`EvidenceFailure::BadCommit`] at the commit it precedes.
pub async fn replay_chain_with_actions(
    mut base: Principal<MemoryStorage>,
    entries: &[PatchEntry],
    actions: &[ActionBundle],
) -> Result<Principal<MemoryStorage>, EvidenceFailure> {
    for step in replay_order(0, entries, actions) {
        match step {
            Step::Commit(index, entry) => {
                let bundle = entry
                    .bundle
                    .as_ref()
                    .map_err(|_| EvidenceFailure::BadCommit {
                        commit: index,
                        what: "entry is undecodable",
                    })?;
                replay_commit(&mut base, index, bundle).await?;
            },
            Step::Actions(bundle) => {
                let blobs = bundle
                    .blobs
                    .as_ref()
                    .map_err(|_| EvidenceFailure::BadCommit {
                        commit: usize::try_from(bundle.after).unwrap_or(usize::MAX),
                        what: "action bundle is undecodable",
                    })?;
                let at = usize::try_from(bundle.after).unwrap_or(usize::MAX);
                replay_commit(&mut base, at, &WireBundle::actions(blobs.clone())).await?;
            },
        }
    }
    Ok(base)
}

/// Verify a `principal-fork` item against the chain the caller holds.
///
/// `pg` is the principal asked about (bare); `base` is that principal at
/// its genesis state and `entries` its commits as fetched (any peer's
/// `/patch`; they are replayed, not trusted). The check:
///
/// 1. the item names `pg`, and `base` derives it: its own PR names `pg` (a principal named by its
///    genesis key), or the genesis commit opens with `base`'s genesis key and, replayed from
///    `base`, establishes a PG naming `pg` (SPEC 5.1). At `height` 0 the genesis commits are the
///    two served rivals, and each must establish a PG naming `pg`;
/// 2. replaying the first `height` held commits reaches the item's `pre`;
/// 3. each of the two served commits, replayed from a copy of that state, verifies, so each is
///    signed by a key active at `pre`;
/// 4. they are different commits.
///
/// # Errors
///
/// An [`EvidenceFailure`] naming the first check that refused.
pub async fn verify_principal_fork(
    item: &Value,
    pg: &str,
    base: Principal<MemoryStorage>,
    entries: &[PatchEntry],
) -> Result<ForkProof, EvidenceFailure> {
    verify_principal_fork_with_actions(item, pg, base, entries, &[]).await
}

/// A commit proved to extend a rival branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Its position.
    pub height: u64,
    /// Its bundle.
    pub bundle: WireBundle,
    /// Its commit id.
    pub id: String,
    /// The id of the commit it extends: a fork's rival, or an extension.
    pub parent: String,
}

/// What a holder's chain proves of a set of served `principal-fork` items.
#[derive(Debug, Default)]
pub struct ItemSet {
    /// Each fork at a position of the chain, with its rival's bundle (the
    /// item's commit that is not the chain's).
    pub forks: Vec<(ForkProof, WireBundle)>,
    /// Each commit that extends a rival branch, in position order.
    pub extensions: Vec<Extension>,
    /// Why each other item was refused.
    pub rejected: Vec<EvidenceFailure>,
}

/// Verify a peer's `principal-fork` items against a holder's chain
/// (`entries` replayed from `base`, with its action bundles `actions`;
/// `chain_ids` the chain's commit ids by position).
///
/// An item whose `pre` is on the chain is a fork
/// ([`verify_principal_fork_with_actions`]). One whose `pre` is off it is
/// tried as a commit extending a rival branch: each proved rival's state is
/// replayed once, items are taken in position order and matched by
/// (position below, `pre`) to the one branch tip they can extend, and the
/// item's commit that applies there becomes that branch's next tip. Each
/// item is verified at most once, from its parent's state, so the result
/// is the same for any order or repetition of the items, and an item whose
/// parent is not proved (a broken link, a `pre` from later in a branch) is
/// refused.
pub async fn verify_fork_items(
    items: &[&Value],
    pg: &str,
    base: &Principal<MemoryStorage>,
    entries: &[PatchEntry],
    actions: &[ActionBundle],
    chain_ids: &[Option<String>],
) -> ItemSet {
    let mut set = ItemSet::default();
    let fork_of = async |p: &Principal<MemoryStorage>, at: usize| {
        p.fork()
            .await
            .map_err(|source| EvidenceFailure::Replay { commit: at, source })
    };
    let mut off_chain = Vec::new();
    for item in items {
        let verified = async {
            let proof = verify_principal_fork_with_actions(
                item,
                pg,
                fork_of(base, 0).await?,
                entries,
                actions,
            )
            .await?;
            let EvidenceItem::PrincipalFork { a, b, .. } = EvidenceItem::parse(item)?;
            let height = usize::try_from(proof.height).unwrap_or(usize::MAX);
            let mine = chain_ids.get(height).cloned().flatten();
            let rival = if mine.as_ref() == Some(&proof.commits[1]) {
                a
            } else {
                b
            };
            Ok::<_, EvidenceFailure>((proof, rival))
        }
        .await;
        match verified {
            Ok(fork) => {
                if !set.forks.iter().any(|(p, _)| p == &fork.0) {
                    set.forks.push(fork);
                }
            },
            Err(EvidenceFailure::PreMismatch) => off_chain.push(*item),
            Err(failure) => set.rejected.push(failure),
        }
    }

    // Each branch tip, by (position, PR): its state and commit id.
    let mut tips: BTreeMap<(usize, String), (Principal<MemoryStorage>, String)> = BTreeMap::new();
    for (proof, rival) in &set.forks {
        let height = usize::try_from(proof.height).unwrap_or(usize::MAX);
        let Some(prefix) = entries.get(..height) else {
            continue;
        };
        let mut line = prefix.to_vec();
        line.push(PatchEntry {
            sequence: proof.height,
            bundle: Ok(rival.clone()),
        });
        let below: Vec<ActionBundle> = actions
            .iter()
            .filter(|a| a.after < proof.height)
            .cloned()
            .collect();
        let Ok(base) = fork_of(base, 0).await else {
            continue;
        };
        let Ok(state) = replay_chain_with_actions(base, &line, &below).await else {
            continue;
        };
        let (Ok(pr), Some(id)) = (state.pr_tagged(), rival_id(proof, chain_ids)) else {
            continue;
        };
        tips.insert((height, pr), (state, id));
    }

    let mut pending: Vec<(usize, Option<String>, &Value)> = Vec::new();
    for item in off_chain {
        match EvidenceItem::parse(item) {
            Ok(EvidenceItem::PrincipalFork { pg: named, .. }) if named != pg => {
                set.rejected.push(EvidenceFailure::OtherPrincipal);
            },
            Ok(EvidenceItem::PrincipalFork { height, pre, .. }) => {
                pending.push((usize::try_from(height).unwrap_or(usize::MAX), pre, item));
            },
            Err(failure) => set.rejected.push(failure),
        }
    }
    pending.sort_by_key(|(height, ..)| *height);
    for (height, pre, item) in pending {
        let parent = pre.and_then(|pre| {
            let below = height.checked_sub(1)?;
            tips.get(&(below, pre))
        });
        let Some((state, parent)) = parent else {
            set.rejected.push(EvidenceFailure::PreMismatch);
            continue;
        };
        match extend(item, state, height).await {
            Ok((bundle, id, next)) => {
                if !set.extensions.iter().any(|e| e.id == id) {
                    set.extensions.push(Extension {
                        height: height as u64,
                        bundle,
                        id: id.clone(),
                        parent: parent.clone(),
                    });
                }
                if let Ok(pr) = next.pr_tagged() {
                    tips.insert((height, pr), (next, id));
                }
            },
            Err(failure) => set.rejected.push(failure),
        }
    }
    set
}

/// The id of a proved fork's rival: its commit that is not the chain's.
fn rival_id(proof: &ForkProof, chain_ids: &[Option<String>]) -> Option<String> {
    let height = usize::try_from(proof.height).ok()?;
    let mine = chain_ids.get(height).cloned().flatten();
    proof
        .commits
        .iter()
        .find(|c| Some(*c) != mine.as_ref())
        .cloned()
}

/// The item's commit that applies on `state` (the branch tip below it), its
/// id, and the state after it.
async fn extend(
    item: &Value,
    state: &Principal<MemoryStorage>,
    height: usize,
) -> Result<(WireBundle, String, Principal<MemoryStorage>), EvidenceFailure> {
    let EvidenceItem::PrincipalFork { a, b, .. } = EvidenceItem::parse(item)?;
    for blobs in [b, a] {
        let mut copy = state
            .fork()
            .await
            .map_err(|source| EvidenceFailure::Replay {
                commit: height,
                source,
            })?;
        if replay_commit(&mut copy, height, &blobs).await.is_err() {
            continue;
        }
        let id = copy
            .commits()
            .last()
            .map(|c| c.tr().0.tagged_first().map(|d| d.to_string()))
            .transpose()
            .map_err(|source| EvidenceFailure::Replay {
                commit: height,
                source,
            })?
            .ok_or(EvidenceFailure::BadCommit {
                commit: height,
                what: "no commit formed",
            })?;
        return Ok((blobs, id, copy));
    }
    Err(EvidenceFailure::BadCommit {
        commit: height,
        what: "neither commit extends the rival branch",
    })
}

/// [`verify_principal_fork`] for a principal whose history carries data
/// actions: `actions` are the patch's action-only bundles, replayed with
/// the commits (those accepted up to the fork's position precede it).
///
/// # Errors
///
/// As [`verify_principal_fork`].
pub async fn verify_principal_fork_with_actions(
    item: &Value,
    pg: &str,
    base: Principal<MemoryStorage>,
    entries: &[PatchEntry],
    actions: &[ActionBundle],
) -> Result<ForkProof, EvidenceFailure> {
    let EvidenceItem::PrincipalFork {
        pg: item_pg,
        height,
        pre,
        a,
        b,
    } = EvidenceItem::parse(item)?;
    if item_pg != pg {
        return Err(EvidenceFailure::OtherPrincipal);
    }
    let prefix = usize::try_from(height)
        .ok()
        .and_then(|h| entries.get(..h))
        .ok_or(EvidenceFailure::ChainTooShort {
            need: height,
            have: entries.len(),
        })?;
    // The replay is only evidence about `pg` if it starts from the genesis
    // `pg` names. A principal is its genesis key (SPEC 5.1): one that names
    // itself by that key's PR derives `pg` from `base` alone; one named by
    // its PG derives it through its genesis commit, which must open with
    // `base`'s genesis key (a foreign genesis is refused here, not as a
    // replay failure) and establish that PG.
    let named_by_key = base.pr_tagged().is_ok_and(|g| names_pg(pg, &g));
    let genesis_commit = match prefix.first() {
        Some(first) => Some(
            first
                .bundle
                .as_ref()
                .map_err(|_| EvidenceFailure::BadCommit {
                    commit: 0,
                    what: "undecodable blobs",
                })?,
        ),
        None => None,
    };
    if !named_by_key {
        let opened = match genesis_commit {
            Some(blobs) => opens_with(blobs, base.genesis_key()),
            None => opens_with(&a, base.genesis_key()) && opens_with(&b, base.genesis_key()),
        };
        if !opened {
            return Err(EvidenceFailure::GenesisMismatch);
        }
    }
    // The state at `pre` holds the actions accepted before the fork's
    // position only. Those accepted AT it (`after == height`) lead the
    // commit of whichever branch the patch's holder kept: they are no
    // part of the other branch's `pre`, which brings its own actions
    // inline (SPEC 4.8.2), so each branch is tried with and without them.
    let before_fork: Vec<ActionBundle> = actions
        .iter()
        .filter(|a| a.after < height)
        .cloned()
        .collect();
    let leading: Vec<WireBundle> = actions
        .iter()
        .filter(|a| a.after == height)
        .filter_map(|a| a.blobs.as_ref().ok())
        .map(|blobs| WireBundle::actions(blobs.clone()))
        .collect();
    let state = replay_chain_with_actions(base, prefix, &before_fork).await?;
    if genesis_commit.is_some() && !named_by_key && !pg_names(&state, pg) {
        return Err(EvidenceFailure::GenesisMismatch);
    }
    if pre.is_some() && state.pr_tagged().ok() != pre {
        return Err(EvidenceFailure::PreMismatch);
    }
    if a == b {
        return Err(EvidenceFailure::NotConflicting(
            "the two commits are identical",
        ));
    }
    let at = prefix.len();
    let branch = async |which,
                        blobs: &WireBundle|
           -> Result<(Principal<MemoryStorage>, Commit), EvidenceFailure> {
        let mut tried = None;
        // A branch that carries its own actions is replayed from `pre`
        // alone; one that carries none may lean on the leading actions.
        let with_leading = blobs.actions.is_empty() && !leading.is_empty();
        for lead in [with_leading, false] {
            let mut copy = state
                .fork()
                .await
                .map_err(|source| EvidenceFailure::Replay { commit: at, source })?;
            if lead {
                for held in &leading {
                    replay_commit(&mut copy, at, held).await?;
                }
            }
            match replay_commit(&mut copy, at, blobs).await {
                Ok(()) => {
                    tried = Some(Ok(copy));
                    break;
                },
                Err(e) => tried = Some(Err(e)),
            }
        }
        let copy = match tried {
            Some(Ok(copy)) => copy,
            Some(Err(EvidenceFailure::Replay { source, .. })) => {
                return Err(EvidenceFailure::CommitRefused { which, source });
            },
            Some(Err(other)) => return Err(other),
            None => {
                return Err(EvidenceFailure::BadCommit {
                    commit: at,
                    what: "no commit formed",
                });
            },
        };
        let commit = copy
            .commits()
            .last()
            .cloned()
            .ok_or(EvidenceFailure::BadCommit {
                commit: at,
                what: "no commit formed",
            })?;
        Ok((copy, commit))
    };
    let (ca, cb) = (branch("a", &a).await?, branch("b", &b).await?);
    if prefix.is_empty() && !(pg_names(&ca.0, pg) && pg_names(&cb.0, pg)) {
        return Err(EvidenceFailure::GenesisMismatch);
    }
    let (ca, cb) = (ca.1, cb.1);
    if ca.tr() == cb.tr() {
        return Err(EvidenceFailure::NotConflicting(
            "the two commits have one id",
        ));
    }
    let id = |c: &Commit| {
        c.tr()
            .0
            .tagged_first()
            .map(|d| d.to_string())
            .map_err(|source| EvidenceFailure::Replay { commit: at, source })
    };
    Ok(ForkProof {
        pg: item_pg,
        height,
        pre,
        commits: [id(&ca)?, id(&cb)?],
    })
}

/// Whether `g`, a tagged or bare root, names `pg` (bare).
pub(crate) fn names_pg(pg: &str, g: &str) -> bool {
    g == pg || g.split_once(':').is_some_and(|(_, bare)| bare == pg)
}

/// Whether `principal` has a PG naming `pg` in any of its algorithms.
pub(crate) fn pg_names(principal: &Principal<MemoryStorage>, pg: &str) -> bool {
    use cyphr::StateDigest as _;
    principal.pg().is_some_and(|g| {
        let digest = g.as_multihash();
        digest
            .algorithms()
            .filter_map(|alg| digest.tagged(alg).ok())
            .any(|t| names_pg(pg, &t.to_string()))
    })
}

/// Whether the commit `bundle` opens with a coz signed by `genesis_key` (a
/// genesis commit opens with its genesis key's own `key/create`, SPEC 5.1).
fn opens_with(bundle: &WireBundle, genesis_key: &str) -> bool {
    bundle
        .cozies()
        .next()
        .and_then(|blob| serde_json::from_slice::<Value>(blob).ok())
        .is_some_and(|coz| coz.pointer("/pay/tmb").and_then(Value::as_str) == Some(genesis_key))
}

/// Replay one entry's bundle onto `principal` through the core's one
/// replay entry point, as [`PeerChain`](crate::PeerChain) does.
async fn replay_commit(
    principal: &mut Principal<MemoryStorage>,
    commit: usize,
    bundle: &WireBundle,
) -> Result<(), EvidenceFailure> {
    crate::peer::replay_entry(principal, bundle)
        .await
        .map(|_| ())
        .map_err(|refusal| match refusal {
            crate::peer::EntryRefusal::Malformed(what) => {
                EvidenceFailure::BadCommit { commit, what }
            },
            crate::peer::EntryRefusal::Replay(source) => EvidenceFailure::Replay { commit, source },
        })
}
