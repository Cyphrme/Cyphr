//! Offline verification of evidence: proof, checkable by anyone from
//! signatures and the chain alone, that a principal forked or that a peer
//! equivocated.
//!
//! Nothing here asks to be believed. A served item names claims; this
//! module replays or re-verifies every one of them from keys the caller's
//! own replayed chain holds, so a serving peer can neither fabricate
//! evidence nor erase it (`arch-evidence-is-portable`). Evidence is only
//! ever added: a verdict never depends on later statements
//! (`arch-finding-never-clears`).
//!
//! # Items
//!
//! Each item is self-describing, with a `kind` and the principal's `pg`:
//!
//! - `principal-fork`: `{pg, height, pre, a, b}` where `a` and `b` are `{blobs: [base64url coz]}`,
//!   two distinct commits that both verify against the principal's state at `pre`, the Principal
//!   Root after commit `height - 1` (`null` at height 0). Checked by [`verify_principal_fork`],
//!   which replays the commits from that state; no server signature takes part, so it convicts no
//!   server (`arch-principal-fork-evidence`).
//! - `peer-equivocation`: `{pg, peer, a, b}` where `a` and `b` are signed statements (`{pay, sig}`:
//!   view statements or tip reports) about `pg`. Checked by [`verify_peer_equivocation`] against
//!   the peer's own chain.
//!
//! # Replay copy
//!
//! [`replay_chain`] replays commits onto a principal the way `peer.rs`
//! and `cyphr-storage` do; the core has no public replay entry point, so
//! this is a third copy of that rule. HA1 replaces all three with one core
//! function.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::eml::{MemoryStorage, Storage};
use cyphr::state::TaggedDigest;
use cyphr::{Commit, Key, Principal};
use serde::Deserialize as _;
use serde_json::Value;

use crate::patch::PatchEntry;
use crate::report::{TipReport, VIEW_STATEMENT_TYP, ViewStatement};

/// The `typ` a signed tip report carries (`cyphr-server/receipt/tip`).
const TIP_REPORT_TYP: &str = "cyphr-server/receipt/tip";

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
    /// The item is of a kind this check does not handle.
    #[error("not a {expected} item")]
    WrongKind {
        /// The kind the check handles.
        expected: &'static str,
    },
    /// The item (or a statement in it) is about another principal.
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
    /// The two statements or commits do not conflict.
    #[error("the two do not conflict: {0}")]
    NotConflicting(&'static str),
    /// A statement is not signed by a key the peer's chain held and had
    /// not revoked at the statement's own time.
    #[error("statement {which}: {why}")]
    Statement {
        /// `a` or `b`.
        which: &'static str,
        /// Why it was refused.
        why: &'static str,
    },
    /// The statements sit at different positions and no chain was held
    /// that backs the higher one, so the lower cannot be compared.
    #[error("a chain backing the higher statement is needed to compare different positions")]
    NeedsChain,
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
        /// The first commit's coz blobs.
        a: Vec<Vec<u8>>,
        /// The second commit's coz blobs.
        b: Vec<Vec<u8>>,
    },
    /// Two statements of one peer about one principal.
    PeerEquivocation {
        /// The principal's bare genesis identifier.
        pg: String,
        /// The accused peer, as the item names it.
        peer: String,
        /// The first statement.
        a: coz::CozJson,
        /// The second statement.
        b: coz::CozJson,
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
            Some("peer-equivocation") => {
                let statement = |field: &str| {
                    item.get(field)
                        .and_then(|v| coz::CozJson::deserialize(v).ok())
                        .ok_or(EvidenceFailure::Malformed("statement is not a signed coz"))
                };
                Ok(Self::PeerEquivocation {
                    pg,
                    peer: text("peer", "no peer")?,
                    a: statement("a")?,
                    b: statement("b")?,
                })
            },
            _ => Err(EvidenceFailure::Malformed("unknown kind")),
        }
    }
}

fn commit_blobs(commit: Option<&Value>) -> Result<Vec<Vec<u8>>, EvidenceFailure> {
    let blobs = commit
        .and_then(|c| c.get("blobs"))
        .and_then(Value::as_array)
        .ok_or(EvidenceFailure::Malformed("commit has no blobs array"))?;
    if blobs.is_empty() || blobs.len() > MAX_COMMIT_BLOBS {
        return Err(EvidenceFailure::Malformed("commit blob count out of range"));
    }
    blobs
        .iter()
        .map(|b| {
            b.as_str()
                .and_then(|s| Base64UrlUnpadded::decode_vec(s).ok())
                .ok_or(EvidenceFailure::Malformed("blob is not base64url"))
        })
        .collect()
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
}

/// What a verified peer equivocation proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    /// The principal both statements are about.
    pub pg: coz::Thumbprint,
    /// The keys that signed the two statements (equal for a single key).
    pub signers: [coz::Thumbprint; 2],
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
    mut base: Principal<MemoryStorage>,
    entries: &[PatchEntry],
) -> Result<Principal<MemoryStorage>, EvidenceFailure> {
    for (index, entry) in entries.iter().enumerate() {
        let blobs = entry
            .blobs
            .as_ref()
            .map_err(|_| EvidenceFailure::BadCommit {
                commit: index,
                what: "entry is undecodable",
            })?;
        replay_commit(&mut base, index, blobs).await?;
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
    let EvidenceItem::PrincipalFork {
        pg: item_pg,
        height,
        pre,
        a,
        b,
    } = EvidenceItem::parse(item)?
    else {
        return Err(EvidenceFailure::WrongKind {
            expected: "principal-fork",
        });
    };
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
                .blobs
                .as_deref()
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
    let state = replay_chain(base, prefix).await?;
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
                        blobs: &[Vec<u8>]|
           -> Result<(Principal<MemoryStorage>, Commit), EvidenceFailure> {
        let mut copy = state
            .fork()
            .await
            .map_err(|source| EvidenceFailure::Replay { commit: at, source })?;
        replay_commit(&mut copy, at, blobs)
            .await
            .map_err(|e| match e {
                EvidenceFailure::Replay { source, .. } => {
                    EvidenceFailure::CommitRefused { which, source }
                },
                other => other,
            })?;
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
    Ok(ForkProof {
        pg: item_pg,
        height,
        pre,
    })
}

/// A statement's claim about a principal, common to the two statement
/// kinds a peer signs.
struct Claim {
    pr: coz::Thumbprint,
    /// Commits the statement says the peer holds.
    size: u64,
    commit_id: TaggedDigest,
    root_pr: TaggedDigest,
    /// Statement time, signed.
    now: i64,
}

fn claim(coz: &coz::CozJson, which: &'static str) -> Result<Claim, EvidenceFailure> {
    let bad = |why| EvidenceFailure::Statement { which, why };
    match coz.pay["typ"].as_str() {
        Some(VIEW_STATEMENT_TYP) => {
            let v = ViewStatement::parse(coz).map_err(|_| bad("view statement is malformed"))?;
            Ok(Claim {
                pr: v.pr,
                size: v.tree_size,
                commit_id: v.commit_id,
                root_pr: v.roots.pr,
                now: v.now,
            })
        },
        Some(TIP_REPORT_TYP) => {
            let t = TipReport::parse(coz).map_err(|_| bad("tip report is malformed"))?;
            let now = coz.pay["now"]
                .as_i64()
                .ok_or(bad("tip report has no now"))?;
            Ok(Claim {
                pr: t.pr,
                size: t.sequence.checked_add(1).ok_or(bad("sequence overflows"))?,
                commit_id: t.commit_id,
                root_pr: t.roots.pr,
                now,
            })
        },
        _ => Err(bad("not a view statement or tip report")),
    }
}

/// The keys a peer principal has held and when, rebuilt from its chain.
///
/// The chain's live key set only knows keys still present; a rotation
/// removes the old key outright. Evidence outlives rotation, so this
/// keeps every key the chain ever introduced, each with the signed times
/// that bound its life: it starts at the `now` of the coz that introduced
/// it (genesis keys, at the beginning) and ends, exclusive, at the
/// earliest of its self-revocation `rvk`, the `now` of the coz that
/// deleted it, or the `now` of the replace in which it was the signer
/// (SPEC 6.4: `now >= rvk` is not active).
#[derive(Debug, Clone)]
pub struct KeyHistory {
    keys: Vec<HeldKey>,
}

#[derive(Debug, Clone)]
struct HeldKey {
    key: Key,
    from: i64,
    until: Option<i64>,
}

impl KeyHistory {
    /// The history of `chain`, a peer principal replayed from `genesis`.
    #[must_use]
    pub fn of<S: Storage>(genesis: &[Key], chain: &Principal<S>) -> Self {
        let mut keys: Vec<HeldKey> = genesis
            .iter()
            .map(|key| HeldKey {
                key: key.clone(),
                from: i64::MIN,
                until: None,
            })
            .collect();
        // One pass in chain order: an end closes only the interval of that
        // key open at that point, so a key deleted and added again keeps
        // its later interval.
        let end = |keys: &mut Vec<HeldKey>, tmb: &coz::Thumbprint, at: i64| {
            if let Some(held) = keys
                .iter_mut()
                .rev()
                .find(|h| h.key.tmb() == tmb && h.until.is_none())
            {
                held.until = Some(at);
            }
        };
        for vc in chain.iter_all_cozies() {
            let cz = vc.coz();
            match cz.kind() {
                cyphr::CozKind::KeyDelete { id } => end(&mut keys, id, cz.now()),
                cyphr::CozKind::KeyReplace { .. } => end(&mut keys, cz.signer(), cz.now()),
                cyphr::CozKind::SelfRevoke { rvk } => end(&mut keys, cz.signer(), *rvk),
                _ => {},
            }
            // A genesis key's own `key/create` (SPEC 5.2 TX0) discloses a
            // key already held from the beginning: its interval is open.
            if let Some(key) = vc.new_key().filter(|k| {
                !keys
                    .iter()
                    .any(|h| h.key.tmb() == k.tmb() && h.until.is_none())
            }) {
                keys.push(HeldKey {
                    key: key.clone(),
                    from: cz.now(),
                    until: None,
                });
            }
        }
        Self { keys }
    }

    /// The key `tmb` as it stood at `now`, if the chain held it then.
    fn at(&self, tmb: &coz::Thumbprint, now: i64) -> Option<&Key> {
        self.keys
            .iter()
            .find(|h| h.key.tmb() == tmb && h.from <= now && h.until.is_none_or(|u| now < u))
            .map(|h| &h.key)
    }

    /// Whether the chain ever held `tmb`.
    fn ever(&self, tmb: &coz::Thumbprint) -> bool {
        self.keys.iter().any(|h| h.key.tmb() == tmb)
    }
}

/// The key that signed `coz`, if the peer held it at the statement's own
/// signed time and the signature verifies.
///
/// This is the HISTORICAL form: a key the chain has since revoked or
/// rotated out still vouches for statements signed before that, so a later
/// revocation cannot erase evidence. [`crate::verify_view`] is the
/// current-view form and refuses such a key; it is unchanged.
fn signer_then(
    coz: &coz::CozJson,
    peer: &KeyHistory,
    now: i64,
    which: &'static str,
) -> Result<coz::Thumbprint, EvidenceFailure> {
    let bad = |why| EvidenceFailure::Statement { which, why };
    let tmb = coz.pay["tmb"]
        .as_str()
        .and_then(|t| Base64UrlUnpadded::decode_vec(t).ok())
        .map(coz::Thumbprint::from_bytes)
        .ok_or(bad("names no signing key"))?;
    if !peer.ever(&tmb) {
        return Err(bad("signed by a key the peer chain never held"));
    }
    let key = peer
        .at(&tmb, now)
        .ok_or(bad("signed when the peer did not hold the key"))?;
    let pay_json = serde_json::to_vec(&coz.pay).map_err(|_| bad("pay does not serialize"))?;
    if coz.pay["alg"].as_str() != Some(key.alg())
        || coz::verify_json(&pay_json, &coz.sig, key.alg(), key.pub_key()) != Some(true)
    {
        return Err(bad("signature does not verify"));
    }
    Ok(tmb)
}

/// Whether `commit` is the commit `id` names.
fn commit_is(commit: &Commit, id: &TaggedDigest) -> bool {
    commit.tr().0.get(id.alg()) == Some(id.as_bytes())
}

/// Verify a `peer-equivocation` item: two statements of one peer about
/// principal `pr` that are not prefix-consistent.
///
/// - Both statements verify under keys of the peer's own chain ([`KeyHistory`]), each judged at its
///   own signed time; the item's word about who signed is never consulted.
/// - Both are about `pr`.
/// - At one position they conflict when they differ in commit id or roots. At different positions
///   `m < n` the lower is compared with the higher's own chain: `higher_chain` must be a replay of
///   a chain whose commit `n - 1` is the higher statement's `commit_id`; if its commit `m - 1` is
///   the lower's `commit_id` the lower is merely behind (a prefix, never evidence), otherwise the
///   two forked at or before `m` (`arch-behind-is-not-fork`).
///
/// # Errors
///
/// An [`EvidenceFailure`]; [`EvidenceFailure::NotConflicting`] means the
/// statements are consistent, which settles nothing against the peer.
pub fn verify_peer_equivocation<H: Storage>(
    item: &Value,
    pr: &coz::Thumbprint,
    peer: &KeyHistory,
    higher_chain: Option<&Principal<H>>,
) -> Result<EquivocationProof, EvidenceFailure> {
    let EvidenceItem::PeerEquivocation { pg, a, b, .. } = EvidenceItem::parse(item)? else {
        return Err(EvidenceFailure::WrongKind {
            expected: "peer-equivocation",
        });
    };
    if pg != Base64UrlUnpadded::encode_string(pr.as_bytes()) {
        return Err(EvidenceFailure::OtherPrincipal);
    }
    let (ca, cb) = (claim(&a, "a")?, claim(&b, "b")?);
    if ca.pr.as_bytes() != pr.as_bytes() || cb.pr.as_bytes() != pr.as_bytes() {
        return Err(EvidenceFailure::OtherPrincipal);
    }
    let signers = [
        signer_then(&a, peer, ca.now, "a")?,
        signer_then(&b, peer, cb.now, "b")?,
    ];

    let (lo, hi) = if ca.size <= cb.size {
        (&ca, &cb)
    } else {
        (&cb, &ca)
    };
    if lo.size == hi.size {
        if lo.commit_id == hi.commit_id && lo.root_pr == hi.root_pr {
            return Err(EvidenceFailure::NotConflicting("the statements agree"));
        }
    } else {
        let chain = higher_chain.ok_or(EvidenceFailure::NeedsChain)?;
        let commits: Vec<&Commit> = chain.commits().collect();
        let at = |size: u64| usize::try_from(size - 1).ok().and_then(|i| commits.get(i));
        let backs_higher = at(hi.size).is_some_and(|c| commit_is(c, &hi.commit_id));
        if !backs_higher {
            return Err(EvidenceFailure::NeedsChain);
        }
        let lower_is_prefix = at(lo.size).is_some_and(|c| {
            commit_is(c, &lo.commit_id)
                && c.pr().0.get(lo.root_pr.alg()) == Some(lo.root_pr.as_bytes())
        });
        if lower_is_prefix {
            return Err(EvidenceFailure::NotConflicting(
                "the lower statement is a prefix of the higher",
            ));
        }
    }
    Ok(EquivocationProof {
        pg: pr.clone(),
        signers,
    })
}

/// Whether `g`, a tagged or bare root, names `pg` (bare).
fn names_pg(pg: &str, g: &str) -> bool {
    g == pg || g.split_once(':').is_some_and(|(_, bare)| bare == pg)
}

/// Whether `principal` has a PG naming `pg` in any of its algorithms.
fn pg_names(principal: &Principal<MemoryStorage>, pg: &str) -> bool {
    use cyphr::StateDigest as _;
    principal.pg().is_some_and(|g| {
        let digest = g.as_multihash();
        digest
            .algorithms()
            .filter_map(|alg| digest.tagged(alg).ok())
            .any(|t| names_pg(pg, &t.to_string()))
    })
}

/// Whether the commit `blobs` opens with a coz signed by `genesis_key` (a
/// genesis commit opens with its genesis key's own `key/create`, SPEC 5.1).
fn opens_with(blobs: &[Vec<u8>], genesis_key: &str) -> bool {
    blobs
        .first()
        .and_then(|blob| serde_json::from_slice::<Value>(blob).ok())
        .is_some_and(|coz| coz.pointer("/pay/tmb").and_then(Value::as_str) == Some(genesis_key))
}

/// Replay one entry's blobs onto `principal` through the core's one replay
/// entry point, as [`PeerChain`](crate::PeerChain) does.
async fn replay_commit(
    principal: &mut Principal<MemoryStorage>,
    commit: usize,
    blobs: &[Vec<u8>],
) -> Result<(), EvidenceFailure> {
    crate::peer::replay_entry(principal, blobs)
        .await
        .map(|_| ())
        .map_err(|refusal| match refusal {
            crate::peer::EntryRefusal::Malformed(what) => {
                EvidenceFailure::BadCommit { commit, what }
            },
            crate::peer::EntryRefusal::Replay(source) => EvidenceFailure::Replay { commit, source },
        })
}
