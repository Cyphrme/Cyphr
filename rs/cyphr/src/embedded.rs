//! Embedded principals at default weight (SPEC be0663f §10.3, §10.5, §10.7).
//!
//! An embedded principal B sits in A's Key Tree as one digest leaf, B's PR
//! or PG, inserted by `cyphr/AT/KT/nonce/create`: an embedding is a digest
//! like a nonce, indistinguishable from one until the client reveals it
//! (10.1). At the default weight of one it is one member of A's KR, so
//! below Level 5 (no rules) any key B authorizes may sign for A.
//!
//! Authorization through B is conjunctive (10.5): the signer is an active
//! key of B at the tip the verifier holds for B (B's own AR), and B's digest
//! is in A's KT when the coz is applied (A's rule). A key B has removed is
//! refused whatever `now` it claims, because the tip shows it gone; B in
//! `Error` makes the authorization `EmbeddedErrored`. Only one level is
//! resolved: B's keys sign, B's own embeddings do not, so a cycle of
//! embeddings cannot recurse (10).
//!
//! Only PG and PR follow a tip (10.7; the "AR" of 10.3 is an editorial
//! error the spec author acknowledged). The verifier reveals a KT digest as
//! an embedded principal with [`Tracking::Follow`], the default, or
//! force-pins it to a state it holds with [`Tracking::Pin`]. Retrieval goes
//! through [`TipSource`], so the core reaches no network and reads no clock
//! for a tip: the source states when it pulled. A digest never revealed is
//! opaque: nothing is retrieved for it and it authorizes nothing, as a pin
//! to an unknown state would.
//!
//! Verdicts do not change after the fact: a newer tip is consulted for the
//! cozies verified after it arrives, and the commits A already holds are
//! never judged again.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use coz::Thumbprint;

use crate::error::{Error, Result};
use crate::key::Key;
use crate::principal::PrincipalState;
use crate::state::{StateDigest as _, TaggedDigest};

/// What a verifier holds of an embedded principal B: B's state replayed to
/// a tip, when the verifier pulled it, and what else the source verified
/// about B (naked revokes, a fork).
#[derive(Debug, Clone)]
pub struct Tip {
    state: PrincipalState,
    revoked: BTreeSet<String>,
    errored: bool,
    pulled_at: i64,
}

impl Tip {
    /// B's `state` (a [`Principal`](crate::Principal) derefs to it) as
    /// pulled at `pulled_at`: Unix seconds, the verifier's own clock at the
    /// pull.
    #[must_use]
    pub fn new(state: &PrincipalState, pulled_at: i64) -> Self {
        Self {
            state: state.clone(),
            revoked: BTreeSet::new(),
            errored: false,
            pulled_at,
        }
    }

    /// Keys the source saw revoked by a verified naked revoke (SPEC 6.4):
    /// inactive in B from then on, though B's chain does not show it yet.
    /// Thumbprints are base64url, as the revokes carry them.
    #[must_use]
    pub fn with_revoked<'a>(mut self, tmbs: impl IntoIterator<Item = &'a str>) -> Self {
        self.revoked.extend(tmbs.into_iter().map(str::to_owned));
        self
    }

    /// Mark B as in `Error` (SPEC 11.1): the source found a fork.
    #[must_use]
    pub fn in_error(mut self) -> Self {
        self.errored = true;
        self
    }

    /// When the verifier pulled this tip.
    #[must_use]
    pub fn pulled_at(&self) -> i64 {
        self.pulled_at
    }

    /// The newest `now` in B's chain at this tip.
    #[must_use]
    pub fn newest_now(&self) -> i64 {
        self.state.latest_timestamp
    }

    /// Whether B is in `Error`.
    #[must_use]
    pub fn is_errored(&self) -> bool {
        self.errored || self.state.is_errored()
    }

    /// Whether this tip is a state of the principal `member` names: B's PG,
    /// or a PR B has held, under the member's algorithm.
    fn names(&self, member: &TaggedDigest) -> bool {
        let same = |d: Option<&[u8]>| d == Some(member.as_bytes());
        self.state.pg().is_some_and(|pg| same(pg.get(member.alg())))
            || self
                .state
                .held_prs
                .iter()
                .any(|pr| same(pr.get(member.alg())))
    }

    /// B's key `tmb` if B's key history authorizes it at `now` (SPEC 6.5):
    /// `None` if `tmb` was never a key of B.
    fn signer_at(&self, tmb: &Thumbprint, now: i64) -> Option<Result<&Key>> {
        if self.revoked.contains(&tmb.to_b64()) {
            return Some(Err(Error::KeyRevoked));
        }
        let verdict = self.state.key_timeline.authorize(tmb, now)?;
        Some(if verdict.is_ok() && self.is_errored() {
            Err(Error::EmbeddedErrored)
        } else {
            verdict
        })
    }

    /// B's key `tmb` if B authorizes it at this tip: `None` if `tmb` is no
    /// key B has ever revoked or holds.
    fn signer(&self, tmb: &Thumbprint) -> Option<Result<&Key>> {
        let b64 = tmb.to_b64();
        if self.revoked.contains(&b64) || self.state.auth.revoked.contains_key(&b64) {
            return Some(Err(Error::KeyRevoked));
        }
        let key = self.state.auth.keys.get(&b64)?;
        Some(if self.is_errored() {
            Err(Error::EmbeddedErrored)
        } else {
            Ok(key)
        })
    }
}

/// Where a verifier gets the tip of an embedded principal: gossip, a store,
/// or a test fake. The seam keeps the core off the network and off the
/// clock.
pub trait TipSource {
    /// The tip of the principal `member` names (its PG or a PR it held,
    /// tagged `ALG:digest`), or `None` if the source has none.
    fn tip(&mut self, member: &str) -> impl Future<Output = Option<Tip>>;
}

/// How a revealed embedding is tracked (SPEC 10.7).
#[derive(Debug, Clone)]
pub enum Tracking {
    /// Follow B's tip: every [`follow_embedded`] asks the [`TipSource`].
    ///
    /// [`follow_embedded`]: crate::Principal::follow_embedded
    Follow,
    /// Pin B to this state: never retrieved, never updated.
    Pin(Box<Tip>),
}

/// The state one KT digest was judged against by
/// [`follow_embedded`](crate::Principal::follow_embedded).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbedStatus {
    /// Followed: the tip the source pulled at `pulled_at`, whose newest
    /// `now` is `newest_now`. Never current: it is as old as the pull.
    Followed {
        /// When the verifier pulled the tip.
        pulled_at: i64,
        /// The newest `now` in B's chain at that tip.
        newest_now: i64,
    },
    /// Followed, but the source had no tip that is a state of the member:
    /// it authorizes nothing until one arrives.
    Unavailable,
    /// Static: nothing was retrieved. `opaque` is a digest never revealed
    /// (10.3: opaque nodes do not trigger state synchronization); otherwise
    /// the client pinned it.
    Pinned {
        /// Whether the digest was never revealed.
        opaque: bool,
    },
}

/// One KT digest and how it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbedReport {
    /// The digest, tagged `ALG:digest`.
    pub member: String,
    /// How it was judged.
    pub status: EmbedStatus,
}

/// The embeddings a verifier has revealed on one principal, by digest
/// bytes. Verifier knowledge, never hashed into any root.
#[derive(Debug, Clone, Default)]
pub(crate) struct Members(BTreeMap<Vec<u8>, Member>);

#[derive(Debug, Clone)]
struct Member {
    id: TaggedDigest,
    follow: bool,
    view: Option<Tip>,
}

impl Members {
    /// Reveal `id` as an embedded principal tracked by `tracking`.
    ///
    /// # Errors
    ///
    /// `StateMismatch` if a pinned tip is not a state of `id`.
    pub(crate) fn reveal(&mut self, id: TaggedDigest, tracking: Tracking) -> Result<()> {
        let (follow, view) = match tracking {
            Tracking::Follow => (true, None),
            Tracking::Pin(tip) if tip.names(&id) => (false, Some(*tip)),
            Tracking::Pin(_) => return Err(Error::StateMismatch),
        };
        self.0
            .insert(id.as_bytes().to_vec(), Member { id, follow, view });
        Ok(())
    }

    /// Refresh every followed member in `kt` (A's KT digests) from
    /// `source`, and report every digest of `kt`.
    pub(crate) async fn follow<T: TipSource>(
        &mut self,
        kt: &[(Vec<u8>, TaggedDigest)],
        source: &mut T,
    ) -> Vec<EmbedReport> {
        let mut reports = Vec::with_capacity(kt.len());
        for (bytes, tagged) in kt {
            let status = match self.0.get_mut(bytes) {
                None => EmbedStatus::Pinned { opaque: true },
                Some(m) if !m.follow => EmbedStatus::Pinned { opaque: false },
                Some(m) => {
                    // A failed refresh fails closed: the old tip is dropped
                    // rather than kept as if it were still the newest.
                    m.view = source
                        .tip(&m.id.to_string())
                        .await
                        .filter(|t| t.names(&m.id));
                    m.view
                        .as_ref()
                        .map_or(EmbedStatus::Unavailable, |t| EmbedStatus::Followed {
                            pulled_at: t.pulled_at(),
                            newest_now: t.newest_now(),
                        })
                },
            };
            reports.push(EmbedReport {
                member: tagged.to_string(),
                status,
            });
        }
        reports
    }

    /// The key `tmb` of a member that is in A's KT (`in_kt`) and authorizes
    /// it, or `None` if no such member knows `tmb`. A refusal from one
    /// member wins over silence from the rest; an acceptance wins over
    /// both.
    pub(crate) fn signer(
        &self,
        tmb: &Thumbprint,
        in_kt: impl Fn(&[u8]) -> bool,
    ) -> Option<Result<&Key>> {
        let mut refusal = None;
        for (bytes, member) in &self.0 {
            let Some(found) = member
                .view
                .as_ref()
                .filter(|_| in_kt(bytes))
                .and_then(|t| t.signer(tmb))
            else {
                continue;
            };
            match found {
                Ok(key) => return Some(Ok(key)),
                Err(e) => refusal = Some(Err(e)),
            }
        }
        refusal
    }

    /// A key some member in view has held under `tmb` at any commit
    /// ([`PrincipalState::key_ever_held`]).
    pub(crate) fn key_ever_held(&self, tmb: &Thumbprint) -> Option<&Key> {
        self.0
            .values()
            .filter_map(|member| member.view.as_ref())
            .find_map(|tip| tip.state.key_ever_held(tmb))
    }

    /// [`Self::signer`] judged by each member's key history at `now`
    /// rather than at its tip: the authority for a data action.
    pub(crate) fn signer_at(
        &self,
        tmb: &Thumbprint,
        now: i64,
        in_kt: impl Fn(&[u8]) -> bool,
    ) -> Option<Result<&Key>> {
        let mut refusal = None;
        for (bytes, member) in &self.0 {
            let Some(found) = member
                .view
                .as_ref()
                .filter(|_| in_kt(bytes))
                .and_then(|t| t.signer_at(tmb, now))
            else {
                continue;
            };
            match found {
                Ok(key) => return Some(Ok(key)),
                Err(e) => refusal = Some(Err(e)),
            }
        }
        refusal
    }
}
