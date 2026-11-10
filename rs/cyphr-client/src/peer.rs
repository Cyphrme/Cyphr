//! A peer as a principal: pinned by its PG and genesis key, followed over
//! `/patch`, and the authority for the statements the peer signs.
//!
//! A client that pins a bare signing key cannot follow a rotation; a client
//! that pins the peer's *chain* can. [`PeerChain`] holds the peer's own
//! principal, replayed locally by the core from the pinned genesis, and
//! judges every statement (a signed tip, a view) against the keys ACTIVE in
//! that chain: a statement is never accepted by key bytes alone, and a key
//! the held chain has retired is refused. The pattern is the pinned-origin,
//! verified-log shape of C2SP `tlog-checkpoint`: trust is rooted in what
//! the client pinned, and everything else is verified up from it.
//!
//! # Snapshot trust
//!
//! Keys are judged against the held chain SNAPSHOT, as with
//! [`verify_view`](crate::verify_view): a key the peer retires after the
//! last [`follow`](PeerChain::follow) stays accepted until the caller
//! follows again. The caller owns the re-follow policy (how often, and
//! after which signal); [`PeerChain::verify_tip_following`] re-follows
//! only to admit a key the snapshot lacks, never to retire one.
//!
//! Nothing the peer says about its own chain is trusted beyond the signed
//! commits the core verifies on replay. A followed patch is replayed onto a
//! fresh principal from the pinned genesis and only then compared with the
//! held chain, so a failed or hostile follow leaves the held chain exactly
//! as it was (I2: a fork is detected, never merged).
//!
//! No I/O lives here except the one `/patch` fetch in [`PeerChain::follow`]
//! through a [`Connector`]; [`PeerChain::verify_tip`] and
//! [`PeerChain::verify_view`] are pure, so a carrier that already holds a
//! statement (a Noise responder, gossip) can verify it against the chain
//! without HTTP.

use coz::base64ct::{Base64UrlUnpadded, Encoding};
use cyphr::eml::MemoryStorage;
use cyphr::replay::{BundleId, StoredCoz, WireError, replay_bundle};
use cyphr::{Key, Principal};
use serde::Deserialize as _;
use serde_json::Value;

use crate::connector::{BindingPolicy, Connector};
use crate::patch::{
    AuthorityKey, EntryDefect, PatchFailure, PatchRequest, Statement, fetch_patch,
    verify_authenticated_envelope,
};
use crate::report::{TipReport, ViewFailure, ViewStatement, verify_view};

/// The wire version of the response envelope a tip arrives in.
const ENVELOPE_VERSION: u64 = 1;

/// Why a peer chain was not followed, or a peer statement not accepted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerFailure {
    /// The pinned PG does not derive from the pinned genesis key, so the
    /// key does not root the chain the PG names; nothing is adopted.
    #[error("pinned pg {pg} does not derive from the pinned genesis key (derives {derived})")]
    PinMismatch {
        /// The PG the caller pinned.
        pg: String,
        /// The PG the pinned genesis key actually derives.
        derived: String,
    },
    /// The peer's chain does not extend the held one: it diverges at
    /// `index`, the first patch entry (a commit, or an action-only bundle)
    /// whose replayed identity differs.
    #[error("the peer's chain diverges from the held chain at entry {index}")]
    Fork {
        /// The zero-based position of the first differing entry.
        index: usize,
    },
    /// The peer offered fewer entries than are already held, every one of
    /// them agreeing with the held chain: a stale or rolled-back peer.
    #[error("the peer offered {offered} entries but {held} are held")]
    Behind {
        /// Entries held.
        held: usize,
        /// Entries offered.
        offered: usize,
    },
    /// The statement's signing key is not active in the held chain: never
    /// in it, or retired since.
    #[error("signing key {tmb} is not active in the held peer chain")]
    KeyNotActive {
        /// The signing key the statement names, as claimed (unverified).
        tmb: String,
    },
    /// The `/patch` fetch failed or its envelope was refused.
    #[error("patch: {0}")]
    Patch(#[from] PatchFailure),
    /// A patch entry could not be decoded.
    #[error("patch entry {index} is undecodable: {defect:?}")]
    Entry {
        /// The entry's position in the patch.
        index: usize,
        /// Why it could not be decoded.
        defect: EntryDefect,
    },
    /// A commit in the patch is not the shape a coz commit has.
    #[error("commit {commit} is malformed: {what}")]
    Malformed {
        /// The commit's position in the patch.
        commit: usize,
        /// What is wrong with it.
        what: &'static str,
    },
    /// The core refused a commit on replay from the pinned genesis.
    #[error("commit {commit} fails replay from the pinned genesis: {source}")]
    Replay {
        /// The commit's position in the patch.
        commit: usize,
        /// The core's refusal.
        source: cyphr::Error,
    },
    /// The tip's envelope or signature was refused.
    #[error("tip: {0}")]
    Tip(PatchFailure),
    /// The view statement was refused.
    #[error("view: {0}")]
    View(ViewFailure),
}

/// The extent of a held peer chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldTip {
    /// Commits held; zero for a chain not yet followed.
    pub commits: usize,
    /// The tip Principal Root, tagged (`ALG:digest`).
    pub pr: String,
}

/// The state a pin is in: a verified root to follow from, or a refusal
/// that every later call repeats.
enum Pin {
    Held(Box<Principal<MemoryStorage>>),
    Mismatch { pg: String, derived: String },
}

/// A peer principal the client holds: the chain replayed so far, from a
/// pinned PG and genesis key.
pub struct PeerChain {
    pg: String,
    genesis: Key,
    pin: Pin,
    /// The identity of every bundle the held chain replayed, in order,
    /// action-only bundles included, so a follow can compare them all.
    bundles: Vec<BundleId>,
    /// Whether a follow has ever completed. A bare pin holds only the
    /// genesis key, which is key bytes and not yet a chain.
    followed: bool,
}

impl PeerChain {
    /// Pin a peer by its PG and its genesis key.
    ///
    /// Infallible: a pin whose PG the key does not derive is held as a
    /// refusal, so [`follow`](Self::follow) and every verification report
    /// [`PeerFailure::PinMismatch`] and trust nothing.
    ///
    /// The pin is a single genesis key. A peer whose genesis commit
    /// creates further keys derives its PG from the whole key set, so the
    /// genesis key alone cannot match it: such a peer can never be pinned
    /// and fails closed with `PinMismatch`.
    #[must_use]
    pub fn pin(pg: &str, genesis: Key) -> Self {
        let pin = match Principal::implicit(genesis.clone()) {
            Ok(principal) => match principal.pr_tagged() {
                Ok(derived) if matches_pg(pg, &derived) => Pin::Held(Box::new(principal)),
                Ok(derived) => Pin::Mismatch {
                    pg: pg.to_string(),
                    derived,
                },
                Err(err) => Pin::Mismatch {
                    pg: pg.to_string(),
                    derived: format!("underivable: {err}"),
                },
            },
            Err(err) => Pin::Mismatch {
                pg: pg.to_string(),
                derived: format!("underivable: {err}"),
            },
        };
        Self {
            pg: pg.to_string(),
            genesis,
            pin,
            bundles: Vec::new(),
            followed: false,
        }
    }

    fn chain(&self) -> Result<&Principal<MemoryStorage>, PeerFailure> {
        match &self.pin {
            Pin::Held(chain) => Ok(chain),
            Pin::Mismatch { pg, derived } => Err(PeerFailure::PinMismatch {
                pg: pg.clone(),
                derived: derived.clone(),
            }),
        }
    }

    /// The pinned PG.
    #[must_use]
    pub fn pg(&self) -> &str {
        &self.pg
    }

    /// The held chain's ACTIVE key with thumbprint `tmb`, for a transport
    /// or sign-on layer that verifies a statement of its own against the
    /// peer chain without HTTP. Judged against the held snapshot, like every
    /// verification here.
    ///
    /// # Errors
    ///
    /// [`PeerFailure::KeyNotActive`] when no active key has that
    /// thumbprint (never held, or revoked or replaced);
    /// [`PeerFailure::PinMismatch`] for a refused pin.
    pub fn active_key(&self, tmb: &coz::Thumbprint) -> Result<&Key, PeerFailure> {
        self.chain()?
            .active_keys()
            .find(|k| k.tmb() == tmb)
            .ok_or_else(|| PeerFailure::KeyNotActive { tmb: tmb.to_b64() })
    }

    /// How far the held chain reaches: its commit count and tip PR.
    ///
    /// # Errors
    ///
    /// [`PeerFailure::PinMismatch`] for a refused pin; [`PeerFailure::Replay`]
    /// if the core cannot render the tip PR.
    pub fn held_tip(&self) -> Result<HeldTip, PeerFailure> {
        let chain = self.chain()?;
        let commits = chain.commits().count();
        let pr = chain.pr_tagged().map_err(|source| PeerFailure::Replay {
            commit: commits,
            source,
        })?;
        Ok(HeldTip { commits, pr })
    }

    /// Fetch the peer's full chain and extend the held one with it.
    ///
    /// The patch carries no anchor: the whole history is replayed by the
    /// core from the pinned genesis, which is what authenticates it (the
    /// patch's own statement is not consulted), and the held chain must be
    /// a prefix of the result. The held chain changes only when the whole
    /// patch verifies and extends it.
    ///
    /// # Errors
    ///
    /// [`PeerFailure::PinMismatch`] for a refused pin; [`PeerFailure::Patch`]
    /// or [`PeerFailure::Entry`] for a fetch or decode failure;
    /// [`PeerFailure::Replay`] or [`PeerFailure::Malformed`] when the core
    /// refuses a commit; [`PeerFailure::Fork`] when the patch diverges from
    /// the held chain; [`PeerFailure::Behind`] when it is shorter.
    pub async fn follow<C: Connector>(&mut self, connector: &C) -> Result<(), PeerFailure> {
        self.chain()?;
        let patch = fetch_patch(
            connector,
            &PatchRequest {
                principal_id: &self.pg,
                anchor: None,
            },
            BindingPolicy::NotRequired,
            None,
        )
        .await?;

        // The replay root is a fresh principal from the pinned genesis,
        // never the held (already extended) one.
        let mut candidate = Principal::implicit(self.genesis.clone())
            .map_err(|source| PeerFailure::Replay { commit: 0, source })?;
        let mut offered = Vec::with_capacity(patch.entries.len());
        for (index, entry) in patch.entries.iter().enumerate() {
            let blobs = entry.blobs.as_ref().map_err(|defect| PeerFailure::Entry {
                index,
                defect: *defect,
            })?;
            offered.push(
                replay_entry(&mut candidate, blobs).map_err(|refusal| match refusal {
                    EntryRefusal::Malformed(what) => PeerFailure::Malformed {
                        commit: index,
                        what,
                    },
                    EntryRefusal::Replay(source) => PeerFailure::Replay {
                        commit: index,
                        source,
                    },
                })?,
            );
        }

        // Every held bundle is compared, the action-only ones after the
        // last commit included: no commit covers those, so comparing
        // commits alone would let a peer rewrite them unseen.
        if let Some(index) = self.bundles.iter().zip(&offered).position(|(h, o)| h != o) {
            return Err(PeerFailure::Fork { index });
        }
        if offered.len() < self.bundles.len() {
            return Err(PeerFailure::Behind {
                held: self.bundles.len(),
                offered: offered.len(),
            });
        }

        self.pin = Pin::Held(Box::new(candidate));
        self.bundles = offered;
        self.followed = true;
        Ok(())
    }

    /// Verify a signed `/tip` envelope against the keys active in the held
    /// chain snapshot. `principal_id` is the principal the tip is about (not
    /// the peer's own).
    ///
    /// A key the peer retired after the last [`follow`](Self::follow) is
    /// still active in the snapshot and still accepted; call `follow` to
    /// learn of the retirement.
    ///
    /// # Errors
    ///
    /// [`PeerFailure::KeyNotActive`] when the signing key is not active in
    /// the held chain; [`PeerFailure::Tip`] for any other refusal of the
    /// envelope; [`PeerFailure::PinMismatch`] for a refused pin.
    pub fn verify_tip(&self, body: &Value, principal_id: &str) -> Result<TipReport, PeerFailure> {
        let chain = self.chain()?;
        let found = body.get("v").and_then(Value::as_u64).unwrap_or(0);
        if found != ENVELOPE_VERSION {
            return Err(PeerFailure::Tip(PatchFailure::UnsupportedVersion {
                found,
                supported: ENVELOPE_VERSION,
            }));
        }
        let Some(Statement::Signed(coz)) = body
            .get("statement")
            .and_then(|s| Statement::deserialize(s).ok())
        else {
            return Err(PeerFailure::Tip(PatchFailure::EnvelopeUnsignedOrMisSigned));
        };
        let tmb =
            claimed_tmb(&coz).ok_or(PeerFailure::Tip(PatchFailure::EnvelopeUnsignedOrMisSigned))?;
        // ACTIVE keys only: `get_key` also returns revoked ones.
        let key = chain
            .active_keys()
            .find(|k| k.tmb() == &tmb)
            .ok_or_else(|| PeerFailure::KeyNotActive { tmb: tmb.to_b64() })?;
        let authority = AuthorityKey {
            alg: key.alg().to_string(),
            pub_key: key.pub_key().to_vec(),
        };
        verify_authenticated_envelope(body, &authority, principal_id).map_err(PeerFailure::Tip)
    }

    /// Verify a peer view statement against the keys active in the held
    /// chain; `pr` is the principal the view is about. Freshness and
    /// pinning remain the caller's, as in [`verify_view`](crate::verify_view).
    ///
    /// # Errors
    ///
    /// [`PeerFailure::KeyNotActive`] when the signing key is not active in
    /// the held chain; [`PeerFailure::View`] for any other refusal;
    /// [`PeerFailure::PinMismatch`] for a refused pin.
    pub fn verify_view(
        &self,
        coz: &coz::CozJson,
        pr: &coz::Thumbprint,
    ) -> Result<ViewStatement, PeerFailure> {
        verify_view(coz, self.chain()?, pr).map_err(|failure| match failure {
            ViewFailure::KeyNotActive => PeerFailure::KeyNotActive {
                tmb: claimed_tmb(coz).map_or_else(String::new, |t| t.to_b64()),
            },
            other => PeerFailure::View(other),
        })
    }

    /// [`verify_tip`](Self::verify_tip), following the peer first when the
    /// held chain cannot yet vouch: the chain was never followed (a bare
    /// pin is key bytes, not a chain) or the signing key is not active in
    /// it (the peer may have rotated). At most one fetch: following cannot
    /// conjure a key, so a key the followed chain still lacks stays refused.
    ///
    /// This admits keys; it does not retire them. On a chain already
    /// followed, a key the snapshot still holds verifies without a fetch
    /// even if the peer has since retired it; re-follow policy is the
    /// caller's.
    ///
    /// # Errors
    ///
    /// As [`verify_tip`](Self::verify_tip) and [`follow`](Self::follow).
    pub async fn verify_tip_following<C: Connector>(
        &mut self,
        connector: &C,
        body: &Value,
        principal_id: &str,
    ) -> Result<TipReport, PeerFailure> {
        if !self.followed {
            self.follow(connector).await?;
            return self.verify_tip(body, principal_id);
        }
        match self.verify_tip(body, principal_id) {
            Err(PeerFailure::KeyNotActive { .. }) => {
                self.follow(connector).await?;
                self.verify_tip(body, principal_id)
            },
            other => other,
        }
    }
}

/// Whether the pinned `pg` names the derived PR, labelled or bare.
fn matches_pg(pg: &str, derived: &str) -> bool {
    pg == derived || derived.split_once(':').is_some_and(|(_, bare)| pg == bare)
}

fn claimed_tmb(coz: &coz::CozJson) -> Option<coz::Thumbprint> {
    coz.pay["tmb"]
        .as_str()
        .and_then(|t| Base64UrlUnpadded::decode_vec(t).ok())
        .map(coz::Thumbprint::from_bytes)
}

/// Why a fetched entry did not replay: its wire form is malformed, or the
/// core refused it.
pub(crate) enum EntryRefusal {
    /// A static description of the wire defect.
    Malformed(&'static str),
    /// The core's refusal, from decoding the pay header or from replay.
    Replay(cyphr::Error),
}

/// Decode one entry's wire blobs and replay them onto `principal` through
/// the core's one replay entry point, returning the bundle's identity.
/// Shared by [`PeerChain::follow`] and the evidence verifier, so a fetched
/// entry means one thing on both.
pub(crate) fn replay_entry(
    principal: &mut Principal<MemoryStorage>,
    blobs: &[Vec<u8>],
) -> Result<BundleId, EntryRefusal> {
    let cozies = blobs
        .iter()
        .map(|blob| {
            StoredCoz::from_wire(blob).map_err(|e| match e {
                WireError::Header(source) | WireError::Protocol(source) => {
                    EntryRefusal::Replay(source)
                },
                WireError::NotJson => EntryRefusal::Malformed("blob is not JSON"),
                WireError::MissingPay => EntryRefusal::Malformed("no pay"),
                WireError::BadSig => EntryRefusal::Malformed("sig is not base64url"),
                WireError::KeyFields | WireError::Key(_) => {
                    EntryRefusal::Malformed("key sidecar is malformed")
                },
                _ => EntryRefusal::Malformed("malformed coz"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    replay_bundle(principal, &cozies).map_err(|e| EntryRefusal::Replay(e.source))
}
