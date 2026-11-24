//! # The death set
//!
//! Naked revokes this node accepted, by thumbprint, with its receipt time of
//! each: the cutoff past which a key's arrivals are refused (SPEC 6.4).
//! A cache of the revoke records in the blob store (I1), filled by the
//! rebuild scan and by [`StorageEngine::record_revoke`].

use std::collections::HashMap;

use cyphr::replay::WireBundle;

use super::{
    BlobStore, EngineError, Indexer, IndexerWrite, REVOKE_RECORD_PREFIX, RevokeRecord,
    StorageEngine,
};
/// Verify a naked revoke's `{pay, sig, key}` envelope by the one core
/// rule ([`cyphr::revoke::verify_naked_revoke`]), returning the revoked
/// thumbprint (base64url).
pub(super) fn verify_revoke(evidence: &serde_json::Value) -> Result<String, String> {
    cyphr::revoke::verify_naked_revoke(evidence)
        .map(|revoke| revoke.tmb.to_b64())
        .map_err(|e| e.to_string())
}

/// A naked revoke the engine keeps for one key: this node's receipt time
/// of it, the key's cutoff, and the hash of its revoke record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Death {
    wrt: i64,
    record: [u8; 32],
}

impl Death {
    pub(super) fn new(wrt: i64, record: [u8; 32]) -> Self {
        Self { wrt, record }
    }
}

/// The naked-revoked thumbprints (base64url), each with the revoke the
/// engine keeps for it, the first it accepted: a cache of the revoke
/// records (I1).
#[derive(Debug, Clone, Default)]
pub(super) struct Revoked(HashMap<String, Death>);

impl Revoked {
    /// Note a revoke found in the store: live keeps one record per key,
    /// the first accepted; were there two, the earliest receipt stands.
    pub(super) fn note(&mut self, tmb: String, death: Death) {
        let at = self.0.entry(tmb).or_insert(death);
        *at = (*at).min(death);
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `tmb` was dead at `now`: revoked, with `now` at or after
    /// this node's receipt time of the revoke.
    fn is_dead_at(&self, tmb: &str, now: i64) -> bool {
        self.0.get(tmb).is_some_and(|death| now >= death.wrt)
    }

    /// The revoked thumbprints (base64url).
    pub(super) fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// The revocations in force, behind the one lock that orders them.
#[derive(Debug, Default)]
pub(super) struct DeathSet {
    revoked: std::sync::Mutex<Revoked>,
}

impl DeathSet {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Replace every revocation with `revoked`: a rebuild re-derives the
    /// set from the blobs.
    pub(super) fn replace(&self, revoked: Revoked) {
        *self.revoked.lock().unwrap_or_else(|p| p.into_inner()) = revoked;
    }

    pub(super) fn contains(&self, tmb: &str) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .contains_key(tmb)
    }

    /// Whether `tmb` was dead at `now`: revoked, with `now` at or after
    /// this node's receipt time of the revoke.
    pub(super) fn is_dead_at(&self, tmb: &str, now: i64) -> bool {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_dead_at(tmb, now)
    }

    pub(super) fn insert(&self, tmb: String, death: Death) {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .insert(tmb, death);
    }

    /// A copy of the revocations in force, for a check that spans an await.
    pub(super) fn snapshot(&self) -> Revoked {
        self.revoked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Key death at admission (SPEC 6.4), the one check every path that hands
/// the engine a bundle passes (`/push`, gossip, witness sync, a verifier's
/// store): the refusal for `bundle` if a coz in it is signed by a revoked
/// key and the coz is dated at or after the key's cutoff, this node's
/// receipt time of its revoke ([`Death::wrt`]; a coz with no readable
/// `now` is judged dated after it). Introducing a revoked key is not
/// refused: the introduction is the introducer's act, not the key's (SPEC
/// 6.4 rejects "further use of the revoked key"), and a revoke is in no
/// commit's causal past, so a rule that depends on it splits holders of
/// the same messages. That convergence is guaranteed for introductions
/// only: a coz the revoked key itself signs, dated within the window
/// between two holders' receipt times of its revoke, is still admitted by
/// one and refused by the other, and nothing re-joins them (no
/// retrospection, SPEC 14.12). That split waits on the spec author's
/// answer (forge #203).
///
/// Not retroactive: history a key signed before the cutoff stands, so a
/// node that learned the revoke first still syncs it. A coz that revokes
/// its own signer is never refused: it can only end the key (SPEC 6.4:
/// "sign a standard revoke, a subsequent `key/delete` ... and commit").
///
/// The revokes are read here, against what arrives, and held in no
/// principal's state: a revoke judges nothing already held (SPEC 14.12), so
/// no verified state changes when one is recorded.
///
/// The key's holder chooses `now`, so a holder of a compromised key can
/// date a commit below the cutoff. That is not prevented here: the owner
/// recovers by mutating the principal forward (SPEC 14.12), since Cyphr
/// does not use reversion. Where that leaves both branches extended, the
/// fork is in Error (rule E) and the exit is a resync PoP asserting the
/// owner's tip ([`StorageEngine::submit_resync`], SPEC 15.8 item 2).
///
/// Refusal-only: it reads each coz's declared `pay.tmb`, `pay.typ` and
/// `pay.now` before any signature is checked, so a forgery
/// can at worst refuse the bundle it travels in. It must never admit or
/// authorize on these fields.
pub(super) fn dead_key_in(bundle: &WireBundle, revoked: &Revoked) -> Option<EngineError> {
    if revoked.is_empty() {
        return None;
    }
    // A bundle that does not decode is refused by the admission that
    // follows; this gate only names a dead key.
    let decoded = bundle.decode().ok()?;
    let dead_at = |coz: &cyphr::replay::StoredCoz| {
        let header = coz.header();
        revoked.is_dead_at(&header.tmb.to_b64(), header.now)
    };
    // A data action a dead key signs is refused as the core refuses one
    // signed by a key revoked in the chain: `KeyRevoked`. That is the
    // answer whoever the key belonged to. Key death is global by
    // thumbprint (SPEC 6.4), so a dead key that was never this principal's
    // is answered `KeyRevoked` here too, where a live key it never held is
    // answered `UnknownKey` by the core: a client sees the revoke, not the
    // absence, when both are true.
    if decoded.action_cozies().iter().any(dead_at) {
        return Some(EngineError::Protocol(cyphr::Error::KeyRevoked));
    }
    for coz in decoded.txs().iter().flatten() {
        let self_revoke = cyphr::parsed_coz::typ::has_suffix(
            &coz.header().typ,
            cyphr::parsed_coz::typ::KEY_REVOKE,
        );
        if dead_at(coz) && !self_revoke {
            return Some(EngineError::DeadKey {
                key: coz.header().tmb.to_b64(),
            });
        }
    }
    None
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Record a self-signed naked revoke (SPEC 6.4), received by this node
    /// at `wrt` (its Witness Receipt Timestamp, Unix seconds), as a revoke
    /// record in the blob store. `evidence` is the `{pay, sig, key}`
    /// envelope the revoke arrived in; it is verified here, since a
    /// rebuild re-verifies it. A Coz-valid revoke is always accepted,
    /// pushed or relayed, whatever its `now` or `rvk` (the spec author on
    /// #203: "Coz valid revokes are always accepted").
    ///
    /// The key's cutoff is `wrt`, never the revoke's own `now` or `rvk`
    /// (#203: "honor it from the witness's own receipt time"; SPEC 14.12).
    /// A revoke is an admission gate and nothing else: a message the key
    /// signs that arrives after it is refused iff its own `now` is at or
    /// after the cutoff ([`dead_key_in`], transactions and data actions
    /// alike). A held message is never judged again, live or on
    /// rebuild (SPEC 14.12: "Principals must explicitly mutate their state
    /// forward"), so recording a revoke changes no answer about what is
    /// held. A relayed
    /// revoke gets this node's receipt time, never the relayer's. The
    /// caller supplies `wrt` from its clock.
    ///
    /// The first revoke of a key accepted stands and is never replaced: a
    /// later one stores nothing, so re-signing cannot grow the store and a
    /// clock stepping back cannot lower the cutoff. Key death is global by
    /// thumbprint, so the record names no principal.
    ///
    /// # Errors
    ///
    /// [`EngineError::InvalidInput`] for a revoke that is not Coz-valid or
    /// not self-signed; a storage error if the record cannot be written.
    pub async fn record_revoke(
        &self,
        evidence: &serde_json::Value,
        wrt: i64,
    ) -> Result<(), EngineError> {
        self.writable()?;
        self.ensure_healed().await?;
        let tmb = verify_revoke(evidence).map_err(EngineError::InvalidInput)?;
        // Held across the write, so two revokes of one key store one record.
        let lock = self.principal_lock(&format!("revoke\0{tmb}"));
        let _one_record = lock.lock().await;
        if self.deaths.contains(&tmb) {
            return Ok(());
        }
        let mut bytes = REVOKE_RECORD_PREFIX.to_vec();
        serde_json::to_writer(
            &mut bytes,
            &RevokeRecord {
                wrt,
                evidence: evidence.clone(),
            },
        )
        .map_err(|e| EngineError::MalformedBlob(format!("revoke record serialize: {e}")))?;
        let death = Death::new(wrt, *blake3::hash(&bytes).as_bytes());
        self.blob_store.put(&bytes).await?;
        // The caller is told the key was durably recorded dead (the
        // /revoke response), and a death-set a power cut can revert would
        // let a dead key's commits back in: durable before it is visible.
        self.persist_record().await?;
        self.deaths.insert(tmb, death);
        Ok(())
    }

    /// Whether the engine holds a revoke record for `tmb` (base64url).
    #[must_use]
    pub fn is_revoked(&self, tmb: &str) -> bool {
        self.deaths.contains(tmb)
    }
}
