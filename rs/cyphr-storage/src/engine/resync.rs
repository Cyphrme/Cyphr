//! # Resync proofs
//!
//! The resync proofs of possession this node holds (SPEC 13, 15.8 item 2),
//! by principal and asserted tip: a cache of the resync records in the
//! blob store (I1), filled by the rebuild scan and by
//! [`StorageEngine::submit_resync`].

use std::collections::{BTreeMap, HashMap};

use super::*;

/// Each principal's held resync PoPs (the verified `{pay, sig}` coz) by
/// the PR they assert.
#[derive(Debug, Default)]
pub(super) struct Resyncs(HashMap<PrincipalGenesis, BTreeMap<String, serde_json::Value>>);

impl Resyncs {
    /// Hold `evidence`, the PoP for `principal_id`'s tip `tip`.
    pub(super) fn note(
        &mut self,
        principal_id: PrincipalGenesis,
        tip: String,
        evidence: serde_json::Value,
    ) {
        self.0
            .entry(principal_id)
            .or_default()
            .insert(tip, evidence);
    }

    /// The PRs `principal_id`'s held PoPs assert, sorted.
    pub(super) fn asserted(&self, principal_id: &PrincipalGenesis) -> Vec<String> {
        self.0
            .get(principal_id)
            .map(|held| held.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The PoPs held for `principal_id`, one per asserted tip, sorted by tip.
    fn proofs(&self, principal_id: &PrincipalGenesis) -> Vec<serde_json::Value> {
        self.0
            .get(principal_id)
            .map(|held| held.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// The held resync PoPs, behind the one lock that orders them.
#[derive(Debug, Default)]
pub(super) struct ResyncStore {
    held: std::sync::Mutex<Resyncs>,
}

impl ResyncStore {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Replace every held PoP with `resyncs`: a rebuild re-derives the set
    /// from the blobs.
    pub(super) fn replace(&self, resyncs: Resyncs) {
        *self.held.lock().unwrap_or_else(|p| p.into_inner()) = resyncs;
    }

    pub(super) fn note(
        &self,
        principal_id: PrincipalGenesis,
        tip: String,
        evidence: serde_json::Value,
    ) {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .note(principal_id, tip, evidence);
    }

    /// The PRs `principal_id`'s held PoPs assert, sorted.
    pub(super) fn asserted(&self, principal_id: &PrincipalGenesis) -> Vec<String> {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .asserted(principal_id)
    }

    /// The PoPs held for `principal_id`, one per asserted tip.
    pub(super) fn proofs(&self, principal_id: &PrincipalGenesis) -> Vec<serde_json::Value> {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .proofs(principal_id)
    }
}
/// What [`StorageEngine::submit_resync`] did with a PoP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResyncReceipt {
    /// The principal's storage key.
    pub principal_id: cyphr::PrincipalGenesis,
    /// The asserted tip's PR.
    pub id: String,
    /// `false` when a PoP for this tip was already held: nothing was
    /// stored.
    pub stored: bool,
    /// The PoP made the line it asserts the principal's chain.
    pub promoted: bool,
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Accept a resync proof of possession (SPEC 13, 15.8 item 2) for the
    /// tip it asserts, and keep the record: one blob per asserted PR. The
    /// proof names a tip's Principal Root as its `id` and is signed, `now`
    /// required and no window tested, by a key active in the state at that
    /// tip. The tip is held, or `line` carries the commits from a held
    /// commit up to it; a line is verified as any commit is, and its
    /// commits not yet held are kept within the caps, or past them when
    /// the proof would change the standing or the fork point (rule X).
    /// Where the fork rule over everything held, the proof included, is
    /// Active on a line that is not the chain, that line becomes the chain
    /// outside the caps and the displaced chain is retained.
    ///
    /// The signer's key must not be dead at `now` (the revoke gate that
    /// applies to any arrival, SPEC 6.4). A PoP for a tip that already
    /// has one stores nothing.
    ///
    /// # Errors
    ///
    /// [`EngineError::InvalidInput`] for a malformed proof,
    /// [`EngineError::NotFound`] for a principal not stored or a tip not
    /// held and not carried, a [`EngineError::Protocol`] error when the
    /// signer is no active key at the tip or its signature does not
    /// verify, [`EngineError::DeadKey`] for a revoked signer, and
    /// [`EngineError::BranchLimit`] for a line whose commits the caps
    /// refuse and that changes nothing. A refusal stores nothing of the
    /// proof.
    pub async fn submit_resync(
        &self,
        principal_id: &PrincipalGenesis,
        pop: &serde_json::Value,
        line: &[WireBundle],
    ) -> Result<ResyncReceipt, EngineError> {
        self.writable()?;
        self.ensure_healed().await?;
        let resync = cyphr::resync::parse_resync(pop)
            .map_err(|e| EngineError::InvalidInput(e.to_string()))?;
        let principal_id = self.stored_id(principal_id).await?.ok_or_else(|| {
            EngineError::NotFound(format!("no principal {principal_id} is stored"))
        })?;
        let principal_id = &principal_id;
        let receipt = |stored, promoted| ResyncReceipt {
            principal_id: principal_id.clone(),
            id: resync.id.clone(),
            stored,
            promoted,
        };

        // Cheapest refusals first, before the line is read and before the
        // principal's write lock is taken, so a refusal costs what the
        // sender's PoP costs and not what its line does. The signer must be
        // a key this principal ever held (its chain's or a retained
        // branch's) and its signature must verify.
        let held_key = match self.at_tip(principal_id).await? {
            Some(at_tip) => at_tip.key_ever_held(&resync.tmb).cloned(),
            None => None,
        }
        .or_else(|| {
            self.branches
                .keys(principal_id)
                .iter()
                .find(|k| k.tmb == resync.tmb.to_b64())
                .and_then(|k| k.to_key().ok())
        })
        .ok_or(EngineError::Protocol(cyphr::Error::UnknownKey))?;
        cyphr::resync::verify_resync(pop, &held_key)
            .map_err(|_| EngineError::Protocol(cyphr::Error::InvalidSignature))?;
        let signer = resync.tmb.to_b64();
        if self.deaths.is_dead_at(&signer, resync.now) {
            return Err(EngineError::DeadKey { key: signer });
        }
        if self.resyncs.asserted(principal_id).contains(&resync.id) {
            return Ok(receipt(false, false));
        }

        let genesis = self.genesis_of_stored(principal_id).await?;
        let lock = self.principal_lock(principal_id);
        let write = Self::lock_writes(&lock, principal_id).await;
        // Held across the line work below: a PoP for this tip that landed
        // while this one waited for the lock leaves nothing to do.
        if self.resyncs.asserted(principal_id).contains(&resync.id) {
            return Ok(receipt(false, false));
        }
        let line = line
            .iter()
            .map(canonical_bundle)
            .collect::<Result<Vec<_>, _>>()?;

        // The state at the asserted tip, where the signer is read.
        let stored = self.stored_entries(principal_id, None).await?;
        let rivals = self.branches.retained(principal_id);
        let by_pr: HashMap<(u64, &str), &Retained> = rivals
            .iter()
            .map(|r| ((r.tip.sequence, r.pr.as_str()), r))
            .collect();
        let mut carried: Vec<(IndexableCommit, Vec<EmbeddedPin>)> = Vec::new();
        let key: cyphr::Key = if let Some(at) = stored.prs.iter().position(|pr| *pr == resync.id) {
            // The asserted tip is on the chain: the signer's key history,
            // read off the state at the chain's tip, says whether it was
            // active at that position, so nothing is replayed.
            let tip = self.indexer.get_tip(principal_id).await?.ok_or_else(|| {
                EngineError::NotFound(format!("principal {principal_id} has no tip"))
            })?;
            let verified = self
                .verified(principal_id, Some(&genesis), &tip, &write)
                .await?;
            let state = verified.principal.state();
            state
                .key_ever_held(&resync.tmb)
                .filter(|_| state.key_active_at_position(&resync.tmb, at as u64))
                .cloned()
                .ok_or(EngineError::Protocol(cyphr::Error::UnknownKey))?
        } else if let Some(rival) = rivals.iter().find(|r| r.pr == resync.id) {
            let principal = self
                .replay_line(principal_id, &genesis, &stored, &by_pr, rival)
                .await?
                .ok_or_else(|| {
                    EngineError::MalformedBlob(format!(
                        "the retained line to {} no longer replays",
                        resync.id
                    ))
                })?
                .principal;
            Self::active_key(&principal, &resync.tmb)?
        } else if line.is_empty() {
            return Err(EngineError::NotFound(format!(
                "the asserted tip {} is not held and no line carries it",
                resync.id
            )));
        } else {
            let tip = self.indexer.get_tip(principal_id).await?.ok_or_else(|| {
                EngineError::NotFound(format!("principal {principal_id} has no tip"))
            })?;
            let verified = self
                .verified(principal_id, Some(&genesis), &tip, &write)
                .await?;
            let attached = self
                .attach_line(
                    principal_id,
                    &genesis,
                    &stored,
                    &rivals,
                    &by_pr,
                    verified.principal.state(),
                    &line,
                    &resync.id,
                )
                .await?
                .ok_or_else(|| {
                    EngineError::NotFound(format!(
                        "the line does not extend a held commit up to {}",
                        resync.id
                    ))
                })?;
            // Arrivals pass the revoke gate; a commit already held is
            // not judged again (SPEC 14.12).
            let revoked = self.deaths.snapshot();
            for bundle in line.iter().take(attached.commits.len()) {
                let hashes: Vec<Blake3Hash> = bundle
                    .cozies()
                    .map(|b| Blake3Hash::from_bytes(*blake3::hash(b).as_bytes()))
                    .collect();
                let held = self
                    .branches
                    .is_retained(principal_id, &hashes, &Shape::of(bundle))
                    || self.is_already_stored(principal_id, bundle).await?;
                if !held && let Some(dead) = dead_key_in(bundle, &revoked) {
                    return Err(dead);
                }
            }
            carried = attached.commits;
            Self::active_key(&attached.principal, &resync.tmb)?
        };
        cyphr::resync::verify_resync(pop, &key)
            .map_err(|_| EngineError::Protocol(cyphr::Error::InvalidSignature))?;
        let record_key = KeyEntry::of(&key);

        // What the proof does to the verdict over everything held.
        let lowest = carried.iter().map(|(c, _)| c.sequence).min();
        let mut asserted = self.resyncs.asserted(principal_id);
        let held = self.held_with(principal_id, lowest).await?;
        let before = assessment(&held, &asserted);
        let mut with_line = held;
        with_line.extend(carried.iter().map(|(c, _)| held_of(c)));
        asserted.push(resync.id.clone());
        let after = assessment(&with_line, &asserted);
        let chain_tip = self
            .indexer
            .get_tip(principal_id)
            .await?
            .map(|t| t.commit_id);
        let promote = after.consensus == Consensus::Active
            && after.heads.first().map(String::as_str) != chain_tip.as_deref();
        let force =
            promote || after.consensus != before.consensus || after.fork_point != before.fork_point;

        let built: Vec<IndexableCommit> = carried.iter().map(|(c, _)| c.clone()).collect();
        // I1 order: the carried commits, then the record, then the chain.
        for ((commit, embedded), bundle) in carried.into_iter().zip(&line) {
            if let Err(refusal) = self
                .keep_branch_with(bundle, commit, embedded.as_slice(), force)
                .await
            {
                return Err(self.answer_in_error(principal_id, refusal).await);
            }
        }
        let mut bytes = RESYNC_RECORD_PREFIX.to_vec();
        serde_json::to_writer(
            &mut bytes,
            &ResyncRecord {
                principal_id: principal_id.clone(),
                tip: resync.id.clone(),
                evidence: pop.clone(),
                key: record_key,
            },
        )
        .map_err(|e| EngineError::MalformedBlob(format!("resync record serialize: {e}")))?;
        self.ensure_room(u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
        self.put_counted(&bytes).await?;
        self.persist_record().await?;
        self.resyncs
            .note(principal_id.clone(), resync.id.clone(), pop.clone());
        if !promote {
            return Ok(receipt(true, false));
        }

        let head = after.heads.first().cloned().unwrap_or_default();
        let rivals = self.branches.retained(principal_id);
        let by_pr: HashMap<(u64, &str), &Retained> = rivals
            .iter()
            .map(|r| ((r.tip.sequence, r.pr.as_str()), r))
            .collect();
        let rival = rivals.iter().find(|r| r.tip.tip == head).ok_or_else(|| {
            EngineError::Indexer(crate::index::IndexerError::Consistency(format!(
                "the head {head} of {principal_id} is neither the chain's tip nor retained"
            )))
        })?;
        // A line this call carried whole was applied once already, to verify
        // it: the commits it built are the chain's, so the line is not
        // replayed again and n commits cost n applications. A line that
        // reaches back into commits already retained is replayed.
        let retained_line = retained_line(&by_pr, rival);
        let (line, mut line_commits) = if built.len() == retained_line.len()
            && built.last().and_then(|c| c.commit_ids.first()) == Some(&head)
        {
            (retained_line, built)
        } else {
            let replayed = self
                .replay_line(principal_id, &genesis, &stored, &by_pr, rival)
                .await?
                .ok_or_else(|| {
                    EngineError::MalformedBlob(format!(
                        "the retained line to {head} no longer replays"
                    ))
                })?;
            (replayed.line, replayed.line_commits)
        };
        self.promote_branch(principal_id, &line, &mut line_commits, None)
            .await?;
        Ok(receipt(true, true))
    }

    /// The resync PoPs held for `principal_id`, one per asserted tip, as
    /// the `{pay, sig}` coz each arrived in: what a peer fetches to reach
    /// the same verdict ([`Self::submit_resync`]).
    pub async fn resyncs(
        &self,
        principal_id: &PrincipalGenesis,
    ) -> Result<Vec<serde_json::Value>, EngineError> {
        let principal_id = self.canonical_principal_id(principal_id).await?;
        Ok(self.resyncs.proofs(&principal_id))
    }
}
