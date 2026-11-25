//! # Rebuild
//!
//! Re-deriving the index and every cache from the blob store: the manifest
//! scan that heals a crash window, the fork-aware choice of each
//! principal's canonical chain, and the report of what it left out. A pass
//! over the other concerns' state, owning none of it but the heal gate.

use std::collections::HashMap;

use super::*;

/// Set once the engine has healed its index ([`StorageEngine::ensure_healed`]):
/// per instance rather than per backend, since another instance over the
/// same backends has its own crash window to close.
#[derive(Debug, Default)]
pub(super) struct HealGate(tokio::sync::OnceCell<()>);

impl HealGate {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Run `heal` if it has not yet succeeded; a failure is not cached, so
    /// the next call retries.
    async fn once<F, Fut>(&self, heal: F) -> Result<(), EngineError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), EngineError>>,
    {
        self.0.get_or_try_init(heal).await?;
        Ok(())
    }

    /// Record that a rebuild from scratch healed the index.
    fn mark(&self) {
        let _already_healed = self.0.set(());
    }
}
/// Why a stored manifest was left out of a rebuilt index.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineReason {
    /// The manifest blob is not a well-formed manifest.
    Malformed(String),
    /// The manifest names blobs the store does not hold.
    Unsupported(String),
    /// The manifest is not bound to the principal it names.
    Unbound(String),
    /// Indexing it would re-point an exclusive claim (a PG alias).
    Conflict(String),
    /// A different commit holds this manifest's chain position
    /// `(principal, sequence)`: a commit that extends a held commit but
    /// lost the canonical walk and is not kept as a branch. Fork evidence
    /// (I2), kept out of the index.
    Fork(String),
    /// An earlier commit of the same principal was quarantined, so indexing
    /// this one would leave a gap in the chain.
    Orphaned(String),
    /// Replaying the manifest's blobs onto its principal does not yield the
    /// commit the manifest records (only a rebuild from scratch replays).
    Unreplayable(String),
}

/// A manifest a rebuild left out, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedManifest {
    /// BLAKE3 hash of the manifest blob.
    pub manifest: Blake3Hash,
    /// The principal id the manifest claims, when it parsed far enough.
    pub principal_id: Option<String>,
    /// Why it was left out.
    pub reason: QuarantineReason,
}

/// What a rebuild did: how many manifests it indexed, and which it
/// quarantined. A quarantined manifest never fails the rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildReport {
    /// Manifests indexed (including those already indexed).
    pub indexed: usize,
    /// Manifests left out, in canonical order.
    pub quarantined: Vec<QuarantinedManifest>,
}

/// Every PR a stored manifest records, by principal and position: the
/// commits a rebuild holds, canonical or not.
pub(super) type HeldRoots = std::collections::HashSet<(String, u64, String)>;

/// The stored manifests split by [`walk_chains`].
pub(super) struct Walk {
    /// Each principal's canonical commits, in canonical order (sequence,
    /// then principal id, then manifest hash).
    pub(super) canonical: Vec<(Blake3Hash, CommitManifest)>,
    /// Every other manifest: candidates for a retained branch.
    pub(super) rest: Vec<(Blake3Hash, CommitManifest)>,
}

/// Choose each principal's canonical chain from its stored commit and
/// branch manifests, the blobs alone deciding (I1).
///
/// A fork is resolved by a commit whose `pre` is the tip of the chosen
/// branch (SPEC 15.8), recorded as an ordinary commit manifest while the
/// chosen rival keeps its branch manifest; no other record exists. So the
/// walk starts at the principal's highest commit manifest (the first in
/// hash order when several share it) and goes down: the canonical commit
/// at each position is the one whose PR the canonical successor's `pre`
/// names, a commit manifest before a branch manifest and then hash order
/// among equals. A position the successor names nothing at falls back to
/// its first commit manifest, as an unresolved chain always did.
///
/// Which of two branches that both continue is canonical is not decided
/// here (see [`in_error`]); the hash-order head stays served. A principal
/// with held resync PoPs (`asserted`, by principal id) that the fork rule
/// leaves Active is walked from the head the rule names instead: the
/// asserted line is the chain, whatever positions other branches reach.
///
/// Principals in `unbound` are not walked: their commit manifests pass
/// through unchanged, to be quarantined by the caller.
pub(super) fn walk_chains(
    commits: Vec<(Blake3Hash, CommitManifest)>,
    branches: Vec<(Blake3Hash, CommitManifest)>,
    unbound: &HashMap<String, String>,
    asserted: &Resyncs,
) -> Walk {
    use std::collections::BTreeMap;

    type Position = Vec<(bool, Blake3Hash, CommitManifest)>;
    let mut by_principal: BTreeMap<String, BTreeMap<u64, Position>> = BTreeMap::new();
    let tagged = commits
        .into_iter()
        .map(|(h, m)| (false, h, m))
        .chain(branches.into_iter().map(|(h, m)| (true, h, m)));
    for (branch, hash, manifest) in tagged {
        by_principal
            .entry(manifest.commit.principal_id.clone())
            .or_default()
            .entry(manifest.commit.sequence)
            .or_default()
            .push((branch, hash, manifest));
    }

    let mut walk = Walk {
        canonical: Vec::new(),
        rest: Vec::new(),
    };
    let extends = |successor: &CommitManifest, held: &CommitManifest| {
        successor
            .commit
            .pre
            .as_ref()
            .is_some_and(|pre| held.commit.prs.contains(pre))
    };
    for (principal_id, mut positions) in by_principal {
        for held in positions.values_mut() {
            held.sort_by_key(|(branch, hash, _)| (*branch, *hash.as_bytes()));
        }
        let walked = !unbound.contains_key(&principal_id);
        // The head the fork rule names, where PoPs are held and it is
        // Active.
        let head = Some(asserted.asserted(&principal_id))
            .filter(|prs| walked && !prs.is_empty())
            .and_then(|prs| {
                let held: Vec<Held> = positions
                    .values()
                    .flatten()
                    .map(|(_, _, m)| held_of(&m.commit))
                    .collect();
                let a = assessment(&held, &prs);
                match (a.consensus, a.heads.as_slice()) {
                    (Consensus::Active, [head]) => Some(head.clone()),
                    _ => None,
                }
            });
        let mut chosen: HashMap<u64, usize> = HashMap::new();
        if walked {
            let mut successor: Option<&CommitManifest> = None;
            for (&sequence, held) in positions.iter().rev() {
                let named = successor.filter(|s| s.commit.sequence == sequence + 1);
                let at_head = |m: &CommitManifest| {
                    head.as_ref()
                        .is_some_and(|h| m.commit.commit_ids.first() == Some(h))
                };
                // Above the named head no position is on the chain.
                let pick = if successor.is_none() && head.is_some() {
                    held.iter().position(|(_, _, m)| at_head(m))
                } else {
                    named
                        .and_then(|s| held.iter().position(|(_, _, m)| extends(s, m)))
                        .or_else(|| held.iter().position(|(branch, ..)| !branch))
                };
                if let Some(at) = pick {
                    chosen.insert(sequence, at);
                    successor = Some(&held[at].2);
                }
            }
        }
        for (sequence, held) in positions {
            for (at, (branch, hash, manifest)) in held.into_iter().enumerate() {
                let canonical = if walked {
                    chosen.get(&sequence) == Some(&at)
                } else {
                    !branch
                };
                if canonical {
                    walk.canonical.push((hash, manifest));
                } else {
                    walk.rest.push((hash, manifest));
                }
            }
        }
    }
    walk.canonical.sort_by(|(ha, a), (hb, b)| {
        (a.commit.sequence, &a.commit.principal_id, ha.as_bytes()).cmp(&(
            b.commit.sequence,
            &b.commit.principal_id,
            hb.as_bytes(),
        ))
    });
    walk
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Ensure this engine's index has no pending crash-window recovery
    /// before any of its own methods read or write against it.
    ///
    /// Implements [recovery-reindex] (docs/specs/storage-engine.md:236-241)
    /// for the "no explicit call" case: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent index write (see the
    /// crash-window doc on [`Self::rebuild_index_from_manifests`] below)
    /// must heal automatically the next time the engine is opened,
    /// without any caller remembering to invoke
    /// [`Self::rebuild_index_from_manifests`] itself. "Opened" here means
    /// construct-plus-first-use (engine constructors are synchronous, so
    /// there is no async open step to hook): this lazy once-per-instance
    /// guard runs the full manifest scan on this engine's first call into
    /// any of the methods below, and never again for the lifetime of this
    /// instance.
    ///
    /// Cost strategy: always a full [`Self::rebuild_index_from_manifests`]
    /// scan rather than a cheaper orphan-detection pre-check. Against this
    /// crate's backends the scan is already the mechanism full recovery
    /// relies on, `index_commit` is idempotent so
    /// a healthy store's scan is a pure read with no re-indexing writes,
    /// and it runs at most once per instance -- an orphan pre-check would
    /// only save a single redundant scan's read cost per process lifetime,
    /// not a recurring cost, so the simpler always-scan is what ships.
    ///
    /// Scoped to this engine's own methods: [`Self::indexer`] and
    /// [`Self::blob_store`] are raw accessors that bypass this gate by
    /// design (see their docs) -- a caller reaching the backends directly
    /// is outside the invariant this method closes.
    ///
    /// A heal failure surfaces as an `EngineError` from the caller's first
    /// call, same as any other engine error -- not a swallowed or
    /// reordered error, and not a public-error-contract change. The guard
    /// is left uninitialized on error (`get_or_try_init` does not cache
    /// failures), so the next call retries rather than wedging this
    /// instance in a permanently-failed state.
    pub(super) async fn ensure_healed(&self) -> Result<(), EngineError> {
        // Type-erased: every read and write passes through here, and the
        // rebuild below reaches back to them, so the compiler's auto-trait
        // check would otherwise cycle through this future.
        let heal: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), EngineError>> + Send + '_>,
        > = Box::pin(async { self.rebuild_index_from_manifests().await.map(|_| ()) });
        self.healed.once(|| heal).await
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, returning how many were indexed.
    /// [`Self::rebuild_index_with_report`] is the same pass with the
    /// quarantined manifests named.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_manifests(&self) -> Result<usize, EngineError> {
        let report = self.rebuild_index_with_report().await?;
        for q in &report.quarantined {
            tracing::warn!(
                manifest = %q.manifest,
                principal = ?q.principal_id,
                reason = ?q.reason,
                "manifest quarantined: left out of the index"
            );
        }
        Ok(report.indexed)
    }

    /// Scan the blob store for [`CommitManifest`] blobs and (re-)index each
    /// one, idempotently, quarantining any it cannot index.
    ///
    /// Closes the ingest crash window: a crash between
    /// [`Self::store_blobs_and_manifest`]'s manifest write and
    /// [`Self::ingest_commit`]'s subsequent `indexer.index_commit` call
    /// leaves a manifest durably stored with no index entry yet; this
    /// completes the index write from the manifest's already-resolved
    /// `IndexableCommit`. It also serves full reconstruction: clearing the
    /// index and calling this rebuilds every manifest-backed commit from
    /// the blob store alone (root `AGENTS.md` invariant I1).
    ///
    /// **The index is a function of the blob set.** Manifests are indexed
    /// in canonical order (sequence, then principal id, then manifest
    /// hash), never the blob store's listing order, and every index write
    /// is order-independent (digests name sets of holders). The one
    /// exclusive claim is a principal's PG alias: if two manifests contest
    /// one, the earlier in canonical order wins.
    ///
    /// **A manifest the index cannot take never fails the rebuild.** It is
    /// quarantined with a typed [`QuarantineReason`] (malformed, naming
    /// blobs the store lacks, not bound to its principal, contesting a
    /// PG alias, or rivalling a commit already at its chain position), and so are that principal's
    /// later commits, so no chain is indexed with a gap. Backend failures and a manifest-shaped
    /// wire blob ([`EngineError::LegacyManifest`]) still fail the rebuild.
    ///
    /// This does not replay: it trusts the engine-written manifests plus
    /// the blob-presence and binding checks. The replaying rebuild is
    /// [`Self::rebuild_index_from_scratch_with_report`].
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_with_report(&self) -> Result<RebuildReport, EngineError> {
        self.rebuild_pass(false).await
    }

    /// The rebuild pass. With `replay`, every manifest's blobs are also
    /// replayed onto its principal from genesis by the admission path
    /// ([`Self::build_commit`]), and a manifest whose commit the replay
    /// does not reproduce is quarantined ([`QuarantineReason::Unreplayable`]).
    pub(super) async fn rebuild_pass(&self, replay: bool) -> Result<RebuildReport, EngineError> {
        self.kept.clear();
        self.branches.clear_forks();
        self.rebuild_pass_on(&self.indexer, replay).await
    }

    /// [`Self::rebuild_pass`] building into `index` rather than the
    /// engine's own, so a scan can run without touching the real index.
    pub(super) async fn rebuild_pass_on<X: Indexer + IndexerWrite>(
        &self,
        index: &X,
        replay: bool,
    ) -> Result<RebuildReport, EngineError> {
        let iter = self.blob_store.iter().await?;
        let hashes: Vec<Blake3Hash> = iter.collect::<Result<Vec<_>, _>>()?;

        let mut quarantined = Vec::new();
        // The earliest sequence at which a principal's chain broke, for any
        // reason; every later commit of that principal is orphaned, so the
        // indexed chain is always a gapless prefix.
        let mut broken_from: HashMap<String, u64> = HashMap::new();
        let mut manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut branch_manifests: Vec<(Blake3Hash, CommitManifest)> = Vec::new();
        let mut action_manifests: Vec<(Blake3Hash, ActionManifest)> = Vec::new();
        let mut revoked = Revoked::default();
        let mut resyncs = Resyncs::default();
        for hash in hashes {
            let Some(data) = self.blob_store.get(&hash).await? else {
                continue;
            };
            if let Some(json) = data.strip_prefix(RESYNC_RECORD_PREFIX) {
                // A record that does not verify costs only itself: its tip
                // is not asserted.
                let checked = serde_json::from_slice::<ResyncRecord>(json)
                    .map_err(|e| e.to_string())
                    .and_then(|r| r.check().map(|()| r));
                match checked {
                    Ok(r) => {
                        resyncs.note(r.principal_id, r.tip, r.evidence);
                    },
                    Err(why) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(format!("resync record: {why}")),
                    }),
                }
                continue;
            }
            if data.starts_with(REVOKE_RECORD_V1_PREFIX) {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: None,
                    reason: QuarantineReason::Malformed(
                        "a v1 revoke record carries no receipt time".into(),
                    ),
                });
                continue;
            }
            if let Some(json) = data.strip_prefix(REVOKE_RECORD_PREFIX) {
                // The revoke a record carries is re-verified, never
                // trusted; its receipt time is this node's own statement.
                // One that fails costs only itself. That includes a record
                // an earlier build accepted that the current rule refuses
                // (an over-size revoke): it is quarantined here and its key
                // is not dead in the engine, so the warning below names it.
                let record = serde_json::from_slice::<RevokeRecord>(json);
                let verified = match &record {
                    Ok(r) => verify_revoke(&r.evidence).map(|tmb| (tmb, r.wrt)),
                    Err(e) => Err(e.to_string()),
                };
                if let Err(why) = &verified {
                    // A record that no longer verifies (for one, a v2
                    // record over the revoke size limit) leaves its key
                    // alive in the engine, so the log names the key.
                    let key = record
                        .as_ref()
                        .ok()
                        .and_then(|r| cyphr::parsed_coz::CozHeader::parse(&r.evidence["pay"]).ok())
                        .map_or_else(|| "unreadable".to_owned(), |h| h.tmb.to_b64());
                    tracing::warn!(
                        key = %key,
                        reason = %why,
                        "revoke record quarantined on rebuild; its key is not dead in the engine"
                    );
                }
                match verified {
                    // Live keeps one record per key, the first accepted;
                    // were there two, the earliest receipt stands.
                    Ok((tmb, wrt)) => {
                        revoked.note(tmb, Death::new(wrt, *hash.as_bytes()));
                    },
                    Err(why) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(format!("revoke record: {why}")),
                    }),
                }
                continue;
            }
            if let Some(json) = data.strip_prefix(ACTION_MANIFEST_PREFIX) {
                // Actions are not chained: a bad action manifest costs only
                // itself.
                match serde_json::from_slice::<ActionManifest>(json) {
                    Ok(m) if m.kind == ACTION_MANIFEST_KIND => action_manifests.push((hash, m)),
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "action manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            if let Some(json) = data.strip_prefix(BRANCH_MANIFEST_PREFIX) {
                // Retained branches never reach the index, so a bad one
                // costs only its own listing, never a chain position.
                match serde_json::from_slice::<CommitManifest>(json) {
                    Ok(m) if m.kind == BRANCH_MANIFEST_KIND => {
                        match self.check_manifest_supported(&hash, &m).await? {
                            Ok(()) => branch_manifests.push((hash, m)),
                            Err(reason) => quarantined.push(QuarantinedManifest {
                                manifest: hash,
                                principal_id: Some(m.commit.principal_id.clone()),
                                reason,
                            }),
                        }
                    },
                    Ok(m) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(m.commit.principal_id),
                        reason: QuarantineReason::Malformed(format!(
                            "branch manifest of kind {}",
                            m.kind
                        )),
                    }),
                    Err(e) => quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    }),
                }
                continue;
            }
            let Some(json) = data.strip_prefix(COMMIT_MANIFEST_PREFIX) else {
                // The engine's own keyspace under a version this build does
                // not know: skipping it would report a clean store with
                // whatever it records missing (R6), so it is quarantined.
                if data.starts_with(ENGINE_BLOB_NAMESPACE) {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Unsupported(
                            "an engine blob of a version this build does not know".into(),
                        ),
                    });
                    continue;
                }
                // A wire blob. One shaped like a manifest cannot have been
                // written by this engine (it stores wire cozes in canonical
                // form only), so it is an old shared-store manifest or a
                // forged coz, and nothing here can tell which.
                if is_legacy_manifest(&data) {
                    return Err(EngineError::LegacyManifest { hash });
                }
                continue;
            };
            let manifest: CommitManifest = match serde_json::from_slice(json) {
                Ok(m) => m,
                Err(e) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: None,
                        reason: QuarantineReason::Malformed(e.to_string()),
                    });
                    continue;
                },
            };
            if let Err(reason) = self.check_manifest_supported(&hash, &manifest).await? {
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason,
                });
                continue;
            }
            manifests.push((hash, manifest));
        }

        manifests.sort_by(|(ha, a), (hb, b)| {
            (a.commit.sequence, &a.commit.principal_id, ha.as_bytes()).cmp(&(
                b.commit.sequence,
                &b.commit.principal_id,
                hb.as_bytes(),
            ))
        });

        // A key a held commit revokes by its own signature is dead from the
        // receipt of that commit, on every branch: derived from the
        // manifests, which record when each was first seen (I1).
        for (hash, manifest) in manifests.iter().chain(&branch_manifests) {
            for tmb in self_revoked_keys(&manifest.commit) {
                revoked.note(
                    tmb.to_owned(),
                    Death::new(manifest.seen.unwrap_or_default(), *hash.as_bytes()),
                );
            }
        }
        let unbound = self.unbound_principals(&manifests).await?;
        for (hash, manifest) in &manifests {
            if let Some(why) = unbound.get(&manifest.commit.principal_id) {
                quarantined.push(QuarantinedManifest {
                    manifest: *hash,
                    principal_id: Some(manifest.commit.principal_id.clone()),
                    reason: QuarantineReason::Unbound(why.clone()),
                });
                broken_from
                    .entry(manifest.commit.principal_id.clone())
                    .and_modify(|from| *from = (*from).min(manifest.commit.sequence))
                    .or_insert(manifest.commit.sequence);
            }
        }

        let Walk {
            canonical: manifests,
            rest: branch_manifests,
        } = walk_chains(manifests, branch_manifests, &unbound, &resyncs);
        let held: HeldRoots = manifests
            .iter()
            .chain(&branch_manifests)
            .flat_map(|(_, m)| {
                m.commit
                    .prs
                    .iter()
                    .map(|pr| (m.commit.principal_id.clone(), m.commit.sequence, pr.clone()))
            })
            .collect();

        let mut indexed = 0;
        // One memo for the whole rebuild: each embedded principal is replayed
        // once, whatever number of commits and actions pin it.
        let pins = PinSource::manifests(&manifests, &branch_manifests);
        let mut replays: HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>> =
            HashMap::new();
        // What the last replaying rebuild quarantined: a pass that does
        // not replay cannot judge those manifests, so it keeps them out.
        let skip: HashMap<Blake3Hash, String> = if replay {
            HashMap::new()
        } else {
            index.quarantined().await?.into_iter().collect()
        };
        let histories = self
            .read_action_manifests(action_manifests, &skip, &mut quarantined)
            .await?;
        for (hash, manifest) in &manifests {
            let hash = *hash;
            let commit = &manifest.commit;
            if unbound.contains_key(&commit.principal_id) {
                continue;
            }
            if broken_from
                .get(&commit.principal_id)
                .is_some_and(|from| commit.sequence > *from)
            {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Orphaned(
                        "an earlier commit of this principal was quarantined".into(),
                    ),
                });
                continue;
            }
            let refused = match skip.get(&hash) {
                Some(why) => Err(format!("quarantined by the last scratch rebuild: {why}")),
                None if replay => self.replay_manifest(&mut replays, manifest, &pins).await?,
                None => Ok(()),
            };
            if let Err(why) = refused {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason: QuarantineReason::Unreplayable(why),
                });
                broken_from
                    .entry(commit.principal_id.clone())
                    .or_insert(commit.sequence);
                continue;
            }
            let mut written = index.index_commit(commit, &DeriveToken::new()).await;
            if let Err(crate::index::IndexerError::Consistency(_)) = written {
                // The index holds another commit here: it was built before
                // the fork was resolved, and the chain is re-pointed.
                written = index
                    .replace_chain_from(
                        &commit.principal_id,
                        commit.sequence,
                        std::slice::from_ref(commit),
                        &DeriveToken::new(),
                    )
                    .await;
            }
            match written {
                Ok(()) => {
                    self.record_frame(commit, &manifest.shape, manifest.seen, &manifest.embedded);
                    indexed += 1;
                },
                Err(crate::index::IndexerError::Conflict(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Conflict(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(crate::index::IndexerError::Consistency(why)) => {
                    quarantined.push(QuarantinedManifest {
                        manifest: hash,
                        principal_id: Some(commit.principal_id.clone()),
                        reason: QuarantineReason::Fork(why),
                    });
                    broken_from
                        .entry(commit.principal_id.clone())
                        .or_insert(commit.sequence);
                },
                Err(e) => return Err(e.into()),
            }
        }

        // Actions hold no chain position: each principal's are recorded
        // once its chain is in, judged at their own `now` against the key
        // history (SPEC 6.5). The naked revokes are not in force: a stored
        // action was admitted when it arrived, and a revoke gates only what
        // arrives after it (SPEC 14.12). A replaying pass keeps the ones its
        // replay accepts; one that does not replay keeps those of a
        // principal the index holds.
        let mut actions: HashMap<String, Vec<StoredActions>> = HashMap::new();
        for (principal_id, history) in histories {
            let mut orphaned = |bundle: ActionBundle, reason| {
                quarantined.push(QuarantinedManifest {
                    manifest: bundle.manifest,
                    principal_id: Some(principal_id.clone()),
                    reason,
                });
            };
            if replay {
                let Some(principal) = replays.get_mut(&principal_id) else {
                    for bundle in history {
                        orphaned(
                            bundle,
                            QuarantineReason::Orphaned("its principal has no chain".into()),
                        );
                    }
                    continue;
                };
                for bundle in history {
                    if let Err(e) = self
                        .apply_pins(principal, &pins, &bundle.embedded, EMBED_DEPTH)
                        .await
                    {
                        orphaned(bundle, QuarantineReason::Unreplayable(e.to_string()));
                        continue;
                    }
                    match cyphr::replay::replay_held(principal, &bundle.bundle).await {
                        Ok(_) => actions
                            .entry(principal_id.clone())
                            .or_default()
                            .push(bundle.stored()),
                        Err(e) => orphaned(bundle, QuarantineReason::Unreplayable(e.to_string())),
                    }
                }
            } else if index.get_tip(&principal_id).await?.is_some() {
                actions
                    .entry(principal_id.clone())
                    .or_default()
                    .extend(history.into_iter().map(|b| b.stored()));
            } else {
                for bundle in history {
                    orphaned(
                        bundle,
                        QuarantineReason::Orphaned("its principal has no chain".into()),
                    );
                }
            }
        }
        self.actions.replace(actions);

        let branches = self
            .classify_branches(branch_manifests, &held, &mut quarantined)
            .await?;
        self.branches.replace(branches);
        self.deaths.replace(revoked);
        self.resyncs.replace(resyncs);

        quarantined.sort_by_key(|q| *q.manifest.as_bytes());
        Ok(RebuildReport {
            indexed,
            quarantined,
        })
    }

    /// Read back the scanned action manifests' bundles by principal,
    /// quarantining any whose blobs are missing or are not an
    /// action-only bundle, and, in a pass that does not replay, any the
    /// last scratch rebuild quarantined (`skip`).
    pub(super) async fn read_action_manifests(
        &self,
        manifests: Vec<(Blake3Hash, ActionManifest)>,
        skip: &HashMap<Blake3Hash, String>,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, ActionHistory>, EngineError> {
        let mut histories: HashMap<String, ActionHistory> = HashMap::new();
        'manifests: for (hash, manifest) in manifests {
            let mut reject = |reason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(manifest.principal_id.clone()),
                    reason,
                });
            };
            if let Some(why) = skip.get(&hash) {
                reject(QuarantineReason::Unreplayable(format!(
                    "quarantined by the last scratch rebuild: {why}"
                )));
                continue;
            }
            let mut blobs = Vec::with_capacity(manifest.blob_hashes.len());
            for blob in &manifest.blob_hashes {
                let Some(data) = self.blob_store.get(blob).await? else {
                    reject(QuarantineReason::Unsupported(format!(
                        "action manifest {hash} names blob {blob}, which is not stored"
                    )));
                    continue 'manifests;
                };
                blobs.push(data);
            }
            match action_bundle(blobs) {
                Ok(bundle) => histories
                    .entry(manifest.principal_id.clone())
                    .or_default()
                    .push(ActionBundle {
                        manifest: hash,
                        blobs: manifest.blob_hashes,
                        embedded: manifest.embedded,
                        bundle,
                    }),
                Err(why) => reject(QuarantineReason::Malformed(format!(
                    "action manifest {hash}: {why}"
                ))),
            }
        }
        for bundles in histories.values_mut() {
            replay_order(bundles);
        }
        Ok(histories)
    }

    /// Decide which stored manifests the canonical walk left out
    /// ([`walk_chains`]) are branches of the index just rebuilt. A branch is
    /// kept only if it forks the canonical chain: the canonical commit at
    /// its position exists and is a different commit, and its `pre` is the
    /// canonical parent's PR or the PR of a branch kept one position below
    /// (a branch extending a branch, as an unresolved fork's two extended
    /// heads leave). The rest are quarantined.
    ///
    /// The index is already final when this runs and is never read to
    /// decide the canonical chain here, so the result is a function of the
    /// blob set: manifests are taken by position, then in hash order, which
    /// fixes the order a branch can extend a kept branch. The retention
    /// caps ([`BRANCH_LIMIT`]) are admission rules and are not applied
    /// here.
    pub(super) async fn classify_branches(
        &self,
        mut branch_manifests: Vec<(Blake3Hash, CommitManifest)>,
        held: &HeldRoots,
        quarantined: &mut Vec<QuarantinedManifest>,
    ) -> Result<HashMap<String, Vec<Retained>>, EngineError> {
        branch_manifests.sort_by_key(|(hash, m)| (m.commit.sequence, *hash.as_bytes()));
        let mut kept: HashMap<String, Vec<Retained>> = HashMap::new();
        // The PRs of the branches kept so far, by principal and position.
        let mut kept_prs: std::collections::HashSet<(String, u64, String)> =
            std::collections::HashSet::new();
        for (hash, manifest) in branch_manifests {
            let CommitManifest {
                commit,
                shape,
                kind,
                seen,
                embedded,
            } = manifest;
            let tip = commit.commit_ids.first().cloned().unwrap_or_default();
            // A commit manifest that lost the canonical walk but extends a
            // held commit is fork evidence: whatever keeps it out of the
            // branch table, it is reported as a fork, never as damage.
            let fork = kind == COMMIT_MANIFEST_KIND
                && match &commit.pre {
                    None => commit.sequence == 0,
                    Some(pre) => commit.sequence.checked_sub(1).is_some_and(|below| {
                        held.contains(&(commit.principal_id.clone(), below, pre.clone()))
                    }),
                };
            let unless_fork = |why: String, otherwise: fn(String) -> QuarantineReason| {
                if fork {
                    QuarantineReason::Fork(why)
                } else {
                    otherwise(why)
                }
            };
            let mut reject = |reason: QuarantineReason| {
                quarantined.push(QuarantinedManifest {
                    manifest: hash,
                    principal_id: Some(commit.principal_id.clone()),
                    reason,
                });
            };
            let from = commit.sequence.saturating_sub(1);
            let chain = self
                .chain(&commit.principal_id, Some(from), Some(commit.sequence))
                .await?;
            // A branch past the canonical head (refused while the principal
            // was in Error) has no canonical commit at its position; its
            // `pre` still must name the head or a kept branch, below.
            let canonical = chain.iter().find(|c| c.sequence == commit.sequence);
            if canonical.is_some_and(|c| c.commit_id == tip) {
                reject(QuarantineReason::Conflict(
                    "branch is the canonical commit at its position".into(),
                ));
                continue;
            }
            let parent = chain.iter().find(|c| c.sequence + 1 == commit.sequence);
            let on_branch = |pre: &String| {
                commit.sequence > 0
                    && kept_prs.contains(&(
                        commit.principal_id.clone(),
                        commit.sequence - 1,
                        pre.clone(),
                    ))
            };
            if commit.pre.as_ref() != parent.map(|c| &c.pr)
                && !commit.pre.as_ref().is_some_and(on_branch)
            {
                reject(unless_fork(
                    "branch's pre is not the canonical parent's PR".into(),
                    QuarantineReason::Orphaned,
                ));
                continue;
            }
            let of_principal = kept.entry(commit.principal_id.clone()).or_default();
            if of_principal
                .iter()
                .any(|b| b.tip.tip == tip && b.tip.sequence == commit.sequence)
            {
                continue;
            }
            let signer = commit_signer(&commit);
            // No quota here: the caps bound what ingest admits, and a
            // promotion retains its displaced commits past them, so a
            // quota in the rebuild would drop a once-canonical commit the
            // live store keeps (I1).
            for pr in &commit.prs {
                kept_prs.insert((commit.principal_id.clone(), commit.sequence, pr.clone()));
            }
            of_principal.push(Retained {
                pr: commit.prs.first().cloned().unwrap_or_default(),
                signed: signed_of(&commit),
                tip: BranchTip {
                    tip,
                    pre: commit.pre,
                    sequence: commit.sequence,
                    canonical: false,
                    seen,
                },
                signer,
                keys: key_entries(&commit.keys),
                blobs: commit.blob_hashes,
                shape,
                embedded,
            });
        }
        Ok(kept)
    }

    /// A corruption detector, not a security boundary. Without replay: the
    /// genesis a principal's first sequence-0 manifest (in canonical
    /// order) discloses in its blobs ([`disclosed_genesis`]) must derive
    /// the principal id the manifests carry ([`record_key`]). Returns each failing principal with
    /// why; they are quarantined.
    ///
    /// Scope: a principal whose blobs disclose no genesis is not judged
    /// here (the replaying rebuild quarantines it), and when several
    /// sequence-0 manifests claim one id only the first is checked. The
    /// guarantee that a forged manifest cannot re-point a principal comes
    /// from the manifest keyspace plus the single writer
    /// ([`COMMIT_MANIFEST_PREFIX`], [`canonical_coz`]), not from this
    /// check.
    pub(super) async fn unbound_principals(
        &self,
        manifests: &[(Blake3Hash, CommitManifest)],
    ) -> Result<HashMap<String, String>, EngineError> {
        let mut firsts: HashMap<&str, &CommitManifest> = HashMap::new();
        for (_, manifest) in manifests {
            if manifest.commit.sequence == 0 {
                firsts
                    .entry(&manifest.commit.principal_id)
                    .or_insert(manifest);
            }
        }
        let mut unbound = HashMap::new();
        let mut principals: Vec<&str> = manifests
            .iter()
            .map(|(_, m)| m.commit.principal_id.as_str())
            .collect();
        principals.sort_unstable();
        principals.dedup();
        for principal_id in principals {
            let Some(first) = firsts.get(principal_id) else {
                unbound.insert(
                    principal_id.to_string(),
                    "no sequence-0 manifest for the principal".to_string(),
                );
                continue;
            };
            let bundle = self.manifest_bundle(first).await?;
            // Without a disclosed genesis the id cannot be proven from
            // blobs; this pass does not judge it (the replaying rebuild
            // quarantines it).
            let genesis = match disclosed_genesis(&bundle) {
                Some(Ok(genesis)) => genesis,
                None => continue,
                Some(Err(e)) => {
                    unbound.insert(
                        principal_id.to_string(),
                        format!("genesis not derivable from its blobs: {e}"),
                    );
                    continue;
                },
            };
            // The key is a function of the record (I1: not of what a
            // manifest claims), so that one commit is replayed, not the
            // chain ([`record_key`]).
            let derived = record_key(&genesis, &bundle).await;
            // Strict by decision: the project is pre-1.0 with nothing
            // deployed, so a store keyed by a PG-to-be exists only in test
            // runs and needs no lenient branch.
            if derived.as_deref() != Some(principal_id) {
                unbound.insert(
                    principal_id.to_string(),
                    "its first commit does not derive this id as its key".to_string(),
                );
            }
        }
        Ok(unbound)
    }

    /// Replay `commit`'s blobs onto its principal (`replays` holds each
    /// principal's state, advanced manifest by manifest in sequence order)
    /// and compare the commit the admission path builds with the one the
    /// manifest records. `Ok(Err(why))` is a manifest to quarantine.
    ///
    /// A principal is replayed from the genesis its sequence-0 blobs
    /// disclose ([`disclosed_genesis`]): every chain begins with a genesis
    /// commit (SPEC 5.1), so one that discloses none is quarantined.
    pub(super) async fn replay_manifest(
        &self,
        replays: &mut HashMap<String, cyphr::Principal<cyphr::eml::MemoryStorage>>,
        manifest: &CommitManifest,
        pins: &PinSource<'_>,
    ) -> Result<Result<(), String>, EngineError> {
        let commit = &manifest.commit;
        let bundle = self.manifest_bundle(manifest).await?;
        let principal = match replays.entry(commit.principal_id.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let Some(genesis) = disclosed_genesis(&bundle) else {
                    return Ok(Err("its first commit discloses no genesis".into()));
                };
                let opened = match genesis {
                    Ok(genesis) => {
                        Self::principal_from_genesis(genesis, cyphr::eml::MemoryStorage::new())
                            .await
                    },
                    Err(e) => Err(e),
                };
                match opened {
                    Ok(principal) => e.insert(principal),
                    Err(e) => return Ok(Err(format!("genesis does not replay: {e}"))),
                }
            },
        };
        // The embedded principals the commit was admitted through are
        // replayed from the manifests themselves: the index that would
        // serve them is being rebuilt.
        if let Err(e) = self
            .apply_pins(principal, pins, &manifest.embedded, EMBED_DEPTH)
            .await
        {
            return Ok(Err(format!("an embedded principal does not replay: {e}")));
        }
        let built =
            Self::build_commit(principal, &bundle, &commit.principal_id, commit.sequence).await;
        let StagedBuild {
            commit: mut replayed,
            staged,
            ..
        } = match built {
            Ok(Some(build)) => build,
            Ok(None) => return Ok(Err("its blobs form no commit".into())),
            Err(e) => return Ok(Err(format!("its blobs do not replay: {e}"))),
        };
        if let Err(e) = staged.commit().await {
            return Ok(Err(format!("its blobs do not replay: {e}")));
        }
        // `store_manifest` fills these in at ingest.
        replayed.blob_hashes.clone_from(&commit.blob_hashes);
        for (coz, hash) in replayed.cozies.iter_mut().zip(&commit.blob_hashes) {
            coz.blob_hash = *hash;
        }
        let same = serde_json::to_value(&replayed).ok() == serde_json::to_value(commit).ok();
        Ok(if same {
            Ok(())
        } else {
            Err("it records a commit its blobs do not yield".into())
        })
    }

    /// The bundle a commit manifest records: its blobs grouped by its
    /// shape, with the keys its commit introduced.
    pub(super) async fn manifest_bundle(
        &self,
        manifest: &CommitManifest,
    ) -> Result<WireBundle, EngineError> {
        let blobs = self.read_blobs(&manifest.commit.blob_hashes).await?;
        manifest
            .shape
            .group(blobs, key_entries(&manifest.commit.keys))
            .ok_or_else(|| {
                EngineError::MalformedBlob(
                    "a commit manifest's shape groups a different number of blobs".into(),
                )
            })
    }

    /// Discard the index and rebuild it from every durable manifest.
    ///
    /// The full-recovery form of [`Self::rebuild_index_from_manifests`]
    /// ([recovery-reindex], [recovery-convergence]): the index is a
    /// rebuildable cache of the blob store (root `AGENTS.md` I1), so
    /// clearing it first also drops any entry no manifest backs. `clear`
    /// requires a [`DeriveToken`] that only this crate can mint, which is
    /// why the clear lives here rather than at the call site.
    ///
    /// Unlike the heal pass, this rebuild trusts no manifest it can check:
    /// each principal is replayed from genesis through the admission path
    /// ([`Self::build_commit`]), manifest by manifest in sequence order, and
    /// a manifest recording a commit its blobs do not yield is quarantined
    /// ([`QuarantineReason::Unreplayable`]) with the rest of its chain, as
    /// is a principal whose sequence-0 blobs disclose no genesis (every
    /// chain begins with a genesis commit, SPEC 5.1).
    ///
    /// Known cost: the rebuild replays the whole store twice, the first
    /// time into a throwaway in-memory index (the quarantine set is
    /// written before the index is cleared, so a crash between the clear
    /// and the re-index cannot re-admit a quarantined manifest), and holds
    /// that index until the first pass ends. It is an operator-run
    /// recovery, not a request path, so the cost is accepted.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch(&self) -> Result<usize, EngineError> {
        Ok(self.rebuild_index_from_scratch_with_report().await?.indexed)
    }

    /// [`Self::rebuild_index_from_scratch`], reporting what it quarantined.
    #[tracing::instrument(skip(self))]
    pub async fn rebuild_index_from_scratch_with_report(
        &self,
    ) -> Result<RebuildReport, EngineError> {
        // The quarantine set is written before the index is cleared. It
        // derives from a replaying scan, which runs into a throwaway index
        // first: a failure after the clear and before the re-index then
        // leaves a store whose next heal, which trusts the manifests and
        // honours the set, keeps a quarantined manifest out.
        let scan = self
            .rebuild_pass_on(&crate::index::MemoryIndexer::new(), true)
            .await?;
        self.indexer
            .set_quarantined(&Self::quarantine_set(&scan), &DeriveToken::new())
            .await?;
        self.indexer.clear(&DeriveToken::new()).await?;
        let report = self.rebuild_pass(true).await?;
        self.indexer
            .set_quarantined(&Self::quarantine_set(&report), &DeriveToken::new())
            .await?;
        // This pass is a full heal: without marking it, the first read
        // would run the trusting heal pass and re-index the manifests this
        // one quarantined. Already set means a heal ran earlier, which the
        // clear above has superseded either way.
        self.healed.mark();
        Ok(report)
    }

    /// The quarantine set a rebuild report records in the index.
    pub(super) fn quarantine_set(report: &RebuildReport) -> Vec<(Blake3Hash, String)> {
        report
            .quarantined
            .iter()
            .map(|q| (q.manifest, format!("{:?}", q.reason)))
            .collect()
    }
}
