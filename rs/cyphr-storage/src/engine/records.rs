//! # Record formats
//!
//! The byte formats the engine writes into the blob store beside the wire
//! blobs: manifests of commits, branches and action bundles, and the revoke
//! and resync records. Formats only: no state lives here.
//!
//! Each format is its own keyspace behind a prefix; the prefixes extend
//! [`ENGINE_BLOB_NAMESPACE`], so a blob that begins with it and matches no
//! known prefix is a record this build cannot read.

use cyphr::replay::WireBundle;

use super::{EngineError, QuarantineReason, StorageEngine};
use crate::KeyEntry;
use crate::blob::{Blake3Hash, BlobStore};
use crate::index::{IndexableCommit, Indexer, IndexerWrite};
/// Discriminator embedded in every [`CommitManifest`]. Since manifests
/// moved behind [`COMMIT_MANIFEST_PREFIX`] it no longer separates them from
/// wire blobs; it survives as the shape of the legacy manifests
/// [`StorageEngine::rebuild_index_from_manifests`] refuses.
pub(super) const COMMIT_MANIFEST_KIND: &str = "cyphr-storage/commit-manifest/v1";

/// Marks a blob as a [`CommitManifest`]: every stored manifest is these
/// bytes followed by its JSON.
///
/// This is the manifest keyspace inside the shared blob store. A wire blob
/// can never carry it: [`canonical_coz`] re-serializes every submitted coz
/// itself, so a stored wire blob is always a JSON object and begins with
/// `{`, while the leading NUL here is not valid at the start of any JSON
/// document. Separation therefore rests on the engine's own serializer,
/// never on inspecting caller bytes for a marker (an escaped member name
/// such as `"\u006bind"` would defeat any such inspection). Chosen over a
/// second backend keyspace because `BlobStore` has out-of-tree
/// implementors; a backend keyspace is the stronger form if that trait is
/// ever widened.
pub const COMMIT_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/commit-manifest/v1\0";

/// A durable, content-addressed record of one [`ingest_commit`](StorageEngine::ingest_commit)
/// call's fully-resolved [`IndexableCommit`] — written to the blob store
/// (never only to the index) so a commit's intra-commit transaction order
/// and derived state digests survive independently of the index.
///
/// This is the signal that lets an index rebuild ([`StorageEngine::rebuild_index_from_manifests`])
/// re-derive a commit directly, without the permutation search
/// that reconstructing same-timestamp mutation order would need. Per root `AGENTS.md` invariant I1,
/// the manifest is itself blob-store content, not a new index-only source of truth.
///
/// Stored as [`COMMIT_MANIFEST_PREFIX`] followed by this struct's JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct CommitManifest {
    pub(super) kind: String,
    pub(super) commit: IndexableCommit,
    /// How the commit's blobs group into its bundle; required, so a
    /// manifest written before grouping was recorded is malformed rather
    /// than read as one transaction per coz.
    pub(super) shape: Shape,
    /// When this engine first stored the commit (Unix seconds; SPEC 15.9,
    /// "I saw this at x time"), so a rebuild serves the time the commit
    /// was seen, not the time of the rebuild. `None` in a manifest written
    /// before it was recorded.
    #[serde(default)]
    pub(super) seen: Option<i64>,
    /// The embedded principals the commit's signers were authorized
    /// through, each with the state of it this engine held at admission:
    /// this node's own statement of what it authenticated against (SPEC
    /// 10.7, 6.2). A replay judges the commit against that state, never a
    /// later one, so a rebuild reaches what the admission reached (I1).
    /// Absent in a manifest of a commit no embedded principal signed, so
    /// every manifest written before the field exists is unchanged and the
    /// manifest version is not bumped. A store holding embedded-signed
    /// objects is not readable by an earlier build: it quarantines them as
    /// unreplayable rather than judging them without their pin.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// An embedded principal B at the state an admitted commit of A was
/// judged against: `member` is the digest in A's Key Tree (B's PG or a PR
/// it held), `b` the PR B had at admission, tagged `ALG:digest`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct EmbeddedPin {
    pub(super) member: String,
    pub(super) b: String,
}

/// How a commit's blobs (`IndexableCommit::blob_hashes`, in bundle order)
/// group into its bundle: the first `actions` are its data actions, then
/// each entry of `txs` is the coz count of one transaction (SPEC 4.6.2).
/// The bundle's order is retained at ingest, never recovered (root U1).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct Shape {
    pub(super) actions: usize,
    pub(super) txs: Vec<usize>,
}

impl Shape {
    pub(super) fn of(bundle: &WireBundle) -> Self {
        Self {
            actions: bundle.actions.len(),
            txs: bundle.txs.iter().map(Vec::len).collect(),
        }
    }

    /// How many blobs the shape groups.
    pub(super) fn len(&self) -> usize {
        self.actions + self.txs.iter().sum::<usize>()
    }

    /// `blobs` grouped by this shape, with `keys`; `None` when the count
    /// differs.
    pub(super) fn group(&self, mut blobs: Vec<Vec<u8>>, keys: Vec<KeyEntry>) -> Option<WireBundle> {
        if blobs.len() != self.len() {
            return None;
        }
        let rest = blobs.split_off(self.actions);
        let mut rest = rest.into_iter();
        let txs = self
            .txs
            .iter()
            .map(|&n| rest.by_ref().take(n).collect())
            .collect();
        Some(WireBundle {
            actions: blobs,
            txs,
            keys,
        })
    }
}

/// Discriminator of a [`CommitManifest`] that records a retained branch
/// instead of a chain commit.
pub(super) const BRANCH_MANIFEST_KIND: &str = "cyphr-storage/branch-manifest/v1";

/// Marks a blob as a retained-branch manifest: these bytes followed by a
/// [`CommitManifest`]'s JSON whose `kind` is [`BRANCH_MANIFEST_KIND`].
///
/// A keyspace distinct from [`COMMIT_MANIFEST_PREFIX`] is the whole
/// mechanism: [`StorageEngine::rebuild_index_with_report`] indexes exactly
/// the blobs behind the commit prefix, so a branch can never be chosen as
/// (or flip) a principal's canonical chain whatever order manifest hashes
/// sort in. Branches are read back into the engine's branch table by the
/// same scan, never into the [`Indexer`].
pub const BRANCH_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/branch-manifest/v1\0";

/// The leading bytes of every blob the engine itself writes (each prefix
/// above extends it). A wire coz is JSON and never starts with NUL, so a
/// blob that starts with this but matches no known prefix is the engine's
/// own record in a version this build cannot read.
pub(super) const ENGINE_BLOB_NAMESPACE: &[u8] = b"\0cyphr-storage/";

/// Marks a blob as a revoke record: these bytes followed by the JSON of a
/// [`RevokeRecord`]. A keyspace of its own, as [`COMMIT_MANIFEST_PREFIX`]
/// is. A rebuild re-verifies the revoke it carries rather than trusting it.
pub const REVOKE_RECORD_PREFIX: &[u8] = b"\0cyphr-storage/revoke-record/v2\0";

/// The first revoke record version, the bare envelope with no receipt
/// time; a rebuild quarantines one rather than guess its cutoff.
pub(super) const REVOKE_RECORD_V1_PREFIX: &[u8] = b"\0cyphr-storage/revoke-record/v1\0";

/// A naked revoke this node accepted, and when: the record of a key's
/// death (SPEC 6.4).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RevokeRecord {
    /// This node's Witness Receipt Timestamp of the revoke, Unix seconds:
    /// the key's cutoff (the spec author on #203: "honor it from the
    /// witness's own receipt time"). The node's own statement in its own
    /// store, not something the revoke's signature proves.
    pub(super) wrt: i64,
    /// The verified `{pay, sig, key}` envelope as received.
    pub(super) evidence: serde_json::Value,
}

/// Marks a blob as a resync record: these bytes followed by the JSON of a
/// [`ResyncRecord`]. A keyspace of its own, as [`REVOKE_RECORD_PREFIX`] is,
/// so a PoP is never read as a commit and a rebuild finds exactly these.
pub const RESYNC_RECORD_PREFIX: &[u8] = b"\0cyphr-storage/resync-record/v1\0";

/// A resync PoP this engine accepted (SPEC 13, 15.8 item 2): the one
/// record per asserted tip. The blob is the record (I1): the in-memory set
/// of asserted PRs is rebuilt from these.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct ResyncRecord {
    /// The canonical id of the principal whose tip the PoP asserts.
    pub(super) principal_id: String,
    /// The asserted tip's PR: the coz's `id`.
    pub(super) tip: String,
    /// The verified `{pay, sig}` coz as received.
    pub(super) evidence: serde_json::Value,
    /// The signer's key as the asserted state holds it, so a rebuild can
    /// re-check the signature without replaying to the tip.
    pub(super) key: KeyEntry,
}

impl ResyncRecord {
    /// The signature check a rebuild repeats. That the signer was active
    /// at the tip was checked on acceptance; like a retained branch's
    /// manifest, the record is not replayed on rebuild.
    pub(super) fn check(&self) -> Result<(), String> {
        let key = self.key.to_key().map_err(|e| e.to_string())?;
        let resync =
            cyphr::resync::verify_resync(&self.evidence, &key).map_err(|e| e.to_string())?;
        if resync.id != self.tip {
            return Err("the record's tip is not the proof's id".into());
        }
        Ok(())
    }
}

/// Discriminator of an [`ActionManifest`].
pub(super) const ACTION_MANIFEST_KIND: &str = "cyphr-storage/action-manifest/v1";

/// Marks a blob as an [`ActionManifest`]: these bytes followed by its
/// JSON. A keyspace of its own, separated from wire blobs as
/// [`COMMIT_MANIFEST_PREFIX`] is, so a rebuild never reads one as a commit.
pub const ACTION_MANIFEST_PREFIX: &[u8] = b"\0cyphr-storage/action-manifest/v1\0";

/// The durable record of one accepted action-only bundle: its data
/// actions are recorded in DT, not chained (SPEC 4.8.1), so they form no
/// commit and hold no chain position. Every replay records them once the
/// commits are in, each judged at its own `now` (SPEC 6.5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ActionManifest {
    pub(super) kind: String,
    pub(super) principal_id: String,
    pub(super) blob_hashes: Vec<Blake3Hash>,
    /// As on [`CommitManifest`]: the embedded principals the actions were
    /// judged through, absent (and the manifest byte-identical to one
    /// written before this field) when none was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// An accepted action-only bundle as the engine tracks it: a cache of its
/// [`ActionManifest`] (I1).
#[derive(Debug, Clone)]
pub(super) struct StoredActions {
    pub(super) manifest: Blake3Hash,
    pub(super) blobs: Vec<Blake3Hash>,
    pub(super) embedded: Vec<EmbeddedPin>,
}

/// Whether `data` parses as the pre-keyspace manifest shape. Parsed, not
/// searched: JSON lets any member name be spelled with escapes.
pub(super) fn is_legacy_manifest(data: &[u8]) -> bool {
    /// The pre-keyspace manifest's shape: a kind and a commit, whatever
    /// else it carried (it predates the recorded transaction shape).
    #[derive(serde::Deserialize)]
    struct Legacy {
        kind: String,
        #[serde(rename = "commit")]
        _commit: IndexableCommit,
    }
    serde_json::from_slice::<Legacy>(data).is_ok_and(|m| m.kind == COMMIT_MANIFEST_KIND)
}

impl<B: BlobStore, I: Indexer + IndexerWrite, S: cyphr::eml::Storage> StorageEngine<B, I, S> {
    /// Whether a manifest's commit names blobs the store holds: the index
    /// is a cache of the blobs (I1), so a manifest field the blobs do not
    /// support must not reach it. `Ok(Err(reason))` is a manifest to
    /// quarantine; `Err` is a backend failure.
    pub(super) async fn check_manifest_supported(
        &self,
        manifest_hash: &Blake3Hash,
        manifest: &CommitManifest,
    ) -> Result<Result<(), QuarantineReason>, EngineError> {
        let commit = &manifest.commit;
        if manifest.shape.len() != commit.blob_hashes.len() {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest_hash}: its shape groups a different number of blobs"
            ))));
        }
        let manifest = manifest_hash;
        if commit.blob_hashes.is_empty()
            || commit.cozies.len() != commit.blob_hashes.len()
            || commit
                .cozies
                .iter()
                .zip(&commit.blob_hashes)
                .any(|(coz, hash)| coz.blob_hash != *hash)
        {
            return Ok(Err(QuarantineReason::Malformed(format!(
                "commit manifest {manifest}: cozies and blob hashes disagree"
            ))));
        }
        for hash in &commit.blob_hashes {
            if !self.blob_store.exists(hash).await? {
                return Ok(Err(QuarantineReason::Unsupported(format!(
                    "commit manifest {manifest} names blob {hash}, which is not stored"
                ))));
            }
        }
        Ok(Ok(()))
    }
}
