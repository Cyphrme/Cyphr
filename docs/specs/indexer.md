# SPEC: Query Index

<!--
  SPEC document — abstract API requirements for the Indexer layer.
  Source: storage-engine.md (original), a 2026-05-28 storage-object-model
  design sketch (no longer in the repository)
  Authority: SPEC.md (Zamicol and nrdxp)

  This document specifies the backend-agnostic contract for the query
  index. Implementation-specific details (Fjall key layouts, etc.) belong in
  their respective implementation specs.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Secondary-index lookups over Cyphr commits, transactions, and
public keys. Accelerates queries that the content-addressed BlobStore cannot
serve efficiently: tip lookups, commit chain traversal, digest resolution,
key metadata retrieval.

**Role in Architecture:** Layer 1 — a secondary projection of the BlobStore.
The index is always rebuildable by scanning blobs and re-parsing. The index
MUST NOT be the source of truth for any data derivable from blob content.

**Trust Model:** The index is a conventional database. It does not provide
authenticated query results or completeness proofs. Trustless verification
of query results relies on chain replay — the `pre`-linked EML chain has
no gaps, so fetching the patch and filtering locally is trustless by
construction. The index provides _performance_; the chain provides _trust_.

The design rationale and the evaluated alternatives (sorted index tables,
MSTs, distributed authenticated primitives — all rejected) are captured in
the "Decision: ACCEPTED — Conventional Index with Chain Replay Verification"
design record.

**Cross-references:**
[`storage-engine.md`](storage-engine.md) (engine coordination),
[`blob-store.md`](blob-store.md) (content store),
`cyphr-index-fjall` (Fjall implementation; no dedicated implementation-level
spec doc yet — see `rs/cyphr-index-fjall/src/lib.rs`).

## Type Declarations

```
TYPE TaggedDigest    = (HashAlg, ProtocolDigest)   -- "alg:base64url" pair
TYPE MultihashId     = Map<HashAlg, ProtocolDigest> -- One variant per active algorithm
TYPE Blake3Hash      = Opaque[32]                  -- Storage-level content address

-- Per-Coz metadata for the canonical event log
TYPE IndexableCoz = {
    blob_hash:    Blake3Hash,   -- BLAKE3 hash of the coz blob
    czd:          String,       -- Tagged protocol digest (primary czd variant)
    typ:          String,       -- Action type (e.g., "cyphr.me/cyphr/key/create")
    tmb:          String,       -- Signer thumbprint
    alg:          String,       -- Algorithm
    now:          i64,          -- Timestamp (Unix seconds)
    payload:      Option<String> -- Raw JSON pay object (for unstructured data queries)
}

-- Index-Level Types (serialized representations, not live protocol objects)
TYPE IndexableCommit = {
    principal_id:      String,       -- Principal genesis identifier
    commit_ids:        [String],     -- Commit ID variants (tagged digest strings)
    sequence:          u64,          -- 0-indexed within principal
    pre:               Option<String>, -- Prior PR (None for genesis)
    prs:               [String],     -- Principal Root variants (post-commit)
    srs:               [String],     -- State Root variants (post-commit)
    ars:               [String],     -- Auth Root variants (post-commit)
    blob_hashes:       [Blake3Hash], -- BLAKE3 hashes of coz blobs in this commit
    cozies:            [IndexableCoz], -- Per-coz metadata for the event log
    timestamp:         i64,          -- From the commit transaction's `now` field
    keys:              [PublicKeyInfo]
}

TYPE TipState = {
    principal_id:  String,
    pr:            String,     -- Current Principal Root
    sr:            String,     -- Current State Root
    ar:            String,     -- Current Auth Root
    commit_id:     String,     -- Most recent Commit ID
    commit_count:  u64,
    last_updated:  i64
}

TYPE CommitRef = {
    commit_id:   String,
    sequence:    u64,
    pre:         Option<String>,   -- Prior PR (chain link)
    pr:          String,           -- Principal Root after this commit
    sr:          String,           -- State Root after this commit
    ar:          String,           -- Auth Root after this commit
    blob_hashes: [Blake3Hash],
}

TYPE EntityRef = {
    digest:      String,
    blob_hash:   Blake3Hash,
    entity_type: EntityType
}

TYPE EntityType     = COMMIT | TRANSACTION | ACTION
TYPE PrincipalSummary = { principal_id, pr, commit_count, created, last_updated }

-- NOTE: `public_key` bytes are sourced from the unsigned `keys` auxiliary
-- field of the commit wire format, NOT from chain-committed state. Only
-- `thumbprint` is in KT.
TYPE PublicKeyInfo  = { thumbprint, algorithm, public_key }

```

## Constraints

### Secondary Nature

**[index-secondary]**: The Indexer MUST be a secondary projection of the
BlobStore — always rebuildable by scanning blobs and re-parsing. The Indexer
MUST NOT be the source of truth for any data that can be derived from blob
content.
`VERIFIED: rs/cyphr-storage/src/index/mod.rs — trait doc, reindex() in engine`

**[index-idempotent]**: `index_commit()` MUST be idempotent. Re-indexing a
commit that is already indexed (identified by `commit_id`) MUST be a no-op
and MUST NOT produce an error.
`VERIFIED: rs/cyphr-index-fjall/src/lib.rs — db_index_commit's contains_key(commit_key) early-return; rs/cyphr-storage/src/index/memory.rs — dedup check`

### Digest Resolution

**[digest-index-completeness]**: When indexing a commit, the Indexer MUST
store digest mappings for ALL MHMR variants of each state identifier (PR,
SR, AR, KR, CR, TR). The Indexer MUST NOT store only a single algorithm
variant. Each variant MUST resolve to the same underlying entity. This
enables O(1) lookup by any algorithm variant, supporting the multihash
nature of the protocol (per `state-tree.md` [mhmr-equivalence]).
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — format_multihash_all()`

**[alg-set-storage-transition]**: When the active algorithm set changes at
a commit boundary (key added or removed), the MHMR variants stored in the
digest index for that commit MUST reflect the **post-mutation** algorithm
set. The Indexer MUST NOT store variants for deactivated algorithms on new
commits, and MUST begin storing variants for newly activated algorithms.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — uses post-commit alg set`

### Data Action Indexing

**[per-action-indexing]**: The digest index SHOULD include per-action entries
mapping each data action's `czd` (as a `TaggedDigest`) to its blob, in
addition to the aggregate DR at each commit. Actions are the atomic unit
of data in Cyphr — individually signed and individually verifiable.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — transaction_ids indexed`

### Query Scoping

Most Indexer trait methods are naturally scoped to a single principal
(get_tip, get_commit_chain, etc.) as a consequence of the protocol's
per-principal state model. However, the underlying index schema MUST NOT
preclude cross-principal queries. At minimum, operators need to query
across all principals for database management and observability (e.g.,
"show recent activity," "find all key revocations").

The retired `cyphr-index-sqlite` backend achieved this by indexing universal
Coz metadata (`typ`, `tmb`, `now`, `alg`, `czd`) in a single `cozies` table
(see the archived `docs/plans/archive/indexer-sqlite.md`), though no
`Indexer` trait method ever exposed a query over it. `cyphr-index-fjall`
does not currently maintain per-coz metadata at all — its own source
documents this as deliberate, since no live trait method reads it. This
constraint's schema-level requirement is presently unenforced by either
production backend's actual exposed surface; it constrains schema design
if/when a cross-principal query method is added to the trait.

### Tip Consistency

**[no-stale-tip]**: The TipState returned by `get_tip()` MUST reflect the
most recently indexed commit for that principal. A TipState that lags behind
the indexed commit chain is a consistency violation.
`VERIFIED: rs/cyphr-index-fjall/src/lib.rs — db_index_commit's tips batch.insert runs in the same atomic batch as commits/principals`

### Async

**[async-index]**: The `Indexer` trait MUST expose an asynchronous API using
RPITIT (`impl Future<Output = ...> + Send`). See `blob-store.md`
[async-storage] for the rationale and the RPITIT note explaining why
`impl Future + Send` is used instead of `async fn`.
`VERIFIED: rs/cyphr-storage/src/index/mod.rs — all methods use RPITIT`

**[runtime-agnostic-index]**: The `Indexer` trait MUST NOT depend on any
specific async runtime in its signature. See `blob-store.md`
[runtime-agnostic]. Runtime-specific types (e.g., `cyphr-index-fjall`'s use
of `tokio::task::spawn_blocking` to bridge Fjall's synchronous API) belong
in implementation crates.

### Thread Safety

**[send-sync-index]**: The `Indexer` trait MUST require `Send + Sync`.
`VERIFIED: rs/cyphr-storage/src/index/mod.rs — trait bound`

## Trait Signature

```rust
pub trait Indexer: Send + Sync {
    fn index_commit(&self, commit: &IndexableCommit)
        -> impl Future<Output = Result<(), IndexerError>> + Send;

    fn get_tip(&self, principal_id: &str)
        -> impl Future<Output = Result<Option<TipState>, IndexerError>> + Send;

    fn get_commit_chain(&self, principal_id: &str, from: Option<u64>, to: Option<u64>)
        -> impl Future<Output = Result<Vec<CommitRef>, IndexerError>> + Send;

    fn resolve_digest(&self, digest: &TaggedDigest)
        -> impl Future<Output = Result<Option<EntityRef>, IndexerError>> + Send;

    fn list_principals(&self)
        -> impl Future<Output = Result<Vec<PrincipalSummary>, IndexerError>> + Send;

    fn clear(&self)
        -> impl Future<Output = Result<(), IndexerError>> + Send;

    fn is_blob_indexed(&self, hash: &Blake3Hash)
        -> impl Future<Output = Result<bool, IndexerError>> + Send;

    fn get_key(&self, thumbprint: &str)
        -> impl Future<Output = Result<Option<PublicKeyInfo>, IndexerError>> + Send;
}
```

## Forbidden States

**[no-orphaned-index]**: A commit MUST NOT appear in the Indexer without all
of its referenced blobs present in the BlobStore. An indexed commit with
missing blobs is a consistency violation. The engine's write path (store
blobs before indexing) prevents this under normal operation; recovery
re-indexing repairs it.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — ingest_commit ordering`

## Behavioral Properties

**[recovery-reindex]**: After any failure during the persist phase, the
system MUST be recoverable by re-indexing. Re-indexing scans the BlobStore,
parses each blob, and reconstructs the Indexer state. This process MUST
produce an index identical to one built from a clean sequential ingest of
the same commits.

- **Type**: Liveness
  `VERIFIED: rs/cyphr-storage/src/engine/mod.rs — reindex()`

**[recovery-convergence]**: Re-indexing from the BlobStore MUST converge to
a consistent state in finite time. Given a finite set of blobs, the recovery
process MUST terminate and MUST produce a complete, correct index.

- **Type**: Liveness
  `VERIFIED: rs/cyphr-storage/src/engine/mod.rs — reindex() terminates`

**[read-after-write-index]**: After `index_commit()` returns successfully,
any subsequent `get_tip()`, `get_commit_chain()`, or `resolve_digest()` call
for the same principal MUST reflect the indexed commit's state.

- **Type**: Safety
  `VERIFIED: integration tests`

**[monotonic-sequence]**: Commit sequence numbers within a principal MUST be
monotonically increasing. A commit with sequence `n` MUST NOT be indexed if
a commit with sequence `n` already exists for that principal (unless
idempotent re-indexing of the same commit).

- **Type**: Safety
  `VERIFIED: rs/cyphr-index-fjall/src/lib.rs — commit_key(principal_id, sequence) composite key`

**[commit-chain-integrity]**: The commit chain returned by
`get_commit_chain()` MUST be contiguous — no gaps in the sequence. If
commits 0..n are indexed, `get_commit_chain(principal, 0, n)` MUST return
exactly n+1 entries in monotonic order.

- **Type**: Safety
  `VERIFIED: integration tests`

## Trustless Verification Model

The index does NOT provide authenticated query results. Trustless
verification uses chain replay:

| Query                   | Verification mechanism                                                         |
| :---------------------- | :----------------------------------------------------------------------------- |
| Tip for principal X     | `GET /tip` → chain replay from trust anchor, or cross-witness gossip (§13.7)   |
| All actions for X       | Fetch patch via `GET /patch`. Chain is `pre`-linked — no gaps. Filter locally. |
| All key/revoke for X    | Chain replay + filter. No action omissible without breaking `pre` chain.       |
| Does principal X exist? | Index lookup (fast). Not security-critical — presence is observable.           |

For the critical case — detecting omitted key revocations — chain replay
is the ONLY sound mechanism. Authorization semantics (key membership,
signature verification, revocation effects) must be replayed in order.
No index can shortcut this.

## Implementations

| Backend           | Crate                | Status                    | Notes                                                |
| :---------------- | :------------------- | :------------------------ | :---------------------------------------------------- |
| Fjall (LSM-tree)  | `cyphr-index-fjall`  | Implemented (production)  | No dedicated spec doc yet; see crate source          |
| SQLite (B-tree)   | `cyphr-index-sqlite` | Retired (2026-07-08)      | Replaced by Fjall (N09-kv-index); spec archived to `docs/plans/archive/indexer-sqlite.md` |
| In-memory HashMap | `cyphr-storage`      | Testing                   | `MemoryIndexer`                                      |
