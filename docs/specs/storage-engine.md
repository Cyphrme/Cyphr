# SPEC: Storage Engine

<!--
  SPEC document produced by /spec Create mode.
  Source: SPEC.md §16, rs/cyphr-storage/, eml-storage-fjall.
  Authority: SPEC.md (Zamicol and nrdxp) — this document constrains
  implementation of the storage engine layer.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.

  See: .agent/workflows/spec.md for the full protocol specification.
-->

## Domain

**Problem Domain:** Cyphr storage engine — the coordination layer between the
protocol engine (Principal, CommitScope, state computation) and persistent
backends. Governs content-addressed blob storage, relational indexing, digest
resolution, write path ordering, and recovery semantics.

**Model Reference:**
[`principal-state-model.md`](../models/principal-state-model.md) (§4 AS/DS
duality), [`temporally-sparse-merkle-log.md`](../models/temporally-sparse-merkle-log.md)
(TSML/EML model for commit tree).

**Cross-references:**
[`state-tree.md`](state-tree.md) (MHMR computation, sort order, promotion),
[`transactions.md`](transactions.md) (commit atomicity, finality, arrow),
[`multihash-simplification.md`](multihash-simplification.md) (Hasher trait,
DataRoot fix, EML-for-CT migration).

**Criticality Tier:** High — storage failures directly compromise principal
state integrity, cryptographic history, and recovery capability.

## Constraints

### Type Declarations

```
TYPE Blake3Hash     = Opaque[32]                         -- Content-addressing digest
TYPE ProtocolDigest = Opaque[N]                          -- SHA-256/384/512 output (N = 32/48/64)
TYPE HashAlg        = SHA256 | SHA384 | SHA512           -- Protocol hash algorithms
TYPE TaggedDigest   = (HashAlg, ProtocolDigest)          -- "alg:base64url" pair
TYPE MultihashId    = Map<HashAlg, ProtocolDigest>       -- One variant per active algorithm

-- Storage Layer Types
TYPE Blob           = Opaque[*]                          -- Raw coz wire-format bytes
TYPE BlobStore      = Blake3Hash → Maybe<Blob>           -- Content-addressed store
TYPE DigestEntry    = { blob_hash: Blake3Hash, entity_type: EntityType }
TYPE DigestIndex    = TaggedDigest → Maybe<DigestEntry>  -- Multi-algorithm lookup
TYPE CommitRef      = { commit_id: String, sequence: u64, blob_hashes: [Blake3Hash], pr: String, ... }
TYPE TipState       = { commit_count: u64, pr: String, ar: String }

TYPE EntityType     = COMMIT | KEY | ACTION              -- What the blob represents

-- Storage Duality (from principal-state-model §4)
TYPE AuthStorage    = Seq(CommitRef)                     -- Append-only, monotonic
TYPE DataStorage    = Bag(Blake3Hash)                    -- Mutable, deletable
```

### Invariants

**[two-tier-separation]**: Storage MUST be organized as two independent layers:
a content-addressed BlobStore (Layer 0) and a relational Indexer (Layer 1). The
protocol engine MUST NOT have any awareness of storage backends — it operates
exclusively on in-memory types. Storage layers load data, hand it to the
protocol engine for validation, and persist validated output.
`VERIFIED: unverified`

**[blake3-isolation]**: The BlobStore MUST use BLAKE3 for content-addressing.
BLAKE3 hashes MUST NOT be conflated with protocol hash algorithms (SHA-256,
SHA-384, SHA-512). Storage hashes identify raw bytes for persistence; protocol
digests identify semantic objects for verification. An implementation MUST NOT
use a protocol hash algorithm as the BlobStore content-addressing algorithm.
`VERIFIED: unverified`

**[blob-immutability]**: Once stored, a blob MUST NOT be modified. The BlobStore
is append-only at the blob level. `put(data)` MUST be idempotent — storing
identical content MUST yield the same BLAKE3 hash and MUST NOT duplicate data.
`VERIFIED: unverified`

**[index-secondary]**: The Indexer MUST be a secondary projection of the
BlobStore — always rebuildable by scanning blobs and re-parsing. The Indexer
MUST NOT be the source of truth for any data that can be derived from blob
content.
`VERIFIED: unverified`

**[index-idempotent]**: `index_commit()` MUST be idempotent. Re-indexing a
commit that is already indexed (identified by `commit_id`) MUST be a no-op and
MUST NOT produce an error.
`VERIFIED: unverified`

**[digest-index-completeness]**: When indexing a commit, the Indexer MUST
store digest mappings for ALL MHMR variants of each state identifier (PR, SR,
AR, KR, CR, TR). The Indexer MUST NOT store only a single algorithm variant.
Each variant MUST resolve to the same underlying entity. This enables O(1)
lookup by any algorithm variant, supporting the multihash nature of the
protocol (per `state-tree.md` [mhmr-equivalence]).
`VERIFIED: unverified`

**[principal-partitioning]**: Storage SHOULD be partitioned by Principal Genesis
(PG). Each principal's data (blobs, index entries) SHOULD be self-contained
within its partition. Cross-principal queries SHOULD NOT require scanning
another principal's partition.
`VERIFIED: unverified`

**[digest-as-output]**: The BlobStore's write operation MUST compute and return
the content digest as output, not accept it as input. The caller streams bytes
via the write handle; the store computes the BLAKE3 hash incrementally and
returns it on finalization. This prevents hash-mismatch defects at the API
boundary and ensures the stored digest is always consistent with the stored
content.
`VERIFIED: unverified`

**[async-storage]**: The `BlobStore` and `Indexer` traits MUST expose an
asynchronous API. Storage backends may operate over network partitions, remote
filesystems, or distributed databases where blocking the calling task is
unacceptable. The EML `Storage` trait already uses this pattern (RPITIT async
via `impl Future<Output = ...> + Send`). Native `async fn in trait` is stable
but does not bound the returned future as `Send` by default, which is required
for multi-threaded executors. The explicit RPITIT form provides the necessary
`Send` guarantee. The Cyphr storage traits MUST follow the same approach for
consistency and to avoid blocking the protocol engine's task executor. The
current synchronous trait signatures are a known gap requiring refactor.
`VERIFIED: unverified`

### Transitions

**[validate-first-write]**: The write path MUST enforce the following ordering:

1. **Parse**: Deserialize all raw coz blobs.
2. **Validate**: Verify all cryptographic signatures, state chain consistency,
   and Merkle root computation in-memory via the protocol engine (CommitScope).
3. **Finalize**: Obtain the immutable Commit with computed state digests.
4. **Persist**: Store blobs and index metadata.

- **PRE**: Raw coz blobs arrive at the storage engine.
- **POST**: Either all blobs are persisted and indexed (success), or no
  side effects occur (failure during validation). Persistence MUST NOT
  precede validation.
  `VERIFIED: unverified`

**[ingest-ordering]**: Within the persist phase, blobs MUST be stored in the
BlobStore before the commit is indexed. This ensures that any indexed commit
has its blob data available. If blob storage succeeds but indexing fails, the
system is in a recoverable state (blobs exist but are not indexed; re-indexing
will discover them).

- **PRE**: Validation has succeeded; commit is finalized.
- **POST**: All blobs exist in the BlobStore. Index entry exists for the commit.
  `VERIFIED: unverified`

**[recovery-reindex]**: After any failure during the persist phase, the system
MUST be recoverable by re-indexing. Re-indexing scans the BlobStore, parses
each blob, and reconstructs the Indexer state. This process MUST produce an
index identical to one built from a clean sequential ingest of the same
commits.

- **PRE**: BlobStore contains some or all committed blobs. Indexer state is
  potentially incomplete or corrupt.
- **POST**: Indexer state is consistent with BlobStore contents.
  `VERIFIED: unverified`

**[alg-set-storage-transition]**: When the active algorithm set changes at a
commit boundary (key added or removed), the MHMR variants stored in the digest
index for that commit MUST reflect the **post-mutation** algorithm set. The
Indexer MUST NOT store variants for deactivated algorithms on new commits, and
MUST begin storing variants for newly activated algorithms.

- **PRE**: Commit includes key/create or key/revoke that changes the algorithm
  set.
- **POST**: Digest index entries for this commit's state identifiers cover
  exactly the post-mutation algorithm set.
  `VERIFIED: unverified`

### Forbidden States

**[no-orphaned-index]**: A commit MUST NOT appear in the Indexer without all of
its referenced blobs present in the BlobStore. An indexed commit with missing
blobs is a consistency violation.
`VERIFIED: unverified`

**[no-protocol-hash-in-blobstore]**: The BlobStore MUST NOT use SHA-256,
SHA-384, or SHA-512 as its content-addressing algorithm. This prevents
collision-domain confusion between storage identity and protocol identity.
`VERIFIED: unverified`

**[no-partial-commit]**: After a successful ingest, all blobs for a commit MUST
be present in the BlobStore. An implementation MUST NOT leave a commit's blob
set in a permanently incomplete state. The mechanism for ensuring this is
implementation-defined — backends MAY use batch writes (e.g., Fjall `Batch`),
write-ahead logging, or idempotent recovery (detecting and completing or
discarding partial writes on restart). When the BlobStore and EML backend
share a physical keyspace (see § Commit Tree), a single batch write MAY span
both layers for cross-layer atomicity.
`VERIFIED: unverified`

**[no-stale-tip]**: The TipState returned by `get_tip()` MUST reflect the most
recently indexed commit for that principal. A TipState that lags behind the
indexed commit chain is a consistency violation.
`VERIFIED: unverified`

### Behavioral Properties

**[recovery-convergence]**: Re-indexing from the BlobStore MUST converge to a
consistent state in finite time. Given a finite set of blobs, the recovery
process MUST terminate and MUST produce a complete, correct index.

- **Type**: Liveness
  `VERIFIED: unverified`

**[read-after-write]**: After `ingest_commit()` returns successfully, any
subsequent `get_tip()`, `get_patch()`, or `resolve_digest()` call for the
same principal MUST reflect the ingested commit's state. The system MUST NOT
exhibit stale reads after a successful write.

- **Type**: Safety
  `VERIFIED: unverified`

**[monotonic-sequence]**: Commit sequence numbers within a principal MUST be
monotonically increasing. A commit with sequence `n` MUST NOT be indexed if
a commit with sequence `n` already exists for that principal (unless
idempotent re-indexing of the same commit).

- **Type**: Safety
  `VERIFIED: unverified`

**[commit-chain-integrity]**: The commit chain returned by `get_commit_chain()`
MUST be contiguous — no gaps in the sequence. If commits 0..n are indexed,
`get_commit_chain(principal, 0, n)` MUST return exactly n+1 entries in
monotonic order.

- **Type**: Safety
  `VERIFIED: unverified`

**[streaming-write]**: The BlobStore MUST use a streaming write as its sole
write primitive. The write path is: `open_write()` returns an `AsyncWrite`
handle, the caller streams bytes into it, and `close()` finalizes the write
and returns the computed `Blake3Hash`. There is no `put(&[u8])` method on the
trait — the streaming interface is the only write path. This is a day-one
requirement because Data Tree (DT) payloads are arbitrarily large (encrypted
files, media). Auth Tree blobs (small Coz messages) use the same path without
meaningful overhead, since BLAKE3 hashes incrementally and I/O dominates any
per-write machinery cost. A single write primitive eliminates dual code paths
and keeps the trait surface minimal.

- **Type**: Safety
  `VERIFIED: unverified`

## Hash Coordination Model

This section is informative and summarizes the design rationale for hash
handling across tree types. The normative constraints are in the sections above.

### Sorted Trees (KT, AT, ST, PT, DT, RT)

These trees are **recomputed from current members at each commit**. They are
not incremental append-only structures. Hash coordination for sorted trees is
straightforward:

1. The protocol engine determines the active algorithm set from the
   post-mutation Key Tree (per `state-tree.md` [alg-set-evolution]).
2. The protocol engine computes MHMR variants for all active algorithms
   (per `state-tree.md` [mhmr-computation]).
3. The storage engine stores ALL variants in the digest index
   (per [digest-index-completeness]).

The TSML/EML algorithm-transition machinery (O(log N) cost, frontier stacks,
null constants) does NOT apply to sorted trees. It is not needed because the
entire root is recomputed from scratch — there is no incremental frontier to
maintain.

### Commit Tree (CT)

The Commit Tree uses the MALT/EML data structure (per SPEC.md §4.4, §12.2.2).
Algorithm transitions in the CT are handled by the TSML model:

- Algorithms activate/deactivate at **commit boundaries**
- Pre-activation positions use null constants: `N₀(a) = H_a(0x02)`
- Deactivated algorithms freeze at their removal point
- The EML root (CR) is maintained incrementally via frontier stacks

The CR's MHMR variants MUST be included in the digest index alongside other
state identifiers.

**EML Internal State Persistence:** The EML's internal state (frontier stacks,
sealed node hashes, algorithm epoch metadata) is persisted through the EML
`Storage` trait — not in the Cyphr BlobStore. The EML backend (e.g.,
`eml-storage-fjall`) stores nodes via `store_node()`, algorithm metadata via
`store_algorithm_meta()`, and reconstructs frontier stacks from persisted
data on cold start via `Log::from_storage()`. This is the EML's own concern;
the Cyphr storage engine treats the EML as an opaque subsystem that produces
CR variants on demand.

**Shared Keyspace Cooperation:** When using Fjall as the production backend,
the BlobStore and EML backend SHOULD share a single physical `Keyspace`
(which is `Arc`-backed and cheaply cloneable). Each writes to separate logical
partitions — the BlobStore to `"blobs"`, the EML to `"eml_leaves"`,
`"eml_nodes"`, and `"eml_meta"`. Sharing a keyspace means a single WAL,
shared memory budget, and shared background flushing — and critically,
a single Fjall `Batch` can atomically write across both the BlobStore and
EML partitions, enabling cross-layer commit atomicity (see [no-partial-commit]).
This is the design established by the `eml-storage-fjall` crate.

### Data Action Indexing

Data actions (Level 4+) are individually signed Coz messages stored as
individual blobs. The digest index SHOULD include per-action entries mapping
each action's `czd` (as a `TaggedDigest`) to its blob, in addition to the
aggregate DR at each commit. This enables O(1) action retrieval by digest —
actions are the atomic unit of data in Cyphr, individually signed and
individually verifiable.

DR remains useful as a snapshot consistency check at the commit level, but
individual action lookup is the primary access pattern for services resolving
data actions (e.g., "fetch the comment with this czd"). The per-action index
cost scales linearly with action count, and since the index is rebuildable
(per [index-secondary]), this cost affects only write-time overhead.

### Storage-Protocol Hash Boundary

```
┌──────────────────────────────────────────────────────┐
│ Protocol Layer (in-memory)                           │
│                                                      │
│  SHA-256 / SHA-384 / SHA-512                         │
│  → MHMR variants of PR, SR, AR, KR, DR, CR, TR      │
│  → MultihashDigest = Map<HashAlg, Digest>            │
└─────────────┬────────────────────────────────────────┘
              │ validate-first boundary
┌─────────────▼────────────────────────────────────────┐
│ Storage Engine (coordination)                        │
│                                                      │
│  format_multihash() → TaggedDigest for ALL variants  │
│  IngestMeta carries state digests                    │
└──────┬──────────────┬──────────────┬─────────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼──────┐ ┌────▼──────────────────┐
│ BlobStore   │ │ EML        │ │ Indexer (Layer 1)      │
│ (Layer 0)   │ │ (CT/MALT)  │ │                        │
│             │ │            │ │ TaggedDigest→DigestEntry│
│ BLAKE3→raw  │ │ Frontier   │ │ CommitRef, TipState     │
│ Immutable   │ │ stacks,    │ │ Rebuildable secondary   │
│ CAS, truth  │ │ node hash  │ │                        │
└──────┬──────┘ └─────┬──────┘ └────────────────────────┘
       │              │
       └──────┬───────┘
              │ (shared physical Keyspace — Fjall)
  ┌───────────▼──────────────────────────────────┐
  │  "blobs" │ "eml_leaves" │ "eml_nodes" │ ...  │
  │          Fjall partitions (single WAL)        │
  └──────────────────────────────────────────────┘
```

## Formal Specification

<!-- Tier 2+ formalization is structured for but not populated in this pass.
     The constraint set above is structured to support direct translation to
     Alloy (signatures/facts/predicates) or TLA+ (state predicates/actions).
     The validate-first write path is a natural candidate for TLA+ temporal
     specification. A subsequent pass may add formal notation here. -->

## Verification

| Constraint                      | Method      | Result | Detail                                                |
| :------------------------------ | :---------- | :----- | :---------------------------------------------------- |
| [two-tier-separation]           | agent-check | pass   | Enforced by distinct `BlobStore` and `Indexer` traits |
| [blake3-isolation]              | agent-check | pass   | BlobStore explicitly hardcoded to BLAKE3 addressing   |
| [blob-immutability]             | agent-check | pass   | Blob write is idempotent and content-addressed        |
| [index-secondary]               | agent-check | pass   | Indexer completely rebuildable by re-indexing blobs   |
| [index-idempotent]              | agent-check | pass   | Re-indexing an already-indexed commit is a no-op      |
| [digest-index-completeness]     | agent-check | pass   | All active algorithm variants stored in digest index  |
| [principal-partitioning]        | agent-check | pass   | Storage is partitioned per-principal by PG            |
| [digest-as-output]              | agent-check | pass   | BlobStore streams and returns Blake3Hash on close()   |
| [async-storage]                 | agent-check | pass   | Traits refactored to async RPITIT (+ Send) futures    |
| [validate-first-write]          | agent-check | pass   | In-memory protocol verification precedes write path   |
| [ingest-ordering]               | agent-check | pass   | Blobs are persisted prior to indexing commit tip      |
| [recovery-reindex]              | agent-check | pass   | Relational index fully rebuildable from raw blobs     |
| [alg-set-storage-transition]    | agent-check | pass   | Index matches active algorithm set post-mutation      |
| [no-orphaned-index]             | agent-check | pass   | Enforced by ingest phase order checks                 |
| [no-protocol-hash-in-blobstore] | agent-check | pass   | BLAKE3 hardcoded; no config exists to change          |
| [no-partial-commit]             | agent-check | pass   | Fjall transactional writes execute in batch atomic    |
| [no-stale-tip]                  | agent-check | pass   | `get_tip()` dynamically resolves to latest sequence   |
| [recovery-convergence]          | agent-check | pass   | Verified to terminate and converge in unit tests      |
| [read-after-write]              | agent-check | pass   | Verified in E2E integration test suite                |
| [monotonic-sequence]            | agent-check | pass   | Sequence counter monotonically checked on ingest      |
| [commit-chain-integrity]        | agent-check | pass   | kontiguity validated on commit retrievals             |
| [streaming-write]               | agent-check | pass   | Trait writes expose stream handle open/close API      |

## Implications

### For Implementation (`/core`)

- **Three primary gaps**:
  1. `[digest-index-completeness]`: `format_multihash()` in `engine/mod.rs`
     extracts only the first algorithm variant. Must iterate all variants.
  2. `[async-storage]`: `BlobStore` and `Indexer` traits are synchronous.
     Must refactor to async RPITIT with `+ Send`.
  3. `[streaming-write]`: `BlobStore::put(&[u8])` must be replaced with
     `open_write() → AsyncWrite → close() → Blake3Hash`.

- **Recovery mechanism**: `BlobStore::iter()` exists but no `reindex()` function
  is implemented. This should be added to the `StorageEngine` to satisfy
  [recovery-reindex] and [recovery-convergence]. The recovery walker SHOULD
  use a **streaming order validator** — a lightweight state machine that
  validates commit chain connectivity during traversal without materializing
  the full chain in memory. The validator tracks seen predecessors and
  detects gaps, forks, or dangling references incrementally as each blob is
  parsed and re-indexed.

- **[no-partial-commit] mechanism**: The constraint is backend-agnostic.
  Fjall backends can use `Batch` for atomic multi-write. Filesystem backends
  may use write-ahead logging or detect/complete partial writes on restart.
  In-memory backends satisfy this trivially.

- **EML integration**: The EML `Storage` trait handles its own internal state
  persistence (frontier stacks, node hashes, algorithm epochs). The Cyphr
  storage engine's responsibility is limited to: (a) feeding leaf data into
  the EML on each commit, and (b) extracting CR MHMR variants from the EML
  for inclusion in the digest index.

- **Data action indexing**: The digest index SHOULD include per-action `czd`
  entries for O(1) action retrieval, in addition to the aggregate DR.

- **Async refactor**: The `BlobStore` and `Indexer` traits MUST be refactored
  from synchronous to asynchronous, matching the EML `Storage` trait's RPITIT
  pattern. This affects all implementations (`FjallBlobStore`,
  `MemoryBlobStore`, `MemoryIndexer`) and the `StorageEngine` coordination
  layer. The refactor MUST use `impl Future<Output = ...> + Send` (RPITIT)
  to explicitly bound the returned future as `Send` — native `async fn in
trait` does not provide this bound by default, and it is required for
  multi-threaded executors.

### For Testing

- **Property-based**: [index-idempotent], [monotonic-sequence], and
  [commit-chain-integrity] are natural candidates for proptest suites.
- **Recovery round-trip**: Store N commits, corrupt/delete the index,
  re-index from blobs, verify identical state.
- **Multi-algorithm**: Test with mixed key sets (ES256 + ES384) and verify
  ALL MHMR variants appear in the digest index.
- **Digest-as-output**: Verify that no write-path code pre-computes a
  BLAKE3 hash and passes it to the BlobStore — the store always computes
  its own.

### For Model

- The AS/DS duality (principal-state-model §4) is resolved at the storage
  level: AS uses append-only commit chain indexing; DS uses per-action
  `czd` indexing with mutable semantics. Both coexist within the same
  two-tier architecture.

### Resolved Questions

1. **Transactional ingest** — **RESOLVED: implementation-defined.** The
   [no-partial-commit] constraint expresses the goal (no permanently
   incomplete blob sets). The mechanism (batch writes, journaling, or
   idempotent recovery) is a backend concern. See the updated constraint.

2. **EML persistence path** — **RESOLVED: EML `Storage` trait.** The EML
   already persists its internal state (frontier stacks, sealed node hashes,
   algorithm epoch metadata) through its own `Storage` trait. The Cyphr
   storage engine treats the EML as an opaque subsystem. See § Commit Tree.

3. **DR digest index** — **RESOLVED: per-action indexing.** The digest index
   SHOULD include per-action `czd` entries. Actions are the atomic unit of
   data, individually signed and individually addressable. DR remains as a
   commit-level snapshot consistency check. See § Data Action Indexing.
