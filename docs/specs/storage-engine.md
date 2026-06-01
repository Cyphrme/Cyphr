# SPEC: Storage Engine

<!--
  SPEC document — coordination layer between protocol engine and persistent
  backends. Updated 2026-06-01 to reflect four-document split and research
  conclusions from .sketches/2026-05-28-storage-object-model.md.

  This document governs the StorageEngine coordination layer. Backend-specific
  contracts are defined in their respective specs:
  - blob-store.md      — abstract BlobStore API
  - blob-store-fjall.md — Fjall BlobStore implementation
  - indexer.md          — abstract Indexer API
  - indexer-sqlite.md   — SQLite Indexer implementation

  Source: SPEC.md §16, rs/cyphr-storage/, eml-storage-fjall.
  Authority: SPEC.md (Zamicol and nrdxp)

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.

  See: .agent/workflows/spec.md for the full protocol specification.
-->

## Domain

**Problem Domain:** Cyphr storage engine — the coordination layer between the
protocol engine (Principal, CommitScope, state computation) and persistent
backends. Governs write path ordering, read path assembly, recovery
orchestration, and the boundary between protocol-level types and
storage-level representations.

**Architectural Role:** The storage engine does NOT own storage or indexing
logic. It orchestrates a `BlobStore` and an `Indexer` to serve assembled
responses. The engine is the layer that the HTTP server programs against.

**Specification Split (2026-06-01):**

| Document                                     | Concern                                                        |
| :------------------------------------------- | :------------------------------------------------------------- |
| **This document**                            | Engine coordination: write/read paths, recovery, type boundary |
| [`blob-store.md`](blob-store.md)             | Abstract BlobStore API (backend-agnostic)                      |
| [`blob-store-fjall.md`](blob-store-fjall.md) | Fjall BlobStore implementation                                 |
| [`indexer.md`](indexer.md)                   | Abstract Indexer API (backend-agnostic)                        |
| [`indexer-sqlite.md`](indexer-sqlite.md)     | SQLite Indexer implementation                                  |

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

## Architecture

### Two-Layer Model

**[two-tier-separation]**: Storage MUST be organized as two independent
layers: a content-addressed BlobStore (Layer 0) and a relational Indexer
(Layer 1). The protocol engine MUST NOT have any awareness of storage
backends — it operates exclusively on in-memory types. Storage layers load
data, hand it to the protocol engine for validation, and persist validated
output.
`VERIFIED: StorageEngine<B, I> generic over backend types`

The two layers are:

| Layer                      | Responsibility                                         | Backend                                                          | Spec                             |
| :------------------------- | :----------------------------------------------------- | :--------------------------------------------------------------- | :------------------------------- |
| **Layer 0: Content Store** | Immutable content-addressed blobs (BLAKE3 → raw bytes) | Fjall (production), HashMap (testing)                            | [`blob-store.md`](blob-store.md) |
| **Layer 1: Query Index**   | Relational index: tips, chains, digests, keys          | SQLite (production, planned), Fjall (current), HashMap (testing) | [`indexer.md`](indexer.md)       |

**[separate-durability]**: Content store and index are **separate databases**
with independent durability. The content store is the durable source of
truth; the index is a derived, rebuildable projection. If the index is lost,
it is reconstructed from the content store via re-indexing. Cross-store
atomicity is not a correctness requirement — the engine's recovery semantics
handle partial failures.
`VERIFIED: unverified (pending SQLite migration)`

**[crate-isolation]**: Implementation backends MUST be isolated in their
own crates, separate from the trait definitions. The trait crate defines
the abstract API; implementation crates depend on the trait crate and
bring in backend-specific dependencies. This keeps the generic layer
free of backend dependencies and makes it simple to add or swap
implementations.

```
rs/
├── cyphr-storage/          # Trait crate
│   ├── blob.rs             # BlobStore trait, Blake3Hash, errors
│   ├── index.rs            # Indexer trait, types, errors
│   ├── engine.rs           # StorageEngine<B, I> coordination
│   ├── blob/memory.rs      # MemoryBlobStore (testing)
│   └── index/memory.rs     # MemoryIndexer (testing)
│
├── cyphr-blob-fjall/       # BlobStore impl → depends on: cyphr-storage, fjall
│
└── cyphr-index-sqlite/     # Indexer impl → depends on: cyphr-storage, rusqlite, tokio
```

In-memory implementations (`MemoryBlobStore`, `MemoryIndexer`) remain
in the trait crate because they carry no external dependencies and are
needed for testing the trait contracts themselves.

### Trust Model

The index is a conventional database providing _performance_ (fast lookups).
Trustless verification uses _chain replay_ — the `pre`-linked MALT chain
has no gaps, so fetching the patch and filtering locally is trustless by
construction. The index does not provide authenticated query results or
completeness proofs. See [`indexer.md`](indexer.md) § "Trustless Verification
Model" for the full table.

## Type Declarations

```
-- Engine-Level Types (bridge between protocol and storage)
TYPE IngestMeta  = {
    principal_id:      String,
    commit_ids:        [String],     -- MHMR variants
    sequence:          u64,
    prs:               [String],     -- MHMR variants
    srs:               [String],     -- MHMR variants
    ars:               [String],     -- MHMR variants
    transaction_types: [String],
    transaction_ids:   [[String]],   -- Per-coz: czd MHMR variants
    timestamp:         i64,
    keys:              [PublicKeyInfo]
}

TYPE IngestResult = { blob_hashes: [Blake3Hash] }

TYPE PatchEntry = {
    commit: CommitRef,     -- From index
    blobs:  [Blob]         -- From content store
}

TYPE PatchResponse = {
    principal_id: String,
    entries:      [PatchEntry]
}
```

## Constraints

### Write Path

**[validate-first-write]**: The write path MUST enforce the following
ordering:

1. **Parse**: Deserialize all raw coz blobs.
2. **Validate**: Verify all cryptographic signatures, state chain
   consistency, and Merkle root computation in-memory via the protocol
   engine (CommitScope).
3. **Finalize**: Obtain the immutable Commit with computed state digests.
4. **Persist**: Store blobs and index metadata.

- **PRE**: Raw coz blobs arrive at the storage engine.
- **POST**: Either all blobs are persisted and indexed (success), or no
  side effects occur (failure during validation). Persistence MUST NOT
  precede validation.
  `VERIFIED: rs/cyphr-storage/src/engine/mod.rs — submit_commit()`

**[ingest-ordering]**: Within the persist phase, the engine MUST follow
this sequence:

1. **Store blobs**: Write all coz blobs to the BlobStore. Each write
   returns a `Blake3Hash`.
2. **Extract index metadata**: Parse each coz blob to extract universal
   Coz metadata (`typ`, `tmb`, `alg`, `now`, `czd`) and the raw `pay`
   JSON object. These become `IndexableCoz` entries. Public key bytes
   are extracted from the unsigned `keys` auxiliary field of the commit
   wire format (not from chain state — see `indexer.md` `PublicKeyInfo`).
3. **Index the commit**: Pass the assembled `IndexableCommit` (including
   `IndexableCoz` entries, state roots, MHMR digest variants, and key
   metadata) to the Indexer.

This ordering ensures that any indexed commit has its blob data available.
If blob storage succeeds but indexing fails, the system is in a
recoverable state (blobs exist but are not indexed; re-indexing will
discover them).

- **PRE**: Validation has succeeded; commit is finalized.
- **POST**: All blobs exist in the BlobStore. Index entry exists for the
  commit.
  `VERIFIED: rs/cyphr-storage/src/engine/mod.rs — ingest_commit()`

### Read Path

**[read-path-coordination]**: The engine's read path joins index and
content store. For `get_patch()`:

1. Query index for commit chain metadata (`CommitRef` list)
2. For each commit, fetch blob content from BlobStore by BLAKE3 hash
3. Assemble `PatchResponse` with metadata + content

For `get_entity()`:

1. Resolve tagged digest to `EntityRef` via index
2. Fetch blob content from BlobStore by `entity_ref.blob_hash`

Neither the BlobStore nor the Indexer can serve these responses alone.
The engine's coordination is the value.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — get_patch(), get_entity()`

### Recovery

**[recovery-reindex]**: After any failure during the persist phase, the
system MUST be recoverable by re-indexing. Re-indexing scans the BlobStore,
parses each blob, and reconstructs the Indexer state. This process MUST
produce an index identical to one built from a clean sequential ingest of
the same commits.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — reindex()`

**[recovery-convergence]**: Re-indexing from the BlobStore MUST converge to
a consistent state in finite time.
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — reindex() terminates`

### Hash Boundary

**[hash-boundary]**: The engine is the bridge between protocol hashes
(SHA-256/384/512, MHMR variants) and storage hashes (BLAKE3). The engine:

1. Receives finalized protocol state (PR, SR, AR with MHMR variants)
2. Formats all variants as tagged digest strings
3. Passes tagged strings to the Indexer for storage
4. Passes raw blob bytes to the BlobStore for content-addressed storage

The engine MUST format ALL active algorithm variants for each state
identifier, per [`indexer.md`](indexer.md) [digest-index-completeness].
`VERIFIED: rs/cyphr-storage/src/engine/mod.rs — format_multihash_all()`

## Hash Coordination Model

This section summarizes hash handling across tree types. Normative
constraints are defined in the referenced specs.

### Sorted Trees (KT, AT, ST, PT, DT, RT)

Recomputed from current members at each commit. The protocol engine
determines the active algorithm set post-mutation, computes MHMR variants
for all active algorithms, and the engine stores ALL variants in the
digest index per [digest-index-completeness].

### Commit Tree (CT)

Uses the MALT/EML data structure (SPEC.md §4.4, §12.2.2). Algorithm
transitions are handled by the TSML model: null constants for
pre-activation, frozen values for deactivated algorithms, incremental
frontier stacks.

**EML Internal State Persistence:** The EML's internal state (frontier
stacks, sealed node hashes, algorithm epoch metadata) is persisted through
the EML `Storage` trait — not in the Cyphr BlobStore. The Cyphr storage
engine treats the EML as an opaque subsystem that produces CR variants
on demand.

**Shared Keyspace Cooperation:** When using Fjall as the BlobStore backend,
the BlobStore and EML backend SHOULD share a single `Keyspace`
(see [`blob-store-fjall.md`](blob-store-fjall.md) [fjall-single-keyspace]).

### Data Action Indexing

Data actions (Level 4+) are individually signed Coz messages stored as
individual blobs. The digest index SHOULD include per-action entries mapping
each action's `czd` to its blob, in addition to the aggregate DR at each
commit.

## Storage-Protocol Hash Boundary

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
│ Storage Engine (coordination — this document)        │
│                                                      │
│  format_multihash() → TaggedDigest for ALL variants  │
│  IngestMeta carries state digests                    │
│  PatchResponse assembles index + blob content        │
└──────┬──────────────┬──────────────┬─────────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼──────┐ ┌────▼──────────────────┐
│ BlobStore   │ │ EML        │ │ Indexer (Layer 1)      │
│ (Layer 0)   │ │ (CT/MALT)  │ │                        │
│             │ │            │ │ TaggedDigest→EntityRef  │
│ BLAKE3→raw  │ │ Frontier   │ │ CommitRef, TipState     │
│ Immutable   │ │ stacks,    │ │ Rebuildable secondary   │
│ CAS, truth  │ │ node hash  │ │                        │
└─────────────┘ └────────────┘ └────────────────────────┘
       │                              │
       │ (Fjall)                      │ (SQLite — separate DB)
       ▼                              ▼
   blob-store-fjall.md           indexer-sqlite.md
```

## Behavioral Properties

**[read-after-write]**: After `ingest_commit()` returns successfully, any
subsequent `get_tip()`, `get_patch()`, or `resolve_digest()` call for the
same principal MUST reflect the ingested commit's state.

- **Type**: Safety
  `VERIFIED: integration tests`

## Verification

| Constraint               | Method      | Result  | Detail                                             |
| :----------------------- | :---------- | :------ | :------------------------------------------------- |
| [two-tier-separation]    | agent-check | pass    | `StorageEngine<B, I>` generic over distinct traits |
| [separate-durability]    | agent-check | pending | Pending SQLite migration (currently shared Fjall)  |
| [validate-first-write]   | agent-check | pass    | submit_commit(): verify → finalize → persist       |
| [ingest-ordering]        | agent-check | pass    | Blobs stored before index_commit()                 |
| [read-path-coordination] | agent-check | pass    | get_patch() joins index + blobs                    |
| [recovery-reindex]       | agent-check | pass    | reindex() scans BlobStore, rebuilds index          |
| [recovery-convergence]   | agent-check | pass    | reindex() terminates in finite time                |
| [hash-boundary]          | agent-check | pass    | format_multihash_all() for all active variants     |
| [read-after-write]       | agent-check | pass    | Verified in integration tests                      |

## Implications

### Constraints delegated to sub-specs

The following constraints from the original monolithic spec are now defined
in their respective sub-specifications. They are NOT duplicated here.

**BlobStore constraints** (see [`blob-store.md`](blob-store.md)):
[blake3-content-address], [blake3-isolation], [blob-immutability],
[put-write], [digest-as-output], [max-blob-size], [get-by-hash],
[existence-check], [blob-iteration], [async-storage], [runtime-agnostic],
[send-sync], [no-protocol-hash-in-blobstore].

**Indexer constraints** (see [`indexer.md`](indexer.md)):
[index-secondary], [index-idempotent], [digest-index-completeness],
[alg-set-storage-transition], [per-action-indexing],
[no-stale-tip], [async-index], [runtime-agnostic-index], [send-sync-index],
[no-orphaned-index], [monotonic-sequence], [commit-chain-integrity].

**BlobStore implementation** (see [`blob-store-fjall.md`](blob-store-fjall.md)):
[fjall-single-keyspace], [fjall-partition-isolation], [no-partial-commit],
[fjall-write-buffering], [fjall-compaction], [fjall-iter-consistency].

**Indexer implementation** (see [`indexer-sqlite.md`](indexer-sqlite.md)):
[sqlite-write-transaction], schema design, async actor model, migration
strategy.

### For Testing

- **Property-based**: [index-idempotent], [monotonic-sequence], and
  [commit-chain-integrity] are natural candidates for proptest suites.
- **Recovery round-trip**: Store N commits, corrupt/delete the index,
  re-index from blobs, verify identical state.
- **Multi-algorithm**: Test with mixed key sets (ES256 + ES384) and verify
  ALL MHMR variants appear in the digest index.
- **Digest-as-output**: Verify that no write-path code pre-computes a
  BLAKE3 hash and passes it to the BlobStore.

### For Model

- The AS/DS duality (principal-state-model §4) is resolved at the storage
  level: AS uses append-only commit chain indexing; DS uses per-action
  `czd` indexing with mutable semantics. Both coexist within the same
  two-tier architecture.

### Resolved Questions

1. **Transactional ingest** — **RESOLVED: implementation-defined.** The
   [no-partial-commit] constraint expresses the goal (no permanently
   incomplete blob sets). The mechanism (batch writes, journaling, or
   idempotent recovery) is a backend concern.

2. **EML persistence path** — **RESOLVED: EML `Storage` trait.** The EML
   already persists its internal state through its own `Storage` trait. The
   Cyphr storage engine treats the EML as an opaque subsystem.

3. **DR digest index** — **RESOLVED: per-action indexing.** The digest index
   SHOULD include per-action `czd` entries. DR remains as a commit-level
   snapshot consistency check.

4. **Authenticated index** — **RESOLVED: rejected (2026-06-01).** Four
   authenticated index structures (JMT, sorted index tables, MSTs,
   distributed primitives) were evaluated and rejected. Chain replay
   provides trustless completeness for per-principal queries. See the
   [storage object model sketch](../../.sketches/2026-05-28-storage-object-model.md)
   for the full rationale.

5. **Index backend** — **RESOLVED: SQLite (2026-06-01).** SQLite replaces
   Fjall for the index layer. B-trees match the read-heavy workload; schema
   flexibility is critical for a pre-alpha protocol. See
   [`indexer-sqlite.md`](indexer-sqlite.md).

6. **Separate durability** — **RESOLVED: yes (2026-06-01).** Content store
   and index are separate databases. Cross-store atomicity is not a
   correctness requirement — recovery re-indexing handles partial failures.

7. **Recovery ordering** — **RESOLVED: deterministic (2026-06-01).** The
   commit wire format (`txs`, `txs_order`, `pre`) carries explicit ordering
   metadata (SPEC.md §4.6). Re-indexing follows `pre`-linked chain order
   and reads transaction/coz order directly from the commit structure.
   No permutation search or brute-force ordering is required or acceptable.
   The earlier implementation's permutation scan was an artifact of a flat
   blob model that did not preserve commit structure — that model is
   superseded by the current architecture which stores commits as
   self-describing bundles with explicit ordering.

8. **Blob scope** — **RESOLVED: protocol messages only (2026-06-01).** The
   BlobStore stores protocol messages (commits, transactions, actions) —
   NOT Data Tree payload data. DT actions reference external data by
   hash/URI; the actual data lives outside the protocol's blob service.
   See [`blob-store.md`](blob-store.md) § "Scope boundary".

9. **Witness storage** — **RESOLVED: no special treatment (2026-06-01).** A
   witness is itself a principal (SPEC.md §2.2.15). Its commits traverse
   the same protocol and storage path as any other principal's commits.
   No separate partition or special storage treatment is warranted.
