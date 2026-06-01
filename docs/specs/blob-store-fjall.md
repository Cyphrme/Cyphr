# SPEC: Fjall BlobStore Implementation

<!--
  SPEC document — Fjall-specific implementation of the BlobStore trait.
  Source: storage-engine.md, .sketches/2026-05-28-storage-object-model.md
  Crate:  rs/cyphr-blob-fjall/ (see storage-engine.md [crate-isolation])
  Authority: SPEC.md (Zamicol and nrdxp)

  This document specifies the Fjall LSM-tree implementation of the abstract
  BlobStore API defined in blob-store.md. It covers physical layout,
  atomicity guarantees, and Fjall-specific configuration.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Production-grade persistent implementation of the
`BlobStore` trait using [Fjall](https://github.com/fjall-rs/fjall), a
pure-Rust LSM-tree key-value store.

**Why Fjall:** The content store workload is simple key-value get/put by
BLAKE3 hash. Fjall is:
- Pure Rust (no C FFI, no build dependencies)
- Crash-safe (WAL-backed)
- Suitable for write-heavy append-only workloads (LSM-tree)
- Embeddable (no separate process)
- `Arc`-backed `Keyspace` for cheap cross-thread sharing

**Why NOT SQLite for blobs:** Content-addressed blobs are opaque byte
sequences with no relational structure. A KV store is the natural fit.
SQLite's B-tree is optimized for ordered, relational data — overhead
without benefit for hash→bytes access.

**Cross-references:**
[`blob-store.md`](blob-store.md) (abstract API),
[`storage-engine.md`](storage-engine.md) (engine coordination).

## Physical Layout

```
Fjall Keyspace
│
└── "blobs"           Content-addressed blob partition
    Key:   BLAKE3 hash (32 bytes, raw)
    Value: Raw blob bytes (commit JSON, transaction JSON, or coz envelope)
```

A witness is itself a principal (SPEC.md §2.2.15). Its commits traverse the
same protocol and storage path as any other principal's commits. No separate
partition is warranted — artificially segregating the witness's data would
undermine the protocol's natural treatment of witnesses as principals.


### Keyspace Configuration

**[fjall-single-keyspace]**: The BlobStore SHOULD share a Fjall `Keyspace`
with the EML backend (`eml-storage-fjall`) when both are in use. Sharing
a keyspace means:
- Single WAL — one crash-recovery journal
- Single `Batch` can span both BlobStore and EML partitions
- Shared background flush/compaction threads

The `Keyspace` is `Arc`-backed and cheaply cloneable. Creating a
`FjallBlobStore` from an existing `Keyspace` MUST NOT open a new database.

**[fjall-partition-isolation]**: The blob partition (`"blobs"`) and EML
partitions (`"eml_leaves"`, `"eml_nodes"`, `"eml_meta"`) MUST use separate
logical partitions within the shared keyspace. Reads and writes to blobs
MUST NOT interfere with EML internal state.

## Constraints

### Atomicity

**[no-partial-commit]**: After a successful ingest, all blobs for a commit
MUST be present in the BlobStore. An implementation MUST NOT leave a
commit's blob set in a permanently incomplete state. Fjall's `Batch` type
provides cross-partition atomic writes — a single batch write MAY span
both the blob partition and EML partitions for commit-level atomicity.

**Current implementation note:** The `FjallBlobStore` writes blobs
individually (one `insert` per blob). Cross-blob atomicity relies on the
engine's recovery semantics ([recovery-reindex]) rather than batch writes.
This is acceptable because blob writes are idempotent — a crash between
blob N and blob N+1 leaves blob N stored and blob N+1 missing, which
re-ingest will detect and repair.

### Write Mapping

**[fjall-put-mapping]**: The `put` implementation for Fjall computes the
BLAKE3 hash of the provided bytes and issues a single
`partition.insert(hash, bytes)`. Fjall's insert is synchronous; the async
wrapper uses `spawn_blocking` (or equivalent) to avoid blocking the
executor.

For protocol message payloads, the implementation SHOULD enforce a
maximum blob size and reject writes exceeding it. The current
implementation does not enforce a limit — this is tracked as a future
concern.

### Compaction

**[fjall-compaction]**: Fjall's LSM-tree compaction is transparent to the
BlobStore. The implementation MUST NOT require manual compaction management.
Fjall's background compaction SHOULD be configured for the blob workload:
- Large L0 threshold (blobs are write-once, read-many)
- Leveled compaction (default) — reduces read amplification for point lookups

### Iteration

**[fjall-iter-consistency]**: The `iter()` implementation MUST return a
consistent snapshot of all stored blob hashes. Fjall's snapshot isolation
provides this — the iterator sees a frozen view of the partition at the
time of creation.

## Error Mapping

| Fjall error | BlobStoreError variant |
|:------------|:----------------------|
| `fjall::Error` (I/O, corruption) | `Backend(error.to_string())` |
| Hash mismatch on verification read | `HashMismatch { expected, actual }` |
| I/O error during write buffering | `Io(error)` |

## Configuration

| Parameter | Default | Notes |
|:----------|:--------|:------|
| Partition name | `"blobs"` | Fixed — not user-configurable |
| Block size | Fjall default (4 KB) | Suitable for typical coz blobs (1-5 KB) |
| Compression | Fjall default (LZ4) | Reduces disk usage; coz JSON compresses well |
| WAL | Enabled (Fjall default) | Required for crash safety |

## Verification

| Constraint (from blob-store.md) | Status | Notes |
|:-------------------------------|:-------|:------|
| [blake3-content-address] | pass | BLAKE3 computed in `put()`, used as insert key |
| [blake3-isolation] | pass | No protocol hashes used in BlobStore |
| [blob-immutability] | pass | Content-addressed — same content = same key = idempotent |
| [put-write] | pass | `put(bytes)` hashes and inserts atomically |
| [digest-as-output] | pass | `put()` returns computed Blake3Hash |
| [get-by-hash] | pass | partition.get(hash) |
| [existence-check] | pass | partition.contains_key(hash) |
| [blob-iteration] | pass | partition.iter() over all keys |
| [async-storage] | pass | Async wrapper over synchronous Fjall API |
| [runtime-agnostic] | pass | No runtime types in trait; impl uses spawn_blocking |
| [send-sync] | pass | Fjall Keyspace is Arc-backed, Partition is Send+Sync |
