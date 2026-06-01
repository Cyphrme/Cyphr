# SPEC: Content-Addressed Blob Store

<!--
  SPEC document — abstract API requirements for the BlobStore layer.
  Source: storage-engine.md (original), .sketches/2026-05-28-storage-object-model.md
  Authority: SPEC.md (Zamicol and nrdxp)

  This document specifies the backend-agnostic contract for content-addressed
  blob storage. Implementation-specific details (Fjall partitions, SQLite
  schemas, etc.) belong in their respective implementation specs.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.

  See: .agent/workflows/spec.md for the full protocol specification.
-->

## Domain

**Problem Domain:** Content-addressed storage of raw cryptographic protocol
messages — commits, transactions, and signed actions — as immutable blobs
keyed by BLAKE3 digest.

**Scope boundary:** The BlobStore stores **protocol messages only**. Data
Tree (DT) actions reference external data (files, media, encrypted payloads)
by hash and/or URI, but the actual data referenced by DT actions lives
outside the protocol's blob service. Storing DT-referenced payload data is
a separate concern, not governed by this spec.

**Role in Architecture:** Layer 0 — the durable source of truth. All other
storage structures (indexes, caches, derived views) are secondary projections
rebuildable from blob content. The BlobStore is the only storage component
whose data loss is irrecoverable from local state alone.

**Cross-references:**
[`storage-engine.md`](storage-engine.md) (engine coordination),
[`indexer.md`](indexer.md) (secondary index),
[`blob-store-fjall.md`](blob-store-fjall.md) (Fjall implementation).

## Type Declarations

```
TYPE Blake3Hash      = Opaque[32]           -- 32-byte BLAKE3 digest
TYPE Blob            = Opaque[*]            -- Raw coz wire-format bytes
TYPE BlobStore       = Blake3Hash → Maybe<Blob>
TYPE WriteHandle     = AsyncWrite + Unpin + Send
```

## Constraints

### Content Addressing

**[blake3-content-address]**: The BlobStore MUST use BLAKE3 as its sole
content-addressing algorithm. The BLAKE3 hash of a blob's raw bytes IS
its storage key. No other addressing scheme is permitted.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — Blake3Hash type, FjallBlobStore`

**[blake3-isolation]**: BLAKE3 hashes MUST NOT be conflated with protocol
hash algorithms (SHA-256, SHA-384, SHA-512). Storage hashes identify raw
bytes for persistence; protocol digests identify semantic objects for
verification. An implementation MUST NOT use a protocol hash algorithm
as the BlobStore content-addressing algorithm.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — separate Blake3Hash type`

### Immutability

**[blob-immutability]**: Once stored, a blob MUST NOT be modified. The
BlobStore is append-only at the blob level. Storing identical content
MUST yield the same BLAKE3 hash and MUST NOT duplicate data (idempotent
put).
`VERIFIED: rs/cyphr-storage/src/blob/fjall_store.rs — content-addressed put`

### Write Interface

**[streaming-write]**: The BlobStore MUST use a streaming write as its
sole write primitive. The write path is:

1. `open_write()` → returns a `WriteHandle` (implements `AsyncWrite`)
2. Caller streams bytes into the handle
3. `close(handle)` → finalizes the write and returns the computed `Blake3Hash`

There is no `put(&[u8])` method on the trait. The streaming interface is
the only write path.

**Rationale:** A single write primitive eliminates dual code paths. All
protocol blobs (commits, transactions, actions) are small Coz JSON
envelopes, but the streaming interface generalizes cleanly and computes
BLAKE3 incrementally.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — open_write/close API`

**[max-blob-size]**: The BlobStore SHOULD enforce a configurable maximum
blob size. Since blobs are protocol messages (not DT payload data), they
are bounded by Coz envelope size. A witness SHOULD reject blobs exceeding
the configured limit to mitigate denial-of-service attacks. The default
limit is implementation-defined.
`VERIFIED: unverified (not yet implemented)`

**[digest-as-output]**: The BlobStore's write operation MUST compute and
return the content digest as output, not accept it as input. The caller
streams bytes via the write handle; the store computes the BLAKE3 hash
incrementally and returns it on finalization. This prevents hash-mismatch
defects at the API boundary.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — close() returns Blake3Hash`

### Read Interface

**[get-by-hash]**: The BlobStore MUST support retrieval by BLAKE3 hash,
returning `None` for unknown hashes. This is the only read primitive.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — get() method`

**[existence-check]**: The BlobStore MUST support an existence check
(`exists(hash) → bool`) that does not retrieve blob content. Used for
deduplication and index recovery.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — exists() method`

### Enumeration

**[blob-iteration]**: The BlobStore MUST support iterating over all
stored blob hashes. Used for index recovery (`reindex`). The iterator
MUST be consistent — it MUST NOT skip blobs that existed when iteration
began, and it MUST NOT return blobs that were never stored.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — iter() method`

### Async

**[async-storage]**: The `BlobStore` trait MUST expose an asynchronous
API. Storage backends may operate over network partitions, remote
filesystems, or distributed databases where blocking the calling task
is unacceptable. The trait MUST use RPITIT
(`impl Future<Output = ...> + Send`) to bound returned futures as `Send`
for multi-threaded executors.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — all methods use RPITIT`

### Thread Safety

**[send-sync]**: The `BlobStore` trait MUST require `Send + Sync`. The
store is shared across concurrent request handlers in the server.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — trait bound`

## Trait Signature

```rust
pub trait BlobStore: Send + Sync {
    type WriteHandle: tokio::io::AsyncWrite + Unpin + Send;

    fn open_write(&self) -> impl Future<Output = Result<Self::WriteHandle, BlobStoreError>> + Send;
    fn close(&self, handle: Self::WriteHandle) -> impl Future<Output = Result<Blake3Hash, BlobStoreError>> + Send;
    fn get(&self, hash: &Blake3Hash) -> impl Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send;
    fn exists(&self, hash: &Blake3Hash) -> impl Future<Output = Result<bool, BlobStoreError>> + Send;
    fn iter(&self) -> impl Future<Output = Result<Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>, BlobStoreError>> + Send;
}
```

## Forbidden States

**[no-protocol-hash-in-blobstore]**: The BlobStore MUST NOT use SHA-256,
SHA-384, or SHA-512 as its content-addressing algorithm. This prevents
collision-domain confusion between storage identity and protocol identity.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — hardcoded BLAKE3`

## Behavioral Properties

**[write-idempotency]**: Storing the same byte sequence twice MUST produce
the same `Blake3Hash` both times. The second write MUST NOT duplicate
storage. This is a safety property — content addressing guarantees it
by construction.

**[read-after-write]**: After `close(handle)` returns `Ok(hash)`, a
subsequent `get(hash)` MUST return `Some(data)` containing the bytes
that were written. The system MUST NOT exhibit stale reads after a
successful write.

**[hash-integrity]**: For any stored blob, `blake3::hash(blob_bytes)`
MUST equal the hash under which the blob is stored. A blob whose content
does not match its hash is a corruption — the implementation SHOULD
detect and report this.

## Implementations

| Backend | Crate | Status | Notes |
|:--------|:------|:-------|:------|
| Fjall (LSM-tree) | `cyphr-storage` | Production | See [`blob-store-fjall.md`](blob-store-fjall.md) |
| In-memory HashMap | `cyphr-storage` | Testing | `MemoryBlobStore` |
