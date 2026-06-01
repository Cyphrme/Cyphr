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

**[put-write]**: The BlobStore MUST expose `put(&[u8])` as its sole write
primitive. The caller provides the complete blob bytes; the store computes
the BLAKE3 hash and returns it.

**Rationale:** Protocol blobs are small Coz JSON envelopes (typically
1-5 KB), bounded by [max-blob-size]. A single `put` call is the simplest
correct API — one method, one failure point, no handle lifecycle. This
aligns with Irmin's `add(value) → key` pattern (the purest content-
addressable store design) and EML's `store_leaf(index, &[u8])` pattern.
A streaming write interface (open/write/close) was evaluated and rejected:
it splits one conceptual operation into two fallible steps with a handle
state in between, adding ceremony with no benefit for small payloads.
`VERIFIED: unverified (implementation uses streaming; to be refactored)`

**[max-blob-size]**: The BlobStore SHOULD enforce a configurable maximum
blob size. Since blobs are protocol messages (not DT payload data), they
are bounded by Coz envelope size. A witness SHOULD reject blobs exceeding
the configured limit to mitigate denial-of-service attacks. The default
limit is implementation-defined.
`VERIFIED: unverified (not yet implemented)`

**[digest-as-output]**: The BlobStore's `put` operation MUST compute and
return the content digest as output, not accept it as input. The store
computes the BLAKE3 hash internally and returns it on completion. This
prevents hash-mismatch defects at the API boundary — the store owns the
hash function. (Irmin pattern; contrast IPFS Blockstore where the CID is
caller-supplied, requiring a paranoia flag `HashOnRead` to compensate.)
`VERIFIED: unverified (implementation uses streaming; to be refactored)`

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

> **Note:** RPITIT (`-> impl Future<...> + Send`) is the *desugared form*
> of `async fn`. Rust's `async fn` in traits (stable since 1.75) does not
> automatically add a `Send` bound to the returned future, which would
> prevent use from multi-threaded executors. The explicit `impl Future +
> Send` form is used instead to enforce this bound at the trait level.

`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — all methods use RPITIT`

**[runtime-agnostic]**: The `BlobStore` trait MUST NOT depend on any
specific async runtime (tokio, smol, async-std, etc.) in its signature.
All methods use bare `impl Future + Send` via RPITIT, which is executor-
agnostic. Runtime-specific types (e.g., `tokio::sync::mpsc`,
`tokio::task::spawn_blocking`) belong in implementation crates, not in
the trait definition. This permits alternative runtimes for constrained
environments without modifying the trait.

### Thread Safety

**[send-sync]**: The `BlobStore` trait MUST require `Send + Sync`. The
store is shared across concurrent request handlers in the server.
`VERIFIED: rs/cyphr-storage/src/blob/mod.rs — trait bound`

## Trait Signature

```rust
pub trait BlobStore: Send + Sync {
    fn put(&self, data: &[u8]) -> impl Future<Output = Result<Blake3Hash, BlobStoreError>> + Send;
    fn get(&self, hash: &Blake3Hash) -> impl Future<Output = Result<Option<Vec<u8>>, BlobStoreError>> + Send;
    fn exists(&self, hash: &Blake3Hash) -> impl Future<Output = Result<bool, BlobStoreError>> + Send;
    fn iter(&self) -> impl Future<Output = Result<Box<dyn Iterator<Item = Result<Blake3Hash, BlobStoreError>> + Send>, BlobStoreError>> + Send;
}
```

No associated types. No runtime-specific imports. Four methods.

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

**[read-after-write]**: After `put(data)` returns `Ok(hash)`, a
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
