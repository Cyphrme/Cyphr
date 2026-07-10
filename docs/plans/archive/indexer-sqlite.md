# ARCHIVED: SQLite Indexer Implementation

<!--
  ARCHIVED 2026-07-08. This is no longer a live spec. It documented the
  SQLite implementation of the Indexer trait, which was itself a
  2026-06-01 replacement of the original FjallIndexer. That SQLite
  implementation (`cyphr-index-sqlite`) was in turn retired 2026-07-08 by
  the KV-index migration, which reinstated a Fjall-backed Indexer
  (`cyphr-index-fjall`) as production. This document is kept for historical
  / archaeological reference only — read for the schema-design rationale
  that motivated the SQLite detour, not as a description of current
  behavior. The live abstract Indexer contract is `docs/specs/indexer.md`;
  the current production implementation is `rs/cyphr-index-fjall/`, which
  has no dedicated implementation-level spec doc of its own yet.

  Original header, preserved below for provenance:

  SPEC document — SQLite-specific implementation of the Indexer trait.
  Source: .sketches/2026-05-28-storage-object-model.md (ACCEPTED decision),
          docs/plans/archive/cyphr-server.md (SQLite selection rationale),
          storage-engine.md (original constraints)
  Crate:  rs/cyphr-index-sqlite/ (see storage-engine.md [crate-isolation])
  Authority: SPEC.md (Zamicol and nrdxp)

  This document specifies the planned SQLite implementation of the abstract
  Indexer API defined in indexer.md. It covers schema design, migration
  strategy, and the rationale for replacing the existing FjallIndexer.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
  "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when,
  and only when, they appear in all capitals, as shown here.
-->

## Domain

**Problem Domain:** Production-grade persistent implementation of the
`Indexer` trait using SQLite via `rusqlite` (bundled, no system dependency).

**Why SQLite replaces Fjall for the index:** The index workload is
read-heavy point lookups (tip checks, digest resolution, key lookups)
with infrequent writes (commit ingestion). After four research passes
(2026-06-01), the following factors drove the decision:

1. **B-trees outperform LSM-trees for read-heavy point lookups.** The
   FjallIndexer suffers from read amplification across multiple LSM levels.
   SQLite's B-tree provides O(log n) point lookups without level scanning.

2. **Schema flexibility for a pre-alpha protocol.** Query patterns evolve.
   SQLite provides declarative indexing (`CREATE INDEX`), schema migration
   (`ALTER TABLE`), and ad-hoc debugging (`sqlite3` CLI). The FjallIndexer
   requires redesigning composite key layouts and migrating data for every
   query pattern change.

3. **Manual key encoding is maintenance burden.** The FjallIndexer uses
   406 lines of manual key construction (`principal_id + "/" + hex(sequence)`,
   serde_json round-trips, prefix scans). SQLite replaces this with
   declarative schema.

4. **Separate durability is architecturally sound.** Content store (Fjall)
   is the durable source of truth — never lose a blob. Index (SQLite) is a
   derived, rebuildable projection — losing it is an inconvenience, not a
   catastrophe. No shared WAL needed.

The storage object model sketch (ref: `.sketches/2026-05-28-storage-object-model.md`,
Decision: ACCEPTED — Conventional Index with Chain Replay Verification)
provides full analysis including the Fjall index critique.

**Cross-references:**
[`indexer.md`](indexer.md) (abstract API),
[`storage-engine.md`](storage-engine.md) (engine coordination),
[`blob-store.md`](blob-store.md) (content store).

## Schema

The schema is designed around the natural domain: every protocol entity is
a signed Coz message with universal metadata (`typ`, `tmb`, `now`, `alg`,
`czd`). Cross-principal queries emerge naturally because these fields are
not scoped to a principal — they are intrinsic to every message.

### Core Tables

```sql
-- Every indexed Coz message (commit transactions, auth mutations, data actions).
-- This is the canonical event log. All other state is derived from it.
CREATE TABLE cozies (
    blob_hash     TEXT NOT NULL,       -- BLAKE3 hex (storage-level identity)
    czd           TEXT NOT NULL,       -- Tagged protocol digest (e.g., "SHA-256:U5X...")
    principal_id  TEXT NOT NULL,       -- Owning principal
    typ           TEXT NOT NULL,       -- Action type (e.g., "cyphr.me/cyphr/key/create")
    tmb           TEXT NOT NULL,       -- Signer thumbprint
    alg           TEXT NOT NULL,       -- Algorithm
    now           INTEGER NOT NULL,    -- Timestamp (Unix seconds)
    commit_seq    INTEGER,            -- Which commit included this coz (NULL for unconfirmed)
    payload       TEXT,               -- Raw JSON pay object (for json_extract queries)
    PRIMARY KEY (czd)
) WITHOUT ROWID;

-- Commit chain structure. One row per commit per principal.
-- Commits are the ordering/grouping layer; cozies are the content.
CREATE TABLE commits (
    principal_id  TEXT NOT NULL,
    sequence      INTEGER NOT NULL,
    commit_czd    TEXT NOT NULL,       -- czd of the commit/create coz
    pre           TEXT,               -- Prior PR (NULL for genesis)
    pr            TEXT NOT NULL,       -- Principal Root after this commit
    sr            TEXT NOT NULL,       -- State Root after this commit
    ar            TEXT NOT NULL,       -- Auth Root after this commit
    blob_hashes   TEXT NOT NULL,       -- JSON array of BLAKE3 hashes in this commit
    created_at    INTEGER NOT NULL,    -- Commit timestamp (from commit/create now)
    PRIMARY KEY (principal_id, sequence)
) WITHOUT ROWID;

-- Protocol digest → storage blob resolution (all MHMR variants).
-- This is a lookup table, not an event log. Keyed by tagged digest.
CREATE TABLE digests (
    digest        TEXT PRIMARY KEY,    -- Tagged digest string ("SHA-256:U5XUZ...")
    blob_hash     TEXT NOT NULL,       -- BLAKE3 hex
    entity_type   TEXT NOT NULL        -- "commit", "transaction", or "action"
) WITHOUT ROWID;

-- Public key metadata (extracted from key-introducing cozies).
-- NOTE: `public_key` bytes are sourced from the unsigned `keys` auxiliary
-- field of the commit wire format (SPEC §4.6), NOT from the Merkle-committed
-- chain state. Only `tmb` (thumbprint) is committed to KT. This table is a
-- pragmatic convenience cache — `thumbprint`, `algorithm`, `principal_id`,
-- `introduced_at`, and `revoked_at` are chain-derivable; `public_key` is not.
CREATE TABLE public_keys (
    thumbprint    TEXT PRIMARY KEY,
    algorithm     TEXT NOT NULL,
    principal_id  TEXT NOT NULL,
    public_key    TEXT NOT NULL,       -- Base64url-encoded (from wire `keys`, NOT chain)
    introduced_at INTEGER NOT NULL,    -- Commit sequence where key appeared
    revoked_at    INTEGER             -- Commit sequence where key was revoked (NULL if active)
) WITHOUT ROWID;
```

### Materialized Views

`tips` and `principals` are materialized as normal tables, updated
atomically within the `index_commit()` transaction. They are convenience
projections — an operator could reconstruct them from `commits` alone.

```sql
-- Current tip state per principal (hot path).
CREATE TABLE tips (
    principal_id  TEXT PRIMARY KEY,
    pr            TEXT NOT NULL,
    sr            TEXT NOT NULL,
    ar            TEXT NOT NULL,
    commit_czd    TEXT NOT NULL,
    commit_count  INTEGER NOT NULL,
    last_updated  INTEGER NOT NULL
) WITHOUT ROWID;

-- Principal summary (for list_principals).
CREATE TABLE principals (
    principal_id  TEXT PRIMARY KEY,
    pr            TEXT NOT NULL,
    commit_count  INTEGER NOT NULL,
    created       INTEGER NOT NULL,
    last_updated  INTEGER NOT NULL
) WITHOUT ROWID;
```

### Indexes

```sql
-- Cross-principal queries on cozies (the central value proposition)
CREATE INDEX idx_cozies_typ       ON cozies(typ);
CREATE INDEX idx_cozies_tmb       ON cozies(tmb);
CREATE INDEX idx_cozies_now       ON cozies(now);
CREATE INDEX idx_cozies_principal ON cozies(principal_id);
CREATE INDEX idx_cozies_blob      ON cozies(blob_hash);
CREATE INDEX idx_cozies_commit    ON cozies(principal_id, commit_seq);

-- Commit lookups
CREATE INDEX idx_commits_czd      ON commits(commit_czd);
CREATE INDEX idx_commits_time     ON commits(created_at);

-- Digest reverse lookup (BLAKE3 → protocol digests)
CREATE INDEX idx_digests_blob     ON digests(blob_hash);

-- Key lookups
CREATE INDEX idx_keys_principal   ON public_keys(principal_id);
```

### Schema Design Rationale

**Cozies table as canonical event log**: Every protocol entity (key/create,
key/revoke, commit/create, comment/create, etc.) is a signed Coz message
with the same universal metadata fields. Indexing these uniformly in a
single table enables cross-principal queries naturally:

```sql
-- All key revocations across all principals in the last hour
SELECT * FROM cozies WHERE typ = 'cyphr.me/cyphr/key/revoke' AND now > ?;

-- All actions by a specific signer across all principals
SELECT * FROM cozies WHERE tmb = ?;

-- All comment/create actions (cross-principal)
SELECT * FROM cozies WHERE typ = 'cyphr.me/comment/create' ORDER BY now DESC;

-- Operator: what happened recently?
SELECT * FROM cozies ORDER BY now DESC LIMIT 50;
```

None of these queries require specialized tables or schema changes.

**`payload` column for unstructured data**: Data actions carry
application-specific fields (SPEC.md §4.8). The `payload` column stores
the raw `pay` JSON object, enabling ad-hoc queries via `json_extract()`
without schema changes:

```sql
-- Find all comments containing a specific word (operator debugging)
SELECT * FROM cozies
WHERE typ = 'cyphr.me/comment/create'
  AND json_extract(payload, '$.msg') LIKE '%hello%';
```

For frequently queried payload fields, SQLite generated columns promote
JSON paths to indexed virtual columns without schema migration:

```sql
ALTER TABLE cozies ADD COLUMN msg TEXT
GENERATED ALWAYS AS (json_extract(payload, '$.msg')) VIRTUAL;
CREATE INDEX idx_cozies_msg ON cozies(msg);
```

**`WITHOUT ROWID`**: All tables use natural primary keys stored directly
in the B-tree, eliminating the hidden `rowid` column and reducing I/O
for point lookups.

**`blob_hashes` as JSON array in commits**: Commit blob hashes are stored
as a JSON array rather than a join table. We always read/write ALL blob
hashes for a commit atomically, never query individual ones.

**Timestamps as INTEGER**: Unix timestamps (i64) for range queries
without string parsing.

**`introduced_at` / `revoked_at` as sequence numbers**: Key lifecycle is
tied to commit sequence rather than wall-clock time. This supports
deterministic replay — key active periods are defined by chain position,
not timestamps.

## Dependencies

**[rusqlite-dependency]**: The `SqliteIndexer` MUST use `rusqlite` (with
the `bundled` feature) as its SQLite binding. Alternatives were evaluated:

| Crate        | Verdict      | Rationale                                                                                                                                                                                              |
| :----------- | :----------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **rusqlite** | **Selected** | Synchronous API matches the actor pattern. Direct SQL matches our specified DDL. Ecosystem standard for embedded SQLite in Rust (used by nostr-rs-relay, iroh).                                        |
| sqlx         | Rejected     | Async-native, but wraps async-over-sync-over-async for SQLite (no benefit with the actor model). Compile-time query checking cannot verify SQLite-specific features (`WITHOUT ROWID`, `json_extract`). |
| diesel       | Rejected     | Full ORM adds indirection over a schema we've already specified down to exact DDL. Macro-heavy, opinionated.                                                                                           |

The actor model (see below) naturally bridges `rusqlite`'s synchronous
API to the async `Indexer` trait.

## Async Model

SQLite is synchronous. The `SqliteIndexer` MUST bridge to async using one
of two patterns:

**Option A (recommended): Actor model via `tokio::sync::mpsc`**

A dedicated thread owns the `rusqlite::Connection`. Async methods send
requests through a channel and receive responses. This avoids blocking
the Tokio executor and naturally serializes writes.

```
     Tokio tasks                         SQLite thread
    ┌──────────┐     mpsc::channel      ┌──────────────┐
    │ get_tip() ├───── Request ─────────►│              │
    │           │◄──── Response ─────────┤ Connection   │
    └──────────┘     oneshot::channel    │ (single)     │
    ┌──────────┐                        │              │
    │ index_   ├───── Request ─────────►│              │
    │ commit() │◄──── Response ─────────┤              │
    └──────────┘                        └──────────────┘
```

**Option B: `spawn_blocking`**

Wrap each synchronous SQLite call in `tokio::task::spawn_blocking()`. Simpler
but risks exhausting the blocking thread pool under load.

The actor model is preferred because it:

- Serializes writes naturally (single connection, no locking)
- Avoids thread pool exhaustion
- Allows connection-level pragmas to persist across calls

## Connection Configuration

```sql
-- Set on connection open
PRAGMA journal_mode = WAL;          -- Write-Ahead Logging for concurrent reads
PRAGMA synchronous = NORMAL;        -- Acceptable since index is rebuildable
PRAGMA cache_size = -8000;          -- 8 MB page cache
PRAGMA foreign_keys = OFF;          -- No FK constraints (rebuildable index)
PRAGMA busy_timeout = 5000;         -- 5 second retry on lock contention
```

**`synchronous = NORMAL`**: The index is rebuildable from the BlobStore.
Fsync on every transaction is unnecessary — a crash losing the last few
index writes is repaired by re-indexing. The content store (Fjall) MUST
use `synchronous = FULL` equivalent for its WAL.

**`journal_mode = WAL`**: Required for concurrent reads while a write is
in progress. The server handles concurrent HTTP requests that read tips
while new commits are being indexed.

## Transaction Strategy

**[sqlite-write-transaction]**: `index_commit()` MUST execute within a
single SQLite transaction. The writes across `cozies`, `commits`, `digests`,
`public_keys`, `tips`, and `principals` MUST be atomic — no partially
indexed commit is observable.

```sql
BEGIN IMMEDIATE;
  -- Index each coz in the commit
  INSERT OR IGNORE INTO cozies (...) VALUES (...);  -- repeated per coz
  -- Index the commit chain entry
  INSERT OR IGNORE INTO commits (...) VALUES (...);
  -- Index all MHMR digest variants
  INSERT OR IGNORE INTO digests (...) VALUES (...);  -- repeated per variant
  -- Index any new keys
  INSERT OR IGNORE INTO public_keys (...) VALUES (...);
  -- Update materialized views
  INSERT OR REPLACE INTO tips (...) VALUES (...);
  INSERT OR REPLACE INTO principals (...) VALUES (...);
COMMIT;
```

**`INSERT OR IGNORE`** for cozies, commits, and digests ensures idempotency
per [index-idempotent]. Re-indexing the same commit produces identical
entries, which are silently ignored.

**`INSERT OR REPLACE`** for tips and principals ensures the latest state
always wins per [no-stale-tip].

## Method Mapping

| Indexer method       | SQLite query                                                                                                                       |
| :------------------- | :--------------------------------------------------------------------------------------------------------------------------------- |
| `index_commit()`     | Transaction: INSERT across 6 tables (cozies, commits, digests, public_keys, tips, principals)                                      |
| `get_tip()`          | `SELECT * FROM tips WHERE principal_id = ?`                                                                                        |
| `get_commit_chain()` | `SELECT * FROM commits WHERE principal_id = ? AND sequence BETWEEN ? AND ? ORDER BY sequence`                                      |
| `resolve_digest()`   | `SELECT * FROM digests WHERE digest = ?`                                                                                           |
| `list_principals()`  | `SELECT * FROM principals`                                                                                                         |
| `clear()`            | `DELETE FROM cozies; DELETE FROM commits; DELETE FROM digests; DELETE FROM public_keys; DELETE FROM tips; DELETE FROM principals;` |
| `get_key()`          | `SELECT * FROM public_keys WHERE thumbprint = ?`                                                                                   |

## Migration Strategy

### From FjallIndexer to SqliteIndexer

The migration is non-destructive because the index is rebuildable:

1. Implement `SqliteIndexer` behind the `Indexer` trait
2. Replace `FjallIndexer` in the `StorageEngine` constructor
3. On first startup with SQLite, run `reindex(total_check=true)` to
   populate from the BlobStore
4. Remove `FjallIndexer` code

No data migration, no deprecation period. The project is pre-alpha with no
users — cleanliness and correctness take precedence over compatibility.

### Schema Versioning

The SQLite database SHOULD include a version table:

```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT INTO schema_version (version) VALUES (1);
```

Schema migrations check `MAX(version)` on startup and apply pending
migrations sequentially.

## Error Mapping

| SQLite error                             | IndexerError variant         |
| :--------------------------------------- | :--------------------------- |
| `rusqlite::Error::QueryReturnedNoRows`   | `NotFound(context)`          |
| `rusqlite::Error` (other)                | `Backend(error.to_string())` |
| Constraint violation on duplicate commit | No-op (idempotent)           |
| `UNIQUE` violation on digest             | No-op (idempotent)           |

## Verification

| Constraint (from indexer.md) | Status | Notes                                                     |
| :--------------------------- | :----- | :-------------------------------------------------------- |
| [index-secondary]            | pass   | Rebuildable via `reindex()` from BlobStore                |
| [index-idempotent]           | pass   | `INSERT OR IGNORE` for commits/digests                    |
| [digest-index-completeness]  | pass   | Engine provides all MHMR variants; SQLite stores verbatim |
| [no-stale-tip]               | pass   | `INSERT OR REPLACE` in atomic transaction                 |
| [no-orphaned-index]          | pass   | Engine stores blobs before indexing                       |
| [recovery-reindex]           | pass   | `clear()` + full re-index from BlobStore                  |
| [monotonic-sequence]         | pass   | `PRIMARY KEY (principal_id, sequence)` enforces           |
| [commit-chain-integrity]     | pass   | `ORDER BY sequence` ensures contiguity                    |
| [async-index]                | pass   | Actor model bridges sync SQLite to async trait            |
| [send-sync-index]            | pass   | Actor handle (`mpsc::Sender`) is `Send + Sync`            |

## Implementation Status

| Component                     | Status                              |
| :---------------------------- | :---------------------------------- |
| Schema design                 | Specified (this document)           |
| `SqliteIndexer` struct        | Implemented                         |
| Actor model (async bridge)    | Implemented (tokio::sync::mpsc)     |
| Migration from `FjallIndexer` | Complete (FjallIndexer removed)     |
| Schema versioning             | Implemented (schema_version table)  |
| Integration tests             | Implemented (unit + proptest)       |
