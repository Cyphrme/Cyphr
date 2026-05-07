# PLAN: Cyphr Server

<!--
  Produced from /plan COMMIT phase.
  Source sketch: .sketches/2026-05-01-cyphrme-protocol-transition.md
  Challenge and scope findings are recorded in the sketch lifecycle journal.
-->

## Goal

Implement a Rust-based Cyphr server capable of operating as either an
**authority** (canonical state holder, accepts pushes) or a **witness**
(verifying replica, syncs from authorities). Both modes share the same
protocol engine, storage layer (BLAKE3-addressed redb BlobStore + SQLite
Indexer), and MSS HTTP API (SPEC §13.4). The mode is a configuration knob,
not an architectural bifurcation. This is the first realization of the Cyphr
Protocol as a deployable network service.

## Constraints

- **Protocol boundary inviolable:** `rs/cyphr` (core protocol engine) must
  not be modified for server needs. The server is a consumer, not an extension.
- **BLAKE3 for storage addressing:** The BlobStore uses BLAKE3 digests as
  content keys, deliberately disjoint from the protocol's hash algorithm set
  (SHA-256, SHA-384, SHA-512) to prevent ambiguity between storage addresses
  and protocol digests.
- **Validate-first write path:** All cryptographic verification (signatures,
  chain continuity, state root computation) occurs in memory via
  `cyphr::Principal` before any persistence. No rollback scenario exists.
- **MSS API conformance:** The server implements the HTTP endpoints defined
  in SPEC §13.4: `/tip`, `/patch`, `/push`, `/e/<digest>`.
- **Single-binary deployment:** No external database processes. All storage
  is embedded (redb + SQLite).
- **Dual-mode operation:** A single binary operates as authority or witness
  based on TOML configuration. The distinction is a write-policy and
  sync-direction concern, not an architectural fork.
- **12-factor methodology:** The server adheres to the [twelve-factor app](https://12factor.net/)
  principles throughout. Configuration from file (figment + TOML), environment
  (`CYPHR_*`), and CLI (clap derive) — shared config structs, no duplication.
  Logs as event streams to stdout (not files). Storage as attached resources.
  Admin tasks as subcommands on the same binary. See §12-Factor Compliance.
- **Structured observability from day 1:** `tracing` crate with
  `tracing-subscriber` (EnvFilter, JSON/pretty output), `tower-http::TraceLayer`
  for request spans, and `#[instrument]` on engine/handler functions. Not
  retrofitted — established in the crate scaffold.
- **Rust-first:** Go server implementation is not part of this plan.

## Decisions

| Decision                 | Choice                                  | Rationale                                                                                                                                                                                                                                                                                                                              |
| :----------------------- | :-------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BlobStore hash algorithm | BLAKE3                                  | Fast, secure, deliberately absent from protocol hash set — zero ambiguity between storage and protocol digests                                                                                                                                                                                                                         |
| BlobStore backend        | fjall (v2.9)                            | Pure Rust, LSM-tree (RocksDB-inspired). Write-optimized for blob ingestion. Free-standing iterators (no transaction-scoped lifetimes). Built-in LZ4 compression. KV-separation for large blobs. Sled rejected (alpha stability). RocksDB rejected (C++ dependency). redb rejected (CoW B-tree iterator lifetimes leak into trait API). |
| Indexer backend          | SQLite via rusqlite                     | Relational JOINs across commit→tx→entry hierarchy + `json_extract()` for variable-schema data actions. Rebuildable from BlobStore.                                                                                                                                                                                                     |
| Async SQLite strategy    | Actor model                             | Single dedicated thread owns the `rusqlite::Connection`, communicates via `tokio::sync::mpsc`. Eliminates contention by construction. `tokio-rusqlite` is an acceptable alternative.                                                                                                                                                   |
| HTTP framework           | axum + tokio                            | De facto Rust async HTTP stack. Tower middleware for rate limiting, CORS, tracing.                                                                                                                                                                                                                                                     |
| Trait evolution          | Replace legacy `Store`                  | `BlobStore`/`Indexer` replace the legacy `Store` trait and `FileStore`. No dual API surface. CLI updated to new API later. Pre-alpha: backward compatibility is explicitly not a concern.                                                                                                                                              |
| Configuration            | figment + clap derive                   | figment loads TOML config file; clap handles CLI args + env vars (`CYPHR_*`). Shared `ServerConfig` struct (`Deserialize` + `Parser`). clap handles env vars (not figment) so they appear in `--help`. Precedence: defaults → file → env → CLI.                                                                                        |
| Observability            | tracing ecosystem (composable registry) | `tracing` + `tracing-subscriber` registry with composable layers. `EnvFilter` via `RUST_LOG`, JSON/pretty to stderr. `tower-http::TraceLayer` for request spans. `#[instrument]` on engine methods. Registry pattern explicitly designed for future OTLP/OpenTelemetry expansion (add a layer, not a rewrite).                         |
| Server identity          | Cyphr principal                         | The server bootstraps its own key pair and signs bearer tokens as a Cyphr principal — verifiable by clients via standard PoP.                                                                                                                                                                                                          |
| Sync interface           | NullSyncer stub                         | Trait defined, no peer sync implementation. Client-driven MSS is sufficient for single-authority deployment.                                                                                                                                                                                                                           |

## 12-Factor Compliance

| Factor                 | Approach                                                                                                                                                                                          |
| :--------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| I. Codebase            | Mono-repo (`Cyphrpass`), single deployable per server crate                                                                                                                                       |
| II. Dependencies       | Explicitly declared in `Cargo.toml`, vendored via `cargo`                                                                                                                                         |
| III. Config            | figment (TOML file) + clap (CLI + env). Shared struct. `CYPHR_*` env namespace. Nothing hardcoded.                                                                                                |
| IV. Backing services   | fjall and SQLite are attached resources — paths configured, not compiled in. Swappable via trait.                                                                                                 |
| V. Build, release, run | `cargo build --release` → binary artifact → run with config. Strict separation.                                                                                                                   |
| VI. Processes          | Stateless process. All durable state in storage (fjall + SQLite). In-process principal cache is ephemeral and reconstructible.                                                                    |
| VII. Port binding      | axum binds to configured `listen` address. Self-contained, no app server.                                                                                                                         |
| VIII. Concurrency      | tokio runtime. Scale via process model (multiple instances with distinct data dirs). Architecture does not prevent horizontal scaling.                                                            |
| IX. Disposability      | Fast startup (index pre-built in SQLite). Graceful SIGTERM shutdown (drain connections, flush writes). Crash recovery via index rebuild from BlobStore.                                           |
| X. Dev/prod parity     | Same binary, different config. In-memory storage backends implement the same `BlobStore`/`Indexer` traits as production backends — not separate interfaces. JSON tracing (prod) vs. pretty (dev). |
| XI. Logs               | Event stream to stderr only. Server does NOT manage log files, rotation, or destinations. Execution environment handles routing.                                                                  |
| XII. Admin processes   | Index rebuild, data export/import as CLI subcommands on the same `cyphr-server` binary. Same config loading, same dependencies.                                                                   |

## Risks & Assumptions

| Risk / Assumption                                  | Severity | Status       | Mitigation / Evidence                                                                                                                  |
| :------------------------------------------------- | :------- | :----------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| Async/sync impedance (rusqlite + tokio)            | MEDIUM   | Mitigated    | Actor model (dedicated thread + mpsc channels) or `tokio-rusqlite`. Must be designed explicitly in Phase 2, not deferred.              |
| Dual-backend crash inconsistency (fjall ↔ SQLite) | MEDIUM   | Mitigated    | BlobStore IS the durable log; index is always rebuildable. Recovery path (scan BlobStore for unindexed blobs) implemented in Phase 2.  |
| Over-engineered index schema for day 1             | LOW      | Accepted     | Index is ephemeral (DROP + rebuild). Schema changes are non-catastrophic. Cost of starting with full schema is small.                  |
| Existing import/export paths assume JSONL          | LOW      | Accepted     | Server write path is new code. Legacy `Store`/`FileStore` will be replaced, not retained alongside new traits. CLI updated separately. |
| Protocol engine needs no modification              | —        | ✅ Validated | Pre-implementation audit: 66+7 tests passing, clean crate boundary, data actions tested.                                               |
| fjall is production-ready                          | —        | ✅ Validated | Pure Rust LSM-tree, actively maintained, v2.9 (2025). Thread-safe, crash-safe via WAL, cross-partition atomic writes.                  |
| BLAKE3 crate is mature                             | —        | ✅ Validated | Official BLAKE3 team implementation, widely deployed.                                                                                  |
| SQLite is right for index (vs. redb-only)          | —        | ⚠️ Partial   | Relational JOINs + `json_extract()` justify the complexity. Async friction solvable via actor model.                                   |
| MSS API maps to protocol engine API                | —        | ⚠️ Partial   | `/push` and `/tip` map cleanly. `/patch` (delta construction) is new logic.                                                            |

## Open Questions

- **Commit bundle blob storage:** Store the full `txs` wire-format as a
  separate blob for fast MSS re-serving on `/patch`, or reconstruct from
  individual cozies on demand? Deferred to Phase 3 implementation; both
  approaches are compatible with the BlobStore design.

- **Data action interface:** Single `Indexer::index_commit()` that handles
  both auth transactions and data actions within the same commit, or separate
  `Indexer::index_data_action()` method? Deferred to Phase 2; the commit is
  the natural ingestion boundary so the single-method approach is likely
  cleaner.

- **§14.4.1 Recovery Validity numbering:** Parent §14.4 does not exist in
  SPEC.md — likely a numbering artifact from section reorganization. Low
  priority; remediate when spec is next revised.

## Scope

### In Scope

- `BlobStore` trait + `RedbBlobStore` (production) + `MemoryBlobStore` (testing)
- `Indexer` trait + `SqliteIndexer` (production) + `MemoryIndexer` (testing)
- Async SQLite wrapper (actor model or `tokio-rusqlite`)
- Index recovery from BlobStore (rebuild path)
- `StorageEngine` orchestrating BlobStore + Indexer + Protocol Engine
- Write path (validate → persist) and read path (query → reconstruct)
- Delta construction for `/patch` endpoint
- `cyphr-server` crate with axum HTTP server
- MSS API endpoints: `/tip`, `/patch`, `/push`, `/e/<digest>`
- Configuration (listen address, storage directory, log level)
- Structured logging via `tracing`
- PoP authentication (challenge-response and timestamp-based login)
- Bearer token issuance and verification
- Server principal bootstrapping

### Out of Scope

- Gossip / libp2p / peer-to-peer sync
- Level 5 (Rules) and Level 6 (VM) support
- Frontend / web UI
- Legacy Cyphr.me Datastore migration
- Inter-principal sharding
- Go server implementation
- Production deployment tooling (systemd, Docker, monitoring)
- WebSocket / real-time sync
- TLS termination (use a reverse proxy)
- Multi-authority federation
- Performance benchmarking or optimization

## Phases

<!--
  Each phase is independently valuable — stopping after any phase yields
  a useful, stable artifact. Phases are ordered by dependency.
  Each phase is a bounded /core invocation.
-->

1. **Phase 1: BlobStore Foundation** — content-addressed blob storage with BLAKE3
   - [x] `BlobStore` trait definition (`cyphr-storage/src/blob/mod.rs`)
     - [x] `put(raw_bytes) -> Result<Blake3Hash>`
     - [x] `get(hash) -> Result<Option<Vec<u8>>>`
     - [x] `exists(hash) -> Result<bool>`
     - [x] `iter() -> Result<Box<dyn Iterator<Item = Result<(Blake3Hash, Vec<u8>)>>>>`
   - [x] `FjallBlobStore` implementation
     - [x] Single fjall partition: `blake3_hash -> raw_bytes`
     - [x] Directory-based configuration (storage path)
   - [x] `MemoryBlobStore` implementation (`HashMap`-backed)
   - [x] Unit tests for both implementations
   - [x] Integration test: round-trip raw coz bytes through BlobStore

2. **Phase 2: Indexer Foundation** — relational index with async SQLite
   - [x] `Indexer` trait definition (`cyphr-storage/src/index/mod.rs`)
     - [x] `index_commit(&IndexableCommit) -> Result<()>`
     - [x] `get_tip(principal_id) -> Result<Option<TipState>>`
     - [x] `get_commit_chain(principal_id, from, to) -> Result<Vec<CommitRef>>`
     - [x] `resolve_digest(&TaggedDigest) -> Result<Option<EntityRef>>`
     - [x] `list_principals() -> Result<Vec<PrincipalSummary>>`
   - [x] `SqliteIndexer` implementation
     - [x] 6-table schema: `principals`, `commits`, `transactions`, `entries`, `digest_index`, `data_actions`
     - [x] WAL mode, busy timeout configuration
     - [x] `json_extract()` for variable payload fields
   - [x] Async wrapper for `SqliteIndexer`
     - [x] Actor model (dedicated thread + `tokio::sync::mpsc`) or `tokio-rusqlite`
   - [x] `MemoryIndexer` implementation for testing
   - [x] Index recovery: scan BlobStore for unindexed blobs, re-parse, re-index
   - [x] Unit tests for trait operations (11 tests: tip CRUD, commit chain, digest resolution, principal listing)

3. **Phase 3: Engine Orchestration** — coordinated write/read paths
   - [x] `StorageEngine` struct wrapping `BlobStore` + `Indexer`
     - [x] Constructor with configuration
     - [x] Startup: load index, verify consistency, recover if needed
   - [x] Write path
     - [x] `ingest_commit()`: store blobs + index pre-validated metadata
     - [x] `submit_commit()`: validated write path (verify via CommitScope → persist)
     - [x] `BlobStore::put()` for each coz in the commit
     - [x] `Indexer::index_commit()` for relational tracking
   - [x] Read path
     - [x] `get_tip()`: principal current state from index
     - [x] `get_patch()`: delta between two states (commit chain query + blob fetch)
     - [x] `get_entity()`: content-addressed lookup via `digest_index` → BlobStore
   - [/] Principal lifecycle
     - [x] Load existing principal from storage (replay from BlobStore via index ordering)
     - [x] Create new principal (genesis, implicit + explicit)
     - [x] Resume from checkpoint
   - [x] Integration tests using `MemoryBlobStore` + `MemoryIndexer` (17 tests)

4. **Phase 4: HTTP Server (MSS API)** — deployable authority server
   - [x] `cyphr-server` crate scaffolding
     - [x] `Cargo.toml` with dependencies (axum, tokio, tower-http, tracing, clap)
     - [x] `main.rs`: entrypoint, config parsing, server startup
   - [x] MSS API routes
     - [x] `GET /tip?pr=<PG>` — current principal state
     - [x] `GET /patch?pr=<PG>&from=<ps>&to=<ps>` — delta fetch
     - [x] `POST /push` — accept and validate signed commit bundle
     - [x] `GET /e/<digest>` — content-addressed entity lookup
   - [x] Request/response types (JSON serialization)
   - [x] Error handling (structured error responses)
   - [x] 12-factor configuration (figment + clap)
     - [x] `ServerConfig` struct with `#[derive(Deserialize, Parser)]`
     - [x] figment provider: load `cyphr-server.toml` (TOML)
     - [x] clap: CLI flags (`--listen`, `--data-dir`, `--mode`, `--log-level`)
     - [x] clap env integration: `#[arg(env = "CYPHR_LISTEN")]` etc. (shows in `--help`)
     - [x] Merge order: figment defaults → TOML file → clap (env + CLI)
     - [x] `[server]` — `listen` address (default `127.0.0.1:3000`), `log_format` (`json`|`pretty`)
     - [x] `[storage]` — `data_dir` path (default `./data`)
     - [x] `[mode]` — `role = "authority"` or `role = "witness"`
     - [x] Authority mode: accept `/push` from authenticated clients
     - [x] Witness mode: read-only API, sync from configured authority URLs
   - [x] Observability (tracing — composable registry)
     - [x] `tracing_subscriber::registry()` with `.with()` layer composition
     - [x] `EnvFilter` from `RUST_LOG` (default `cyphr_server=info,tower_http=info`)
     - [x] JSON fmt layer (production) vs. pretty fmt layer (dev), switchable via `log_format` config
     - [x] All output to stderr (Factor XI — logs as event stream, not files)
     - [x] `tower-http::TraceLayer` on all routes (method, URI, status, latency)
     - [x] Request correlation ID middleware (generate UUID, attach to span)
     - [x] `#[instrument]` on `StorageEngine` public methods and route handlers
     - [x] Registry is explicitly extensible: future `tracing-opentelemetry` layer is additive, not a rewrite
   - [/] Admin subcommands (Factor XII)
     - [x] `cyphr-server serve` — run the HTTP server (default)
     - [/] `cyphr-server rebuild-index` — rebuild SQLite index from BlobStore
     - [/] `cyphr-server export <pr>` — export principal data
   - [/] Graceful startup/shutdown (Factor IX)
     - [x] SIGTERM handler: drain active connections, flush pending writes
     - [/] Startup: load config → init storage → verify/recover index → bind port
   - [x] End-to-end test: create principal → push commits → query `/tip` → fetch `/patch`

5. **Phase 5: Authentication (PoP)** — proof of possession per SPEC §17
   - [ ] Server principal bootstrapping
     - [ ] Generate or load server key pair on first start
     - [ ] Store server identity in the same storage engine
   - [ ] Login flows
     - [ ] Challenge-response (§17.2 Option A): issue nonce → verify signed response
     - [ ] Timestamp-based (§17.2 Option B): verify signed coz with `now` tolerance
   - [ ] Bearer token management
     - [ ] Token issuance: server-signed coz with `PG`, permissions, expiry
     - [ ] Token verification: axum middleware layer
     - [ ] Token revocation (optional, stretch goal)
   - [ ] Route protection
     - [ ] Public routes: `/tip` (read), `/e/<digest>` (read)
     - [ ] Auth-required routes: `/push` (write)
     - [ ] Configurable per-route policy
   - [ ] Integration test: login → bearer token → authenticated push → verify rejection without token

## Verification

- [ ] `cargo test` passes for all crates (`cyphr`, `cyphr-storage`, `cyphr-server`)
- [ ] `cargo clippy` clean (no warnings)
- [ ] End-to-end: `cyphr-cli` creates a principal, `cyphr-server` ingests it via `/push`, `/tip` returns correct state
- [ ] Index recovery: corrupt/delete SQLite file, restart server, verify automatic rebuild from BlobStore
- [ ] Authentication: unauthenticated `/push` rejected with 401, authenticated `/push` succeeds
- [ ] Delta fetch: `/patch?from=<genesis>&to=<current>` returns complete commit chain

## Technical Debt

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Item                                          | Severity | Why Introduced                                         | Follow-Up                                               | Resolved |
| :-------------------------------------------- | :------- | :----------------------------------------------------- | :------------------------------------------------------ | :------: |
| `BlobStoreError` missing `#[non_exhaustive]`  | Low      | Pre-alpha                                              | Add before 1.0                                          |          |
| `IndexerError` missing `#[non_exhaustive]`    | Low      | Pre-alpha                                              | Add before 1.0                                          |          |
| `Indexer` trait lacks `Send + Sync` bounds    | Medium   | Phase 3 requirement not yet materialized               | Add when engine needs `Arc<dyn Indexer + Send + Sync>`  |          |
| `MemoryIndexer::resolve_digest` uses hex keys | Low      | Test-only simplification                               | SQLite impl stores real TaggedDigest strings            |          |
| `ingest_commit` non-atomic (blobs vs index)   | Low      | Content-addressed orphans harmless                     | Production backend: coordinate via DB transactions      |          |
| `PatchResponse` loads all blobs into memory   | Low      | Pre-alpha simplicity                                   | Streaming patches for Phase 4+                          |          |
| `CommitEntry.{ar,sr}` empty strings in replay | Low      | `replay_commits` ignores state digests                 | Refactor `CommitEntry` or expand `CommitRef` with ar/sr |          |
| Wire format: key-embed invariant undocumented | Low      | Implicit in `key_value_to_entry` logic                 | Document in SPEC or assert in engine ingestion path     |          |
| `submit_commit` HashAlg→alg_str static match  | Low      | No HashAlg→str API in cyphr crate                      | Add conversion method to cyphr crate                    |          |
| `submit_commit` silently skips action coz     | Low      | Actions need post-finalize handling                    | Support action recording in submit_commit (Phase 4+)    |          |
| `submit_commit` re-serializes pay JSON        | Low      | Canonical hashing makes this safe                      | Document contract or pass raw bytes through             |          |
| Server uses `MemoryBlobStore`+`MemoryIndexer` | Medium   | SQLite indexer not yet implemented                     | Wire FjallBlobStore + SQLiteIndexer (Phase 2b)          |          |
| No request correlation ID middleware          | Low      | Stub routes; no requests to correlate                  | Add uuid-based span middleware with route wiring        |    ✓     |
| No `#[instrument]` on engine/handlers         | Low      | Stub routes don't call engine                          | Add when routes are wired (Step 2)                      |    ✓     |
| Authority/Witness mode not enforced at route  | Low      | Scaffold — routes are 501 stubs                        | Add middleware guard on `/push` (Phase 5)               |          |
| `resolve_genesis` only produces `Implicit`    | Low      | Explicit multi-key genesis needs richer wire format    | Extend when explicit genesis support is needed          |          |
| No genesis-from-scratch test fixture          | Medium   | Fixtures model existing principals adding keys         | Create fixture where first key/create is self-signed    |          |
| E2E push test bootstraps via engine, not HTTP | Low      | Fixtures lack self-signed genesis for HTTP auto-detect | Add once genesis-from-scratch fixture exists            |          |

## Deviation Log

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| ID  | Date       | Description                                                                           | Impact                                                     |
| --- | ---------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| D1  | 2026-05-07 | `submit_commit` changed to `Option<Genesis>` — engine auto-detects from storage/blobs | Cleaner server API; engine encapsulates genesis resolution |

| Commit   | Planned                                                | Actual                                                    | Rationale                                        |
| :------- | :----------------------------------------------------- | :-------------------------------------------------------- | :----------------------------------------------- |
| Phase 2a | `index_commit(principal_id, commit_data, blob_hashes)` | `index_commit(&IndexableCommit)`                          | Single struct cleaner than 3+ loose params       |
| Phase 2a | `resolve_digest(tagged_digest)` — untyped              | `resolve_digest(&TaggedDigest)`                           | Protocol type provides parse-time validation     |
| Phase 2a | Phase 2 as single CORE session                         | Split into 2a (trait+memory) / 2b (SQLite+async+recovery) | Exceeds granularity cap; mirrors Phase 1 pattern |
| Phase 3a | Phase 2b (SQLite) before Phase 3                       | Phase 3 first with memory backends                        | Engine stress-tests traits before SQL schema     |
| Phase 3a | Write path: accept raw commit bundle bytes             | `ingest_commit` takes pre-validated blobs + metadata      | Principal validation deferred to Phase 3b        |

## Retrospective

<!--
  Filled in after execution is complete.
-->

### Process

- Did the plan hold up? Where did we diverge and why?
- Were the estimates/appetite realistic?
- Did CHALLENGE catch the risks that actually materialized?

### Outcomes

- What unexpected debt was introduced?
- What would we do differently next cycle?

### Pipeline Improvements

- Should any axiom/persona/workflow be updated based on this experience?

## References

- Sketch: [`.sketches/2026-05-01-cyphrme-protocol-transition.md`](../../.sketches/2026-05-01-cyphrme-protocol-transition.md)
- Charter: [`docs/charters/spec-alignment.md`](../charters/spec-alignment.md)
- Specification: [`SPEC.md`](../../SPEC.md) (§13.4 MSS API, §16.3.2 Storage Architecture, §17 Authentication)
- Pre-implementation audit: [sketch §Pre-Implementation Readiness Audit](../../.sketches/2026-05-01-cyphrme-protocol-transition.md)
