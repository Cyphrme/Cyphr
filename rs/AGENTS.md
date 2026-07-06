# rs/ — Rust Workspace

**Alignment to parent:** this workspace is where the root goal (production
Rust implementation of the Cyphr Protocol; see `/AGENTS.md`) is realized.
All active development happens here.

## Crate map

| Crate | Role |
| :--- | :--- |
| `cyphr` | Protocol core: `Principal<S: eml::Storage>`, commit/transaction machinery, Merkle trees (`principal_tree`, `semantic_tree`), multihash. Consumer-agnostic (root I4). |
| `cyphr-storage` | `StorageEngine<B: BlobStore, I: Indexer, S>`: validated write path (`submit_commit`), read paths, recovery (`reindex`), import/export |
| `cyphr-blob-fjall` | Durable fjall `BlobStore` + principal-scoped eml storage opener (multitenancy by construction) |
| `cyphr-index-sqlite` | SQLite `Indexer` (actor thread). **Transitional** — slated for replacement by KV index tables (root R3) |
| `cyphr-server` | axum HTTP scaffold: `/tip`, `/patch`, `/push`, `/e/{digest}` wired to durable backends. No auth yet; `Export` subcommand and `witness` mode are non-functional stubs |
| `cyphr-cli` | Single-user dev CLI; plaintext keystore, not secure by design |
| `test-fixtures`, `fixture-gen` | Golden-corpus harness + generator (Rust is the canonical generator) |
| `fuzz` | cargo-fuzz targets; not run in CI |

## Gates

- `cargo test --workspace` — green (~3 min; slowest: persistent-engine proptest).
- `cargo clippy --workspace --all-targets` — clean; keep it that way.
- `cargo fmt --check` — **known red workspace-wide** (forge #28, pre-existing).
  Do not fix piecemeal on unrelated diffs; it gets a dedicated pass.
- Protocol-behavior changes: regenerate goldens (root R2) —
  `cargo run -p fixture-gen -- generate ...` per `tests/README.md`.

## Invariants

- **I1 — Write-path validation order.** All cryptographic verification
  happens in memory via `cyphr::Principal` before any persistence; there
  is no rollback path. Grounding: `submit_commit`
  (`cyphr-storage/src/engine/mod.rs`). Signpost: any persist-then-validate
  sequence violates this.
- **I2 — Multitenancy by construction.** Principal scoping flows through
  the storage factory and sanitized fjall keyspace prefixes, never by
  convention. Grounding: `cyphr-blob-fjall` scoped opener +
  `cyphr-storage/tests/multitenancy.rs`. Signpost: forge #36 (prefix
  injectivity is an unenforced precondition — guard it when touching id
  formats).
- **I3 — Trait seams are stable.** `BlobStore`, `Indexer`, `eml::Storage`
  are the replacement boundaries (the index replacement lands behind
  `Indexer`). Signpost: backend types leaking through a seam into
  consumers.

## Known traps (verified 2026-07-06; fix, don't inherit)

- **Crate READMEs lie.** All three (`cyphr`, `cyphr-storage`, `cyphr-cli`)
  document APIs/commands that do not exist. Trust `lib.rs` exports and
  tests, not READMEs, until the truth-restoration pass lands.
- **`reindex` silently under-recovers.** O(n!) permutation search capped
  at 8 same-timestamp mutations; on give-up it warns and returns `Ok(())`
  (`engine/mod.rs` ~1162–1461). Also implicit-genesis-only bootstrap
  (forge #33). Do not build on it as-is.
- **`CloneableLog` concurrency assumption.** `block_on` under a `Mutex`
  (`cyphr/src/commit_root.rs`); sound only because every engine call
  builds a fresh `Principal`. Do not share a live `Principal` across
  concurrent tasks (root U2).
- **Error collapse.** eml storage errors become
  `Error::UnsupportedAlgorithm` (forge #32), and the server maps all
  protocol errors to one 422. Don't branch on those error values as if
  they were accurate.
- **Trust-boundary parsing is multiplied.** Coz header extraction /
  czd computation are hand-rolled in ~4/10 places (engine, reindex,
  import, CLI) with silent defaults. Don't add a fifth — the campaign
  consolidates these into canonical `cyphr` primitives.
- Conformance suites exist for `Indexer`/`BlobStore`/engine but currently
  run only against memory backends (forge #35 and siblings) — new backend
  work must wire them, not hand-roll subsets.

## Unknowns

Inherited from root (`/AGENTS.md` U1–U3): intra-commit ordering,
live-principal concurrency, replay-cost/caching. Resolve there, not
locally.

## Spec Pointers

- Storage layer: `docs/specs/storage-engine.md`, `blob-store*.md`,
  `indexer*.md` (status caveats: `docs/AGENTS.md`)
- Idiom: `rs/rust_idioms.md`
