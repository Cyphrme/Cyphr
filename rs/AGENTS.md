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
| `cyphr-index-fjall` | fjall KV-backed `Indexer` (production; the SQLite backend is retired per root R3) -- length-prefixed commit keys, one meta partition tracking schema version |
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
  `fixture-gen` reads `tests/intents/*.toml` + `tests/keys/pool.toml`
  and rewrites `tests/golden/`; exact invocation in `tests/README.md`
  (the `--pool` flag and working directory matter — follow the README,
  not memory).
- Manual smoke test of the CLI: `rs/cyphr-cli/demo.sh` (full
  key-add/export/import/revoke cycle).
- Formatting is `treefmt` from the repo root, not `cargo fmt` (see root
  `AGENTS.md`).

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

## Known traps (updated 2026-07-08; fix, don't inherit)

- **`CloneableLog` concurrency assumption.** `block_on` under a `Mutex`
  (`cyphr/src/commit_root.rs`); sound only because every engine call
  builds a fresh `Principal`. A shared, long-lived `Principal` across
  concurrent tasks would violate this -- resolved externally, not by
  changing `CloneableLog` itself: `StorageEngine::submit_commit` now
  holds a per-principal async lock across its whole critical section
  (`F3`/`F24`, mitigated), so the server's real access pattern never
  exercises concurrent calls against the same live `Principal`. The
  assumption above is still true of `CloneableLog` in isolation --
  don't drive it directly from concurrent tasks without an equivalent
  guard.
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
