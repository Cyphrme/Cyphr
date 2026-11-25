# rs/ — Rust Workspace

**Alignment to parent:** this workspace is where the root goal (production
Rust implementation of the Cyphr Protocol; see `/AGENTS.md`) is realized.
All active development happens here.

## Crate map

| Crate                          | Role                                                                                                                                                                                                                                                                              |
| :----------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cyphr`                        | Protocol core: `Principal<S: eml::Storage>`, commit/transaction machinery, Merkle trees (`principal_tree`, `semantic_tree`), multihash. Consumer-agnostic (root I4).                                                                                                              |
| `cyphr-storage`                | `StorageEngine<B: BlobStore, I: Indexer, S>`: validated write path (`submit_commit`), read paths, recovery (`reindex`), import/export                                                                                                                                             |
| `cyphr-blob-fjall`             | Durable fjall `BlobStore` + principal-scoped eml storage opener (multitenancy by construction)                                                                                                                                                                                    |
| `cyphr-index-fjall`            | fjall KV-backed `Indexer` (production; the SQLite backend is retired per root R3) -- one keyspace per logical index (length-prefixed commit keys) plus a `meta` keyspace tracking the index keyspaces and schema version                                                          |
| `cyphr-server`                 | axum HTTP server over the durable backends: envelope and signed receipts, admission, equivocation evidence, witness-mode sync, and the `auth/` modules (server identity, login, bearer-token middleware, route protection) and the operator subcommands (`rotate-key`, `backup`, `restore`, `export`, `verify-all`, `invite`) |
| `cyphr-client`                 | Carrier-independent sync client: a no-I/O verify core (patch, evidence, revoke, relying-party verdicts) plus the HTTP and Noise connectors behind the `Connector` trait                                                                                                           |
| `cyphr-keystore`               | The `KeyBackend` seam (keys are generated and used, never exported) and the plaintext `JsonKeyStore` software backend; no encryption exists yet                                                                                                                                   |
| `cyphr-cli`                    | Single-user CLI over `cyphr-keystore`; software-held, unencrypted keys (see `docs/guides/key-storage.md`)                                                                                                                                                                         |
| `cyphr-scenarios`              | End-to-end scenario harness: drives the shipped server and CLI binaries over loopback behind a fault-injecting proxy (root R13)                                                                                                                                                   |
| `test-fixtures`, `fixture-gen` | Golden-corpus harness + generator (Rust is the canonical generator)                                                                                                                                                                                                               |
| `fuzz`                         | cargo-fuzz targets for every parser of untrusted input (the nine in `fuzz/fuzz_targets/`); CI runs each as a 60-second smoke                                                                                                                                                                                         |

Hardware-held keys sign through the `cyphr::signer::Signer` seam; the
Coz Rust library (`Cyphrme/coz-rust`) still takes raw private-key bytes
in `coz::sign_json`, so a backend that cannot export its key needs an
upstream change.

## Building: the target directory

If your checkout shares a cargo target directory across worktrees (a local,
untracked `.cargo/config.toml` with `build.target-dir`), then when two worktrees
have matching dependency graphs, cargo can reuse a workspace crate's
artifacts built from another worktree's source, so a test result can
describe code that is not in your tree (reproduced). Before any build or
test run whose result matters, clean the workspace crates, and build in
one worktree at a time:

```sh
cd rs && cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[].name' | sed 's/^/-p /' | xargs cargo clean
```

Dependency crates stay cached, so this costs a rebuild of the workspace
only.

Each worktree builds into its own default `rs/target`, with no shared
`target-dir`: concurrent builds into a shared target replace the `debug/cyphr`
and `debug/cyphr-server` binaries that CLI and scenario tests run by path.
Test temp files go under the repo's `.scratch/tmp`, never `/tmp`. A worktree is
removed when its node merges.

## Testing policy

Root R13 governs. nrd: "We want meaningful property, metamorphic and
integration and e2e scenarios, and unit tests sparingly if at all for
perhaps tricky edges, but we should prefer to rule those out at the type
level if and where possible."

- The suite is property tests (`proptest`), metamorphic relations,
  integration tests, and e2e scenarios against real `cyphr-server`
  instances and clients. `../tests/golden` pins byte-exact formats;
  `fuzz/` covers parsers of untrusted input.
- A unit test is allowed only as a regression test for a defect actually
  found, usually written after the fact, and its doc comment says which
  defect. nrd: "The only time we should be unit testing is for regression
  testing. If we find an edge case and we want to make sure it doesn't
  recur, that's about the only time." Prefer making the edge
  unrepresentable in the types over testing it.
- Every test names the spec rule or user-visible behaviour it checks.
- Delete a test that cannot fail for a real defect: green by
  construction, re-asserting a mock, or duplicating a stronger test.
- Show each new test failing for the right reason before implementing.
- Run only targeted tests (`cargo test -p <crate>`) while working; the
  full suite runs once, at the merge gate.

## Gates

- `cargo test --workspace` — green; run once, at the merge gate. A worker
  runs only the tests pertinent to its change (slowest: persistent-engine
  proptest).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean; CI
  runs it with `-D warnings`.
- `cargo fmt --check` — green, on stable or nightly (forge #28, resolved by
  a full-workspace reformat; see below — `.rustfmt.toml`'s nightly-only
  keys were kept, not dropped).
- Protocol-behavior changes: regenerate goldens (root R2) —
  `fixture-gen` reads `tests/intents/*.toml` + `tests/keys/pool.toml`
  and rewrites `tests/golden/`; exact invocation in `tests/README.md`
  (the `--pool` flag and working directory matter — follow the README,
  not memory).
- Manual smoke test of the CLI: `rs/cyphr-cli/demo.sh` (full
  key-add/export/import/revoke cycle).
- Formatting: `treefmt` from the repo root is authoritative (see root
  `AGENTS.md`). `rs/.rustfmt.toml` sets `unstable_features = true` plus
  several nightly-only keys (import grouping, comment wrapping,
  macro/doc-comment formatting) — `treefmt` enforces these because it runs
  under the project's pinned nightly toolchain (`rs/rust-toolchain.toml`).
  A stable `cargo fmt --check` currently agrees (it prints harmless "can't
  set X, unstable features are only available in nightly channel"
  warnings and falls back to defaults for those keys, which happen to
  match the already-canonical tree), but a stable `cargo fmt` won't
  auto-fix a new nightly-gated violation — use `treefmt` or a nightly
  `cargo fmt` for that.

## Invariants

- **I1 — Write-path validation order.** All cryptographic verification
  happens in memory via `cyphr::Principal` before any persistence; there
  is no rollback path. Grounding: `submit_commit`
  (`cyphr-storage/src/engine/mod.rs`). Signpost: any persist-then-validate
  sequence violates this.
- **I2 — Multitenancy by construction.** Principal scoping flows through
  the storage factory, never by convention. Every principal's commit log
  lives in one fixed keyspace triplet, told apart by a key scope (the
  principal id bytes, then the log generation as a `u64` big-endian) that
  `polydigest-storage-fjall` 0.3 length-prefixes, so no scope is a prefix
  of another: nothing is sanitized, and the prefix-injectivity concern of
  forge #36 is structural. Grounding: `cyphr-blob-fjall` `EmlLogs` +
  `cyphr-storage/tests/multitenancy.rs`, with the layout pinned by
  `cyphr-storage/tests/properties.rs` and
  `cyphr-server/tests/log_layout.rs`; `cyphr-blob-fjall/tests/log_model.rs`
  is the direct witness for scope isolation. Signpost: a log opened outside
  `EmlLogs`, or a keyspace created per principal.
- **I3 — Trait seams are stable.** `BlobStore`, `Indexer`, `eml::Storage`
  are the replacement boundaries (the index replacement lands behind
  `Indexer`). Signpost: backend types leaking through a seam into
  consumers.
- **I4 — Server instance independence.** Every server instance is fully
  isolated by construction with its own data directory, storage engine, and
  identity key pair. No state, cache, or cryptographic material is shared
  across server instances. Grounding: `rs/cyphr-server/tests/invariants.rs`
  (`two_instances_are_independent`) and `tests/common/multi.rs`.
- **I5 — Refusals are never signed.** Server error responses, rejections,
  and refusals MUST ALWAYS be returned as unsigned envelopes
  (`Statement::Unsigned`) and MUST NEVER carry a signed statement / receipt.
  Grounding: `rs/cyphr-server/tests/invariants.rs` (`refusals_are_never_signed`).
- **I6 — Signed statements carry a timestamp.** All signed server statements
  and receipts MUST carry a valid, positive, non-zero unix timestamp (`now`)
  reflecting request processing time. The timestamp is not a freshness
  proof: no request nonce binds a statement to one request, so a genuine
  statement can be replayed (forge #152). Grounding:
  `rs/cyphr-server/tests/invariants.rs` (`signed_statements_carry_freshness`).
- **I7 — No standing honesty claim.** The server MUST NEVER issue or publish
  standing, static, or unverified claims of honesty or attestation. Keyless
  and unbootstrapped configurations strictly declare `repository` tier
  without identity claims, and attestations are bound per-request. Grounding:
  `rs/cyphr-server/tests/invariants.rs` (`no_standing_honesty_claim`).
- **I8 — Storage pressure and pruning refusal.** storage pressure is relieved by refusing admission, never by pruning retained history; a design that needs pruning is a SPEC §16.2 escalation, not a server change.
- **I9 — The CLI never signs unprompted.** It signs only when the user ran
  a command whose purpose is to sign. Fetching, pushing and adopting a
  peer's history never sign or re-sign anything; what cannot be kept as
  signed is dropped and reported, and the user signs it again explicitly.

## Known traps (updated 2026-07-08; fix, don't inherit)

- **One writer per principal log.** A `Principal` owns its commit log
  outright (`cyphr/src/commit_root.rs`, `CommitTrees`): no alias, no lock
  in the core, and no `Clone` (a copy is `fork()`, only over storage that
  copies independently). Two `Principal`s opened over one durable store
  are still two writers of it; `StorageEngine::submit_commit` serializes
  them with a per-principal async lock across its whole critical section.
  Don't open the same durable principal from concurrent
  tasks without an equivalent guard.
- **The record is synced before the index and before the answer.**
  `submit_commit` calls `BlobStore::persist` once, after the blobs,
  manifest and commit-log append and before the first index write; every
  role pays it. A failed sync sets a flag and the engine refuses every
  later write (`EngineError::DurabilityLost`, a `500` over HTTP) until the
  process restarts. Never move a signature or an answer ahead of it
  (`docs/specs/storage-engine.md` `[record-durable-first]`).

## Unknowns

Inherited from root (`/AGENTS.md`); resolve there, not locally:

- U1 — intra-commit ordering (resolved);
- U2 — live-principal concurrency (in-process lock exists; no cross-process lease);
- U3 — replay cost (resolved for the write path);
- U4 — EMT→EML conversion;
- U5 — peer transport (decided: Noise NN);
- U6 — keychain design details;
- U7 — restore watermark;
- U8 — passphrase root defaults and attestation roots;
- U9 — witness currency and identity binding;
- U10 — questions for the SPEC author.

## Spec Pointers

- Storage layer: `docs/specs/storage-engine.md`, `blob-store*.md`,
  `indexer*.md` (status caveats: `docs/AGENTS.md`)
- Idiom: `rs/rust_idioms.md`
