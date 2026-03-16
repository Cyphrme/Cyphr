# PLAN: Test Infrastructure Alignment

<!--
  PLAN documents are structured procedures for /core execution.
  They should be professional, complete, and ready to hand off.

  Iterate in your sketch; commit in the plan.

  See: workflows/plan.md for the full protocol specification.
-->

## Goal

Align the test fixture pipeline with the SPEC wire format so golden fixtures
are canonical protocol representations. Key changes: extract `keys[]` to
top-level (currently embedded per-tx), enrich key fields with `tag` and `now`,
and refactor the generator to use `CommitScope` (eliminating the parallel
`build_pay_json` code path). After this work, golden JSON matches the SPEC §5.2
/ §5.3 wire format: `{txs: [...], keys: [...]}`.

## Constraints

- **Cross-language parity**: Go and Rust consume identical golden JSON.
- **`[wire-format-plurals]`**: `txs` for auth transactions, `keys` for key
  material. `cozies` reserved for data actions (Level 5+ / future).
- **Bit-perfect preservation**: `Entry` / `RawValue` invariants must survive —
  signing/czd depends on exact bytes.
- **Pre-alpha**: No backwards compatibility required (AGENTS.md).
- **Charter budget**: Items 4 (Spec Alignment) + 5 (Verification Infrastructure).

## Decisions

| Decision                | Choice                              | Rationale                                                                                                  |
| :---------------------- | :---------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| `txs` field name        | Keep `txs`                          | Zami confirmed: `txs` = AT-mutating transactions, `cozies` = data actions. Commits use `txs`.              |
| Key placement           | Top-level `keys[]` per commit       | SPEC §5.2, §5.3: keys are outside coz objects at commit level.                                             |
| Key fields              | `alg`, `pub`, `tmb`, `tag?`, `now?` | SPEC §6: full key includes `tag` and `now`. Both optional for backwards compat.                            |
| Generator approach      | CommitScope-first (Approach A)      | Eliminates parallel `build_pay_json` code path. Sustained after steel-manning Approach B.                  |
| Declarative format (§8) | Out of scope                        | §8.1 is client-internal, §8.2 is a checkpoint transaction type. Neither relevant for test fixtures.        |
| Storage abstraction     | Current layering is correct         | `CommitEntry` is the JSON wire format model. `Store` trait is the backend abstraction. No refactor needed. |
| Execution order         | Storage → Generator → Consumers     | Generator calls `export_commits()` — format must stabilize first.                                          |

## Risks & Assumptions

| Risk / Assumption                                        | Severity | Status    | Mitigation / Evidence                                   |
| :------------------------------------------------------- | :------- | :-------- | :------------------------------------------------------ |
| `Principal` derives `Clone` (override tests)             | CRITICAL | Validated | principal.rs:163 `#[derive(Debug, Clone)]`              |
| `CommitScope::finalize_with_commit()` exists             | CRITICAL | Validated | commit.rs L382-465                                      |
| Generator delegates to `export_commits()`                | HIGH     | Validated | golden.rs `export_principal_commits()` L292-360         |
| Phase 1 changes automatically propagate to golden output | HIGH     | Validated | Golden output flows through `CommitEntry` serialization |
| Import path rename is mechanical                         | MEDIUM   | Validated | import.rs `replay_commits()` L329-441                   |
| CLI output format changes                                | LOW      | Accepted  | Pre-alpha, no backwards compat                          |
| `tag`/`now` fields may be absent on existing keys        | LOW      | Mitigated | Use `skip_serializing_if = "Option::is_none"`           |

## Open Questions

- None blocking. All questions resolved via SPEC review and Zami clarification.

## Scope

### In Scope

- **`keys[]` extraction**: Move key material from per-tx embedded `key` to top-level `keys[]` array per commit
- **Key field enrichment**: Add `tag` and `now` to exported `KeyEntry` (SPEC §6)
- **CommitEntry update**: Add `keys: Vec<KeyEntry>` field
- **Export refactor**: `export_commits()` collects keys at commit level
- **Import update**: `extract_key_from_entry()` reads from commit-level `keys[]` instead of per-tx `key`
- **Generator refactor**: Replace `build_pay_json()`/`sign_pay()` with `CommitScope::finalize_with_commit()`
- **Go consumer**: Update `GoldenCommit` to parse top-level `Keys []GoldenKey`
- **Golden fixture regeneration**: `cargo run -p fixture-gen`, verify all tests pass

### Out of Scope

- `cozies` field (Level 5+ multi-coz transactions)
- Declarative format / checkpoint transactions (§8.2)
- Client JSON dump format (§8.1)
- Storage abstraction refactor (current layering is correct)
- Multi-tx-per-commit generator support (no intents require it)
- `ds/create` transaction (separate workstream)

## Phases

1. **Phase 1: Wire Format Alignment** — `CommitEntry` keys extraction + export/import
   - [ ] Define `KeyEntry` struct: `alg`, `pub`, `tmb`, `tag?`, `now?`
   - [x] Add `keys: Vec<KeyEntry>` to `CommitEntry` (no backward compat)
   - [x] Update `export_commits()`: collect new keys at commit level into `keys[]`, stop embedding `key` per-tx
   - [x] Update `import.rs`: `replay_commits()` reads from commit-level `keys[]` via iterator
   - [x] Update `test-fixtures/golden.rs`: `coz_to_commit_entry()` uses commit-level `KeyEntry`
   - [x] Run `cargo test -p cyphrpass-storage` — 16/16 unit tests pass

2. **Phase 2: Generator Refactor** — Use `CommitScope` for coz construction
   - [ ] Replace `build_pay_json()` + `sign_pay()` with `CommitScope::finalize_with_commit()` in generator
   - [ ] Implement clone-modify pattern for override/error test generation
   - [ ] Regenerate golden fixtures: `cargo run -p fixture-gen`
   - [ ] Run `cargo test -p cyphrpass` — all unit tests pass

3. **Phase 3: Consumer Updates** — Go + Rust consumers parse aligned golden JSON
   - [ ] Add `Keys []GoldenKey` to `GoldenCommit` struct (Go)
   - [ ] Update `convertEntries()` to parse keys from commit-level `Keys`
   - [ ] Run `go test ./...` — all golden tests pass
   - [ ] Run `cargo test` (full workspace) — all tests pass

## Verification

- [ ] `cargo test -p cyphrpass-storage` — storage round-trip tests pass
- [ ] `cargo run -p fixture-gen` — fixture generation succeeds
- [ ] `cargo test` — full Rust workspace passes
- [ ] `go test ./...` — full Go test suite passes
- [ ] Spot-check golden JSON: top-level `keys[]` present, no embedded `key` per-tx
- [ ] Spot-check golden JSON: `txs` field name unchanged, `tag`/`now` present on keys

## Technical Debt

| Item | Severity | Why Introduced | Follow-Up | Resolved |
| :--- | :------- | :------------- | :-------- | :------: |

## Deviation Log

| Commit   | Planned                       | Actual                    | Rationale                                                         |
| :------- | :---------------------------- | :------------------------ | :---------------------------------------------------------------- |
| Phase 1a | `#[serde(default)]` on `keys` | No backward compat guards | Pre-alpha policy: old format is dead, deserialization should fail |

## Retrospective

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

- Charter: `docs/charters/spec-alignment.md` (items 4 + 5)
- Sketch: `.sketches/2026-03-13-test-intent-validation.md`
- Machine spec: `docs/specs/transactions.md` (`[wire-format-plurals]`)
- SPEC: `SPEC.md` §4.4 (commit finality), §5.2-5.3 (genesis wire format), §6 (key structure), §8 (declaration)
- Prior plan: `docs/plans/spec-alignment.md` (WS6 deferred fixture regeneration)
