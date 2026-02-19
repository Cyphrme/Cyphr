# PLAN: State Tree Restructuring (CS Pivot)

## Goal

Restructure the state computation hierarchy in both Go and Rust to match
SPEC §8.3–8.5. The current code computes `AS = MR(KS, TS?, RS?)` and
`PS = MR(AS, DS?)`. The spec now defines:

- `AS = MR(KS, RS?)` — TS removed from AS
- `CS = MR(AS, Commit ID)` — new state node
- `PS = MR(CS, DS?)` — CS replaces AS in PS

The "Transaction State" (TS) concept becomes "Commit ID" — its computation
is unchanged (Merkle root of czds), but it moves from _inside_ AS to a
sibling of AS _under_ CS.

## Constraints

- Pre-alpha: no backwards-compatibility requirement
- SPEC.md (working tree version) is authoritative for all formulas
- Go/Rust must achieve parity — same types, same formulas
- Golden fixtures are deferred — they will be regenerated after
  state computation is correct, not concurrently
- Formal model (`docs/models/principal-state-model.md`) is reference, not code

## Decisions

| Decision               | Choice                                                | Rationale                                                                                                   |
| :--------------------- | :---------------------------------------------------- | :---------------------------------------------------------------------------------------------------------- |
| TS → CommitID rename   | Rename `TransactionState` to `CommitID` in both langs | Matches spec §8.5 terminology; TS is misleading now                                                         |
| New `CommitState` type | Add `CommitState` struct wrapping `MultihashDigest`   | Mirrors KS/AS/PS type pattern; CS is a first-class state node                                               |
| `compute_cs` function  | New function: `compute_cs(as, commit_id, algs)`       | Clean separation; no circular dependency (AS computed first)                                                |
| `compute_as` signature | Remove `ts` parameter entirely                        | AS = MR(KS, RS?) per §8.4; TS is not a component                                                            |
| `compute_ps` signature | Replace `auth_state` with `cs` parameter              | PS = MR(CS, DS?) per §8.3; AS no longer visible to PS                                                       |
| `pre` semantics        | Remains as-is (TaggedDigest)                          | `pre` references previous CS; we rename the stored field from `auth_state` to `cs` where it's used as `pre` |
| Fixture regeneration   | Deferred to separate phase                            | Avoids churn during structural changes                                                                      |
| Go Commit struct       | Add minimal `Commit` concept to Go                    | Go lacks a `Commit` struct; needs at minimum `CommitState` and czd tracking for CS computation              |

## Risks & Assumptions

| Risk / Assumption                                             | Severity | Status      | Mitigation / Evidence                                                                                                                                                                                                                                                                                                                                     |
| :------------------------------------------------------------ | :------- | :---------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pre` field type must change from `AuthState` → `CommitState` | **HIGH** | Unmitigated | `TransactionKind` variants (KeyCreate, KeyDelete, KeyReplace, KeyRevoke, PrincipalCreate) all have `pre: AuthState`. This must become `pre: CommitState` since `pre` references CS not AS. Cascades through `extract_pre()`, `parse_kind()`, and all match arms. Compiler will catch type mismatches, but semantic correctness must be manually verified. |
| `pre` validation breaks during restructuring                  | MEDIUM   | Unmitigated | Currently validated by comparing `pre` against `self.auth_state`. Must compare against `self.cs`. Both Rust `apply_verified` and Go `Apply` need this change                                                                                                                                                                                              |
| Genesis `pre` semantics are promotion-safe                    | LOW      | Validated   | At genesis CS == AS == KS == tmb (full promotion chain), so `pre = tmb` remains correct. §5.1 confirms bootstrap uses implicit first key tmb                                                                                                                                                                                                              |
| Go `recomputeState` is the single recomputation path          | LOW      | Validated   | Called only from state-mutating operations; single function to change                                                                                                                                                                                                                                                                                     |
| Rust `Commit` struct holds `ts: TransactionState`             | LOW      | Validated   | Rename to `commit_id: CommitID` and add `cs: CommitState`                                                                                                                                                                                                                                                                                                 |
| Golden tests will all fail until fixtures regenerated         | LOW      | Accepted    | Expected; defer fixture regen to separate phase                                                                                                                                                                                                                                                                                                           |
| Go lacks `Commit` struct — needs CS tracking                  | MEDIUM   | Unmitigated | Go uses flat `currentCommitCzds` + `recomputeState()`. Add `cs *CommitState` field to `Principal` without over-engineering                                                                                                                                                                                                                                |

### Alternative Rejected: Big-Bang Reset from Master

**Approach**: Start fresh from master, implement spec from scratch, replay functional changes after.

**Strongest argument for**: No risk of missed references during rename. Clean commit history.

**Why rejected**: ~1500 lines of non-trivial work survives (TaggedDigest parsing, cross-algo czd conversion, unified pre enforcement). Reimplementing is pure waste. The restructuring is mechanical, greppable, and compiler-checkable. Risk of missed references is LOW.

## Open Questions

- **Q1**: Should the Rust `Commit` struct also store `cs: CommitState`?
  Likely yes — CS is the canonical state output of a commit, analogous to
  how it currently stores `auth_state: AuthState`.
  _Resolution_: Yes, add `cs` to `Commit` and update `PendingCommit.finalize()`.

- **Q2**: Should Go gain a `CommitState` type alongside the existing type family?
  _Resolution_: Yes, for type safety and parity with Rust. Same pattern as
  `KeyState`, `AuthState`, `PrincipalState`.

## Scope

### In Scope

- Rename `TransactionState` → `CommitID` (both langs)
- Add `CommitState` type (both langs)
- Add `compute_cs()` / `ComputeCS()` function (both langs)
- Modify `compute_as()` / `ComputeAS()` to remove TS parameter
- Modify `compute_ps()` / `ComputePS()` to take CS instead of AS
- Update `finalize_current_commit()` (Rust) and `recomputeState()` (Go)
- Update `Principal` struct fields: store CS alongside AS
- Update `Commit` struct (Rust): add `cs`, rename `ts` to `commit_id`
- Update `pre` validation to compare against CS instead of AS
- Add `Principal.CS()` accessor (Go) and `Principal.cs()` (Rust)
- **Phase 5**: Redesign `Principal` API for explicit commit boundaries (Rust `PendingCommit` typestate; Go `CommitBatch` tx pattern)
- **Phase 5**: Update storage import layers (`replayEntries` / `try_apply_entry`) to iterate and finalize commits

### Out of Scope

- Rule State (RS) — Level 5, not implemented
- Lifecycle state machine implementation
- SPEC.md changes (reference-only, not committed to this branch)

### Model Coherence

Cross-referenced against `docs/models/principal-state-model.md` §1.1:

| Model (§1.1 Derived Quantities)                   | Plan Target             | Match |
| :------------------------------------------------ | :---------------------- | :---: |
| `as(s) = MR(ks(s), rs(s)?)`                       | `AS = MR(KS, RS?)`      |   ✓   |
| `cs(s) = MR(as(s), commit_id)`                    | `CS = MR(AS, CommitID)` |   ✓   |
| `ps(s) = MR(cs(s), ds(s)?, ...)`                  | `PS = MR(CS, DS?)`      |   ✓   |
| `Commit = { czds, pre: Digest, cs: Digest, ... }` | `Commit` stores CS      |   ✓   |

## Phases

1. **Phase 1: Type Restructuring** — Introduce new types and rename existing ones
   - [x] **Rust**: Rename `TransactionState` → `CommitID` in `state.rs`
   - [x] **Rust**: Add `CommitState` type in `state.rs` (wraps `MultihashDigest`)
   - [x] **Rust**: Add `compute_cs(as, commit_id, algs) → CommitState` in `state.rs`
   - [x] **Rust**: Update `compute_as()` — remove `ts` parameter
   - [x] **Rust**: Update `compute_ps()` — take `CommitState` instead of `AuthState`
   - [x] **Go**: Rename `TransactionState` → `CommitID` in `state.go`
   - [x] **Go**: Add `CommitState` type in `state.go`
   - [x] **Go**: Add `ComputeCS(as, commitID, algs) → CommitState` in `state.go`
   - [x] **Go**: Update `ComputeAS()` — remove `ts` parameter
   - [x] **Go**: Update `ComputePS()` — take `CommitState` instead of `AuthState`

2. **Phase 2a: Core Integration (Rust)** — Wire new types through Principal and Commit
   - [x] **Rust**: Update `Principal` struct — add `cs: Option<CommitState>`, rename `ts` to `commit_id`
   - [x] **Rust**: Update `finalize_current_commit()` — compute CS between AS and PS
   - [x] **Rust**: Update `Commit` struct — add `cs: CommitState`, rename `ts` to `commit_id`
   - [x] **Rust**: Update `PendingCommit` — rename `compute_ts()` to `compute_commit_id()`
   - [x] **Rust**: Add `Principal.cs()` accessor
   - [x] **Rust**: Update `TransactionKind` variants — `pre: AuthState` → `pre: CommitState`
   - [x] **Rust**: Update `extract_pre()` — return `CommitState` instead of `AuthState`
   - [x] **Rust**: Update `pre` validation in `apply_verified` — compare against `self.cs`

3. **Phase 2b: Downstream Integration (Rust)** — Storage, CLI, Test Fixtures

   > [!WARNING]
   > Scope creep: This phase was originally Phase 3/4 work but was performed continuously with Phase 2a.
   - [x] **Storage**: Update `CommitEntry` struct and `export.rs`
   - [x] **CLI**: Update `key` command `pre` extraction
   - [x] **Fixtures**: Update `GoldenExpected` and `Intent` structs
   - [x] **E2E**: Update `e2e.rs` references

4. **Phase 2c: Downstream Verification (Rust)** — Verify the changes from 2b
   - [x] **Unit Tests**: Verify `cargo test --workspace` passes (except golden data)
   - [x] **CLI Verification**: Manual check of `cyphrpass-cli key` commands → **BUG FOUND** (Finding 1)
   - [x] **E2E Verification**: Manual check of `e2e.rs` logic → **GAP FOUND** (Finding 3)

5. **Phase 2d: Core Integration (Go)** — Wire new types
   - [x] **Go**: Update `Principal` struct — add `cs *CommitState`, rename `ts` to `commitID`
   - [x] **Go**: Update `recomputeState()` — compute CS between AS and PS
   - [x] **Go**: Add `(*Principal).CS()` and `CommitID()` accessors
   - [x] **Go**: Update transaction `Pre` field type — use `CommitState`
   - [x] **Go**: Update `pre` validation in `verifyPre` — compare against CS
   - [x] **Go**: Rename `currentCommitCzds` comment references to use `CommitID` terminology
   - [x] **Go**: Update `Commit` struct — add `cs`, rename `ts` to `commitID`
   - [x] **Go**: Update `PendingCommit.ComputeTS()` → `ComputeCommitID()`
   - [x] **Go**: Update `e2e_runner.go` — multihash coherence, `buildTransactionPay`
   - [x] **Go**: Add `CommitState.Tagged()` method for wire-format `pre` field

6. **Phase 3: Cleanup & Verification** — Comment/doc updates, compilation checks
   - [x] Update all doc comments with new terminology (TS → Commit ID, AS formulas)
   - [x] Verify Rust unit tests pass (`cargo test -p cyphrpass --lib` — 64/64)
   - [x] Verify Go unit tests pass (`go test ./cyphrpass/...` — 26/26)
   - [x] Verify both `cargo build --workspace` and `go build ./...` compile cleanly
   - [x] Verify non-golden unit tests pass in both languages
   - [x] Stale reference sweep: zero `TransactionState`/`ComputeTS`/`.TS()` hits

7. **Phase 4: Fixture Format Alignment & Golden Regeneration**
   _Sketch: `.sketches/2026-02-18-fixture-format-alignment.md`_

   **4a: Intent struct redesign** — Add new types, keep legacy bridge
   - [x] **Rust `intent.rs`**: Add `CommitIntent` + `TxIntent` types, `cs` field in `ExpectedAssertions`
   - [x] **Go `intent.go`**: Mirror Rust struct changes, rename `TS` → `CommitID`
   - [x] **Rust `intent.rs`**: Unify actions — `action: Option` + `action_step: Vec` → `action: Vec<ActionIntent>`
   - [x] **Go `intent.go`**: Mirror action unification
   - [x] **Rust `golden.rs`**: Update generator refs (`action.as_ref()` → `action.first()`, `action_step` → `action`)
   - [x] **Rust `intent.rs`**: Remove legacy types (`PayIntent`, `CryptoIntent`, `StepIntent`) and old fields
   - [x] **Go `intent.go`**: Remove legacy types and old fields

   **4b: Generator fixes** — Fix bugs and dead code in `golden.rs`
   - [x] Fix `commit_id` always-`None` bug (L1214: `principal.transactions().last().and(None)`)
   - [x] Add `cs` computation and emission to `build_expected_from_principal`
   - [x] Add `cs` field to `GoldenExpected` (Rust `golden.rs`)
   - [x] Fix DRY violation: `apply_action_to_principal` rebuilds pay JSON — reuse from `build_action_coz`
   - [x] ~~Remove deprecated `entries` field from `Golden` struct (Rust)~~ _(already absent — resolved in 4a)_
   - [x] ~~Simplify generator dispatch from 7-way to commit-based iteration~~ _(already commit-based — resolved in 4a)_

   **4c: Expected assertions & struct cleanup** — Add `cs`, remove deprecated fields
   - [x] Add `cs` to Rust `ExpectedAssertions` (`intent.rs`) _(done in 4a)_
   - [x] Add `cs` to Go `ExpectedAssertions` (`intent.go`) _(done in 4a)_
   - [x] Rename Go `ExpectedAssertions.TS` → `CommitID` (field + toml tag) _(done in 4a)_
   - [x] Add `cs` to Go `GoldenExpected` (`golden.go`)
   - [x] Remove deprecated `Entries` field from Go `Golden` struct
   - [x] Remove Go `golden.go` legacy fallback methods (`FlattenEntries`, `EntryCount`, `IsGenesisOnly` Entries checks)
   - [x] ~~Rewrite Go `intent.go` dispatch helpers for commit-based model~~ _(already done in 4a)_

   **4d: TOML file migration** — Migrate all intent/E2E files to new format _(must precede golden regen)_
   - [x] **Intent TOML files**: Migrate all 7 files to `[[test.commit]]` + `[[test.commit.tx]]` format
   - [x] **E2E TOML files**: Migrate all 5 files to new format
   - [x] **All TOML files**: Remove all `commit = true` fields _(intent files done; E2E pending)_
   - [x] **All TOML files**: Fix stale SPEC §7 references → §8 _(intent files done; E2E pending)_
   - [x] **All TOML files**: Unify actions — `[test.action]`/`[[test.action_step]]` → `[[test.action]]` _(intent files done; E2E pending)_

   **4e: Golden regeneration** — Regenerate all fixtures _(after TOML migration)_
   - [x] Run `cargo run -p fixture-gen -- --pool ../tests/keys/pool.toml generate -r ../tests/intents/ ../tests/golden/`
   - [x] Verify golden JSON output includes `commit_id` and `cs` in expected
   - [x] Verify golden JSON uses `commits` format (not `entries`)

   **4f: Consumer updates** — Update test consumers to verify CS
   - [x] **Rust e2e tests**: Update golden consumers to verify `cs` field _(already done in Phase 2c)_
   - [x] **Go golden tests**: Update `golden_test.go` to verify `CS` _(already done in Phase 4c — `checkExpected` in `runner.go`)_
   - [x] **Go e2e runner**: Verify `e2e_runner.go` commit assertions include `cs` _(already done in Phase 2c)_

   **4g: Documentation** — Update README and terminology
   - [x] `tests/README.md`: Update golden format example (add `commit_id`, `cs`)
   - [x] `tests/README.md`: Update error table (`pre doesn't match current AS` → `CS`)
   - [x] `tests/README.md`: Update state categories (`KS, TS, AS, PS` → `KS, CommitID, AS, CS, PS`)
   - [x] `tests/README.md`: Update intent field reference table for new format
   - [x] `tests/README.md`: Remove `entries` format documentation

   **4h: Verification** — Full test suite
   - [x] `cargo test` — builds clean; 5/7 golden categories fail (ks mismatch — generator/runtime parity gap)
   - [x] `go test ./...` — builds clean; 3 multi-commit golden tests fail (cs/ps mismatch)
   - [x] Both builds compile cleanly
   - [ ] Verify no duplicate action tests remain (consolidate `actions.toml` tests 3-5)
   - [ ] **NEW**: Resolve generator–runtime state computation parity gap (Phase 5 work)

8. **Phase 5: Commit API Restructuring**
   _Sketch: `.sketches/2026-02-19-commit-api-redesign.md`_
   - [x] **Rust**: Introduce `CommitScope<'a>` typestate pattern; remove auto-creation semantic from `verify_and_apply_transaction`
   - [ ] **Go**: Introduce `CommitBatch` (Tx pattern) with `BeginCommit()`, `Apply()`, `Finalize()`
   - [x] **Rust**: Update `cyphrpass-storage` import loop (`replay_commits`) to use CommitScope with deferred action handling
   - [ ] **Go**: Update `storage/import.go` loop (`replayEntries`) to respect commit boundaries
   - [x] **Rust**: Refactor test consumers (golden runners, CLI, internal tests) to use new commit API
   - [ ] **Go**: Refactor test consumers to explicitly handle multi-tx boundaries
   - [ ] **Both**: Verify all tests pass, including golden categories that previously failed

## Verification

- [ ] `cargo test -p cyphrpass --lib` passes (unit tests, excludes golden integration tests)
- [ ] `go test ./cyphrpass/...` passes (unit tests, package-level)
- [ ] `go test ./storage/...` passes (storage tests)
- [ ] Both `cargo build` and `go build ./...` compile cleanly
- [ ] grep for stale `TransactionState` references returns zero hits (excluding golden fixtures)
- [ ] Manual inspection: `finalize_current_commit()` and `recomputeState()` compute each state node using the correct inputs per SPEC §8 (`AS` from `KS`, `CS` from `AS`+`CommitID`, `PS` from `CS`)

### Commands

```bash
# Rust — unit tests only (excludes golden fixtures)
cargo test -p cyphrpass --lib

# Rust — full compilation check
cargo build -p cyphrpass

# Go — package-level tests
go test ./cyphrpass/... ./storage/... ./testfixtures/...

# Go — full compilation
go build ./...

# Stale terminology check
rg 'TransactionState' rs/cyphrpass/src/ go/cyphrpass/ --glob '!*_test.go' --glob '!*golden*'
```

## Technical Debt

| Item                                                                         | Severity | Why Introduced                                                                                                      | Follow-Up                                                                                            | Resolved |
| :--------------------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------------------- | :------: |
| CLI `add`/`revoke` missing `complete_transaction()`                          | HIGH     | Auto-finalize removed during restructuring; callers not updated                                                     | Add `complete_transaction()` call after `verify_and_apply_transaction()` in both commands            |   [x]    |
| Stale `pre` comments say "auth state"                                        | LOW      | Terminology change from AS→CS for `pre`                                                                             | Update comments in `key.rs` L168, L264                                                               |   [x]    |
| `compare_commits` missing `cs` field check                                   | MEDIUM   | `cs` field added to `CommitEntry` but comparison not updated                                                        | Add `cs` comparison in `e2e.rs` `compare_commits`                                                    |   [x]    |
| `vtx.clone()` in `principal.rs` L780                                         | LOW      | Borrow checker workaround during restructuring                                                                      | Verify if clone is needed; if not, revert to move. If needed, add comment explaining why             |   [ ]    |
| Legacy intent bridge types (`PayIntent`, `CryptoIntent`, `StepIntent`)       | MEDIUM   | Kept for generator `golden.rs` compatibility during Phase 4a                                                        | Remove entirely in Phase 4b when generator is rewritten to use `CommitIntent`/`TxIntent`             |   [x]    |
| Action unification deferred (`action: Option` + `action_step: Vec`)          | MEDIUM   | TOML `[test.action]` (table) can't deserialize into `Vec`; should have used `[[test.action]]` and broken old format | Unify to `action: Vec<ActionIntent>` and update generator `action.as_ref()` → `action.first()`       |   [x]    |
| Generator functions still named `generate_single_step`/`generate_multi_step` | LOW      | Cosmetic rename to `_commit` would add noise to type-migration diff                                                 | Rename in Phase 4b DRY cleanup                                                                       |   [ ]    |
| `build_pay_json` unconditionally sets `commit=true`                          | LOW      | All current commits have 1 tx; correct for current invariant                                                        | Revisit if multi-tx-per-commit tests are added                                                       |   [ ]    |
| Dead `pre` fallback in `build_pay_json` for `PrincipalCreate.id`             | LOW      | Defensive coding; `current_as` is always provided in practice                                                       | Remove fallback branch or convert to error — `pre` is CS, not AS, so fallback is semantically wrong  |   [ ]    |
| `unwrap()`/`expect()` panics in library code                                 | LOW      | Carried forward from pre-restructuring code                                                                         | Replace with `Result` propagation per Rust persona; panics are inappropriate in library code         |   [ ]    |
| Double `resolve_key` in `build_action_coz` after DRY refactor                | LOW      | `build_action_pay_json` calls `resolve_key` internally, then `build_action_coz` calls again for signing             | Refactor if signing API evolves to accept signer directly; optimizing now would complicate lifetimes |   [ ]    |
| Unused `_alg` return from `build_action_pay_json`                            | LOW      | Helper returns `(Vec<u8>, String)` but alg unused at both call sites                                                | Remove second tuple element if no consumer materializes                                              |   [ ]    |

## Deviation Log

- **2026-02-17**: Scope creep in Phase 2. While performing Rust integration (Phase 2a), also updated downstream consumers in `cyphrpass-storage`, `cyphrpass-cli`, `test-fixtures`, and `e2e.rs`. This should have been Phase 3 work. Plan updated to include "Phase 2b" to retrospectively capture this work.
- **2026-02-19**: Phase ordering fix. TOML migration (was 4f) must precede golden regeneration (was 4d) because the generator can't parse old-format intent files after type restructuring. Reordered: 4d=TOML migration, 4e=golden regen, 4f=consumer updates.
- **2026-02-19**: Phase 4h (Verification) revealed a pre-existing parity gap: test runners failed to finalize commit boundaries, causing state divergence. Investigation (.sketches/2026-02-19-commit-api-redesign.md) revealed a structural flaw in the `Principal` API where commits were implicitly opened but never auto-finalized. Added Phase 5 to redesign the Commit API to use language-idiomatic enforcement (Rust Typestate, Go database/sql Tx pattern) instead of trying to patch the test runners.
- **2026-02-19**: Phase 5 Rust implementation used `CommitScope<'a>` instead of `PendingCommit<'a>` (plan name) to avoid collision with existing `PendingCommit` struct. Added `verify_and_apply()` and `principal_hash_alg()` to `CommitScope` — not in plan, but required because the scope's `&mut Principal` borrow prevents calling principal methods directly from storage import code. Added deferred action handling for `replay_commits` — actions in commit bundles can't be processed inside a `CommitScope`. Removed dead error variants `CommitInProgress` and `NoPendingCommit`.

## Retrospective

<!-- Filled after execution -->

## References

- Sketch: `.sketches/2026-02-17-branch-realignment.md`
- SPEC: `SPEC.md` §8.3–8.5 (working tree, not committed)
- Formal model: `docs/models/principal-state-model.md`
