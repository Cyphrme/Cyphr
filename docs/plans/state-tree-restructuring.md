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

6. **Phase 3: Cleanup & Verification** — Comment/doc updates, unit tests, compilation checks
   - [ ] Update all doc comments with new terminology (TS → Commit ID, AS formulas)
   - [ ] Update Rust unit tests in `commit.rs` and `state.rs`
   - [ ] Update Go unit tests in `state_test.go`
   - [ ] Verify both `cargo test` and `go test ./...` compile (tests may still fail on golden fixtures)
   - [ ] Verify non-golden unit tests pass in both languages

7. **Phase 4: Golden Fixture Regeneration** — Update test fixtures to match new state computation
   - [ ] Identify all golden fixture files in both languages
   - [ ] Update fixture generator(s) to use new computation hierarchy
   - [ ] Regenerate golden fixtures
   - [ ] Verify full test suites pass: `cargo test` and `go test ./...`

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

| Item                                                             | Severity | Why Introduced                                                  | Follow-Up                                                                                           | Resolved |
| :--------------------------------------------------------------- | :------- | :-------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- | :------: |
| CLI `add`/`revoke` missing `complete_transaction()`              | HIGH     | Auto-finalize removed during restructuring; callers not updated | Add `complete_transaction()` call after `verify_and_apply_transaction()` in both commands           |   [x]    |
| Stale `pre` comments say "auth state"                            | LOW      | Terminology change from AS→CS for `pre`                         | Update comments in `key.rs` L168, L264                                                              |   [x]    |
| `compare_commits` missing `cs` field check                       | MEDIUM   | `cs` field added to `CommitEntry` but comparison not updated    | Add `cs` comparison in `e2e.rs` `compare_commits`                                                   |   [x]    |
| `vtx.clone()` in `principal.rs` L780                             | LOW      | Borrow checker workaround during restructuring                  | Verify if clone is needed; if not, revert to move. If needed, add comment explaining why            |   [ ]    |
| Dead `pre` fallback in `build_pay_json` for `PrincipalCreate.id` | LOW      | Defensive coding; `current_as` is always provided in practice   | Remove fallback branch or convert to error — `pre` is CS, not AS, so fallback is semantically wrong |   [ ]    |
| `unwrap()`/`expect()` panics in library code                     | LOW      | Carried forward from pre-restructuring code                     | Replace with `Result` propagation per Rust persona; panics are inappropriate in library code        |   [ ]    |

## Deviation Log

- **2026-02-17**: Scope creep in Phase 2. While performing Rust integration (Phase 2a), also updated downstream consumers in `cyphrpass-storage`, `cyphrpass-cli`, `test-fixtures`, and `e2e.rs`. This should have been Phase 3 work. Plan updated to include "Phase 2b" to retrospectively capture this work.

## Retrospective

<!-- Filled after execution -->

## References

- Sketch: `.sketches/2026-02-17-branch-realignment.md`
- SPEC: `SPEC.md` §8.3–8.5 (working tree, not committed)
- Formal model: `docs/models/principal-state-model.md`
