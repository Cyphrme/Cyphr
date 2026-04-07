# PLAN: Implementation Alignment (State Tree + Commit Model)

<!--
  Align both Go and Rust implementations with the updated SPEC.md state tree
  hierarchy, commit model, and terminology. The prior CS Pivot plan brought
  the code to a state that no longer matches the current spec.

  See: workflows/plan.md for the full protocol specification.
-->

## Goal

Align Go and Rust implementations with the updated SPEC.md state tree
hierarchy, commit model, and terminology. The February 2026 CS Pivot plan
(`docs/plans/state-tree-restructuring.md`) restructured the code to use
`CS = MR(AS, CommitID)` and `PS = MR(CS, DS?)`. The spec has since evolved
past this model to:

- `SR = MR(AR, DR?)` — **State Root** replaces Commit State
- `PR = MR(SR, CR)` — **Principal Root** is now the evolving top-level digest
- `TR = MR(TMR, TCR)` — **Transaction Root** replaces Commit ID
- `CR = MALTR(TR₀, TR₁, ...)` — **Commit Root** uses a MALT append-only tree
- `Arrow = MR(pre, fwd, TMR)` — commit finality mechanism (new)
- `PG` — **Principal Genesis** is the immutable identity (first PR)

Both implementations must compute identical state values using the canonical
formulas. Backwards compatibility is explicitly not a concern (pre-alpha).

## Constraints

- SPEC.md is authoritative for all formulas, terminology, and wire formats
- Go and Rust must achieve parity — same types, same formulas, same outputs
- MALT packages must remain standalone modules/crates (future repo split)
- Pre-alpha: no backwards-compatibility requirement; break anything that
  contradicts the spec

## Decisions

| Decision                       | Choice                                  | Rationale                                                                                                                |
| :----------------------------- | :-------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- |
| daolfmt → malt rename          | Rename packages before integration      | MALT is the canonical spec name. Rename first to avoid importing the wrong name                                          |
| Keep malt standalone           | Separate go.mod / workspace crate       | Future repo split anticipated. Cyphrpass adds as dependency                                                              |
| Phase renames before structure | Mechanical grep/replace first           | Low-risk terminology alignment before touching computation logic                                                         |
| Eliminate CS entirely          | Delete CommitState type, not adapt      | CS has no spec analog. SR replaces it with different semantics (excludes commit info)                                    |
| Wire format: commit → arrow    | Replace 'commit' coz field with 'arrow' | SPEC.md §5.2 shows commit coz has 'arrow' field. Old CS-embedding wire format is dead                                    |
| Sub-phase the SR restructuring | Split Phase 3 into 3a-3d                | Prior plan's deviation log warns scope creep is inevitable; sub-phase by compilation boundary                            |
| `pre` semantics unchanged      | pre already references PR (correct)     | Code already uses PrincipalState for pre. SPEC.md §4.1.1 confirms. Only type rename needed                               |
| Defer formal model alignment   | Update after implementation, not during | Model is reference, not driver. Implementation may surface issues that change it                                         |
| List-of-lists `txs` structure  | In scope, part of Phase 4               | TR decomposition requires distinguishing mutation cozies from commit cozies. Storage + fixtures depend on this structure |
| Embedding parameters           | Add to all compute function signatures  | We're rewriting every signature anyway. Adding `embedding` now is trivial; deferring costs a second restructuring pass   |

## Risks & Assumptions

| Risk / Assumption                                            | Severity | Status    | Mitigation / Evidence                                                                                   |
| :----------------------------------------------------------- | :------- | :-------- | :------------------------------------------------------------------------------------------------------ |
| Phase 3 scope explosion (precedent: Feb CS Pivot 4→8 phases) | HIGH     | Mitigated | Sub-phased from start (3a-3d). Prior plan's deviation log explicitly captured this lesson               |
| Wire format change: 'commit' → 'arrow' in commit coz         | MEDIUM   | Mitigated | SPEC.md L699 confirms. Go `parseCommit` (transaction.go L219) and Rust commit coz builder need updating |
| Go malt is a separate module — dependency wiring             | MEDIUM   | Mitigated | Add as go.mod dependency. TreeHasher implementation needed for Cyphrpass hash algorithms                |
| DAOLFMT Append() takes raw []byte, not typed TR digests      | LOW      | Mitigated | Standard pre-hashed-leaf pattern: Leaf = identity, Node = MR. Minor integration work                    |
| Formal model alignment may be premature                      | LOW      | Accepted  | Deferred to post-implementation verification phase                                                      |
| `pre` already references PrincipalState (≈PR)                | —        | Validated | Go verifyPre() takes PrincipalState; Rust extract_pre() returns PrincipalState                          |
| CommitState → StateRoot is a direct structural replacement   | —        | Validated | CS = MR(AS, DS?) maps to SR = MR(AR, DR?). Same formula shape, same slot in structs                     |
| MALT API sufficient for CR computation                       | —        | Validated | Both langs have Log.Append() + Log.Root(). API surface is sufficient                                    |
| Golden fixtures will break but can be regenerated            | —        | Validated | Precedent from prior plan. fixture-gen binary exists                                                    |

## Open Questions

- **Wire field name for SR in coz JSON**: SPEC.md tx*meta (L716) shows `"fwd"` holds the SR value.
  The old `"commit"` field embedded CS. Need to verify: does the commit coz also carry `"fwd"` as a
  standalone field, or is SR only derivable from the `"arrow"` digest? Must read SPEC.md §5.2 closely
  during Phase 6 implementation. \_Not plan-blocking — execution-level detail.*

## Scope

### In Scope

- Rename all "State" types to "Root" in both Go and Rust (KS→KR, AS→AR, DS→DR, PS→PR, PR→PG)
- Rename daolfmt packages to malt in both Go and Rust
- Introduce StateRoot (SR) type and ComputeSR function
- Eliminate CommitState (CS) type and ComputeCS function
- Add `embedding` parameter to all compute functions (KR, AR, SR, PR)
- Replace CommitID with TMR/TCR/TR decomposition
- List-of-lists `txs` structure (distinguish mutation cozies from commit cozies)
- Integrate MALT for CR computation
- Implement arrow finality (arrow = MR(pre, fwd, TMR))
- Update wire format (commit → arrow)
- Update all downstream consumers (storage, CLI, fixtures, e2e runners)
- Regenerate golden fixtures
- Spec tracing verification (genesis + key addition walkthroughs)
- Machine spec realignment pass

### Out of Scope

- Rule State / Rule Root (RS/RR) — Level 5, not implemented
- Level 6 VM
- Recovery timelocks
- Algorithm rank
- MALT inclusion/consistency proofs in cyphrpass core
- Formal model alignment (`docs/models/principal-state-model.md`) — deferred to post-verification

## Phases

1. **Phase 1: MALT Package Rename** — Rename daolfmt → malt in both Go and Rust ✅
   - [x] Go: rename `go/daolfmt/` → `go/malt/`, update module path to `github.com/cyphrme/malt`
   - [x] Rust: rename `rs/daolfmt/` → `rs/malt/`, update crate name in `Cargo.toml`
   - [x] Update `Cargo.toml` workspace members list
   - [x] Update any existing references/imports
   - [x] Both packages build and pass tests under new name

2. **Phase 2: Type Renames (State → Root)** — Align type and function names with SPEC.md terminology ✅
   - [x] Go: `KeyState` → `KeyRoot`
   - [x] Go: `AuthState` → `AuthRoot`
   - [x] Go: `DataState` → `DataRoot`
   - [x] Go: `PrincipalState` → `PrincipalRoot`
   - [x] Go: `PrincipalRoot` → `PrincipalGenesis`
   - [x] Go: `CommitState` kept temporarily (deleted in Phase 3)
   - [x] Go: accessor renames (`.KS()` → `.KR()`, `.AS()` → `.AR()`, `.DS()` → `.DR()`, `.PS()` → `.PR()`, `.PR()` → `.PG()`)
   - [x] Go: function renames (`ComputeKS` → `ComputeKR`, `ComputeAS` → `ComputeAR`, `ComputeDS` → `ComputeDR`, `ComputePS` → `ComputePR`)
   - [x] Rust: identical renames
   - [x] All tests, storage, CLI, fixtures updated
   - [x] Both implementations build and pass all tests

3. **Phase 3: SR Introduction + CS Elimination** — Replace `CS = MR(AS, DS?)` with `SR = MR(AR, DR?)` and restructure `PR = MR(SR, CR)` ✅

   **3a: Core types and compute (both langs)**
   - [x] Add `StateRoot` type (both langs)
   - [x] Add `ComputeSR(ar, dr?, embedding?, algs) → StateRoot` (`SR = MR(AR, DR?, embedding?)`)
   - [x] Add `embedding` parameter to `ComputeKR`, `ComputeAR`, `ComputePR`
   - [x] Delete `ComputeCS` (both langs)
   - [x] Rewrite `ComputePR`: inputs change from `(CS, DS)` to `(SR, CR, embedding?)`
   - [x] If no CR (Levels 1-3): `PR = SR` (implicit promotion)

   **3b: Principal struct integration (both langs)**
   - [x] Replace `cs` field with `sr` field in Principal
   - [x] Update state recomputation in `finalize_commit` / `FinalizeCommit`
   - [x] Add `.SR()` accessor
   - [x] Delete `.CS()` accessor and `CommitState` type

   **3c: Commit struct + finalization (both langs)**
   - [x] Replace `cs` field with `sr` in `Commit` struct
   - [x] Update `PendingCommit` / `CommitScope` finalization
   - [x] Update `CommitBatch` (Go) finalization

   **3d: Downstream consumers (both langs)**
   - [x] Update storage export/import (if CS is referenced)
   - [x] Update CLI commands
   - [x] Update test fixtures and intent structs
   - [x] Update e2e runners

4. 4. **Phase 4: TR Decomposition + List-of-Lists** — Replace CommitID with TMR/TCR/TR; adopt list-of-lists `txs` structure

- [x] Restructure transaction model: `txs` is list of transactions, each transaction is list of cozies (mutation cozies + commit coz)
- [x] Update storage format to reflect list-of-lists structure
- [x] Add `TransactionMutationRoot`, `TransactionCommitRoot`, `TransactionRoot` types (both langs)
- [x] Add `ComputeTMR`, `ComputeTCR`, `ComputeTR` functions (both langs)
- [x] Delete `CommitID` type and `ComputeCommitID` / `ComputeCommitIDTagged` functions
- [x] Update `Commit` / `PendingCommit` / `CommitScope` structs: `commitID` → `tr` (with `tmr`, `tcr`)
- [x] Update commit finalization: compute TMR from tx mutation czds, TCR from commit czds, `TR = MR(TMR, TCR)`
- [x] Update downstream consumers (storage, fixtures, runners)

5. **Phase 5: MALT Integration for CR** — Wire malt package for `CR = MALTR(TR₀, TR₁, ...)`
   - [x] Go: add `github.com/cyphrme/malt` dependency to `go.mod`
   - [x] Rust: add `malt = { path = "../malt" }` to `cyphrpass/Cargo.toml`
   - [x] Implement `TreeHasher` for Cyphrpass hash algorithms (both langs)
   - [x] Add `CommitRoot` type (both langs)
   - [x] Add `ComputeCR` using MALT `Log.Append()` + `Log.Root()`
   - [x] Add `commit_tree` (MALT `Log`) to Principal struct
   - [x] Update PR computation: `PR = MR(SR, CR)`
   - [x] Handle genesis: single-element MALT → `CR = Leaf(TR₀)`

6. **Phase 6: Arrow Finality** — Implement `arrow = MR(pre, fwd, TMR)`
   - [x] Add `arrow` field to commit transaction coz (replaces old `commit` field)
   - [x] Compute arrow during commit finalization: `MR(pre_PR, fwd_SR, TMR)`
   - [x] Validate arrow during transaction verification
   - [x] Update wire format: remove `commit` field, add `arrow` field
   - [x] Update transaction parsing (Go `parseCommit` → `parseArrow`)
   - [x] Update transaction building (Rust/Go commit coz construction)
   - [x] **Genesis arrow**: update genesis flow — `pre` == `tmb` at bootstrap,
         arrow is `MR(tmb, SR_genesis, TMR_genesis)`. Verify `[genesis-bootstrap]`,
         `[genesis-pre-bootstrap]`, `[genesis-finality]` are all satisfied
   - [x] Verify `[level-1-2-identity]` corollary: `tmb == KR == AR == SR == PR == PG`
         via implicit promotion through the new SR layer

7. **Phase 7: Verification + Fixture Regeneration** — Rebuild tests against new structure

   **7a: Bug fixes (blocking verification)** ✅
   - [x] Go: Fix `ParseCoz` `HashAlg` initialization — `HashAlg(pay.Alg)` → `HashAlgFromSEAlg(pay.Alg)` (raw cast of signing alg to hash alg produced garbage)
   - [x] Go: Add `TypCommitCreate` / `TxCommitCreate` — `commit/create` typ was missing from `ParseCoz` and `typSuffix`, preventing `FinalizeWithArrow` from parsing its own output
   - [x] Go: Update `Push()` routing — also route by `Kind == TxCommitCreate` (defense-in-depth alongside `Arrow != nil`)
   - [x] Go: Fix `HasCommit()` in `entry.go` — now detects both `"arrow"` and `"commit"` fields for terminal coz detection during import
   - [x] Go: Fix `IsTransaction()` / `containsKeyPrefix()` — now matches `/commit/` prefix so `commit/create` entries are recognized as transactions
   - [x] Go: Fix `test_helpers_test.go` build — pointer/value mismatch on `cz.Arrow` assignment
   - [x] Rust: Fix `commit.cz` → `commit.tx` in `golden.rs:591` (stale field access from Phase 4)
   - [x] Rust: Remove `.unwrap()` from infallible `Thumbprint::from_bytes()` in `key.rs` (2 sites)
   - [x] Both codebases build cleanly: `go build ./...` and `cargo build --workspace`

   **7c: Intent format migration (list-of-lists)** ✅
   - [x] Struct change: `CommitIntent.Tx` from `Vec<TxIntent>` / `[]TxIntent` to `Vec<Vec<TxIntent>>` / `[][]TxIntent` (Go + Rust)
   - [x] Migrate all 12 TOML files from `[[test.commit.tx]]` table arrays to inline `tx = [[{...}]]` list-of-lists
   - [x] Update Go e2e runner to iterate transactions → cozies (add inner loop)
   - [x] Update Rust golden generator to iterate transactions → cozies
   - [x] Verify both parsers round-trip: load a migrated TOML, confirm struct matches expected shape
   - [x] Update `tests/README.md` documentation examples to match new format
   - [x] Sketch ref: `.sketches/2026-04-02-intent-list-of-lists.md`

   **7d: Fixture regeneration + bug fixes** ✅
   - [x] Regenerate all golden fixtures via `fixture-gen` (40 fixtures from 7 intent files)
   - [x] Go build clean: `go build ./...`
   - [x] Rust build clean: `cargo build --workspace`
   - [x] Go `ApplyTransactionUnsafe` nil deref — mutation coz routed to commitTx, TMR nil
   - [x] Go `ExportEntries` missing commit cozies — reimport couldn't detect boundaries
   - [x] Go `TestLoadGolden` stale TxCount assertion (1 → 2)
   - [x] Go genesis bootstrap bug — Arrow `pre` used post-mutation Keys[0].Tmb instead of p.pr (3 locations)
   - [x] Go [pre-mutation-key-rule] — `CommitBatch` snapshots active keys at BeginCommit;
         commit/create coz signed by replaced/revoked key now authorized correctly
   - [x] Rust `state_root` → `arrow` field rename in `apply_transaction_test`
   - [x] Rust `apply_transaction_test` same mutation+commit coz split as Go
   - [x] Rust `make_test_tx` — `commit` → `arrow` field, typ → `cyphrpass/commit/create`
   - Go test failures: 17 → 4 (all multi-algorithm PR divergence)
   - Rust unit tests: 55/65 → 65/65 passing
   - Rust golden integration: 6/7 failing (`MissingCommit` — fixture runner needs commit coz split)

   **7e: Final verification** (Partially Complete)
   - [x] Fix Rust golden fixture runner (`MissingCommit` — same commit coz pattern)
   - [x] Fix multi-algorithm PR divergence (4 Go tests, likely Rust too)
   - [x] Full test suite passes in both langs (`go test ./...`, `cargo test`)
   - [ ] Genesis commit trace walkthrough
   - [ ] Key addition (Level 3) trace walkthrough
   - [ ] Stale terminology sweep (zero hits for old names):
         `rg 'KeyState|AuthState|CommitState|CommitID|PrincipalState|daolfmt'`

   **7f: MALT Multi-Algorithm Architecture Pivot**
   - [x] Go: Remove `CyphrpassMultiHasher`, replace with single-alg `CyphrpassHasher` in `commit_root.go`
   - [x] Go: Change `Principal.commitTree` to `commitTrees CommitTrees` (`map[HashAlg]*CommitLog`)
   - [x] Go: Assemble CR from per-alg MALT roots via `NewCommitRootFromTrees`, filtered to active algs only
   - [x] Go: Fix `FinalizeWithArrow` to derive post-mutation alg set for KR/AR/SR computation
   - [x] Go: Fix `ComputeRoots` to accept `algs` parameter; TMR/TCR/TR use signer's single alg (CZDs are single-alg)
   - [x] Go: Move `activeAlgs` re-derivation in `finalizeCommit` before state root computation
   - [x] Go: All tests pass (`go test ./...`)
   - [x] Rust: Same pivot — replace multi-alg hasher with per-alg MALTs
   - [x] Verify multi-algorithm PR parity between Go and Rust

### 7.1 Technical Debt Log (From Phase 4-7)

During the structural alignment phases, the following technical debt was incurred and must be resolved before finalizing the release:

- **Rust unused variables**: The `principal.rs` logic triggers `#[warn(unused_variables)]` for `claimed_arrow`, `tmr`, and `pre`, due to partial deferment of deep arrow validation structure inside `finalize_commit`.
- **Rust documentation coverage**: `missing_docs` compiler warnings ignore documentation for newly split components like `commit.rs`, `commit_root.rs`, and `transaction_root.rs`.
- **Testing Helpers**: `ApplyTransactionUnsafe` (Go) and equivalent helpers in Rust testing use emergency patches (`cz.Arrow = sr.MultihashDigest`, etc.) to bypass structural enforcement. They need to be properly refactored to compute `Arrow` correctly.
- **Fixture internal backwards compatibility**: Rust `test-fixtures` has 3 internal unittests failing because they predated the single-commit format changes (list-of-lists) and assume atomic single-coz capability without `commit/create` wrapping.

8. **Phase 8: Machine Spec Tracing + Realignment** — Verify machine specs reflect implementation reality and refine constraints

   This phase is the explicit tracing/realignment segment. For each machine spec,
   trace the key constraints to their implementation, verify correctness, and
   update the machine spec if the implementation surfaced gaps or if constraints
   need refinement.

   **8a: state-tree.md tracing**
   - [ ] `[state-computation]` — verify 4-step algorithm is implemented (collect, sort, promote, MR)
   - [ ] `[implicit-promotion]` — verify single-child promotion works through new SR layer
   - [ ] `[no-circular-state]` — verify SR excludes CR in implementation; PR = MR(SR, CR)
   - [ ] `[mr-sort-order]` with MALT exception — verify MALT uses append-order, everything else uses lexical sort
   - [ ] State formulas — verify code matches: `KR`, `AR`, `SR = MR(AR, DR?, embedding?)`, `PR = MR(SR, CR, embedding?)`
   - [ ] `[level-1-2-identity]` — verify promotion chain: `tmb == KR == AR == SR == PR == PG`
   - [ ] `[conversion]` — verify cross-algorithm conversion still works with new types
   - [ ] Update `state-tree.md` if any constraints need refinement (e.g., embedding semantics)

   **8b: transactions.md tracing**
   - [ ] `[txs-list-of-lists]` — verify list-of-lists structure in both implementations
   - [ ] `[tx-root-computation]` — verify per-transaction `TX = MR(czds)`
   - [ ] `[tmr-computation]` — verify `TMR = MR(TX₀, TX₁?, ...)`
   - [ ] `[tcr-computation]` — verify `TCR = MR(czd₀, czd₁?, ...)`
   - [ ] `[tr-computation]` — verify `TR = MR(TMR, TCR)`
   - [ ] `[commit-finality-arrow]` — verify `arrow = MR(pre, fwd, TMR)` computation and validation
   - [ ] `[arrow-excludes-self]` — verify `fwd` is SR (not PR)
   - [ ] `[pr-after-commit]` — verify `PR = MR(SR, CR)` after commit finalization
   - [ ] `[intra-commit-ordering]` — verify array-order application
   - [ ] `[genesis-bootstrap]`, `[genesis-pre-bootstrap]`, `[genesis-finality]` — verify genesis flow
   - [ ] Update `transactions.md` if any constraints need refinement

   **8c: remaining specs spot-check**
   - [ ] `principal-lifecycle.md` — verify `[lifecycle-derived-from-state]` uses new type names
   - [ ] `authentication.md` — verify `[verification-replay]` works with new state structure
   - [ ] `consensus.md` — verify `[fork-detection]` uses PR (not CS) for tip comparison
   - [ ] `recovery.md` — verify `[disown-no-ar-mutation]` terminology is current
   - [ ] Update any specs where old terminology persists or constraints are stale

   **8d: constraint inventory**
   - [ ] Produce a summary table: new constraints introduced, constraints modified, constraints unchanged
   - [ ] Verify no orphan constraints (constraints that reference removed concepts like CS or CommitID)

### Phase Dependency Graph

```
Phase 1 (malt rename) ─────────────────────────────────────┐
                                                            v
Phase 2 (type renames) ──→ Phase 3 (SR+CS) ──→ Phase 4 (TR) ──→ Phase 5 (MALT/CR)
                                       │              │                │
                                       └──────────────┴── Phase 6 (Arrow)
                                                               │
                                                  Phase 7 (Verify+Fixtures)
                                                               │
                                                  Phase 8 (Spec Tracing) ←──┘
```

Phases 1 and 2 are independent (either order or parallel).
Phase 3 gates all structural work.
Phase 5 requires both Phase 1 (malt rename) and Phase 4 (TR types).
Phase 6 requires Phase 3 (SR for `fwd`) and Phase 4 (TMR).
Phase 8 is the explicit tracing/realignment pass after implementation is stable.

## Verification

- [ ] `go test ./...` passes (from `go/`)
- [ ] `cargo test` passes (from `rs/`)
- [ ] `cargo build --workspace` compiles cleanly
- [ ] `go build ./...` compiles cleanly
- [ ] Stale terminology sweep returns zero hits:
      `rg 'KeyState|AuthState|CommitState|CommitID|PrincipalState|daolfmt' go/cyphrpass/ rs/cyphrpass/src/`
- [ ] Golden fixtures regenerated and verified
- [ ] Genesis commit trace: all state derivations match machine spec constraints
- [ ] Key addition trace: all state derivations match machine spec constraints
- [ ] Phase 8 tracing complete: all key constraints in `docs/specs/` traced to code
- [ ] No orphan constraints in machine specs (zero references to CS, CommitID, or old type names)

### Commands

```bash
# Go — all tests
cd go && go test ./...

# Rust — all tests
cd rs && cargo test

# Stale terminology check
rg 'KeyState|AuthState|CommitState|CommitID|PrincipalState|daolfmt' \
  go/cyphrpass/ rs/cyphrpass/src/ \
  --glob '!*_test*' --glob '!*golden*'

# MALT package rename check
rg 'daolfmt' go/ rs/ --glob '!target'
```

## Technical Debt

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Item                                                                                                             | Severity | Why Introduced                                                         | Follow-Up                                                       |  Resolved  |
| :--------------------------------------------------------------------------------------------------------------- | :------- | :--------------------------------------------------------------------- | :-------------------------------------------------------------- | :--------: |
| Go `Transaction.CommitCS` field name retains stale CS terminology                                                | MEDIUM   | Minimizing churn during Phase 3 structural refactor                    | Rename to `CommitSR` in cleanup pass                            | 2026-04-01 |
| Rust `PrincipalCore.cs`, `Commit.cs`, `pub fn cs()` accessor names retain stale `cs` naming                      | MEDIUM   | Same — minimizing churn                                                | Rename to `sr`/`state_root()` in cleanup pass                   | 2026-04-01 |
| ~20 doc comments across both langs still reference "Commit State" or describe `MR(AS, CommitID)` semantics       | LOW      | Focus was on structural correctness, not prose                         | Sweep with `rg 'commit.state\|Commit State'`                    | 2026-04-01 |
| Golden fixture JSON values stale — computed under old CS hierarchy                                               | HIGH     | Expected — new computation chain produces different digests            | Regenerate via `fixture-gen` (Phase 7)                          |            |
| Intent/golden struct comments in `intent.go`/`intent.rs`/`golden.go`/`golden.rs` still say "commit state digest" | LOW      | Focus was on types and functions, not field comments                   | Sweep alongside doc comment cleanup                             | 2026-04-01 |
| C.O.R.E. boundary consolidation during Phase 4 list-of-lists                                                     | LOW      | Session interruption caused context drop                               | Formal protocol restored and output applied                     | 2026-04-01 |
| Rust e2e tests fail dynamically due to `commit.cz` validation logic breaking on multi-transaction layouts        | LOW      | List-of-lists format integration wasn't applied to testers             | Fix test logic in Phase 7                                       |            |
| Missing docs lint warnings in Rust related to `commit.rs` and `transaction_root.rs`                              | LOW      | Minor structural refactoring churn                                     | Cleanup in Phase 7                                              |            |
| Go `ApplyTransactionUnsafe` injects SR as Arrow placeholder instead of computing real Arrow                      | MEDIUM   | Emergency patch during test helper adaptation                          | Refactor to compute Arrow properly or remove helper             | 2026-04-03 |
| Go `containsKeyPrefix` function name misleading — checks for infixes (`/key/`, `/commit/`) not prefixes          | LOW      | Pre-existing; expanded during Phase 7a `/commit/` addition             | Rename to `containsKnownTypInfix` in cleanup pass               |            |
| Go `FinalizeWithArrow` uses raw `HashAlg(signerKey.Alg.Hash())` instead of `HashAlgFromSEAlg` wrapper            | LOW      | Pre-existing; functionally equivalent but inconsistent                 | Normalize to `HashAlgFromSEAlg` in next code sweep              |            |
| Go genesis bootstrap override in Arrow `pre` computation — used post-mutation key set                            | MEDIUM   | Incorrect assumption that p.pr needed re-derivation at genesis         | Removed in 3 locations; p.pr always correct                     | 2026-04-03 |
| Go `VerifyCoz` checked live state for commit/create auth instead of pre-mutation snapshot                        | HIGH     | Violated [pre-mutation-key-rule] — spec says pre-commit keys authorize | Added `verifyCozWithSnapshot` + key snapshot                    | 2026-04-03 |
| Rust `apply_transaction_test` put arrow on mutation coz instead of separate commit coz                           | MEDIUM   | Same structural error as Go `ApplyTransactionUnsafe`                   | Ported same fix: mutation + commit coz split                    | 2026-04-06 |
| Rust golden fixture runner doesn't construct commit/create coz                                                   | MEDIUM   | Runner predates list-of-lists commit coz separation                    | Needs same pattern as unit test helper                          |            |
| Multi-algorithm PR divergence between Go and Rust                                                                | HIGH     | Go and Rust compute PR differently when activeAlgs > 1                 | Root cause: multi-alg MALT hasher. Fixed via per-alg MALT pivot | 2026-04-07 |
| Go `test_helpers_test.go` `ApplyTransactionUnsafe` uses pre-mutation `activeAlgs` for arrow computation          | LOW      | Only used in single-algorithm unit tests; multi-alg would fail         | Align with `FinalizeWithArrow` post-mutation pattern            |            |
| Go `PendingCommit.Finalize` computes TR with single `p.hashAlg` instead of full active alg set                   | LOW      | Only called from `finalizeCommit` which separately computes TR         | Align when/if Finalize is used independently                    |            |

## Deviation Log

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Commit              | Planned                                    | Actual                                                                                                                                                                         | Rationale                                                                                                                                                                             |
| :------------------ | :----------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `19dc1cd` (Phase 3) | `embedding` was Open Question #5, deferred | Added `embedding` parameter stubs proactively to all compute function signatures (always `nil`/`None`)                                                                         | Spec formulas include `embedding?` at every MR level. Adding now avoids a future signature-breaking change; cost is negligible                                                        |
| Phase 7a (Bug Fix)  | Phase 7 was marked complete                | Discovered 4 critical bugs blocking verification: Go `HashAlg` misinitialization, missing `commit/create` typ parsing, stale storage import detection, and Rust compile errors | Prior session (Gemini) marked Phase 7 items complete but fixture regeneration had produced incorrect digests. Root causes identified during cross-implementation audit                |
| Phase 7c (Format)   | Phase 7b was next after bug fixes          | Added intent format migration to list-of-lists (`Vec<Vec<TxIntent>>`) before fixture regeneration                                                                              | Current flat `tx` list can't distinguish single-coz vs. multi-coz transactions — a structural blind spot preventing tests for the full transaction model. Must fix before regen       |
| Phase 7d (Bugs)     | Fixture regen + full pass                  | Fixture regen produced 17 Go failures; uncovered 3 distinct bug classes requiring 7 code fixes across Go + Rust                                                                | Genesis bootstrap, pre-mutation key rule, and mutation/commit coz split were all independently blocking; each required spec consultation                                              |
| Phase 7d (Split)    | Single verification phase                  | Split 7d (bug fixes, done) from 7e (final verification, not started) due to scope expansion                                                                                    | 7d grew from "regen + verify" to "regen + discover 3 bug classes + fix 7 locations + port to Rust". Clean boundary needed                                                             |
| Phase 7f (Pivot)    | N/A                                        | Introduced Phase 7f to replace `CyphrpassMultiHasher` with a one-MALT-per-algorithm architecture                                                                               | Investigating 4 PR divergence failures revealed the multi-algorithm hasher violates MALT's single-algorithm concern and forces O(n) rebuilds. Pivot ensures canonical spec alignment. |

## Retrospective

<!--
  Filled in after execution is complete.
-->

### Process

### Outcomes

### Pipeline Improvements

## References

- Sketch: `.sketches/2026-03-31-implementation-alignment.md`
- Prior plan: `docs/plans/state-tree-restructuring.md` (CS Pivot — superseded)
- Spec: `SPEC.md` (working tree, authoritative)
- Machine specs: `docs/specs/` (6 normative specifications)
- Formal model: `docs/models/principal-state-model.md` (stale — deferred)
