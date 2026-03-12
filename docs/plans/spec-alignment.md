# PLAN: Spec Alignment Implementation (§1-11)

<!--
  PLAN document for charter item 4: implementing breaking spec changes
  identified during machine spec realignment against SPEC.md `305631b`.

  Scoped to §1-11 only (Zami stability boundary, declared 2026-03-09).

  See: workflows/plan.md for the full protocol specification.
-->

## Goal

Align both Go and Rust implementations with the 5 breaking changes
identified during machine spec realignment against SPEC.md `305631b`.
The CS/PS computation model has fundamentally changed (CommitID swaps
from CS to PS), commit ID hashing uses array order instead of lexical
sort, PR no longer exists for Levels 1-2, and commits now use a
`commit` field for finalization signaling. This plan implements all
changes from stable sections §1-11 only.

## Constraints

- Scoped to SPEC.md §1-11 (Zami stability boundary). §12+ deferred.
- Go and Rust must remain independently buildable — no shared codegen.
- Existing test suites must pass after each workstream (regression net).
- Golden fixtures regenerated **after** all changes land (audit-remediation WS6).
- Each workstream produces self-contained, independently committable work.
- Machine spec constraint IDs (`docs/specs/*.md`) are the normative anchors.
- **No legacy cruft.** Superseded code paths MUST be removed, not deprecated. No compatibility shims. Pre-alpha; backwards compatibility is a non-goal (per AGENTS.md).

## Decisions

| Decision                   | Choice                                                            | Rationale                                                                                                |
| :------------------------- | :---------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------- |
| CS/PS restructure approach | Swap CommitID membership; CS and PS computed in parallel from AS  | Sequential chain (AS→CS→PS) becomes parallel (AS→CS, AS→PS). PS no longer depends on CS.                 |
| `pre` type migration       | `Transaction.Pre` becomes `PrincipalState` (was `CommitState`)    | SPEC §4.3: `pre` references PS. In new model CS ≠ PS when CommitID exists (Level 3+).                    |
| Array-order implementation | New `hashConcatBytes` (no sort) alongside existing sorted variant | Sorted variant still needed for state tree MR computation                                                |
| L1/2 PR treatment          | `PR` becomes `Option`/pointer (nil for L1/2)                      | Type-safe representation of absence matches spec semantics                                               |
| Genesis `id` assertion     | Update to compare PS (not AS)                                     | Per `[genesis-finality]` — PS at genesis equals PR for L3+                                               |
| Commit finality API        | CommitBuilder with deferred last-coz signing                      | CS must be known before last coz is signed; CommitID requires all czds after signing. Natural batch API. |

## Risks & Assumptions

| Risk / Assumption                                                                                                                        | Severity | Status      | Mitigation / Evidence                                                                                                                                                            |
| :--------------------------------------------------------------------------------------------------------------------------------------- | :------- | :---------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CS/PS swap touches every state computation call site                                                                                     | MEDIUM   | Validated   | Surveyed Go `state.go` — 3 functions (`ComputeCS`, `ComputePS`, `ComputeDS`), ~6 call sites in `principal.go`. Contained.                                                        |
| Existing tests may silently pass with wrong values after swap                                                                            | MEDIUM   | Unvalidated | Golden fixtures compare computed values. After CS/PS swap, if tests pass they're testing the _wrong_ expected values. Must regenerate fixtures after changes.                    |
| `hashConcatBytes` (no sort) may produce different results from `hashSortedConcatBytes` only when components aren't already in sort order | LOW      | Validated   | By definition — if inputs happen to be in sort order, both functions produce identical output. Divergence is intentional.                                                        |
| `commit` field parsing may require coz library changes                                                                                   | LOW      | Validated   | Coz payloads are opaque JSON — `commit` is just another `pay` field. No library changes needed.                                                                                  |
| Array order applies to MR inputs for commit ID only, not state tree                                                                      | HIGH     | Validated   | `[mr-sort-order]` + `[intra-commit-ordering]` — state tree nodes still lexically sorted, only commit ID computation uses array order. Decision record in sketch.                 |
| `pre` type change ripples through Transaction, verifyPre, tests, and import path                                                         | MEDIUM   | Validated   | Surveyed: Go `transaction.go:55`, `principal.go:578`; Rust `transaction.rs:36+`, `principal.rs:892`. Every variant, every test constructing `Pre:`. Contained to WS-A.           |
| CommitBuilder requires access to signing key for deferred last-coz signing                                                               | MEDIUM   | Unvalidated | Current architecture signs cozies externally. CommitBuilder must either accept a signer callback or take ownership of the signing step. Design decision needed during execution. |

## Open Questions

- **Coz in commit use array order for hashing?** Yes — decided with Zami
  (2026-03-09). Captured in `[intra-commit-ordering]`. Not yet in SPEC.md
  but verbal agreement. Implementation proceeds on this basis.
- **`commit` error semantics?** Three error conditions identified but not
  yet in SPEC.md: `COMMIT_NOT_LAST` (commit in non-final coz),
  `MISSING_COMMIT` (no commit field), `COMMIT_MISMATCH` (value ≠ CS).
  We will implement these and propose to Zami.
- **CommitBuilder signing API?** The CommitBuilder must sign the last coz
  after injecting `commit:<CS>`. Two options: (a) accept a signer/key
  callback, or (b) accept an unsigned last payload and return a signable
  message. Decision deferred to execution — both are clean.

## Scope

### In Scope

- **WS-A**: CS/PS computation restructure (swap CommitID membership) + `pre` type migration
- **WS-B**: Commit ID array order (replace sorted concat)
- **WS-C**: L1/2 PR removal (make PR conditional on Level 3+)
- **WS-D**: Genesis finality (update `id` = PS, verify fixtures)
- **WS-E**: Commit finality plumbing (CommitBuilder API + verification semantics)

### Out of Scope

- §12+ features (embedding, MSS, consensus, recovery, state jumping)
- Golden fixture regeneration (deferred to audit-remediation WS6)
- Formal model review (charter item 3)
- Level 5+ rules implementation
- New error codes in consensus spec (deferred until §17/§24 stabilize)

## Phases

<!--
  Phases are ordered by structural dependency.

  COMPUTATION GRAPH CHANGE (critical architectural note):

  Old model (sequential):
    KS → AS → CS(AS, CommitID) → PS(CS, DS?)

  New model (parallel):
    KS → AS ─┬→ CS(AS, DS?)              # PT minus CommitID
              ├→ CommitID(czds)            # from array-ordered czds
              └→ PS(AS, CommitID?, DS?)    # includes CommitID directly

  CS and CommitID are now independent computations from AS.
  PS depends on both but NOT on CS — PS is computed directly from
  raw components (AS, CommitID, DS), not from the CS digest.

  This also means `pre` (which references PS per SPEC §4.3) must be
  typed as PrincipalState, not CommitState. In the old model CS == PS
  (without DS), so the type conflation was harmless. No longer.
-->

1. **Phase 1: State Computation** — Fix the core CS/PS formulas, commit
   ID hashing order, and `pre` type. Most structurally impactful; must
   land first because every downstream computation depends on correct
   state values.
   - [x] **WS-A: CS/PS Restructure + `pre` Migration** _(2026-03-10)_
     - [x] Go: Update `ComputeCS()` — remove `commitID` param, add `ds *DataState`
     - [x] Go: Update `ComputePS()` — remove `cs CommitState` param, add `as AuthState`, `commitID *CommitID` (keep `ds`)
     - [x] Go: Update `finalizeCommit()` — compute CS and PS in parallel from AS (not sequentially)
     - [x] Go: Update `RecordAction()` — recompute PS from AS directly (not from CS)
     - [x] Go: Update doc comments on `CommitState` ("PT minus CommitID"), `PrincipalState` ("includes CommitID")
     - [x] Go: Change `Transaction.Pre` from `CommitState` to `PrincipalState`
     - [x] Go: Update `verifyPre()` — compare against `p.ps` (not `p.cs`)
     - [x] Go: Update all test `Pre:` constructions from `*p.CS()` to `p.PS()`
     - [x] Rust: Mirror CS/PS signature changes in `state.rs`
     - [x] Rust: Change `pre` field in all `TransactionKind` variants from `CommitState` to `PrincipalState`
     - [x] Rust: Update `verify_pre()` — compare against PS
     - [x] Rust: Update `extract_pre()` to return `PrincipalState`
     - [x] Rust: Update doc comments
     - [x] Both: `go test ./...` and `cargo test --workspace` pass
   - [x] **WS-B: Commit ID Array Order** _(2026-03-10)_
     - [x] Go: Add `hashConcatBytes()` (concatenate without sorting)
     - [x] Go: Update `ComputeCommitID()` to use `hashConcatBytes`
     - [x] Rust: Add `hash_concat_bytes()` (concatenate without sorting)
     - [x] Rust: Update `compute_commit_id()` to use `hash_concat_bytes`
     - [x] Both: Sorted variant (`hashSortedConcatBytes`) preserved for state tree
     - [x] Both: `go test ./...` and `cargo test --workspace` pass

2. **Phase 2: Identity Corrections** — Fix PR optionality and genesis
   finality semantics. Independent of Phase 1 in concept but may share
   call sites in `principal.go`/`principal.rs`.
   - [x] **WS-C: L1/2 PR Removal** _(Go 2026-03-11, Rust 2026-03-12)_
     - [x] Go: Change `pr` field to `*PrincipalRoot` (nilable)
     - [x] Go: Only set `pr` at principal/create (not in constructors)
     - [x] Go: Update `PR()` accessor to return `*PrincipalRoot`
     - [x] Go: Update callers that assume PR is always present
     - [x] Rust: Wrap `pr` field in `Option<PrincipalRoot>`
     - [x] Rust: Only set at Level 3+ in genesis and import flows
     - [x] Rust: Update accessor to return `Option<&PrincipalRoot>`
     - [x] Rust: Update 13 files across cyphrpass, cyphrpass-storage, cyphrpass-cli, test-fixtures
     - [x] Both: `go test ./...` and `cargo test --workspace` unit tests pass
   - [x] **WS-D: Genesis Finality** _(Go 2026-03-11, Rust 2026-03-12)_
     - [x] Go: Genesis `id` assertion uses PS (was AS)
     - [x] Go: PR frozen at TxPrincipalCreate, not in constructors
     - [x] Rust: PrincipalCreate handler checks `id` against PS, freezes PR
     - [ ] Verify golden fixture values still hold (blocked on pre-field semantics — see Tech Debt)
     - [x] Both: `go test ./...` and `cargo test --workspace` unit tests pass

3. **Phase 2.5: PR Type Safety (Approach C)** — Refine `Option<PrincipalRoot>` from Phase 2
   into an enum-based representation that makes invalid PR states unrepresentable.
   - [x] **Rust: Enum-based PR enforcement** _(2026-03-12)_
     - [x] Extract `PrincipalCore` (12 shared fields)
     - [x] Define `PrincipalKind` enum: `Nascent(PrincipalCore)` | `Established{core, pr}`
     - [x] Impl `Deref`/`DerefMut` for transparent field access
     - [x] Add `establish_pr()` as sole Nascent → Established transition
     - [x] Add `Default` to `MultihashDigest` + 5 state newtypes (for `std::mem::take`)
     - [x] Update constructors + PrincipalCreate handler
     - [x] `cargo test --workspace` — 64 unit tests pass
   - [x] **Go: Invariant documentation** _(2026-03-12)_
     - [x] Enhanced `pr` field + `PR()` accessor docs with sealed-construction invariant
     - [x] `go test ./...` passes

4. **Phase 3: Commit Finality Plumbing** — Introduce CommitBuilder API
   and wire `commit` field verification. Depends on Phase 1 (CS must be
   correctly computed to embed in cozies).
   - [ ] **WS-E: CommitBuilder API + `commit` Field Verification**
     - [ ] **CommitBuilder (creation path):** New API that manages the commit lifecycle:
       1. Accepts transactions, accumulating mutations
       2. On finalize: computes CS from post-mutation state (AS', DS')
       3. Injects `commit:<CS>` into last coz payload
       4. Signs last coz (deferred signing — only the last coz is delayed)
       5. Computes CommitID from all czds (including signed last coz)
       6. Computes PS from AS', CommitID, DS'
     - [ ] Go: Implement `CommitBuilder` (evolve from `CommitBatch`)
     - [ ] Rust: Implement `CommitBuilder` (evolve from `CommitScope`)
     - [ ] **Verification/import path:** Detect and validate `commit` during array processing:
       - [ ] Coz with `commit` → mark as final
       - [ ] Error if cozies remain after `commit` coz (`COMMIT_NOT_LAST`)
       - [ ] Error if array ends without `commit` (`MISSING_COMMIT`)
       - [ ] Error if `commit` value ≠ independently computed CS (`COMMIT_MISMATCH`)
     - [ ] Go: Add error sentinels for the 3 new error conditions
     - [ ] Rust: Add error variants for the 3 new error conditions
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass

## Verification

- [x] Phase 1: `go test ./...` and `cargo test --workspace` pass after CS/PS + array-order + pre migration _(2026-03-10: core unit tests pass; golden fixtures expected-fail pending WS6)_
- [x] Phase 2: `go test ./...` and `cargo test --workspace` unit tests pass after PR + genesis _(2026-03-12: all unit tests pass; golden fixtures expected-fail pending pre-field fix + WS6)_
- [x] Phase 2.5: Enum-based PR enforcement verified _(2026-03-12: 64/64 Rust unit tests, Go tests pass)_
- [ ] Phase 3: `go test ./...` and `cargo test --workspace` pass after CommitBuilder + verification
- [ ] Cross-cutting: Both implementations produce identical PS/CS for same inputs (parity)
- [ ] Post-plan: Golden fixture regeneration via `cargo run -p fixture-gen` (deferred to WS6)
- [ ] Dead symbol sweep: grep for superseded symbols — zero hits:
  - `CommitBatch` / `CommitScope` (replaced by `CommitBuilder`)
  - `verifyPre(CommitState)` / `verify_pre(&CommitState)` (now takes `PrincipalState`)
  - `hashSortedConcatBytes` in `ComputeCommitID` call site (replaced by `hashConcatBytes`)
  - `ApplyTransactionUnsafe` (replaced by proper CommitBuilder flow)
  - Any `Pre: *p.CS()` test constructions (now `Pre: p.PS()`)

### Automated Tests

```bash
# Go — run all tests
cd go && go test ./... -count=1 -v

# Rust — run all tests
cargo test --workspace
```

## Technical Debt

<!--
  Populated during execution. Empty at plan creation.
-->

| Item                                                              | Severity | Why Introduced                  | Follow-Up                                                               | Resolved |
| :---------------------------------------------------------------- | :------- | :------------------------------ | :---------------------------------------------------------------------- | :------: |
| TD-3 (from audit plan): `ComputeCommitIDTagged` not wired         | LOW      | Pre-existing                    | Wire when Level 5+ multikey needed                                      |          |
| Golden fixtures stale after Phase 1 formula changes               | MEDIUM   | CS/PS swap + array-order change | Regenerate via `cargo run -p fixture-gen` (WS6)                         |    ✅    |
| `export.go` doc comment example uses value-type PR                | LOW      | PR → \*PrincipalRoot (WS-C)     | Fix in next doc sweep                                                   |          |
| `pre` field semantics: fixture-gen uses CS, verify_pre expects PS | HIGH     | Surfaced during WS-C/D Rust     | Fix fixture-gen to use PS-tagged, or fix verify_pre                     |    ✅    |
| CLI integration tests panic on L1 key add (`.expect()` on PR)     | MEDIUM   | PR optionality (WS-C/Phase 2.5) | Update CLI tests to use L3+ principals or precede with principal/create |          |

## Deviation Log

<!--
  Populated during execution. Empty at plan creation.
-->

| Commit      | Planned                                | Actual                                                    | Rationale                                                                     |
| :---------- | :------------------------------------- | :-------------------------------------------------------- | :---------------------------------------------------------------------------- |
| Go WS-A     | CS/PS swap only                        | + `ErrNoCommitState` removal, + `PrincipalState.Tagged()` | Dead code per cruft constraint; Tagged() needed by e2e runner for `pre` field |
| Go WS-A     | Update `ComputeCommitIDTagged` in WS-B | Also updated in WS-A commit scope                         | Same file, cleaner to ship together                                           |
| Go WS-C/D   | PR field + tests only                  | + `Store` interface `PrincipalRoot` → `*PrincipalRoot`    | Structurally required for type-level PR optionality                           |
| Rust WS-C/D | Option<PrincipalRoot> only             | + Approach C enum refactor (Phase 2.5)                    | User-driven: Option allows invalid states; enum eliminates them               |

## Retrospective

<!--
  Filled after execution.
-->

### Process

### Outcomes

### Pipeline Improvements

## References

- Charter: [spec-alignment.md](../charters/spec-alignment.md)
- Sketch: [.sketches/2026-03-02-machine-spec.md](../../.sketches/2026-03-02-machine-spec.md)
- Machine specs: [docs/specs/](../specs/) (145 constraints across 6 documents)
- Audit plan: [audit-remediation.md](audit-remediation.md)
- SPEC.md: `f2428ea` (latest reviewed commit on `origin/zami`)
