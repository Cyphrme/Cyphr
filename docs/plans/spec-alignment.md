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

## Decisions

| Decision                   | Choice                                                            | Rationale                                                                        |
| :------------------------- | :---------------------------------------------------------------- | :------------------------------------------------------------------------------- |
| CS/PS restructure approach | Swap CommitID membership, update function signatures              | Minimal refactor — same functions, new parameter sets                            |
| Array-order implementation | New `hashConcatBytes` (no sort) alongside existing sorted variant | Sorted variant still needed for state tree MR computation                        |
| L1/2 PR treatment          | `PR` becomes `Option`/pointer (nil for L1/2)                      | Type-safe representation of absence matches spec semantics                       |
| Genesis `id` assertion     | Update to compare PS (not AS)                                     | Per `[genesis-finality]` — PS at genesis equals PR for L3+                       |
| Commit finality API        | Data-driven: `commit` field in last coz signals finality          | Matches spec model; `PendingCommit.finalize()` injects `commit:<CS>` on creation |

## Risks & Assumptions

| Risk / Assumption                                                                                                                        | Severity | Status      | Mitigation / Evidence                                                                                                                                                              |
| :--------------------------------------------------------------------------------------------------------------------------------------- | :------- | :---------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CS/PS swap touches every state computation call site                                                                                     | MEDIUM   | Validated   | Surveyed Go `state.go` — 3 functions (`ComputeCS`, `ComputePS`, `ComputeDS`), ~6 call sites in `principal.go`. Contained.                                                          |
| Existing tests may silently pass with wrong values after swap                                                                            | MEDIUM   | Unvalidated | Golden fixtures compare computed values. After CS/PS swap, if tests pass they're testing the _wrong_ expected values. Must regenerate fixtures after changes.                      |
| `hashConcatBytes` (no sort) may produce different results from `hashSortedConcatBytes` only when components aren't already in sort order | LOW      | Validated   | By definition — if inputs happen to be in sort order, both functions produce identical output. Divergence is intentional.                                                          |
| `commit` field parsing may require coz library changes                                                                                   | LOW      | Validated   | Coz payloads are opaque JSON — `commit` is just another `pay` field. No library changes needed.                                                                                    |
| Commit finality processing changes verification/import flow                                                                              | MEDIUM   | Unvalidated | Current `PendingCommit.finalize()` is caller-driven. New model makes finality data-driven on verification. Creation path can keep an explicit `finalize()` that injects the field. |
| Array order applies to MR inputs for commit ID only, not state tree                                                                      | HIGH     | Validated   | `[mr-sort-order]` + `[intra-commit-ordering]` — state tree nodes still lexically sorted, only commit ID computation uses array order. Decision record in sketch.                   |

## Open Questions

- **Coz in commit use array order for hashing?** Yes — decided with Zami
  (2026-03-09). Captured in `[intra-commit-ordering]`. Not yet in SPEC.md
  but verbal agreement. Implementation proceeds on this basis.
- **`commit` error semantics?** Three error conditions identified but not
  yet in SPEC.md: `COMMIT_NOT_LAST` (commit in non-final coz),
  `MISSING_COMMIT` (no commit field), `COMMIT_MISMATCH` (value ≠ CS).
  We will implement these and propose to Zami.

## Scope

### In Scope

- **WS-A**: CS/PS computation restructure (swap CommitID membership)
- **WS-B**: Commit ID array order (replace sorted concat)
- **WS-C**: L1/2 PR removal (make PR conditional on Level 3+)
- **WS-D**: Genesis finality (update `id` = PS, verify fixtures)
- **WS-E**: Commit finality plumbing (wire `commit` field semantics)

### Out of Scope

- §12+ features (embedding, MSS, consensus, recovery, state jumping)
- Golden fixture regeneration (deferred to audit-remediation WS6)
- Formal model review (charter item 3)
- Level 5+ rules implementation
- New error codes in consensus spec (deferred until §17/§24 stabilize)

## Phases

<!--
  Phases are ordered by structural dependency. Phase 1 changes function
  signatures that Phase 2 builds on. Phase 3 depends on CS being correctly
  computed (Phase 1) to inject it into cozies.
-->

1. **Phase 1: State Computation** — Fix the core CS/PS formulas and commit
   ID hashing order. Most structurally impactful; must land first because
   every downstream computation depends on correct state values.
   - [ ] **WS-A: CS/PS Restructure**
     - [ ] Go: Update `ComputeCS()` — remove `commitID` param, add `ds *DataState`
     - [ ] Go: Update `ComputePS()` — change `cs CommitState` to `as AuthState`, add `commitID *CommitID`
     - [ ] Go: Update all call sites in `principal.go`
     - [ ] Go: Update doc comments on `CommitState`, `PrincipalState` types
     - [ ] Rust: Mirror CS/PS signature changes in `state.rs`
     - [ ] Rust: Update all call sites in `principal.rs`
     - [ ] Rust: Update doc comments
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass
   - [ ] **WS-B: Commit ID Array Order**
     - [ ] Go: Add `hashConcatBytes()` (concatenate without sorting)
     - [ ] Go: Update `ComputeCommitID()` to use `hashConcatBytes`
     - [ ] Rust: Add `hash_concat_bytes()` (concatenate without sorting)
     - [ ] Rust: Update `compute_commit_id()` to use `hash_concat_bytes`
     - [ ] Both: Sorted variant (`hashSortedConcatBytes`) preserved for state tree
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass

2. **Phase 2: Identity Corrections** — Fix PR optionality and genesis
   finality semantics. Independent of Phase 1 in concept but may share
   call sites in `principal.go`/`principal.rs`.
   - [ ] **WS-C: L1/2 PR Removal**
     - [ ] Go: Change `pr` field to `*PrincipalRoot` (nilable)
     - [ ] Go: Only set `pr` at Level 3+ in genesis and import flows
     - [ ] Go: Update `PR()` accessor to return `*PrincipalRoot`
     - [ ] Go: Update callers that assume PR is always present
     - [ ] Rust: Wrap `pr` field in `Option<PrincipalRoot>`
     - [ ] Rust: Only set at Level 3+ in genesis and import flows
     - [ ] Rust: Update accessor to return `Option<&PrincipalRoot>`
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass
   - [ ] **WS-D: Genesis Finality**
     - [ ] Verify genesis `id` assertion already uses PS (likely correct via promotion)
     - [ ] Update any stale comments referencing AS where PS is meant
     - [ ] Verify golden fixture values still hold (AS == PS at genesis w/o DS)
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass

3. **Phase 3: Commit Finality Plumbing** — Wire the `commit` field into
   coz processing. Depends on Phase 1 (CS must be correctly computed to
   embed in cozies).
   - [ ] **WS-E: `commit` Field and Finalization Semantics**
     - [ ] **Creation path:** `PendingCommit.finalize()` computes CS and injects
           `commit:<CS>` into last coz payload before signing
     - [ ] **Verification/import path:** Detect `commit` during array processing:
       - [ ] Coz with `commit` → mark as final
       - [ ] Error if cozies remain after `commit` coz (`COMMIT_NOT_LAST`)
       - [ ] Error if array ends without `commit` (`MISSING_COMMIT`)
       - [ ] Error if `commit` value ≠ computed CS (`COMMIT_MISMATCH`)
     - [ ] Go: Add error sentinels for the 3 new error conditions
     - [ ] Rust: Add error variants for the 3 new error conditions
     - [ ] Both: `go test ./...` and `cargo test --workspace` pass

## Verification

- [ ] Phase 1: `go test ./...` and `cargo test --workspace` pass after CS/PS + array-order
- [ ] Phase 2: `go test ./...` and `cargo test --workspace` pass after PR + genesis
- [ ] Phase 3: `go test ./...` and `cargo test --workspace` pass after commit field plumbing
- [ ] Cross-cutting: Both implementations produce identical PS/CS for same inputs (parity)
- [ ] Post-plan: Golden fixture regeneration via `cargo run -p fixture-gen` (deferred to WS6)

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

| Item                                                      | Severity | Why Introduced | Follow-Up                          | Resolved |
| :-------------------------------------------------------- | :------- | :------------- | :--------------------------------- | :------: |
| TD-3 (from audit plan): `ComputeCommitIDTagged` not wired | LOW      | Pre-existing   | Wire when Level 5+ multikey needed |          |

## Deviation Log

<!--
  Populated during execution. Empty at plan creation.
-->

| Commit | Planned | Actual | Rationale |
| :----- | :------ | :----- | :-------- |

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
- SPEC.md: `305631b` (latest reviewed commit on `origin/zami`)
