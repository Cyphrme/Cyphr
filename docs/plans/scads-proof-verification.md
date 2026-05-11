# PLAN: SCADS Proof Verification

<!--
  Produced from /plan COMMIT phase.
  Source sketch: .sketches/2026-05-07-malt-proof-verification.md
  ADR: docs/adr/0001-self-certifying-network-architecture.md
  Predecessor: docs/plans/cyphr-server.md (Phases 1-4 complete, Phase 5 deferred)
-->

## Goal

Transition `cyphr-server`'s write path from O(n) full-chain replay to O(log n)
MALT proof-based verification, implementing the SCADS paradigm established in
ADR-0001. The change spans three layers: core crate (proof generation API for
clients), storage engine (proof-based verification path), and HTTP server
(wire format for proof material). Go parity is required for core crate changes.

This plan resumes work interrupted by the architectural impedance mismatch
discovered during the previous `cyphr-server` plan's Phase 4 E2E integration.
The previous plan's Phase 5 (PoP authentication) remains queued for the next
plan cycle.

## Constraints

- **Auth domain only.** Scoped to the Commit Tree (MALT). Data Tree
  verification is explicitly out of scope (ADR-0001 §Decision).
- **SPEC gaps G5/G6 unresolved.** Proof wire format is provisional — designed
  to mirror RFC 9162 proof structures. Will be realigned when Zami's SPEC
  update lands.
- **Correctness over backward compatibility.** Pre-alpha. Core crate API
  changes are acceptable without deprecation ceremony.
- **Full replay preserved.** Proof-based verification is the primary path; full
  replay remains as bootstrap and fat-witness fallback. Both paths coexist.
- **Multi-algorithm proofs.** `CommitTrees` is `BTreeMap<HashAlg, CommitLog>`.
  Proofs are per-algorithm, mirroring `MultihashDigest`'s keyed structure.

## Decisions

| Decision                   | Choice                                            | Rationale                                                                                                                                                                                                                            |
| :------------------------- | :------------------------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Core crate modifications   | Yes — expose proof generation API                 | Proof generation is a core protocol capability (prover side). `pub(crate)` visibility on `commit_trees` is encapsulation theater at pre-alpha.                                                                                       |
| Proof path skips Principal | Yes — standalone `malt::verify_*` + `coz::verify` | The proof path verifies consistency (append-only), inclusion (blob-tree binding), and signatures (authorization) without constructing a `Principal`. Accepts claimed key state for transitions.                                      |
| `ProofBundle` is required  | Always — not optional                             | Proofs are the push protocol, not an optimization. Bootstrap, steady-state, and catch-up all use proof-based verification. Full replay is an audit operation, not a push acceptance path.                                            |
| Thin/fat is witness state  | Not an API distinction                            | A thin witness becomes fat by receiving historical blobs. The API doesn't bifurcate — `submit_commit` always requires `ProofBundle`. Fat witnesses also have the ability to audit via replay, but that's a separate operation.       |
| Fix `from_checkpoint`      | In scope — restore MALT state                     | `from_checkpoint` currently discards MALT state (`CommitTrees::new()`). This is a pre-existing design flaw. A checkpoint must include MALT state (CR + tree_size per algorithm at minimum). Required for correct TipState operation. |
| Wire format provisional    | Designed but marked unstable                      | G5/G6 unresolved. Cost of redesigning proof structs when SPEC stabilizes is low. Cost of waiting indefinitely is high.                                                                                                               |
| Go parity                  | Required for core crate changes only              | Both implementations share the protocol layer. Go `malt` library has identical proof API (confirmed: `proof.go`). Engine/server changes are Rust-only.                                                                               |

## Risks & Assumptions

| Risk / Assumption                            | Severity | Status       | Mitigation / Evidence                                                                                                                                                                                                              |
| :------------------------------------------- | :------- | :----------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fork detection gap for thin witnesses        | HIGH     | Inherent     | Consistency proofs prove append-only extension of ONE chain. Cannot detect equivocation across witnesses. Same limitation as CT. Gossip-layer auditing (§13.7) detects forks — out of scope for this plan. Documented in ADR-0001. |
| Multi-algorithm proof wire format complexity | MEDIUM   | Mitigated    | Mirrors `MultihashDigest` pattern — proofs keyed by `HashAlg`. Structural complexity, not novel difficulty.                                                                                                                        |
| Go parity expands scope                      | MEDIUM   | Mitigated    | Structurally identical changes (same malt library, same `CommitTrees`). Bounded to 2-3 public methods + tests.                                                                                                                     |
| TipState schema migration                    | LOW      | Accepted     | Only `MemoryIndexer` exists. Pre-alpha, no production data to migrate.                                                                                                                                                             |
| `malt` crate proof API is sufficient         | —        | ✅ Validated | Rust: `verify_inclusion`, `verify_consistency` (standalone, no `Log`). Go: `VerifyInclusion`, `VerifyConsistency` (standalone). Full parity confirmed.                                                                             |
| Proof generation requires full MALT tree     | —        | ✅ Validated | `Log` stores all leaves. `inclusion_proof(index)` and `consistency_proof(old_size)` traverse the stored tree. Only the entity with the full log (prover) can generate proofs.                                                      |
| `from_checkpoint` creates empty MALT trees   | MEDIUM   | Fix in scope | principal.rs:365 — `CommitTrees::new()`. Pre-existing design flaw: a checkpoint without MALT state is not a real checkpoint. Fix: accept MALT state (CR + tree_size per algorithm). Required for correct TipState bootstrapping.   |

## Open Questions

No design-level open questions remain. Implementation-level decisions
(Phase 4 sync API design) are scoped within that phase.

## Scope

### In Scope

- `Principal::consistency_proof()` and `Principal::inclusion_proof()` (Rust)
- Go parity: equivalent methods on `Principal`
- Fix `from_checkpoint` to accept MALT state (Rust + Go)
- `TipState` extension: `active_keys`, `cr`, `tree_size`
- `IndexableCommit` extension: corresponding new fields
- `MemoryIndexer` updates for new fields
- Engine `advance_tip` (proof-verified tip advancement)
- Engine `sync` (chain data transfer + optional verification)
- `PushRequest` wire format expansion (provisional)
- HTTP route updates for `advance_tip` and `sync`
- Documentation of fork detection limitation
- Tests at each layer

### Out of Scope

- Data Tree verification or DT MALT mode
- Gossip / cross-witness fork detection
- SQLite indexer implementation (still on memory backends)
- Phase 5 (PoP authentication) from previous plan — next cycle
- Wire format stabilization (provisional until SPEC update)
- Performance benchmarking or optimization
- Go server implementation
- Production deployment tooling

## Phases

<!--
  Each phase is independently valuable. Phase 1 (prover) and Phase 2
  (verifier) are independent sides of the same boundary — either can
  be implemented first. Phase 3 wires them together at the HTTP layer.

  Phase 2 tests use raw malt::Log instances (not Principal) to generate
  test proofs, so it does NOT depend on Phase 1.
-->

1. **Phase 1: Core Crate — Proof Generation + Checkpoint Fix (Rust + Go)**
   — expose MALT proof generation from `Principal` and fix `from_checkpoint`
   to restore MALT state
   - [ ] Fix `from_checkpoint` to accept MALT state (CR + tree_size per
         algorithm, or full `CommitTrees`). A checkpoint without MALT state
         is not a real checkpoint.
   - [ ] Go: equivalent fix to `FromCheckpoint`
   - [ ] Rust: `Principal::consistency_proof(old_size: u64)` → per-algorithm
         consistency proofs from `commit_trees`
   - [ ] Rust: `Principal::inclusion_proof(index: u64)` → per-algorithm
         inclusion proofs from `commit_trees`
   - [ ] Rust: re-export `malt::InclusionProof`, `malt::ConsistencyProof`,
         `malt::verify_inclusion`, `malt::verify_consistency` from
         `cyphr::commit_root` (or new `cyphr::proof` module)
   - [ ] Go: `(p *Principal) ConsistencyProof(oldSize uint64)` with
         equivalent per-algorithm proof generation
   - [ ] Go: `(p *Principal) InclusionProof(index uint64)` with equivalent
   - [ ] Tests (Rust): build principal, append commits, generate proofs,
         verify with standalone verifiers. Verify checkpoint round-trip
         preserves MALT state.
   - [ ] Tests (Go): mirror Rust test structure

2. **Phase 2: Engine `advance_tip`** — proof-verified tip advancement,
   replacing the full-replay push path
   - [ ] Extend `TipState` with `active_keys: Vec<SerializedKey>`, `cr: String`,
         `tree_size: u64`
   - [ ] Extend `IndexableCommit` with corresponding fields
   - [ ] Update `MemoryIndexer` to persist/return new `TipState` fields
   - [ ] Define `ProofBundle` type: per-algorithm consistency proofs +
         per-algorithm inclusion proofs + new CR + new tree_size +
         claimed new state (active_keys, AR, SR, PR)
   - [ ] Implement `advance_tip`:
     - [ ] Read `TipState` from index (trust anchor). If absent (bootstrap),
           verify genesis + spanning proof to establish initial TipState.
     - [ ] Compute TR from received blobs (derive expected leaf)
     - [ ] `malt::verify_consistency()` per algorithm (old_cr → new_cr)
     - [ ] `malt::verify_inclusion()` per algorithm (TR matches tree)
     - [ ] `coz::verify()` each transaction signature against stored
           `active_keys` (authorization)
     - [ ] Accept claimed new state (key transitions), persist blobs,
           update TipState
   - [ ] Retain `load_principal` as an audit/recovery utility (not a push path)
   - [ ] Tests: construct `malt::Log` directly, generate consistency +
         inclusion proofs, submit through `advance_tip`, verify
         TipState update
   - [ ] Tests: bootstrap — genesis + spanning proof establishes TipState
   - [ ] Tests: invalid consistency proof rejected
   - [ ] Tests: invalid inclusion proof rejected (blob-swap detection)
   - [ ] Tests: invalid signature rejected

3. **Phase 3: Wire Format Integration** — connect HTTP layer to `advance_tip`
   (provisional format)
   - [ ] Update `PushRequest` to require `ProofBundle` field (JSON
         serialization, base64url proof paths)
   - [ ] Update `/push` route handler to extract proof material and pass to
         `advance_tip`
   - [ ] Mark wire format as provisional (doc comment + SPEC gap reference)
   - [ ] E2E test: push via HTTP → verify TipState reflects new state
   - [ ] E2E test: bootstrap push via HTTP → new principal established
   - [ ] Document fork detection limitation in server README or doc comments

4. **Phase 4: Chain Sync** — data transfer operation for historical blob
   ingestion, distinct from tip advancement

   <!--
     `advance_tip` and `sync` are fundamentally different operations:
     - advance_tip: "my chain grew, here's the proof" (O(log n + k))
     - sync: "here's chain data you don't have" (data transfer)

     A thin witness becomes fat by receiving sync data. The witness's
     "thinness" is its current state, not an inherent property.
   -->
   - [ ] Design `sync` API. Open design questions:
     - Partial range sync: how does the witness verify received blobs belong
       to the tree? Likely needs inclusion proofs per blob.
     - Full chain sync: if syncing to tip, state verification happens
       naturally. Witness should update TipState as part of the sync.
     - Streaming interface: for large chain transfers, `&[&[u8]]` is
       inadequate. Consider `impl Iterator<Item = &[u8]>` or `Read` trait.
   - [ ] Implement `sync` at engine layer:
     - [ ] Accept blob range (not necessarily contiguous)
     - [ ] Optionally verify blobs via inclusion proofs against stored CR
     - [ ] Store blobs in BlobStore
     - [ ] If syncing to tip, update TipState with verified state
   - [ ] Wire HTTP route for sync (provisional)
   - [ ] Tests: sync partial range, verify blobs stored
   - [ ] Tests: sync to tip, verify TipState updated
   - [ ] Tests: sync with invalid blobs rejected (if inclusion proofs provided)

## Verification

- [ ] `cargo test` passes for `cyphr`, `cyphr-storage`, `cyphr-server`
- [ ] `go test ./...` passes in `go/`
- [ ] Proof round-trip: principal generates consistency proof → `advance_tip`
      verifies via standalone path → TipState updated correctly
- [ ] Bootstrap: genesis + spanning proof establishes new principal
- [ ] Rejection: invalid consistency/inclusion proof rejected
- [ ] Rejection: invalid signature rejected
- [ ] Multi-algorithm: principal with 2+ algorithms generates per-algorithm
      proofs, all verified independently
- [ ] Sync: partial and full chain data transfer verified

## Technical Debt

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Item                                                                                                                                                                                                                                                  | Severity | Why Introduced                                                                                                                                           | Follow-Up                                                                                                                                                                        | Resolved |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: |
| `malt::Error` mapped to `Error::UnsupportedAlgorithm(msg)` — semantically imprecise. `IndexOutOfBounds` and `EmptyTree` from malt are not "unsupported algorithm" errors; the error message is preserved in the string but the variant is misleading. | LOW      | Pre-alpha error enum; adding a dedicated `ProofError` variant was out of scope for the proof API commit. No downstream consumers parse this variant yet. | Introduce `Error::ProofError(String)` or `Error::Proof(malt::Error)` when the error taxonomy is revisited (likely during Phase 2 `advance_tip` which will consume these errors). |    ☐     |

## Deviation Log

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Commit | Planned | Actual | Rationale |
| :----- | :------ | :----- | :-------- |

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

- Charter: `docs/charters/spec-alignment.md` (Item 4: Spec Alignment)
- Sketch: `.sketches/2026-05-07-malt-proof-verification.md`
- ADR: `docs/adr/0001-self-certifying-network-architecture.md`
- Predecessor plan: `docs/plans/cyphr-server.md`
- MALT crate (Rust): `malt` 0.1.1 — `src/proof.rs`
- MALT library (Go): `github.com/cyphrme/malt` — `proof.go`
