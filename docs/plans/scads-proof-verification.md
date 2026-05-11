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

| Decision                          | Choice                                      | Rationale                                                                                                                                                                                                                                                                                               |
| :-------------------------------- | :------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Core crate modifications          | Yes — expose proof generation API           | Proof generation is a core protocol capability (prover side). `pub(crate)` visibility on `commit_trees` is encapsulation theater at pre-alpha.                                                                                                                                                          |
| Thin witness path skips Principal | Yes — standalone `malt::verify_consistency` | The thin witness verifies only the MALT consistency proof (append-only extension) and stores blobs. No signature verification, no transaction-effect parsing, no `Principal` construction. The principal provides its new state as part of the push; the consistency proof guarantees honest extension. |
| Per-request path selection        | Proof presence on request, not config flag  | Fat witnesses accept both proofed and unproofed pushes. Thin witnesses require proofs. Engine inspects the request, not a global mode flag.                                                                                                                                                             |
| Verification tier determines path | Thin = proof only; Fat = full replay        | The proof-based path IS the thin witness path. It does not re-derive state — the principal is sovereign. Independent state verification is a fat witness concern handled by the existing full-replay path. This mirrors CT: the log stores, auditors verify.                                            |
| Wire format provisional           | Designed but marked unstable                | G5/G6 unresolved. Cost of redesigning proof structs when SPEC stabilizes is low. Cost of waiting indefinitely is high.                                                                                                                                                                                  |
| Go parity                         | Required for core crate changes only        | Both implementations share the protocol layer. Go `malt` library has identical proof API (confirmed: `proof.go`). Engine/server changes are Rust-only.                                                                                                                                                  |

## Risks & Assumptions

| Risk / Assumption                            | Severity | Status       | Mitigation / Evidence                                                                                                                                                                                                              |
| :------------------------------------------- | :------- | :----------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fork detection gap for thin witnesses        | HIGH     | Inherent     | Consistency proofs prove append-only extension of ONE chain. Cannot detect equivocation across witnesses. Same limitation as CT. Gossip-layer auditing (§13.7) detects forks — out of scope for this plan. Documented in ADR-0001. |
| Multi-algorithm proof wire format complexity | MEDIUM   | Mitigated    | Mirrors `MultihashDigest` pattern — proofs keyed by `HashAlg`. Structural complexity, not novel difficulty.                                                                                                                        |
| Go parity expands scope                      | MEDIUM   | Mitigated    | Structurally identical changes (same malt library, same `CommitTrees`). Bounded to 2-3 public methods + tests.                                                                                                                     |
| TipState schema migration                    | LOW      | Accepted     | Only `MemoryIndexer` exists. Pre-alpha, no production data to migrate.                                                                                                                                                             |
| `malt` crate proof API is sufficient         | —        | ✅ Validated | Rust: `verify_inclusion`, `verify_consistency` (standalone, no `Log`). Go: `VerifyInclusion`, `VerifyConsistency` (standalone). Full parity confirmed.                                                                             |
| Proof generation requires full MALT tree     | —        | ✅ Validated | `Log` stores all leaves. `inclusion_proof(index)` and `consistency_proof(old_size)` traverse the stored tree. Only the entity with the full log (prover) can generate proofs.                                                      |
| `from_checkpoint` creates empty MALT trees   | —        | ✅ Validated | principal.rs:365 — `CommitTrees::new()`. Checkpoint-resumed principals cannot generate proofs. Verifier path uses standalone functions, not `Principal`.                                                                           |

## Open Questions

- **Proof wire format encoding.** Proof paths are `Vec<Vec<u8>>` (Rust) /
  `[]D` (Go). Wire encoding options: base64url array in JSON, CBOR, or raw
  bytes. Provisional decision deferred to Phase 3 implementation; JSON with
  base64url arrays is the likely starting point for consistency with existing
  coz encoding.

- **Key material in TipState.** The thin witness verifies signatures against
  its stored `active_keys` (authorization), then accepts the principal's
  claimed new key state for key transitions (consistency proof guarantees
  append-only extension). TipState stores the last accepted key state; format
  mirrors `from_checkpoint`'s parameter list (`Vec<Key>`).

- **Should `submit_commit` branch or split?** Either add proof-optional
  parameters to the existing method, or create a separate
  `submit_commit_with_proof()`. Deferred to Phase 2 implementation; single
  method with `Option<ProofBundle>` is likely cleaner.

## Scope

### In Scope

- `Principal::consistency_proof()` and `Principal::inclusion_proof()` (Rust)
- Go parity: equivalent methods on `Principal`
- `TipState` extension: `active_keys`, `cr`, `tree_size`
- `IndexableCommit` extension: corresponding new fields
- `MemoryIndexer` updates for new fields
- Engine proof-based verification path (standalone `malt::verify_*`)
- `PushRequest` wire format expansion (provisional)
- HTTP route updates to pass proof material to engine
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

1. **Phase 1: Core Crate Proof Generation (Rust + Go)** — expose MALT proof
   generation from `Principal` for client/prover use
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
   - [ ] Tests (Rust): build principal from fixture, append commits, generate
         proofs, verify with standalone verifiers
   - [ ] Tests (Go): mirror Rust test structure

2. **Phase 2: Engine Proof Verification Path** — add lightweight proof-based
   write path that skips `Principal` construction entirely
   - [ ] Extend `TipState` with `active_keys: Vec<SerializedKey>`, `cr: String`,
         `tree_size: u64`
   - [ ] Extend `IndexableCommit` with corresponding fields
   - [ ] Update `MemoryIndexer` to persist/return new `TipState` fields
   - [ ] Define `ProofBundle` type: per-algorithm consistency proofs +
         per-algorithm inclusion proofs + new CR + new tree_size +
         claimed new state (active_keys, AR, SR, PR)
   - [ ] Implement thin-witness engine path:
     - [ ] Read `TipState` from index (trust anchor)
     - [ ] Compute TR from received blobs (derive expected leaf)
     - [ ] `malt::verify_consistency()` per algorithm (old_cr → new_cr)
     - [ ] `malt::verify_inclusion()` per algorithm (TR matches tree)
     - [ ] `coz::verify()` each transaction signature against stored
           `active_keys` (authorization)
     - [ ] Accept claimed new state (key transitions), persist blobs,
           update TipState
   - [ ] Preserve existing full-replay path as fat-witness fallback
   - [ ] Tests: construct `malt::Log` directly, generate consistency +
         inclusion proofs, submit through thin-witness path, verify
         TipState update
   - [ ] Tests: verify fallback to full-replay when no proof material present
   - [ ] Tests: invalid consistency proof rejected
   - [ ] Tests: invalid inclusion proof rejected (blob-swap detection)
   - [ ] Tests: invalid signature rejected

3. **Phase 3: Wire Format Integration** — connect HTTP layer to engine proof
   path (provisional format)
   - [ ] Expand `PushRequest` with optional `proof` field containing
         `ProofBundle` (JSON serialization, base64url proof paths)
   - [ ] Update `/push` route handler to extract proof material and pass to
         engine
   - [ ] Mark wire format as provisional (doc comment + SPEC gap reference)
   - [ ] E2E test: proofed push via HTTP → verify TipState reflects new state
   - [ ] E2E test: unproofed push via HTTP → verify fallback to replay path
   - [ ] Document fork detection limitation in server README or doc comments

## Verification

- [ ] `cargo test` passes for `cyphr`, `cyphr-storage`, `cyphr-server`
- [ ] `go test ./...` passes in `go/`
- [ ] Proof round-trip: principal generates consistency proof → engine verifies
      it via standalone path → TipState updated correctly
- [ ] Fallback: push without proof material still works via full-replay
- [ ] Rejection: invalid consistency proof rejected with appropriate error
- [ ] Multi-algorithm: principal with 2+ algorithms generates per-algorithm
      proofs, all verified independently

## Technical Debt

<!--
  Populated during CORE execution. Empty at plan creation.
-->

| Item | Severity | Why Introduced | Follow-Up | Resolved |
| :--- | :------- | :------------- | :-------- | :------: |

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
