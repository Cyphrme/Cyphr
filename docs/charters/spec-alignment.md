# CHARTER: Spec Alignment & Implementation Hardening

<!--
  Strategic framing for bringing both Go and Rust implementations into
  provable alignment with SPEC.md, starting from API surface remediation
  and progressing through structural spec changes as they stabilize.

  See: workflows/charter.md for the full protocol specification.
-->

## Purpose

The Cyphrpass Identity Protocol has dual reference implementations in Go and
Rust. A comprehensive API coherence audit (2026-02-20) surfaced 12 bugs, 9
feature deviations, and 43 remediation items spanning correctness, safety,
encapsulation, and cross-language parity.

Concurrently, the specification itself is undergoing significant structural
revision — new transaction verbs (`key/delete`), principal lifecycle operations
(close, merge, fork), state computation changes (commit state simplification),
and new features (state jumping) are being added by Zami. The implementations
were built against an earlier snapshot of the spec.

This charter frames the strategic arc of bringing both implementations into
alignment with the evolving specification, ensuring that new features are built
on a correct, hardened, and formally verified foundation.

## North Star

Both implementations pass an identical set of spec-anchored test vectors,
enforce the protocol's formal invariants structurally rather than by convention,
and present an API surface where invalid states are unrepresentable (to the
degree each language allows). The formal model is verified against the current
spec. A contributor can pick up either implementation and reason about
correctness from the types alone.

## Strategic Sequence

Each item below produces its own plan document with independent scope,
verification criteria, and approval. The sequence is ordered by dependency,
not urgency.

### 1. API Audit Remediation

Fix the existing code quality, error handling, encapsulation, and
cross-language parity issues surfaced by the 2026-02-20 audit. This work
targets the code as it existed at the time of the audit — it does not attempt
to incorporate spec changes that arrived after the audit was written.

- Plan: [audit-remediation.md](../plans/audit-remediation.md)
- Status: WS1-4 complete, WS5-7 remaining

### 2. Model Review

Audit the formal model (`principal-state-model.md`) against the current spec.
The model was produced by the `/model` workflow against an earlier spec
snapshot. Zami's structural additions (key/delete, close/merge/fork, state
jumping, commit state simplification) may have introduced gaps, invalidated
assumptions, or created new invariants that the model does not capture.

This review is gated on sufficient spec stability — the model should be audited
against a spec snapshot that is not actively in flux.

### 3. Spec Alignment

Implement the new and revised spec sections in both Go and Rust. This is the
largest and least-defined item in the sequence. It covers at minimum:

- New transaction verbs: `key/delete`
- Principal lifecycle: close, merge, fork
- State computation: commit state revision
- Grammar: `typ` action grammar consolidation
- State optimization: state jumping

This work is inherently incremental. Sections are implemented as they stabilize
in the spec, not as a monolithic batch. Each coherent batch gets its own plan.

### 4. Verification Infrastructure

Prove both implementations match the spec via:

- Spec-anchored golden test vectors (hand-computed)
- Negative tests for known invariant violations
- Property-based / fuzz testing evaluation
- Observation congruence coverage (formal invariant I5)

## Non-Goals

- **Level 5+ implementation** (rules, weighted permissions) — The spec defines
  these but implementation is gated on completing Levels 1-4 correctly.
- **Level 6** (programmable VM) — Research-stage, not implementation-ready.
- **Protocol versioning strategy** — Important for long-term stability but
  orthogonal to this charter's alignment work.
- **Go CLI** — Building one is a feature, not remediation. Out of scope.
- **Consumer onboarding** — Premature while the API surface is in active
  development through this charter.

## Decision Principles

- **Spec stability gates implementation.** Don't build on sections that are
  actively in flux. Wait for sufficient stability before committing to a plan.
- **Model review precedes structural implementation.** Before implementing new
  spec features (sequence item 3), the formal model should be audited against
  the current spec (sequence item 2).
- **Each plan is independently scoped and approved.** The charter provides
  strategic direction; plans provide tactical detail.
- **Current plan finishes out regardless of spec changes.** The audit
  remediation plan (sequence item 1) addresses code quality issues that are
  valid independent of any spec revision.

## Appetite

The audit remediation plan (item 1) is well-scoped: 8 workstreams across
~10 sessions, with the first 4 complete. The remaining items carry increasing
uncertainty:

- **Model review** (item 2) is bounded but timing depends on spec stability.
  Likely 1-3 sessions once started.
- **Spec alignment** (item 3) is open-ended by nature — its scope grows with
  the spec. Individual plan batches should be kept small (1-3 sessions each).
- **Verification infrastructure** (item 4) is a sustained investment that
  grows with each new feature. Initial golden vector work is 1-2 sessions;
  property testing is a longer-term evaluation.

Total appetite is deliberately unbounded at the charter level. Each plan is
individually scoped and can be paused or reprioritized without invalidating the
strategic direction.

## References

- Audit: [2026-02-20-api-coherence-audit.md](../audit/2026-02-20-api-coherence-audit.md)
- Plan (item 1): [audit-remediation.md](../plans/audit-remediation.md)
- Formal model: [principal-state-model.md](../models/principal-state-model.md)
- Specification: [SPEC.md](../../SPEC.md)
- Sketch: [2026-02-24-charter-scope.md](../../.sketches/2026-02-24-charter-scope.md)
