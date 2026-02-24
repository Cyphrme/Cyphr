# CHARTER: Audit Remediation

<!--
  Strategic framing for remediating the findings of the
  2026-02-20 API Coherence Audit (docs/audit/2026-02-20-api-coherence-audit.md).

  See: workflows/charter.md for the full protocol specification.
-->

## Purpose

The Cyphrpass Identity Protocol has dual reference implementations in Go and
Rust. A comprehensive API coherence audit surfaced 12 bugs, 9 feature
deviations, and 43 remediation items spanning correctness, safety, encapsulation,
and cross-language parity.

The Go implementation scored 3.0/5 overall coherence; Rust scored 4.3/5. The Go
side has systemic issues: library code that panics on recoverable input, public
fields that leak mutable access to internal state, and unmatchable `fmt.Errorf`
errors that prevent callers from distinguishing failure modes. The Rust side is
structurally sound in its core but has a CLI layer with ~350 lines of
copy-pasted helpers and string-typed errors.

Beyond surface issues, the audit identified a correctness bug in both
implementations: `addKey`/`add_key` does not check the revoked set, allowing a
compromised key to be re-added (BUG-12, violating formal invariant I2). It also
identified a functional gap where Go cannot compute multi-algorithm Commit IDs
(BUG-7), breaking SPEC §20 compliance.

These findings need structured remediation before the protocol advances toward
Level 5+ features (lifecycle states, fork detection, data actions), because the
current error handling and encapsulation deficiencies would compound with each
new feature added on top of them.

## North Star

Both implementations pass an identical set of spec-anchored test vectors,
enforce the protocol's formal invariants structurally rather than by convention,
and present an API surface where invalid states are unrepresentable (to the
degree each language allows). A contributor can pick up either implementation
and reason about correctness from the types alone.

## Workstreams

<!--
  Ordered by the dependency graph from Appendix C §C.8.
  Workstreams 1-2 are prerequisites; 3-6 are independent of each other
  once 1-2 are complete; 7 depends on 5.
-->

1. **Go Correctness, Safety & Type Representation** — Eliminate panics in
   library code, remove dead `TxOtherRevoke` variant, fix `typSuffix` parsing,
   and add the revoked-key-re-add guard (BUG-1, BUG-2, BUG-3, BUG-5, BUG-12).
   Also address type representation gaps: constrain `TransactionKind` beyond
   bare `int` (B.1), disambiguate `Revocation.By` nil-vs-empty semantics (B.2),
   and evaluate `DataState` inner type (`coz.B64` vs `Cad`) (D.3).
   - Spawns: `.sketches/go-correctness-safety.md`
   - Status: Not Started

2. **Go Error Hardening** — Replace all `fmt.Errorf` usages in core and state
   modules with sentinel or typed errors so callers can distinguish failure
   modes via `errors.Is`/`errors.As` (BUG-4, F.2, F.4). This is a prerequisite
   for lifecycle states (Appendix C §C.2).
   - Spawns: `.sketches/go-error-hardening.md`
   - Status: Not Started

3. **Go Encapsulation Hardening** — Address the systemic anti-pattern of
   returning internal collections by reference. Unexport `AuthLedger`/
   `DataLedger` fields, return defensive copies from `Variants()`,
   `Transactions()`, `Commits()`, `Actions()`, remove `SetRaw()`, unexport
   `Entry.Raw` (BUG-6, BUG-10, BUG-11, A.1, B.4). Unexport `NewCommit` and
   `FinalizeCommit` to enforce commit lifecycle through the API (A.2). One
   root cause, seven findings (Appendix C §C.1).
   - Spawns: `.sketches/go-encapsulation-hardening.md`
   - Status: Not Started

4. **Rust CLI Deduplication & Error Typing** — Extract ~350 lines of duplicated
   helpers into `commands/common.rs`, de-duplicate key generation match arms,
   remove `eprintln!` debug output from `load_principal` (BUG-8, BUG-9, C.2,
   C.3), and introduce a `cli::Error` enum to replace `.ok_or("...")` string
   errors throughout the CLI layer (D.9, F.5).
   - Spawns: `.sketches/rust-cli-deduplication.md`
   - Status: Not Started

5. **Cross-Implementation Parity** — Close the feature deviation gap: port
   `ComputeCommitIDTagged` to Go (BUG-7, DEV-3), refactor Go import/test paths
   to use atomic `VerifyAndApply` (C.1, D.10), decide the Go commit-based
   storage question (DEV-1, DEV-2), and replace Rust core's three
   `debug_assert!` calls with proper `Result` returns so the library never
   panics on malformed input (Phase 3 §3.1).
   - Spawns: `.sketches/cross-implementation-parity.md`
   - Status: Not Started

6. **Verification Infrastructure** — Add hand-computed spec-anchored reference
   vectors (Appendix C §C.4, Appendix E §E.5), targeted negative tests for
   BUG-12 and timestamp regression (§E.4), and evaluate property-based /
   fuzz testing introduction (§E.1, §E.2). The sketch should also explicitly
   target I5 (Observation Congruence / promotion equivalence), which the audit
   flagged as untested in Appendix D.
   - Spawns: `.sketches/verification-infrastructure.md`
   - Status: Not Started

7. **Structural Invariant Improvements** — Hoist `pre` verification to occur
   once before transaction dispatch (C.3), settle the data action pipeline
   design question before storage hardening (C.7, B.6), address
   `latestTimestamp` atomicity (C.6), and enforce level monotonicity (I4)
   structurally rather than leaving it emergent. Depends on workstream 5 for
   storage decisions.
   - Spawns: `.sketches/structural-invariants.md`
   - Status: Not Started

## Non-Goals

- **Lifecycle state implementation (B.1)** — The formal model defines 12
  lifecycle combinations (Active, Frozen, Deleted, Zombie, Dead, Nuked × OK/
  Errored). The audit confirms the API is structurally ready for this, but
  implementing it is Level 5+ work. This charter focuses on making the current
  Level 1-4 surface correct and hardened so lifecycle states can be added
  without inheriting the existing deficiencies. Go error hardening (workstream 2) is explicitly framed as a _prerequisite_ for lifecycle, not a substitute.

- **Fork detection (I6)** — Not implemented in either language and the audit
  correctly identifies it as a consumer/service-layer concern. The primitives
  (`pre` tracking) exist. Implementing detection and conflict resolution policy
  belongs in a separate charter when multi-service deployments are pursued.

- **Protocol versioning strategy (F.3)** — Important long-term questions
  (v0.2 compatibility, genesis version embedding, forward-compatibility) but
  orthogonal to the remediation workstreams. Worth a dedicated charter or
  sketch cycle when the protocol approaches stability.

- **Consumer onboarding / "hello world" examples (F.2)** — Valuable for
  adoption but premature while the API surface is actively changing through
  this remediation. Better done after the API stabilizes.

- **P3 items as a dedicated workstream** — The audit's P3 tier (AI stylistic
  comments, `VerifiedTx` → `VerifiedTransaction` naming, `#[doc(hidden)]` on
  test helpers, `checkExpected` refactoring, accessor symmetries, `Entry`
  extractor documentation) does not warrant its own sketch→plan→core cycle.
  These items are governed by the **boy-scout policy** below instead.

- **Go CLI** — Go has no CLI (DEV-8). Building one is a feature, not
  remediation. Out of scope.

## Boy-Scout Policy (P3)

P3 items are not chartered as independent work. Instead, when a workstream
touches a file containing a P3 item, that item is resolved in the same commit.
The relevant P3 items and their expected resolution context:

| Item | Description                               | Expected During       |
| :--- | :---------------------------------------- | :-------------------- |
| E.1  | `VerifiedTx` → `VerifiedTransaction`      | WS2 (Error Hardening) |
| A.3  | `#[doc(hidden)]` on Rust test helpers     | WS4 (CLI Dedup)       |
| B.5  | Go `checkExpected` block refactoring      | WS6 (Verification)    |
| D.7  | `Entry` extractors: document async design | WS3 (Encapsulation)   |
| D.4  | Accessor visibility symmetries            | WS3 (Encapsulation)   |
| E.2  | Rust accessor symmetries                  | WS4 (CLI Dedup)       |
| E.3  | Rust visibility consistency               | WS4 (CLI Dedup)       |
| A.A  | AI "what not why" comment cleanup         | Any workstream        |

If a P3 item is not naturally encountered during any workstream, it remains
open — but the expectation is that most will be resolved incidentally.

## Appetite

A focused multi-cycle commitment. Workstreams 1-4 are concrete, well-scoped
refactoring passes — each is a single sketch→plan→core cycle, likely 1-2
sessions each. Workstreams 5-7 involve design decisions (commit-based storage,
data action pipeline) that may require more deliberation.

Realistic estimate: 8-12 sketch→plan→core cycles total, spread across
multiple sessions. If any workstream balloons beyond its sketch scope, that's a
signal to split it into sub-workstreams rather than expanding the appetite.

## Sequel: Formal Model Audit

The formal model (`principal-state-model.md`) was produced by the `/model`
workflow and has not been independently audited against `SPEC.md`. This
charter's workstreams do not depend on the model — they are driven by the API
coherence audit findings. However, any future charter that _implements_ from
the model (lifecycle states, fork detection, the Level 5 rule system) should
first audit the model for correctness. The recommended sequence is:

1. **This charter** — remediate the Level 1-4 API surface.
2. **Model audit** — verify the coalgebraic state machine, session types, and
   derived invariants against the current spec.
3. **Implementation charter** — build lifecycle, fork detection, and Level 5+
   features on the audited model and remediated API.

## References

- Audit: [2026-02-20-api-coherence-audit.md](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/audit/2026-02-20-api-coherence-audit.md)
- Formal model: [principal-state-model.md](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/docs/models/principal-state-model.md)
- Specification: [SPEC.md](file:///var/home/nrd/git/github.com/Cyphrme/Cyphrpass/SPEC.md)
